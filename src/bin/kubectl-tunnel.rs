use std::{
    io::Write,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{BufMut as _, BytesMut};
use futures::{SinkExt, StreamExt};
use kube::{
    Api, Client, Config, ResourceExt,
    api::{DeleteParams, PostParams},
    config::{KubeConfigOptions, Kubeconfig},
    runtime::{
        conditions::{is_deleted, is_pod_running},
        wait::await_condition,
    },
};
use kubectl_tunnel::{
    codec::{MAX_SIZE, PREFIX_SIZE, TUNCodec, encode, parse_packet},
    nettop::{PacketDirection, SessionTracker, TopBarState, TunnelConnectionStatus, run_ui},
    utils::{create_device, handle_handshake},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use k8s_openapi::api::core::v1::Pod;

type Result<T> = std::result::Result<T, std::io::Error>;

use clap::{Parser, Subcommand};

use tun::{AbstractDevice, AsyncDevice};

struct TunnelSettings {
    port: u16,
    routes: Vec<String>,
    dns: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "kubectl-tunnel", about = "Tunnel kubectl plugin", version)]
pub struct Cli {
    /// Kubernetes context to use
    #[arg(long)]
    pub context: Option<String>,

    /// Kubernetes namespace
    #[arg(short, long)]
    pub namespace: Option<String>,

    /// Output format (json|yaml|wide)
    #[arg(short, long)]
    pub output: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a pod and start the tunnel
    Connect {
        name: String,
        #[arg(long, default_value_t = false)]
        tui: bool,
    },

    /// Delete a pod
    Delete { name: String },

    /// Create a pod from a manifest file
    Create { file_name: String },
}

async fn create_tunnel<'a>(
    dev: &'a mut AsyncDevice,
    stream: impl AsyncRead + AsyncWrite + Unpin + 'a,
    tracker: Option<Arc<Mutex<SessionTracker>>>,
    top_bar: Arc<RwLock<TopBarState>>,
) -> Result<(String, impl Future<Output = Result<()>> + 'a)> {
    let (mut tcp_reader, tcp_writer) = tokio::io::split(stream);

    let config = handle_handshake(&mut tcp_reader).await?;

    dev.configure(&config)?;
    refresh_top_bar_endpoints(dev, &top_bar);
    let mtu = dev.mtu().expect("Invalid mtu");
    let device_name = dev.tun_name()?;

    let mut tcp_reader = tokio_util::codec::FramedRead::new(tcp_reader, TUNCodec(mtu, false));
    let mut tcp_writer = tokio_util::codec::FramedWrite::new(tcp_writer, TUNCodec(mtu, false));

    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    // TCP -> TUN: read from the port-forward stream and write into the TUN device.
    let tracker_a = tracker.clone();
    let task_a = async move {
        while let Some(packet) = tcp_reader.next().await {
            match packet {
                Ok(packet) => {
                    if let Some(tracker) = &tracker_a {
                        if let Ok(mut tracker) = tracker.lock() {
                            tracker.observe(PacketDirection::Inbound, &packet);
                        }
                    }
                    match encode(packet) {
                        Ok(encoded) => {
                            if let Err(err) = tun_writer.write_all(&encoded).await {
                                eprintln!("Failed writing to TUN: {err}");
                                break;
                            }
                        }
                        Err(err) => eprintln!("Failed to encode packet for TUN: {err}"),
                    }
                }
                Err(err) => {
                    eprintln!("Failed reading from TCP stream: {err}");
                    break;
                }
            }
        }
    };

    // TUN -> TCP: read from the TUN device and write back to the port-forward stream.
    let tracker_b = tracker.clone();
    let task_b = async move {
        let mut bufa = BytesMut::with_capacity(MAX_SIZE);
        let mut buf = [0x0u8; MAX_SIZE];

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(len) => {
                    bufa.put_slice(&buf[0..len]);

                    while let Ok(Some(packet)) = parse_packet(PREFIX_SIZE, &mut bufa) {
                        if let Some(tracker) = &tracker_b {
                            if let Ok(mut tracker) = tracker.lock() {
                                tracker.observe(PacketDirection::Outbound, &packet);
                            }
                        }
                        if let Err(err) = tcp_writer.send(packet).await {
                            eprintln!("Failed writing to TCP stream: {err}");
                            break;
                        }
                    }
                }

                Err(err) => {
                    eprintln!("Failed reading from TUN: {err}");
                    break;
                }
            };
        }
    };

    let fut = async move {
        tokio::select!(a = task_a => a, b = task_b => b);
        Ok(())
    };

    Ok((device_name, fut))
}

fn refresh_top_bar_endpoints(dev: &AsyncDevice, top_bar: &Arc<RwLock<TopBarState>>) {
    if let Ok(mut top) = top_bar.write() {
        top.address = dev.address().ok().map(|ip| ip.to_string());
        top.destination = dev.destination().ok().map(|ip| ip.to_string());
    }
}

fn set_top_bar_status(top_bar: &Arc<RwLock<TopBarState>>, status: TunnelConnectionStatus) {
    if let Ok(mut top) = top_bar.write() {
        top.status = status;
    }
}

fn extract_tunnel_settings(pod: &Pod) -> std::result::Result<TunnelSettings, String> {
    let annotations = pod.annotations();
    let port = annotations
        .get("tunnel/port")
        .ok_or_else(|| "Tunnel port missing".to_string())?
        .parse::<u16>()
        .map_err(|_| "Invalid tunnel port".to_string())?;

    let routes = annotations
        .get("tunnel/routes")
        .map_or_else(Vec::new, |val| val.lines().map(str::to_owned).collect());
    let dns = annotations.get("tunnel/dns").map(ToOwned::to_owned);

    Ok(TunnelSettings { port, routes, dns })
}

async fn wait_for_tunnel_settings(
    pods: &Api<Pod>,
    pod_name: &str,
) -> std::result::Result<TunnelSettings, String> {
    match await_condition(pods.clone(), pod_name, is_pod_running()).await {
        Ok(Some(pod)) => extract_tunnel_settings(&pod),
        Ok(None) => Err(format!("Pod not found {pod_name}")),
        Err(err) => Err(err.to_string()),
    }
}

fn apply_routes(interface_name: &str, routes: &[String]) {
    if routes.is_empty() {
        return;
    }

    println!("APPLYING ROUTES:\n");
    for route in routes {
        if let Err(err) = std::process::Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                route.as_str(),
                "-interface",
                interface_name,
            ])
            .status()
        {
            eprintln!("Unable to apply route {route}: {err}");
        }
    }
}

fn apply_dns(dns: Option<&str>) {
    let Some(dns) = dns else {
        return;
    };

    for mut line in dns.lines().map(|l| l.split(": ")) {
        if let (Some(nameserver), Some(search)) = (line.next(), line.next()) {
            let grouped =
                kubectl_tunnel::utils::group_by_base_suffix(search.split_ascii_whitespace());
            for (domain, search) in grouped {
                let resolver_path = format!("/etc/resolver/{domain}");
                let path = std::path::Path::new(&resolver_path);

                if let Some(parent) = path.parent()
                    && let Err(err) = std::fs::create_dir_all(parent)
                {
                    eprintln!("Unable to create resolver folder {parent:?}: {err}");
                    continue;
                }

                let resolver = format!("search {}\nnameserver {nameserver}", search.join(" "));
                match std::fs::File::create(path) {
                    Ok(mut file) => {
                        if let Err(err) = writeln!(file, "{resolver}") {
                            eprintln!("Unable to write resolver file {resolver_path}: {err}");
                        } else {
                            println!(
                                "\n\nAPPLYING DNS:\n\ncat <<EOF >> {resolver_path}\n{resolver}\nEOF"
                            );
                        }
                    }
                    Err(err) => eprintln!("Unable to create resolver file {resolver_path}: {err}"),
                }
            }
        }
    }
}

async fn run_connect(
    pods: Api<Pod>,
    pod_name: String,
    tui: bool,
) -> std::result::Result<(), kube::Error> {
    let mut dev = create_device().expect("Unable to create TUN");

    let tun_name = match dev.tun_name() {
        Ok(name) => name,
        Err(err) => {
            eprintln!("Unable to read TUN name: {err}");
            return Ok(());
        }
    };

    if let Err(err) = pods.get(&pod_name).await {
        match err {
            kube::Error::Api(status) => eprintln!("{status}"),
            _ => eprintln!("{err}"),
        };
        return Ok(());
    }

    let settings = match wait_for_tunnel_settings(&pods, &pod_name).await {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("{err}");
            return Ok(());
        }
    };

    apply_routes(&tun_name, &settings.routes);
    apply_dns(settings.dns.as_deref());

    let tracker = if tui {
        Some(Arc::new(Mutex::new(SessionTracker::new())))
    } else {
        None
    };
    let top_bar = Arc::new(RwLock::new(TopBarState::new(
        TunnelConnectionStatus::Initializing,
    )));
    refresh_top_bar_endpoints(&dev, &top_bar);
    let stop = Arc::new(AtomicBool::new(false));
    let ui_thread = if tui {
        let ui_tracker = tracker.clone().expect("tracker exists when tui=true");
        let ui_stop = stop.clone();
        let ui_tun = tun_name.clone();
        let ui_pod = pod_name.clone();
        let ui_top_bar = top_bar.clone();
        Some(std::thread::spawn(move || {
            if let Err(err) = run_ui(ui_tracker, ui_stop, ui_tun, ui_pod, ui_top_bar) {
                eprintln!("TUI error: {err}");
            }
        }))
    } else {
        None
    };

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        set_top_bar_status(&top_bar, TunnelConnectionStatus::Connecting);
        let mut forwarder = pods.portforward(&pod_name, &[settings.port]).await?;
        if let Some(upstream_conn) = forwarder.take_stream(settings.port) {
            set_top_bar_status(&top_bar, TunnelConnectionStatus::Connected);
            match create_tunnel(&mut dev, upstream_conn, tracker.clone(), top_bar.clone()).await {
                Ok((_name, conn)) => {
                    let _ = conn.await;
                    set_top_bar_status(&top_bar, TunnelConnectionStatus::Reconnecting);
                }
                Err(err) => {
                    set_top_bar_status(&top_bar, TunnelConnectionStatus::Error);
                    eprintln!("Tunnel error: {err}");
                }
            }
        } else {
            set_top_bar_status(&top_bar, TunnelConnectionStatus::Disconnected);
            eprintln!("Port-forward stream missing for port {}", settings.port);
        }
    }

    set_top_bar_status(&top_bar, TunnelConnectionStatus::Stopped);
    stop.store(true, Ordering::Relaxed);
    if let Some(handle) = ui_thread {
        let _ = handle.join();
    }

    Ok(())
}

async fn run_create(pods: Api<Pod>, file_name: String) -> std::result::Result<(), kube::Error> {
    let file = match std::fs::File::open(&file_name) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Unable to open manifest {file_name}: {err}");
            return Ok(());
        }
    };

    let pod: Pod = match serde_yaml::from_reader(file) {
        Ok(pod) => pod,
        Err(err) => {
            eprintln!("Invalid manifest {file_name}: {err}");
            return Ok(());
        }
    };

    match pods.create(&PostParams::default(), &pod).await {
        Ok(pod) => println!("pod/{} created", pod.name_any()),
        Err(err) => eprintln!("{err:?}"),
    }

    Ok(())
}

async fn run_delete(pods: Api<Pod>, pod_name: String) -> std::result::Result<(), kube::Error> {
    match pods.delete(&pod_name, &DeleteParams::default()).await {
        Ok(either::Either::Left(pod)) => {
            println!("pod \"{pod_name}\" deleted from default namespace");
            if let Some(uid) = pod.uid()
                && let Err(err) = await_condition(pods.clone(), &pod_name, is_deleted(&uid)).await
            {
                eprintln!("{err}");
            }
        }
        Ok(either::Either::Right(status)) => println!("DELETE STATUS {status}"),
        Err(err) => match err {
            kube::Error::Api(status) => eprintln!("Error from server: {status}"),
            _ => eprintln!("{err}"),
        },
    }

    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), kube::Error> {
    let args = Cli::parse();
    let kubeconfig = Kubeconfig::read()?;
    let options = KubeConfigOptions {
        context: args.context.or_else(|| std::env::var("KUBE_CONTEXT").ok()),
        cluster: None,
        user: None,
    };

    let config = Config::from_custom_kubeconfig(kubeconfig, &options).await?;
    let client = Client::try_from(config)?;
    let pods: Api<Pod> = if let Some(ns) = args.namespace {
        Api::namespaced(client, &ns)
    } else {
        Api::default_namespaced(client)
    };
    match args.command {
        Commands::Connect { name, tui } => run_connect(pods, name, tui).await?,
        Commands::Create { file_name } => run_create(pods, file_name).await?,
        Commands::Delete { name } => run_delete(pods, name).await?,
    }

    Ok(())
}
