use std::{io::Write, net::Ipv4Addr, str::FromStr};

use kube::{
    Api, Client, Config, ResourceExt,
    api::{DeleteParams, PostParams},
    config::{KubeConfigOptions, Kubeconfig},
    runtime::{
        conditions::{is_deleted, is_pod_running},
        wait::await_condition,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

use k8s_openapi::api::core::v1::Pod;

type Result<T> = std::result::Result<T, std::io::Error>;

use clap::{Parser, Subcommand};

use tun::{AbstractDevice, AsyncDevice};

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
    },

    /// Delete a pod
    Delete {
        name: String,
    },

    /// Create a pod from a manifest file
    Create {
        file_name: String,
    },
}


async fn create_tunnel(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    dev: AsyncDevice,
) -> Result<()> {
    let (mut tun_writer, mut tun_reader) = dev.split()?;
    let (mut tcp_reader, mut tcp_writer) = tokio::io::split(stream);
    // TCP -> TUN: read from the port-forward stream and write into the TUN device.
    let task_a = async {
        let mut buf = [0u8; 4096];
        loop {
            let len = tcp_reader.read(&mut buf).await?;
            if len == 0 {
                break;
            }


            
            #[cfg(target_os = "macos")]
            {
                let _ = kubectl_tunnel::utils::linux_to_macos(&mut buf[0..len]).expect("Invalid package");
            }

            tun_writer.write_all(&buf[..len]).await?;
            tun_writer.flush().await?;
        }

        Ok::<(), std::io::Error>(())
    };

    // TUN -> TCP: read from the TUN device and write back to the port-forward stream.
    let task_b = async {
        let mut buf = [0u8; 4096];
        loop {
            let len = tun_reader.read(&mut buf).await?;
            if len == 0 {
                break;
            }

            
            #[cfg(target_os = "macos")]
            {
              let _ = kubectl_tunnel::utils::macos_to_linux(&mut buf[0..len]).expect("Invalid package");
            }

            tcp_writer.write_all(&buf[..len]).await?;
            tcp_writer.flush().await?;
        }

        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(task_a, task_b)?;

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
    match args.command {
        Commands::Connect { name } => {
            let pods: Api<Pod> = Api::default_namespaced(client);
            if let Err(err) = pods.get(&name).await {
                match err {
                    kube::Error::Api(status) => eprintln!("{status}"),
                    _ => eprintln!("{err}"),
                };

                return Ok(());
            }

            // Wait for the pod to be running and gather tunnel config from annotations.
            let (addr, mask, port, routes, dns) =
                match await_condition(pods.clone(), &name, is_pod_running()).await {
                    Ok(Some(pod)) => {
                        let port = pod
                            .annotations()
                            .get("tunnel/port")
                            .expect("Tunnel port missing");
                        let address = pod
                            .annotations()
                            .get("tunnel/address")
                            .expect("Tunnel address missing");
                        let port = port.parse::<u16>().expect("Invalid port");
                        let (addr, mask) = kubectl_tunnel::utils::parse_cidr_mask(&address).unwrap();
                        let routes =
                            pod.annotations()
                                .get("tunnel/routes")
                                .map_or(vec![], |routes| {
                                    routes.lines().map(str::to_owned).collect()
                                });

                        let dns: Option<String> = pod.annotations().get("tunnel/dns").map(|x| x.to_owned());
                        (addr, mask, port, routes, dns)
                    }

                    Ok(None) => {
                        eprintln!("Pod not found {name}");
                        return Ok(());
                    }

                    Err(err) => {
                        eprintln!("{err}");
                        return Ok(());
                    }
                };

            // Configure the local TUN interface for the tunnel.
            let mut config = tun::Configuration::default();
            config
                .address(Ipv4Addr::from(u32::from(addr) + 2))
                .netmask(mask)
                .destination(Ipv4Addr::from(u32::from(addr) + 1))
                .mtu(1400)
                .up();

            config.platform_config(|config| {
                // requiring root privilege to acquire complete functions
                #[cfg(target_os = "linux")]
                config.ensure_root_privileges(true);

                config.packet_information(false);
                config.enable_routing(false);
            });

            let dev = tun::create_as_async(&config).unwrap();
            let tun_name = dev.tun_name().unwrap_or_default();
            // Apply per-route OS routing so traffic hits the TUN interface.
            println!("APPLYING ROUTES: \n");
            for route in routes {
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", route.as_str(), "-interface", tun_name.as_str()])
                    .status();
            }

            if let Some(dns) = dns {
                let path = std::path::Path::new("/etc/resolver/svc.cluster.local");

                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .expect("Unable to create dns resolver folder");
                }

                let mut file = std::fs::File::create(path).expect("Unable to create dns resolver");
                file.write_all(dns.as_bytes()).expect("Unable to write resolver");
                println!("\n\nAPPLYING DNS: \n\ncat <<EOF >> /etc/resolver/svc.cluster.local\n{}\nEOF", dns);
            
            }

            // Start the Kubernetes port-forward and bridge it to the TUN device.
            let mut forwarder = pods.portforward(&name, &[port]).await?;
            if let Some(upstream_conn) = forwarder.take_stream(port) {
                if let Err(err) = create_tunnel(upstream_conn, dev).await {
                    eprintln!("Tunnel error: {err}");
                }
            } else {
                eprintln!("Port-forward stream missing for port {port}");
            }
        }

        Commands::Create { file_name } => {
            let pods: Api<Pod> = Api::default_namespaced(client);
            let file = std::fs::File::open(&file_name).unwrap();
            let pod: Pod = serde_yaml::from_reader(file).unwrap();
            match pods.create(&PostParams::default(), &pod).await {
                Ok(pod) => println!("pod/{} created", pod.name_any()),
                Err(err) => {
                    eprintln!("{err:?}")
                }
            }
        }

        Commands::Delete { name } => {
            let pods: Api<Pod> = Api::default_namespaced(client);
            match pods.delete(&name, &DeleteParams::default()).await {
                Ok(either::Either::Left(pod)) => {
                    println!("pod \"{name}\" deleted from default namespace");
                    if let Some(uid) = pod.uid() {
                        if let Err(err) =
                            await_condition(pods.clone(), &name, is_deleted(&uid)).await
                        {
                            eprintln!("{err}");
                        }
                    }
                }

                Ok(either::Either::Right(status)) => {
                    println!("DELETE STATUS {status}");
                }

                Err(err) => match err {
                    kube::Error::Api(status) => eprintln!("Error from server: {status}"),
                    _ => eprintln!("{err}"),
                },
            }
        }
    }

    Ok(())
}
