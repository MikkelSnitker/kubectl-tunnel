use std::{io::Write, net::Ipv4Addr, os::unix::process::CommandExt, str::FromStr};

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
    net::TcpStream,
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
    /// List something
    Connect {
        name: String,
    },

    Delete {
        name: String,
    },

    Create {
        file_name: String,
    },
}

fn parse_cidr_mask(
    input: &str,
) -> std::result::Result<(std::net::Ipv4Addr, std::net::Ipv4Addr), &'static str> {
    let (address_str, prefix_str) = input.split_once('/').ok_or("missing '/' in CIDR")?;

    let prefix: u8 = prefix_str.parse().map_err(|_| "invalid prefix")?;

    if prefix > 32 {
        return Err("prefix out of range");
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    Ok((
        std::net::Ipv4Addr::from_str(address_str).expect("Invalid address"),
        std::net::Ipv4Addr::from(mask),
    ))
}

fn netmask_to_prefix(mask: Ipv4Addr) -> std::result::Result<u8, &'static str> {
    let value = u32::from(mask);

    // Count number of leading 1 bits
    let prefix = value.leading_ones() as u8;

    // Reconstruct mask from prefix to validate contiguity
    let reconstructed = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    if value != reconstructed {
        return Err("non-contiguous netmask");
    }

    Ok(prefix)
}

fn prefix_to_netmask(prefix: u8) -> std::result::Result<std::net::Ipv4Addr, &'static str> {
    if prefix > 32 {
        return Err("invalid IPv4 prefix");
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    Ok(std::net::Ipv4Addr::from(mask))
}

async fn create_tunnel(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    dev: AsyncDevice,
) -> Result<()> {
    let (mut tun_writer, mut tun_reader) = dev.split()?;
    let (mut tcp_reader, mut tcp_writer) = tokio::io::split(stream);
    let task_a = async {
        let mut buf = [0u8; 4096];
        loop {
            let len = tcp_reader.read(&mut buf).await?;
            if len == 0 {
                break;
            }

            if buf[2] == 0x08 && buf[3] == 0x00 {
                buf[2] = 0x00;
                buf[3] = 0x02;
            }
            tun_writer.write_all(&buf[0..len]).await?;
            tun_writer.flush().await?;
        }

        Ok::<(), std::io::Error>(())
    };

    let task_b = async {
        let mut buf = [0u8; 4096];
        loop {
            let len = tun_reader.read(&mut buf).await?;
            if len == 0 {
                break;
            }

            if buf[2] == 00 && buf[3] == 0x02 {
                buf[2] = 0x08;
                buf[3] = 0x00;
            }

            tcp_writer.write(&buf[0..len]).await?;
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
                    kube::Error::Api(status) => eprintln!("{}", status),
                    _ => eprintln!("{}", err),
                };

                return Ok(());
            }

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
                        let (addr, mask) = parse_cidr_mask(&address).unwrap();
                        let routes =
                            pod.annotations()
                                .get("tunnel/routes")
                                .map_or(vec![], |routes| {
                                    routes.lines().map(str::to_owned).collect()
                                    //routes.split("\n").collect::<Vec<_>>()
                                });

                        let dns = pod.annotations().get("tunnel/dns").map(|x| x.to_owned());
                        (addr, mask, port, routes, dns)
                    }

                    Ok(None) => {
                        eprintln!("Pod not found {}", &name);
                        return Ok(());
                    }

                    Err(err) => {
                        eprintln!("{}", err);
                        return Ok(());
                    }
                };

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
            println!("APPLYING ROUTES: \n");
            for route in routes {
               let _ = std::process::Command::new("route")
                    .args(vec![
                        "-n",
                        "add",
                        "-net",
                        &route,
                        "-interface",
                        &dev.tun_name().unwrap(),
                    ])
                    .status();
            }
            
            if let Some(dns) = dns {
                let path = std::path::Path::new("/etc/resolver/svc.cluster.local");

                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).expect("Unable to create dns resolver folder" ); // creates full directory chain
                }

                let mut file = std::fs::File::create(path).expect("Unable to create dns resolver");
                println!("\n\nAPPLYING DNS: \n\ncat <<EOF >> /etc/resolver/svc.cluster.local\n{}\nEOF", dns);
                file.write_all(dns.as_bytes()).expect("Unable to write resolver");
            }

            let mut forwarder = pods.portforward(&name, &[port]).await?;
            if let Some(upstream_conn) = forwarder.take_stream(port) {
                let a = create_tunnel(upstream_conn, dev).await;
                println!("CONNECTED {:?}", a);
            } else {
                println!("ERR")
                //println!("POD {:?}", pod);
            }
        }

        Commands::Create { file_name } => {
            let pods: Api<Pod> = Api::default_namespaced(client);
            let mut file = std::fs::File::open("./pod.yaml").unwrap();
            let pod: Pod = serde_yaml::from_reader(file).unwrap();
            match pods.create(&PostParams::default(), &pod).await {
                Ok(pod) => println!("{:?}", pod),
                Err(err) => {
                    println!("{:?}", err)
                }
            }
            //let cfg = s.annotations().get("tunnel/config");
        }

        Commands::Delete { name } => {
            let pods: Api<Pod> = Api::default_namespaced(client);
            match pods.delete(&name, &DeleteParams::default()).await {
                Ok(either::Either::Left(pod)) => {
                    println!("pod \"{}\" deleted from default namespace", &name);
                    if let Some(uid) = pod.uid() {
                        if let Err(err) =
                            await_condition(pods.clone(), &name, is_deleted(&uid)).await
                        {
                            eprintln!("{}", err);
                        }
                    }
                }

                Ok(either::Either::Right(status)) => {
                    println!("DELETE STATUS {}", status);
                    // println!("pod \"{}\" deleted from default namespace", &name)

                    //      await_condition(pods.clone(), &name, is_deleted(s.) )
                }

                Err(err) => match err {
                    kube::Error::Api(status) => println!("Error from server: {}", status),
                    _ => println!("{}", err),
                },
            }
        }
    }

    Ok(())
}
