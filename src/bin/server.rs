use bytes::{BufMut, BytesMut};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::{
    codec::{MAX_SIZE, PREFIX_SIZE, TUNCodec, encode, parse_packet},
    handshake::{HandshakeRequest, HandshakeResponse},
};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration, u32};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt},
    net::{TcpListener, tcp::OwnedWriteHalf},
    sync::{Mutex, RwLock},
};

#[derive(Parser, Debug)]
#[command(name = "tunnel", about = "Tunnel server", version)]
pub struct Cli {
    /// Kubernetes context to use
    #[arg(long, default_value = "10.0.0.0/24")]
    pub network: String,

    #[arg(long, default_value = "1234")]
    pub port: u16,

    #[arg(long, default_value = "1400")]
    pub mtu: u16,
}

type Result<T> = std::result::Result<T, std::io::Error>;
type TunnelWriter = tokio_util::codec::FramedWrite<OwnedWriteHalf, TUNCodec>;
type TunnelMap = HashMap<Ipv4Addr, Option<TunnelWriter>>;

#[inline]
fn packet_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    Some(Ipv4Addr::from_octets(packet[16..20].try_into().ok()?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let (network, mask) =
        kubectl_tunnel::utils::parse_cidr_mask(&args.network).expect("Invalid network");
    let network = Ipv4Addr::from(u32::from(network) & u32::from(mask));
    println!("Network {} Mask {}", network, mask);
    let available_hosts = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));
    let tunnels = Arc::new(RwLock::new(TunnelMap::new()));

    let num_of_hosts = u32::MAX - u32::from(mask) - 1;
    let mut next_host = 1;

    println!("Number of hosts: {} next host: {}", num_of_hosts, next_host);
    let mtu = args.mtu;
    let local = Ipv4Addr::from(u32::from(network) + 1);
    let mut config = tun::Configuration::default();
    config
        .address(local)
        .netmask(mask)
        .destination(Ipv4Addr::from(u32::from(network) + num_of_hosts))
        .mtu(mtu)
        .up();

    config.platform_config(|config| {
        // requiring root privilege to acquire complete functions
        #[cfg(target_os = "linux")]
        config.ensure_root_privileges(true);

        config.packet_information(true);

        #[cfg(target_os = "macos")]
        config.enable_routing(true);
    });

    let dev = tun::create_as_async(&config).unwrap();

    let (tun_writer, mut tun_reader) = dev.split()?;

    let tun_writer = Arc::new(Mutex::new(tun_writer));

    let tunnel = tunnels.clone();
    tokio::spawn(async move {
        let tunnels = tunnel;

        let mut bufa = BytesMut::with_capacity(MAX_SIZE);
        let mut buf = [0x0u8; MAX_SIZE];

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(len) => {
                    bufa.put_slice(&buf[0..len]);

                    while let Ok(Some(packet)) = parse_packet(PREFIX_SIZE, &mut bufa) {
                        let Some(dst) = packet_destination(&packet) else {
                            continue;
                        };
                        let mut lock = tunnels.write().await;
                        if let Some(Some(dst)) = lock.get_mut(&dst) {
                            let _ = dst.send(packet).await;
                        }
                    }
                }

                Err(err) => {
                    eprintln!("{err}")
                }
            }
        }
    });

    let listener = TcpListener::bind(("0.0.0.0", args.port)).await?;

    while let Ok((mut stream, addr)) = listener.accept().await {
        println!("Client {} connected ", addr);

        let mut buf = [0u8; 6];
        let handshake = tokio::select! {
            _ = stream.read_exact(&mut buf) => {

                 match  HandshakeRequest::try_from(&buf[..]) {
                    Ok(request) if request.address == Ipv4Addr::from(0) => Some((request.version, None)),
                    Ok(request) => Some((request.version, Some(request.address))),
                    Err(_) => None

                }

            },

            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                None
            }
        };

        let mut remote = None;

        if let Some((_version, Some(address))) = handshake {
            let mut tunnels = tunnels.write().await;

            if !tunnels.contains_key(&address) {
                tunnels.insert(address, None);
                println!("Reuse address {}", address);
                remote = Some(address);
            }
        }

        if remote.is_none() {
            let mut lock = available_hosts.lock().await;
            remote = lock.pop().or_else(|| {
                if next_host + 1 > num_of_hosts {
                    return None;
                }
                {
                    next_host += 1;
                    return Some(Ipv4Addr::from(u32::from(network) + next_host));
                }
            });
        }

        match remote {
            Some(remote) => {
                let tunnels = tunnels.clone();
                let available_hosts = available_hosts.clone();
                let tun_writer = tun_writer.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();

                    println!("Assigned IP {} to {}", remote, addr);
                    let response = HandshakeResponse {
                        version: 1,
                        remote_address: local,
                        netmask: mask,
                        local_address: remote,
                        mtu_size: mtu,
                    };

                    let _ = writer.write_all(&Vec::<u8>::from(response)).await;

                    let writer = tokio_util::codec::FramedWrite::with_capacity(
                        writer,
                        TUNCodec(mtu, false),
                        MAX_SIZE,
                    );
                    let mut reader = tokio_util::codec::FramedRead::with_capacity(
                        reader,
                        TUNCodec(mtu, false),
                        MAX_SIZE,
                    );
                    {
                        let mut tunnels = tunnels.write().await;

                        tunnels.insert(remote, Some(writer));
                        drop(tunnels);
                    }
                    while let Some(packet) = reader.next().await {
                        if let Ok(packet) = packet {
                            let Some(dst) = packet_destination(&packet) else {
                                continue;
                            };
                            let mut tunnels = tunnels.write().await;
                            if let Some(Some(dst)) = tunnels.get_mut(&dst) {
                                let _ = dst.send(packet).await;
                            } else {
                                let mut lock = tun_writer.lock().await;
                                let _ = lock.write(&encode(packet)?).await;
                            }
                        }
                    }

                    {
                        let mut tunnels = tunnels.write().await;
                        tunnels.remove(&remote);
                    }

                    println!("Client {} disconnected... ", addr);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    {
                        let tunnels = tunnels.write().await;
                        if !tunnels.contains_key(&remote) {
                            println!("Release IP {}", remote);
                            available_hosts.lock().await.push(remote);
                        }
                    }
                    Ok::<(), std::io::Error>(())
                });
            }
            None => {
                println!("Network hosts exhausted");
                let _ = stream.shutdown().await;
            }
        }
    }

    Ok(())
}
