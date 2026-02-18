use bytes::{BufMut, BytesMut};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::codec::{MAX_SIZE, PREFIX_SIZE, TUNCodec, encode, parse_packet};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, u32};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt},
    net::{TcpListener, tcp::OwnedWriteHalf},
    sync::Mutex,
};
use tokio_util::codec::Decoder;

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let (network, mask) =
        kubectl_tunnel::utils::parse_cidr_mask(&args.network).expect("Invalid network");
    let network = Ipv4Addr::from(u32::from(network) & u32::from(mask));
    println!("Network {} Mask {}", network, mask);
    let available_hosts = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));
    let tunnels = Arc::new(Mutex::new(HashMap::<
        Ipv4Addr,
        tokio_util::codec::FramedWrite<OwnedWriteHalf, TUNCodec>,
    >::new()));

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

                        let mut lock = tunnels.lock().await;
                        let dst = Ipv4Addr::from_octets(
                            packet[16..20].try_into().expect("Invalid header"),
                        );
                            
                        if let Some(dst) = lock.get_mut(&dst) {
                            let _ = dst.send(packet).await;
                        }

                        drop(lock);
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
        println!("Client connected {}", addr);

        let mut lock = available_hosts.lock().await;
        let remote = lock.pop().or_else(|| {
            if next_host + 1 > num_of_hosts {
                return None;
            }
            {
                next_host += 1;
                return Some(Ipv4Addr::from(u32::from(network) + next_host));
            }
        });
        drop(lock);

        match remote {
            Some(remote) => {
                let tunnels = tunnels.clone();
                let available_hosts = available_hosts.clone();
                let tun_writer = tun_writer.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();

                    println!("Assigned host {}", remote);
                    let mut buf = Vec::with_capacity(14);
                    buf.extend_from_slice(&remote.to_bits().to_be_bytes());
                    buf.extend_from_slice(&mask.to_bits().to_be_bytes());
                    buf.extend_from_slice(&local.to_bits().to_be_bytes());
                    buf.extend_from_slice(&mtu.to_be_bytes());

                    let _ = writer.write(&buf).await;

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
                        let mut tunnels = tunnels.lock().await;

                        tunnels.insert(remote, writer);
                        drop(tunnels);
                    }
                    while let Some(packet) = reader.next().await {
                        if let Ok(packet) = packet {
                            let mut tunnels = tunnels.lock().await;
                            let dst = Ipv4Addr::from_octets(
                                packet[16..20].try_into().expect("Invalid header"),
                            );
                            if let Some(dst) = tunnels.get_mut(&dst) {
                                let _ = dst.send(packet).await;
                            } else {
                                let mut lock = tun_writer.lock().await;
                                let _ = lock.write(&encode(packet)?).await;
                                drop(lock);
                            }
                            drop(tunnels);
                        }
                       
                    }

                    println!("Client disconnected... ");
                    available_hosts.lock().await.push(remote);
                    return Ok::<(), std::io::Error>(());
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
