use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::codec::TUNCodec;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
    u32,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, WriteHalf},
    net::{TcpListener, tcp::OwnedWriteHalf},
    sync::Mutex,
};

#[derive(Parser, Debug)]
#[command(name = "tunnel", about = "Tunnel server", version)]
pub struct Cli {
    /// Kubernetes context to use
    #[arg(long, default_value = "10.0.0.0/24")]
    pub network: String,

    #[arg(long, default_value = "1234")]
    pub port: u16,
}

type Result<T> = std::result::Result<T, std::io::Error>;

async fn create_tunnel(host: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let (network, mask) =
        kubectl_tunnel::utils::parse_cidr_mask(&args.network).expect("Invalid network");
    let network = Ipv4Addr::from(u32::from(network) & u32::from(mask));
    println!("Network {} Mask {}", network, mask);
    let available_hosts = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));
    let tunnels = Arc::new(Mutex::new(HashMap::<Ipv4Addr, tokio_util::codec::FramedWrite<OwnedWriteHalf, TUNCodec>>::new()));

    let num_of_hosts = u32::MAX - u32::from(mask) - 1;
    let mut next_host = 1;

    println!("Number of hosts: {} next host: {}", num_of_hosts, next_host);
    let mtu = 1400;
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

        config.packet_information(false);

        #[cfg(target_os = "macos")]
        config.enable_routing(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    let (mut tun_writer, mut tun_reader) = dev.split()?;
    let mut tun_writer = tokio_util::codec::FramedWrite::new(tun_writer, TUNCodec(mtu, true));
    let mut tun_reader = tokio_util::codec::FramedRead::new(tun_reader, TUNCodec(mtu, true));
    let tun_writer = Arc::new(Mutex::new(tun_writer));
    let tunnel = tunnels.clone();
    tokio::spawn(async move {
        let tunnels = tunnel;
        loop {
            if let Some(packet) = tun_reader.next().await {
                if let Ok(packet::ip::Packet::V4(packet)) = packet {
                    let mut lock = tunnels.lock().await;
                    
                    if let Some(dst) = lock.get_mut(&packet.destination()) {
                      let _ = dst.send(packet::ip::Packet::V4(packet)).await;
                   // let _ = dst.write(&buf[0..len]).await;
                    
                    }  

                    drop(lock);
                }
            }
        }
     /* let mut buf = [0x0u8; 1500];  loop {
            match tun_reader.read(&mut buf).await {
                Ok(len) => {
                    if len < 20 {
                        continue;
                    }

                    let data = &buf[0..len];


                    #[cfg(target_os = "macos")]
                    let data = &buf[4..len];

                    let version = data[0] >> 4;
                    let ihl = (data[0] & 0x0F) * 4;
                    let protocol = data[9];
                    let src: [u8;4] = data[12..16].try_into().unwrap();
                    let dst: [u8;4] = data[16..20].try_into().unwrap();
                    let dst = Ipv4Addr::from_octets(dst);
                    let mut lock = tunnels.lock().await;
                    
                    if let Some(dst) = lock.get_mut(&dst) {
                     
                    let _ = dst.write(&buf[0..len]).await;
                    let _ = dst.flush().await;
                    }  
                    drop(lock);    

                    
                }

                Err(err) => {
                    eprintln!("{err}")
                }
            }
        } */

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
                    let mut buf =Vec::with_capacity(14);
                    buf.extend_from_slice(&remote.to_bits().to_be_bytes());
                    buf.extend_from_slice(&mask.to_bits().to_be_bytes());
                    buf.extend_from_slice(&local.to_bits().to_be_bytes());
                    buf.extend_from_slice(&mtu.to_be_bytes());
                    
                    
                    let _ = writer.write(&buf).await;
                  
                    let writer = tokio_util::codec::FramedWrite::new(writer, TUNCodec(mtu, false));
                    let mut reader = tokio_util::codec::FramedRead::new(reader, TUNCodec(mtu, false));
                    {
                    let mut tunnels = tunnels.lock().await;

                    tunnels.insert(remote, writer);
                    drop(tunnels);
                    }
                    while let Some(packet) = reader.next().await {
                        match packet {
                            Ok(packet::ip::Packet::V4(packet)) => {
                                let  mut tunnels = tunnels.lock().await;
                                if let Some(dst) = tunnels.get_mut(&packet.destination()) {
                                    let _ = dst.send(packet::ip::Packet::V4(packet)).await;
                                } else {
                                    let mut lock = tun_writer.lock().await;
                                    let _ = lock.send( packet::ip::Packet::V4(packet)).await;
                                    drop(lock);
                                }
                                drop(tunnels);
                            },
                            Ok(_) => {}
                            Err(err) => eprintln!("{err}")
                        }
                    }

                  /* 
                  let mut buf = [0u8; 1500];
                  loop {
                        let len = reader.read(&mut buf).await?;
                        if len == 0 {
                            break;
                        }

                        println!("TCP DATA {:2x?}", &buf[0..len]);

                        let mut lock = tun_writer.lock().await;
                        let _ = lock.write(&buf[0..len]).await;
                        let _ = lock.flush().await; 
                    }
*/ 
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
