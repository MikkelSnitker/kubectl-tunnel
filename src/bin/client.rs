use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::{
    codec::{MAX_SIZE, PREFIX_SIZE, TUNCodec, encode, parse_packet},
    utils::create_device,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tun::AbstractDevice;

type Result<T> = std::result::Result<T, std::io::Error>;

#[derive(Parser, Debug)]
#[command(name = "tunnel", about = "Tunnel client", version)]
pub struct Cli {
    /// Kubernetes context to use
    #[arg(long, default_value = "localhost")]
    pub server: String,

    #[arg(long, default_value = "1234")]
    pub port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let stream = TcpStream::connect((args.server, args.port)).await?;
    let (mut tcp_reader, mut tcp_writer) = stream.into_split();

    let mut dev = create_device().expect("Unable to create TUN");
    let address = match dev.address() {
        Ok(std::net::IpAddr::V4(addr)) => addr,
        _ => Ipv4Addr::LOCALHOST,
    };

    let config =
        match kubectl_tunnel::utils::handle_handshake(&mut tcp_reader, &mut tcp_writer, address)
            .await
        {
            Ok(config) => config,
            Err(err) => {
                eprintln!("Handshake failed: {err}");
                return Ok(());
            }
        };

    dev.configure(&config)?;
    let tun_name = dev.tun_name()?;
    println!("TUN {tun_name}");
    let mtu = dev.mtu()?;

    let mut net_reader = tokio_util::codec::FramedRead::new(tcp_reader, TUNCodec(mtu, false));
    let mut net_writer = tokio_util::codec::FramedWrite::new(tcp_writer, TUNCodec(mtu, false));
    let (mut tun_writer, mut tun_reader) = dev.split()?;

    tokio::spawn(async move {
        let mut bufa = BytesMut::with_capacity(MAX_SIZE);
        let mut buf = [0x0u8; MAX_SIZE];

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(len) => {
                    bufa.put_slice(&buf[0..len]);

                    while let Ok(Some(packet)) = parse_packet(PREFIX_SIZE, &mut bufa) {
                        let _ = net_writer.send(packet).await;
                    }
                }

                Err(err) => {
                    eprintln!("{err}");
                    break;
                }
            }
        }
    });

    while let Some(packet) = net_reader.next().await {
        match packet {
            Ok(packet) => {
                let _ = tun_writer.write_all(&encode(packet)?).await;
            }
            Err(err) => {
                eprintln!("Error {err}");
            }
        }
    }

    Ok(())
}
