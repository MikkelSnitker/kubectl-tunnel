use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::{codec::{MAX_SIZE, PREFIX_SIZE, TUNCodec, encode, parse_packet}, utils::create_device};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp::OwnedReadHalf},
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
    let (mut reader, writer) = stream.into_split();

    let mut dev = create_device().expect("Unable to create TUN");
    if let Ok(config) = kubectl_tunnel::utils::handle_handshake(&mut reader).await {
        dev.configure(&config)?;
        println!("TUN {}", dev.tun_name().unwrap());
        let mtu = dev.mtu().unwrap();

        let mut reader = tokio_util::codec::FramedRead::new(reader, TUNCodec(mtu, false));
        let mut writer = tokio_util::codec::FramedWrite::new(writer, TUNCodec(mtu, false));
        let (mut tun_writer, mut tun_reader) = dev.split()?;

        tokio::spawn(async move {
            let mut bufa = BytesMut::with_capacity(MAX_SIZE);
            let mut buf = [0x0u8; MAX_SIZE];

            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(len) => {
                        bufa.put_slice(&buf[0..len]);

                        while let Ok(Some(packet)) = parse_packet(PREFIX_SIZE, &mut bufa) {
                            let _ = writer.send(packet).await;
                        }
                    }

                    Err(err) => {
                        eprintln!("{err}");
                    }
                };
            }
        });

        while let Some(packet) = reader.next().await {
            match packet {
                Ok(packet) => {
                    let _ = tun_writer.write(&encode(packet)?).await;
                }
                Err(err) => {
                    eprintln!("Error {err}");
                }
            }
        }
    }
    Ok(())
}
