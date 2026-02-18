use std::net::Ipv4Addr;

use clap::Parser;
use futures::{SinkExt, StreamExt};
use kubectl_tunnel::codec::TUNCodec;
use tokio::{
    io::AsyncReadExt,
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
     
    if let Ok(dev) = kubectl_tunnel::utils::handle_handshake(&mut reader).await {
        println!("TUN {}", dev.tun_name().unwrap());
        let mtu = dev.mtu().unwrap();
        
        let mut reader = tokio_util::codec::FramedRead::new(reader, TUNCodec(mtu, false));
        let mut writer = tokio_util::codec::FramedWrite::new(writer, TUNCodec(mtu, false));
    

        let (tun_write, tun_read) = dev.split()?;

        let mut tun_reader = tokio_util::codec::FramedRead::new(tun_read, TUNCodec(mtu, true));
        let mut tun_writer = tokio_util::codec::FramedWrite::new(tun_write, TUNCodec(mtu, true));

        tokio::spawn(async move {
            while let Some(packet) = tun_reader.next().await {
                match packet {
                    Ok(packet) => {
                    /*    let data = [packet.header(), packet.payload()].concat();
                        let _ = writer.write(&data).await;
                         */
                        let _ = writer.send(packet).await;
                    }
                    Err(err) => {
                        eprintln!("Error {err}");
                        return Err(err);
                    }
                };
            }
            /*
            let mut buf = [0u8; 1500];

              while let Ok(len) = tun_reader.read(&mut buf).await {

                 #[cfg(target_os = "macos")]
                 let buf = &buf[4..]; // REMOVE FRAME INFO

                 let _ = writer.write(&buf[0..len]).await;
                 let _ = writer.flush().await;
             }*/

            Ok::<(), packet::Error>(())
        });

        while let Some(packet) = reader.next().await {
            match packet {
                Ok(packet) => {
                    let _ = tun_writer.send(packet).await;
                },
                Err(err) => {
                    eprintln!("Error {err}");
                },
            }
        }
    }
    Ok(())
}
