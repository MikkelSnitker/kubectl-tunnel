use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use packet::{Packet, Size};
use tokio_util::codec::{Decoder, Encoder};

#[cfg(not(target_os = "macos"))]
const PREFIX_SIZE: usize = 0;
#[cfg(target_os = "macos")]
const PREFIX_SIZE: usize = 4;

pub struct TUNCodec(pub u16, pub bool);


fn decode_ipv4(prefix_len: usize, src: &mut BytesMut) -> Result<Option<packet::ip::Packet<Vec<u8>>>, packet::Error> {
    if src.len() < prefix_len + 20 {
        return Ok(None);
    }
    
    let ihl = (src[prefix_len + 0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return Err(packet::Error::InvalidValue);
    }

    if  src.len() < ihl + prefix_len {
        println!("src.len() < ihl + prefix_len");
        return Ok(None);
    }
    

    let total_len = u16::from_be_bytes([src[prefix_len + 2], src[prefix_len + 3]]) as usize;
    if total_len < ihl {
        println!("total_len < ihl");
        return Err(packet::Error::InvalidValue);
    }

    if src.len() < prefix_len + total_len {
        println!("src.len() < prefix_len + total_len , {} < {} + {}  (CAP {}){:2x?}", src.len(), prefix_len, total_len, src.capacity(), &src[..]);
        return Ok(None);
    }

    // Zero-copy split of exactly one packet
    if prefix_len > 0 {
        println!("ADVANCE {prefix_len}");
        src.advance(prefix_len);

        
    }
    println!("{} {}", total_len, src.len());
    
    let packet = src.split_to( total_len).freeze();
    
    let packet = packet::ip::Packet::new(packet)?;
    Ok(Some(packet.to_owned()))
}

fn decode_ipv6(prefix_len: usize, src: &mut BytesMut) -> Result<Option<packet::ip::Packet<Vec<u8>>>, packet::Error> {
    if src.len() < prefix_len + 40 {
        return Ok(None);
    }

    let payload_len = u16::from_be_bytes([src[prefix_len + 4], src[prefix_len + 5]]) as usize;
    let total_len = 40 + payload_len;

    if src.len() < prefix_len + total_len {
        return Ok(None);
    }

    let packet = src.split_to(prefix_len + total_len).freeze();
    let packet = packet::ip::Packet::new(packet)?;
    Ok(Some(packet.to_owned()))
}

impl Decoder for TUNCodec {
    type Item = packet::ip::Packet<Vec<u8>>;
    type Error = packet::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let prefix_len = if self.1 { PREFIX_SIZE } else { 0 };
         if src.is_empty() {
            return Ok(None);
        }

        
        
        let version = src[prefix_len + 0] >> 4;
        
        match version {
            4 => decode_ipv4(prefix_len, src),
            6 => decode_ipv6(prefix_len, src),
            _ => {
                println!("ERR {:2x?}", &src[0..src.len()]);
                std::thread::sleep(Duration::from_secs(60));
                Err(packet::Error::InvalidPacket)
            },
        }
        
    }
}

impl Encoder<packet::ip::Packet<Vec<u8>>> for TUNCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: packet::ip::Packet<Vec<u8>>, dst: &mut BytesMut) -> Result<(), Self::Error> {
         
                #[cfg(target_os = "macos")]
                if self.1 {
                    let frame = match item {
                        packet::ip::Packet::V4(_) => 0x0002,
                        packet::ip::Packet::V6(_) => 0x001e,
                    };
                    dst.put_u32(frame);
                }

                dst.put(item.header());
                dst.put(item.payload());
                Ok(())
           
        
    }
}
