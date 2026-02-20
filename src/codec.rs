use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use packet::{Packet, Size};
use tokio_util::codec::{Decoder, Encoder};

pub struct TUNCodec(pub u16, pub bool);

fn decode_ipv4(prefix_len: usize, src: &mut BytesMut) -> Result<Option<Bytes>, packet::Error> {
    if src.len() < prefix_len + 20 {
        return Ok(None);
    }

    let ihl = (src[prefix_len + 0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return Err(packet::Error::InvalidValue);
    }

    if src.len() < ihl + prefix_len {
        println!("src.len() < ihl + prefix_len");
        return Ok(None);
    }

    let total_len = u16::from_be_bytes([src[prefix_len + 2], src[prefix_len + 3]]) as usize;
    if total_len < ihl {
        println!("total_len < ihl");
        return Err(packet::Error::InvalidValue);
    }

    if src.len() < prefix_len + total_len {
        return Ok(None);
    }

    // Zero-copy split of exactly one packet
    if prefix_len > 0 {
        src.advance(prefix_len);
    }
    let packet = src.split_to(total_len).freeze();
    // let packet = packet::ip::Packet::unchecked(packet);
    // Ok(Some(packet.to_owned()))
    Ok(Some(packet))
}

fn decode_ipv6(prefix_len: usize, src: &mut BytesMut) -> Result<Option<Bytes>, packet::Error> {
    if src.len() < prefix_len + 40 {
        return Ok(None);
    }

    let payload_len = u16::from_be_bytes([src[prefix_len + 4], src[prefix_len + 5]]) as usize;
    let total_len = 40 + payload_len;

    if src.len() < prefix_len + total_len {
        return Ok(None);
    }

    let packet = src.split_to(prefix_len + total_len).freeze();
    /* let packet = packet::ip::Packet::new(packet)?;
    Ok(Some(packet.to_owned()))
     */
    Ok(Some(packet))
}

pub fn ipv4_header_valid(header: &[u8]) -> bool {
    let mut sum: u32 = 0;

    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u16 == 0xFFFF
}

pub fn decode(prefix_len: usize, src: &mut BytesMut) -> Result<Option<Bytes>, packet::Error> {
    if src.is_empty() {
        return Ok(None);
    }

    let version = src[prefix_len + 0] >> 4;

    match version {
        4 => decode_ipv4(prefix_len, src),
        6 => decode_ipv6(prefix_len, src),
        _ => {
            println!("ERR {:2x?}", &src[0..src.len()]);
            Err(packet::Error::InvalidPacket)
        }
    }
}

pub fn parse_packet(
    prefix_len: usize,
    src: &mut BytesMut,
) -> Result<Option<Bytes>, std::io::Error> {
    match decode(prefix_len, src) {
        Ok(Some(val)) => {
            if let 4 = val[0] >> 4 {
                let ihl = (val[0] & 0x0f) as usize * 4;
                let checksum = u16::from_be_bytes([val[10], val[11]]);

                let valid_checksum = ipv4_header_valid(&val[0..ihl]);
                let total_len = u16::from_be_bytes([val[2], val[3]]) as usize;
                if total_len != val.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid packet length",
                    ));
                }
                if !valid_checksum {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid checksum",
                    ));
                }

                return Ok(Some(val));
            }

            Ok(None)
        }
        Ok(None) => Ok(None),
        Err(err) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
    }
}

pub fn encode(src: Bytes) -> Result<Bytes, std::io::Error> {
    let mut dst = BytesMut::with_capacity(src.len());
    #[cfg(target_os = "macos")]
    {
        let frame = match src[0] >> 4 {
            4 => 0x0002,
            6 => 0x001e,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid protocol",
                ));
            }
        };
        dst.put_u32(frame);
    }

    dst.put(src);

    return Ok(dst.freeze());
}
impl Decoder for TUNCodec {
    type Item = Bytes;
    type Error = packet::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let prefix_len = if self.1 { PREFIX_SIZE } else { 0 };
        if src.is_empty() {
            return Ok(None);
        }

        let version = src[prefix_len + 0] >> 4;

        match version {
            4 => decode_ipv4(prefix_len, src), //.map(|b| b.map(|b| packet::ip::Packet::new(b).expect("").to_owned())),
            6 => decode_ipv6(prefix_len, src), //.map(|b| b.map(|b| packet::ip::Packet::new(b).expect("").to_owned())),
            _ => {
                println!("ERR {:2x?}", &src[0..src.len()]);
                Err(packet::Error::InvalidPacket)
            }
        }
    }
}

impl Encoder<Bytes> for TUNCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        #[cfg(target_os = "macos")]
        if self.1 {
            let frame = match item[0] >> 4 {
                4 => 0x0002,
                6 => 0x001e,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid protocol",
                    ));
                }
            };
            dst.put_u32(frame);
        }

        dst.put(item);

        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
pub const PREFIX_SIZE: usize = 0;
#[cfg(target_os = "macos")]
pub const PREFIX_SIZE: usize = 4;

pub const MAX_SIZE: usize = 1024 * 96;
