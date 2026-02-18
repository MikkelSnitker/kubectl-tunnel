use bytes::{Buf, BufMut, BytesMut};
use packet::{Packet};
use tokio_util::codec::{Decoder, Encoder};

#[cfg(not(target_os = "macos"))]
const PREFIX_SIZE: usize = 0;
#[cfg(target_os = "macos")]
const PREFIX_SIZE: usize = 4;

pub struct TUNCodec(pub u16, pub bool);

impl Decoder for TUNCodec {
    type Item = packet::ip::Packet<Vec<u8>>;
    type Error = packet::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 20 {
            return Ok(None);
        }
        let prefix_size = if self.1 { PREFIX_SIZE } else { 0 };
        let mut len = 0;  
        
        let result = match packet::ip::Packet::new(&mut src[prefix_size..]) {
            Ok(packet) => {
                
                let packet =packet.to_owned();
                len = packet.header().len() + packet.payload().len();
                if len == 0 {
                    len = src.len();
                }
                
                Ok(Some(packet))
            }
            Err(packet::Error::SmallBuffer) => Ok(None),
            Err(err) => {
                println!("ERR {:2x?}", &src[0..src.len()]);
                Err(err)
            } ,
        };
  
        src.advance(prefix_size + len);
        return result;
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
