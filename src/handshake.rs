use std::convert::{TryFrom, TryInto};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub version: u16,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub version: u16,
    pub local_address: Ipv4Addr,
    pub remote_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidLength { expected: usize, actual: usize },
}

//
// ---- HandshakeRequest ----
//

impl TryFrom<&[u8]> for HandshakeRequest {
    type Error = HandshakeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        const LEN: usize = 6;

        if bytes.len() != LEN {
            return Err(HandshakeError::InvalidLength {
                expected: LEN,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            version: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            address: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[2..6]).unwrap()),
        })
    }
}

impl From<HandshakeRequest> for Vec<u8> {
    fn from(req: HandshakeRequest) -> Self {
        let mut buf = Vec::with_capacity(6);
        buf.extend_from_slice(&req.version.to_be_bytes());
        buf.extend_from_slice(&req.address.octets());
        buf
    }
}

//
// ---- HandshakeResponse ----
//

impl TryFrom<&[u8]> for HandshakeResponse {
    type Error = HandshakeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        const LEN: usize = 16;

        if bytes.len() != LEN {
            return Err(HandshakeError::InvalidLength {
                expected: LEN,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            version: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            local_address: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[2..6]).unwrap()),
            remote_address: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[6..10]).unwrap()),
            netmask: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[10..14]).unwrap()),
            mtu_size: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
        })
    }
}

impl From<HandshakeResponse> for Vec<u8> {
    fn from(resp: HandshakeResponse) -> Self {
        let mut buf = Vec::with_capacity(16);

        buf.extend_from_slice(&resp.version.to_be_bytes());
        buf.extend_from_slice(&resp.local_address.octets());
        buf.extend_from_slice(&resp.remote_address.octets());
        buf.extend_from_slice(&resp.netmask.octets());
        buf.extend_from_slice(&resp.mtu_size.to_be_bytes());

        buf
    }
}
