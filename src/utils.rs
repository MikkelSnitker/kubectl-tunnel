use std::str::FromStr;

pub fn linux_pi_proto(buf: &[u8]) -> Option<u16> {
    if buf.len() < 4 { return None; }
    Some(u16::from_be_bytes([buf[2], buf[3]])) // proto in network order
}

pub fn macos_utun_af(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 { return None; }
    Some(u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]])) // host order
}

#[derive(Debug)]
pub enum HeaderConvError {
    TooShort,
    UnknownAf(u32),
    UnknownProto(u16),
}

pub fn macos_to_linux(buf: &mut [u8]) -> Result<(), HeaderConvError> {
    if buf.len() < 4 {
        return Err(HeaderConvError::TooShort);
    }

    // Map AF -> EtherType (Linux tun_pi proto field)
    match (buf[2], buf[3]) {
        (0x00, 0x02) => {
            // AF_INET  -> IPv4 EtherType
            buf[2] = 0x08;
            buf[3] = 0x00;
        }
        (0x00, 0x1e) => {
            // AF_INET6 -> IPv6 EtherType
            buf[2] = 0x86;
            buf[3] = 0xdd;
        }
         _ => return Err(HeaderConvError::UnknownProto(( (buf[2] as u16) << 8 ) + buf[3] as u16))
    }

    Ok(())
}

pub fn linux_to_macos(buf: &mut [u8]) -> Result<(), HeaderConvError> {
    if buf.len() < 4 {
        return Err(HeaderConvError::TooShort);
    }

     // Map EtherType -> macOS address family
    match (buf[2], buf[3]) {
        (0x08, 0x00) => {
            // IPv4 -> AF_INET
            buf[2] = 0x00;
            buf[3] = 0x02;
        }

        (0x86, 0xdd) => {
            // IPv6 -> AF_INET6
            buf[2] = 0x00;
            buf[3] = 0x1e;
        }

        _ => return Err(HeaderConvError::UnknownProto(( (buf[2] as u16) << 8 ) + buf[3] as u16))
    }
    Ok(())
}

pub fn parse_cidr_mask(
    input: &str,
) -> std::result::Result<(std::net::Ipv4Addr, std::net::Ipv4Addr), &'static str> {
    let (address_str, prefix_str) = input.split_once('/').ok_or("missing '/' in CIDR")?;

    let prefix: u8 = prefix_str.parse().map_err(|_| "invalid prefix")?;

    if prefix > 32 {
        return Err("prefix out of range");
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    Ok((
        std::net::Ipv4Addr::from_str(address_str).expect("Invalid address"),
        std::net::Ipv4Addr::from(mask),
    ))
}
