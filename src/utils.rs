use std::{net::Ipv4Addr, str::FromStr};

use tokio::{io::AsyncReadExt, net::tcp::OwnedReadHalf};
use tun::{AsyncDevice, ToAddress};

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

pub fn create_device() -> std::result::Result<AsyncDevice, tun::Error> {
    let mut config = tun::Configuration::default();
       
   config
        .address(Ipv4Addr::LOCALHOST)
        .netmask("255.255.255.255")
        .destination(Ipv4Addr::LOCALHOST)
        .mtu(1500)
        .down();

    config.platform_config(|config| {
        // requiring root privilege to acquire complete functions
        #[cfg(target_os = "linux")]
        config.ensure_root_privileges(true);

        config.packet_information(false);

        #[cfg(target_os = "macos")]
        config.enable_routing(true);
    });

    tun::create_as_async(&config)
}

pub async fn handle_handshake<T: tokio::io::AsyncRead + Unpin>(
    reader: &mut T,
) -> std::result::Result<tun::Configuration, tun::Error> {
    let mut handshake = [0u8; 14];
    let _len = reader.read_exact(&mut handshake).await?;
    let local = Ipv4Addr::from_octets(handshake[0..4].try_into().expect("Invalid bytes"));
    let mask = Ipv4Addr::from_octets(handshake[4..8].try_into().expect("Invalid bytes"));
    let remote = Ipv4Addr::from_octets(handshake[8..12].try_into().expect("Invalid bytes"));
    let mtu = u16::from_be_bytes(handshake[12..14].try_into().expect("Invalid bytes"));

    let mut config = tun::Configuration::default();
    config
        .address(local)
        .netmask(mask)
        .destination(remote)
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

    Ok(config)

  //  tun::create_as_async(&config)
}


use std::collections::BTreeMap;

/// Group domains by their "base" suffix (last 2 labels).
/// Examples:
/// - default.svc.cluster.local -> cluster.local
/// - c.gowish-devx.internal    -> gowish-devx.internal
/// - google.internal           -> google.internal
pub fn group_by_base_suffix<'a, I>(domains: I) -> BTreeMap<String, Vec<String>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for d in domains {
        let d = d.trim().trim_end_matches('.'); // tolerate trailing dot
        if d.is_empty() {
            continue;
        }

        let labels: Vec<&str> = d.split('.').filter(|s| !s.is_empty()).collect();

        // Base suffix = last 2 labels, or the whole thing if < 2 labels.
        let key = match labels.len() {
            0 => continue,
            1 => labels[0].to_string(),
            _ => format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]),
        };

        out.entry(key).or_default().push(d.to_string());
    }

    out
}
