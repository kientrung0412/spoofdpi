//! Building and parsing raw IPv4/IPv6 packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn pseudo_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
            acc += proto as u32;
            acc += len as u32;
        }
        _ => {
            acc = sum16(&v6(src).octets(), acc);
            acc = sum16(&v6(dst).octets(), acc);
            acc += (len as u32) >> 16;
            acc += (len as u32) & 0xffff;
            acc += proto as u32;
        }
    }
    acc
}

fn v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Normalizes v4-mapped addresses so both ends use the same family.
fn families(src: SocketAddr, dst: SocketAddr) -> (IpAddr, IpAddr) {
    match (v4(src.ip()), v4(dst.ip())) {
        (Some(s), Some(d)) => (IpAddr::V4(s), IpAddr::V4(d)),
        _ => (IpAddr::V6(v6(src.ip())), IpAddr::V6(v6(dst.ip()))),
    }
}

fn ip_header(src: IpAddr, dst: IpAddr, proto: u8, ttl: u8, l4_len: usize) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + l4_len;
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            h[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
            h[8] = ttl;
            h[9] = proto;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let csum = fold(sum16(&h, 0));
            h[10..12].copy_from_slice(&csum.to_be_bytes());
            h
        }
        _ => {
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
            h[6] = proto;
            h[7] = ttl;
            h[8..24].copy_from_slice(&v6(src).octets());
            h[24..40].copy_from_slice(&v6(dst).octets());
            h
        }
    }
}

/// A TCP PSH|ACK segment with random sequence numbers, as used for fake
/// ClientHello packets.
pub fn build_tcp(src: SocketAddr, dst: SocketAddr, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let (s, d) = families(src, dst);
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    tcp[8..12].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x18; // PSH | ACK
    tcp[14..16].copy_from_slice(&12345u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    let csum = fold(sum16(&tcp, pseudo_sum(s, d, PROTO_TCP, tcp.len())));
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut pkt = ip_header(s, d, PROTO_TCP, ttl, tcp.len());
    pkt.extend_from_slice(&tcp);
    pkt
}

pub fn build_udp(src: SocketAddr, dst: SocketAddr, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let (s, d) = families(src, dst);
    let len = 8 + payload.len();
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    udp.extend_from_slice(payload);
    let mut csum = fold(sum16(&udp, pseudo_sum(s, d, PROTO_UDP, len)));
    if csum == 0 {
        csum = 0xffff;
    }
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    let mut pkt = ip_header(s, d, PROTO_UDP, ttl, udp.len());
    pkt.extend_from_slice(&udp);
    pkt
}

/// The fields of a received packet needed for hop counting.
#[derive(Debug, PartialEq, Eq)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub proto: u8,
    /// TCP flags byte when `proto` is TCP and the header is present.
    pub tcp_flags: Option<u8>,
}

pub fn parse_ip(pkt: &[u8]) -> Option<IpInfo> {
    let version = pkt.first()? >> 4;
    let (src, dst, ttl, proto, l4) = match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
            let l4 = if frag == 0 { pkt.get(ihl..) } else { None };
            (
                IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                pkt[8],
                pkt[9],
                l4,
            )
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            (
                IpAddr::V6(s.into()),
                IpAddr::V6(d.into()),
                pkt[7],
                pkt[6],
                pkt.get(40..),
            )
        }
        _ => return None,
    };
    let tcp_flags = if proto == PROTO_TCP {
        l4.and_then(|l| l.get(13)).copied()
    } else {
        None
    };
    Some(IpInfo {
        src,
        dst,
        ttl,
        proto,
        tcp_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_v4_checksums_verify() {
        let src: SocketAddr = "192.168.1.10:50000".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let pkt = build_tcp(src, dst, 7, b"hello");
        assert_eq!(pkt.len(), 20 + 20 + 5);
        // IP header checksum over the header must fold to zero.
        assert_eq!(fold(sum16(&pkt[..20], 0)), 0);
        // TCP checksum including the pseudo header must fold to zero.
        let l4 = &pkt[20..];
        assert_eq!(
            fold(sum16(l4, pseudo_sum(src.ip(), dst.ip(), PROTO_TCP, l4.len()))),
            0
        );

        let info = parse_ip(&pkt).unwrap();
        assert_eq!(info.ttl, 7);
        assert_eq!(info.proto, PROTO_TCP);
        assert_eq!(info.tcp_flags, Some(0x18));
        assert_eq!(info.dst, dst.ip());
    }

    #[test]
    fn udp_v6_checksum_verifies() {
        let src: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let pkt = build_udp(src, dst, 3, b"quic");
        assert_eq!(pkt.len(), 40 + 8 + 4);
        let l4 = &pkt[40..];
        assert_eq!(
            fold(sum16(l4, pseudo_sum(src.ip(), dst.ip(), PROTO_UDP, l4.len()))),
            0
        );
        let info = parse_ip(&pkt).unwrap();
        assert_eq!((info.ttl, info.proto, info.tcp_flags), (3, PROTO_UDP, None));
    }

    #[test]
    fn mapped_addresses_use_ipv4() {
        let src: SocketAddr = "[::ffff:10.0.0.2]:1000".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let pkt = build_tcp(src, dst, 5, &[]);
        assert_eq!(pkt[0] >> 4, 4);
    }
}
