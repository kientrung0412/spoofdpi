//! SOCKS5 (RFC 1928) wire format.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_FQDN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug, Clone)]
pub struct Request {
    pub cmd: u8,
    pub atyp: u8,
    pub fqdn: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Request> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("version mismatch: expected {VERSION:x}, got {:x}", header[0]),
        ));
    }
    let cmd = header[1];
    let atyp = header[3];
    let mut fqdn = String::new();
    let mut ip = None;
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            ip = Some(IpAddr::V4(Ipv4Addr::from(b)));
        }
        ATYP_FQDN => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            fqdn = String::from_utf8_lossy(&b).into_owned();
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            ip = Some(IpAddr::V6(Ipv6Addr::from(b)));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported atyp: {other}"),
            ))
        }
    }
    let port = r.read_u16().await?;
    Ok(Request {
        cmd,
        atyp,
        fqdn,
        ip,
        port,
    })
}

/// Writes a reply. IPv6 bind addresses are reported as IPv4 zero, matching
/// the behaviour clients of the original implementation relied on.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    rep: u8,
    bind: Option<SocketAddr>,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(10);
    buf.extend_from_slice(&[VERSION, rep, 0x00, ATYP_IPV4]);
    let (ip, port) = match bind {
        Some(SocketAddr::V4(a)) => (a.ip().octets(), a.port()),
        Some(SocketAddr::V6(a)) => (
            a.ip().to_ipv4_mapped().map(|v| v.octets()).unwrap_or([0; 4]),
            a.port(),
        ),
        None => ([0; 4], 0),
    };
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    w.write_all(&buf).await
}

/// Parses a SOCKS5 UDP request header. Returns `(host, port, payload)`.
pub fn parse_udp_header(b: &[u8]) -> Result<(String, u16, &[u8]), String> {
    if b.len() < 4 {
        return Err("header too short".into());
    }
    if b[0] != 0 || b[1] != 0 {
        return Err("invalid rsv".into());
    }
    if b[2] != 0 {
        return Err("fragmentation not supported".into());
    }
    let (host, pos) = match b[3] {
        ATYP_IPV4 => {
            if b.len() < 10 {
                return Err("header too short for ipv4".into());
            }
            (Ipv4Addr::new(b[4], b[5], b[6], b[7]).to_string(), 8)
        }
        ATYP_IPV6 => {
            if b.len() < 22 {
                return Err("header too short for ipv6".into());
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[4..20]);
            (Ipv6Addr::from(a).to_string(), 20)
        }
        ATYP_FQDN => {
            if b.len() < 5 {
                return Err("header too short for fqdn".into());
            }
            let l = b[4] as usize;
            if b.len() < 5 + l + 2 {
                return Err("header too short for fqdn data".into());
            }
            (String::from_utf8_lossy(&b[5..5 + l]).into_owned(), 5 + l)
        }
        other => return Err(format!("unsupported atyp: {other}")),
    };
    let port = u16::from_be_bytes([b[pos], b[pos + 1]]);
    Ok((host, port, &b[pos + 2..]))
}

pub fn udp_header_for(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(&[0, 0, 0]);
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_fqdn() {
        let mut data = vec![5, 1, 0, 3, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let req = read_request(&mut &data[..]).await.unwrap();
        assert_eq!(req.cmd, CMD_CONNECT);
        assert_eq!(req.fqdn, "example.com");
        assert_eq!(req.port, 443);
        assert!(req.ip.is_none());
    }

    #[tokio::test]
    async fn request_ipv4_and_reply() {
        let data = [5u8, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        let req = read_request(&mut &data[..]).await.unwrap();
        assert_eq!(req.ip, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(req.port, 80);

        let mut out = Vec::new();
        write_reply(&mut out, REP_SUCCESS, Some("127.0.0.1:1080".parse().unwrap()))
            .await
            .unwrap();
        assert_eq!(out, vec![5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn udp_header_roundtrip() {
        let addr: SocketAddr = "8.8.4.4:53".parse().unwrap();
        let mut pkt = udp_header_for(addr);
        pkt.extend_from_slice(b"payload");
        let (host, port, payload) = parse_udp_header(&pkt).unwrap();
        assert_eq!(host, "8.8.4.4");
        assert_eq!(port, 53);
        assert_eq!(payload, b"payload");
        assert!(parse_udp_header(&[0, 0, 1, 1]).is_err());
    }
}
