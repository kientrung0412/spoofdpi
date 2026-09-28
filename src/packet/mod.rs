//! Raw packet IO for fake packets and hop-count learning.
//!
//! * Windows: WinDivert (layer-3 injection and sniffing, no MAC needed).
//! * Linux: raw IPv4 sockets.
//! * Other platforms: unsupported; fake packets are disabled.

pub mod craft;
pub mod hop;
#[cfg(windows)]
mod windivert;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub use hop::HopTracker;

use crate::logging::Logger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniffKind {
    Tcp,
    Udp,
}

/// Injects crafted IP packets.
pub struct PacketWriter {
    #[cfg(windows)]
    inner: windivert::WinDivert,
    #[cfg(target_os = "linux")]
    inner: socket2::Socket,
}

impl PacketWriter {
    #[cfg(windows)]
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            inner: windivert::WinDivert::sender()?,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn open() -> io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        const IPPROTO_RAW: i32 = 255;
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        Ok(Self { inner: sock })
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub fn open() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fake packets are not supported on this platform",
        ))
    }

    fn send(&self, pkt: &[u8], dst: IpAddr) -> io::Result<()> {
        #[cfg(windows)]
        {
            let _ = dst;
            self.inner.send_outbound(pkt)
        }
        #[cfg(target_os = "linux")]
        {
            if pkt.first().map(|b| b >> 4) != Some(4) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 fake packets are not supported on this platform",
                ));
            }
            self.inner
                .send_to(pkt, &SocketAddr::new(dst, 0).into())
                .map(|_| ())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = (pkt, dst);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Sends a TCP segment carrying `payload` from `src` to `dst` with `ttl`.
    pub fn write_tcp(&self, src: SocketAddr, dst: SocketAddr, ttl: u8, payload: &[u8]) -> io::Result<usize> {
        self.send(&craft::build_tcp(src, dst, ttl, payload), dst.ip())?;
        Ok(payload.len())
    }

    pub fn write_udp(&self, src: SocketAddr, dst: SocketAddr, ttl: u8, payload: &[u8]) -> io::Result<usize> {
        self.send(&craft::build_udp(src, dst, ttl, payload), dst.ip())?;
        Ok(payload.len())
    }
}

/// Learns hop counts from inbound packets on a background thread:
/// SYN/ACKs for TCP, any datagram for UDP.
pub fn start_sniffer(kind: SniffKind, tracker: Arc<HopTracker>, logger: Logger) -> io::Result<()> {
    let source = open_sniffer(kind)?;
    let tag = match kind {
        SniffKind::Tcp => "tcp",
        SniffKind::Udp => "udp",
    };
    std::thread::Builder::new()
        .name(format!("sniff-{tag}"))
        .spawn(move || {
            let logger = logger.local("sniff");
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match source.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        error!(logger, ["err" => e], "packet capture stopped");
                        return;
                    }
                };
                let Some(info) = craft::parse_ip(&buf[..n]) else {
                    continue;
                };
                if !accept(kind, &info) {
                    continue;
                }
                trace!(logger, ["src" => info.src, "ttl" => info.ttl], "captured {tag} packet");
                tracker.observe(&logger, info.src, info.ttl, tag);
            }
        })?;
    Ok(())
}

fn accept(kind: SniffKind, info: &craft::IpInfo) -> bool {
    match kind {
        SniffKind::Tcp => {
            info.proto == craft::PROTO_TCP
                && info.tcp_flags.map(|f| f & 0x12 == 0x12).unwrap_or(false)
                && !(info.src.is_ipv4() && hop::is_local_ip(info.src))
        }
        SniffKind::Udp => {
            info.proto == craft::PROTO_UDP
                && !(info.src.is_ipv4() && (hop::is_local_ip(info.src) || !hop::is_local_ip(info.dst)))
        }
    }
}

#[cfg(windows)]
fn open_sniffer(kind: SniffKind) -> io::Result<windivert::WinDivert> {
    let filter = match kind {
        SniffKind::Tcp => "inbound and !loopback and tcp.Syn and tcp.Ack",
        SniffKind::Udp => "inbound and !loopback and udp",
    };
    windivert::WinDivert::sniffer(filter)
}

#[cfg(target_os = "linux")]
fn open_sniffer(kind: SniffKind) -> io::Result<RawRecv> {
    use socket2::{Domain, Protocol, Socket, Type};
    let proto = match kind {
        SniffKind::Tcp => Protocol::TCP,
        SniffKind::Udp => Protocol::UDP,
    };
    Ok(RawRecv(Socket::new(Domain::IPV4, Type::RAW, Some(proto))?))
}

#[cfg(target_os = "linux")]
struct RawRecv(socket2::Socket);

#[cfg(target_os = "linux")]
impl RawRecv {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        (&self.0).read(buf)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn open_sniffer(_kind: SniffKind) -> io::Result<NoRecv> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "packet capture is not supported on this platform",
    ))
}

#[cfg(not(any(windows, target_os = "linux")))]
struct NoRecv;

#[cfg(not(any(windows, target_os = "linux")))]
impl NoRecv {
    fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft::IpInfo;

    fn info(src: &str, dst: &str, proto: u8, flags: Option<u8>) -> IpInfo {
        IpInfo {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            ttl: 50,
            proto,
            tcp_flags: flags,
        }
    }

    #[test]
    fn sniff_filters() {
        use craft::{PROTO_TCP, PROTO_UDP};
        assert!(accept(
            SniffKind::Tcp,
            &info("8.8.8.8", "192.168.0.2", PROTO_TCP, Some(0x12))
        ));
        assert!(!accept(
            SniffKind::Tcp,
            &info("8.8.8.8", "192.168.0.2", PROTO_TCP, Some(0x10))
        ));
        assert!(!accept(
            SniffKind::Tcp,
            &info("192.168.0.1", "192.168.0.2", PROTO_TCP, Some(0x12))
        ));
        assert!(accept(
            SniffKind::Udp,
            &info("8.8.8.8", "192.168.0.2", PROTO_UDP, None)
        ));
        assert!(!accept(
            SniffKind::Udp,
            &info("8.8.8.8", "8.8.4.4", PROTO_UDP, None)
        ));
    }
}
