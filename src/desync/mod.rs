//! DPI desynchronization strategies.

pub mod tls;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub use tls::TlsDesyncer;

use crate::config::UdpOptions;
use crate::logging::Logger;
use crate::packet::{HopTracker, PacketWriter};

/// Sends low-TTL fake datagrams ahead of a new UDP flow.
pub struct UdpDesyncer {
    writer: Option<Arc<PacketWriter>>,
    tracker: Option<Arc<HopTracker>>,
}

impl UdpDesyncer {
    pub fn new(writer: Option<Arc<PacketWriter>>, tracker: Option<Arc<HopTracker>>) -> Self {
        Self { writer, tracker }
    }

    pub fn prepare_hop_track(&self, addrs: &[IpAddr], opts: &UdpOptions) {
        if let Some(t) = &self.tracker {
            if opts.fake_count > 0 {
                t.register(addrs);
            }
        }
    }

    /// `local` is the source address of the real flow (the outbound socket).
    pub fn desync(&self, local: SocketAddr, remote: SocketAddr, opts: &UdpOptions, logger: &Logger) -> usize {
        let logger = logger.local("udp_desync");
        let (Some(w), Some(t)) = (&self.writer, &self.tracker) else {
            return 0;
        };
        if opts.fake_count == 0 {
            return 0;
        }
        let ttl = t.optimal_ttl(remote.ip());
        let mut total = 0;
        for _ in 0..opts.fake_count {
            match w.write_udp(local, remote, ttl, &opts.fake_packet) {
                Ok(n) => total += n,
                Err(e) => warn!(logger, ["err" => e], "failed to send fake packet"),
            }
        }
        if total > 0 {
            debug!(logger, ["count" => opts.fake_count, "bytes" => total, "ttl" => ttl], "sent fake packets");
        }
        total
    }
}
