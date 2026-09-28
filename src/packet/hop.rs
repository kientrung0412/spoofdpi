//! Hop-count learning used to pick a TTL for fake packets that expires
//! after the DPI box but before the real server.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::logging::Logger;

const CAPACITY: usize = 8192;

pub struct HopTracker {
    default_ttl: u8,
    inner: Mutex<Inner>,
}

struct Inner {
    map: HashMap<IpAddr, (u8, u64)>,
    clock: u64,
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

impl HopTracker {
    pub fn new(default_ttl: u8) -> Self {
        Self {
            default_ttl,
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                clock: 0,
            }),
        }
    }

    /// Starts tracking addresses (keeping existing estimates).
    pub fn register(&self, addrs: &[IpAddr]) {
        let mut g = self.inner.lock().unwrap();
        for ip in addrs {
            g.clock += 1;
            let clock = g.clock;
            g.map
                .entry(normalize(*ip))
                .and_modify(|e| e.1 = clock)
                .or_insert((self.default_ttl, clock));
        }
        if g.map.len() > CAPACITY {
            evict(&mut g);
        }
    }

    /// TTL for fake packets towards `ip`: one less than the estimated hops.
    pub fn optimal_ttl(&self, ip: IpAddr) -> u8 {
        let mut g = self.inner.lock().unwrap();
        g.clock += 1;
        let clock = g.clock;
        let hops = match g.map.get_mut(&normalize(ip)) {
            Some(e) => {
                e.1 = clock;
                e.0
            }
            None => 255,
        };
        hops.max(2) - 1
    }

    /// Records the TTL left on a packet received from `src`. Only already
    /// registered addresses are updated.
    pub fn observe(&self, logger: &Logger, src: IpAddr, ttl_left: u8, kind: &str) {
        let nhops = estimate_hops(ttl_left);
        let mut g = self.inner.lock().unwrap();
        if let Some(e) = g.map.get_mut(&normalize(src)) {
            if e.0 != nhops {
                trace!(logger, ["from" => src, "nhops" => nhops, "ttlLeft" => ttl_left], "ttl({kind}) update");
            }
            e.0 = nhops;
        }
    }

    #[cfg(test)]
    fn get(&self, ip: IpAddr) -> Option<u8> {
        self.inner.lock().unwrap().map.get(&ip).map(|e| e.0)
    }
}

/// Drops the least recently used tenth of the entries.
fn evict(g: &mut Inner) {
    let mut stamps: Vec<u64> = g.map.values().map(|e| e.1).collect();
    stamps.sort_unstable();
    let cutoff = stamps[stamps.len() / 10];
    g.map.retain(|_, e| e.1 > cutoff);
}

/// Estimates hops from the remaining TTL, assuming the sender started from
/// the nearest common initial TTL (64, 128 or 255), like GoodbyeDPI.
pub fn estimate_hops(ttl_left: u8) -> u8 {
    let initial: u8 = if ttl_left <= 64 {
        64
    } else if ttl_left <= 128 {
        128
    } else {
        255
    };
    initial - ttl_left
}

/// Private, loopback and link-local IPv4 ranges.
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || o[0] == 127
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hops() {
        assert_eq!(estimate_hops(56), 8);
        assert_eq!(estimate_hops(64), 0);
        assert_eq!(estimate_hops(118), 10);
        assert_eq!(estimate_hops(250), 5);
    }

    #[test]
    fn local_ranges() {
        for ip in [
            "10.1.1.1",
            "127.0.0.1",
            "172.20.0.1",
            "192.168.0.5",
            "169.254.1.1",
        ] {
            assert!(is_local_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1"] {
            assert!(!is_local_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn tracker_flow() {
        let t = HopTracker::new(8);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        let other: IpAddr = "1.1.1.1".parse().unwrap();
        let logger = Logger::new("test");

        // Unregistered addresses use the maximum TTL and are not learned.
        t.observe(&logger, other, 50, "tcp");
        assert_eq!(t.get(other), None);
        assert_eq!(t.optimal_ttl(other), 254);

        t.register(&[ip]);
        assert_eq!(t.optimal_ttl(ip), 7);
        t.observe(&logger, ip, 52, "tcp"); // 12 hops
        assert_eq!(t.optimal_ttl(ip), 11);
        // Re-registering keeps the learned estimate.
        t.register(&[ip]);
        assert_eq!(t.get(ip), Some(12));
        // Nearby servers never get a TTL below 1.
        t.observe(&logger, ip, 64, "tcp");
        assert_eq!(t.optimal_ttl(ip), 1);
    }

    #[test]
    fn eviction_bounds_size() {
        let t = HopTracker::new(8);
        for i in 0..(CAPACITY as u32 + 100) {
            t.register(&[IpAddr::V4(i.into())]);
        }
        assert!(t.inner.lock().unwrap().map.len() <= CAPACITY);
    }
}
