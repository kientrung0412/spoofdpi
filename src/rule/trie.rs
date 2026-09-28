//! Domain and CIDR matchers.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::parse_cidr;

#[derive(Default)]
struct DomainNode<T> {
    children: HashMap<String, DomainNode<T>>,
    wildcard: Option<Box<DomainNode<T>>>,
    globstar: Option<Box<DomainNode<T>>>,
    value: Option<T>,
}

impl<T> DomainNode<T> {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            wildcard: None,
            globstar: None,
            value: None,
        }
    }
}

/// Trie keyed by reversed domain labels. Supports exact labels, `*` (one
/// label) and `**` (any number of labels). Both wildcards also match the apex.
/// Search prefers the most specific match: exact > `*` > `**`.
pub struct DomainTrie<T> {
    root: DomainNode<T>,
}

impl<T: Clone> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn split_domain(domain: &str) -> Vec<String> {
    let d = domain.trim_end_matches('.');
    if d.is_empty() {
        return Vec::new();
    }
    d.split('.').rev().map(|s| s.to_ascii_lowercase()).collect()
}

impl<T: Clone> DomainTrie<T> {
    pub fn new() -> Self {
        Self {
            root: DomainNode::new(),
        }
    }

    pub fn add(&mut self, pattern: &str, value: T) -> Result<(), String> {
        if pattern.is_empty() {
            return Err("empty domain pattern".into());
        }
        let mut n = &mut self.root;
        for seg in split_domain(pattern) {
            n = match seg.as_str() {
                "*" => n.wildcard.get_or_insert_with(|| Box::new(DomainNode::new())),
                "**" => n.globstar.get_or_insert_with(|| Box::new(DomainNode::new())),
                _ => n.children.entry(seg).or_insert_with(DomainNode::new),
            };
        }
        n.value = Some(value);
        Ok(())
    }

    pub fn search(&self, domain: &str) -> Option<T> {
        let segs = split_domain(domain);
        Self::search_node(&self.root, &segs)
    }

    fn search_node(n: &DomainNode<T>, segs: &[String]) -> Option<T> {
        if segs.is_empty() {
            if let Some(v) = &n.value {
                return Some(v.clone());
            }
            if let Some(v) = n.wildcard.as_ref().and_then(|w| w.value.clone()) {
                return Some(v);
            }
            return n.globstar.as_ref().and_then(|g| g.value.clone());
        }

        let (seg, rest) = (&segs[0], &segs[1..]);

        if let Some(child) = n.children.get(seg) {
            if let Some(v) = Self::search_node(child, rest) {
                return Some(v);
            }
        }
        if let Some(w) = &n.wildcard {
            if let Some(v) = Self::search_node(w, rest) {
                return Some(v);
            }
        }
        if let Some(g) = &n.globstar {
            if let Some(v) = &g.value {
                return Some(v.clone());
            }
            for i in 0..=segs.len() {
                if let Some(v) = Self::search_node(g, &segs[i..]) {
                    return Some(v);
                }
            }
        }
        None
    }
}

/// Longest-prefix match over IPv4 and IPv6 CIDRs.
pub struct CidrTrie<T> {
    /// Indexed by prefix length; maps masked network address to value.
    v4: Vec<HashMap<IpAddr, T>>,
    v6: Vec<HashMap<IpAddr, T>>,
}

impl<T: Clone> Default for CidrTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> CidrTrie<T> {
    pub fn new() -> Self {
        Self {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
        }
    }

    pub fn add(&mut self, cidr: &str, value: T) -> Result<(), String> {
        let (net, len) = parse_cidr(cidr).map_err(|e| format!("invalid cidr {cidr:?}: {e}"))?;
        let table = if net.is_ipv4() { &mut self.v4 } else { &mut self.v6 };
        table[len as usize].insert(net, value);
        Ok(())
    }

    pub fn search_ip(&self, ip: IpAddr) -> Option<T> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        let table = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        for len in (0..table.len()).rev() {
            if table[len].is_empty() {
                continue;
            }
            let net = crate::config::mask_ip(ip, len as u8);
            if let Some(v) = table[len].get(&net) {
                return Some(v.clone());
            }
        }
        None
    }

    #[cfg(test)]
    pub fn search(&self, key: &str) -> Option<T> {
        self.search_ip(key.parse().ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_search() {
        let mut t = DomainTrie::new();
        t.add("example.com", "exact").unwrap();
        t.add("*.google.com", "wildcard").unwrap();
        t.add("**.youtube.com", "globstar").unwrap();
        t.add("mail.google.com", "exact-over-wildcard").unwrap();

        let cases = [
            ("example.com", Some("exact")),
            ("maps.google.com", Some("wildcard")),
            ("google.com", Some("wildcard")),
            ("mail.google.com", Some("exact-over-wildcard")),
            ("a.youtube.com", Some("globstar")),
            ("foo.bar.youtube.com", Some("globstar")),
            ("youtube.com", Some("globstar")),
            ("a.b.google.com", None),
            ("naver.com", None),
            ("EXAMPLE.com.", Some("exact")),
        ];
        for (d, want) in cases {
            assert_eq!(t.search(d), want, "{d}");
        }
    }

    #[test]
    fn domain_overwrite_and_empty() {
        let mut t = DomainTrie::new();
        t.add("example.com", 1).unwrap();
        t.add("example.com", 2).unwrap();
        assert_eq!(t.search("example.com"), Some(2));
        assert!(t.add("", 3).is_err());
    }

    #[test]
    fn cidr_search() {
        let mut t = CidrTrie::new();
        t.add("192.168.1.0/24", "lan").unwrap();
        t.add("10.0.0.0/8", "private").unwrap();
        t.add("172.16.0.0/16", "wide").unwrap();
        t.add("172.16.1.0/24", "narrow").unwrap();
        t.add("2001:db8::/32", "v6").unwrap();

        assert_eq!(t.search("192.168.1.10"), Some("lan"));
        assert_eq!(t.search("10.0.0.5"), Some("private"));
        assert_eq!(t.search("172.16.1.5"), Some("narrow"));
        assert_eq!(t.search("172.16.2.5"), Some("wide"));
        assert_eq!(t.search("172.128.0.1"), None);
        assert_eq!(t.search("2001:db8::1"), Some("v6"));
        assert_eq!(t.search("2001:db9::1"), None);
        assert_eq!(t.search("::ffff:10.1.2.3"), Some("private"));
        assert_eq!(t.search("not-an-ip"), None);
        assert!(t.add("not-a-cidr", "x").is_err());
    }
}
