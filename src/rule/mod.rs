//! Rule matching by domain and destination address.

mod trie;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub use trie::{CidrTrie, DomainTrie};

use crate::config::Rule;

/// Stores rules and resolves them by domain (specificity: exact > `*` > `**`)
/// or address (longest prefix). Priority resolves conflicts when rules are
/// added and breaks ties between a domain match and an address match.
#[derive(Default)]
pub struct RuleSet {
    domain: DomainTrie<Arc<Rule>>,
    cidr: CidrTrie<Arc<Rule>>,
    domain_keys: HashMap<String, Arc<Rule>>,
    cidr_keys: HashMap<String, Arc<Rule>>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: Rule) -> Result<(), String> {
        let Some(m) = rule.matcher.clone() else {
            return Err("rule match attributes cannot be nil".into());
        };
        if m.domains.is_empty() && m.cidrs.is_empty() {
            return Err("invalid rule: match must contain 'domain' or 'cidrs'".into());
        }
        let rule = Arc::new(rule);

        for pattern in &m.domains {
            if let Some(existing) = self.domain_keys.get(pattern) {
                if existing.priority == rule.priority {
                    return Err(format!(
                        "rules '{}' and '{}' conflict on '{}' (priority {})",
                        existing.name, rule.name, pattern, rule.priority
                    ));
                }
                if rule.priority <= existing.priority {
                    continue;
                }
            }
            self.domain.add(pattern, rule.clone())?;
            self.domain_keys.insert(pattern.clone(), rule.clone());
        }

        for cidr in &m.cidrs {
            if let Some(existing) = self.cidr_keys.get(cidr) {
                if existing.priority == rule.priority {
                    return Err(format!(
                        "rules '{}' and '{}' conflict on '{}' (priority {})",
                        existing.name, rule.name, cidr, rule.priority
                    ));
                }
                if rule.priority <= existing.priority {
                    continue;
                }
            }
            self.cidr.add(cidr, rule.clone())?;
            self.cidr_keys.insert(cidr.clone(), rule.clone());
        }
        Ok(())
    }

    pub fn search_domain(&self, domain: &str) -> Option<Arc<Rule>> {
        self.domain.search(domain)
    }

    /// Best match among the given addresses.
    pub fn search_addrs(&self, addrs: &[IpAddr]) -> Option<Arc<Rule>> {
        addrs
            .iter()
            .fold(None, |best, ip| higher_priority(best, self.cidr.search_ip(*ip)))
    }
}

/// Returns whichever rule has the higher priority; `a` wins ties.
pub fn higher_priority(a: Option<Arc<Rule>>, b: Option<Arc<Rule>>) -> Option<Arc<Rule>> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => {
            if a.priority >= b.priority {
                Some(a)
            } else {
                Some(b)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MatchAttrs};

    fn mk(name: &str, priority: u16, domains: &[&str], cidrs: &[&str]) -> Rule {
        Rule {
            name: name.into(),
            priority,
            block: false,
            matcher: Some(MatchAttrs {
                domains: domains.iter().map(|s| s.to_string()).collect(),
                cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            }),
            config: Config::default().runtime,
        }
    }

    fn name(r: Option<Arc<Rule>>) -> Option<String> {
        r.map(|r| r.name.clone())
    }

    #[test]
    fn add_errors_and_priority() {
        let mut rs = RuleSet::new();
        let mut bad = mk("bad", 0, &[], &[]);
        bad.matcher = None;
        assert!(rs.add(bad).is_err());
        assert!(rs.add(mk("empty", 0, &[], &[])).is_err());

        rs.add(mk("a", 10, &["dup.com"], &[])).unwrap();
        assert!(rs
            .add(mk("b", 10, &["dup.com"], &[]))
            .unwrap_err()
            .contains("conflict"));

        rs.add(mk("high", 20, &["dup.com"], &[])).unwrap();
        rs.add(mk("low", 5, &["dup.com"], &[])).unwrap();
        assert_eq!(name(rs.search_domain("dup.com")), Some("high".into()));
    }

    #[test]
    fn search_domain() {
        let mut rs = RuleSet::new();
        rs.add(mk("exact", 10, &["example.com"], &[])).unwrap();
        rs.add(mk("wildcard", 20, &["*.google.com"], &[])).unwrap();
        rs.add(mk("glob", 5, &["**.youtube.com"], &[])).unwrap();
        rs.add(mk("mail", 30, &["mail.google.com"], &[])).unwrap();
        assert_eq!(name(rs.search_domain("example.com")), Some("exact".into()));
        assert_eq!(name(rs.search_domain("maps.google.com")), Some("wildcard".into()));
        assert_eq!(name(rs.search_domain("google.com")), Some("wildcard".into()));
        assert_eq!(name(rs.search_domain("mail.google.com")), Some("mail".into()));
        assert_eq!(name(rs.search_domain("foo.bar.youtube.com")), Some("glob".into()));
        assert_eq!(name(rs.search_domain("naver.com")), None);
    }

    #[test]
    fn search_cidr_longest_prefix() {
        let mut rs = RuleSet::new();
        rs.add(mk("wide", 5, &[], &["172.16.0.0/16"])).unwrap();
        rs.add(mk("narrow", 4, &[], &["172.16.1.0/24"])).unwrap();
        assert_eq!(
            name(rs.search_addrs(&["172.16.1.5".parse().unwrap()])),
            Some("narrow".into())
        );
        assert_eq!(
            name(rs.search_addrs(&["172.16.2.5".parse().unwrap()])),
            Some("wide".into())
        );
    }

    #[test]
    fn domain_vs_cidr() {
        let mut rs = RuleSet::new();
        rs.add(mk("by-domain", 10, &["example.com"], &[])).unwrap();
        rs.add(mk("by-cidr", 20, &[], &["1.2.3.0/24"])).unwrap();
        let best = higher_priority(
            rs.search_addrs(&["1.2.3.4".parse().unwrap()]),
            rs.search_domain("example.com"),
        );
        assert_eq!(name(best), Some("by-cidr".into()));
    }

    #[test]
    fn higher_priority_ties() {
        let a = Arc::new(mk("a", 10, &["a.com"], &[]));
        let b = Arc::new(mk("b", 10, &["b.com"], &[]));
        assert_eq!(name(higher_priority(Some(a.clone()), Some(b))), Some("a".into()));
        assert_eq!(name(higher_priority(None, Some(a.clone()))), Some("a".into()));
        assert_eq!(name(higher_priority(Some(a), None)), Some("a".into()));
        assert!(higher_priority(None, None).is_none());
    }
}
