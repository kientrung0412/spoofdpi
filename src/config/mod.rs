//! Configuration model, defaults and load pipeline.
//!
//! Configuration is assembled from three layers in precedence order:
//! defaults → TOML file → CLI flags. See [`load::load`].

pub mod cli;
mod fake;
mod fileutil;
pub mod load;
mod parse;
mod toml_apply;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::logging::Level;

pub use fake::FAKE_CLIENT_HELLO;
pub use parse::{mask_ip, parse_cidr};

// ┌─────────────────┐
// │ ENUMS           │
// └─────────────────┘

macro_rules! str_enum {
    ($name:ident, $values:ident, { $($variant:ident => $s:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }

        pub const $values: &[&str] = &[$($s),+];

        impl $name {
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $s,)+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

str_enum!(AppMode, APP_MODE_VALUES, {
    Http => "http",
    Socks5 => "socks5",
    Tun => "tun",
});

str_enum!(DnsMode, DNS_MODE_VALUES, {
    Udp => "udp",
    Https => "https",
    System => "system",
});

str_enum!(DnsQueryType, DNS_QUERY_VALUES, {
    Ipv4 => "ipv4",
    Ipv6 => "ipv6",
    All => "all",
});

str_enum!(SplitMode, SPLIT_MODE_VALUES, {
    Sni => "sni",
    Random => "random",
    Chunk => "chunk",
    FirstByte => "first-byte",
    Custom => "custom",
    None => "none",
});

str_enum!(SegmentFrom, SEGMENT_FROM_VALUES, {
    Head => "head",
    Sni => "sni",
});

// ┌─────────────────┐
// │ OPTIONS         │
// └─────────────────┘

#[derive(Clone, Debug)]
pub struct AppOptions {
    pub no_tui: bool,
    pub log_level: Level,
    pub silent: bool,
    pub auto_configure_network: bool,
    pub mode: AppMode,
    /// `None` until [`Config::finalize`] picks a per-mode default.
    pub listen_addr: Option<SocketAddr>,
    /// FreeBSD only. Accepted for config compatibility, ignored elsewhere.
    pub freebsd_fib: i64,
}

#[derive(Clone, Debug)]
pub struct ConnOptions {
    pub default_fake_ttl: u8,
    pub dns_timeout: Duration,
    pub tcp_timeout: Duration,
    pub udp_idle_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct DnsOptions {
    pub mode: DnsMode,
    pub addr: SocketAddr,
    pub https_url: String,
    pub qtype: DnsQueryType,
    pub cache: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentPlan {
    pub from: SegmentFrom,
    pub at: i64,
    pub lazy: bool,
    pub noise: i64,
}

#[derive(Clone, Debug)]
pub struct HttpsOptions {
    pub disorder: bool,
    pub fake_count: u8,
    pub fake_packet: Arc<Vec<u8>>,
    pub split_mode: SplitMode,
    pub chunk_size: u8,
    pub skip: bool,
    pub custom_segments: Vec<SegmentPlan>,
}

#[derive(Clone, Debug)]
pub struct UdpOptions {
    pub skip: bool,
    pub fake_count: u8,
    pub fake_packet: Arc<Vec<u8>>,
}

/// Sections read on the request hot path. Rules carry a complete copy so a
/// matched rule can replace the whole runtime config in one step.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub conn: ConnOptions,
    pub dns: DnsOptions,
    pub https: HttpsOptions,
    pub udp: UdpOptions,
}

#[derive(Clone, Debug, Default)]
pub struct MatchAttrs {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub priority: u16,
    pub block: bool,
    pub matcher: Option<MatchAttrs>,
    pub config: RuntimeConfig,
}

impl Rule {
    /// Compact single-line summary for trace logs.
    pub fn summary(&self) -> String {
        let r = &self.config;
        let mut m = serde_json::Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("priority".into(), self.priority.into());
        m.insert("block".into(), self.block.into());
        if let Some(ma) = &self.matcher {
            let mut mm = serde_json::Map::new();
            if !ma.domains.is_empty() {
                mm.insert("domains".into(), format!("{} items", ma.domains.len()).into());
            }
            if !ma.cidrs.is_empty() {
                mm.insert("cidrs".into(), format!("{} items", ma.cidrs.len()).into());
            }
            m.insert("match".into(), mm.into());
        }
        m.insert(
            "config".into(),
            serde_json::json!({
                "conn": {
                    "default-fake-ttl": r.conn.default_fake_ttl,
                    "dns-timeout": format!("{:?}", r.conn.dns_timeout),
                    "tcp-timeout": format!("{:?}", r.conn.tcp_timeout),
                    "udp-idle-timeout": format!("{:?}", r.conn.udp_idle_timeout),
                },
                "dns": {
                    "mode": r.dns.mode.as_str(),
                    "addr": r.dns.addr.to_string(),
                    "https-url": r.dns.https_url,
                    "qtype": r.dns.qtype.as_str(),
                    "cache": r.dns.cache,
                },
                "https": {
                    "disorder": r.https.disorder,
                    "fake-count": r.https.fake_count,
                    "fake-packet-len": r.https.fake_packet.len(),
                    "split-mode": r.https.split_mode.as_str(),
                    "chunk-size": r.https.chunk_size,
                    "skip": r.https.skip,
                    "custom-segments": format!("{} items", r.https.custom_segments.len()),
                },
                "udp": {
                    "skip": r.udp.skip,
                    "fake-count": r.udp.fake_count,
                    "fake-packet-len": r.udp.fake_packet.len(),
                },
            }),
        );
        serde_json::Value::Object(m).to_string()
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub app: AppOptions,
    pub rules: Vec<Rule>,
    pub runtime: RuntimeConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            app: AppOptions {
                no_tui: false,
                log_level: Level::Info,
                silent: false,
                auto_configure_network: false,
                mode: AppMode::Http,
                listen_addr: None,
                freebsd_fib: 1,
            },
            rules: Vec::new(),
            runtime: RuntimeConfig {
                conn: ConnOptions {
                    default_fake_ttl: 8,
                    dns_timeout: Duration::from_millis(5000),
                    tcp_timeout: Duration::from_millis(10000),
                    udp_idle_timeout: Duration::from_millis(25000),
                },
                dns: DnsOptions {
                    mode: DnsMode::Udp,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                    https_url: "https://dns.google/dns-query".into(),
                    qtype: DnsQueryType::Ipv4,
                    cache: false,
                },
                https: HttpsOptions {
                    disorder: false,
                    fake_count: 0,
                    fake_packet: Arc::new(FAKE_CLIENT_HELLO.to_vec()),
                    split_mode: SplitMode::Sni,
                    chunk_size: 35,
                    skip: false,
                    custom_segments: Vec::new(),
                },
                udp: UdpOptions {
                    skip: false,
                    fake_count: 0,
                    fake_packet: Arc::new(vec![0u8; 64]),
                },
            },
        }
    }
}

impl Config {
    /// Applies defaults that depend on other fields (listen address per mode).
    pub fn finalize(&mut self) {
        if self.app.listen_addr.is_none() {
            let port = if self.app.mode == AppMode::Socks5 {
                1080
            } else {
                8080
            };
            self.app.listen_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }

        match self.app.mode {
            AppMode::Socks5 => add_warn_msg("'socks5' mode is an experimental feature"),
            AppMode::Tun => add_warn_msg("'tun' mode is an experimental feature"),
            AppMode::Http => {}
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.app
            .listen_addr
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
    }

    /// Whether any TCP fake-packet feature is enabled, in the base config or
    /// in any rule. Raw packet IO for TCP is only set up when this is true.
    pub fn needs_packet_tcp(&self) -> bool {
        self.runtime.https.fake_count > 0 || self.rules.iter().any(|r| r.config.https.fake_count > 0)
    }

    pub fn needs_packet_udp(&self) -> bool {
        self.runtime.udp.fake_count > 0 || self.rules.iter().any(|r| r.config.udp.fake_count > 0)
    }

    pub fn needs_packet(&self) -> bool {
        self.needs_packet_tcp() || self.needs_packet_udp()
    }
}

// ┌─────────────────┐
// │ WARNINGS        │
// └─────────────────┘

fn warn_msgs() -> &'static Mutex<Vec<String>> {
    static W: std::sync::OnceLock<Mutex<Vec<String>>> = std::sync::OnceLock::new();
    W.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn add_warn_msg(msg: impl Into<String>) {
    warn_msgs().lock().unwrap().push(msg.into());
}

pub fn take_warn_msgs() -> Vec<String> {
    std::mem::take(&mut *warn_msgs().lock().unwrap())
}
