//! Command line flags. Every flag is optional so that only flags the user
//! actually passed override the TOML/default layers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use super::parse::*;
use super::*;
use crate::logging::{Level, LEVEL_VALUES};

fn enum_parser(values: &'static [&'static str]) -> impl Fn(&str) -> Result<String, String> + Clone {
    move |s: &str| check_one_of(s, values).map(|_| s.to_string())
}

fn int(s: &str) -> Result<i64, String> {
    s.trim()
        .parse::<i64>()
        .map_err(|_| format!("invalid value {s:?}"))
}

fn uint8(s: &str) -> Result<u8, String> {
    check_uint8(int(s)?)
}

fn uint8_non_zero(s: &str) -> Result<u8, String> {
    check_uint8_non_zero(int(s)?)
}

fn millis(s: &str) -> Result<Duration, String> {
    Ok(Duration::from_millis(check_uint16(int(s)?)? as u64))
}

fn fib(s: &str) -> Result<i64, String> {
    check_freebsd_fib(int(s)?)
}

fn host_port(s: &str) -> Result<SocketAddr, String> {
    parse_host_port(s)
}

fn https_url(s: &str) -> Result<String, String> {
    check_https_endpoint(s).map(|_| s.to_string())
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    parse_hex_bytes(s)
}

fn enum_help(values: &[&str]) -> String {
    let quoted: Vec<String> = values.iter().map(|v| format!("{v:?}")).collect();
    format!("<{}>", quoted.join("|"))
}

#[derive(Parser, Debug, Default)]
#[command(
    name = "spoofdpi",
    about = "Simple and fast anti-censorship tool to bypass DPI",
    disable_version_flag = true,
    after_help = "Copyright: Apache License, Version 2.0, January 2004"
)]
pub struct Cli {
    /// Specifies the proxy mode. Note that 'socks5' and 'tun' modes are currently experimental. (default: "http")
    #[arg(long, value_name = "MODE", value_parser = enum_parser(APP_MODE_VALUES))]
    pub app_mode: Option<String>,

    /// If set, all configuration files will be ignored
    #[arg(long)]
    pub clean: bool,

    /// Custom location of the config file to load. Options given through the command line
    /// flags will override the options set in this file.
    #[arg(long, short = 'c', env = "SPOOFDPI_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Default TTL value for fake packets. (default: 8)
    #[arg(long, value_name = "TTL", value_parser = uint8_non_zero)]
    pub default_fake_ttl: Option<u8>,

    /// <ip:port> Upstream DNS server address for standard UDP queries. (default: 8.8.8.8:53)
    #[arg(long, value_name = "ADDR", value_parser = host_port)]
    pub dns_addr: Option<SocketAddr>,

    /// If set, DNS records will be cached. (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub dns_cache: Option<bool>,

    /// Default resolution mode for domains that do not match any specific rule. (default: "udp")
    #[arg(long, value_name = "MODE", value_parser = enum_parser(DNS_MODE_VALUES))]
    pub dns_mode: Option<String>,

    /// <https_url> Endpoint URL for DNS over HTTPS (DoH) queries. (default: "https://dns.google/dns-query")
    #[arg(long, value_name = "URL", value_parser = https_url)]
    pub dns_https_url: Option<String>,

    /// Filters DNS queries by record type (A for IPv4, AAAA for IPv6). (default: "ipv4")
    #[arg(long, value_name = "QTYPE", value_parser = enum_parser(DNS_QUERY_VALUES))]
    pub dns_qtype: Option<String>,

    /// Timeout for dns connection in milliseconds. No effect when the value is 0 (default: 5000, max: 65535)
    #[arg(long, value_name = "MS", value_parser = millis)]
    pub dns_timeout: Option<Duration>,

    /// Number of fake packets to be sent before the Client Hello. (default: 0)
    #[arg(long, value_name = "N", value_parser = uint8)]
    pub https_fake_count: Option<u8>,

    /// <byte_array> Comma-separated hexadecimal byte array used for fake Client Hello.
    /// (default: built-in fake packet)
    #[arg(long, value_name = "BYTES", value_parser = hex_bytes)]
    pub https_fake_packet: Option<Vec<u8>>,

    /// If set, sends fragmented Client Hello packets out-of-order. (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub https_disorder: Option<bool>,

    /// Specifies the default packet fragmentation strategy to use. (default: "sni")
    #[arg(long, value_name = "MODE", value_parser = enum_parser(SPLIT_MODE_VALUES))]
    pub https_split_mode: Option<String>,

    /// If set, HTTPS traffic will be processed without any DPI bypass techniques. (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub https_skip: Option<bool>,

    /// The chunk size (in bytes) for packet fragmentation. This value is only applied when
    /// 'https-split-mode' is 'chunk'. (default: 35, max: 255)
    #[arg(long, value_name = "N", value_parser = uint8_non_zero)]
    pub https_chunk_size: Option<u8>,

    /// Number of fake packets to be sent. (default: 0)
    #[arg(long, value_name = "N", value_parser = uint8)]
    pub udp_fake_count: Option<u8>,

    /// <byte_array> Comma-separated hexadecimal byte array used for fake packet.
    /// (default: built-in fake packet)
    #[arg(long, value_name = "BYTES", value_parser = hex_bytes)]
    pub udp_fake_packet: Option<Vec<u8>>,

    /// If set, UDP traffic will be processed without any DPI bypass techniques. (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub udp_skip: Option<bool>,

    /// Idle timeout for udp connection in milliseconds. No effect when the value is 0
    /// (default: 25000, max: 65535)
    #[arg(long, value_name = "MS", value_parser = millis)]
    pub udp_idle_timeout: Option<Duration>,

    /// IP address to listen on (default: 127.0.0.1:8080 for http, or 127.0.0.1:1080 for socks5)
    #[arg(long, value_name = "ADDR", value_parser = host_port)]
    pub listen_addr: Option<SocketAddr>,

    /// Set log level (default: "info")
    #[arg(long, value_name = "LEVEL", value_parser = enum_parser(LEVEL_VALUES))]
    pub log_level: Option<String>,

    /// Disable TUI and run in headless mode. (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub no_tui: Option<bool>,

    /// Automatically set system-wide proxy configuration (default: false)
    #[arg(long, value_name = "BOOL", num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub auto_configure_network: Option<bool>,

    /// Timeout for tcp connection in milliseconds. No effect when the value is 0
    /// (default: 10000, max: 65535)
    #[arg(long, value_name = "MS", value_parser = millis)]
    pub tcp_timeout: Option<Duration>,

    /// FIB ID for FreeBSD routing table (1-15). Ignored on other platforms. (default: 1)
    #[arg(long, value_name = "ID", value_parser = fib)]
    pub freebsd_fib: Option<i64>,

    /// Print version; this may contain some other relevant information
    #[arg(long, short = 'v')]
    pub version: bool,
}

impl Cli {
    /// Applies the flags the user set on top of `cfg`.
    pub fn apply(&self, cfg: &mut Config) {
        let app = &mut cfg.app;
        let rt = &mut cfg.runtime;

        if let Some(v) = &self.app_mode {
            app.mode = AppMode::parse(v).unwrap();
        }
        if let Some(v) = self.default_fake_ttl {
            rt.conn.default_fake_ttl = v;
        }
        if let Some(v) = self.dns_addr {
            rt.dns.addr = v;
        }
        if let Some(v) = self.dns_cache {
            rt.dns.cache = v;
        }
        if let Some(v) = &self.dns_mode {
            rt.dns.mode = DnsMode::parse(v).unwrap();
        }
        if let Some(v) = &self.dns_https_url {
            rt.dns.https_url = v.clone();
        }
        if let Some(v) = &self.dns_qtype {
            rt.dns.qtype = DnsQueryType::parse(v).unwrap();
        }
        if let Some(v) = self.dns_timeout {
            rt.conn.dns_timeout = v;
        }
        if let Some(v) = self.https_fake_count {
            rt.https.fake_count = v;
        }
        if let Some(v) = &self.https_fake_packet {
            rt.https.fake_packet = Arc::new(v.clone());
        }
        if let Some(v) = self.https_disorder {
            rt.https.disorder = v;
        }
        if let Some(v) = &self.https_split_mode {
            rt.https.split_mode = SplitMode::parse(v).unwrap();
        }
        if let Some(v) = self.https_skip {
            rt.https.skip = v;
        }
        if let Some(v) = self.https_chunk_size {
            rt.https.chunk_size = v;
        }
        if let Some(v) = self.udp_fake_count {
            rt.udp.fake_count = v;
        }
        if let Some(v) = &self.udp_fake_packet {
            rt.udp.fake_packet = Arc::new(v.clone());
        }
        if let Some(v) = self.udp_skip {
            rt.udp.skip = v;
        }
        if let Some(v) = self.udp_idle_timeout {
            rt.conn.udp_idle_timeout = v;
        }
        if let Some(v) = self.listen_addr {
            app.listen_addr = Some(v);
        }
        if let Some(v) = &self.log_level {
            app.log_level = Level::parse(v).unwrap();
        }
        if let Some(v) = self.no_tui {
            app.no_tui = v;
        }
        if let Some(v) = self.auto_configure_network {
            app.auto_configure_network = v;
        }
        if let Some(v) = self.tcp_timeout {
            rt.conn.tcp_timeout = v;
        }
        if let Some(v) = self.freebsd_fib {
            app.freebsd_fib = v;
        }
    }
}

/// Help text listing enum values, kept next to the flag definitions.
pub fn enum_values_help() -> String {
    format!(
        "Accepted values:\n  --app-mode {}\n  --dns-mode {}\n  --dns-qtype {}\n  --https-split-mode {}\n  --log-level {}",
        enum_help(APP_MODE_VALUES),
        enum_help(DNS_MODE_VALUES),
        enum_help(DNS_QUERY_VALUES),
        enum_help(SPLIT_MODE_VALUES),
        enum_help(LEVEL_VALUES),
    )
}
