//! DNS resolution over UDP, DNS-over-HTTPS or the system resolver, with an
//! optional TTL cache.

mod addrselect;
mod msg;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::join_all;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::config::{DnsMode, DnsQueryType, RuntimeConfig};
use crate::logging::Logger;

pub use addrselect::sort_by_rfc6724;
use msg::{build_query, parse_response, type_name, RCODE_NAME_ERROR, RCODE_SUCCESS, TYPE_A, TYPE_AAAA};

type Lookup = Result<(Vec<IpAddr>, u32), String>;

pub struct Client {
    base: Arc<RuntimeConfig>,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

fn query_types(q: DnsQueryType) -> &'static [u16] {
    match q {
        DnsQueryType::Ipv4 => &[TYPE_A],
        DnsQueryType::Ipv6 => &[TYPE_AAAA],
        DnsQueryType::All => &[TYPE_A, TYPE_AAAA],
    }
}

impl Client {
    pub fn new(logger: Logger, base: Arc<RuntimeConfig>, cancel: CancellationToken) -> Arc<Self> {
        // Idempotent; reqwest is built without a default crypto provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(100)
            .tcp_keepalive(Duration::from_secs(30))
            .no_proxy();
        if !base.conn.dns_timeout.is_zero() {
            builder = builder
                .timeout(base.conn.dns_timeout)
                .connect_timeout(base.conn.dns_timeout);
        }
        let http = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        info!(logger, "dns info");
        info!(logger, " query type '{}'", base.dns.qtype);
        info!(logger, " resolvers");
        for (name, dst) in [
            ("udp", base.dns.addr.to_string()),
            ("https", base.dns.https_url.clone()),
            ("system", "builtin".to_string()),
            ("cache", "dynamic".to_string()),
        ] {
            info!(logger, ["dst" => dst], "  {name}");
        }

        let client = Arc::new(Self {
            base,
            http,
            cache: Mutex::new(HashMap::new()),
        });

        let weak = Arc::downgrade(&client);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(180));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let Some(c) = weak.upgrade() else { return };
                let now = Instant::now();
                c.cache.lock().unwrap().retain(|_, (_, exp)| *exp > now);
            }
        });

        client
    }

    /// Resolves `domain` using the DNS settings of `cfg` (the matched rule's
    /// config, or the base config).
    pub async fn resolve(
        &self,
        cfg: &RuntimeConfig,
        domain: &str,
        logger: &Logger,
    ) -> Result<Vec<IpAddr>, String> {
        let logger = logger.scoped("dns").local("client");
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let use_cache = cfg.dns.cache && cfg.dns.mode != DnsMode::System;
        if use_cache {
            let hit = self
                .cache
                .lock()
                .unwrap()
                .get(domain)
                .filter(|(_, exp)| *exp > Instant::now())
                .map(|(a, _)| a.clone());
            if let Some(addrs) = hit {
                debug!(logger, ["domain" => domain], "cache hit");
                return Ok(addrs);
            }
            debug!(logger, ["domain" => domain], "cache miss");
        }

        let started = Instant::now();
        let fut = self.lookup(cfg, domain, &logger);
        let (addrs, ttl) = match tokio::time::timeout(Duration::from_secs(3), fut).await {
            Ok(r) => r?,
            Err(_) => return Err("context deadline exceeded".into()),
        };

        debug!(
            logger,
            ["domain" => domain, "len" => addrs.len(), "took" => format!("{:.3}ms", started.elapsed().as_secs_f64() * 1000.0)],
            "dns lookup ok"
        );

        if use_cache {
            self.cache.lock().unwrap().insert(
                domain.to_string(),
                (addrs.clone(), Instant::now() + Duration::from_secs(ttl as u64)),
            );
        }
        Ok(addrs)
    }

    async fn lookup(&self, cfg: &RuntimeConfig, domain: &str, logger: &Logger) -> Lookup {
        let qtypes = query_types(cfg.dns.qtype);
        if cfg.dns.mode == DnsMode::System {
            return self.lookup_system(domain, qtypes).await;
        }

        let results = join_all(qtypes.iter().map(|&qt| async move {
            let res = match cfg.dns.mode {
                DnsMode::Https => {
                    self.exchange_https(&doh_url(&cfg.dns.https_url), domain, qt, logger)
                        .await
                }
                _ => self.exchange_udp(cfg.dns.addr, domain, qt, logger).await,
            };
            res.map_err(|e| format!("failed to resolve '{domain}', query type={}: {e}", type_name(qt)))
        }))
        .await;

        let mut addrs = Vec::new();
        let mut min_ttl = u32::MAX;
        let mut errs = Vec::new();
        for r in results {
            match r {
                Ok(answers) => {
                    for (ip, ttl) in answers {
                        addrs.push(ip);
                        min_ttl = min_ttl.min(ttl);
                    }
                }
                Err(e) => errs.push(e),
            }
        }

        if !addrs.is_empty() {
            sort_by_rfc6724(&mut addrs);
            return Ok((addrs, min_ttl));
        }
        if !errs.is_empty() {
            return Err(errs.join("\n"));
        }
        Err("record not found".into())
    }

    async fn exchange_udp(
        &self,
        server: SocketAddr,
        domain: &str,
        qtype: u16,
        logger: &Logger,
    ) -> Result<Vec<(IpAddr, u32)>, String> {
        let logger = logger.local("udp_exchange");
        let id: u16 = rand::random();
        let query = build_query(id, domain, qtype)?;
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let run = async {
            let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
            sock.connect(server).await.map_err(|e| e.to_string())?;
            sock.send(&query).await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
                match parse_response(&buf[..n]) {
                    Ok(r) if r.id == id => return Ok(r),
                    _ => continue,
                }
            }
        };

        let timeout = self.base.conn.dns_timeout;
        let res = if timeout.is_zero() {
            run.await
        } else {
            tokio::time::timeout(timeout, run)
                .await
                .unwrap_or_else(|_| Err("i/o timeout".into()))
        };

        match res {
            Ok(r) if r.rcode == RCODE_SUCCESS || r.rcode == RCODE_NAME_ERROR => Ok(r.addrs),
            Ok(r) => Err(format!("Rcode({})", r.rcode)),
            Err(e) => {
                trace!(logger, ["err" => e], "client returned error");
                Err(e)
            }
        }
    }

    async fn exchange_https(
        &self,
        url: &str,
        domain: &str,
        qtype: u16,
        logger: &Logger,
    ) -> Result<Vec<(IpAddr, u32)>, String> {
        let logger = logger.local("doh_exchange");
        // DoH recommends ID 0 for cache friendliness.
        let query = build_query(0, domain, qtype)?;

        const MAX_RETRIES: usize = 2;
        let mut last_err = String::new();
        let mut resp = None;
        for i in 0..MAX_RETRIES {
            let r = self
                .http
                .post(url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query.clone())
                .send()
                .await;
            match r {
                Ok(r) => {
                    resp = Some(r);
                    break;
                }
                Err(e) => {
                    last_err = error_chain(&e);
                    if i + 1 < MAX_RETRIES && is_retryable(&last_err) {
                        continue;
                    }
                    break;
                }
            }
        }
        let resp = resp.ok_or(last_err)?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| error_chain(&e))?;
        if !status.is_success() {
            trace!(
                logger,
                ["len" => body.len(), "status" => status.as_u16(), "body" => String::from_utf8_lossy(&body)],
                "doh status not ok"
            );
            return Err(format!("status code({})", status.as_u16()));
        }
        let r = parse_response(&body)?;
        if r.rcode != RCODE_SUCCESS && r.rcode != RCODE_NAME_ERROR {
            trace!(logger, ["rcode" => r.rcode], "doh rcode not ok");
            return Err(format!("Rcode({})", r.rcode));
        }
        Ok(r.addrs)
    }

    async fn lookup_system(&self, domain: &str, qtypes: &[u16]) -> Lookup {
        let want_a = qtypes.contains(&TYPE_A);
        let want_aaaa = qtypes.contains(&TYPE_AAAA);
        let found = tokio::net::lookup_host((domain, 0))
            .await
            .map_err(|e| format!("lookup {domain}: {e}"))?;
        let mut out: Vec<IpAddr> = Vec::new();
        for sa in found {
            let ip = match sa.ip() {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
                v4 => v4,
            };
            let ok = (want_a && ip.is_ipv4()) || (want_aaaa && ip.is_ipv6());
            if ok && !out.contains(&ip) {
                out.push(ip);
            }
        }
        Ok((out, 0))
    }
}

fn doh_url(upstream: &str) -> String {
    if upstream.starts_with("https://") {
        upstream.to_string()
    } else {
        format!("https://{upstream}/dns-query")
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

fn is_retryable(msg: &str) -> bool {
    msg.contains("unexpected EOF")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("connection closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_url_normalization() {
        assert_eq!(
            doh_url("https://dns.google/dns-query"),
            "https://dns.google/dns-query"
        );
        assert_eq!(doh_url("dns.google"), "https://dns.google/dns-query");
    }

    #[tokio::test]
    async fn udp_exchange_against_fake_server() {
        // A tiny DNS server answering every A query with 10.9.8.7.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                let mut resp = q.to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[7] = 1; // ANCOUNT = 1
                resp.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 9, 8, 7]);
                server.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut cfg = crate::config::Config::default().runtime;
        cfg.dns.addr = addr;
        cfg.dns.cache = true;
        let cfg = Arc::new(cfg);
        let client = Client::new(Logger::new("dns"), cfg.clone(), CancellationToken::new());
        let logger = Logger::new("test");
        let addrs = client.resolve(&cfg, "example.com", &logger).await.unwrap();
        assert_eq!(addrs, vec!["10.9.8.7".parse::<IpAddr>().unwrap()]);
        // Served from cache the second time.
        let addrs = client.resolve(&cfg, "example.com", &logger).await.unwrap();
        assert_eq!(addrs.len(), 1);
        // IP literals bypass DNS.
        let addrs = client.resolve(&cfg, "1.2.3.4", &logger).await.unwrap();
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }
}
