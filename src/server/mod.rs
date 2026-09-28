//! Proxy front-ends: HTTP, SOCKS5 and TUN.

pub mod http;
pub mod socks5;
pub mod tun;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::config::{Rule, RuntimeConfig};
use crate::desync::{TlsDesyncer, UdpDesyncer};
use crate::dns;
use crate::logging::Logger;
use crate::netutil::TunnelResult;
use crate::rule::{higher_priority, RuleSet};
use crate::sysnet::Route;

/// Everything a connection handler needs.
pub struct Shared {
    pub logger: Logger,
    pub cfg: Arc<RuntimeConfig>,
    pub rules: Arc<RuleSet>,
    pub dns: Arc<dns::Client>,
    pub tls: Arc<TlsDesyncer>,
    pub udp: Arc<UdpDesyncer>,
    pub listen: SocketAddr,
    pub route: Route,
}

impl Shared {
    /// The runtime config to use for a request matched by `rule`.
    pub fn cfg_for<'a>(&'a self, rule: &'a Option<Arc<Rule>>) -> &'a RuntimeConfig {
        rule.as_ref().map(|r| &r.config).unwrap_or(&self.cfg)
    }

    /// Resolves `host` (domain or IP literal) and picks the best rule by
    /// domain and resolved addresses.
    pub async fn resolve(
        &self,
        host: &str,
        logger: &Logger,
    ) -> Result<(Vec<IpAddr>, Option<Arc<Rule>>), String> {
        let (addrs, name_match) = match host.parse::<IpAddr>() {
            Ok(ip) => {
                trace!(logger, "skipping dns lookup for non-domain host {host:?}");
                (vec![ip], None)
            }
            Err(_) => {
                let name_match = self.rules.search_domain(host);
                let cfg = self.cfg_for(&name_match);
                let addrs = self.dns.resolve(cfg, host, logger).await?;
                (addrs, name_match)
            }
        };
        let best = higher_priority(self.rules.search_addrs(&addrs), name_match);
        if let Some(r) = &best {
            if logger.enabled(crate::logging::Level::Trace) {
                trace!(logger, ["summary" => r.summary()], "match");
            }
        }
        Ok((addrs, best))
    }
}

pub enum Server {
    Http(Arc<http::HttpProxy>),
    Socks5(Arc<socks5::Socks5Proxy>),
    Tun(Arc<tun::TunServer>),
}

impl Server {
    pub async fn listen_and_serve(&self, cancel: CancellationToken) -> Result<(), String> {
        match self {
            Server::Http(s) => s.clone().listen_and_serve(cancel).await,
            Server::Socks5(s) => s.clone().listen_and_serve(cancel).await,
            Server::Tun(s) => s.clone().listen_and_serve(cancel).await,
        }
    }

    pub fn addr(&self) -> String {
        match self {
            Server::Http(s) => s.shared.listen.to_string(),
            Server::Socks5(s) => s.shared.listen.to_string(),
            Server::Tun(s) => s.name().to_string(),
        }
    }

    /// Builds and saves the system network jobs. Returns the state file, or
    /// `None` when the platform has nothing to configure.
    pub async fn setup_network_jobs(&self, cancel: CancellationToken) -> Result<Option<PathBuf>, String> {
        match self {
            Server::Http(s) => s.setup_network_jobs(cancel).await,
            Server::Socks5(s) => s.setup_network_jobs(cancel).await,
            Server::Tun(s) => s.setup_network_jobs(),
        }
    }
}

/// Accept loop with exponential back-off on errors.
pub fn spawn_accept_loop<F, Fut>(listener: TcpListener, logger: Logger, cancel: CancellationToken, handle: F)
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut delay = Duration::ZERO;
        loop {
            let accepted = tokio::select! {
                _ = cancel.cancelled() => return,
                r = listener.accept() => r,
            };
            match accepted {
                Ok((conn, peer)) => {
                    delay = Duration::ZERO;
                    tokio::spawn(handle(conn, peer));
                }
                Err(e) => {
                    error!(logger, ["err" => e], "failed to accept new connection");
                    delay = if delay.is_zero() {
                        Duration::from_millis(5)
                    } else {
                        (delay * 2).min(Duration::from_secs(10))
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
    });
}

pub enum FirstData {
    /// The client sent data; the first byte is available.
    Client(u8),
    /// The server spoke first (or the client stayed silent).
    ServerFirst,
    Closed,
}

/// Waits for the first byte from the client, unless the remote side sends
/// something first (server-first protocols such as SSH or SMTP).
pub async fn wait_first_data<R: AsyncBufRead + Unpin>(
    local: &mut R,
    remote: &TcpStream,
) -> io::Result<FirstData> {
    tokio::select! {
        r = local.fill_buf() => {
            let buf = r?;
            Ok(match buf.first() {
                Some(b) => FirstData::Client(*b),
                None => FirstData::Closed,
            })
        }
        r = remote.readable() => {
            r?;
            Ok(FirstData::ServerFirst)
        }
    }
}

pub fn log_tunnel(logger: &Logger, res: &TunnelResult, route: &str) {
    trace!(
        logger,
        [
            "out" => res.out_bytes,
            "in" => res.in_bytes,
            "took" => format!("{:.3}ms", res.took.as_secs_f64() * 1000.0),
            "route" => route,
            "errs" => res.errors.len()
        ],
        "tunnel closed"
    );
}

pub fn is_quiet_io_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

pub fn describe_route(local: Option<SocketAddr>, remote: Option<SocketAddr>) -> String {
    let f = |a: Option<SocketAddr>| a.map(|a| a.to_string()).unwrap_or_else(|| "?".into());
    format!("{}(tcp) -> {}(tcp)", f(local), f(remote))
}
