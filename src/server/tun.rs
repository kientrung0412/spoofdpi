//! TUN mode: a userspace TCP/IP stack terminates connections captured by
//! the TUN device and re-originates them from the physical interface.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

use super::{describe_route, log_tunnel, Shared};
use crate::logging::new_trace_id;
use crate::netutil::{count_rx, count_tx, dial_tcp_fastest, dial_udp, jobs::save_jobs, tunnel, BindSpec};
use crate::proto::tls::{read_tls_message, TLS_HANDSHAKE};
use crate::sysnet::{self, TunSetup};

pub struct TunServer {
    pub shared: Arc<Shared>,
    setup: Mutex<Option<TunSetup>>,
    name: String,
    jobs: Vec<crate::netutil::jobs::NetworkJob>,
    bind: Arc<BindSpec>,
}

impl TunServer {
    pub fn new(shared: Arc<Shared>, setup: TunSetup) -> Self {
        let bind = shared.route.bind_spec();
        Self {
            name: setup.name.clone(),
            jobs: setup.jobs.clone(),
            setup: Mutex::new(Some(setup)),
            shared,
            bind,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn setup_network_jobs(&self) -> Result<Option<PathBuf>, String> {
        let Some(state) = sysnet::tun_state_file() else {
            return Ok(None);
        };
        save_jobs(&state, &self.jobs)?;
        Ok(Some(state))
    }

    pub async fn listen_and_serve(self: Arc<Self>, cancel: CancellationToken) -> Result<(), String> {
        let setup = self
            .setup
            .lock()
            .unwrap()
            .take()
            .ok_or("tun device not available")?;

        let mut config = IpStackConfig::default();
        config.mtu(1500).map_err(|e| e.to_string())?;
        let idle = self.shared.cfg.conn.udp_idle_timeout;
        if !idle.is_zero() {
            config.udp_timeout(idle);
        }
        let mut stack = IpStack::new(config, setup.device);
        let logger = self.shared.logger.local("tun");

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = stack.accept() => match r {
                        Ok(s) => s,
                        Err(e) => {
                            error!(logger, ["err" => e], "tun stack stopped");
                            return;
                        }
                    },
                };
                match stream {
                    IpStackStream::Tcp(tcp) => {
                        tokio::spawn(this.clone().handle_tcp(tcp));
                    }
                    IpStackStream::Udp(udp) => {
                        tokio::spawn(this.clone().handle_udp(udp));
                    }
                    IpStackStream::UnknownTransport(u) => {
                        trace!(logger, ["proto" => format!("{:?}", u.ip_protocol())], "ignoring unknown transport");
                    }
                    IpStackStream::UnknownNetwork(pkt) => {
                        trace!(logger, ["len" => pkt.len()], "ignoring unknown network packet");
                    }
                }
            }
        });
        Ok(())
    }

    async fn handle_tcp(self: Arc<Self>, stream: IpStackTcpStream) {
        let trace_id = new_trace_id();
        let logger = self.shared.logger.with_trace(&trace_id).local("tcp");
        let dst = stream.peer_addr();
        let src = stream.local_addr();

        // Address-based rule first; SNI may refine it below.
        let mut rule = self.shared.rules.search_addrs(&[dst.ip()]);
        if let Some(r) = &rule {
            trace!(logger, ["summary" => r.summary()], "addr match");
        }

        let mut local = BufReader::new(stream);
        let first = match tokio::time::timeout(Duration::from_secs(1), local.fill_buf()).await {
            Ok(Ok([])) | Ok(Err(_)) => return,
            Ok(Ok(buf)) => Some(buf[0]),
            Err(_) => None, // server-first protocol
        };

        let mut tls_msg = None;
        if first == Some(TLS_HANDSHAKE) {
            debug!(logger, "detected tls handshake");
            match read_tls_message(&mut local).await {
                Ok(msg) => {
                    if let Some(sni) = msg.sni().filter(|_| msg.is_client_hello()) {
                        trace!(logger, ["value" => sni], "extracted sni field");
                        if let Some(r) = self.shared.rules.search_domain(sni) {
                            trace!(logger, ["summary" => r.summary()], "domain match");
                            rule = Some(r);
                        }
                    }
                    tls_msg = Some(msg);
                }
                Err(e) => {
                    debug!(logger, ["err" => e], "tls handler failed");
                    return;
                }
            }
        }

        let cfg = self.shared.cfg_for(&rule);
        if rule.as_ref().is_some_and(|r| r.block) {
            debug!(logger, "request is blocked by policy");
            return;
        }
        if tls_msg.is_some() {
            self.shared.tls.prepare_hop_track(&[dst.ip()], &cfg.https);
        }

        let mut remote =
            match dial_tcp_fastest(&[dst.ip()], dst.port(), cfg.conn.tcp_timeout, Some(&self.bind)).await {
                Ok(r) => r,
                Err(e) => {
                    error!(logger, "failed to dial {e}");
                    return;
                }
            };
        debug!(
            logger,
            "new remote conn ({src} -> {})",
            remote.peer_addr().map(|a| a.to_string()).unwrap_or_default()
        );

        if let Some(msg) = tls_msg {
            let res = if msg.is_client_hello() {
                self.shared
                    .tls
                    .desync(&mut remote, &msg, &cfg.https, &logger)
                    .await
            } else {
                remote.write_all(msg.raw()).await.map(|_| msg.len())
            };
            if let Err(e) = res {
                debug!(logger, ["err" => e], "tls handler failed");
                return;
            }
        }

        let route = describe_route(Some(src), remote.peer_addr().ok());
        let res = tunnel(local, remote).await;
        log_tunnel(&logger, &res, &route);
        if let Some(e) = res.errors.first() {
            error!(logger, ["err" => e], "error handling request");
        }
    }

    async fn handle_udp(self: Arc<Self>, mut stream: IpStackUdpStream) {
        let trace_id = new_trace_id();
        let logger = self.shared.logger.with_trace(&trace_id).local("udp");
        let dst: SocketAddr = stream.peer_addr();

        let rule = self.shared.rules.search_addrs(&[dst.ip()]);
        if let Some(r) = &rule {
            trace!(logger, ["summary" => r.summary()], "match");
        }
        let cfg = self.shared.cfg_for(&rule);
        if rule.as_ref().is_some_and(|r| r.block) {
            return;
        }

        self.shared.udp.prepare_hop_track(&[dst.ip()], &cfg.udp);
        let sock = match dial_udp(dst, Some(&self.bind)).await {
            Ok(s) => s,
            Err(e) => {
                error!(logger, ["err" => e], "error dialing to {dst}");
                return;
            }
        };

        if !cfg.udp.skip {
            if let Ok(local) = sock.local_addr() {
                self.shared.udp.desync(local, dst, &cfg.udp, &logger);
            }
        }
        debug!(logger, "new remote conn ({} -> {dst})", stream.local_addr());

        let idle = cfg.conn.udp_idle_timeout;
        let mut last = Instant::now();
        let mut up = vec![0u8; 65535];
        let mut down = vec![0u8; 65535];
        loop {
            let wait = if idle.is_zero() {
                Duration::from_secs(3600)
            } else {
                idle.saturating_sub(last.elapsed())
            };
            tokio::select! {
                r = stream.read(&mut up) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.send(&up[..n]).await.is_err() {
                            break;
                        }
                        count_tx(n);
                        last = Instant::now();
                    }
                },
                r = sock.recv(&mut down) => match r {
                    Ok(n) => {
                        if stream.write_all(&down[..n]).await.is_err() {
                            break;
                        }
                        count_rx(n);
                        last = Instant::now();
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(wait) => {
                    if !idle.is_zero() && last.elapsed() >= idle {
                        break;
                    }
                }
            }
        }
        trace!(logger, "udp flow closed");
    }
}
