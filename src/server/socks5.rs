//! SOCKS5 proxy with CONNECT (TLS desync), BIND and UDP ASSOCIATE.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::{describe_route, log_tunnel, spawn_accept_loop, wait_first_data, FirstData, Shared};
use crate::config::Rule;
use crate::logging::{new_trace_id, Logger};
use crate::netutil::{
    self, count_rx, count_tx, dial_tcp_fastest, dial_udp, jobs::save_jobs, run_pac_server, tunnel,
};
use crate::proto::socks5::{self as s5, Request};
use crate::proto::tls::{read_tls_message, TLS_HANDSHAKE};
use crate::sysnet::{self, ProxyKind};

const NAT_CAPACITY: usize = 4096;
const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

type NatKey = (SocketAddr, SocketAddr);

/// Outbound UDP sockets keyed by (client, target).
#[derive(Default)]
struct NatPool {
    map: Mutex<HashMap<NatKey, Arc<UdpSocket>>>,
}

impl NatPool {
    fn get(&self, key: &NatKey) -> Option<Arc<UdpSocket>> {
        self.map.lock().unwrap().get(key).cloned()
    }

    fn insert(&self, key: NatKey, sock: Arc<UdpSocket>) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= NAT_CAPACITY {
            // Relays evict themselves when idle; drop an arbitrary entry to
            // stay bounded under bursts.
            if let Some(k) = m.keys().next().copied() {
                m.remove(&k);
            }
        }
        m.insert(key, sock);
    }

    fn remove(&self, key: &NatKey) {
        self.map.lock().unwrap().remove(key);
    }
}

pub struct Socks5Proxy {
    pub shared: Arc<Shared>,
    nat: Arc<NatPool>,
    cancel: Mutex<Option<CancellationToken>>,
}

impl Socks5Proxy {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            nat: Arc::new(NatPool::default()),
            cancel: Mutex::new(None),
        }
    }

    pub async fn listen_and_serve(self: Arc<Self>, cancel: CancellationToken) -> Result<(), String> {
        let listener = TcpListener::bind(self.shared.listen)
            .await
            .map_err(|e| format!("error creating listener on {}: {e}", self.shared.listen))?;
        *self.cancel.lock().unwrap() = Some(cancel.clone());
        let this = self.clone();
        spawn_accept_loop(
            listener,
            self.shared.logger.clone(),
            cancel,
            move |conn, _peer| {
                let this = this.clone();
                async move { this.handle_connection(conn).await }
            },
        );
        Ok(())
    }

    fn app_cancel(&self) -> CancellationToken {
        self.cancel.lock().unwrap().clone().unwrap_or_default()
    }

    pub async fn setup_network_jobs(&self, cancel: CancellationToken) -> Result<Option<PathBuf>, String> {
        let Some(state) = sysnet::proxy_state_file(ProxyKind::Socks5) else {
            return Ok(None);
        };
        let port = self.shared.listen.port();
        let pac = format!(
            "function FindProxyForURL(url, host) {{\n    return \"SOCKS5 127.0.0.1:{port}; SOCKS 127.0.0.1:{port}; DIRECT\";\n}}"
        );
        let pac_url = run_pac_server(pac, cancel)
            .await
            .map_err(|e| format!("error creating pac server: {e}"))?;
        let jobs = sysnet::build_proxy_jobs(ProxyKind::Socks5, &self.shared.route, port, &pac_url)?;
        save_jobs(&state, &jobs).map_err(|e| format!("failed to save state: {e}"))?;
        Ok(Some(state))
    }

    async fn handle_connection(self: Arc<Self>, mut conn: TcpStream) {
        let trace_id = new_trace_id();
        let logger = self.shared.logger.with_trace(&trace_id).local("socks5");

        if let Err(e) = negotiate(&mut conn).await {
            debug!(logger, ["err" => e], "negotiation failed");
            return;
        }

        let req = match s5::read_request(&mut conn).await {
            Ok(r) => r,
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    warn!(logger, ["err" => e], "failed to read request");
                }
                return;
            }
        };

        debug!(
            logger,
            ["cmd" => req.cmd, "port" => req.port, "fqdn" => req.fqdn, "ip" => req.ip.map(|i| i.to_string()).unwrap_or_default()],
            "new request"
        );

        let res = match req.cmd {
            s5::CMD_CONNECT => {
                let host = match req.ip {
                    Some(ip) => ip.to_string(),
                    None if req.atyp == s5::ATYP_FQDN && req.fqdn.len() > 1 => req.fqdn.clone(),
                    None => {
                        trace!(logger, "no addrs specified for this request. skipping");
                        return;
                    }
                };
                let (addrs, rule) = match self.shared.resolve(&host, &logger).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!(logger, ["domain" => host, "err" => e], "dns lookup failed");
                        let _ = s5::write_reply(&mut conn, s5::REP_GENERAL_FAILURE, None).await;
                        return;
                    }
                };
                self.handle_connect(conn, &req, &addrs, &rule, &logger).await
            }
            s5::CMD_BIND => self.handle_bind(conn, &req, &logger).await,
            s5::CMD_UDP_ASSOCIATE => self.handle_udp_associate(conn, &logger).await,
            other => {
                warn!(logger, ["cmd" => other], "unsupported command");
                let _ = s5::write_reply(&mut conn, s5::REP_CMD_NOT_SUPPORTED, None).await;
                Ok(())
            }
        };

        if let Err(e) = res {
            error!(logger, ["err" => e], "failed to handle");
        }
    }

    async fn handle_connect(
        &self,
        mut local: TcpStream,
        req: &Request,
        addrs: &[IpAddr],
        rule: &Option<Arc<Rule>>,
        logger: &Logger,
    ) -> Result<(), String> {
        let logger = logger.local("connect");
        let cfg = self.shared.cfg_for(rule);

        if let Err(e) = netutil::is_valid_destination(addrs, req.port, self.shared.listen) {
            debug!(logger, ["err" => e], "error determining if valid destination");
            let _ = s5::write_reply(&mut local, s5::REP_GENERAL_FAILURE, None).await;
            return Err(e);
        }

        if rule.as_ref().is_some_and(|r| r.block) {
            debug!(logger, "request is blocked by policy");
            let _ = s5::write_reply(&mut local, s5::REP_GENERAL_FAILURE, None).await;
            return Err("request blocked".into());
        }

        self.shared.tls.prepare_hop_track(addrs, &cfg.https);

        let mut remote = match dial_tcp_fastest(addrs, req.port, cfg.conn.tcp_timeout, None).await {
            Ok(r) => r,
            Err(e) => {
                let _ = s5::write_reply(&mut local, s5::REP_GENERAL_FAILURE, None).await;
                return Err(e.to_string());
            }
        };

        s5::write_reply(&mut local, s5::REP_SUCCESS, None)
            .await
            .map_err(|e| format!("failed to write socks5 success reply: {e}"))?;

        let remote_addr = remote.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        debug!(logger, "new remote conn -> {remote_addr}");

        let mut local = BufReader::new(local);
        match wait_first_data(&mut local, &remote).await {
            Ok(FirstData::Client(TLS_HANDSHAKE)) => {
                let msg = match read_tls_message(&mut local).await {
                    Ok(m) => m,
                    Err(e) if super::is_quiet_io_error(&e) => return Ok(()),
                    Err(e) => {
                        trace!(logger, ["err" => e], "failed to read first message from client");
                        return Err(e.to_string());
                    }
                };
                if msg.is_client_hello() {
                    debug!(logger, ["len" => msg.len()], "client hello received <- {}", local.get_ref().peer_addr().map(|a| a.to_string()).unwrap_or_default());
                    let n = self
                        .shared
                        .tls
                        .desync(&mut remote, &msg, &cfg.https, &logger)
                        .await
                        .map_err(|e| format!("failed to send client hello: {e}"))?;
                    debug!(logger, ["len" => n], "sent client hello -> {remote_addr}");
                } else {
                    debug!(logger, ["len" => msg.len()], "not a client hello. fallback to pure tcp");
                    remote
                        .write_all(msg.raw())
                        .await
                        .map_err(|e| format!("failed to write initial bytes to remote: {e}"))?;
                }
            }
            Ok(FirstData::Closed) => return Ok(()),
            Ok(_) => debug!(logger, "not a tls handshake. fallback to pure tcp"),
            Err(e) => return Err(e.to_string()),
        }

        let route = describe_route(local.get_ref().peer_addr().ok(), remote.peer_addr().ok());
        let res = tunnel(local, remote).await;
        log_tunnel(&logger, &res, &route);
        match res.errors.into_iter().next() {
            Some(e) => Err(e.to_string()),
            None => Ok(()),
        }
    }

    async fn handle_bind(&self, mut conn: TcpStream, req: &Request, logger: &Logger) -> Result<(), String> {
        let logger = logger.local("bind");

        // Listen on the address the client reached us on so the advertised
        // address is reachable.
        let local_ip = conn.local_addr().map_err(|e| e.to_string())?.ip();
        let listener = match TcpListener::bind(SocketAddr::new(local_ip, 0)).await {
            Ok(l) => l,
            Err(e) => {
                error!(logger, ["err" => e], "failed to create bind listener");
                let _ = s5::write_reply(&mut conn, s5::REP_GENERAL_FAILURE, None).await;
                return Err(e.to_string());
            }
        };
        let laddr = listener.local_addr().map_err(|e| e.to_string())?;
        debug!(logger, ["addr" => laddr], "new listener");

        s5::write_reply(&mut conn, s5::REP_SUCCESS, Some(laddr))
            .await
            .map_err(|e| format!("failed to write first bind reply: {e}"))?;
        debug!(logger, ["bind_addr" => laddr], "waiting for incoming connection");

        let cancel = self.app_cancel();
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = wait_closed(&conn) => return Ok(()),
            _ = cancel.cancelled() => return Ok(()),
        };
        let (remote, raddr) = match accepted {
            Ok(v) => v,
            Err(e) => {
                error!(logger, ["err" => e], "failed to accept incoming connection");
                let _ = s5::write_reply(&mut conn, s5::REP_GENERAL_FAILURE, None).await;
                return Err(e.to_string());
            }
        };
        drop(listener);

        // RFC 1928: the connecting host must match DST.ADDR when given.
        if let Some(expected) = req.ip {
            if !expected.is_unspecified() && expected != raddr.ip() {
                warn!(logger, ["expected" => expected, "actual" => raddr.ip()], "rejecting connection from unexpected host");
                let _ = s5::write_reply(&mut conn, s5::REP_GENERAL_FAILURE, None).await;
                return Err(format!("bind: unexpected connecting host {}", raddr.ip()));
            }
        }
        debug!(logger, ["remote_addr" => raddr], "accepted incoming connection");

        s5::write_reply(&mut conn, s5::REP_SUCCESS, Some(raddr))
            .await
            .map_err(|e| format!("failed to write second bind reply: {e}"))?;

        let route = describe_route(conn.peer_addr().ok(), Some(raddr));
        let res = tunnel(conn, remote).await;
        log_tunnel(&logger, &res, &route);
        Ok(())
    }

    async fn handle_udp_associate(&self, mut conn: TcpStream, logger: &Logger) -> Result<(), String> {
        let logger = logger.local("udp_associate");
        let cfg = self.shared.cfg.clone();

        let local_ip = conn.local_addr().map_err(|e| e.to_string())?.ip();
        let client_ip = conn.peer_addr().map_err(|e| e.to_string())?.ip();
        let relay = match UdpSocket::bind(SocketAddr::new(local_ip, 0)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(logger, ["err" => e], "failed to create udp listener");
                let _ = s5::write_reply(&mut conn, s5::REP_GENERAL_FAILURE, None).await;
                return Err(e.to_string());
            }
        };
        let relay_addr = relay.local_addr().map_err(|e| e.to_string())?;
        debug!(logger, ["bind_addr" => relay_addr], "socks5 udp associate established");

        s5::write_reply(&mut conn, s5::REP_SUCCESS, Some(relay_addr))
            .await
            .map_err(|e| format!("failed to write socks5 success reply: {e}"))?;

        // RFC 1928 §6: the association ends when its TCP connection closes.
        let done = self.app_cancel().child_token();
        {
            let done = done.clone();
            tokio::spawn(async move {
                let mut sink = [0u8; 256];
                while let Ok(n) = conn.read(&mut sink).await {
                    if n == 0 {
                        break;
                    }
                }
                done.cancel();
            });
        }

        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = tokio::select! {
                _ = done.cancelled() => return Ok(()),
                r = relay.recv_from(&mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(logger, ["err" => e], "error reading from udp");
                        return Err(e.to_string());
                    }
                },
            };

            // Only accept datagrams from the client that opened the association.
            if src.ip() != client_ip {
                debug!(logger, ["expected" => client_ip, "actual" => src.ip()], "dropped udp packet from unexpected ip");
                continue;
            }

            let (host, port, payload) = match s5::parse_udp_header(&buf[..n]) {
                Ok(v) => v,
                Err(e) => {
                    warn!(logger, ["err" => e], "failed to parse socks5 udp header");
                    continue;
                }
            };
            let dst = match resolve_udp_target(&host, port).await {
                Ok(a) => a,
                Err(e) => {
                    warn!(logger, ["err" => e, "addr" => format!("{host}:{port}")], "failed to resolve udp target");
                    continue;
                }
            };

            let key = (src, dst);
            if let Some(sock) = self.nat.get(&key) {
                debug!(logger, ["key" => format!("{src} > {dst}")], "session cache hit");
                if let Err(e) = sock.send(payload).await {
                    warn!(logger, ["err" => e], "failed to write udp to target");
                } else {
                    count_tx(payload.len());
                }
                continue;
            }
            debug!(logger, ["key" => format!("{src} > {dst}")], "session cache miss");

            self.shared.udp.prepare_hop_track(&[dst.ip()], &cfg.udp);
            let sock = match dial_udp(dst, None).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!(logger, ["err" => e, "addr" => dst], "failed to dial udp target");
                    continue;
                }
            };
            self.nat.insert(key, sock.clone());

            if !cfg.udp.skip {
                if let Ok(local) = sock.local_addr() {
                    self.shared.udp.desync(local, dst, &cfg.udp, &logger);
                }
            }

            tokio::spawn(relay_inbound(
                self.nat.clone(),
                relay.clone(),
                sock.clone(),
                src,
                dst,
                done.clone(),
                logger.clone(),
            ));

            if let Err(e) = sock.send(payload).await {
                warn!(logger, ["err" => e], "failed to write udp to target");
            } else {
                count_tx(payload.len());
            }
        }
    }
}

async fn relay_inbound(
    nat: Arc<NatPool>,
    relay: Arc<UdpSocket>,
    sock: Arc<UdpSocket>,
    client: SocketAddr,
    target: SocketAddr,
    done: CancellationToken,
    logger: Logger,
) {
    let header = s5::udp_header_for(target);
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::select! {
            _ = done.cancelled() => break,
            r = tokio::time::timeout(NAT_IDLE_TIMEOUT, sock.recv(&mut buf)) => match r {
                Ok(Ok(n)) => n,
                _ => break,
            },
        };
        count_rx(n);
        let mut pkt = Vec::with_capacity(header.len() + n);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&buf[..n]);
        if let Err(e) = relay.send_to(&pkt, client).await {
            warn!(logger, ["err" => e], "failed to write udp to client");
            break;
        }
    }
    nat.remove(&(client, target));
}

async fn resolve_udp_target(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses"))
}

/// Resolves once the peer closes the connection (without consuming data).
async fn wait_closed(conn: &TcpStream) {
    let mut b = [0u8; 1];
    loop {
        match conn.peek(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

async fn negotiate(conn: &mut TcpStream) -> Result<(), String> {
    let mut header = [0u8; 2];
    conn.read_exact(&mut header).await.map_err(|e| e.to_string())?;

    if header[0] != s5::VERSION {
        // "CO" is likely an HTTP CONNECT sent to the SOCKS5 port.
        if header == *b"CO" {
            let mut rest = Vec::new();
            let mut b = [0u8; 1];
            while rest.len() < 4096 && !rest.ends_with(b"\r\n") {
                match conn.read(&mut b).await {
                    Ok(1) => rest.push(b[0]),
                    _ => break,
                }
            }
            let line = format!("CO{}", String::from_utf8_lossy(&rest));
            let host = line.split_whitespace().nth(1).unwrap_or("?");
            return Err(format!("invalid request: http connect to {host}"));
        }
        return Err(format!("invalid version: {}", header[0]));
    }

    let mut methods = vec![0u8; header[1] as usize];
    conn.read_exact(&mut methods).await.map_err(|e| e.to_string())?;
    conn.write_all(&[s5::VERSION, s5::AUTH_NONE])
        .await
        .map_err(|e| e.to_string())
}
