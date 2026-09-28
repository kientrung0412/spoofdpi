//! HTTP proxy: plain requests are forwarded, CONNECT tunnels get their TLS
//! ClientHello desynchronized.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use super::{describe_route, log_tunnel, spawn_accept_loop, wait_first_data, FirstData, Shared};
use crate::config::Rule;
use crate::logging::{new_trace_id, Logger};
use crate::netutil::{self, dial_tcp_fastest, jobs::save_jobs, run_pac_server, tunnel};
use crate::proto::http::{self as h, HttpRequest};
use crate::proto::tls::{read_tls_message, TLS_HANDSHAKE};
use crate::sysnet::{self, ProxyKind};

pub struct HttpProxy {
    pub shared: Arc<Shared>,
}

impl HttpProxy {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    pub async fn listen_and_serve(self: Arc<Self>, cancel: CancellationToken) -> Result<(), String> {
        let listener = TcpListener::bind(self.shared.listen)
            .await
            .map_err(|e| format!("error creating listener on {}: {e}", self.shared.listen))?;
        let this = self.clone();
        spawn_accept_loop(listener, self.shared.logger.clone(), cancel, move |conn, peer| {
            let this = this.clone();
            async move { this.handle_connection(conn, peer).await }
        });
        Ok(())
    }

    pub async fn setup_network_jobs(&self, cancel: CancellationToken) -> Result<Option<PathBuf>, String> {
        let Some(state) = sysnet::proxy_state_file(ProxyKind::Http) else {
            return Ok(None);
        };
        let port = self.shared.listen.port();
        let pac = format!(
            "function FindProxyForURL(url, host) {{\n    return \"PROXY 127.0.0.1:{port}; DIRECT\";\n}}"
        );
        let pac_url = run_pac_server(pac, cancel)
            .await
            .map_err(|e| format!("error creating pac server: {e}"))?;
        let jobs = sysnet::build_proxy_jobs(ProxyKind::Http, &self.shared.route, port, &pac_url)?;
        save_jobs(&state, &jobs).map_err(|e| format!("failed to save state: {e}"))?;
        Ok(Some(state))
    }

    async fn handle_connection(self: Arc<Self>, conn: TcpStream, peer: SocketAddr) {
        let trace_id = new_trace_id();
        let logger = self.shared.logger.with_trace(&trace_id).local("conn_init");
        let mut local = BufReader::new(conn);

        let req = match h::read_request(&mut local).await {
            Ok(r) => r,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    warn!(logger, ["err" => e], "failed to read http request");
                }
                return;
            }
        };

        debug!(logger, ["from" => peer, "host" => req.host], "new request");

        if !req.is_valid_method() {
            warn!(logger, ["method" => req.method], "unsupported method. abort");
            let _ = local.write_all(h::NOT_IMPLEMENTED).await;
            return;
        }

        let host = req.extract_host();
        let port = match req.extract_port() {
            Ok(p) => p,
            Err(_) => {
                warn!(logger, ["host" => req.host], "failed to extract port");
                let _ = local.write_all(h::BAD_REQUEST).await;
                return;
            }
        };

        debug!(logger, ["method" => req.method, "from" => peer], "new request");

        let (addrs, rule) = match self.shared.resolve(&host, &logger).await {
            Ok(v) => v,
            Err(e) => {
                let _ = local.write_all(h::BAD_GATEWAY).await;
                error!(logger, ["err" => e], "dns lookup failed for {host}");
                return;
            }
        };

        // Avoid recursively connecting to ourselves.
        if let Err(e) = netutil::is_valid_destination(&addrs, port, self.shared.listen) {
            debug!(logger, ["err" => e], "error validating dst addrs");
            let _ = local.write_all(h::FORBIDDEN).await;
            return;
        }

        if rule.as_ref().is_some_and(|r| r.block) {
            debug!(logger, "request is blocked by policy");
            return;
        }

        let res = if req.is_connect() {
            self.handle_https(local, &addrs, port, &rule, &logger).await
        } else {
            self.handle_http(local, &req, &addrs, port, &rule, &logger).await
        };

        if let Err(e) = res {
            warn!(logger, ["err" => e], "error handling request");
        }
    }

    async fn handle_http(
        &self,
        mut local: BufReader<TcpStream>,
        req: &HttpRequest,
        addrs: &[IpAddr],
        port: u16,
        rule: &Option<Arc<Rule>>,
        logger: &Logger,
    ) -> Result<(), String> {
        let logger = logger.local("http");
        let cfg = self.shared.cfg_for(rule);

        let mut remote = match dial_tcp_fastest(addrs, port, cfg.conn.tcp_timeout, None).await {
            Ok(r) => r,
            Err(e) => {
                let _ = local.write_all(h::BAD_GATEWAY).await;
                return Err(e.to_string());
            }
        };
        debug!(
            logger,
            "new remote conn -> {}",
            remote.peer_addr().map(|a| a.to_string()).unwrap_or_default()
        );

        remote
            .write_all(&req.to_origin_head())
            .await
            .map_err(|e| format!("failed to send request: {e}"))?;

        let route = describe_route(local.get_ref().peer_addr().ok(), remote.peer_addr().ok());
        let res = tunnel(local, remote).await;
        log_tunnel(&logger, &res, &route);
        match res.errors.into_iter().next() {
            Some(e) => Err(e.to_string()),
            None => Ok(()),
        }
    }

    async fn handle_https(
        &self,
        mut local: BufReader<TcpStream>,
        addrs: &[IpAddr],
        port: u16,
        rule: &Option<Arc<Rule>>,
        logger: &Logger,
    ) -> Result<(), String> {
        let logger = logger.local("https");
        let cfg = self.shared.cfg_for(rule);
        self.shared.tls.prepare_hop_track(addrs, &cfg.https);

        // 1. Tell the client the tunnel is ready.
        if let Err(e) = local.write_all(h::CONNECTION_ESTABLISHED).await {
            if super::is_quiet_io_error(&e) {
                return Ok(());
            }
            trace!(logger, ["err" => e], "proxy handshake error");
            return Err(format!("failed to handle proxy handshake: {e}"));
        }
        trace!(
            logger,
            "sent 200 connection established -> {}",
            local
                .get_ref()
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default()
        );

        // 2. Dial the destination.
        let mut remote = dial_tcp_fastest(addrs, port, cfg.conn.tcp_timeout, None)
            .await
            .map_err(|e| e.to_string())?;
        let remote_addr = remote.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        debug!(logger, "new remote conn -> {remote_addr}");

        // 3. Desync the ClientHello when the client starts a TLS handshake.
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
                debug!(logger, ["len" => msg.len()], "client hello received <- {}", local.get_ref().peer_addr().map(|a| a.to_string()).unwrap_or_default());

                if msg.is_client_hello() {
                    let n = self
                        .shared
                        .tls
                        .desync(&mut remote, &msg, &cfg.https, &logger)
                        .await
                        .map_err(|e| format!("failed to send client hello: {e}"))?;
                    debug!(logger, ["len" => n], "sent client hello -> {remote_addr}");
                } else {
                    trace!(logger, ["len" => msg.len()], "not a client hello. fallback to pure tcp");
                    remote
                        .write_all(msg.raw())
                        .await
                        .map_err(|e| format!("failed to write initial bytes to remote: {e}"))?;
                }
            }
            Ok(FirstData::Closed) => return Ok(()),
            Ok(_) => trace!(logger, "not a tls handshake. fallback to pure tcp"),
            Err(e) => return Err(e.to_string()),
        }

        // 4. Relay the rest.
        let route = describe_route(local.get_ref().peer_addr().ok(), remote.peer_addr().ok());
        let res = tunnel(local, remote).await;
        log_tunnel(&logger, &res, &route);
        if res.blocked() {
            return Err("request blocked".into());
        }
        match res.errors.into_iter().next() {
            Some(e) => Err(e.to_string()),
            None => Ok(()),
        }
    }
}
