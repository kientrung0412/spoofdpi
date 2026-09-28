//! spoofdpi - simple and fast anti-censorship tool to bypass DPI.

#[macro_use]
mod logging;

mod config;
mod desync;
mod dns;
mod netutil;
mod packet;
mod proto;
mod rule;
mod server;
mod sysnet;
mod tui;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{CommandFactory, FromArgMatches};
use tokio_util::sync::CancellationToken;

use config::cli::Cli;
use config::{AppMode, Config};
use desync::{TlsDesyncer, UdpDesyncer};
use logging::Logger;
use packet::{HopTracker, PacketWriter, SniffKind};
use server::{Server, Shared};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = match option_env!("SPOOFDPI_COMMIT") {
    Some(c) => c,
    None => "unknown",
};
const BUILD: &str = match option_env!("SPOOFDPI_BUILD") {
    Some(b) => b,
    None => "cargo",
};

fn main() {
    let cmd = Cli::command().after_long_help(config::cli::enum_values_help());
    let cli = match Cli::from_arg_matches(&cmd.get_matches()) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    if cli.version {
        println!("spoofdpi {VERSION} {COMMIT} ({BUILD})");
        println!("Official docs at https://spoofdpi.xvzc.dev");
        return;
    }

    let (cfg, config_path) = match config::load::load(&cli) {
        Ok(v) => v,
        Err(e) => fail(&e),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => fail(&e.to_string()),
    };

    let code = runtime.block_on(run(cfg, config_path));
    runtime.shutdown_timeout(Duration::from_secs(2));
    std::process::exit(code);
}

fn fail(msg: &str) -> ! {
    println!("application failed to start");
    eprintln!("{msg}");
    std::process::exit(1);
}

async fn run(cfg: Config, config_path: Option<PathBuf>) -> i32 {
    let cancel = CancellationToken::new();
    spawn_signal_handlers(cancel.clone());

    let tui = if cfg.app.no_tui {
        logging::use_stdout();
        None
    } else {
        match tui::Tui::start(cancel.clone()) {
            Ok((t, tx)) => {
                logging::use_channel(tx);
                Some(t)
            }
            Err(e) => {
                println!("application failed to start");
                eprintln!("failed to start tui: {e}");
                return 1;
            }
        }
    };

    logging::set_level(cfg.app.log_level);
    logging::set_write_delay(Duration::from_millis(29));
    let logger = Logger::new("app").with_trace(&logging::new_trace_id());

    let mut state_file: Option<PathBuf> = None;
    let result = start(&cfg, config_path, &logger, &cancel, &mut state_file).await;
    logging::set_write_delay(Duration::ZERO);

    let code = match result {
        Ok(()) => {
            cancel.cancelled().await;
            0
        }
        Err(e) if tui.is_some() => {
            // Keep the error visible in the TUI until the user quits.
            error!(logger, ["err" => e], "application failed to start");
            cancel.cancelled().await;
            0
        }
        Err(e) => {
            if let Some(path) = &state_file {
                netutil::jobs::reset_jobs(&logger, path);
            }
            logging::use_stdout();
            println!("application failed to start");
            eprintln!("{e}");
            return 1;
        }
    };

    if let Some(path) = &state_file {
        info!(logger, "restoring network configuration");
        let logger = logger.clone();
        let path = path.clone();
        let _ = tokio::task::spawn_blocking(move || netutil::jobs::reset_jobs(&logger, &path)).await;
    }
    info!(logger, "bye");

    if let Some(t) = tui {
        logging::use_stdout();
        tokio::task::block_in_place(|| t.stop());
    }
    code
}

async fn start(
    cfg: &Config,
    config_path: Option<PathBuf>,
    logger: &Logger,
    cancel: &CancellationToken,
    state_file: &mut Option<PathBuf>,
) -> Result<(), String> {
    info!(logger, ["version" => VERSION], "spoofdpi");
    match &config_path {
        Some(p) => info!(logger, ["dir" => p.display()], "loaded config file"),
        None => {
            warn!(logger, "config file not found");
            if cfg!(windows) {
                warn!(logger, " put spoofdpi.toml next to spoofdpi.exe or in %APPDATA%\\spoofdpi\\ to load a configuration");
            } else {
                warn!(
                    logger,
                    " please try 'sudo -E spoofdpi' if you expect a configuration to be loaded"
                );
            }
        }
    }
    for m in config::take_warn_msgs() {
        warn!(logger, "{m}");
    }
    info!(logger, ["mode" => cfg.app.mode], "app");

    if (cfg.app.mode == AppMode::Tun || cfg.needs_packet()) && !sysnet::is_elevated() {
        warn!(
            logger,
            "{} requires administrator privileges",
            if cfg.app.mode == AppMode::Tun {
                "tun mode"
            } else {
                "sending fake packets"
            }
        );
    }

    let srv = create_server(cfg, logger, cancel).await?;

    let https = &cfg.runtime.https;
    info!(logger, "https info");
    info!(logger, ["split-mode" => https.split_mode, "chunk-size" => https.chunk_size, "disorder" => https.disorder], " split");
    info!(logger, ["count" => https.fake_count], " fake");
    let conn = &cfg.runtime.conn;
    for (name, d) in [
        ("dns connection timeout", conn.dns_timeout),
        ("tcp connection timeout", conn.tcp_timeout),
        ("udp idle timeout", conn.udp_idle_timeout),
    ] {
        if !d.is_zero() {
            info!(logger, ["value" => format!("{}ms", d.as_millis())], "{name}");
        }
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    srv.listen_and_serve(cancel.clone())
        .await
        .map_err(|e| format!("listen and serve: {e}"))?;
    info!(logger, "server started on {}", srv.addr());

    if cfg.app.auto_configure_network {
        match srv.setup_network_jobs(cancel.clone()).await {
            Err(e) => error!(logger, ["err" => e], "failed to set system network config"),
            Ok(None) => warn!(logger, "auto-configure-network is not supported on this platform"),
            Ok(Some(path)) => {
                let l = logger.clone();
                let p = path.clone();
                let applied = tokio::task::spawn_blocking(move || netutil::jobs::apply_jobs(&l, &p))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                match applied {
                    Ok(()) => {
                        info!(logger, "system network configured");
                        *state_file = Some(path);
                    }
                    Err(e) => error!(logger, ["err" => e], "failed to apply network config"),
                }
            }
        }
    }
    Ok(())
}

async fn create_server(cfg: &Config, logger: &Logger, cancel: &CancellationToken) -> Result<Server, String> {
    let mut rules = rule::RuleSet::new();
    for r in &cfg.rules {
        rules.add(r.clone())?;
    }

    let base = Arc::new(cfg.runtime.clone());
    let dns = dns::Client::new(logger.scoped("dns"), base.clone(), cancel.clone());

    // Clean up state left behind by a crashed session before looking at
    // the routing table.
    for path in [
        sysnet::tun_state_file(),
        sysnet::proxy_state_file(sysnet::ProxyKind::Http),
        sysnet::proxy_state_file(sysnet::ProxyKind::Socks5),
    ]
    .into_iter()
    .flatten()
    {
        netutil::jobs::reset_jobs(logger, &path);
    }

    let discovered = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(sysnet::discover_route),
    )
    .await
    .map_err(|_| "timed out".to_string())
    .and_then(|r| r.map_err(|e| e.to_string()))
    .and_then(|r| r);
    let route = match discovered {
        Ok(r) => r,
        // Only TUN mode and fake packets depend on the physical interface.
        Err(e) if cfg.app.mode == AppMode::Tun || cfg.needs_packet() => {
            return Err(format!("failed to find default route: {e}"))
        }
        Err(e) => {
            warn!(logger, ["err" => e], "failed to find default route");
            sysnet::fallback_route()
        }
    };

    let (writer, tracker) = setup_packet_io(cfg, &route, logger)?;
    let tls = Arc::new(TlsDesyncer::new(writer.clone(), tracker.clone()));
    let udp = Arc::new(UdpDesyncer::new(writer, tracker));

    let tun_setup = if cfg.app.mode == AppMode::Tun {
        info!(
            logger,
            ["interface" => route.display_name, "gateway" => route.gateway.map(|g| g.to_string()).unwrap_or_default()],
            "determined default interface and gateway"
        );
        let r = route.clone();
        Some(
            tokio::task::spawn_blocking(move || sysnet::create_tun(&r))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| format!("failed to create sysnet: {e}"))?,
        )
    } else {
        None
    };

    let shared = Arc::new(Shared {
        logger: logger.scoped("srv"),
        cfg: base,
        rules: Arc::new(rules),
        dns,
        tls,
        udp,
        listen: cfg.listen_addr(),
        route,
    });

    Ok(match cfg.app.mode {
        AppMode::Http => Server::Http(Arc::new(server::http::HttpProxy::new(shared))),
        AppMode::Socks5 => Server::Socks5(Arc::new(server::socks5::Socks5Proxy::new(shared))),
        AppMode::Tun => Server::Tun(Arc::new(server::tun::TunServer::new(shared, tun_setup.unwrap()))),
    })
}

type PacketIo = (Option<Arc<PacketWriter>>, Option<Arc<HopTracker>>);

fn setup_packet_io(cfg: &Config, route: &sysnet::Route, logger: &Logger) -> Result<PacketIo, String> {
    if !cfg.needs_packet() {
        return Ok((None, None));
    }
    let pkt_logger = logger.scoped("pkt");

    info!(logger, "network info");
    info!(logger, ["name" => route.display_name, "mac" => route.mac.clone().unwrap_or_default()], " interface");
    info!(logger, ["mac" => route.gateway_mac.clone().unwrap_or_default()], " gateway");

    let writer = PacketWriter::open().map_err(|e| format!("failed to open packet writer: {e}"))?;
    let tracker = Arc::new(HopTracker::new(cfg.runtime.conn.default_fake_ttl));

    if cfg.needs_packet_tcp() {
        packet::start_sniffer(SniffKind::Tcp, tracker.clone(), pkt_logger.clone())
            .map_err(|e| format!("tcp packet capture: {e}"))?;
    }
    if cfg.needs_packet_udp() {
        packet::start_sniffer(SniffKind::Udp, tracker.clone(), pkt_logger)
            .map_err(|e| format!("udp packet capture: {e}"))?;
    }
    Ok((Some(Arc::new(writer)), Some(tracker)))
}

fn spawn_signal_handlers(cancel: CancellationToken) {
    let c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        c.cancel();
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        for kind in [SignalKind::terminate(), SignalKind::hangup(), SignalKind::quit()] {
            let c = cancel.clone();
            if let Ok(mut s) = signal(kind) {
                tokio::spawn(async move {
                    s.recv().await;
                    c.cancel();
                });
            }
        }
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows;
        // Closing the console window, logging off or shutting down must still
        // restore the system proxy settings.
        macro_rules! on {
            ($f:expr) => {
                if let Ok(mut s) = $f {
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        s.recv().await;
                        c.cancel();
                    });
                }
            };
        }
        on!(windows::ctrl_break());
        on!(windows::ctrl_close());
        on!(windows::ctrl_logoff());
        on!(windows::ctrl_shutdown());
    }
}
