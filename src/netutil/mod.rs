//! Networking helpers shared by all server modes.

mod dial;
pub mod jobs;
pub mod sockopt;
mod system;
mod tunnel;

pub use dial::{dial_tcp_fastest, dial_udp, BindSpec};
pub use system::{addr_in_cidr, find_safe_cidr, is_valid_destination, run_pac_server};
pub use tunnel::{count_rx, count_tx, rx_bytes, tunnel, tx_bytes, TunnelResult};
