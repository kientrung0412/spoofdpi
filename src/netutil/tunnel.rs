//! Bidirectional byte relay with global traffic counters.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

static TX_BYTES: AtomicU64 = AtomicU64::new(0);
static RX_BYTES: AtomicU64 = AtomicU64::new(0);

/// Bytes sent to remote servers.
pub fn tx_bytes() -> u64 {
    TX_BYTES.load(Ordering::Relaxed)
}

/// Bytes received from remote servers.
pub fn rx_bytes() -> u64 {
    RX_BYTES.load(Ordering::Relaxed)
}

pub fn count_tx(n: usize) {
    TX_BYTES.fetch_add(n as u64, Ordering::Relaxed);
}

pub fn count_rx(n: usize) {
    RX_BYTES.fetch_add(n as u64, Ordering::Relaxed);
}

#[derive(Debug, Default)]
pub struct TunnelResult {
    pub out_bytes: u64,
    pub in_bytes: u64,
    pub errors: Vec<io::Error>,
    pub took: Duration,
}

impl TunnelResult {
    pub fn blocked(&self) -> bool {
        self.errors
            .iter()
            .any(|e| e.kind() == io::ErrorKind::ConnectionReset)
    }
}

fn benign(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

async fn copy_counted<R, W>(r: &mut R, w: &mut W, counter: &AtomicU64) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        total += n as u64;
    }
}

/// Relays `local` <-> `remote` until both directions finish or one fails.
/// End of stream on one side is forwarded as a write shutdown on the other.
pub async fn tunnel<L, R>(local: L, remote: R) -> TunnelResult
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let (mut lr, mut lw) = tokio::io::split(local);
    let (mut rr, mut rw) = tokio::io::split(remote);

    let out = async {
        let res = copy_counted(&mut lr, &mut rw, &TX_BYTES).await;
        let _ = rw.shutdown().await;
        res
    };
    let inn = async {
        let res = copy_counted(&mut rr, &mut lw, &RX_BYTES).await;
        let _ = lw.shutdown().await;
        res
    };
    tokio::pin!(out, inn);

    let mut res_out: Option<io::Result<u64>> = None;
    let mut res_in: Option<io::Result<u64>> = None;
    while res_out.is_none() || res_in.is_none() {
        tokio::select! {
            r = &mut out, if res_out.is_none() => {
                let failed = r.is_err();
                res_out = Some(r);
                if failed { break; }
            }
            r = &mut inn, if res_in.is_none() => {
                let failed = r.is_err();
                res_in = Some(r);
                if failed { break; }
            }
        }
    }

    let mut result = TunnelResult {
        took: started.elapsed(),
        ..Default::default()
    };
    for (res, slot) in [(res_out, &mut result.out_bytes), (res_in, &mut result.in_bytes)] {
        match res {
            Some(Ok(n)) => *slot = n,
            Some(Err(e)) if !benign(&e) => result.errors.push(e),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relays_both_directions() {
        let (client, mut client_peer) = tokio::io::duplex(1024);
        let (server, mut server_peer) = tokio::io::duplex(1024);

        let task = tokio::spawn(tunnel(client, server));

        client_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        server_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server_peer.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        client_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!");

        drop(client_peer);
        drop(server_peer);
        let res = task.await.unwrap();
        assert_eq!(res.out_bytes, 5);
        assert_eq!(res.in_bytes, 6);
    }
}
