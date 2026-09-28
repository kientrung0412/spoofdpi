//! TLS ClientHello desynchronization: split the record into segments,
//! optionally send some of them with TTL 1 ("disorder") so they arrive
//! out of order after retransmission, and optionally precede it with fake
//! ClientHellos whose TTL expires before the server.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use rand::Rng;
use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{HttpsOptions, SegmentFrom, SegmentPlan, SplitMode};
use crate::logging::Logger;
use crate::netutil::{count_tx, sockopt};
use crate::packet::{HopTracker, PacketWriter};
use crate::proto::tls::TlsMessage;

/// A byte range of the message and whether it is sent with TTL 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub start: usize,
    pub end: usize,
    pub lazy: bool,
}

impl Segment {
    fn new(start: usize, end: usize, lazy: bool) -> Self {
        Self { start, end, lazy }
    }
}

pub struct TlsDesyncer {
    writer: Option<Arc<PacketWriter>>,
    tracker: Option<Arc<HopTracker>>,
}

impl TlsDesyncer {
    pub fn new(writer: Option<Arc<PacketWriter>>, tracker: Option<Arc<HopTracker>>) -> Self {
        Self { writer, tracker }
    }

    /// Registers destinations for hop-count learning when fakes will be sent.
    pub fn prepare_hop_track(&self, addrs: &[IpAddr], opts: &HttpsOptions) {
        if let Some(t) = &self.tracker {
            if !opts.skip && opts.fake_count > 0 {
                t.register(addrs);
            }
        }
    }

    pub async fn desync(
        &self,
        conn: &mut TcpStream,
        msg: &TlsMessage,
        opts: &HttpsOptions,
        logger: &Logger,
    ) -> io::Result<usize> {
        let logger = logger.local("tls_desync");

        if opts.skip {
            trace!(logger, "skip desync for this request");
            conn.write_all(msg.raw()).await?;
            count_tx(msg.len());
            return Ok(msg.len());
        }

        if opts.fake_count > 0 {
            if let (Some(w), Some(t)) = (&self.writer, &self.tracker) {
                let ttl = t.optimal_ttl(conn.peer_addr()?.ip());
                match self.send_fake_packets(conn, w, ttl, opts, &logger) {
                    Ok(n) => debug!(logger, ["len" => n, "ttl" => ttl], "sent fake packets"),
                    Err(e) => warn!(logger, ["err" => e], "failed to send fake packets"),
                }
            }
        }

        let segments = split(&logger, msg, opts);
        send_segments(conn, msg.raw(), &segments, &logger).await
    }

    fn send_fake_packets(
        &self,
        conn: &TcpStream,
        writer: &PacketWriter,
        ttl: u8,
        opts: &HttpsOptions,
        logger: &Logger,
    ) -> io::Result<usize> {
        let fake = TlsMessage::fake(opts.fake_packet.as_ref().clone());
        let segments = split(logger, &fake, opts);
        let (src, dst) = (conn.local_addr()?, conn.peer_addr()?);
        let mut total = 0;
        for _ in 0..opts.fake_count {
            for s in &segments {
                total += writer.write_tcp(src, dst, ttl, &fake.raw()[s.start..s.end])?;
            }
        }
        Ok(total)
    }
}

/// Writes the segments in order, lowering the TTL to 1 around lazy ones.
pub async fn send_segments(
    conn: &mut TcpStream,
    raw: &[u8],
    segments: &[Segment],
    logger: &Logger,
) -> io::Result<usize> {
    let ipv4 = match conn.peer_addr()?.ip() {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    };
    let default_ttl = sockopt::ttl(SockRef::from(&*conn), ipv4).unwrap_or(64);
    let mut ttl_errored = false;

    let mut total = 0;
    for seg in segments {
        if seg.start == seg.end {
            continue;
        }
        if seg.lazy && !ttl_errored {
            if let Err(e) = sockopt::set_ttl(SockRef::from(&*conn), ipv4, 1) {
                warn!(logger, ["err" => e], "failed to set TTL, continuing without modifying ttl");
                ttl_errored = true;
            }
        }

        conn.write_all(&raw[seg.start..seg.end]).await?;
        count_tx(seg.end - seg.start);
        total += seg.end - seg.start;

        if seg.lazy && !ttl_errored {
            if let Err(e) = sockopt::set_ttl(SockRef::from(&*conn), ipv4, default_ttl) {
                warn!(logger, ["err" => e], "failed to set TTL, continuing without modifying ttl");
                ttl_errored = true;
            }
        }
    }
    Ok(total)
}

/// Computes the segments for `msg` according to the split mode. Falls back
/// to a single segment when the mode cannot be applied.
pub fn split(logger: &Logger, msg: &TlsMessage, opts: &HttpsOptions) -> Vec<Segment> {
    let len = msg.len();
    let whole = || vec![Segment::new(0, len, false)];

    let res: Result<Vec<Segment>, String> = match opts.split_mode {
        SplitMode::Sni => match msg.sni_offset() {
            Ok((start, end)) => {
                trace!(
                    logger,
                    "extracted SNI is '{}'",
                    String::from_utf8_lossy(&msg.raw()[start..end])
                );
                split_sni(len, start, end, opts.disorder)
            }
            Err(e) => Err(e.to_string()),
        },
        SplitMode::Random => split_mask(len, gen_pattern_mask(), opts.disorder),
        SplitMode::Chunk => split_chunks(len, opts.chunk_size as usize, opts.disorder),
        SplitMode::FirstByte => split_first_byte(len, opts.disorder),
        SplitMode::Custom => apply_segment_plans(msg, &opts.custom_segments),
        SplitMode::None => Ok(whole()),
    };

    match res {
        Ok(segments) => {
            debug!(
                logger,
                ["len" => segments.len(), "mode" => opts.split_mode, "kind" => msg.kind(), "disorder" => opts.disorder],
                "segments ready"
            );
            segments
        }
        Err(e) => {
            debug!(
                logger,
                ["err" => e, "kind" => msg.kind()],
                "error processing split mode '{}', fallback to 'none'",
                opts.split_mode
            );
            whole()
        }
    }
}

pub fn split_chunks(len: usize, size: usize, disorder: bool) -> Result<Vec<Segment>, String> {
    if len == 0 {
        return Err("empty data".into());
    }
    if size == 0 {
        return Err("size == 0".into());
    }
    let mut out = Vec::with_capacity(len.div_ceil(size));
    let mut cur_disorder = true;
    let mut pos = 0;
    while pos < len {
        let end = (pos + size).min(len);
        out.push(Segment::new(pos, end, cur_disorder && disorder));
        pos = end;
        cur_disorder = !cur_disorder;
    }
    Ok(out)
}

pub fn split_first_byte(len: usize, disorder: bool) -> Result<Vec<Segment>, String> {
    if len < 2 {
        return Err("len(raw) is less than 2".into());
    }
    Ok(vec![Segment::new(0, 1, disorder), Segment::new(1, len, false)])
}

pub fn split_sni(len: usize, start: usize, end: usize, disorder: bool) -> Result<Vec<Segment>, String> {
    if len == 0 {
        return Err("empty data".into());
    }
    if start > end {
        return Err("invalid start, end pos (start > end)".into());
    }
    if len <= start || len <= end {
        return Err("invalid start, end pos (out of range)".into());
    }
    let mut out = Vec::with_capacity(end - start + 2);
    out.push(Segment::new(0, start, false));
    let mut cur_disorder = true;
    for i in start..end {
        out.push(Segment::new(i, i + 1, cur_disorder && disorder));
        cur_disorder = !cur_disorder;
    }
    out.push(Segment::new(end, len, cur_disorder && disorder));
    Ok(out)
}

pub fn split_mask(len: usize, mask: u64, disorder: bool) -> Result<Vec<Segment>, String> {
    if len == 0 {
        return Err("empty data".into());
    }
    let mut out = Vec::new();
    let mut cur_disorder = true;
    let mut start = 0;
    let mut bit = 1u64;
    for i in 0..len {
        if mask & bit == bit {
            if i > start {
                out.push(Segment::new(start, i, cur_disorder && disorder));
                cur_disorder = !cur_disorder;
            }
            out.push(Segment::new(i, i + 1, cur_disorder && disorder));
            start = i + 1;
            cur_disorder = !cur_disorder;
        }
        bit = bit.rotate_left(1);
    }
    if len > start {
        out.push(Segment::new(start, len, cur_disorder && disorder));
    }
    Ok(out)
}

pub fn apply_segment_plans(msg: &TlsMessage, plans: &[SegmentPlan]) -> Result<Vec<Segment>, String> {
    let len = msg.len() as i64;
    let (sni_start, _) = msg.sni_offset().map_err(String::from)?;
    let mut rng = rand::rng();

    let mut points: Vec<(i64, bool)> = plans
        .iter()
        .map(|p| {
            let base = if p.from == SegmentFrom::Sni {
                sni_start as i64
            } else {
                0
            };
            let mut at = base + p.at;
            if p.noise > 0 {
                at += rng.random_range(0..=p.noise * 2) - p.noise;
            }
            (at.clamp(0, len), p.lazy)
        })
        .collect();
    points.sort_by_key(|p| p.0);

    let mut out = Vec::new();
    let mut prev = 0i64;
    for (at, lazy) in points {
        if at == prev {
            continue;
        }
        out.push(Segment::new(prev as usize, at as usize, lazy));
        prev = at;
    }
    if prev < len {
        out.push(Segment::new(prev as usize, len as usize, false));
    }
    Ok(out)
}

fn rotl8(x: u8, k: i64) -> u8 {
    x.rotate_left((k as u64 & 7) as u32)
}

/// Pseudo-random 64-bit mask of split points with at least one bit set in
/// every byte (xorshift-mutated seed, same layout as the Go implementation).
pub fn gen_pattern_mask() -> u64 {
    let mut seed: u64 = rand::random();
    let mut ret: u64 = 0b1010_1001;

    seed ^= seed >> 13;
    ret |= (rotl8(0b1000_0000, seed as i64) as u64) << 8;
    seed ^= seed << 11;
    ret |= (rotl8(0b1000_0000, -((seed % 7) as i64) + 1) as u64) << 8;

    seed ^= seed >> 17;
    ret |= (rotl8(0b0000_0001, seed as i64) as u64) << 16;

    seed ^= seed << 5;
    ret |= (rotl8(0b0000_0001, seed as i64) as u64) << 24;

    seed ^= seed >> 12;
    ret |= (rotl8(0b0000_0001, (seed % 2) as i64) as u64) << 32;
    ret |= (rotl8(0b0000_0001, (seed % 3) as i64 + 2) as u64) << 32;
    ret |= (rotl8(0b0000_0001, (seed % 3) as i64 + 5) as u64) << 32;

    seed ^= seed << 25;
    ret |= (rotl8(0b0000_0001, seed as i64) as u64) << 40;

    seed ^= seed >> 27;
    ret |= (rotl8(0b0000_0001, seed as i64) as u64) << 48;

    seed ^= seed << 13;
    ret |= (rotl8(0b0000_0001, seed as i64) as u64) << 56;

    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tls::tests::client_hello;

    fn covers(segs: &[Segment], len: usize) -> bool {
        let mut pos = 0;
        for s in segs {
            if s.start != pos || s.end < s.start {
                return false;
            }
            pos = s.end;
        }
        pos == len
    }

    #[test]
    fn chunks() {
        let s = split_chunks(10, 4, true).unwrap();
        assert_eq!(
            s,
            vec![
                Segment::new(0, 4, true),
                Segment::new(4, 8, false),
                Segment::new(8, 10, true)
            ]
        );
        assert!(split_chunks(0, 4, false).is_err());
        assert!(split_chunks(10, 0, false).is_err());
        assert!(split_chunks(10, 3, false).unwrap().iter().all(|s| !s.lazy));
    }

    #[test]
    fn first_byte() {
        assert_eq!(
            split_first_byte(5, true).unwrap(),
            vec![Segment::new(0, 1, true), Segment::new(1, 5, false)]
        );
        assert!(split_first_byte(1, false).is_err());
    }

    #[test]
    fn sni_split() {
        let s = split_sni(10, 3, 6, true).unwrap();
        assert_eq!(s.len(), 5);
        assert_eq!(s[0], Segment::new(0, 3, false));
        assert_eq!(s[1], Segment::new(3, 4, true));
        assert_eq!(s[2], Segment::new(4, 5, false));
        assert_eq!(s[3], Segment::new(5, 6, true));
        assert_eq!(s[4], Segment::new(6, 10, false));
        assert!(covers(&s, 10));
        assert!(split_sni(10, 6, 3, false).is_err());
        assert!(split_sni(10, 3, 10, false).is_err());
    }

    #[test]
    fn mask_split() {
        // Bits 0 and 3 set.
        let s = split_mask(6, 0b1001, false).unwrap();
        assert_eq!(
            s,
            vec![
                Segment::new(0, 1, false),
                Segment::new(1, 3, false),
                Segment::new(3, 4, false),
                Segment::new(4, 6, false)
            ]
        );
        for _ in 0..50 {
            let m = gen_pattern_mask();
            assert_eq!(m & 1, 1);
            for byte in 0..8 {
                assert_ne!((m >> (byte * 8)) & 0xff, 0, "byte {byte} of {m:#x}");
            }
            assert!(covers(&split_mask(517, m, true).unwrap(), 517));
        }
    }

    #[test]
    fn segment_plans() {
        let raw = client_hello("www.example.com");
        let msg = TlsMessage::real(raw.clone());
        let (sni, _) = msg.sni_offset().unwrap();
        let plans = vec![
            SegmentPlan {
                from: SegmentFrom::Sni,
                at: 4,
                lazy: true,
                noise: 0,
            },
            SegmentPlan {
                from: SegmentFrom::Head,
                at: 1,
                lazy: false,
                noise: 0,
            },
            SegmentPlan {
                from: SegmentFrom::Head,
                at: 1,
                lazy: false,
                noise: 0,
            },
            SegmentPlan {
                from: SegmentFrom::Head,
                at: 100_000,
                lazy: false,
                noise: 0,
            },
        ];
        let s = apply_segment_plans(&msg, &plans).unwrap();
        assert_eq!(s[0], Segment::new(0, 1, false));
        assert_eq!(s[1], Segment::new(1, sni + 4, true));
        assert_eq!(s[2], Segment::new(sni + 4, raw.len(), false));
        assert_eq!(s.len(), 3);
        assert!(covers(&s, raw.len()));

        let noisy = vec![SegmentPlan {
            from: SegmentFrom::Sni,
            at: 0,
            lazy: false,
            noise: 3,
        }];
        for _ in 0..20 {
            let s = apply_segment_plans(&msg, &noisy).unwrap();
            assert!(s[0].end.abs_diff(sni) <= 3);
            assert!(covers(&s, raw.len()));
        }
    }

    #[test]
    fn split_falls_back_to_whole_message() {
        let logger = Logger::new("test");
        let mut opts = crate::config::Config::default().runtime.https;
        let msg = TlsMessage::real(vec![0x16, 0x03, 0x01, 0x00, 0x01, 0x02]);
        opts.split_mode = SplitMode::Sni;
        assert_eq!(split(&logger, &msg, &opts), vec![Segment::new(0, 6, false)]);

        let hello = TlsMessage::real(client_hello("a.example.org"));
        let segs = split(&logger, &hello, &opts);
        assert!(segs.len() > 2);
        assert!(covers(&segs, hello.len()));
    }

    #[tokio::test]
    async fn segments_arrive_in_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut conn = TcpStream::connect(addr).await.unwrap();
        let raw = client_hello("order.test");
        let segs = split_chunks(raw.len(), 7, true).unwrap();
        let n = send_segments(&mut conn, &raw, &segs, &Logger::new("t"))
            .await
            .unwrap();
        assert_eq!(n, raw.len());
        // TTL is restored after lazy segments.
        let ttl = sockopt::ttl(SockRef::from(&conn), true).unwrap();
        assert!(ttl > 1);
        drop(conn);
        assert_eq!(server.await.unwrap(), raw);
    }
}
