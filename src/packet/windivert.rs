//! WinDivert backend (Windows). `WinDivert.dll` and `WinDivert64.sys` must
//! be next to the executable and the process must run as Administrator.
//! The DLL is loaded at run time so the binary works without it as long as
//! no fake-packet feature is used.

use std::ffi::{c_char, c_void, CString};
use std::io;
use std::sync::OnceLock;

type Handle = *mut c_void;

const LAYER_NETWORK: i32 = 0;
const FLAG_SNIFF: u64 = 0x0001;
const FLAG_RECV_ONLY: u64 = 0x0004;
const FLAG_SEND_ONLY: u64 = 0x0008;

const ADDR_OUTBOUND: u32 = 1 << 17;
const ADDR_IPV6: u32 = 1 << 20;

/// `WINDIVERT_ADDRESS` (WinDivert 2.x).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved2: u32,
    data: [u8; 64],
}

impl Address {
    fn outbound(ipv6: bool) -> Self {
        Self {
            timestamp: 0,
            flags: ADDR_OUTBOUND | if ipv6 { ADDR_IPV6 } else { 0 },
            reserved2: 0,
            data: [0; 64],
        }
    }

    fn zeroed() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }
}

type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> Handle;
type RecvFn = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "C" fn(Handle) -> i32;
type CalcChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

struct Api {
    _lib: libloading::Library,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    #[allow(dead_code)]
    close: CloseFn,
    calc_checksums: CalcChecksumsFn,
}

// The function pointers are plain C entry points.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| unsafe {
        let lib = libloading::Library::new("WinDivert.dll").map_err(|e| {
            format!("failed to load WinDivert.dll ({e}); put WinDivert.dll and WinDivert64.sys next to spoofdpi.exe")
        })?;
        let open = *lib.get::<OpenFn>(b"WinDivertOpen\0").map_err(|e| e.to_string())?;
        let recv = *lib.get::<RecvFn>(b"WinDivertRecv\0").map_err(|e| e.to_string())?;
        let send = *lib.get::<SendFn>(b"WinDivertSend\0").map_err(|e| e.to_string())?;
        let close = *lib.get::<CloseFn>(b"WinDivertClose\0").map_err(|e| e.to_string())?;
        let calc_checksums = *lib
            .get::<CalcChecksumsFn>(b"WinDivertHelperCalcChecksums\0")
            .map_err(|e| e.to_string())?;
        Ok(Api {
            _lib: lib,
            open,
            recv,
            send,
            close,
            calc_checksums,
        })
    })
    .as_ref()
    .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.clone()))
}

pub struct WinDivert {
    handle: Handle,
    api: &'static Api,
}

unsafe impl Send for WinDivert {}
unsafe impl Sync for WinDivert {}

fn open_error(filter: &str) -> io::Error {
    let err = io::Error::last_os_error();
    let hint = match err.raw_os_error() {
        Some(2) => " (WinDivert64.sys not found next to the executable)",
        Some(5) => " (run spoofdpi as Administrator)",
        Some(577) => " (driver signature could not be verified)",
        Some(1275) => " (driver blocked; an incompatible WinDivert version may be loaded)",
        _ => "",
    };
    io::Error::new(err.kind(), format!("WinDivertOpen({filter:?}): {err}{hint}"))
}

impl WinDivert {
    fn open(filter: &str, flags: u64) -> io::Result<Self> {
        let api = api()?;
        let c = CString::new(filter).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let handle = unsafe { (api.open)(c.as_ptr(), LAYER_NETWORK, 0, flags) };
        if handle.is_null() || handle as isize == -1 {
            return Err(open_error(filter));
        }
        Ok(Self { handle, api })
    }

    /// A handle that only injects packets.
    pub fn sender() -> io::Result<Self> {
        Self::open("false", FLAG_SEND_ONLY)
    }

    /// A handle that receives copies of matching packets without diverting them.
    pub fn sniffer(filter: &str) -> io::Result<Self> {
        Self::open(filter, FLAG_SNIFF | FLAG_RECV_ONLY)
    }

    /// Injects a complete outbound IP packet.
    pub fn send_outbound(&self, pkt: &[u8]) -> io::Result<()> {
        let ipv6 = pkt.first().map(|b| b >> 4 == 6).unwrap_or(false);
        let mut buf = pkt.to_vec();
        let mut addr = Address::outbound(ipv6);
        unsafe {
            (self.api.calc_checksums)(buf.as_mut_ptr().cast(), buf.len() as u32, &mut addr, 0);
            let mut sent = 0u32;
            if (self.api.send)(
                self.handle,
                buf.as_ptr().cast(),
                buf.len() as u32,
                &mut sent,
                &addr,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Blocks until a packet is received; returns its length.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut addr = Address::zeroed();
        let mut n = 0u32;
        let ok = unsafe {
            (self.api.recv)(
                self.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut n,
                &mut addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}
