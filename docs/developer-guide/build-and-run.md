# Build and Run

spoofdpi is written in Rust and builds with plain `cargo`; no C libraries are required.

## Prerequisites

* **Rust:** 1.85 or newer ([rustup.rs](https://rustup.rs)).
* **Windows cross-compilation (optional):** the MinGW-w64 toolchain
  (`sudo apt install gcc-mingw-w64-x86-64`) and `rustup target add x86_64-pc-windows-gnu`.
  Building natively on Windows with the MSVC toolchain also works.

## Running from Source Code

Arguments can be passed after `--`:

```console
$ cargo run -- --https-chunk-size 1 --no-tui
```

## Building an Executable

```console
$ cargo build --release
```

### Windows `.exe`

```console
$ cargo build --release --target x86_64-pc-windows-gnu
```

Or use `make build-windows`. The resulting `spoofdpi.exe` only links against system DLLs.
`WinDivert.dll`/`WinDivert64.sys` (fake packets) and `wintun.dll` (`tun` mode) are loaded at run
time and only when those features are enabled; place them next to the executable.

## Platform support

| Feature | Windows | Linux | macOS |
| :--- | :---: | :---: | :---: |
| HTTP / SOCKS5 proxy, split & disorder | ✅ | ✅ | ✅ |
| Fake packets | ✅ WinDivert | ✅ raw sockets (IPv4) | ❌ |
| `tun` mode | ✅ Wintun | ✅ | ❌ |
| `auto-configure-network` | ✅ system proxy / routes | ✅ routes (`tun` only) | ✅ system proxy |

## Source layout

| Path | Contents |
| :--- | :--- |
| `src/config` | TOML/CLI configuration and the load pipeline |
| `src/proto` | TLS, HTTP and SOCKS5 wire formats |
| `src/desync` | ClientHello splitting, disorder and fake packets |
| `src/server` | HTTP, SOCKS5 and TUN front-ends |
| `src/dns` | UDP, DoH and system resolvers |
| `src/rule` | Domain/CIDR rule matching |
| `src/packet` | Raw packet crafting, WinDivert and hop-count learning |
| `src/sysnet` | OS integration: routes, system proxy, TUN device |
| `src/tui.rs` | Terminal UI |
