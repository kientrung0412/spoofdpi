## Windows 10/11 (x64)

1. Download `spoofdpi-windows-x86_64.zip` from the [releases page](https://github.com/xvzc/spoofdpi/releases) and extract it anywhere.
2. Open a terminal in that folder and run:

```console
> spoofdpi.exe
```

The release zip also contains the optional runtime files. They must stay in the same folder as
`spoofdpi.exe`:

| File | Needed for | Notes |
| :--- | :--- | :--- |
| `WinDivert.dll`, `WinDivert64.sys` | fake packets (`https.fake-count`, `udp.fake-count`) | run as Administrator |
| `wintun.dll` | `tun` mode | run as Administrator |

Plain HTTP/SOCKS5 proxying with packet splitting works without any of them and without
Administrator rights.

!!! tip
    Use `--auto-configure-network` to point the Windows proxy settings at spoofdpi. The previous
    settings are restored when spoofdpi exits, including when the console window is closed.

## Linux and macOS

Prebuilt binaries are attached to each release. Fake packets on Linux use raw sockets and need
root (or `CAP_NET_RAW`); `tun` mode needs root. Fake packets and `tun` mode are not available on
macOS in this version.

## Manual Build

Install a Rust toolchain (1.85 or newer) from [rustup.rs](https://rustup.rs), then:

```console
$ git clone https://github.com/xvzc/spoofdpi.git
$ cd spoofdpi
$ cargo build --release
$ ./target/release/spoofdpi --version
```

To embed the commit hash in `--version`, set `SPOOFDPI_COMMIT` and `SPOOFDPI_BUILD` at build time:

```console
$ SPOOFDPI_COMMIT=$(git rev-parse --short HEAD) SPOOFDPI_BUILD=git cargo build --release
```

### Cross-compiling for Windows from Linux

```console
$ sudo apt install gcc-mingw-w64-x86-64
$ rustup target add x86_64-pc-windows-gnu
$ cargo build --release --target x86_64-pc-windows-gnu
$ ls target/x86_64-pc-windows-gnu/release/spoofdpi.exe
```
