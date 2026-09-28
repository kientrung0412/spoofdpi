<p align="center">
  <img alt="spoofdpi" src="./docs/static/banner.jpg" height="200" />
</p>

> [!CAUTION]
> SpoofDPI is NOT available on iOS or Android. Official binaries are ONLY provided through GitHub and official package managers. DO NOT download SpoofDPI from other sources, as they may contain malware.

`spoofdpi` is a simple proxy tool, mainly designed to neutralize the *Deep Packet Inspection (DPI)* techniques that power many internet censorship systems.

> [!NOTE]
> This branch is a rewrite of spoofdpi in **Rust** with first-class **Windows 10/11 (x64)** support.
> It keeps the command-line flags and the `spoofdpi.toml` format of the Go version.

For more detailed information, please refer to the [Official Documentation](https://spoofdpi.dev).

[Join our Discord channel](https://discord.gg/k7qMbqhrcH) for discussions (If you can 😅).

## 🪟 Windows quick start

1. Download `spoofdpi-windows-x86_64.zip` from the releases page and extract it.
2. Run `spoofdpi.exe` (HTTP proxy on `127.0.0.1:8080`), or let it set the Windows proxy for you:
   ```console
   > spoofdpi.exe --auto-configure-network
   ```
   The previous proxy settings are restored when spoofdpi exits (Ctrl+C or closing the window).

Optional features need extra files next to `spoofdpi.exe` (included in the release zip) and
must be run **as Administrator**:

| Feature | Needs |
| :--- | :--- |
| `--https-fake-count`, `--udp-fake-count` (fake packets) | `WinDivert.dll`, `WinDivert64.sys` ([WinDivert](https://reqrypt.org/windivert.html)) |
| `--app-mode tun` | `wintun.dll` ([Wintun](https://www.wintun.net)) |

The config file is read from `spoofdpi.toml` next to `spoofdpi.exe`, or from
`%APPDATA%\spoofdpi\spoofdpi.toml`.

## 🔨 Building

```console
$ cargo build --release                                   # native
$ cargo build --release --target x86_64-pc-windows-gnu    # cross-compile a Windows .exe
```

See [Build and Run](docs/developer-guide/build-and-run.md) for details.

## 📦 Packaging Status

<a href="https://repology.org/project/spoofdpi/versions">
    <img src="https://repology.org/badge/vertical-allrepos/spoofdpi.svg?columns=1" alt="Packaging status">
</a>

## ☕ Github Sponsors
Your sponsorship directly fuels the motivation required for continued project maintenance. If you find spoofdpi valuable, please consider supporting [@xvzc on Github](https://github.com/sponsors/xvzc).

## 💡 Inspirations
[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel) by @SadeghHayeri  
[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by @ValdikSS

## 🔗 See Also
[DPIBreak](https://github.com/dilluti0n/dpibreak) by @dilluti0n - kernel based circumvention tool for Linux and Windows
