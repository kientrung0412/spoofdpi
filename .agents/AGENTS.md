# AGENTS.md

## Project

spoofdpi is a proxy tool that bypasses Deep Packet Inspection (DPI) — the technique used by many internet censorship systems to inspect and block traffic. It works by fragmenting and desynchronizing TLS handshakes so that DPI middleboxes misparse the connection while the destination server handles it normally.

This branch is a Rust implementation (see `Cargo.toml`, sources under `src/`). Windows 10/11 x64 is a
primary target; keep `cargo build --target x86_64-pc-windows-gnu` compiling.

## Testing

```console
$ cargo test
```

## Formatting

```console
$ cargo fmt --check                            # check
$ cargo fmt                                    # format
$ cargo clippy --all-targets -- -D warnings    # lint
```

Or use `make fmt` / `make lint`.

## Documentation

Docs live in `docs/` and are served with `mkdocs serve`.

- `docs/user-guide/` — config options and runtime behavior
- `docs/getting-started/` — install, quick-start, introduction
- `docs/developer-guide/` — build/test/lint workflow, commit conventions

Update docs when a change adds, removes, or renames a config option, or changes user-observable runtime behavior. Pure refactors and internal changes don't require doc updates.
