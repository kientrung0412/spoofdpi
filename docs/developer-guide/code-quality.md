# Code Quality

Formatting uses `rustfmt` (config: `rustfmt.toml`) and linting uses `clippy`. CI rejects
formatting differences and clippy warnings.

```console
- Format the code
$ cargo fmt

- Check formatting without changing files
$ cargo fmt --check

- Run lints (also for the Windows target)
$ cargo clippy --all-targets -- -D warnings
$ cargo clippy --target x86_64-pc-windows-gnu -- -D warnings
```

Or use `make fmt`, `make fmt-check` and `make lint`.
