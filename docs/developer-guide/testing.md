# Testing

## Running Tests

Unit tests live next to the code in `#[cfg(test)]` modules and do not need network access:

```console
$ cargo test
```

Run a single test or a module by name filter:

```console
$ cargo test desync::tls
$ cargo test extract_sni -- --nocapture
```

To check that the Windows build still compiles from Linux:

```console
$ cargo build --target x86_64-pc-windows-gnu
```

## Conventions

- Put tests in a `mod tests` at the bottom of the file they cover.
- Prefer table-style cases (a list of inputs and expected outputs) for parsers and matchers.
- Tests that need sockets use loopback addresses and ephemeral ports (`127.0.0.1:0`) so they can
  run in parallel.
- Use `#[tokio::test]` for async code.
