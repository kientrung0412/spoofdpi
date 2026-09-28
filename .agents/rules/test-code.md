# Test Code Conventions

Tests live in a `#[cfg(test)] mod tests` at the bottom of the file they cover.

## Naming

- Name tests after the behaviour, in snake_case: `extract_sni`, `skip_not_inherited`,
  `fastest_reports_failure`.

## Table-style tests

Prefer a list of cases over many near-identical tests:

```rust
let cases = [
    ("example.com", Some("exact")),
    ("naver.com", None),
];
for (domain, want) in cases {
    assert_eq!(trie.search(domain), want, "{domain}");
}
```

Include the input in the assertion message so a failing case is easy to find.

## Async and sockets

- Use `#[tokio::test]` for async code.
- Bind test servers to `127.0.0.1:0` so tests can run in parallel.
- Tests must not depend on internet access.
