# rust-check

Decodes and MAC-verifies every token in `../out/tokens.json` with
[fastly/rust-cat](https://github.com/fastly/rust-cat) and writes `../out/rustcat.json`.
`tools/validate.py` then compares what rust-cat read with the case manifest.

```sh
cargo run --release -- ../out/tokens.json ../keys/hs256-test-key.json ../out/rustcat.json
```

Requires Rust 1.88+ (rust-cat's `rust-version`). The dependency tracks rust-cat `main`;
`Cargo.lock` records the exact commit used.

**Status:** written against rust-cat `main` source but not compiled in the environment
where the suite was created (no crates.io access there). Build it once and fix any compile
error before trusting the output.

Expected, reported gaps (not suite failures): rust-cat cannot decode tokens whose claims
contain floats or tags (e.g. most catpor cases, the tagged-value malformed cases).
`rustcat_verify_claims` verdicts for catm / catreplay / catnetprint are informational; known
divergence: CATM-REJ-02 (rust-cat compares methods case-insensitively).
