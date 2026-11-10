#!/usr/bin/env bash
# Full pipeline. Python 3.9+ (standard library only). Rust >= 1.88 for the rust-cat cross-check.
#   tools/run_all.sh            # everything, including rust-cat
#   tools/run_all.sh --no-rust  # Python only (rust-cat cross-check reported as NOT RUN)
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -I tools/toolchain_check.py
python3 -I tools/generate.py
if [[ "${1:-}" != "--no-rust" ]]; then
  (cd rust-check && cargo run --release --quiet -- ../out/tokens.json ../keys/hs256-test-key.json ../out/rustcat.json)
else
  rm -f out/rustcat.json
fi
python3 -I tools/validate.py
python3 -I tools/make_vtc.py
