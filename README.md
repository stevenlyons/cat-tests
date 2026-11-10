# CAT claim test vectors (VCC-1443)

Signed Common Access Token (CAT) test tokens, positive and negative, for the claims tracked
in [VCC-1443](https://fastly.atlassian.net/browse/VCC-1443), with a pipeline that proves each
token is what its test case says it is **before** it is run against the Varnish CAT code.

| Claim (key) | Ticket | Cases | Rules from |
|---|---|---|---|
| catreplay (308) | VCC-1486 | 13 | CTA-5007-B §4.6.6 |
| catpor (309) | VCC-1475 | 27 | CTA-5007-B §4.6.7 (reuse blocking out of scope) |
| catv (310) | VCC-1476 | 9 | CTA-5007-B §4.6.8 |
| catm (313) | VCC-1477 | 16 | CTA-5007-B §4.6.11 |
| catalpn (314) | VCC-1478 | 15 | CTA-5007-B §4.6.12 |
| cattpk (319) | VCC-1402 | 12 | CTA-5007-B §4.6.18 |
| catr (323) | VCC-1479 | 34 | CTA-5007-B §4.9.2 |
| catnetprint (324) | VCC-1396 | 25 | fastly/rust-cat `cattprint` (Fastly decision) |

Out of scope for now: cnf (VCC-1400), catdpop (VCC-1403). See `docs/DECISIONS.md`.

## Quick start

```sh
tools/run_all.sh            # toolchain check, generate, rust-cat cross-check, validate, VTC
tools/run_all.sh --no-rust  # same without the Rust step
```

Requirements: Python 3.9+ (standard library only, no pip installs). The rust-cat
cross-check needs Rust 1.88+ and network access to GitHub/crates.io for the first build.

## Layout

```
cases/*.json            SOURCE OF TRUTH: one file per claim; each case = claims (CBOR diagnostic
                        notation), request context, expected result, spec basis and reason
catcheck/               standard-library CBOR / COSE_Mac0 / rules / reference evaluator
tools/toolchain_check.py  proves catcheck against CTA-5007-B's own published example tokens
tools/generate.py       cases -> out/tokens.json (signed tokens + JSON documentation)
tools/validate.py       checks every token; out/report.json; non-zero exit on any failure
tools/make_vtc.py       out/tokens.json -> out/cat_claims.vtc (only after validate passes)
tools/check_renewed.py  checks a renewed token from the service against §4.9.2 MUST rules
rust-check/             Rust binary that decodes/verifies every token with fastly/rust-cat
vtc/harness_template.vcl  VCL inlined into the VTC; engineers wire in the CAT code here
keys/hs256-test-key.json  TEST-ONLY HMAC key (kid "cat-tests-hs256")
certs/                  TEST-ONLY CA, intermediate and client certificates for cattpk
docs/DECISIONS.md       scope decisions, spec interpretations, rust-cat findings
```

## What a token entry looks like (`out/tokens.json`, 151 tokens)

Each token is documented in JSON. `claims_edn` is CBOR diagnostic notation (the format the
spec uses for its examples); `claims_typed` is the same claim set as typed JSON so that
byte strings vs text, integers vs floats and integer map keys are unambiguous.

```json
{
  "id": "CATALPN-REJ-01",
  "claim": "catalpn", "claim_key": 314, "ticket": "VCC-1478",
  "title": "[h2] over http/1.1",
  "category": "reject",
  "expected": {"access": "reject", "basis": "MUST", "spec_ref": "CTA-5007-B §4.6.12",
               "reason": "ALPN not listed: MUST reject."},
  "request": {"method": "GET", "url": "...", "token_location": "header",
              "token_name": "CTA-Common-Access-Token",
              "tls": {"alpn": "http/1.1", "client_chain": [], "fingerprint": null},
              "cti_seen_before": false},
  "needs": ["tls-alpn"],
  "claims_edn": "{1: \"https://issuer.cat-tests.example\", 4: 4102444800, 7: h'...', 314: [h'6832']}",
  "claims_typed": {"type": "map", "entries": [...]},
  "token_b64url": "2D3RhFSiAQUE...",
  "token_hex": "d83dd18454a2...",
  "token_bytes": 121
}
```

Expected `access` values: `accept`, `reject`, `undefined` (the spec leaves it to the
recipient; no pass/fail is asserted), `probabilistic` (catpor with 0 < p < 1).
`basis` says how strong the requirement is (MUST, CDDL, MAY, rust-cat, interpretation, ...).
catr cases also carry `renewal_decision` (SHOULD renew / SHOULD NOT renew / MAY renew /
MUST NOT renew / undefined).

## How each token is validated (`tools/validate.py`)

1. **decode**: CWT `61(17([...]))`, protected header `{1: 5, 4: "cat-tests-hs256"}`.
2. **mac**: HMAC 256/256 verifies with the test key and fails with a wrong key.
3. **roundtrip**: the decoded claims equal the case's claims exactly (types, values, encoding widths).
4. **encoding**: deterministic-encoding problems exist only in `encoding` cases.
5. **structure**: CDDL-equivalent syntax errors exist only in `malformed` cases, and only on
   the claim under test.
6. **expected**: an independent reference evaluator (`catcheck/evaluate.py`) reaches the
   expected result, the rejection probability and (catr) renewal decision written in the case.
7. **rust-cat**: when `out/rustcat.json` exists, rust-cat must decode the token, verify the
   MAC and read the same claim values. Tokens containing values rust-cat cannot represent
   (floats, tags) are expected to fail rust-cat decoding; that is reported, not hidden.

The toolchain check runs first: it decodes the HMAC example token from CTA-5007-B §A.3,
verifies it with the Annex B.3 key, and re-encodes it from the spec's printed claims to a
**byte-identical** token. It also decodes two of the spec's ES256 examples.

## Running against the Varnish CAT code

`out/cat_claims.vtc` contains one client request per case, with assertions on
`resp.http.cat-result`. The harness in `vtc/harness_template.vcl` deliberately returns
`NOT-WIRED`, so every assertion fails until the CAT verification code (VCC-1484) is wired
in. Regenerate with `tools/make_vtc.py --harness <your harness.vcl>`.

Cases are commented out (with the reason) when:

* the expected result is `undefined` or `probabilistic`, or
* they need TLS context that a plain varnishtest client cannot express: ALPN (catalpn),
  client certificates (cattpk) or a TLS fingerprint (catnetprint). How to supply that
  context is open for the engineers; the request context each case needs is in `request.tls`.

Replay cases (`cti_seen_before`) send the same token twice and assert on the second request.

catr cases: `MUST NOT renew` cases assert that the response has no `Set-Cookie`, `Location`
or `CTA-Common-Access-Token` header. `SHOULD`/`MAY renew` cases are not asserted (the spec
does not require renewal); the expected conveyance is written as a comment, and a renewed
token can be checked with `tools/check_renewed.py CASE_ID TOKEN --verified-at SECONDS`.

## Not verified in this environment

The Rust cross-check (`rust-check/`) was written against rust-cat `main` but could not be
compiled where this suite was built (no access to crates.io). Build it once with
`cargo run` and fix any compile error before relying on its output.
