#!/usr/bin/env python3
"""Validate every generated token before it is used for testing.  out/tokens.json -> out/report.json

Checks per token (all must pass; exit code 1 otherwise):
  1. decode     - token decodes as CWT 61(17([...])) with protected {1: 5, 4: kid}
  2. mac        - HMAC 256/256 verifies with the test key (and fails with a wrong key)
  3. roundtrip  - decoded claims are exactly the claims in the case manifest (types, values, widths)
  4. encoding   - deterministic-encoding issues present  <=>  category == "encoding"
                  (malformed cases may also have them; the syntax error decides the result)
  5. structure  - CDDL-equivalent syntax errors present   <=>  category == "malformed",
                  and every error is on the claim under test
  6. expected   - the reference evaluator (catcheck/evaluate.py) gives the manifest's expected
                  access result, rejection probability and (catr) renewal decision
  7. rust-cat   - if out/rustcat.json exists (cargo run in rust-check/): rust-cat decodes the token,
                  verifies the MAC, and reads the same claim values (see README for expected gaps)

Run tools/toolchain_check.py first; it proves the CBOR/COSE code against the spec's examples.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from catcheck import cbor, cose, evaluate, manifest  # noqa: E402
from catcheck.cbor import Bytes, Float, Int, Map, Text  # noqa: E402


def rustcat_view(claims: Map):
    """What rust-cat's typed API should expose for these claims (see src/claims.rs)."""
    reg, custom = {}, {}
    for k, v in claims.entries:
        if not isinstance(k, Int):
            continue
        key = k.value
        if key in (1, 2, 3):
            if isinstance(v, Text):
                reg[{1: "iss", 2: "sub", 3: "aud"}[key]] = v.value
        elif key in (4, 5, 6):
            if isinstance(v, Int):
                reg[{4: "exp", 5: "nbf", 6: "iat"}[key]] = v.value
        elif key == 7:
            if isinstance(v, Bytes):
                reg["cti"] = v.value.hex()
        else:
            custom[str(key)] = cbor.to_typed_json(_sorted_maps(cbor.strip_widths(v)))
    return reg, custom


def _sorted_maps(item):
    """rust-cat stores maps in a BTreeMap<i32, _>, so its view is sorted by integer key."""
    if isinstance(item, cbor.Array):
        return cbor.Array(tuple(_sorted_maps(x) for x in item.items))
    if isinstance(item, Map):
        return Map(tuple(sorted(((k, _sorted_maps(v)) for k, v in item.entries), key=lambda kv: kv[0].value)))
    return item


def _contains_unsupported(item):
    """rust-cat's CborValue has no float/bool/tag variants and only i32 map keys."""
    if isinstance(item, (Float, cbor.Bool, cbor.Tag)):
        return True
    if isinstance(item, cbor.Array):
        return any(_contains_unsupported(x) for x in item.items)
    if isinstance(item, Map):
        return any(not isinstance(k, Int) or _contains_unsupported(v) for k, v in item.entries)
    return False


def main():
    root = manifest.ROOT
    kid, key = manifest.load_key()
    spki = manifest.load_spki()
    cases = {c["id"]: (meta, c) for meta, c in manifest.load_cases()}
    tokens = json.load(open(os.path.join(root, "out", "tokens.json")))["tokens"]
    rc_path = os.path.join(root, "out", "rustcat.json")
    rustcat = None
    if os.path.exists(rc_path):
        rustcat = {r["id"]: r for r in json.load(open(rc_path))["results"]}

    report, failures = [], 0
    rustcat_disagreements = []  # informational: rust-cat verify_claims vs spec-derived expectation
    if set(cases) != {t["id"] for t in tokens}:
        print("FAIL: out/tokens.json is stale; re-run tools/generate.py")
        sys.exit(1)

    for t in tokens:
        meta, case = cases[t["id"]]
        claim_key = meta["claim_key"]
        checks = {}
        try:
            raw = cose.b64url_decode(t["token_b64url"])
            p = cose.parse_token(raw)
            checks["decode"] = (p.outer_tags == [61, 17] and p.alg == 5 and p.kid == kid
                                and not p.header_report.issues, "tags=%s alg=%s kid=%r" % (p.outer_tags, p.alg, p.kid))
        except Exception as e:  # noqa: BLE001
            checks["decode"] = (False, repr(e))
            report.append({"id": t["id"], "ok": False, "checks": {k: {"ok": v[0], "detail": v[1]} for k, v in checks.items()}})
            failures += 1
            continue

        checks["mac"] = (cose.verify_mac0(p, key) and not cose.verify_mac0(p, b"\x00" * 32), "")
        intended = manifest.full_claims(case, spki)
        checks["roundtrip"] = (p.claims == intended and raw.hex() == t["token_hex"],
                               "decoded %s" % cbor.to_edn(p.claims) if p.claims != intended else "")

        enc = p.payload_report.issues
        # A malformed case may also carry an encoding issue (e.g. 1.0 is both "not a uint" and
        # "integral value as float"); the syntax error decides the result, so that is allowed.
        if case["category"] == "malformed":
            enc_ok = True
        else:
            enc_ok = bool(enc) == (case["category"] == "encoding")
        checks["encoding"] = (enc_ok, "issues=%s" % enc)

        serr = evaluate.structure_errors(p.claims)
        want_mal = case["category"] == "malformed"
        off_target = [m for k, m in serr if k != claim_key]
        checks["structure"] = (bool(serr) == want_mal and not off_target,
                               "errors=%s" % [m for _, m in serr])

        res = evaluate.evaluate(p.claims, t["request"], enc, spki)
        exp = case["expected"]
        ok = res["access"] == exp["access"]
        detail = "evaluator=%s expected=%s reasons=%s" % (res["access"], exp["access"], res["reasons"])
        if exp["access"] == "probabilistic":
            ok = ok and res["probability"] == exp["probability_of_rejection"]
        if claim_key == evaluate.CATR:
            got_r = (res["renewal"] or {}).get("decision")
            ok = ok and got_r == exp["renewal_decision"]
            detail += " renewal=%s expected=%s (%s)" % (got_r, exp["renewal_decision"], (res["renewal"] or {}).get("reason"))
        checks["expected"] = (ok, detail)

        if rustcat is not None:
            r = rustcat.get(t["id"])
            if r is None:
                checks["rust-cat"] = (False, "missing from out/rustcat.json")
            else:
                unsupported = _contains_unsupported(p.claims)
                if not r["decode_ok"]:
                    checks["rust-cat"] = (unsupported, "rust-cat decode error: %s%s" % (
                        r.get("error"), " (expected: value types rust-cat cannot represent)" if unsupported else ""))
                else:
                    reg, custom = rustcat_view(p.claims)
                    same = r["mac_ok"] and r["registered"] == reg and r["custom"] == custom
                    checks["rust-cat"] = (same, "" if same else "rust-cat saw registered=%s custom=%s" % (r["registered"], r["custom"]))
                    rv = r.get("rustcat_verify_claims")
                    if rv is not None and res["access"] in ("accept", "reject"):
                        rc_access = "accept" if rv == "ok" else "reject"
                        if rc_access != res["access"]:
                            rustcat_disagreements.append((t["id"], res["access"], rv))

        entry_ok = all(v[0] for v in checks.values())
        failures += 0 if entry_ok else 1
        report.append({"id": t["id"], "claim": t["claim"], "category": case["category"], "ok": entry_ok,
                       "evaluator": res, "checks": {k: {"ok": v[0], "detail": v[1]} for k, v in checks.items()}})

    with open(os.path.join(root, "out", "report.json"), "w") as f:
        json.dump({"tokens": len(tokens), "failures": failures, "rustcat_checked": rustcat is not None,
                   "rustcat_verify_claims_disagreements": [
                       {"id": i, "expected": e, "rust_cat": v} for i, e, v in rustcat_disagreements],
                   "results": report}, f, indent=2, ensure_ascii=False)

    by_claim = {}
    for r in report:
        by_claim.setdefault(r.get("claim", "?"), [0, 0])
        by_claim[r.get("claim", "?")][0 if r["ok"] else 1] += 1
    for c, (ok, bad) in sorted(by_claim.items()):
        print("%-12s %3d passed  %d failed" % (c, ok, bad))
    for r in report:
        if not r["ok"]:
            print("FAIL %s" % r["id"])
            for k, v in r["checks"].items():
                if not v["ok"]:
                    print("     %s: %s" % (k, v["detail"]))
    if rustcat_disagreements:
        print("\nInformational - rust-cat verify_claims disagrees with the spec-derived expectation:")
        for i, e, v in rustcat_disagreements:
            print("  %s: expected %s, rust-cat %s" % (i, e, v))
    print("\n%d tokens, %d failed, rust-cat cross-check: %s" % (
        len(tokens), failures, "included" if rustcat is not None else "NOT RUN (see rust-check/README)"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
