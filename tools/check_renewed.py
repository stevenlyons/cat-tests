#!/usr/bin/env python3
"""Check a renewed token returned by the service against the MUST-level rules of CTA-5007-B §4.9.2.

Usage:
  tools/check_renewed.py CASE_ID RENEWED_TOKEN_B64URL --verified-at UNIX_SECONDS
                         [--tolerance 5] [--key-b64 KEY --kid KID]

  CASE_ID        the catr case whose token was presented (e.g. CATR-ACC-01)
  --verified-at  when the service verified the original token (e.g. the response Date header)
  --key-b64      the renewal key, if HMAC, to verify the renewed token's MAC (optional:
                 the renewal key is the recipient's, not the suite's test key)

Checks:
  * exp      == verified-at + expiration extension (within --tolerance seconds)      [MUST]
  * cti      new value if the original had one; absent if the original had none      [MUST / MUST NOT]
  * claims   all other claims identical to the original, except exp, iss, iat        [MUST]
  * iss/iat  present                                                                  [SHOULD -> warning]
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from catcheck import cbor, cose  # noqa: E402
from catcheck.cbor import Int  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("renewed")
    ap.add_argument("--verified-at", type=float, required=True)
    ap.add_argument("--tolerance", type=float, default=5)
    ap.add_argument("--key-b64")
    args = ap.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    toks = {t["id"]: t for t in json.load(open(os.path.join(root, "out", "tokens.json")))["tokens"]}
    orig = cose.parse_token(cose.b64url_decode(toks[args.case_id]["token_b64url"])).claims
    new_tok = cose.parse_token(cose.b64url_decode(args.renewed))
    new = new_tok.claims
    problems, warnings = [], []

    if args.key_b64:
        if not cose.verify_mac0(new_tok, base64.b64decode(args.key_b64)):
            problems.append("renewed token MAC does not verify with the given key")

    catr = orig.get(Int(323))
    expadd = catr.get(Int(1)).value
    exp = new.get(Int(4))
    if exp is None:
        problems.append("renewed token has no exp")
    elif abs(exp.value - (args.verified_at + expadd)) > args.tolerance:
        problems.append("exp %s != verified-at %s + %s" % (exp.value, args.verified_at, expadd))

    o_cti, n_cti = orig.get(Int(7)), new.get(Int(7))
    if o_cti is not None and (n_cti is None or n_cti == o_cti):
        problems.append("cti MUST be present with a new value")
    if o_cti is None and n_cti is not None:
        problems.append("cti MUST NOT be present (original had none)")

    skip = {Int(1), Int(4), Int(6), Int(7)}
    o_rest = {k: v for k, v in orig.entries if k not in skip}
    n_rest = {k: v for k, v in new.entries if k not in skip}
    if o_rest != n_rest:
        problems.append("other claims changed: original %s, renewed %s" % (
            cbor.to_edn(cbor.Map(tuple(o_rest.items()))), cbor.to_edn(cbor.Map(tuple(n_rest.items())))))
    for k, name in ((1, "iss"), (6, "iat")):
        if new.get(Int(k)) is None:
            warnings.append("%s SHOULD be present in the renewed token" % name)

    for w in warnings:
        print("WARN  " + w)
    for p in problems:
        print("FAIL  " + p)
    print("OK" if not problems else "%d problem(s)" % len(problems))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
