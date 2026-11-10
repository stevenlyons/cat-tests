#!/usr/bin/env python3
"""Toolchain check: prove the CBOR/COSE code against CTA-5007-B's own published examples.

Must pass before any generated token is trusted. Exits non-zero on any failure.

Vectors (copied from CTA-5007-B; key material from Annex B, which the spec publishes for
validating its examples - these keys must never be used in production):

  V1  §A.3 HMAC256 token   - decode, verify MAC with Annex B.3 key, AND re-encode from the
                              spec's printed claims and require a byte-identical token.
  V2  §A.3 ES256 token     - decode only; payload must equal the same printed claims.
  V3  §4.9.1.2 ES256 token - decode only; payload must equal the printed claims.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from catcheck import cbor, cose  # noqa: E402

ANNEX_B3_KEY = base64.b64decode("i2p+my+r4Cne2k/1E/Isz6yP/RajEXBAtr+kMlbuZOc=")

A3_CLAIMS = '{/exp/ 4: 1700000000, /catu/ 312: { /path/ 3: { /prefix/ 1: "/b04c80bf74ff02b4/" } } }'
A3_HMAC = ("0YRDoQEFoFghogQaZVPxABkBOKEDoQFyL2IwNGM4MGJmNzRmZjAy"
           "YjQvWCDrzYuMLoWS2FuuX2tHdGlm3EZczlfhU3_lNeALlWhE6Q")
A3_ES256 = ("0oRDoQEmoFghogQaZVPxABkBOKEDoQFyL2IwNGM4MGJmNzRmZjAy"
            "YjQvWEDVGGAUXf_umBNaCwvXTr6vu9zqIuK-N3Cn8AqMq7gJD9PE9V2NyR7Nswch-Y7tY6dDf6"
            "gCKGuUEoJXt1PfNudF")
S4912_CLAIMS = ('{ / iss / 1: "cdn.example.com", / iat / 6: 1700000010, '
                '/ catu / 312: { 1: [0, "auth.example.net"], 2: [0, "/"] }, '
                '/ catifdata / 320: ["https://content.example.net/some/content"] }')
S4912_ES256 = ("0oRLogEmBEZhYmMxMjOgWGOkAW9jZG4uZXhhbXBsZS5jb2"
               "0GGmVT8QoZATiiAYIAcGF1dGguZXhhbXBsZS5uZXQCggBhLxkBQIF4KGh0dHBzOi8vY29udGVu"
               "dC5leGFtcGxlLm5ldC9zb21lL2NvbnRlbnRYQKdEuQvf417HIXevB921vjz-TKIfbh0vjuWyZY"
               "yhM9LPR2s2S4xWbEXl_1crbWqfv5dTu2-mRI9ds1B8_hGHyGw")


def run():
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    # V1
    tok = cose.b64url_decode(A3_HMAC)
    p = cose.parse_token(tok)
    want = cbor.parse_edn(A3_CLAIMS)
    check("V1 decode: outer tags == [17]", p.outer_tags == [17], str(p.outer_tags))
    check("V1 decode: protected == {1: 5}", cbor.to_edn(p.protected) == "{1: 5}", cbor.to_edn(p.protected))
    check("V1 decode: claims == spec printed claims", p.claims == want, cbor.to_edn(p.claims))
    check("V1 decode: deterministic encoding", not p.payload_report.issues, p.payload_report.issues)
    check("V1 MAC verifies with Annex B.3 key", cose.verify_mac0(p, ANNEX_B3_KEY))
    check("V1 MAC fails with a wrong key", not cose.verify_mac0(p, b"\x00" * 32))
    rebuilt = cose.build_mac0(want, ANNEX_B3_KEY, None, outer_tags=(17,))
    check("V1 re-encode is byte-identical to spec token", rebuilt == tok, cose.b64url_encode(rebuilt))

    # V2
    p2 = cose.parse_token(cose.b64url_decode(A3_ES256))
    check("V2 decode: outer tags == [18]", p2.outer_tags == [18], str(p2.outer_tags))
    check("V2 decode: protected == {1: -7}", cbor.to_edn(p2.protected) == "{1: -7}", cbor.to_edn(p2.protected))
    check("V2 decode: claims == spec printed claims", p2.claims == want, cbor.to_edn(p2.claims))
    check("V2 decode: 64-byte signature", len(p2.tag_bytes) == 64, str(len(p2.tag_bytes)))

    # V3
    p3 = cose.parse_token(cose.b64url_decode(S4912_ES256))
    check("V3 decode: kid == 'abc123'", p3.kid == b"abc123", repr(p3.kid))
    check("V3 decode: claims == spec printed claims", p3.claims == cbor.parse_edn(S4912_CLAIMS), cbor.to_edn(p3.claims))

    # Encoder self-checks (RFC 8949 Appendix A values where available; others are IEEE 754 per struct)
    rfc = [("0", "00"), ("23", "17"), ("24", "1818"), ("1000", "1903e8"), ("-1", "20"),
           ("0.5", "f93800"), ("1.5", "f93e00"), ("-0.1", "fbbfb999999999999a"),
           ("0.00005", "fb3f0a36e2eb1c432d"), ("1.0", "f93c00"),
           ('"a"', "6161"), ("h'01020304'", "4401020304"), ("[1, 2, 3]", "83010203"),
           ("1(1363896240)", "c11a514b67b0"), ("1_0", "1801"), ("0.5_3", "fb3fe0000000000000")]
    for edn, hexs in rfc:
        got = cbor.encode(cbor.parse_edn(edn)).hex()
        check("encode %s == %s" % (edn, hexs), got == hexs, got)
        back = cbor.decode(bytes.fromhex(hexs))
        check("decode %s round-trips" % hexs, back == cbor.parse_edn(edn), cbor.to_edn(back))
    return results


def main():
    results = run()
    failed = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print("%s  %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "  -> %s" % (detail,)))
    print("\n%d checks, %d failed" % (len(results), len(failed)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
