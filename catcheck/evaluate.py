"""Structure rules (CDDL-equivalent) and a reference evaluator for the in-scope claims.

Every rule cites where it comes from. Sources:
  * CTA-5007-B (Common Access Token), sections as cited.
  * catnetprint (key 324): rust-cat ``src/constants.rs`` / ``src/token.rs::verify_cattprint_claim``
    (Fastly decision: rust-cat is the definition for this claim).

Spec terminology used for results (CTA-5007-B §4.3.1.2):
  * A token is *valid* only if "the syntactic requirements of any present claims are met".
  * A token is *acceptable* only if it is valid and every claim is acceptable.
  So a structural (CDDL) violation makes the token unacceptable  -> expected access "reject".

Access results:
  accept        - spec requires the request to be allowed
  reject        - spec requires the request to be refused
  undefined     - spec leaves it to the recipient (MAY / "undefined"); no pass/fail is asserted
  probabilistic - catpor with 0 < p < 1; check statistically
"""

from __future__ import annotations

import hashlib
import math
import time

from .cbor import Array, Bytes, Float, Int, Map, Tag, Text

# Claim keys
ISS, SUB, AUD, EXP, NBF, IAT, CTI = 1, 2, 3, 4, 5, 6, 7
CATREPLAY, CATPOR, CATV, CATNIP, CATU, CATM, CATALPN = 308, 309, 310, 311, 312, 313, 314
CATTPK, CATR, CATNETPRINT = 319, 323, 324

CLAIM_NAMES = {ISS: "iss", SUB: "sub", AUD: "aud", EXP: "exp", NBF: "nbf", IAT: "iat", CTI: "cti",
               CATREPLAY: "catreplay", CATPOR: "catpor", CATV: "catv", CATNIP: "catnip", CATU: "catu",
               CATM: "catm", CATALPN: "catalpn", CATTPK: "cattpk", CATR: "catr", CATNETPRINT: "catnetprint"}

# rust-cat FingerprintType codes (src/constants.rs)
FINGERPRINT_TYPES = {0: "JA3", 1: "JA3S", 2: "JA4", 3: "JA4S", 4: "JA4H", 5: "JA4L", 6: "JA4X",
                     7: "JA4SSH", 8: "JA4T", 9: "JA4TS", 10: "JA4TScan", 11: "JA4D", 12: "JA4D6"}

DEFAULT_HEADER_NAME = "CTA-Common-Access-Token"   # §4.9.2.3


def _is_number(x):
    return isinstance(x, (Int, Float))


def _num(x):
    return x.value


# ---------------------------------------------------------------------------
# Structure (syntax) rules
# ---------------------------------------------------------------------------

def structure_errors(claims) -> list:
    """Return a list of (claim_key, message). Empty list = claim set is syntactically valid
    for every claim this suite understands. Claims outside scope are not checked."""
    errs = []
    if not isinstance(claims, Map):
        return [(None, "claim set is not a map")]
    keys = claims.keys()
    for k in keys:
        if not isinstance(k, (Int, Text)):
            errs.append((None, "claim label is not int/tstr"))
    seen = []
    for k in keys:
        if k in seen:
            errs.append((None, "duplicate claim label %r" % (k,)))
        seen.append(k)

    def val(key):
        return claims.get(Int(key))

    for key, v in claims.entries:
        if not isinstance(key, Int):
            continue
        k = key.value
        # §4.5: claim values defined in CTA-5007-B (except catnip) MUST NOT be tagged;
        # "Recipients MUST reject a claim set containing a claim with a value that is improperly tagged."
        # (catnetprint is not a CTA-5007-B claim, so §4.5 does not cover it; a tagged value
        # fails its own "must be a map" rule instead.)
        if isinstance(v, Tag) and k in CLAIM_NAMES and k not in (CATNIP, CATNETPRINT):
            errs.append((k, "value is tagged (tag %d); §4.5 forbids tags on this claim" % v.tag))
            continue
        # §4.5: "Floating-point NaN values and negative zero floating-point values are not valid
        # values for any claim defined in this document."
        if k in CLAIM_NAMES and k != CATNETPRINT and _has_nan_or_negzero(v):
            errs.append((k, "contains NaN or negative zero (§4.5: not valid values)"))
            continue
        if k == ISS and not isinstance(v, Text):
            errs.append((k, "iss must be tstr (StringOrURI)"))
        elif k == EXP and not _is_number(v):
            errs.append((k, "exp must be a NumericDate (number)"))
        elif k == CTI and not isinstance(v, Bytes):
            errs.append((k, "cti must be bstr"))
        elif k == CATREPLAY:
            # catreplay-value = 0 / 1 / 2 / uint .gt 2   (§4.6.6)
            if not (isinstance(v, Int) and v.value >= 0):
                errs.append((k, "catreplay must be uint"))
        elif k == CATPOR:
            errs += [(k, m) for m in _catpor_errors(v, claims)]
        elif k == CATV:
            # catv-value = 1 (§4.6.8). Non-1 uints are handled by the evaluator ("MUST reject an
            # unsupported version"); non-uint data types are a syntax error.
            if not (isinstance(v, Int) and v.value >= 0):
                errs.append((k, "catv must be uint"))
        elif k == CATM:
            # catm-value = [ + tstr ] (§4.6.11)
            if not isinstance(v, Array):
                errs.append((k, "catm must be an array"))
            elif len(v.items) == 0:
                errs.append((k, "catm must have at least one member ([ + tstr ])"))
            elif not all(isinstance(x, Text) for x in v.items):
                errs.append((k, "catm members must be tstr"))
        elif k == CATALPN:
            # catalpn-value = [ + bstr ] (§4.6.12)
            if not isinstance(v, Array):
                errs.append((k, "catalpn must be an array"))
            elif len(v.items) == 0:
                errs.append((k, "catalpn must have at least one member ([ + bstr ])"))
            elif not all(isinstance(x, Bytes) for x in v.items):
                errs.append((k, "catalpn members must be bstr"))
        elif k == CATTPK:
            # cattpk-value = bstr (§4.6.18)
            if not isinstance(v, Bytes):
                errs.append((k, "cattpk must be bstr"))
        elif k == CATR:
            errs += [(k, m) for m in _catr_errors(v)]
        elif k == CATNETPRINT:
            # rust-cat: map with 0 => int (FingerprintType), 1 => tstr (fingerprint value)
            if not isinstance(v, Map):
                errs.append((k, "catnetprint must be a map"))
            else:
                t, fv = v.get(Int(0)), v.get(Int(1))
                if not isinstance(t, Int):
                    errs.append((k, "catnetprint key 0 (fingerprint type) must be present and an integer"))
                if not isinstance(fv, Text):
                    errs.append((k, "catnetprint key 1 (fingerprint value) must be present and tstr"))
    return errs


def _has_nan_or_negzero(item):
    if isinstance(item, Float):
        return math.isnan(item.value) or (item.value == 0 and math.copysign(1, item.value) < 0)
    if isinstance(item, Array):
        return any(_has_nan_or_negzero(x) for x in item.items)
    if isinstance(item, Map):
        return any(_has_nan_or_negzero(k) or _has_nan_or_negzero(x) for k, x in item.entries)
    if isinstance(item, Tag):
        return _has_nan_or_negzero(item.item)
    return False


def _catpor_errors(v, claims):
    # catpor-value = [catpor-probability, catpor-id, ?catpor-exp]  (§4.6.7)
    # catpor-probability = number ; MUST be in [0, 1] ("not well-formed and the token MUST be rejected")
    # catpor-id = label / bstr ; a label references another claim that must exist and be bstr
    # catpor-exp = numericdate
    if not isinstance(v, Array):
        return ["catpor must be an array"]
    if not 2 <= len(v.items) <= 3:
        return ["catpor array must have 2 or 3 members, has %d" % len(v.items)]
    errs = []
    p, ident = v.items[0], v.items[1]
    if not _is_number(p):
        errs.append("catpor probability must be a number")
    elif not (0 <= _num(p) <= 1) or (isinstance(p, Float) and math.isnan(p.value)):
        errs.append("catpor probability %r is outside [0, 1]" % _num(p))
    if isinstance(ident, Bytes):
        pass
    elif isinstance(ident, (Int, Text)):
        ref = claims.get(ident)
        if ref is None:
            errs.append("catpor references claim %r which is not present" % ident.value)
        elif not isinstance(ref, Bytes):
            errs.append("catpor references claim %r whose value is not bstr" % ident.value)
    else:
        errs.append("catpor id must be a label (int/tstr) or bstr")
    if len(v.items) == 3 and not _is_number(v.items[2]):
        errs.append("catpor expiration must be a NumericDate (number)")
    return errs


def _catr_errors(v):
    # catr-value (§4.9.2): map; 0 => int (required), 1 => number (required), 2 => number,
    # 3 => tstr, 4 => tstr, 5 => [*tstr], 6 => [*tstr], 7 => int, * int => any
    if not isinstance(v, Map):
        return ["catr must be a map"]
    errs = []
    for k, _ in v.entries:
        if not isinstance(k, Int):
            errs.append("catr keys must be int")
    t, e = v.get(Int(0)), v.get(Int(1))
    if t is None:
        errs.append("catr renewal type (0) is required")
    elif not isinstance(t, Int):
        errs.append("catr renewal type (0) must be int")
    if e is None:
        errs.append("catr expiration extension (1) is required")
    elif not _is_number(e):
        errs.append("catr expiration extension (1) must be a number")
    checks = {2: (_is_number, "number"), 3: (lambda x: isinstance(x, Text), "tstr"),
              4: (lambda x: isinstance(x, Text), "tstr"),
              5: (lambda x: isinstance(x, Array) and all(isinstance(i, Text) for i in x.items), "[* tstr]"),
              6: (lambda x: isinstance(x, Array) and all(isinstance(i, Text) for i in x.items), "[* tstr]"),
              7: (lambda x: isinstance(x, Int), "int")}
    for label, (ok, desc) in checks.items():
        x = v.get(Int(label))
        if x is not None and not ok(x):
            errs.append("catr parameter %d must be %s" % (label, desc))
    return errs


# ---------------------------------------------------------------------------
# Reference evaluator
# ---------------------------------------------------------------------------

_ORDER = {"accept": 0, "probabilistic": 1, "undefined": 2, "reject": 3}


def _combine(results):
    worst = "accept"
    for r in results:
        if _ORDER[r] > _ORDER[worst]:
            worst = r
    return worst


def evaluate(claims, request: dict, encoding_issues: list, spki: dict, now: float | None = None) -> dict:
    """Return {"access": ..., "probability": p|None, "reasons": [...], "renewal": {...}|None}."""
    now = time.time() if now is None else now
    reasons, results = [], []
    prob = None

    serrs = structure_errors(claims)
    if serrs:
        return {"access": "reject", "probability": None,
                "reasons": ["syntax: %s" % m for _, m in serrs], "renewal": _no_renew("token is not valid")}

    if encoding_issues:
        results.append("undefined")
        reasons.append("not deterministically encoded; §4.5: MAY be treated as ill-formed")

    def get(k):
        return claims.get(Int(k))

    exp = get(EXP)
    if exp is not None and now >= _num(exp):
        results.append("reject")
        reasons.append("exp: token expired")

    v = get(CATREPLAY)
    if v is not None:
        if v.value == 0:
            reasons.append("catreplay 0: replay permitted (MUST NOT reject for reuse)")
        elif v.value in (1, 2):
            if request.get("cti_seen_before"):
                results.append("undefined")
                reasons.append("catreplay %d with reused token: recipient MAY reject (tracking outside VCL)" % v.value)
            else:
                reasons.append("catreplay %d: first use" % v.value)
        else:
            results.append("undefined")
            reasons.append("catreplay %d: recipient behaviour undefined (§4.6.6)" % v.value)

    v = get(CATPOR)
    if v is not None:
        p = _num(v.items[0])
        if p == 0:
            reasons.append("catpor probability 0: never rejected")
        elif p == 1:
            results.append("reject")
            reasons.append("catpor probability 1: always rejected")
        else:
            results.append("probabilistic")
            prob = p
            reasons.append("catpor probability %r" % p)

    v = get(CATV)
    if v is not None and v.value != 1:
        results.append("reject")
        reasons.append("catv %d: unsupported version (MUST reject)" % v.value)

    v = get(CATM)
    if v is not None:
        methods = [x.value for x in v.items]
        hit = request["method"] in methods
        if not hit:
            results.append("reject")
            reasons.append("catm: method %r not listed (case-sensitive)" % request["method"])
        elif len(methods) > 50:
            results.append("undefined")
            reasons.append("catm: %d members > 50; recipient MAY treat as invalid" % len(methods))
        else:
            reasons.append("catm: method listed")

    v = get(CATALPN)
    if v is not None:
        tls = request.get("tls")
        alpns = [x.value for x in v.items]
        if tls is None:
            results.append("reject")
            reasons.append("catalpn: request not over TLS (MUST reject)")
        elif tls.get("alpn") is None:
            results.append("reject")
            reasons.append("catalpn: ALPN not determined (MUST reject)")
        elif tls["alpn"].encode() not in alpns:
            results.append("reject")
            reasons.append("catalpn: ALPN %r not listed (byte-wise)" % tls["alpn"])
        elif len(alpns) > 50:
            results.append("undefined")
            reasons.append("catalpn: %d members > 50; recipient MAY treat as invalid" % len(alpns))
        else:
            reasons.append("catalpn: ALPN listed")

    v = get(CATTPK)
    if v is not None:
        tls = request.get("tls")
        if tls is None:
            results.append("reject")
            reasons.append("cattpk: not over TLS; no certificate chain presented (§4.6.18 first sentence)")
        else:
            chain = [spki[n] for n in tls.get("client_chain", [])]
            if v.value in chain and tls.get("chain_validates", True) is False:
                results.append("undefined")
                reasons.append("cattpk: matching certificate is in the presented chain, but the chain does not "
                               "validate; §4.6.18 does not say whether validation is required")
            elif v.value in chain:
                reasons.append("cattpk: matching certificate in client chain")
            else:
                results.append("reject")
                reasons.append("cattpk: no certificate in client chain matches (MUST reject)")

    v = get(CATNETPRINT)
    if v is not None:
        tls = request.get("tls") or {}
        fp = tls.get("fingerprint")
        t, fv = v.get(Int(0)).value, v.get(Int(1)).value
        if fp is None:
            results.append("reject")
            reasons.append("catnetprint: no fingerprint available for the connection (rust-cat errors)")
        elif fp["type"] != t:
            results.append("reject")
            reasons.append("catnetprint: fingerprint type %r != connection type %r" % (t, fp["type"]))
        elif fp["value"].lower() != fv.lower():
            results.append("reject")
            reasons.append("catnetprint: fingerprint value differs (case-insensitive compare)")
        else:
            reasons.append("catnetprint: type and value match")

    v = get(CATR)
    if v is not None and len(v.entries) >= 50:
        results.append("undefined")
        reasons.append("catr: %d members (MUST process only fewer than 50; MAY treat larger as invalid)" % len(v.entries))

    access = _combine(results)
    renewal = None
    if v is not None:
        renewal = _renewal(claims, v, request, access, now)
    return {"access": access, "probability": prob, "reasons": reasons, "renewal": renewal}


def _no_renew(why, level="MUST NOT"):
    return {"decision": "%s renew" % level, "reason": why}


_RFC6265_BAD = set(chr(c) for c in range(0x00, 0x20)) | {chr(0x7F), ";"}


def _renewal(claims, catr: Map, request, access, now):
    """Renewal expectation per §4.9.2."""
    if access == "reject":
        return _no_renew("token is unacceptable (§4.9.2: MUST NOT renew an unacceptable token)")
    if access == "undefined":
        return {"decision": "undefined", "reason": "token acceptance is undefined"}
    rtype = catr.get(Int(0)).value
    expadd = _num(catr.get(Int(1)))
    labels = {k.value for k, _ in catr.entries}
    loc = request.get("token_location", "header")
    exp = claims.get(Int(EXP))

    if rtype not in (0, 1, 2, 3):
        return _no_renew("unknown renewal type %d: MUST ignore (§4.9.2.5)" % rtype)

    if rtype == 0:
        if labels & {5, 6}:
            return _no_renew("automatic renewal MUST NOT have additional parameters (§4.9.2.1); "
                             "parameters not appropriate for the type", level="MUST NOT")
        effective = {"cookie": 1, "header": 2, "uri": 3}[loc]
        inappropriate = set()  # automatic MAY carry parameters inappropriate to the effective type
    else:
        effective = rtype
        appropriate = {0, 1, 2} | {1: {3, 5}, 2: {4, 6}, 3: {7}}[rtype]
        inappropriate = {l for l in labels if l >= 0} - appropriate
        if inappropriate:
            return _no_renew("parameters %s not appropriate for renewal type %d (§4.9.2)" % (sorted(inappropriate), rtype))

    out = {"renewal_type": rtype, "effective_type": effective}
    if effective == 1:
        name = catr.get(Int(3))
        out["conveyance"] = "cookie"
        out["cookie_name"] = name.value if name is not None else request.get("token_name")
        params = catr.get(Int(5))
        if params is not None:
            plist = [p.value for p in params.items]
            if any(ch in _RFC6265_BAD for p in plist for ch in p):
                return _no_renew("additional cookie parameters contain characters illegal per RFC 6265 §5.2")
            out["cookie_params"] = plist
    elif effective == 2:
        name = catr.get(Int(4))
        if name is not None:
            out["header_name"] = name.value
        elif rtype == 0 and request.get("token_name", "").lower() != "authorization":
            out["header_name"] = request.get("token_name")
        else:
            out["header_name"] = DEFAULT_HEADER_NAME
        out["conveyance"] = "header"
    else:
        if loc != "uri":
            return _no_renew("redirect renewal: token not in URI (§4.9.2.4 MUST NOT be processed)")
        code = catr.get(Int(7))
        status = code.value if code is not None else 307
        if not 300 <= status <= 399:
            return {"decision": "undefined", "reason": "status code %d outside 300-399 (spec: MUST be 300-399; "
                    "recipient handling not specified)" % status}
        out["conveyance"] = "redirect"
        out["status"] = status

    dl = catr.get(Int(2))
    if dl is not None:
        if exp is None:
            return _no_renew("renewal deadline present but no exp in base claims (§4.9.2)")
        start = _num(exp) - _num(dl)
        if now >= start:
            out["decision"] = "SHOULD renew"
            out["reason"] = "inside the renewal window [exp - deadline, exp)"
        else:
            out["decision"] = "SHOULD NOT renew"
            out["reason"] = "before the renewal window (exp - deadline is in the future)"
    else:
        out["decision"] = "MAY renew"
        out["reason"] = "no deadline: recipient MAY renew at any point it chooses (§4.9.2)"

    out["renewed_token_requirements"] = {
        "exp": "MUST equal verification time + %r seconds" % expadd,
        "cti": ("MUST be present with a new value" if claims.get(Int(CTI)) is not None
                else "MUST NOT be present"),
        "other_claims": "MUST be unchanged (except exp, iss, iat)",
        "iss_iat": "SHOULD be present and identify the renewing issuer / time",
    }
    return out


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()
