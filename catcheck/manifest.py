"""Load test-case manifests (cases/*.json) and build the full claim set for each case."""

from __future__ import annotations

import base64
import copy
import glob
import hashlib
import json
import os
import re

from . import cbor
from .cbor import Bytes, Int, Map, Text

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

BASE_ISS = "https://issuer.cat-tests.example"
BASE_EXP = 4102444800  # 2100-01-01T00:00:00Z: far enough ahead that tokens do not expire mid-test

DEFAULT_REQUEST = {
    "method": "GET",
    "url": "https://cdn.cat-tests.example/content/index.m3u8",
    "token_location": "header",            # header | cookie | uri
    "token_name": "CTA-Common-Access-Token",
    "tls": {"alpn": "h2", "client_chain": [], "fingerprint": None},   # None = plain HTTP
    "cti_seen_before": False,
}

VALID_CATEGORIES = {"accept", "reject", "malformed", "encoding", "undefined", "statistical"}
VALID_ACCESS = {"accept", "reject", "undefined", "probabilistic"}
VALID_BASIS = {"MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", "CDDL", "normative-text", "undefined", "rust-cat", "interpretation"}
VALID_RENEWAL = {"SHOULD renew", "SHOULD NOT renew", "MAY renew", "MUST NOT renew", "undefined"}


def load_key():
    with open(os.path.join(ROOT, "keys", "hs256-test-key.json")) as f:
        k = json.load(f)
    return k["kid"], base64.b64decode(k["key_b64"])


def load_spki():
    out = {}
    for path in glob.glob(os.path.join(ROOT, "certs", "*.spki.der")):
        out[os.path.basename(path).split(".")[0]] = open(path, "rb").read()
    return out


def _subst(edn: str, spki: dict) -> str:
    def rep(m):
        kind, name = m.group(1), m.group(2)
        if kind == "spki":
            return spki[name].hex()
        if kind == "sha256":
            return hashlib.sha256(spki[name]).hexdigest()
        if kind == "spki_b64":
            return base64.b64encode(spki[name]).decode()
        raise KeyError(kind)
    return re.sub(r"\$\{(spki|sha256|spki_b64):([a-z]+)\}", rep, edn)


def base_claims(case_id: str, omit=()):
    entries = []
    if "iss" not in omit:
        entries.append((Int(1), Text(BASE_ISS)))
    if "exp" not in omit:
        entries.append((Int(4), Int(BASE_EXP)))
    if "cti" not in omit:
        entries.append((Int(7), Bytes(hashlib.sha256(case_id.encode()).digest()[:8])))
    return entries


def full_claims(case: dict, spki: dict) -> Map:
    extra = cbor.parse_edn(_subst(case["claims_edn"], spki))
    if not isinstance(extra, Map):
        raise ValueError("%s: claims_edn must be a map" % case["id"])
    entries = base_claims(case["id"], case.get("base_omit", ()))
    for k, v in extra.entries:
        for i, (bk, _) in enumerate(entries):
            if bk == k:
                entries[i] = (k, v)
                break
        else:
            entries.append((k, v))
    return Map(tuple(entries))


def request_for(case: dict) -> dict:
    req = copy.deepcopy(DEFAULT_REQUEST)
    req.update(copy.deepcopy(case.get("request", {})))
    return req


def check_case_fields(case: dict, file_claim_key: int) -> list:
    errs = []
    for f in ("id", "title", "category", "claims_edn", "expected"):
        if f not in case:
            errs.append("missing field %s" % f)
    if errs:
        return errs
    e = case["expected"]
    if case["category"] not in VALID_CATEGORIES:
        errs.append("bad category %r" % case["category"])
    if e.get("access") not in VALID_ACCESS:
        errs.append("bad expected.access %r" % e.get("access"))
    if e.get("basis") not in VALID_BASIS:
        errs.append("bad expected.basis %r" % e.get("basis"))
    for f in ("spec_ref", "reason"):
        if not e.get(f):
            errs.append("missing expected.%s" % f)
    if e.get("access") == "probabilistic" and "probability_of_rejection" not in e:
        errs.append("probabilistic case needs expected.probability_of_rejection")
    if file_claim_key == 323 and e.get("renewal_decision") not in VALID_RENEWAL:
        errs.append("catr case needs expected.renewal_decision in %s" % sorted(VALID_RENEWAL))
    return errs


def load_cases():
    """Return list of (file_meta, case) in a stable order."""
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "cases", "*.json"))):
        with open(path) as f:
            meta = json.load(f)
        for case in meta["cases"]:
            out.append(({k: v for k, v in meta.items() if k != "cases"} | {"file": os.path.basename(path)}, case))
    ids = [c["id"] for _, c in out]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise ValueError("duplicate case ids: %s" % sorted(dup))
    return out
