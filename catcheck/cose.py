"""COSE_Mac0 (RFC 9052 §6) with HMAC 256/256 (COSE alg 5), wrapped as a CWT (RFC 8392).

Standard library only.

Token layout produced here (same as rust-cat's HMAC output):

    61( 17( [ protected: bstr .cbor {1: 5, 4: kid}, unprotected: {}, payload: bstr .cbor claims, tag: bstr ] ) )

MAC input (RFC 9052 §6.3):

    MAC_structure = [ "MAC0", protected (bstr), external_aad (bstr, empty), payload (bstr) ]
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

from . import cbor
from .cbor import Array, Bytes, Int, Map, Tag, Text

ALG_HMAC_256_256 = 5
TAG_CWT = 61
TAG_COSE_MAC0 = 17
TAG_COSE_SIGN1 = 18


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mac_structure(protected_bytes: bytes, payload_bytes: bytes, external_aad: bytes = b"") -> bytes:
    return cbor.encode(Array((Text("MAC0"), Bytes(protected_bytes), Bytes(external_aad), Bytes(payload_bytes))))


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def build_mac0(claims: Map, key: bytes, kid: str | None, outer_tags=(TAG_CWT, TAG_COSE_MAC0),
               kid_protected: bool = True, payload_bytes: bytes | None = None) -> bytes:
    """Build a CWT/COSE_Mac0 token. ``payload_bytes`` overrides the encoded claims (for raw/malformed cases)."""
    prot_entries = [(Int(1), Int(ALG_HMAC_256_256))]
    unprot_entries = []
    if kid is not None:
        (prot_entries if kid_protected else unprot_entries).append((Int(4), Text(kid)))
    protected_bytes = cbor.encode(Map(tuple(prot_entries)))
    payload = cbor.encode(claims) if payload_bytes is None else payload_bytes
    tag = hmac256(key, mac_structure(protected_bytes, payload))
    msg = Array((Bytes(protected_bytes), Map(tuple(unprot_entries)), Bytes(payload), Bytes(tag)))
    for t in reversed(outer_tags):
        msg = Tag(t, msg)
    return cbor.encode(msg)


@dataclass
class ParsedToken:
    outer_tags: list
    protected_bytes: bytes
    protected: Map
    unprotected: Map
    payload_bytes: bytes
    claims: object          # decoded claims item (normally a Map)
    tag_bytes: bytes
    payload_report: cbor.DecodeReport
    header_report: cbor.DecodeReport

    @property
    def alg(self):
        v = self.protected.get(Int(1))
        return v.value if isinstance(v, Int) else None

    @property
    def kid(self):
        for m in (self.protected, self.unprotected):
            v = m.get(Int(4))
            if isinstance(v, (Text, Bytes)):
                return v.value
        return None

    @property
    def is_mac0(self):
        return TAG_COSE_MAC0 in self.outer_tags or (TAG_COSE_SIGN1 not in self.outer_tags and len(self.tag_bytes) == 32)


def parse_token(token: bytes) -> ParsedToken:
    hdr_report = cbor.DecodeReport()
    outer = cbor.decode(token, hdr_report)
    tags = []
    while isinstance(outer, Tag):
        tags.append(outer.tag)
        outer = outer.item
    if not (isinstance(outer, Array) and len(outer.items) == 4):
        raise ValueError("COSE message is not a 4-element array")
    p, u, pl, t = outer.items
    if not (isinstance(p, Bytes) and isinstance(u, Map) and isinstance(pl, Bytes) and isinstance(t, Bytes)):
        raise ValueError("COSE message element types are wrong")
    protected = cbor.decode(p.value, hdr_report) if p.value else Map(())
    if not isinstance(protected, Map):
        raise ValueError("protected header is not a map")
    payload_report = cbor.DecodeReport()
    claims = cbor.decode(pl.value, payload_report)
    return ParsedToken(tags, p.value, protected, u, pl.value, claims, t.value, payload_report, hdr_report)


def verify_mac0(parsed: ParsedToken, key: bytes) -> bool:
    if parsed.alg != ALG_HMAC_256_256:
        return False
    expected = hmac256(key, mac_structure(parsed.protected_bytes, parsed.payload_bytes))
    return hmac.compare_digest(expected, parsed.tag_bytes)
