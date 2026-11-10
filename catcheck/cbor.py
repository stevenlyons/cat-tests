"""Strict CBOR (RFC 8949) data model, encoder, decoder and EDN (diagnostic notation) parser.

Standard library only. Written for CAT test generation and validation, so it is
deliberately explicit about encoding details:

* Integers and lengths are encoded in shortest form unless a ``width`` is forced
  (EDN encoding indicators ``_0``.. ``_3`` -> 1, 2, 4, 8 argument bytes).
* Floats use the preferred (shortest exact) width unless a ``width`` is forced
  (EDN ``_1``/``_2``/``_3`` -> half, single, double).
* The decoder records any non-shortest / non-preferred encoding in ``width`` so a
  decoded item compares equal to the manifest item that produced it, and reports
  deterministic-encoding issues (RFC 8949 §4.2, CTA-5007-B §4.5).
"""

from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass, field
from typing import Any, List, Tuple

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_WIDTH_TO_AI = {1: 24, 2: 25, 4: 26, 8: 27}
_AI_TO_WIDTH = {v: k for k, v in _WIDTH_TO_AI.items()}
_FLOAT_WIDTH_TO_AI = {2: 25, 4: 26, 8: 27}


@dataclass(frozen=True)
class Int:
    value: int
    width: int | None = None  # forced argument width in bytes (1,2,4,8); None = shortest


@dataclass(frozen=True, eq=False)
class Float:
    value: float
    width: int | None = None  # 2,4,8 bytes; None = preferred (shortest exact)

    # Compare like CBOR data items: NaN equals NaN, and -0.0 differs from 0.0.
    def __eq__(self, other):
        if not isinstance(other, Float) or self.width != other.width:
            return False
        a, b = self.value, other.value
        if math.isnan(a) or math.isnan(b):
            return math.isnan(a) and math.isnan(b)
        return a == b and math.copysign(1, a) == math.copysign(1, b)

    def __hash__(self):
        return hash(("float", "nan" if math.isnan(self.value) else self.value, self.width))


@dataclass(frozen=True)
class Bytes:
    value: bytes


@dataclass(frozen=True)
class Text:
    value: str


@dataclass(frozen=True)
class Array:
    items: Tuple[Any, ...]


@dataclass(frozen=True)
class Map:
    entries: Tuple[Tuple[Any, Any], ...]  # ordered (key, value) pairs

    def get(self, key):
        for k, v in self.entries:
            if k == key:
                return v
        return None

    def keys(self):
        return [k for k, _ in self.entries]


@dataclass(frozen=True)
class Tag:
    tag: int
    item: Any


@dataclass(frozen=True)
class Bool:
    value: bool


@dataclass(frozen=True)
class Null:
    pass


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

def _shortest_width(n: int) -> int:
    if n < 24:
        return 0
    if n < 0x100:
        return 1
    if n < 0x10000:
        return 2
    if n < 0x100000000:
        return 4
    if n < 0x10000000000000000:
        return 8
    raise ValueError("integer argument too large for CBOR: %d" % n)


def _head(major: int, arg: int, width: int | None = None) -> bytes:
    if arg < 0:
        raise ValueError("negative argument")
    w = _shortest_width(arg) if width is None else width
    if width is not None and _shortest_width(arg) > width:
        raise ValueError("argument %d does not fit forced width %d" % (arg, width))
    if w == 0:
        return bytes([(major << 5) | arg])
    return bytes([(major << 5) | _WIDTH_TO_AI[w]]) + arg.to_bytes(w, "big")


def _float_bytes(value: float, width: int) -> bytes:
    fmt = {2: ">e", 4: ">f", 8: ">d"}[width]
    return struct.pack(fmt, value)


def _float_roundtrips(value: float, width: int) -> bool:
    try:
        b = _float_bytes(value, width)
    except (OverflowError, struct.error):
        return False
    back = struct.unpack({2: ">e", 4: ">f", 8: ">d"}[width], b)[0]
    if math.isnan(value):
        return math.isnan(back)
    return back == value and math.copysign(1, back) == math.copysign(1, value)


def preferred_float_width(value: float) -> int:
    for w in (2, 4, 8):
        if _float_roundtrips(value, w):
            return w
    raise ValueError("float not representable")


def encode(item) -> bytes:
    if isinstance(item, Int):
        if item.value >= 0:
            return _head(0, item.value, item.width)
        return _head(1, -1 - item.value, item.width)
    if isinstance(item, Float):
        w = preferred_float_width(item.value) if item.width is None else item.width
        if not _float_roundtrips(item.value, w):
            raise ValueError("float %r not exactly representable in %d bytes" % (item.value, w))
        return bytes([0xE0 | _FLOAT_WIDTH_TO_AI[w]]) + _float_bytes(item.value, w)
    if isinstance(item, Bytes):
        return _head(2, len(item.value)) + item.value
    if isinstance(item, Text):
        b = item.value.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(item, Array):
        return _head(4, len(item.items)) + b"".join(encode(x) for x in item.items)
    if isinstance(item, Map):
        return _head(5, len(item.entries)) + b"".join(encode(k) + encode(v) for k, v in item.entries)
    if isinstance(item, Tag):
        return _head(6, item.tag) + encode(item.item)
    if isinstance(item, Bool):
        return b"\xf5" if item.value else b"\xf4"
    if isinstance(item, Null):
        return b"\xf6"
    raise TypeError("cannot encode %r" % (item,))


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class DecodeError(ValueError):
    pass


@dataclass
class DecodeReport:
    issues: List[str] = field(default_factory=list)

    def add(self, path: str, msg: str):
        self.issues.append("%s: %s" % (path or "$", msg))


def decode(data: bytes, report: DecodeReport | None = None):
    """Decode exactly one CBOR item; raise DecodeError on trailing bytes or malformation."""
    if report is None:
        report = DecodeReport()
    item, end = _decode(data, 0, report, "")
    if end != len(data):
        raise DecodeError("%d trailing bytes after CBOR item" % (len(data) - end))
    return item


def _need(data, i, n):
    if i + n > len(data):
        raise DecodeError("truncated CBOR data")


def _read_arg(data, i, ai, report, path):
    if ai < 24:
        return ai, i, None
    if ai in _AI_TO_WIDTH:
        w = _AI_TO_WIDTH[ai]
        _need(data, i, w)
        v = int.from_bytes(data[i:i + w], "big")
        width = w if _shortest_width(v) != w else None
        if width is not None:
            report.add(path, "argument %d not in shortest form (%d-byte argument)" % (v, w))
        return v, i + w, width
    if ai == 31:
        raise DecodeError("indefinite-length items are not allowed (deterministic encoding)")
    raise DecodeError("reserved additional information value %d" % ai)


def _decode(data, i, report, path):
    _need(data, i, 1)
    ib = data[i]
    major, ai = ib >> 5, ib & 0x1F
    i += 1
    if major == 7:
        if ai == 20:
            return Bool(False), i
        if ai == 21:
            return Bool(True), i
        if ai == 22:
            return Null(), i
        if ai in (25, 26, 27):
            w = {25: 2, 26: 4, 27: 8}[ai]
            _need(data, i, w)
            val = struct.unpack({2: ">e", 4: ">f", 8: ">d"}[w], data[i:i + w])[0]
            pref = preferred_float_width(val)
            width = None if pref == w else w
            if width is not None:
                report.add(path, "float %r not in preferred (shortest) width" % val)
            if math.isfinite(val) and val == int(val) and abs(val) < 2 ** 64:
                report.add(path, "integral value %r encoded as float (must be major type 0/1)" % val)
            if math.isnan(val):
                report.add(path, "NaN is not a valid claim value")
            if val == 0 and math.copysign(1, val) < 0:
                report.add(path, "negative zero is not a valid claim value")
            return Float(val, width), i + w
        raise DecodeError("unsupported simple/major-7 value %d" % ai)
    arg, i, width = _read_arg(data, i, ai, report, path)
    if major == 0:
        return Int(arg, width), i
    if major == 1:
        return Int(-1 - arg, width), i
    if width is not None and major in (2, 3, 4, 5):
        pass  # already reported
    if major == 2:
        _need(data, i, arg)
        return Bytes(bytes(data[i:i + arg])), i + arg
    if major == 3:
        _need(data, i, arg)
        try:
            s = bytes(data[i:i + arg]).decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecodeError("invalid UTF-8 in text string: %s" % e)
        return Text(s), i + arg
    if major == 4:
        items = []
        for n in range(arg):
            x, i = _decode(data, i, report, "%s[%d]" % (path, n))
            items.append(x)
        return Array(tuple(items)), i
    if major == 5:
        entries = []
        seen = []
        for _ in range(arg):
            k, i = _decode(data, i, report, path + ".<key>")
            v, i = _decode(data, i, report, "%s{%s}" % (path, to_edn(k)))
            if k in seen:
                report.add(path, "duplicate map key %s" % to_edn(k))
            seen.append(k)
            entries.append((k, v))
        return Map(tuple(entries)), i
    if major == 6:
        x, i = _decode(data, i, report, "%s<tag %d>" % (path, arg))
        return Tag(arg, x), i
    raise DecodeError("unreachable")


# ---------------------------------------------------------------------------
# Diagnostic notation (EDN) output
# ---------------------------------------------------------------------------

_WIDTH_TO_IND = {1: "_0", 2: "_1", 4: "_2", 8: "_3"}
_FWIDTH_TO_IND = {2: "_1", 4: "_2", 8: "_3"}


def _fmt_float(v: float) -> str:
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "Infinity" if v > 0 else "-Infinity"
    if v == 0 and math.copysign(1, v) < 0:
        return "-0.0"
    if v == int(v) and abs(v) < 1e16:
        return "%.1f" % v
    return repr(v)


def to_edn(item) -> str:
    if isinstance(item, Int):
        return str(item.value) + (_WIDTH_TO_IND[item.width] if item.width else "")
    if isinstance(item, Float):
        return _fmt_float(item.value) + (_FWIDTH_TO_IND[item.width] if item.width else "")
    if isinstance(item, Bytes):
        return "h'%s'" % item.value.hex()
    if isinstance(item, Text):
        return json.dumps(item.value, ensure_ascii=False)
    if isinstance(item, Array):
        return "[" + ", ".join(to_edn(x) for x in item.items) + "]"
    if isinstance(item, Map):
        return "{" + ", ".join("%s: %s" % (to_edn(k), to_edn(v)) for k, v in item.entries) + "}"
    if isinstance(item, Tag):
        return "%d(%s)" % (item.tag, to_edn(item.item))
    if isinstance(item, Bool):
        return "true" if item.value else "false"
    if isinstance(item, Null):
        return "null"
    raise TypeError(repr(item))


# ---------------------------------------------------------------------------
# EDN parser (subset sufficient for CTA-5007-B examples and these test cases)
#   ints with optional encoding indicator (_0.._3), floats (optional _1.._3),
#   h'hex', "text", [..], {k: v}, tags N(item), true/false/null,
#   /comments/ (as used in the spec examples) are skipped.
# ---------------------------------------------------------------------------

class EDNError(ValueError):
    pass


class _P:
    def __init__(self, s: str):
        self.s, self.i = s, 0

    def ws(self):
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r\n,":
                # commas are handled explicitly by containers; here only whitespace
                if c == ",":
                    return
                self.i += 1
            elif c == "/":
                j = s.find("/", self.i + 1)
                if j < 0:
                    raise EDNError("unterminated comment")
                self.i = j + 1
            else:
                return

    def peek(self):
        self.ws()
        return self.s[self.i] if self.i < len(self.s) else ""

    def expect(self, c):
        if self.peek() != c:
            raise EDNError("expected %r at %d in %r" % (c, self.i, self.s))
        self.i += 1

    def item(self):
        c = self.peek()
        s = self.s
        if c == "[":
            self.i += 1
            items = []
            if self.peek() == "]":
                self.i += 1
                return Array(())
            while True:
                items.append(self.item())
                if self.peek() == ",":
                    self.i += 1
                    continue
                self.expect("]")
                return Array(tuple(items))
        if c == "{":
            self.i += 1
            entries = []
            if self.peek() == "}":
                self.i += 1
                return Map(())
            while True:
                k = self.item()
                self.expect(":")
                v = self.item()
                entries.append((k, v))
                if self.peek() == ",":
                    self.i += 1
                    continue
                self.expect("}")
                return Map(tuple(entries))
        if c == '"':
            j = self.i + 1
            while True:
                if j >= len(s):
                    raise EDNError("unterminated string")
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    break
                j += 1
            val = json.loads(s[self.i:j + 1])
            self.i = j + 1
            return Text(val)
        if s.startswith("h'", self.i):
            j = s.find("'", self.i + 2)
            if j < 0:
                raise EDNError("unterminated h''")
            hexs = "".join(s[self.i + 2:j].split())
            self.i = j + 1
            return Bytes(bytes.fromhex(hexs))
        for word, val in (("true", Bool(True)), ("false", Bool(False)), ("null", Null()),
                          ("NaN", Float(float("nan"))), ("Infinity", Float(float("inf"))),
                          ("-Infinity", Float(float("-inf")))):
            if s.startswith(word, self.i):
                self.i += len(word)
                return val
        if c == "-" and s.startswith("-Infinity", self.i):
            self.i += len("-Infinity")
            return Float(float("-inf"))
        if c == "-" or c.isdigit():
            j = self.i + 1
            while j < len(s) and (s[j].isdigit() or s[j] in ".eE+-"):
                if s[j] in "+-" and s[j - 1] not in "eE":
                    break
                j += 1
            num = s[self.i:j]
            ind = None
            if j < len(s) and s[j] == "_":
                if j + 1 < len(s) and s[j + 1] in "0123":
                    ind = int(s[j + 1])
                    j += 2
                else:
                    raise EDNError("bad encoding indicator at %d" % j)
            self.i = j
            if self.peek() == "(" and ind is None and num.lstrip("-").isdigit():
                self.i += 1
                inner = self.item()
                self.expect(")")
                return Tag(int(num), inner)
            if any(ch in num for ch in ".eE"):
                width = None if ind is None else {1: 2, 2: 4, 3: 8}.get(ind)
                if ind == 0:
                    raise EDNError("_0 is not a float width")
                return Float(float(num), width)
            width = None if ind is None else {0: 1, 1: 2, 2: 4, 3: 8}[ind]
            return Int(int(num), width)
        raise EDNError("unexpected %r at %d in %r" % (c, self.i, s))


def parse_edn(s: str):
    p = _P(s)
    item = p.item()
    if p.peek() != "":
        raise EDNError("trailing text at %d in %r" % (p.i, s))
    return item


# ---------------------------------------------------------------------------
# Typed JSON representation (for human-readable JSON documentation)
# ---------------------------------------------------------------------------

def to_typed_json(item):
    if isinstance(item, Int):
        d = {"type": "uint" if item.value >= 0 else "nint", "value": item.value}
        if item.width:
            d["encoding_width_bytes"] = item.width
        return d
    if isinstance(item, Float):
        d = {"type": "float", "value": item.value}
        if item.width:
            d["encoding_width_bytes"] = item.width
        return d
    if isinstance(item, Bytes):
        return {"type": "bstr", "hex": item.value.hex()}
    if isinstance(item, Text):
        return {"type": "tstr", "value": item.value}
    if isinstance(item, Array):
        return {"type": "array", "items": [to_typed_json(x) for x in item.items]}
    if isinstance(item, Map):
        return {"type": "map", "entries": [{"key": to_typed_json(k), "value": to_typed_json(v)} for k, v in item.entries]}
    if isinstance(item, Tag):
        return {"type": "tag", "tag": item.tag, "item": to_typed_json(item.item)}
    if isinstance(item, Bool):
        return {"type": "bool", "value": item.value}
    if isinstance(item, Null):
        return {"type": "null"}
    raise TypeError(repr(item))


def strip_widths(item):
    """Return the item with all forced encoding widths removed (data-model value only)."""
    if isinstance(item, Int):
        return Int(item.value)
    if isinstance(item, Float):
        return Float(item.value)
    if isinstance(item, Array):
        return Array(tuple(strip_widths(x) for x in item.items))
    if isinstance(item, Map):
        return Map(tuple((strip_widths(k), strip_widths(v)) for k, v in item.entries))
    if isinstance(item, Tag):
        return Tag(item.tag, strip_widths(item.item))
    return item
