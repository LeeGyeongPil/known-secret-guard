"""Variant generation: every disguise of a known value we look for."""

from __future__ import annotations

import base64
import json
import urllib.parse

#: Variant code -> one-line description (also used by the ``variants`` command).
VARIANT_CODES: dict[str, str] = {
    "RAW": "the value as is",
    "URL": "percent-encoded (%20)",
    "URL_PLUS": "form-encoded (+ for space)",
    "JSON": "JSON string escaping",
    "REPR": "Python repr escaping",
    "HEX": "lower-case hex of UTF-8 bytes",
    "HEX_UPPER": "upper-case hex of UTF-8 bytes",
    "HTML_DEC": "HTML decimal entities (&#65;)",
    "HTML_HEX": "HTML hex entities, lower-case (&#x41;)",
    "HTML_HEX_UPPER": "HTML hex entities, upper-case (&#x4A;)",
    "B64_STD_K0": "standard base64, secret starts on a 3-byte boundary",
    "B64_STD_K1": "standard base64, secret starts 1 byte into a group",
    "B64_STD_K2": "standard base64, secret starts 2 bytes into a group",
    "B64_URL_K0": "URL-safe base64, offset 0",
    "B64_URL_K1": "URL-safe base64, offset 1",
    "B64_URL_K2": "URL-safe base64, offset 2",
    "HALF_HEAD": "first half of the value (split exfiltration)",
    "HALF_TAIL": "second half of the value (split exfiltration)",
    "NORM_RAW": "value after normalisation (zero-width chars, tags, entities, spaces)",
    "NORM_HALF_HEAD": "first half after normalisation",
    "NORM_HALF_TAIL": "second half after normalisation",
}


def b64_stable_segments(raw: bytes, *, urlsafe: bool, min_length: int) -> list[str]:
    """Base64 substrings that appear whatever bytes surround the secret.

    If the secret starts at byte offset ``k`` (0, 1, 2) inside a 3-byte group,
    only characters made purely of secret bits are stable. Encoding
    ``k`` dummy bytes + the secret and keeping ``[ceil(8k/6), floor(8(k+n)/6))``
    drops the characters that mix in unknown neighbour bytes. Index ``i`` of
    the returned list is ``k``; segments shorter than ``min_length`` are
    returned as an empty string so that indexes stay aligned.
    """
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    n = len(raw)
    out: list[str] = []
    for k in (0, 1, 2):
        encoded = encode(b"\x00" * k + raw).decode("ascii")
        start = (8 * k + 5) // 6
        end = (8 * (k + n)) // 6
        seg = encoded[start:end]
        out.append(seg if len(seg) >= min_length else "")
    return out


def build_variants(secret: str, *, min_length: int = 8) -> list[tuple[str, str]]:
    """Return ``(code, text)`` pairs for ``secret``; duplicates keep the first code."""
    raw = secret.encode("utf-8")
    pairs: list[tuple[str, str]] = [
        ("RAW", secret),
        ("URL", urllib.parse.quote(secret, safe="")),
        ("URL_PLUS", urllib.parse.quote_plus(secret)),
        ("JSON", json.dumps(secret)[1:-1]),
        ("REPR", repr(secret)[1:-1]),
        ("HEX", raw.hex()),
        ("HEX_UPPER", raw.hex().upper()),
        ("HTML_DEC", "".join(f"&#{ord(c)};" for c in secret)),
        ("HTML_HEX", "".join(f"&#x{ord(c):x};" for c in secret)),
        ("HTML_HEX_UPPER", "".join(f"&#x{ord(c):X};" for c in secret)),
    ]
    for k, seg in enumerate(b64_stable_segments(raw, urlsafe=False, min_length=min_length)):
        pairs.append((f"B64_STD_K{k}", seg))
    for k, seg in enumerate(b64_stable_segments(raw, urlsafe=True, min_length=min_length)):
        pairs.append((f"B64_URL_K{k}", seg))
    half = len(secret) // 2
    if half >= min_length:
        pairs.append(("HALF_HEAD", secret[:half]))
        pairs.append(("HALF_TAIL", secret[half:]))
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for code, text in pairs:
        if text and text not in seen:
            seen.add(text)
            out.append((code, text))
    return out
