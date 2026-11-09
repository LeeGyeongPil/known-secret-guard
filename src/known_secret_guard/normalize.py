"""Normalisation used for the second-chance match.

It must be applied to the outgoing text AND to the secret. Applying it to one
side only misses secrets containing ``+`` (turned into a space by
``unquote_plus``), whitespace, ``%`` or ``&``.
"""

from __future__ import annotations

import html
import re
import urllib.parse

# U+200B..U+200D, U+2060, U+FEFF, U+00AD
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_TAG = re.compile(r"<[^>]{0,200}>")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Un-escape, drop tags / zero-width chars / whitespace, then casefold."""
    t = text
    for _ in range(3):  # bounded: stop early once stable
        nt = urllib.parse.unquote_plus(html.unescape(t))
        if nt == t:
            break
        t = nt
    t = _TAG.sub("", t)
    t = _ZERO_WIDTH.sub("", t)
    t = _WS.sub("", t)
    return t.casefold()
