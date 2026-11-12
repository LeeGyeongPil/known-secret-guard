"""AC-5: no false positives on a negative corpus; min length and exclude behave."""

import _lang  # noqa: F401  (pins the output language to English)

import glob
import json
import os
import re
import urllib.parse

import known_secret_guard
from known_secret_guard import Guard


def _corpus() -> list[str]:
    pkg = os.path.dirname(known_secret_guard.__file__)
    files = sorted(glob.glob(os.path.join(pkg, "**", "*.py"), recursive=True))
    # demo.py holds the fake secrets in pieces; a piece can contain half of one, which is a
    # correct HALF_* hit, so the file that *defines* the fakes is not a negative sample.
    files = [f for f in files if os.path.basename(f) != "demo.py"]
    files += [json.__file__, re.__file__, os.__file__, urllib.parse.__file__]
    texts = []
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read())
    return texts


def test_negative_corpus_and_min_length(secrets):
    corpus = _corpus()
    assert len(corpus) >= 8
    guard = Guard({**secrets, "PORT": "8080", "ADMIN": "admin"})
    assert "PORT" in guard.skipped and "ADMIN" in guard.skipped
    assert "PORT" not in guard.names
    for text in corpus:
        assert guard.scan(text) == []
    # excluded names are not checked, other secrets still are
    excl = Guard(secrets, exclude=["FAKE_API_KEY"])
    assert "FAKE_API_KEY" not in excl.names
    leak = "token=" + secrets["FAKE_API_KEY"]
    assert excl.scan(leak) == []
    assert Guard(secrets).scan(leak)


def test_short_halves_not_registered():
    guard = Guard({"K": "abcdefghijkl"})  # 12 chars: halves are 6 < 8, so no HALF_* variants
    assert not any(code.startswith(("HALF", "NORM_HALF")) for _n, code, _l in guard.variant_summary())
