"""AC-3: base64 stable segments catch a secret anywhere in a base64'd body."""

import _lang  # noqa: F401  (pins the output language to English)

import base64
import json

from known_secret_guard import Guard

SECRET = "".join(("sk-", "FAKE", "x9Lq2Wm7Rv4Tz8Kp3Hn6"))
TAILS = ("", "!", "!!", '","x":1}')


def _payloads():
    for pad in range(12):
        for tail in TAILS:
            body = (json.dumps({"p": "y" * pad, "s": SECRET}) + tail).encode()
            yield base64.b64encode(body).decode()
            yield base64.urlsafe_b64encode(body).decode()
            yield base64.urlsafe_b64encode(body).decode().rstrip("=")


def _shift_variants(secret: str) -> list[str]:
    """Reference 'shift' strategy: base64 of secret[k:] for k = 0, 1, 2."""
    raw = secret.encode()
    return [base64.b64encode(raw[k:]).decode() for k in (0, 1, 2)]


def test_midstream_payloads_all_caught():
    guard = Guard({"FAKE_KEY": SECRET})
    payloads = list(_payloads())
    stable = sum(bool(guard.scan(p)) for p in payloads)
    assert stable == len(payloads)
    std = [p for p in payloads if "-" not in p and "_" not in p]
    shift = sum(any(v in p for v in _shift_variants(SECRET)) for p in std)
    assert shift < len(std), "the shift strategy is expected to miss some mid-stream payloads"
