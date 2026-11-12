"""AC-10 (performance part): 50 secrets x 1 MB of base64 noise stays fast and clean."""

import _lang  # noqa: F401  (pins the output language to English)

import base64
import random
import time

from known_secret_guard import Guard


def test_50_secrets_1mb_under_1s():
    rng = random.Random(1234)
    secrets = {f"SECRET_{i}": base64.b64encode(rng.randbytes(24)).decode() for i in range(50)}
    guard = Guard(secrets)
    assert len(guard.names) == 50 and len(guard.variant_summary()) >= 500
    noise = base64.b64encode(rng.randbytes(786_432)).decode()  # ~1 MiB of text
    assert len(noise) >= 1_000_000
    start = time.perf_counter()
    findings = guard.scan(noise)
    elapsed = time.perf_counter() - start
    assert findings == []
    assert elapsed < 1.0, f"scan took {elapsed:.3f}s"
    # sanity: a real leak inside the noise is still found
    leaked = noise[:500_000] + secrets["SECRET_7"] + noise[500_000:]
    assert [f.secret_name for f in guard.scan(leaked)] == ["SECRET_7"]
