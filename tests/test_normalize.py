"""AC-4: normalisation is applied to the secret AND the outgoing text."""

import _lang  # noqa: F401  (pins the output language to English)

from known_secret_guard import Guard
from known_secret_guard.normalize import normalize

# contains '+', space, '%', '&' - everything unquote_plus / html.unescape / whitespace-strip touch
TRICKY = "Ab+Cd Ef%Gh&Ij9Kl!Mn"
ZW = "​"


def test_normalization_applied_to_both_sides():
    guard = Guard({"TRICKY": TRICKY})
    half = len(TRICKY) // 2
    cases = {
        "zero-width everywhere": ZW.join(TRICKY),
        "zero-width in first half only": ZW.join(TRICKY[:half + 4]) + " and then unrelated text",
        "tag split": "<b>" + TRICKY[:9] + "</b><i>" + TRICKY[9:] + "</i>",
        "soft hyphen": "­".join(TRICKY),
    }
    for label, text in cases.items():
        found = guard.scan(text)
        assert found, label
        assert found[0].variant.startswith(("NORM_", "HALF_")), (label, found)
    assert any(f.variant.startswith("NORM_") for f in guard.scan(cases["zero-width everywhere"]))


def test_one_sided_normalization_would_miss():
    # The secret itself contains '+': normalising only the text turns '+' into nothing,
    # so a raw (un-normalised) secret could never match. Both sides must use one function.
    assert "+" not in normalize(TRICKY)
    assert normalize(TRICKY) in normalize(ZW.join(TRICKY))


def test_normalized_findings_have_no_offset():
    guard = Guard({"TRICKY": TRICKY})
    assert guard.scan(ZW.join(TRICKY))[0].offset is None
