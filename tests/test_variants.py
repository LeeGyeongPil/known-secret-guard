"""AC-2: 16 disguises x 3 fake secrets = 48 samples, all caught with the expected code."""

from known_secret_guard import Guard
from known_secret_guard.demo import samples

# Expected code per disguise. Codes are de-duplicated (first wins), so a secret without
# special characters reports RAW for the escaping disguises.
EXPECTED_PLAIN = {
    "raw": "RAW", "url_quote": "RAW", "url_quote_plus_with_prefix": "RAW", "json_in_body": "RAW",
    "repr_in_log": "RAW", "b64_std_alone": "B64_STD_K0", "b64_std_offset1": "B64_STD_K1",
    "b64_std_offset2": "B64_STD_K2", "b64_url_offset1": "B64_STD_K1", "hex_lower": "HEX",
    "hex_upper": "HEX_UPPER", "html_dec": "HTML_DEC", "html_hex": "HTML_HEX_UPPER",
    "split_halves": "HALF_HEAD", "zero_width": "NORM_RAW", "html_tag_split": "HALF_TAIL",
}
EXPECTED_SPECIAL = {**EXPECTED_PLAIN, "url_quote": "URL", "url_quote_plus_with_prefix": "URL",
                    "json_in_body": "JSON", "repr_in_log": "REPR"}


def test_all_48_samples_caught(secrets):
    guard = Guard(secrets)
    count = 0
    for name, stem, disguise, text in samples():
        count += 1
        expected = (EXPECTED_SPECIAL if name == "FAKE_PASSWORD" else EXPECTED_PLAIN)[disguise]
        found = {f.secret_name: f.variant for f in guard.scan(text)}
        assert found.get(name) == expected, f"{stem}: expected {name}:{expected}, got {found}"
    assert count == 48


def test_b64_url_safe_variant_is_distinct_for_special_chars():
    # '+' and '/' differ between the alphabets, so URL-safe segments are real variants.
    from known_secret_guard.variants import build_variants
    codes = {c for c, _ in build_variants("\xfb\xff?>>>" * 4 + "abcdefgh")}
    assert {"B64_STD_K0", "B64_URL_K0"} <= codes
