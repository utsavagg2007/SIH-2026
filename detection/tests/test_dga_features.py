"""Domain normalization and lexical feature tests."""

from __future__ import annotations

import math

import pytest

from detection_core.ml.dga.features import (
    FEATURE_NAMES,
    extract_feature_matrix,
    extract_features,
    extract_features_dict,
    longest_run,
    normalize_domain,
    shannon_entropy,
    split_domain,
)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("GOOGLE.COM", "google.com"),
        ("  github.com  ", "github.com"),
        ("Example.COM.", "example.com"),
        ("wikipedia.org", "wikipedia.org"),
        ("\tMiXeD.Case.Net\n", "mixed.case.net"),
    ],
)
def test_normalization(raw, expected):
    """1, 2, 3."""
    assert normalize_domain(raw) == expected


def test_normalization_is_idempotent():
    once = normalize_domain("  GOOGLE.com. ")
    assert normalize_domain(once) == once


@pytest.mark.parametrize("raw", ["", "   ", ".", "..", "\n"])
def test_empty_domain_rejected(raw):
    """4."""
    with pytest.raises(ValueError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw", ["bad domain.com", "a..b.com", ".leading.com", "http://x.com/path"]
)
def test_malformed_domain_rejected(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_non_string_rejected():
    with pytest.raises(TypeError):
        normalize_domain(1234)


@pytest.mark.parametrize(
    ("domain", "body", "tld"),
    [
        ("google.com", "google", "com"),
        ("abc123.example.com", "abc123example", "com"),
        ("localhost", "localhost", ""),
        ("shop.example.co.uk", "shopexampleco", "uk"),
    ],
)
def test_split_domain(domain, body, tld):
    """The co.uk case documents the missing Public Suffix List."""
    got_body, got_tld, _ = split_domain(domain)
    assert (got_body, got_tld) == (body, tld)


# --------------------------------------------------------------------------
# Feature vector shape
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    ["a.io", "google.com", "kqxvbzmwjrph.com", "x", "mail.google.com", "a-b-c.net"],
)
def test_feature_vector_is_stable_and_finite(domain):
    """5, 7, 13."""
    vector = extract_features(domain)
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in vector)
    assert all(math.isfinite(value) for value in vector)


def test_feature_names_are_stable():
    """6."""
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert extract_features_dict("google.com").keys() == set(FEATURE_NAMES)


def test_feature_extraction_is_deterministic():
    assert extract_features("google.com") == extract_features("GOOGLE.COM.")


def test_feature_matrix_preserves_order():
    domains = ["a.io", "google.com", "kqxvbzmwjrph.com"]
    matrix = extract_feature_matrix(domains)
    assert len(matrix) == 3
    assert matrix[1] == extract_features("google.com")


def test_single_character_domain_has_no_division_error():
    """13. The tiniest valid input must not blow up any ratio."""
    features = extract_features_dict("a")
    assert all(math.isfinite(value) for value in features.values())
    assert features["unique_char_ratio"] == 1.0


# --------------------------------------------------------------------------
# Individual features
# --------------------------------------------------------------------------


def test_entropy_of_repetitive_string_is_lower_than_varied():
    """8."""
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("abcdefgh")
    assert extract_features_dict("aaaaaaaa.com")["entropy"] < (
        extract_features_dict("kqxvbzmw.com")["entropy"]
    )


def test_digit_features():
    """9. 'abc123' body -> 3 of 6 characters are digits."""
    features = extract_features_dict("abc123.com")
    assert features["digit_count"] == 3.0
    assert features["digit_ratio"] == pytest.approx(0.5)
    assert features["alpha_ratio"] == pytest.approx(0.5)


def test_no_digits_gives_zero_ratio():
    features = extract_features_dict("google.com")
    assert features["digit_count"] == 0.0
    assert features["digit_ratio"] == 0.0


def test_hyphen_features():
    """10. body 'a-b-c' -> 2 hyphens of 5 characters."""
    features = extract_features_dict("a-b-c.com")
    assert features["hyphen_count"] == 2.0
    assert features["hyphen_ratio"] == pytest.approx(2 / 5)


def test_longest_digit_run():
    """11."""
    assert extract_features_dict("ab1234cd5.com")["longest_digit_run"] == 4.0
    assert extract_features_dict("google.com")["longest_digit_run"] == 0.0


def test_longest_alpha_run():
    """12."""
    assert extract_features_dict("ab123cdef4.com")["longest_alpha_run"] == 4.0
    assert extract_features_dict("google.com")["longest_alpha_run"] == 6.0


def test_longest_consonant_run():
    """A long consonant cluster is a classic random-looking-domain signal."""
    assert extract_features_dict("kqxvbz.com")["longest_consonant_run"] == 6.0
    assert extract_features_dict("banana.com")["longest_consonant_run"] == 1.0


def test_vowel_and_consonant_ratios_complement_alpha():
    features = extract_features_dict("banana.com")
    assert features["vowel_ratio"] == pytest.approx(0.5)
    assert features["consonant_ratio"] == pytest.approx(0.5)
    assert features["vowel_ratio"] + features["consonant_ratio"] == pytest.approx(
        features["alpha_ratio"]
    )


def test_label_features():
    features = extract_features_dict("mail.google.com")
    assert features["label_count"] == 3.0
    assert features["max_label_length"] == 6.0
    assert features["mean_label_length"] == pytest.approx((4 + 6 + 3) / 3)
    assert features["tld_length"] == 3.0


def test_length_features():
    features = extract_features_dict("google.com")
    assert features["length"] == 10.0
    assert features["body_length"] == 6.0


def test_unique_character_features():
    """'aaabbb' body: 2 unique of 6."""
    features = extract_features_dict("aaabbb.com")
    assert features["unique_char_count"] == 2.0
    assert features["unique_char_ratio"] == pytest.approx(2 / 6)


def test_longest_run_helper():
    assert longest_run("", str.isdigit) == 0
    assert longest_run("111", str.isdigit) == 3
    assert longest_run("1a11a111", str.isdigit) == 3


def test_random_looking_domain_scores_differently_than_a_word():
    """Sanity: the features separate the two classes at all."""
    word = extract_features_dict("wikipedia.org")
    random_looking = extract_features_dict("kqxvbzmwjrph.org")
    assert random_looking["entropy"] > word["entropy"]
    assert random_looking["vowel_ratio"] < word["vowel_ratio"]
