"""Lexical features for DGA classification.

Operates on raw domain strings only. Nothing here reads ingestion's DNS
feature block - this is the *training-time* view of a domain, and it must
behave identically at inference time, so normalization is baked in rather
than left to the caller.

Every feature is deterministic, finite, and explainable in one sentence.
"""

from __future__ import annotations

import math
from collections import Counter

__all__ = [
    "FEATURE_NAMES",
    "VOWELS",
    "normalize_domain",
    "split_domain",
    "shannon_entropy",
    "longest_run",
    "extract_features",
    "extract_features_dict",
    "extract_feature_matrix",
]

VOWELS = frozenset("aeiou")

#: Stable feature order. Training and inference both read this list, and a
#: saved model records it so a schema change cannot pass unnoticed.
FEATURE_NAMES: tuple[str, ...] = (
    "length",
    "body_length",
    "tld_length",
    "label_count",
    "max_label_length",
    "mean_label_length",
    "digit_count",
    "digit_ratio",
    "alpha_ratio",
    "vowel_ratio",
    "consonant_ratio",
    "hyphen_count",
    "hyphen_ratio",
    "unique_char_count",
    "unique_char_ratio",
    "entropy",
    "longest_digit_run",
    "longest_alpha_run",
    "longest_consonant_run",
)


def normalize_domain(domain: str) -> str:
    """Deterministic, idempotent normalization of a domain string.

    Strips surrounding whitespace, lowercases, and removes the trailing DNS
    root dot. Rejects anything that is not a usable hostname rather than
    guessing at a repair.

    IDN/punycode is *not* decoded here: an ``xn--`` label is treated as the
    literal ASCII string it already is. That is a documented simplification
    for this milestone - a punycode label's lexical statistics are those of
    its encoded form, not the Unicode name a user would see.
    """
    if not isinstance(domain, str):
        raise TypeError(f"domain must be a string, got {type(domain).__name__}")

    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("domain must not be empty")
    if any(character.isspace() for character in normalized):
        raise ValueError(f"domain must not contain whitespace: {domain!r}")
    if "/" in normalized:
        raise ValueError(f"domain must be a hostname, not a URL: {domain!r}")
    if any(not label for label in normalized.split(".")):
        raise ValueError(f"domain has an empty label: {domain!r}")
    return normalized


def split_domain(normalized: str) -> tuple[str, str, list[str]]:
    """Return ``(body, tld, labels)`` for an already-normalized domain.

    The *body* is every label except the last, concatenated without dots -
    the part a DGA actually generates. The last label is treated as the TLD.

    Limitation: without a Public Suffix List, a multi-part suffix like
    ``co.uk`` is not resolved. For ``shop.example.co.uk`` the body becomes
    ``shopexampleco`` and the TLD ``uk``. This mislabels the suffix but
    stays deterministic, and the lexical signal we care about (randomness in
    the generated portion) survives. Adding a PSL dependency for this
    milestone was judged not worth it.
    """
    labels = normalized.split(".")
    if len(labels) == 1:
        return labels[0], "", labels
    return "".join(labels[:-1]), labels[-1], labels


def shannon_entropy(text: str) -> float:
    """Bits of Shannon entropy over the characters of ``text``.

    Low for repetitive or predictable strings ("aaaa" -> 0.0), high for
    varied ones. Random-looking DGA domains sit noticeably higher than
    pronounceable words of the same length.
    """
    if not text:
        return 0.0
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(text).values()
    )


def longest_run(text: str, predicate) -> int:
    """Length of the longest consecutive stretch satisfying ``predicate``."""
    longest = current = 0
    for character in text:
        current = current + 1 if predicate(character) else 0
        longest = max(longest, current)
    return longest


def _ratio(numerator: float, denominator: float) -> float:
    """Safe ratio - an empty denominator yields 0.0, never a division error."""
    return numerator / denominator if denominator else 0.0


def extract_features(domain: str) -> list[float]:
    """Feature vector for one domain, in :data:`FEATURE_NAMES` order.

    Normalizes first, so callers cannot accidentally feed training and
    inference differently shaped strings. Every value is a finite float.
    """
    normalized = normalize_domain(domain)
    body, tld, labels = split_domain(normalized)

    # Character statistics are computed on the body: the TLD is chosen from a
    # tiny fixed set and carries no information about how the name was
    # generated. Falls back to the whole domain if the body is somehow empty.
    subject = body or normalized
    length = len(subject)

    digits = sum(character.isdigit() for character in subject)
    alphas = sum(character.isalpha() for character in subject)
    vowels = sum(character in VOWELS for character in subject)
    consonants = alphas - vowels
    hyphens = subject.count("-")
    unique_chars = len(set(subject))
    label_lengths = [len(label) for label in labels]

    values = (
        float(len(normalized)),
        float(len(body)),
        float(len(tld)),
        float(len(labels)),
        float(max(label_lengths)),
        _ratio(sum(label_lengths), len(label_lengths)),
        float(digits),
        _ratio(digits, length),
        _ratio(alphas, length),
        _ratio(vowels, length),
        _ratio(consonants, length),
        float(hyphens),
        _ratio(hyphens, length),
        float(unique_chars),
        _ratio(unique_chars, length),
        shannon_entropy(subject),
        float(longest_run(subject, str.isdigit)),
        float(longest_run(subject, str.isalpha)),
        float(
            longest_run(
                subject, lambda c: c.isalpha() and c not in VOWELS
            )
        ),
    )
    return list(values)


def extract_features_dict(domain: str) -> dict[str, float]:
    """Same features as :func:`extract_features`, keyed by name."""
    return dict(zip(FEATURE_NAMES, extract_features(domain)))


def extract_feature_matrix(domains: list[str]) -> list[list[float]]:
    """Feature rows for many domains, preserving input order."""
    return [extract_features(domain) for domain in domains]
