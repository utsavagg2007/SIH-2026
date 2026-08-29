"""Loading trusted **local** JA3/JA3S/JA4 fingerprints from a file.

This reads a file off the local disk and nothing else. It opens no sockets,
resolves no names, follows no includes, expands no environment variables and
evaluates nothing - a feed is a list of strings, and the only thing that
happens to a string is validation. An IOC list is attacker-adjacent data by
definition, so the parser is deliberately dull.

**No fingerprint list ships with this project.** The sets are empty until an
operator points ``--ja3-feed`` at a file they trust, which is why the
encrypted-malware signature path is inert out of the box.

Feed grammar
------------
One entry per line. Blank lines and ``#`` comments are ignored::

    # incident-2026-08 handover, synthetic examples
    ja3:0123456789abcdef0123456789abcdef
    ja3s:fedcba9876543210fedcba9876543210
    ja4:t13d1516h2_8daaf6152771_02713d6af862

    # a bare MD5 is read as JA3 - the common shape of public JA3 lists
    00112233445566778899aabbccddeeff

A bare hex digest means **ja3** and never ja3s: the two are different
measurements that happen to share a format, and guessing which one a line
meant would put a client fingerprint in the server table.

Anything else is an error naming the file, the line number and the reason.
Malformed entries are never skipped: a silently dropped IOC is a detection
that quietly does not happen.
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "FINGERPRINT_TYPES",
    "FingerprintError",
    "load_fingerprint_feed",
    "normalize_fingerprint",
]

#: The kinds a feed may declare, matching the detector's own tuple.
FINGERPRINT_TYPES: tuple[str, ...] = ("ja3", "ja3s", "ja4")

#: JA3 and JA3S are MD5 digests: exactly 32 hex characters.
_MD5 = re.compile(r"^[0-9a-f]{32}$")

#: A conservative sanity check for JA4, not a specification. The published
#: forms (``t13d1516h2_8daaf6152771_02713d6af862`` and the JA4S/JA4H
#: variants) are lowercase alphanumerics with underscores; separators and a
#: length bound are all that is asserted here, because inventing a stricter
#: grammar than the spec would reject fingerprints that are perfectly valid.
_JA4 = re.compile(r"^[0-9a-z_.\-]{4,128}$")


class FingerprintError(ValueError):
    """A feed could not be read, or one of its lines is not usable."""


def normalize_fingerprint(kind: str, value: str) -> str:
    """Validate one fingerprint and return it in the detector's own form.

    Trimmed and lowercased - exactly what
    ``EncryptedMalwareConfig.__post_init__`` does to whatever it is given, so
    a value loaded here compares equal to the value the detector derives from
    a flow. Doing anything more (stripping separators, reordering fields,
    converting formats) could collapse two distinct fingerprints onto one
    string, and a signature match has to mean precisely what it says.

    Raises :class:`FingerprintError` with a reason rather than returning
    ``None``, because every caller here wants to report *why*.
    """
    if kind not in FINGERPRINT_TYPES:
        raise FingerprintError(
            f"unknown fingerprint type {kind!r}; expected one of "
            f"{', '.join(FINGERPRINT_TYPES)}"
        )
    if not isinstance(value, str):
        raise FingerprintError(f"{kind} fingerprint must be a string, got {type(value).__name__}")

    candidate = value.strip().lower()
    if not candidate:
        raise FingerprintError(f"empty {kind} fingerprint")

    if kind in ("ja3", "ja3s"):
        if not _MD5.match(candidate):
            raise FingerprintError(
                f"{kind} fingerprint {value.strip()!r} is not a 32-character "
                "hex MD5 digest"
            )
    elif not _JA4.match(candidate):
        raise FingerprintError(
            f"ja4 fingerprint {value.strip()!r} is not a plausible JA4 token "
            "(expected 4-128 characters of a-z, 0-9, '_', '.', '-')"
        )
    return candidate


def load_fingerprint_feed(path: str | Path) -> dict[str, frozenset[str]]:
    """Read a local feed file into one normalized set per fingerprint kind.

    Returns a mapping with a key for every entry in
    :data:`FINGERPRINT_TYPES`, each holding a possibly-empty frozenset.
    Duplicates collapse naturally and are not an error - the same indicator
    reaching a team twice is ordinary.

    Raises :class:`FingerprintError` for a missing path, a directory, an
    unreadable or non-UTF-8 file, or any line that is neither blank, a
    comment, nor a valid entry.
    """
    path = Path(path)
    if not path.exists():
        raise FingerprintError(f"fingerprint feed not found: {path}")
    if path.is_dir():
        raise FingerprintError(f"fingerprint feed is a directory, not a file: {path}")

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FingerprintError(f"could not read fingerprint feed {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FingerprintError(
            f"{path} is not valid UTF-8 text; a fingerprint feed is a plain "
            f"text list ({exc})"
        ) from exc

    loaded: dict[str, set[str]] = {kind: set() for kind in FINGERPRINT_TYPES}

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        kind, separator, value = line.partition(":")
        if separator:
            kind = kind.strip().lower()
            if kind not in FINGERPRINT_TYPES:
                raise FingerprintError(
                    f"{path} line {line_no}: unknown fingerprint type {kind!r}; "
                    f"expected one of {', '.join(FINGERPRINT_TYPES)}"
                )
            if not value.strip():
                raise FingerprintError(
                    f"{path} line {line_no}: {kind} entry has no fingerprint"
                )
        else:
            # An untyped line is only meaningful as a JA3 digest.
            kind, value = "ja3", line
            if not _MD5.match(value.lower()):
                raise FingerprintError(
                    f"{path} line {line_no}: {line!r} is neither a "
                    f"'<type>:<fingerprint>' entry nor a 32-character hex MD5 "
                    "digest. Prefix it with ja3:, ja3s: or ja4: to say which "
                    "kind it is"
                )

        try:
            loaded[kind].add(normalize_fingerprint(kind, value))
        except FingerprintError as exc:
            raise FingerprintError(f"{path} line {line_no}: {exc}") from exc

    return {kind: frozenset(values) for kind, values in loaded.items()}
