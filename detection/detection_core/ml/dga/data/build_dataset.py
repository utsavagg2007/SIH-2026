"""Build a ``domain,label,family`` CSV for the offline DGA classifier.

    python -m detection_core.ml.dga.data.build_dataset --out dga_dataset.csv

Two public sources, fetched over HTTPS with the standard library only (no new
dependency):

* **Benign** - the Tranco research top-sites list (https://tranco-list.eu/).
  Ranked, aggregated from several public popularity rankings. The top
  ``--tranco-n`` names are taken, label ``0``, family ``benign``.
* **DGA** - the *example domain* files from
  https://github.com/baderj/domain_generation_algorithms (one
  ``<family>/example_domains.txt`` per malware family). Label ``1``, family =
  the directory name, which is a real malware family and is **never derived
  from the domain text**. Only these generated example strings are fetched;
  none of that repository's code is downloaded or executed.

Both licences and the redistribution rationale are in ``PROVENANCE.md`` next
to this file. Every fetched domain must pass the project's own
:func:`~detection_core.ml.dga.features.normalize_domain`; anything it rejects
is dropped. Domains are then deduplicated (a domain seen under two families,
or as both benign and DGA, is dropped), each DGA family is capped at
``--per-family-cap`` rows, and the benign side is trimmed to roughly match the
DGA total so the classes are balanced.

This script writes a CSV and prints a summary. It trains nothing and imports
nothing from the live detection layer.
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from ..features import normalize_domain

__all__ = [
    "TRANCO_URL",
    "BADERJ_RAW",
    "DEFAULT_FAMILIES",
    "fetch_benign",
    "fetch_dga_family",
    "build",
    "main",
]

#: Tranco "latest" permanent download. A specific list can be pinned with
#: ``--tranco-id`` (the id from a tranco-list.eu permalink); recorded in
#: PROVENANCE.md so a build is reproducible.
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_ID_URL = "https://tranco-list.eu/download/{id}/1000000"

#: Raw base for the baderj example-domain files.
BADERJ_RAW = (
    "https://raw.githubusercontent.com/baderj/"
    "domain_generation_algorithms/master/{family}/example_domains.txt"
)

#: A spread of families with enough examples to survive per-family capping and
#: a family-disjoint split. Override with ``--families a,b,c`` or ``--families all``.
DEFAULT_FAMILIES = (
    "banjori",
    "chinad",
    "corebot",
    "dircrypt",
    "gozi",
    "locky",
    "m0yv",
    "mydoom",
    "necurs",
    "newgoz",
    "ngioweb",
    "nymaim",
    "nymaim2",
    "pitou",
    "proslikefan",
    "pushdo",
    "qadars",
    "qakbot",
    "ramnit",
    "reconyc",
    "shiotob",
    "simda",
    "sisron",
    "symmi",
    "tempedreve",
    "tinba",
    "tufik",
)

_UA = {"User-Agent": "detection-core-dga-dataset-builder/1.0 (+offline research use)"}
_ALL_FAMILIES_SENTINEL = "all"
_GITHUB_API_TREE = (
    "https://api.github.com/repos/baderj/"
    "domain_generation_algorithms/git/trees/master"
)


def _get(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _normalized(raw: str) -> str | None:
    """``normalize_domain`` if the string survives it, else ``None``."""
    try:
        return normalize_domain(raw)
    except (TypeError, ValueError):
        return None


def fetch_benign(count: int, *, tranco_id: str | None, timeout: float) -> list[str]:
    """The top ``count`` Tranco domains that pass ``normalize_domain``."""
    url = TRANCO_ID_URL.format(id=tranco_id) if tranco_id else TRANCO_URL
    payload = _get(url, timeout)

    # The permalink download is raw CSV; the "latest" URL is a zip of one CSV.
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            name = archive.namelist()[0]
            text = archive.read(name).decode("utf-8", "replace")
    else:
        text = payload.decode("utf-8", "replace")

    domains: list[str] = []
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        candidate = row[-1].strip()  # rank,domain  (permalink) or just domain
        normalized = _normalized(candidate)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
        if len(domains) >= count:
            break
    return domains


def _all_baderj_families(timeout: float) -> list[str]:
    import json

    tree = json.loads(_get(_GITHUB_API_TREE + "?recursive=1", timeout))
    return sorted(
        {
            item["path"].split("/", 1)[0]
            for item in tree.get("tree", [])
            if item.get("path", "").endswith("/example_domains.txt")
        }
    )


def fetch_dga_family(family: str, *, timeout: float) -> list[str]:
    """Normalized example domains for one baderj family. ``[]`` if it has none."""
    try:
        text = _get(BADERJ_RAW.format(family=family), timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise

    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = _normalized(line)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def build(
    *,
    tranco_n: int,
    families: list[str],
    per_family_cap: int,
    seed: int,
    tranco_id: str | None,
    timeout: float,
    balance: bool,
) -> tuple[list[tuple[str, int, str]], dict[str, object]]:
    """Return ``(rows, report)`` where ``rows`` is ``(domain, label, family)``."""
    rng = random.Random(seed)

    # --- DGA side -----------------------------------------------------------
    dga_by_domain: dict[str, str] = {}
    per_family_fetched: dict[str, int] = {}
    per_family_kept: dict[str, int] = {}
    for family in families:
        fetched = fetch_dga_family(family, timeout=timeout)
        per_family_fetched[family] = len(fetched)
        if not fetched:
            continue
        rng.shuffle(fetched)
        kept = 0
        for domain in fetched:
            if kept >= per_family_cap:
                break
            if domain in dga_by_domain:  # a domain claimed by an earlier family
                continue
            dga_by_domain[domain] = family
            kept += 1
        per_family_kept[family] = kept

    dga_rows = [(d, 1, f) for d, f in dga_by_domain.items()]

    # --- benign side -----------------------------------------------------
    benign = fetch_benign(tranco_n, tranco_id=tranco_id, timeout=timeout)
    benign = [d for d in benign if d not in dga_by_domain]  # no label conflict
    if balance and len(benign) > len(dga_rows):
        rng.shuffle(benign)
        benign = benign[: len(dga_rows)]
    benign_rows = [(d, 0, "benign") for d in benign]

    rows = sorted(benign_rows + dga_rows, key=lambda r: (r[1], r[2], r[0]))

    report = {
        "tranco_source": TRANCO_ID_URL.format(id=tranco_id) if tranco_id else TRANCO_URL,
        "families_requested": list(families),
        "families_with_examples": sorted(per_family_kept),
        "families_empty": sorted(f for f in families if not per_family_kept.get(f)),
        "per_family_fetched": per_family_fetched,
        "per_family_kept": per_family_kept,
        "per_family_cap": per_family_cap,
        "benign_count": len(benign_rows),
        "dga_count": len(dga_rows),
        "total_rows": len(rows),
        "seed": seed,
    }
    return rows, report


def _verify(rows: list[tuple[str, int, str]], *, sample: int, seed: int) -> None:
    """Assert a random sample round-trips through the real feature extractor."""
    from ..features import extract_features

    rng = random.Random(seed + 1)
    probe = rng.sample(rows, min(sample, len(rows)))
    for domain, _label, _family in probe:
        vector = extract_features(domain)
        if len(vector) != 19 or not all(isinstance(v, float) for v in vector):
            raise AssertionError(f"feature extraction misbehaved on {domain!r}")


def _write_csv(rows: list[tuple[str, int, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("domain", "label", "family"))
        writer.writerows(rows)


def _print_report(report: dict[str, object], out: Path | None) -> None:
    print("DGA dataset build")
    print(f"  tranco source     : {report['tranco_source']}")
    print(f"  seed              : {report['seed']}")
    print(f"  per-family cap     : {report['per_family_cap']}")
    print(f"  benign / dga       : {report['benign_count']} / {report['dga_count']}")
    print(f"  total rows         : {report['total_rows']}")
    empty = report["families_empty"]
    if empty:
        print(f"  families with no examples (skipped): {', '.join(empty)}")
    print("  rows per DGA family:")
    for family, kept in sorted(
        report["per_family_kept"].items(), key=lambda kv: (-kv[1], kv[0])
    ):
        fetched = report["per_family_fetched"].get(family, 0)
        print(f"    {family:<22} {kept:>5}  (of {fetched} fetched)")
    if out is not None:
        print(f"  written            : {out}")
    print("  NOTE: family labels come from the source directory names, never "
          "from the domain text. See PROVENANCE.md.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m detection_core.ml.dga.data.build_dataset",
        description=__doc__.split("\n\n")[0],
    )
    parser.add_argument(
        "--out", type=Path, default=Path("dga_dataset.csv"),
        help="output CSV path (default: dga_dataset.csv)",
    )
    parser.add_argument(
        "--tranco-n", type=int, default=20_000,
        help="how many top Tranco names to consider for the benign side",
    )
    parser.add_argument(
        "--tranco-id", default=None,
        help="pin a specific Tranco list id (from a tranco-list.eu permalink)",
    )
    parser.add_argument(
        "--families", default=",".join(DEFAULT_FAMILIES),
        help=f"comma-separated family list, or '{_ALL_FAMILIES_SENTINEL}'",
    )
    parser.add_argument(
        "--per-family-cap", type=int, default=200,
        help="max rows kept per DGA family (default: 200)",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--no-balance", action="store_true",
        help="keep all fetched benign names instead of trimming to the DGA total",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="skip the feature-extraction round-trip check",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    try:
        if args.families.strip() == _ALL_FAMILIES_SENTINEL:
            families = _all_baderj_families(args.timeout)
        else:
            families = [f.strip() for f in args.families.split(",") if f.strip()]

        rows, report = build(
            tranco_n=args.tranco_n,
            families=families,
            per_family_cap=args.per_family_cap,
            seed=args.seed,
            tranco_id=args.tranco_id,
            timeout=args.timeout,
            balance=not args.no_balance,
        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if report["dga_count"] == 0 or report["benign_count"] == 0:
        print(
            f"ERROR: need both classes; got {report['benign_count']} benign, "
            f"{report['dga_count']} dga. Check network access and --families.",
            file=sys.stderr,
        )
        return 1

    if not args.no_verify:
        _verify(rows, sample=200, seed=args.seed)

    _write_csv(rows, args.out)

    if args.json:
        import json

        print(json.dumps(report, indent=2, default=list))
    else:
        _print_report(report, args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
