#!/usr/bin/env python3
"""Apply database migrations in order, once each.

    python tools/migrate.py                  # apply everything outstanding
    python tools/migrate.py --status         # what is applied, what is pending
    python tools/migrate.py --dry-run

Reads ``DATABASE_URL``, or the ``SUPABASE_*`` settings, through the same
``app.config.Settings`` the service uses - so a migration cannot be applied to a
database the backend would not have connected to.

Why this exists
---------------
``db/schema.sql`` is ``CREATE TABLE IF NOT EXISTS`` from top to bottom, which
means it is a no-op against any database that already has the tables. It cannot
add a column, widen a CHECK, or enable RLS. Every one of those is a change this
schema has already needed, and without a migration mechanism the only way to get
one applied is for somebody to remember to paste a snippet into the Supabase SQL
editor - and to remember whether they already did.

Applied versions are recorded in ``schema_migrations``, so re-running is safe and
"has 0002 landed on the demo database?" has an answer you can query rather than
recall.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"

_LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    checksum    TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""


def _discover() -> list[tuple[str, Path]]:
    """Migration files, ordered by their numeric prefix."""
    if not MIGRATIONS_DIR.is_dir():
        return []
    files = sorted(MIGRATIONS_DIR.glob("*.sql"), key=lambda p: p.name)
    return [(p.stem, p) for p in files]


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


async def run(dsn: str, *, dry_run: bool, status_only: bool) -> int:
    import asyncpg

    migrations = _discover()
    if not migrations:
        print(f"no migrations found in {MIGRATIONS_DIR}", file=sys.stderr)
        return 1

    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(_LEDGER)
        rows = await conn.fetch("SELECT version, checksum FROM schema_migrations")
        applied = {r["version"]: r["checksum"] for r in rows}

        pending = [(v, p) for v, p in migrations if v not in applied]

        for version, path in migrations:
            digest = _checksum(path)
            if version in applied:
                mark = "ok " if applied[version] == digest else "CHANGED"
                if mark == "CHANGED":
                    # A migration that has already run and whose file has since
                    # been edited: the database and the repository now disagree
                    # about what was applied. Say so rather than re-running it.
                    print(
                        f"  {mark} {version}  (applied checksum "
                        f"{applied[version]} != file {digest}) - the file was "
                        "edited after it ran; write a new migration instead"
                    )
                else:
                    print(f"  {mark} {version}")
            else:
                print(f"  -   {version}  PENDING")

        if status_only:
            return 0
        if not pending:
            print("\nnothing to apply")
            return 0
        if dry_run:
            print(f"\n{len(pending)} migration(s) would be applied")
            return 0

        for version, path in pending:
            sql = path.read_text(encoding="utf-8")
            print(f"\napplying {version} ...")
            # Each migration is one transaction: it lands whole or not at all.
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
                    version,
                    _checksum(path),
                )
            print(f"  applied {version}")
        print(f"\n{len(pending)} migration(s) applied")
        return 0
    finally:
        await conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Apply outstanding database migrations")
    ap.add_argument("--dry-run", action="store_true", help="report without applying")
    ap.add_argument("--status", action="store_true", help="report and exit")
    ap.add_argument("--dsn", default=None, help="override the configured connection string")
    args = ap.parse_args()

    dsn = args.dsn or get_settings().resolved_database_url
    if not dsn:
        print(
            "ERROR: no database configured. Set DATABASE_URL, or "
            "SUPABASE_PROJECT_REF + SUPABASE_DB_PASSWORD (+ SUPABASE_REGION).",
            file=sys.stderr,
        )
        return 1

    # Never print the DSN: it carries the password.
    print(f"migrations: {MIGRATIONS_DIR}")
    return asyncio.run(run(dsn, dry_run=args.dry_run, status_only=args.status))


if __name__ == "__main__":
    raise SystemExit(main())
