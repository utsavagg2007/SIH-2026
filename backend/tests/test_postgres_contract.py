"""The Postgres write path, checked without a Postgres.

Three lists have to agree for a single row to insert: the column list, the
`$n` placeholders, and the tuple `_row_params` builds. They are written out by
hand in three different places, and a disagreement between them is invisible
until a real database rejects the statement — which on this project means it
surfaces the first time anyone points the backend at Supabase, and never during
development, because the default store is in-memory.

Also pins that every column the INSERT names actually exists in the schema, so
a migration and the repository cannot drift apart silently.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.storage.postgres import _COLUMNS, _INSERT, PostgresRepository

from .test_projection_aliases import _alert, _project

MIGRATIONS = Path(__file__).resolve().parent.parent / "db" / "migrations"


def _columns() -> list[str]:
    return [c.strip() for c in _COLUMNS.replace("\n", " ").split(",") if c.strip()]


def _placeholders() -> set[int]:
    values = _INSERT[_INSERT.index("VALUES") : _INSERT.index("ON CONFLICT")]
    return {int(n) for n in re.findall(r"\$(\d+)", values)}


def test_columns_placeholders_and_params_all_agree():
    view = _project("port_scan")
    params = PostgresRepository._row_params(view)
    columns = _columns()
    placeholders = _placeholders()

    assert len(columns) == len(params), (
        f"{len(columns)} columns but {len(params)} params — the INSERT would "
        "bind the wrong value to every column after the mismatch"
    )
    assert placeholders == set(range(1, len(columns) + 1)), (
        "placeholders are not a contiguous $1..$n covering every column"
    )


def test_every_inserted_column_exists_in_the_schema():
    ddl = (MIGRATIONS / "0001_init.sql").read_text(encoding="utf-8")
    table = ddl[ddl.index("CREATE TABLE IF NOT EXISTS alerts") : ddl.index("CREATE INDEX")]
    for column in _columns():
        assert re.search(rf"^\s*{re.escape(column)}\s", table, re.M), (
            f"INSERT names {column!r}, which the alerts table does not define"
        )


def test_on_conflict_updates_only_columns_that_exist():
    """Idempotent replay depends on this clause; a bad name fails at runtime."""
    clause = _INSERT[_INSERT.index("ON CONFLICT") :]
    for column in re.findall(r"^\s*(\w+) = ", clause, re.M):
        assert column in _columns(), f"ON CONFLICT sets unknown column {column!r}"


@pytest.mark.parametrize(
    "threat_class",
    ["port_scan", "ddos", "c2_beaconing", "dga_domain",
     "dns_tunnelling", "encrypted_malware", "data_exfiltration"],
)
def test_every_threat_class_serialises_for_postgres(threat_class):
    """JSONB columns must be real JSON, and enums must be sent as their values.

    asyncpg will not serialise a pydantic enum or a set, so a class whose
    evidence happens to contain one fails only for that class, in production.
    """
    view = _project(threat_class)
    params = PostgresRepository._row_params(view)

    for value in params:
        assert value is None or isinstance(
            value, (str, int, float, bool, list)
        ), f"{type(value).__name__} is not a type asyncpg can bind"

    # evidence, evidence_bars, raw are JSONB; visual is JSONB or NULL.
    columns = _columns()
    for name in ("evidence", "evidence_bars", "raw"):
        json.loads(params[columns.index(name)])
    visual = params[columns.index("visual")]
    if visual is not None:
        json.loads(visual)


def test_kill_chain_stage_is_within_the_migrated_check_constraint():
    """0003 added a CHECK; a stage outside it would fail every insert."""
    ddl = (MIGRATIONS / "0003_kill_chain_check.sql").read_text(encoding="utf-8")
    allowed = set(re.findall(r"'(\w+)'", ddl))
    columns = _columns()
    for threat_class in ("port_scan", "c2_beaconing", "data_exfiltration",
                         "dga_domain", "ddos", "dns_tunnelling",
                         "encrypted_malware"):
        stage = PostgresRepository._row_params(_project(threat_class))[
            columns.index("kill_chain_stage")
        ]
        assert stage in allowed, f"{stage!r} violates the CHECK added in 0003"


def test_severity_and_threat_class_match_the_schema_enums():
    ddl = (MIGRATIONS / "0001_init.sql").read_text(encoding="utf-8")
    columns = _columns()
    for constraint, column in (
        ("alerts_severity_enum", "severity"),
        ("alerts_threat_class_enum", "threat_class"),
        ("alerts_score_type_enum", "score_type"),
        ("alerts_event_scope_enum", "event_scope"),
    ):
        block = ddl[ddl.index(constraint) :]
        allowed = set(re.findall(r"'([a-z_]+)'", block[: block.index(")")]))
        value = PostgresRepository._row_params(_project("port_scan"))[
            columns.index(column)
        ]
        assert value in allowed, f"{column}={value!r} violates {constraint}"


def test_an_alert_id_is_bound_once_so_replay_is_idempotent():
    """Same alert twice must hit ON CONFLICT, not create a second row."""
    first = PostgresRepository._row_params(_project("port_scan"))
    assert _INSERT.count("ON CONFLICT (alert_id)") == 1
    assert isinstance(first[_columns().index("alert_id")], str)
