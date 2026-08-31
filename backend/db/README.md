# Alert store

`migrations/` is the source of truth. Apply it with:

```bash
python tools/migrate.py --status     # what is applied, what is pending
python tools/migrate.py              # apply everything outstanding
```

`schema.sql` is the same schema flattened into one file, kept for pasting into
the Supabase SQL editor when that is easier than running the tool. It is
`CREATE ... IF NOT EXISTS` throughout, so it **cannot alter a database that
already has these tables** — that is what the migrations are for, and why
`0002_rls_lockdown.sql` and `0003_kill_chain_check.sql` exist as separate files
rather than as edits to `0001`.

| Migration | What it does |
|---|---|
| `0001_init.sql` | `alerts`, `incidents`, `incident_alerts`, the `host_summary` view, and the indexes the dashboard and analyst filter on |
| `0002_rls_lockdown.sql` | Enables Row Level Security with no policies, so Supabase's PostgREST API returns nothing to the anon key while the backend's Postgres role is unaffected |
| `0003_kill_chain_check.sql` | Adds the one enum CHECK `0001` omitted |

## Supabase

Set either `DATABASE_URL` (paste the whole string from Project Settings →
Database) or all three of:

```
STORAGE_BACKEND=postgres
SUPABASE_PROJECT_REF=<ref>
SUPABASE_DB_PASSWORD=<password>
SUPABASE_REGION=<region>       # NOT guessable; read it off the pooler host
```

The password is percent-encoded before it goes into the URI, so a generated
password containing `@` or `/` works without escaping it by hand.
