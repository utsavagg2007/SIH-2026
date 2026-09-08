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
| `0004_ledger_lockdown.sql` | Does the same for `schema_migrations`, which `0002` could not cover because `tools/migrate.py` creates it rather than a migration |

## Reading Supabase's Security Advisor

Once every migration is applied the advisor shows **0 errors** and **4 info
suggestions**, all four of them `rls_enabled_no_policy` — one per table.

**That is the intended state, not a backlog.** RLS is on and there is
deliberately no policy, which is what makes PostgREST return nothing to the
anon key that ships in the frontend bundle. The backend connects as the owning
Postgres role and bypasses RLS entirely, so it is unaffected. Adding a policy
to clear those four rows would grant the anon key read access to every internal
IP, JA3 fingerprint and incident narrative in the corpus — it would turn a
clean advisor into a data leak.

When a real auth layer arrives, write the policies then, in a new migration.
Until then the four suggestions are the lockdown working.

Verify it directly rather than trusting the advisor's cache:

```sql
SELECT c.relname, c.relrowsecurity AS rls,
       has_table_privilege('anon', c.oid, 'SELECT') AS anon_can_read
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r';
```

Every row must read `rls = true, anon_can_read = false`.

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
