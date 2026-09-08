-- The migration ledger, locked down like every other table.
--
-- `schema_migrations` is not written by any file in `migrations/`. It is
-- created by tools/migrate.py itself, before the first migration runs, with a
-- bare CREATE TABLE IF NOT EXISTS - so it was the one table in `public` that
-- 0002's lockdown could not have covered, and Supabase's Security Advisor
-- flagged it as the only RLS error in the project.
--
-- What it leaks is small but not nothing: which migrations have been applied,
-- when, and their checksums. That is a version fingerprint of the deployment,
-- readable by anyone holding the anon key that ships in the frontend bundle.
-- The reasoning in 0002 applies unchanged - the backend and the migration tool
-- connect as the owning Postgres role and bypass RLS, PostgREST's anon and
-- authenticated roles do not - so enabling it costs nothing and closes the row.
--
-- This migration fixes the database you already have. The same two statements
-- were added to tools/migrate.py's ledger DDL so a database created after this
-- is never briefly exposed in the first place; that is the half of the fix that
-- stops the error coming back on the next Supabase project.

ALTER TABLE schema_migrations ENABLE ROW LEVEL SECURITY;

-- Guarded because `anon` and `authenticated` are Supabase's roles, not
-- Postgres's. db/README.md and storage/postgres.py both document this schema as
-- running against any Postgres, and an unguarded REVOKE aborts the whole
-- migration there with "role does not exist" - failing the lockdown on the one
-- kind of deployment that never needed it.
DO $$
BEGIN
    REVOKE ALL ON schema_migrations FROM anon, authenticated;
EXCEPTION WHEN undefined_object THEN
    RAISE NOTICE 'no anon/authenticated role; not a Supabase database';
END
$$;
