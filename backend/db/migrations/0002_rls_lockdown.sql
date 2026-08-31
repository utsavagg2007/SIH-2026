-- Row Level Security: deny by default.
--
-- Supabase publishes every table in the `public` schema through PostgREST, and
-- that API is reachable with the project's anon key - a key that ships in the
-- frontend bundle and is not a secret. With RLS disabled, `GET /rest/v1/alerts`
-- returns the entire alert corpus to anyone holding it: every internal IP the
-- enclave has ever seen, every JA3 fingerprint, every incident narrative. For a
-- monitoring system whose whole architectural argument is that it cannot be
-- pivoted through, that is the wrong default to leave in place.
--
-- 0001 left RLS off and said so, on the reasoning that the prototype has no
-- auth layer and the service connects with the Postgres role directly. The
-- first half of that is true and the second half is exactly why enabling RLS
-- costs nothing here:
--
--   * the backend connects as the `postgres` role, which is the table owner and
--     BYPASSES RLS entirely - so nothing about the write path or the dashboard
--     changes;
--   * PostgREST connects as `anon`/`authenticated`, which are subject to RLS -
--     and with RLS enabled and no policy granting anything, they can read
--     nothing at all.
--
-- Enabling it with no policies is therefore the correct configuration for a
-- deployment where the only legitimate reader is the backend. When a real auth
-- layer arrives, add policies here rather than turning RLS back off.

ALTER TABLE alerts          ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents       ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;

-- FORCE applies RLS to the table owner too. Deliberately NOT used: the backend
-- connects as the owner and must keep full access. Recorded here so the
-- omission reads as a decision rather than an oversight.
--   ALTER TABLE alerts FORCE ROW LEVEL SECURITY;

-- Revoke the blanket grants Supabase creates for its API roles. RLS already
-- stops them, but a table with no grant cannot be reached even if a future
-- migration adds a permissive policy by accident.
REVOKE ALL ON alerts          FROM anon, authenticated;
REVOKE ALL ON incidents       FROM anon, authenticated;
REVOKE ALL ON incident_alerts FROM anon, authenticated;
REVOKE ALL ON host_summary    FROM anon, authenticated;
