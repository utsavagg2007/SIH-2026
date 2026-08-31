"""Keep the suite off the operator's real database.

``app/config.py`` resolves ``backend/.env`` by absolute path, so once someone
fills in real Supabase credentials the tests inherit them - and a suite that
silently starts writing to a live project is both slow and wrong: it fails when
the network is down, when the password rotates, or when a free-tier project is
paused, none of which is a defect in the code under test.

A real environment variable wins over the ``.env`` file in pydantic-settings, so
one line here pins every test back to the in-memory store. Tests that want the
Postgres path exercise it deliberately, without a server.
"""

import os

os.environ["STORAGE_BACKEND"] = "memory"
os.environ.pop("DATABASE_URL", None)
os.environ.pop("SUPABASE_PROJECT_REF", None)
os.environ.pop("SUPABASE_DB_PASSWORD", None)
