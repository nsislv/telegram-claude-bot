# Alembic migrations

**Status:** design draft — no implementation.

## The problem

`src/storage/database.py` uses a hand-rolled migration runner
(`DatabaseManager._run_migrations` + the `_get_migrations()` list of
`(version, sql)` tuples). It works, but has known rough edges:

- Every migration is a `.executescript()` call — any error
  mid-migration leaves the DB in an inconsistent state because
  `executescript` does not run in a transaction.
- There are no `down` migrations. Rollback = restore from backup.
- Migration numbers are integers assigned by whoever opens the PR
  first; branching teams would hit the same number collision we
  avoided only because there is one contributor.
- Every migration lives in `database.py` as a triple-quoted
  string. No tooling to generate scaffolds; diffs are hard to
  review because they're embedded in a list.

Alembic exists specifically for this problem. The project already
uses SQLAlchemy-adjacent types indirectly via aiosqlite.

## What Alembic buys us

- `alembic revision --autogenerate` diffs the ORM models against
  the live DB schema and produces a migration file. We don't use
  SQLAlchemy models today — that's fine, autogeneration is
  optional. Hand-written migrations are still the norm for
  non-trivial schema changes.
- Versioning by opaque 12-char slug, not integer. No collisions.
- Each migration has `upgrade()` and `downgrade()` functions in a
  proper Python module. Reviewable, testable, mockable.
- `alembic upgrade head` / `alembic downgrade -1` is a known
  command every DBA already recognises.
- Works identically on SQLite and Postgres — critical for the
  `postgres-migration.md` roadmap.

## Migration path (no pun intended)

### Phase 1 — shipped already

- `IF NOT EXISTS` on every DDL in the initial schema (R3).
- WAL + `busy_timeout` + `transaction()` context manager (R2).

### Phase 2 — introduce Alembic alongside

1. Add `alembic` as a dependency.
2. Create `alembic/env.py` that reads the async DB URL from
   `Settings.database_url`, supports both aiosqlite and asyncpg.
3. Create `alembic/versions/0000_baseline.py` — an empty upgrade
   + empty downgrade. This file exists only so Alembic has a
   revision to stamp existing DBs against.
4. Modify `_run_migrations()`:
   - Check if the `alembic_version` table exists.
   - If yes, skip hand-rolled migrations and call
     `alembic upgrade head` (via `command.upgrade`).
   - If no, run the hand-rolled migrations as before AND THEN
     stamp the DB to `0000_baseline` so subsequent runs use
     Alembic.
5. Every new migration after that point goes into
   `alembic/versions/` with a sequential slug.

### Phase 3 — migrate existing migrations over

Convert each entry in `_get_migrations()` to an Alembic revision,
preserving the effective schema:

```
alembic/versions/
    0001_initial_schema.py        # was migration 1
    0002_analytics_views.py       # was migration 2
    0003_agentic_tables.py        # was migration 3 (minus PRAGMA WAL, obsolete per R2)
    0004_project_threads.py       # was migration 4
    0005_audit_log_drop_user_fk.py  # was migration 5 (C3)
```

Then delete `_get_migrations()`. This is the "cutover" PR — large
but mechanical.

### Phase 4 — use Alembic features

`op.batch_alter_table(...)` cleanly handles SQLite's "can't alter
constraints" limitation (the technique migration 5 used manually).
Mark `include_object` hooks to ignore tables we don't manage (e.g.
if Postgres adds extensions with their own tables).

## Tests

Alembic migrations are straightforward to test:

- Apply the full head on an empty DB, compare to a checked-in
  schema snapshot (`sqlite3 db .schema` dump).
- Apply head, then `alembic downgrade base`, assert the schema
  matches empty.
- For each revision: apply up to its parent, run a data fixture,
  apply the revision, assert the data still reads correctly.

## Why this has NOT shipped

- Adding Alembic is a ~500-line diff (env.py, version files,
  migration-runner rewrite, test harness). Larger than any
  single audit finding in `upgrade.md`.
- The hand-rolled runner, while ugly, works and is now
  idempotent (R3) and transaction-aware (R2).
- The biggest benefit — Postgres compatibility — only pays off
  when Postgres ships too. See `postgres-migration.md`.

## Decision signals

Ship this when any of the following is true:

- Second contributor starts writing migrations and we hit a
  version-number collision.
- Postgres migration work begins — Alembic is a prerequisite.
- A migration needs to be rolled back in production (right now
  rollback = restore from backup).

## Scope boundary

This note does NOT cover:

- Data-only migrations (e.g. "rehash every token with HMAC" for
  the M3 fix — handled as a one-shot script today).
- Zero-downtime migrations (add-column-not-null requires a
  multi-step: add-nullable, backfill, flip-to-not-null; Alembic
  makes this easier but doesn't automate it).
