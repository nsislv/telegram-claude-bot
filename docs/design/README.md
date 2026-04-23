# Design notes

Longer-form notes for architectural changes that don't fit in a
commit message. These are **working drafts** — honest about what we
don't know yet, describing the problem space and options rather than
committing to a specific implementation plan before the operator
requirements are clear.

When a design note graduates into implementation, the PR commit
message should link back to it so the reasoning is preserved.

Current notes:

- [h2-per-user-sandbox.md](./h2-per-user-sandbox.md) — H2 from
  `upgrade.md`. Per-user filesystem isolation inside
  `APPROVED_DIRECTORY`.
- [postgres-migration.md](./postgres-migration.md) — SQLite →
  Postgres migration path.
- [alembic-migrations.md](./alembic-migrations.md) — Replacing the
  hand-rolled migration runner with Alembic.
- [bot-worker-split.md](./bot-worker-split.md) — R6 from
  `upgrade.md`. Splitting the single-process bot into a Telegram
  I/O service + a Claude execution worker.

None of these are scheduled — the current audit/security layer has
not yet pushed the bot off the "single-operator, single-host" baseline
those changes target. Revisit when the deployment model changes.
