# R6 — bot / worker process split

**Status:** design draft — no implementation.

## The problem

Everything runs in one Python process:

- Telegram HTTP I/O (long-poll or webhooks).
- FastAPI server (webhooks from GitHub / generic).
- APScheduler (cron-driven agent runs).
- Claude SDK spawns + subprocess lifetime.
- All DB writes.

Consequences:

- **Deployment:** the host runs one `claude-telegram-bot` systemd
  unit. Scaling out = not possible; two units against one SQLite
  file would corrupt each other, and even with Postgres they'd
  fight over Telegram's long-poll (only one connection at a time
  per token).
- **Failure mode:** a stuck Claude subprocess starves the event
  loop. PTB handlers can't ACK Telegram, which retries, which
  makes it worse. Today `StopAwareUpdateProcessor` mitigates this
  via per-user locks (R1), but the event loop is still shared.
- **Upgrades:** restarting the bot kills in-flight Claude calls.
  R4 added graceful interrupt so users see a clean message, but
  zero-downtime upgrades remain impossible.

## Target topology

Two processes, sharing only a DB and a queue:

```
   Telegram/HTTP I/O                       Claude executor
   ────────────────────                    ──────────────────
   ┌──────────────────┐     NOTIFY        ┌─────────────────┐
   │   bot-service    │────────►   DB   ◄─│   bot-worker    │
   │                  │                    │                 │
   │  - PTB polling   │      SELECT ...    │  - pulls job    │
   │  - FastAPI       │    FOR UPDATE      │  - spawns       │
   │  - enqueue job   │◄──────────────────│    Claude SDK   │
   │  - deliver reply │                    │  - writes reply │
   └──────────────────┘                    └─────────────────┘
                                  Shared:
                                  - Postgres (jobs, audit, …)
                                  - APScheduler lives in one
```

The split is **I/O vs execution**, not "one process per concern".
All Telegram I/O stays in one service so PTB's long-poll stream
is not duplicated.

## What needs to change

### Job queue

Today `orchestrator.agentic_text` calls `run_command` inline. That
becomes:

```python
job_id = await jobs.enqueue(
    user_id=user_id,
    prompt=message_text,
    working_directory=current_dir,
    ...
)
# Send a placeholder reply with the job_id
# Keep progress_msg reference indexed by job_id so the worker
# can stream updates back
```

The worker process loops:

```python
async for job in jobs.claim_ready():
    async with jobs.lock(job.id):
        response = await claude.run_command(**job.params)
        await jobs.complete(job.id, response)
```

Postgres `SELECT ... FOR UPDATE SKIP LOCKED` is the canonical
implementation — no separate queue service needed. Use `LISTEN` /
`NOTIFY` for the wake-up signal.

### Progress streaming

The `on_stream` callback currently edits the progress message via
PTB's `edit_message_text`. After the split, the worker can't edit
Telegram messages directly — it writes progress rows to a
`job_progress` table; the bot service tails that table and edits
messages.

**Alternative:** worker pushes progress via a Redis pub/sub channel.
Adds a Redis dep but avoids the polling loop.

### Session state

`ClaudeSession` is per-user + per-directory. Today it lives in
`SessionManager` backed by SQLite (`SQLiteSessionStorage`). That
already works across processes — the worker just queries the same
DB. Nothing to change.

### Scheduler

APScheduler stays in the bot service (not the worker). The
scheduler enqueues jobs just like the bot service does on user
messages; the worker doesn't know the difference between a
user-originated and a scheduler-originated job.

### Graceful shutdown

Worker receives SIGTERM → stops claiming new jobs → lets the
current job finish → exits. Bot service receives SIGTERM → stops
polling Telegram → drains inflight edit/reply tasks → exits. The
R4 `interrupt_all_active_requests` helper stays in the worker for
the "shutdown while job is running" case.

## Why this has NOT shipped

- Requires Postgres (SQLite doesn't handle multi-writer well, and
  `SELECT ... FOR UPDATE` is a no-op in SQLite).
  → See `postgres-migration.md`.
- Requires Alembic (migrating the `jobs` table schema needs proper
  versioning).
  → See `alembic-migrations.md`.
- The current single-process setup handles the traffic volumes a
  Telegram bot realistically sees (double-digit requests/second
  even for a popular bot).
- Operationally, two services means two systemd units, shared
  config discipline, and a runbook for "which one is the leader"
  during upgrades — nontrivial cost.

## Progression

1. **Postgres.** (See `postgres-migration.md`.) Queue lives in
   the same DB as everything else, so Postgres is a prerequisite.
2. **Add a `jobs` table** with `claim_ready() / complete() /
   fail() / heartbeat()` methods. Keep the bot-service calling
   `run_command` inline while the worker does not yet exist —
   the jobs table becomes an audit trail and retry substrate.
3. **Extract a `bot_worker` CLI entry point** that runs the
   claim loop. Have both processes share the same source tree
   (one Python package, two entry points).
4. **Flip the bot service** to enqueue instead of run inline.
   Keep an `INLINE_WORKER=true` escape hatch for deployments
   that still want single-process.
5. **Remove the escape hatch** once the two-process model is
   battle-tested.

## Decision signals

Ship this when any of the following is true:

- One user's long Claude call visibly degrades other users'
  response time. Today R1 (per-user lock) prevents sequentially
  blocking other users, but the shared event loop can still
  thrash if concurrent Claude subprocesses saturate the host.
- Zero-downtime upgrades become a requirement (worker can be
  rolled first, then bot service).
- Operator wants active-active redundancy for the Telegram I/O
  side (run two bot services against one worker — only one
  actually wins the Telegram long-poll, the other is a hot
  spare).

## Scope boundary

This note does NOT cover:

- Multi-datacenter deployment.
- Geographically-distributed Telegram polling.
- User-defined worker pools (different workers for different
  classes of job, e.g. "big-context worker" vs "quick-reply
  worker").

Each of those is a separate design once the basic split ships.
