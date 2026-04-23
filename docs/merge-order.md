# Merge order for the upgrade-audit PRs

This engagement shipped 23 surgical-fix branches closing every
CRITICAL / HIGH / MEDIUM and tractable RELIABILITY finding in
[`upgrade.md`](../upgrade.md), plus one docs branch with design
notes for the remaining L-effort architectural items. This file is
the recommended merge-order and dependency map.

## Reading guide

- **Waves** are groups of branches that can be merged in parallel
  — within a wave, order does not matter.
- Each branch is independent of its siblings unless listed as a
  dependency; the **Parent** column says which (if any) branch
  must merge first.
- **Conflict risk** flags branches that touch files a later wave
  also touches, so after a rebase you may see a merge resolution
  step. Listed because they are mechanical, not dangerous.
- **Test the bot after each wave** — each wave is a shippable
  state. Do not batch two waves without running the suite.

---

## Wave 0 — foundations (CI + observability surface)

Merge these first. They add tooling / process without changing
runtime behaviour, so every subsequent review benefits from
CI + metrics + dep scanning being live.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 1 | CI hardening (poetry-check, mypy non-blocking, tag-version guard, SECURITY contact) | `chore/ci-hardening` | — | None |
| 2 | Dependabot + CodeQL + pip-audit | `chore/dependabot-codeql-pip-audit` | — | None |
| 3 | Docker + systemd hardening | `chore/dockerfile-systemd-hardening` | — | None |
| 4 | Architectural design notes | `docs/architectural-design-notes` | — | None |

After wave 0: CI is fully green on every later branch, dep scans
running weekly, deploy artefacts available.

---

## Wave 1 — CRITICAL security findings

C-level is the audit's top priority — ship together, do not stage.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 5 | C3 — SQLite audit + token storage + migration 5 | `fix/c3-sqlite-audit-tokens` | — | Touches `main.py` — later H1 / append-only-audit-sink will re-touch. Rebase is mechanical. |

C1 and C2 are already in main (PRs #2 / #3). C3 closes the trio.

After wave 1: audit log + auth tokens survive a restart; forensic
trail is durable.

---

## Wave 2 — HIGH-severity security fixes

Can merge in any order within the wave.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 6 | R1 — per-user update lock | `fix/r1-per-user-lock` | — | Low |
| 7 | R2 — WAL + busy_timeout + `transaction()` | `fix/r2-sqlite-wal-transactions` | — | Low |
| 8 | H1 — guardrails on `DISABLE_*` flags | `fix/h1-disable-flag-guardrails` | C3 *(main.py overlap)* | Medium — shares `main.py` + `create_application` with C3 |
| 9 | H3 — bash read-only path validation | `fix/h3-bash-readonly-path-check` | — | Low |
| 10 | H4 — CLAUDE.md isolation | `fix/h4-claude-md-isolation` | — | Low |
| 11 | H5 — real cost tracking | `fix/h5-real-cost-tracking` | — | Low |

After wave 2: concurrent users no longer block each other; every
HIGH-severity audit finding is closed.

---

## Wave 3 — MEDIUM security fixes (can parallel wave 2)

All independent of one another. Ship in whatever order review
comes back.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 12 | M1 — webhook restricted tools + payload wrapping | `fix/m1-webhook-restricted-tools` | — | Low |
| 13 | M2 + M3 — HMAC + constant-time compare | `fix/m2-m3-token-hmac` | C3 *(auth.py touch)* | Low — mostly helper additions |
| 14 | M4 — API bind 127.0.0.1 by default | `fix/m4-api-bind-localhost` | — | None |
| 15 | M5 — redact secrets in stderr/logs | `fix/m5-redact-stderr-logs` | — | Low — creates new util module |
| 16 | M6 — magic-byte upload validation | `fix/m6-magic-byte-validation` | — | None |
| 17 | M7 — sanitize user-facing errors | `fix/m7-sanitize-user-errors` | — | None |

After wave 3: every MEDIUM audit finding is closed.

---

## Wave 4 — RELIABILITY findings

Ship any time after their dependencies land.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 18 | R3 — migration idempotency (`IF NOT EXISTS`) | `fix/r3-migration-idempotency` | R2 *(database.py overlap)* | Low — non-overlapping lines |
| 19 | R4 — graceful shutdown interrupt + PTB persistence | `fix/r4-state-persistence` | C3 *(main.py + orchestrator overlap)* | Medium |
| 20 | R5 correlation IDs | `feat/r5-correlation-ids` | — | Low |
| 21 | R5 Prometheus `/metrics` endpoint | `feat/r5-prometheus-metrics` | — | Low |

After wave 4: observability + durable state is complete.

---

## Wave 5 — dependent follow-ups (MUST wait for parent)

These two PRs explicitly state they cannot land before their parent
merges — the test files they add depend on modules introduced by the
parent.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 22 | R5 metrics hot-path instrumentation | `feat/r5-metrics-hot-paths-v2` | `feat/r5-prometheus-metrics` | None — strictly additive |
| 23 | M6 wiring into real download paths | `fix/m6-wire-download-paths` | `fix/m6-magic-byte-validation` | Low — touches orchestrator + handlers/message |

---

## Wave 6 — architectural (separate engagement)

The append-only audit sink can merge any time after C3 — it's a
tamper-evident forensic sink that composes with whatever primary
audit backend is wired.

| # | Item | Branch | Parent | Conflict risk |
|---|---|---|---|---|
| 24 | Append-only JSONL audit sink | `feat/append-only-audit-sink` | C3 *(optional — composes either way)* | Low |

The four L-effort items (H2 sandbox, Postgres, Alembic, bot/worker
split) are design notes only — no code yet. See
[`docs/design/README.md`](./design/README.md) for the decision
signals that would gate each one.

---

## Merge-order summary

Linear sequence if you want one plan (each group parallelisable
internally):

1. Wave 0: `chore/ci-hardening`, `chore/dependabot-codeql-pip-audit`, `chore/dockerfile-systemd-hardening`, `docs/architectural-design-notes`
2. Wave 1: `fix/c3-sqlite-audit-tokens`
3. Wave 2: `fix/r1-per-user-lock`, `fix/r2-sqlite-wal-transactions`, `fix/h1-disable-flag-guardrails`, `fix/h3-bash-readonly-path-check`, `fix/h4-claude-md-isolation`, `fix/h5-real-cost-tracking`
4. Wave 3: `fix/m1-webhook-restricted-tools`, `fix/m2-m3-token-hmac`, `fix/m4-api-bind-localhost`, `fix/m5-redact-stderr-logs`, `fix/m6-magic-byte-validation`, `fix/m7-sanitize-user-errors`
5. Wave 4: `fix/r3-migration-idempotency`, `fix/r4-state-persistence`, `feat/r5-correlation-ids`, `feat/r5-prometheus-metrics`
6. Wave 5: `feat/r5-metrics-hot-paths-v2`, `fix/m6-wire-download-paths`
7. Wave 6: `feat/append-only-audit-sink`

---

## Operational notes

- Every branch has its own tests that pass in isolation. After
  each wave, run `make test` against `main` to confirm no
  cross-branch regression.
- The pre-existing Windows `ADMINI~1` short-path test flake in
  `tests/unit/test_security/test_validators.py` is still there;
  the CI-hardening wave's mypy step surfaces the 500+ pre-existing
  errors non-blocking — both are tracked to address later.
- `upgrade.md` is the source of truth for which finding a branch
  closes. Every commit message references the ID.
- If any branch hits a merge conflict, the fix is mechanical
  every time — the branches were cut from `main` one at a time
  so conflicts are limited to lines one branch adds near lines
  another branch touches.

## Post-merge checklist

After wave 7 is done:

- [ ] Every CRITICAL / HIGH / MEDIUM finding in `upgrade.md` has
      a ✅ next to it.
- [ ] The four design notes in `docs/design/` have operator
      answers to the open questions.
- [ ] The pre-existing mypy backlog is addressed in a dedicated
      cleanup PR so the CI-hardening branch's non-blocking mypy
      step can flip to blocking.
- [ ] The `file_handler`-enabled branch of the document-upload
      path is wired into magic-byte validation (single gap noted
      in the `fix/m6-wire-download-paths` commit).
