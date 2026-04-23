# H2 — per-user filesystem sandbox

**Status:** design draft — no implementation.

## The problem

`APPROVED_DIRECTORY` is shared across every authenticated user. Any
user who can reach the Claude tool surface (Bash, Write, Edit, Read)
can:

1. Read files belonging to any other user's working copy in the
   shared tree.
2. Plant content (`CLAUDE.md`, a malicious script, a recorded-command
   payload) that another user's future Claude session will pick up.
3. Modify files another user just wrote between their edits — race
   condition on a shared filesystem.

`upgrade.md` calls this out as a HIGH-severity chain with H4
(CLAUDE.md injection — closed by `fix/h4-claude-md-isolation`) and
M1 (webhook prompt injection — closed by
`fix/m1-webhook-restricted-tools`). Those two plug the cross-user
prompt-injection delivery path; H2 is about isolating the file
*substrate* those attacks land on.

## What the current design gets right

- Every tool call passes through `check_bash_directory_boundary` /
  `SecurityValidator.validate_path`, which refuses any path resolving
  outside `APPROVED_DIRECTORY`.
- `H3` (shipped) extends path validation to read-only commands too, so
  `cat ~/.ssh/id_rsa` is blocked even though it's read-only.

So the sandbox problem is specifically **within** `APPROVED_DIRECTORY`
— a legitimately-bounded user should not be able to reach another
legitimately-bounded user's subtree.

## Design options

### Option A — per-user subdirectory + a path-level invariant

Introduce a convention: every user gets `APPROVED_DIRECTORY/<user_id>/`
as their effective root. Every path-validation check compares to that
subtree instead of the full approved directory.

**Pros:**
- Zero new OS-level machinery. Works on every platform, every host.
- Compatible with the existing `validate_path` flow — it's a
  one-line change: `approved_directory / str(user_id)` instead of
  `approved_directory`.

**Cons:**
- Still runs as the same OS user. A Bash tool call that escapes path
  validation (via a bug we haven't found) has full access to the
  whole tree.
- Users with legitimate shared-project needs (a team collaborating
  on one repo) are worse off.
- Does not protect against the `/tmp` escape hatch — Bash can still
  `cd /tmp && curl`, which `H3` only flags if the path is named.

### Option B — per-user OS user + POSIX ACLs

Run Claude as a different Unix user for each authenticated Telegram
user. Each user's subdirectory is owned 700 by that Unix user. The
bot uses `setreuid` (or invokes `sudo -u` / systemd
`DynamicUser=yes`) before spawning the Claude subprocess.

**Pros:**
- Hard kernel-enforced isolation. Even a Bash escape cannot read
  another user's files without CAP_DAC_OVERRIDE.
- Maps cleanly to `getpwuid` / `chown` primitives operators already
  understand.

**Cons:**
- Requires root privileges at bot startup to manage Unix users and
  permission bits — contradicts the non-root container direction.
- Operators without root (shared hosting, PaaS) cannot adopt.
- Managing the user pool (create / delete / quota) becomes a
  separate admin surface.

### Option C — Linux namespace / bubblewrap sandbox

Each Claude subprocess runs inside a mount namespace where
`APPROVED_DIRECTORY/<user_id>/` is bind-mounted over
`APPROVED_DIRECTORY`, and everything else (except `/tmp`, `/dev/null`,
etc.) is read-only or inaccessible. `bubblewrap`, `firejail`, or
raw `unshare(CLONE_NEWNS)` via `runc` all deliver this.

**Pros:**
- Strong isolation + no shared-filesystem race.
- No need for root: `bwrap` runs as the bot user and uses user
  namespaces.
- Per-session teardown is automatic (the namespace disappears when
  the subprocess exits).

**Cons:**
- Linux-only. macOS / Windows operators get no benefit (though most
  prod deployments run Linux anyway).
- Requires `bwrap` installed and kernel support for user namespaces
  (disabled by default on RHEL < 9 and many hardened kernels).
- Adds a sandbox-management layer to the Claude spawn path that has
  its own failure modes.

### Option D — OS-level container per session (gVisor / firecracker)

Full VM-grade isolation. Each Claude call spins up a micro-VM with
only the user's subtree mounted in.

**Pros:**
- Kernel-level isolation including syscall attack surface.
- Effectively the same model as Anthropic's own hosted Code
  Interpreter.

**Cons:**
- Startup latency measured in hundreds of ms. Changes the UX of
  every `/new` session.
- Very operator-heavy: needs a container runtime, image pipeline,
  teardown GC, network namespace plumbing.

## Recommended progression

Layered adoption — each layer is independently useful:

1. **Ship Option A** (per-user subdirectory). Small change,
   universally applicable, measurably reduces blast radius even on
   Windows / macOS dev machines. Primary benefit: H4 / M1
   prompt-injection payloads are contained to the attacking user's
   own subtree.

2. **Document Option C** for Linux production operators as a
   separately-enabled hardening step (`CLAUDE_SANDBOX=bwrap`). The
   wrapper lives alongside the existing `ClaudeSDKManager.execute_command`
   — a command-line prefix (`bwrap --ro-bind / / --bind …/<user_id>/
   …`) rather than a rewrite.

3. **Defer Option B / D** unless the bot gains non-trusted-operator
   multi-tenancy. The operational cost is not worth it for the
   current single-operator-per-host deployment model.

## Open questions for whoever picks this up

- Is the deployment a single-operator machine (low priority) or
  multi-tenant (high priority)? The current audit (upgrade.md §7)
  says single-operator, but the allow-list of users in
  `ALLOWED_USERS` implies the operator expects isolation between
  those users. **Pin this with the operator before writing code.**
- What is the migration plan for existing installations where
  `APPROVED_DIRECTORY` already contains a shared tree? Option A
  breaks them (existing paths no longer resolve from the new
  per-user root). Are they moved, symlinked, or left alone with a
  migration-mode flag?
- How do project threads (`ENABLE_PROJECT_THREADS`) interact with
  per-user subdirectories? A project is currently global; a
  per-user variant would need a project × user matrix.

## Scope boundary

This note does NOT cover:

- `/tmp` isolation (requires full mount-namespace sandbox).
- Network isolation for Bash tool calls.
- Resource limits (CPU / RAM / disk quota per user).

Each of those is its own design note.
