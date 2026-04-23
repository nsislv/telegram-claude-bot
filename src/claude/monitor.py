"""Bash directory boundary enforcement for Claude tool calls.

String-parsing a bash command to decide whether it stays inside a
directory is fundamentally a losing game against a motivated
attacker — the OS-level sandbox is the real boundary. This module
is a best-effort first line of defence that catches the common
exfil / escape shapes before they reach the subprocess.

The review on H3 called out gaps in the original implementation —
notably missing path-reading commands (``grep``, ``awk``, ``xxd``,
``md5sum`` …), the ``env cat /etc/shadow`` re-dispatch bypass, and
redirect / substitution / glob evasion techniques. The current
implementation closes those.
"""

import re
import shlex
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

# Subdirectories under ~/.claude/ that Claude Code uses internally.
_CLAUDE_INTERNAL_SUBDIRS: Set[str] = {"plans", "todos", "settings.json"}

# Commands that modify the filesystem or change context and should have paths checked
_FS_MODIFYING_COMMANDS: Set[str] = {
    "mkdir",
    "touch",
    "cp",
    "mv",
    "rm",
    "rmdir",
    "ln",
    "install",
    "tee",
    "cd",
}

# Read-only commands that take NO filesystem paths at all — safe to
# skip path validation entirely. Kept deliberately small:
#
# - ``echo`` / ``printf`` print literals.
# - ``pwd`` / ``whoami`` / ``date`` return process state.
# - ``which`` resolves command names (emits paths but does not read
#   file *contents*).
# - ``dirname`` / ``basename`` are pure string ops on path-like
#   arguments, not file accesses.
#
# ``env`` / ``printenv`` are **explicitly NOT** in this set — see
# ``_SPECIAL_WRAPPER_COMMANDS`` below for the re-dispatch rationale.
_NO_PATH_COMMANDS: Set[str] = {
    "whoami",
    "pwd",
    "echo",
    "printf",
    "date",
    "which",
    "dirname",
    "basename",
}

# Read-only commands that DO take filesystem paths and must have
# those paths validated. Reads outside ``APPROVED_DIRECTORY`` are
# still disclosure even without mutation.
#
# Covers the obvious readers (``cat``, ``ls``, ``head`` …) plus the
# "content-revealing" classes flagged in review:
#
# - ``grep`` family — content search = content disclosure.
# - ``awk`` / ``sed`` — read files as positional args.
# - ``xxd`` / ``hexdump`` / ``od`` / ``strings`` — binary readers.
# - ``md5sum`` / ``sha*sum`` / ``cksum`` — hashes reveal
#   file equality.
# - Compressed readers — ``zcat``, ``bzcat``, ``xzcat``, ``zgrep``,
#   ``bzgrep``, ``xzgrep``.
# - Filter / transform readers — ``tac``, ``rev``, ``nl``, ``cut``,
#   ``paste``, ``fold``, ``column``, ``expand``, ``unexpand``.
# - Path probes — ``readlink``, ``namei``, ``getfacl``, ``lsattr``.
_READ_WITH_PATHS_COMMANDS: Set[str] = {
    "cat",
    "ls",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "sort",
    "uniq",
    "diff",
    "file",
    "stat",
    "du",
    "df",
    "tree",
    "realpath",
    # grep family
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "zgrep",
    "bzgrep",
    "xzgrep",
    # stream editors / readers
    "awk",
    "sed",
    # binary / encoding readers
    "xxd",
    "hexdump",
    "od",
    "strings",
    # hashers
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "cksum",
    "b2sum",
    # filter / transform
    "tac",
    "rev",
    "nl",
    "cut",
    "paste",
    "fold",
    "column",
    "expand",
    "unexpand",
    # compressed readers
    "zcat",
    "bzcat",
    "xzcat",
    "lzcat",
    # path probes
    "readlink",
    "namei",
    "getfacl",
    "lsattr",
    # env (with args) gets caught by _SPECIAL_WRAPPER_COMMANDS
    # handling below, not here — see _resolve_effective_command.
    # printenv with a name arg only emits an env value, not a
    # file read, but it does leak configured secrets.
    "printenv",
}

# Commands that *wrap* another command (``env`` is the classic
# example — ``env VAR=x cat /etc/shadow`` runs ``cat`` with a
# modified environment). Naive base-command matching would let
# ``env cat /etc/shadow`` through because ``env`` looks like a
# no-path command. ``_resolve_effective_command`` skips over
# variable assignments and flags to find the real command, and
# we dispatch on that.
_SPECIAL_WRAPPER_COMMANDS: Set[str] = {
    "env",
    "nice",
    "nohup",
    "sudo",
    "doas",
    "time",
    "timeout",
    "ionice",
    "chrt",
    "stdbuf",
    "unbuffer",
    "xargs",  # ``xargs -I{} cat {}`` reads files listed on stdin
}

# Flag patterns for common wrapper commands. ``env -u VAR`` takes a
# value flag; most wrappers have short-option value flags. Be
# permissive — the worst case is we skip over an arg that happened
# to be a path (pedantic-false-negative), which is safer than
# mistaking a flag-value for a path (false-positive stack).
_WRAPPER_FLAGS_TAKING_VALUE: Set[str] = {
    "-u",  # env -u VAR
    "-S",  # env -S "..."
    "-C",  # env -C DIR, timeout -C ...
    "-k",  # timeout -k SECS
    "-n",  # nohup/nice
    "-I",  # xargs -I REPLACE
    "-L",  # xargs -L MAX
    "-P",  # xargs -P N
    "--user",
    "--preserve-env",
}

# Actions / expressions that make ``find`` a filesystem-modifying command
_FIND_MUTATING_ACTIONS: Set[str] = {"-delete", "-exec", "-execdir", "-ok", "-okdir"}

# Bash command separators
_COMMAND_SEPARATORS: Set[str] = {"&&", "||", ";", "|", "&"}

# Redirect operators that bash interprets specially — if any of these
# appear on a command line, the file *next to them* is either read or
# written. A read-oriented no-path command (``echo < /etc/shadow``)
# still triggers a filesystem read via the redirect; we can't let it
# short-circuit on the command name alone.
_REDIRECT_OPERATORS: Set[str] = {
    "<",
    ">",
    "<<",
    ">>",
    "<<<",
    "<>",
    "&>",
    "&>>",
}

# Characters / substrings in a token that indicate bash will do
# something at runtime we cannot statically analyse. Presence of any
# of these in a path-handler command's argv disqualifies static
# resolution and forces a fail-closed rejection.
_RUNTIME_EXPANSION_MARKERS: Tuple[str, ...] = (
    "$(",  # command substitution
    "${",  # parameter / brace expansion
    "$",  # catches ``$VAR`` too
    "`",  # legacy command substitution
    "<(",  # process substitution
    ">(",  # process substitution
)
# Unquoted glob chars. ``re`` used so we don't false-positive on
# ``?`` inside a paragraph-of-text literal — require the glob char
# to be at a word boundary.
_UNQUOTED_GLOB_RE = re.compile(r"(?:^|[^\\])([*?\[])")


def check_bash_directory_boundary(
    command: str,
    working_directory: Path,
    approved_directory: Path,
) -> Tuple[bool, Optional[str]]:
    """Check if a bash command's paths stay within the approved directory.

    Returns ``(True, None)`` to allow, ``(False, message)`` to deny.

    Denial reasons (all reviewer-identified exfil paths now closed):

    - Any path argument to a filesystem-modifying, path-reading, or
      ``find``-with-mutating-action command resolves outside the
      approved tree.
    - A redirect operator (``<``, ``>``, etc.) appears anywhere in
      the chain — its target is a filesystem access that cannot be
      validated statically. Fail closed.
    - A path-handler argv contains runtime expansions (``$(...)``,
      ``${VAR}``, backticks, process substitution) — bash would
      evaluate these at run time and we can't see the result.
    - A path-handler argv contains an unquoted glob (``*``, ``?``,
      ``[...]``) — the expanded list could include anything bash
      can see.
    - A path-handler's path argument cannot be resolved — fail
      closed for path-handlers (pre-review the bare ``except`` here
      silently permitted, which was a real bypass).
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unparseable (unclosed quote, etc.) — pass through and let
        # the OS sandbox catch it. Static analysis on malformed input
        # is a losing game.
        return True, None

    if not tokens:
        return True, None

    # Chain on separators AND redirect operators so the check can see
    # the target of a redirect independently of the command that
    # produced it. Redirects are recorded so we can fail closed on
    # them (step 3 below).
    command_chains: List[List[str]] = []
    current_chain: List[str] = []
    redirects_seen = False

    for token in tokens:
        if token in _COMMAND_SEPARATORS:
            if current_chain:
                command_chains.append(current_chain)
            current_chain = []
        elif token in _REDIRECT_OPERATORS:
            redirects_seen = True
            if current_chain:
                command_chains.append(current_chain)
            current_chain = []
        else:
            current_chain.append(token)

    if current_chain:
        command_chains.append(current_chain)

    # A redirect operator anywhere in the line means bash is doing a
    # filesystem access we cannot associate with a specific command.
    # Fail closed — the OS sandbox is still the final check, but we
    # won't allow something that bypasses the static check entirely.
    if redirects_seen:
        return False, (
            "Directory boundary violation: redirect operator (<, >, etc.) "
            "in command cannot be statically validated — refuse."
        )

    resolved_approved = approved_directory.resolve()

    for cmd_tokens in command_chains:
        if not cmd_tokens:
            continue

        # Strip wrappers like ``env`` / ``sudo`` / ``nohup`` so
        # ``env cat /etc/shadow`` is dispatched as ``cat`` with the
        # path argv, not as ``env`` with no check.
        effective_tokens = _resolve_effective_command(cmd_tokens)
        if not effective_tokens:
            # The whole chunk was wrappers / flags with no effective
            # command — allow. Reachable for e.g. ``env -u FOO``.
            continue

        base_command = Path(effective_tokens[0]).name

        # True no-path command (pwd, whoami, echo, …). Safe because
        # we've already rejected redirects up-front and ruled out the
        # ``env cat /etc/shadow`` re-dispatch bypass.
        if base_command in _NO_PATH_COMMANDS:
            continue

        # Decide whether the command needs path validation.
        needs_check = False
        is_find = base_command == "find"
        if is_find:
            needs_check = any(t in _FIND_MUTATING_ACTIONS for t in effective_tokens[1:])
        elif base_command in _FS_MODIFYING_COMMANDS:
            needs_check = True
        elif base_command in _READ_WITH_PATHS_COMMANDS:
            needs_check = True

        if not needs_check:
            continue

        # Which tokens need the full expansion / glob / path checks.
        # For ``find`` we only validate the search-root argument
        # (the first non-flag after the command name); later tokens
        # are ``-name '*.log'`` style expressions where globs and
        # metacharacters are legitimate.
        if is_find:
            args_to_check = _find_search_roots(effective_tokens[1:])
        else:
            args_to_check = effective_tokens[1:]

        # Pre-check for bash metacharacters we can't statically
        # evaluate. Separate from the redirect check because
        # redirects are chain-level and these are token-level.
        for token in args_to_check:
            if _has_runtime_expansion(token):
                return False, (
                    f"Directory boundary violation: '{base_command}' "
                    f"argument '{token}' contains a runtime expansion "
                    f"(command substitution, variable expansion, or "
                    f"process substitution) that cannot be statically "
                    f"validated."
                )
            if _has_unquoted_glob(token):
                return False, (
                    f"Directory boundary violation: '{base_command}' "
                    f"argument '{token}' contains an unquoted glob; "
                    f"refuse because the expansion is not "
                    f"statically knowable."
                )

        # Finally, validate every path argument.
        for token in args_to_check:
            if token.startswith("-"):
                continue

            try:
                if token.startswith("/"):
                    resolved = Path(token).resolve()
                else:
                    resolved = (working_directory / token).resolve()
            except (ValueError, OSError):
                # Pre-review this block silently skipped the token,
                # which was a bypass: an attacker-crafted token that
                # raised during resolution slipped past the check.
                # For a path-handler command, fail closed.
                return False, (
                    f"Directory boundary violation: '{base_command}' "
                    f"argument '{token}' could not be resolved to a "
                    f"concrete path — refusing statically."
                )

            if not _is_within_directory(resolved, resolved_approved):
                return False, (
                    f"Directory boundary violation: '{base_command}' targets "
                    f"'{token}' which is outside approved directory "
                    f"'{resolved_approved}'"
                )

    return True, None


def _find_search_roots(tokens: List[str]) -> List[str]:
    """Return the path-like leading tokens of a ``find`` invocation.

    ``find`` accepts one or more search roots before the first
    expression flag (``-name``, ``-type``, …). Everything after
    the first flag is an expression and must NOT be treated as a
    path for validation.
    """
    roots: List[str] = []
    for tok in tokens:
        if tok.startswith("-"):
            break
        roots.append(tok)
    return roots


def _resolve_effective_command(tokens: List[str]) -> List[str]:
    """Strip wrapper commands + their flags / VAR=value assignments.

    ``env VAR=x FOO=y cat /etc/shadow`` → ``['cat', '/etc/shadow']``.
    ``sudo -u bob cat /etc/shadow`` → ``['cat', '/etc/shadow']``.
    ``env -u FOO`` (no real command) → ``[]``.

    Iterative rather than recursive — an attacker chaining wrappers
    (``sudo env nohup cat …``) gets every layer stripped.
    """
    remaining = list(tokens)

    while remaining:
        first = Path(remaining[0]).name
        if first not in _SPECIAL_WRAPPER_COMMANDS:
            return remaining

        # Step past the wrapper itself, then skip any leading
        # VAR=value assignments and flags (including flag-value
        # pairs for known value-taking flags).
        remaining = remaining[1:]
        advanced = True
        while advanced and remaining:
            advanced = False
            tok = remaining[0]
            # ``VAR=value`` style assignment (only valid directly
            # after the wrapper).
            if _looks_like_assignment(tok):
                remaining = remaining[1:]
                advanced = True
                continue
            # Flags.
            if tok.startswith("-"):
                # Known value-taking flags eat the next token.
                if tok in _WRAPPER_FLAGS_TAKING_VALUE and len(remaining) > 1:
                    remaining = remaining[2:]
                else:
                    remaining = remaining[1:]
                advanced = True
                continue

    return remaining


def _looks_like_assignment(token: str) -> bool:
    """Return True if ``token`` is ``NAME=value`` as bash would see it.

    Conservative — requires the key to be a valid shell identifier
    (letters/digits/underscore, not starting with a digit) so a URL
    (``https://x.com/a=b``) isn't mistaken for an assignment.
    """
    if "=" not in token:
        return False
    key, _, _ = token.partition("=")
    if not key:
        return False
    if not (key[0].isalpha() or key[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in key)


def _has_runtime_expansion(token: str) -> bool:
    """Return True if the token contains bash syntax we can't
    statically resolve (``$(...)``, ``${VAR}``, backticks, process
    substitution). See ``_RUNTIME_EXPANSION_MARKERS``.
    """
    return any(marker in token for marker in _RUNTIME_EXPANSION_MARKERS)


def _has_unquoted_glob(token: str) -> bool:
    """Return True if the token contains a glob metacharacter that
    bash would expand at run time.

    ``shlex.split`` already stripped surrounding quotes, so anything
    that survived is either unquoted or inside the body of a
    concatenated string. Either way, bash will treat it as a glob.
    """
    return _UNQUOTED_GLOB_RE.search(token) is not None


def _is_claude_internal_path(file_path: str) -> bool:
    """Check whether *file_path* points inside ``~/.claude/`` (allowed subdirs only)."""
    try:
        resolved = Path(file_path).resolve()
        home = Path.home().resolve()
        claude_dir = home / ".claude"

        # Path must be inside ~/.claude/
        try:
            rel = resolved.relative_to(claude_dir)
        except ValueError:
            return False

        # Must be in one of the known subdirectories (or a known file)
        top_part = rel.parts[0] if rel.parts else ""
        return top_part in _CLAUDE_INTERNAL_SUBDIRS

    except Exception:
        return False


def _is_within_directory(path: Path, directory: Path) -> bool:
    """Check if path is within directory."""
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


__all__: Iterable[str] = (
    "check_bash_directory_boundary",
    "_is_claude_internal_path",
)
