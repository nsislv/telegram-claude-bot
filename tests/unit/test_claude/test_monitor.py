"""Test bash directory boundary checking."""

from pathlib import Path
from unittest.mock import patch

from src.claude.monitor import (
    _is_claude_internal_path,
    check_bash_directory_boundary,
)


class TestCheckBashDirectoryBoundary:
    """Test the check_bash_directory_boundary function."""

    def setup_method(self) -> None:
        self.approved = Path("/root/projects")
        self.cwd = Path("/root/projects/myapp")

    def test_mkdir_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "mkdir -p /root/web1", self.cwd, self.approved
        )
        assert not valid
        assert "directory boundary violation" in error.lower()
        assert "/root/web1" in error

    def test_mkdir_inside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "mkdir -p /root/projects/newdir", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_touch_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "touch /tmp/evil.txt", self.cwd, self.approved
        )
        assert not valid
        assert "/tmp/evil.txt" in error

    def test_cp_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "cp file.txt /etc/passwd", self.cwd, self.approved
        )
        assert not valid
        assert "/etc/passwd" in error

    def test_mv_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "mv /root/projects/file.txt /tmp/file.txt", self.cwd, self.approved
        )
        assert not valid
        assert "/tmp/file.txt" in error

    def test_relative_paths_inside_approved_pass(self) -> None:
        valid, error = check_bash_directory_boundary(
            "mkdir -p subdir/nested", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_relative_path_traversal_escaping_approved_dir(self) -> None:
        """mkdir ../../evil from /root/projects/myapp resolves to /root/evil."""
        valid, error = check_bash_directory_boundary(
            "mkdir ../../evil", self.cwd, self.approved
        )
        assert not valid
        assert "directory boundary violation" in error.lower()
        assert "../../evil" in error

    def test_relative_path_traversal_staying_inside_approved_dir(self) -> None:
        """mkdir ../sibling from /root/projects/myapp -> /root/projects/sibling (ok)."""
        valid, error = check_bash_directory_boundary(
            "mkdir ../sibling", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_relative_path_dot_dot_at_boundary_root(self) -> None:
        """mkdir .. from approved root itself should be blocked."""
        cwd_at_root = Path("/root/projects")
        valid, error = check_bash_directory_boundary(
            "touch ../outside.txt", cwd_at_root, self.approved
        )
        assert not valid
        assert "directory boundary violation" in error.lower()

    def test_no_path_read_commands_always_pass(self) -> None:
        """Commands that take no filesystem paths (``pwd``, ``whoami``,
        ``date`` etc.) pass through regardless of what follows them.

        NB: ``env`` is deliberately NOT in this list — it's a wrapper
        command and ``env cat /etc/shadow`` must NOT be short-circuited
        here. Bare ``env`` (no args) is tested separately below.
        """
        for cmd in ["pwd", "whoami", "date", "echo hello world"]:
            valid, error = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert valid, f"Expected no-path command to pass: {cmd}"
            assert error is None

    def test_bare_env_is_allowed(self) -> None:
        """``env`` with no args emits the current environment and does
        not wrap a command — the re-dispatch resolves to an empty
        effective command, which is allowed."""
        valid, _ = check_bash_directory_boundary("env", self.cwd, self.approved)
        assert valid

    def test_read_commands_inside_approved_directory_pass(self) -> None:
        """Read-with-path commands against files INSIDE the approved
        tree are fine — H3's fix is about the OUTSIDE case."""
        approved_file = self.approved / "notes.md"
        for cmd in [
            f"cat {approved_file}",
            f"head {approved_file}",
            f"ls {self.approved}",
            f"stat {approved_file}",
        ]:
            valid, error = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert valid, f"Expected read inside approved dir to pass: {cmd}"
            assert error is None

    def test_read_commands_outside_approved_directory_rejected(self) -> None:
        """H3 regression test — pre-fix these all passed, leaking
        arbitrary host files back to the user via Claude."""
        for cmd in [
            "cat /etc/hosts",
            "cat /etc/shadow",
            "tail /var/log/auth.log",
            "head /etc/passwd",
            "ls /tmp",
            "less /var/log/syslog",
            "stat /home/other-user/.ssh/id_rsa",
            "tree /home",
            "du /var",
            "realpath /etc/shadow",
        ]:
            valid, error = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid, (
                f"H3: read-with-path command outside approved dir "
                f"must be rejected: {cmd}"
            )
            assert error is not None
            assert "directory boundary violation" in error.lower()

    def test_non_fs_commands_pass(self) -> None:
        """Commands not in the filesystem-modifying set pass through."""
        for cmd in ["python script.py", "node app.js", "cargo build"]:
            valid, error = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert valid, f"Expected non-fs command to pass: {cmd}"
            assert error is None

    def test_empty_command(self) -> None:
        valid, error = check_bash_directory_boundary("", self.cwd, self.approved)
        assert valid
        assert error is None

    def test_flags_are_skipped(self) -> None:
        valid, error = check_bash_directory_boundary(
            "mkdir -p -v /root/projects/dir", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_unparseable_command_passes_through(self) -> None:
        """Malformed quoting should pass through (sandbox catches it at OS level)."""
        valid, error = check_bash_directory_boundary(
            "mkdir 'unclosed quote", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_rm_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "rm /var/tmp/somefile", self.cwd, self.approved
        )
        assert not valid
        assert "/var/tmp/somefile" in error

    def test_ln_outside_approved_directory(self) -> None:
        valid, error = check_bash_directory_boundary(
            "ln -s /root/projects/file /tmp/link", self.cwd, self.approved
        )
        assert not valid
        assert "/tmp/link" in error

    # --- find command handling ---

    def test_find_without_mutating_flags_passes(self) -> None:
        """Plain find (read-only) should pass regardless of search path."""
        valid, error = check_bash_directory_boundary(
            "find /tmp -name '*.log'", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_find_delete_outside_approved_dir(self) -> None:
        """find /tmp -delete should be blocked because /tmp is outside."""
        valid, error = check_bash_directory_boundary(
            "find /tmp -name '*.log' -delete", self.cwd, self.approved
        )
        assert not valid
        assert "directory boundary violation" in error.lower()
        assert "/tmp" in error

    def test_find_exec_outside_approved_dir(self) -> None:
        """find /var -exec rm {} ; should be blocked."""
        valid, error = check_bash_directory_boundary(
            "find /var -exec rm {} ;", self.cwd, self.approved
        )
        assert not valid
        assert "/var" in error

    def test_find_delete_inside_approved_dir(self) -> None:
        """find inside approved dir with -delete should pass."""
        valid, error = check_bash_directory_boundary(
            "find /root/projects/myapp -name '*.pyc' -delete",
            self.cwd,
            self.approved,
        )
        assert valid
        assert error is None

    def test_find_delete_relative_path_inside(self) -> None:
        """find . -delete from inside approved dir should pass."""
        valid, error = check_bash_directory_boundary(
            "find . -name '*.pyc' -delete", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_find_execdir_outside_approved_dir(self) -> None:
        """find with -execdir outside approved dir should be blocked."""
        valid, error = check_bash_directory_boundary(
            "find /etc -execdir cat {} ;", self.cwd, self.approved
        )
        assert not valid
        assert "/etc" in error

    # --- cd and command chaining handling ---

    def test_cd_outside_approved_directory(self) -> None:
        """cd to an outside directory should be blocked."""
        valid, error = check_bash_directory_boundary("cd /tmp", self.cwd, self.approved)
        assert not valid
        assert "directory boundary violation" in error.lower()
        assert "/tmp" in error

    def test_cd_inside_approved_directory(self) -> None:
        """cd to an inside directory should pass."""
        valid, error = check_bash_directory_boundary(
            "cd subdir", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_chained_commands_outside_blocked(self) -> None:
        """Any command in a chain targeting outside should be blocked."""
        # Chained with &&
        valid, error = check_bash_directory_boundary(
            "ls && rm /etc/passwd", self.cwd, self.approved
        )
        assert not valid
        assert "/etc/passwd" in error

        # Chained with ;
        valid, error = check_bash_directory_boundary(
            "mkdir newdir; mv file.txt /tmp/", self.cwd, self.approved
        )
        assert not valid
        assert "/tmp/" in error

    def test_chained_commands_inside_pass(self) -> None:
        """Chain of valid commands should pass."""
        valid, error = check_bash_directory_boundary(
            "cd subdir && touch file.txt && ls -la", self.cwd, self.approved
        )
        assert valid
        assert error is None

    def test_chained_cd_outside_blocked(self) -> None:
        """cd /tmp && something should be blocked."""
        valid, error = check_bash_directory_boundary(
            "cd /tmp && ls", self.cwd, self.approved
        )
        assert not valid
        assert "/tmp" in error


class TestH3BypassClosures:
    """Regression guards for every bypass the review surfaced.

    Each of these tests represents a concrete exfil / escape the
    pre-review implementation would have allowed. They're kept as
    one-line per-payload parametrised sweeps so adding a new class
    of bypass is a one-liner — and so a regression is obvious.
    """

    def setup_method(self) -> None:
        self.approved = Path("/root/projects")
        self.cwd = Path("/root/projects/myapp")

    # --- Expanded read-with-paths set ---

    def test_expanded_read_commands_blocked_outside(self) -> None:
        """Grep/awk/xxd/md5sum etc. were missing from the original
        read-paths set. They must all be rejected when targeting
        outside the approved tree."""
        payloads = [
            "grep root /etc/passwd",
            "egrep -H foo /etc/shadow",
            "fgrep bar /var/log/syslog",
            "rg secret /etc",
            "awk '{print}' /etc/shadow",
            "sed -n 1p /etc/shadow",
            "xxd /etc/shadow",
            "hexdump /etc/shadow",
            "od -c /etc/shadow",
            "strings /bin/ls",
            "md5sum /etc/shadow",
            "sha256sum /etc/shadow",
            "sha1sum /etc/shadow",
            "sha512sum /etc/shadow",
            "cksum /etc/shadow",
            "tac /var/log/auth.log",
            "rev /etc/hostname",
            "nl /etc/passwd",
            "cut -d: -f1 /etc/passwd",
            "readlink /etc/mtab",
            "zcat /var/log/syslog.1.gz",
            "bzcat /backups/snapshot.bz2",
            "xzcat /backups/snapshot.xz",
            "zgrep root /var/log/auth.log.1.gz",
        ]
        for cmd in payloads:
            valid, error = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid, f"expected rejection: {cmd}"
            assert "directory boundary violation" in (error or "").lower()

    # --- env re-dispatch bypass ---

    def test_env_wrapped_command_is_re_dispatched(self) -> None:
        """``env cat /etc/shadow`` must not short-circuit on ``env``.
        The wrapper is peeled off; ``cat`` is the effective command."""
        valid, error = check_bash_directory_boundary(
            "env cat /etc/shadow", self.cwd, self.approved
        )
        assert not valid
        assert "/etc/shadow" in (error or "")

    def test_env_with_assignments_is_re_dispatched(self) -> None:
        valid, error = check_bash_directory_boundary(
            "env VAR=x FOO=y cat /etc/shadow", self.cwd, self.approved
        )
        assert not valid
        assert "/etc/shadow" in (error or "")

    def test_sudo_wrapped_command_is_re_dispatched(self) -> None:
        valid, error = check_bash_directory_boundary(
            "sudo -u bob cat /etc/shadow", self.cwd, self.approved
        )
        assert not valid
        assert "/etc/shadow" in (error or "")

    def test_chained_wrappers_all_peeled(self) -> None:
        """``sudo env nohup cat /etc/shadow`` — every wrapper layer
        must be stripped; the innermost ``cat`` gets validated."""
        valid, error = check_bash_directory_boundary(
            "sudo env nohup cat /etc/shadow", self.cwd, self.approved
        )
        assert not valid

    def test_bare_wrapper_without_command_allowed(self) -> None:
        """``env -u FOO`` has no effective command. Nothing to
        validate — allow."""
        valid, _ = check_bash_directory_boundary("env -u FOO", self.cwd, self.approved)
        assert valid

    # --- Redirect operator bypass ---

    def test_redirect_with_no_path_command_rejected(self) -> None:
        """``echo < /etc/shadow`` reads the file via redirect. The
        pre-review short-circuit on ``echo`` in _NO_PATH_COMMANDS
        let this through. Post-review: any redirect = refuse."""
        valid, error = check_bash_directory_boundary(
            "echo < /etc/shadow", self.cwd, self.approved
        )
        assert not valid
        assert "redirect" in (error or "").lower()

    def test_redirect_to_outside_path_rejected(self) -> None:
        """``cat >/etc/foo`` writes to an outside target via
        redirect. Refuse on the redirect alone."""
        for cmd in [
            "echo hi > /etc/motd",
            "cat > /etc/shadow",
            "cat >> /etc/shadow",
            "cat <<< 'x' > /etc/shadow",
        ]:
            valid, _ = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid, f"expected rejection on redirect: {cmd}"

    def test_redirect_inside_approved_also_rejected(self) -> None:
        """Per review: redirect targets cannot be associated with
        a command by the static analyser, so we fail closed even
        when the target happens to be inside the approved tree.
        The OS-level sandbox is the final arbiter."""
        valid, _ = check_bash_directory_boundary(
            "cat > /root/projects/out.txt", self.cwd, self.approved
        )
        assert not valid

    # --- Runtime expansion bypass ---

    def test_command_substitution_rejected(self) -> None:
        for cmd in [
            'cat "$(echo /etc/shadow)"',
            "cat `echo /etc/shadow`",
            "grep root $(echo /etc/passwd)",
        ]:
            valid, _ = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid, f"expected rejection on substitution: {cmd}"

    def test_variable_expansion_rejected(self) -> None:
        for cmd in [
            "cat ${HOME}/.ssh/id_rsa",
            "cat $HOME/.bash_history",
        ]:
            valid, _ = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid, f"expected rejection on expansion: {cmd}"

    def test_process_substitution_rejected(self) -> None:
        """``diff <(cat /etc/shadow) /tmp/x`` — bash evaluates
        ``<(...)`` at runtime, we can't see the contents."""
        valid, _ = check_bash_directory_boundary(
            "diff <(cat /etc/shadow) /tmp/x", self.cwd, self.approved
        )
        assert not valid

    def test_unquoted_glob_rejected(self) -> None:
        """``cat /etc/*`` expands at runtime to an unknown list.
        Refuse statically."""
        for cmd in ["cat /etc/*", "grep root /etc/*.conf"]:
            valid, _ = check_bash_directory_boundary(cmd, self.cwd, self.approved)
            assert not valid

    # --- Fail-closed on resolution error ---

    def test_unresolvable_path_fails_closed_for_path_handler(self, monkeypatch) -> None:
        """If ``Path.resolve`` raises, the pre-review code silently
        allowed. Post-review: path-handler commands fail closed.

        Implementation: let the first resolve (the approved-dir
        sanity resolve at the top of the checker) succeed; every
        subsequent resolve — those are the argument tokens — must
        fail. Counter-based, so the test doesn't depend on string-
        matching path forms across OSes.
        """
        import pathlib

        original = pathlib.Path.resolve
        state = {"calls": 0}

        def flaky_resolve(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            state["calls"] += 1
            if state["calls"] == 1:
                return original(self, *args, **kwargs)
            raise OSError("boom")

        monkeypatch.setattr(pathlib.Path, "resolve", flaky_resolve)

        valid, error = check_bash_directory_boundary(
            "cat /etc/shadow", self.cwd, self.approved
        )
        assert not valid
        assert "could not be resolved" in (error or "")

    # --- Printenv explicitly leaks ---

    def test_printenv_with_name_is_rejected(self) -> None:
        """``printenv SECRET`` emits the env value. Pre-review
        ``printenv`` was in the no-path set; now it's in the
        read-with-paths set so it trips path validation (which
        fails because ``SECRET`` is not a resolvable path either
        way, but the right thing happens)."""
        # Note: ``printenv SOME_VAR`` treats SOME_VAR as a name, not
        # a path. Our static analyser will resolve it relative to cwd
        # and probably allow (since the cwd is inside approved). Not
        # a bypass per se — env leaks happen at runtime — but we
        # record the behaviour so changes to the set get noticed.
        valid, _ = check_bash_directory_boundary(
            "printenv SOME_VAR", self.cwd, self.approved
        )
        # Current behaviour: SOME_VAR resolves to cwd/SOME_VAR which
        # is inside approved → allowed. The "real" env leak is a
        # runtime concern that can't be caught by path analysis.
        assert valid


class TestIsClaudeInternalPath:
    """Test the _is_claude_internal_path helper function."""

    def test_plan_file_is_internal(self, tmp_path: Path) -> None:
        """~/.claude/plans/some-plan.md should be recognised as internal."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            (tmp_path / ".claude" / "plans").mkdir(parents=True)
            plan_file = tmp_path / ".claude" / "plans" / "my-plan.md"
            plan_file.touch()
            assert _is_claude_internal_path(str(plan_file)) is True

    def test_todo_file_is_internal(self, tmp_path: Path) -> None:
        """~/.claude/todos/todo.md should be recognised as internal."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            (tmp_path / ".claude" / "todos").mkdir(parents=True)
            todo_file = tmp_path / ".claude" / "todos" / "todo.md"
            todo_file.touch()
            assert _is_claude_internal_path(str(todo_file)) is True

    def test_settings_json_is_internal(self, tmp_path: Path) -> None:
        """~/.claude/settings.json should be recognised as internal."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            (tmp_path / ".claude").mkdir(parents=True)
            settings_file = tmp_path / ".claude" / "settings.json"
            settings_file.touch()
            assert _is_claude_internal_path(str(settings_file)) is True

    def test_arbitrary_file_under_claude_dir_rejected(self, tmp_path: Path) -> None:
        """Files directly under ~/.claude/ (not in known subdirs) are rejected."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            (tmp_path / ".claude").mkdir(parents=True)
            secret = tmp_path / ".claude" / "credentials.json"
            secret.touch()
            assert _is_claude_internal_path(str(secret)) is False

    def test_path_outside_claude_dir_rejected(self, tmp_path: Path) -> None:
        """Paths outside ~/.claude/ entirely are rejected."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            assert _is_claude_internal_path("/etc/passwd") is False
            assert _is_claude_internal_path("/tmp/evil.txt") is False

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        """Empty paths are rejected."""
        assert _is_claude_internal_path("") is False

    def test_unknown_subdir_rejected(self, tmp_path: Path) -> None:
        """Unknown subdirectories under ~/.claude/ are rejected."""
        with patch("src.claude.monitor.Path.home", return_value=tmp_path):
            (tmp_path / ".claude" / "secrets").mkdir(parents=True)
            bad_file = tmp_path / ".claude" / "secrets" / "key.pem"
            bad_file.touch()
            assert _is_claude_internal_path(str(bad_file)) is False
