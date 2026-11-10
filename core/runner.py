"""Safe subprocess execution for external tools.

The runner guarantees:
  * commands are built as argument lists (no shell string interpolation),
  * a hard timeout applies to every call,
  * stdout/stderr are captured and logged,
  * exit codes are surfaced to callers instead of raising unexpectedly.
"""
from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class Result:
    """Outcome of a single tool invocation."""
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def out_lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]

    def __str__(self) -> str:
        return self.stdout or self.stderr


class Runner:
    """Runs external commands safely and logs them."""

    def __init__(self, logger: logging.Logger, timeout: int = 180):
        self.log = logger
        self.timeout = timeout

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def resolve(self, name: str, prefix: str = "") -> str:
        """Return a full path to a tool, honouring an optional name prefix.

        Used for Kali's ``impacket-*`` scripts, so callers can pass
        ``resolve("secretsdump", prefix="impacket-")``.
        """
        candidates = [name]
        if prefix:
            candidates.insert(0, f"{prefix}{name}")
        for candidate in candidates:
            path = self.which(candidate)
            if path:
                return path
        # Fall back to the bare name (let subprocess raise FileNotFoundError).
        return name

    def run(self, cmd: Sequence[str], timeout: int | None = None,
            input_text: str | None = None, silent: bool = False,
            cwd: str | None = None) -> Result:
        """Run a command and return its Result.

        ``cmd`` must be a sequence (list/tuple) of arguments. Never pass a
        single shell string — use ``shlex.split`` yourself if you must.
        """
        cmd_list = [str(c) for c in cmd]
        effective_timeout = timeout if timeout is not None else self.timeout
        display = " ".join(shlex.quote(c) for c in cmd_list)
        if not silent:
            self.log.debug("exec: %s", display)

        try:
            proc = subprocess.run(
                cmd_list,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired as exc:
            self.log.warning("timeout after %ss: %s", effective_timeout, display)
            return Result(cmd_list, -1,
                          stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                          stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                          timed_out=True)
        except FileNotFoundError:
            self.log.error("tool not found: %s", cmd_list[0])
            return Result(cmd_list, 127, "", "command not found")
        except OSError as exc:
            self.log.error("OS error running %s: %s", cmd_list[0], exc)
            return Result(cmd_list, 126, "", str(exc))

        if not silent:
            self.log.debug("exit=%d", proc.returncode)
        return Result(cmd_list, proc.returncode, proc.stdout, proc.stderr)

    def run_shell(self, command: str, timeout: int | None = None) -> Result:
        """Run an already-assembled shell string.

        Only use for pipelines/redirections that can't be expressed as a list.
        """
        return self.run(["bash", "-c", command], timeout=timeout)

    def popen(self, cmd: Sequence[str], log_file: str | None = None):
        """Start a long-running process in the background, returning the Popen.

        Output is appended to ``log_file`` (or discarded). The caller is
        responsible for terminating the process.
        """
        import subprocess
        cmd_list = [str(c) for c in cmd]
        if log_file:
            fh = open(log_file, "w", encoding="utf-8", errors="replace")
        else:
            fh = subprocess.DEVNULL
        self.log.debug("background: %s", " ".join(cmd_list))
        return subprocess.Popen(
            cmd_list, stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL)


def build(cmd: Sequence[str]) -> list[str]:
    """Convenience helper returning a list[str] from mixed args."""
    return [str(c) for c in cmd]
