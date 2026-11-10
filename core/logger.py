"""Structured logging for Zexec.

Logs to console (optionally Rich-formatted) and to a log file inside the
output directory.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

# Colours for console (ANSI), safe fallback if not a TTY.
_COLORS = {
    "DEBUG": "\x1b[90m",      # bright black
    "INFO": "\x1b[36m",       # cyan
    "OK": "\x1b[32m",         # green
    "WARN": "\x1b[33m",       # yellow
    "ERROR": "\x1b[31m",      # red
    "CRIT": "\x1b[41m\x1b[97m",  # white on red
    "RESET": "\x1b[0m",
}

# Add a custom "OK" / "FOUND" success level used for findings.
OK_LEVEL = 25  # between INFO and WARNING
logging.addLevelName(OK_LEVEL, "OK")


def _ok(self, message, *args, **kwargs):  # pragma: no cover - logging helper
    if self.isEnabledFor(OK_LEVEL):
        self._log(OK_LEVEL, message, args, **kwargs)


logging.Logger.ok = _ok  # type: ignore[attr-defined]


class _ColoredFormatter(logging.Formatter):
    def __init__(self, use_color: bool):
        super().__init__(fmt="%(asctime)s [%(levelname)-5s] %(message)s",
                         datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        if self.use_color:
            color = _COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{_COLORS['RESET']}"
        return super().format(record)


class Logger:
    """Thin wrapper that owns a logger + file handler."""

    def __init__(self, output_dir: Path, verbose: bool = False):
        self.logger = logging.getLogger("zexec")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.propagate = False

        # Remove pre-existing handlers (idempotent re-init)
        for h in list(self.logger.handlers):
            self.logger.removeHandler(h)

        use_color = sys.stdout.isatty()
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(_ColoredFormatter(use_color))
        self.logger.addHandler(console)

        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = output_dir / f"zexec_{ts}.log"
        file_handler = logging.FileHandler(self.log_path, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s",
                              datefmt="%Y-%m-%d %H:%M:%S"))
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)

    def debug(self, msg, *args): self.logger.debug(msg, *args)
    def info(self, msg, *args): self.logger.info(msg, *args)
    def ok(self, msg, *args): self.logger.ok(msg, *args)
    def warn(self, msg, *args): self.logger.warning(msg, *args)
    def error(self, msg, *args): self.logger.error(msg, *args)
