"""Command-line entry point.

A placeholder until the collectors and renderers land: it reports the version
and how the command will be used.
"""

from __future__ import annotations

import sys

from . import __version__

USAGE = "usage: takestock <command> [options]  (commands are not available yet)"


def main(argv: list[str] | None = None) -> int:
    """Print the version and a one-line usage, and return an exit status."""
    args = sys.argv[1:] if argv is None else argv
    print(f"takestock {__version__}")
    print(USAGE)
    return 0 if not args or args[0] in ("-h", "--help", "--version") else 2
