#!/usr/bin/env python3
"""Run a contributor's own pre-commit check, if they have named one.

The tracked pre-commit hook is atelier's floor shim, which names no check of its
own. takestock's checks reach it as ``local`` entries in ``.atelier-floor.json``,
and this is one of them: it runs the command a contributor set with

    git config takestock.extraHook "<command>"

as ``<command> pre-commit``, from the top of the working tree, and fails when
that command fails. The command and whatever it reads stay outside the
repository. With nothing set it passes, because the check is optional.

The commit-message half (``<command> commit-msg FILE``) is unchanged: the
tracked ``commit-msg`` hook calls it directly.
"""
from __future__ import annotations

import subprocess
import sys


def main() -> int:
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True).stdout.strip()
    extra = subprocess.run(["git", "config", "--get", "takestock.extraHook"],
                           capture_output=True, text=True, check=False).stdout.strip()
    if not extra:
        print("extra_hook: no takestock.extraHook set; nothing to run.")
        return 0
    # A shell, as the hook always used: the command is the contributor's own,
    # set in their own clone's config, so it runs with their own authority.
    return subprocess.run(["sh", "-c", f'{extra} pre-commit'], cwd=top, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
