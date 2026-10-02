"""Exit codes shared by the ``takestock`` command and every ``python -m takestock.*`` entry point.

* ``0`` (:data:`EXIT_CLEAN`): the work was done and found nothing adverse.
* ``1`` (:data:`EXIT_FINDINGS`): the work was done and found something: a weak
  verdict, an unmet requirement, a derived requirement, a resolver disagreement.
* ``2`` (:data:`EXIT_ERROR`): the work could not be done: wrong arguments (the
  same code :mod:`argparse` uses), an input that is missing or unreadable, or a
  refusal.

An uncaught exception would make Python exit 1, which a caller would read as
"findings present". :func:`guarded` stops that: it turns an input error, or
any other failure, into a one-line message and exit 2.
"""

from __future__ import annotations

import sys
import traceback
from collections.abc import Callable
from typing import TypeVar

import yaml

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

#: What a missing, unreadable or malformed input raises.
INPUT_ERRORS: tuple[type[BaseException], ...] = (OSError, ValueError, KeyError, yaml.YAMLError)

A = TypeVar("A")


def guarded(prog: str, body: Callable[[A], int], arg: A) -> int:
    """Return ``body(arg)``, or :data:`EXIT_ERROR` with a message on stderr if it raises.

    An input error prints ``<prog>: <reason>``. Anything else is a defect, so it
    also prints the traceback, but the exit code is still :data:`EXIT_ERROR`.
    ``SystemExit`` (argparse's usage error, exit 2) passes through untouched.
    """
    try:
        return body(arg)
    except INPUT_ERRORS as exc:
        print(f"{prog}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception:  # noqa: BLE001 - the exit-code contract holds even for a defect
        print(f"{prog}: internal error", file=sys.stderr)
        traceback.print_exc()
        return EXIT_ERROR
