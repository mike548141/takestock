"""Shared pieces for the active-probe tests.

Captured fixtures live in ``fixtures/probes/``; each file's first line says
how it was captured (always from a stub server on loopback, with synthetic
``example.test`` names). :class:`FakeRun` stands in for ``util.run`` so no
test sends a packet anywhere: it answers commands it was told about and
fails the test on any other.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "probes"

AUTH = {"scope": "Published endpoints of Example Widgets Ltd",
        "authorised_by": "Security manager", "date": "2030-01-31"}


def fixture(name: str) -> str:
    """The text of a captured fixture."""
    return (FIXTURES / name).read_text()


def target(authorised: bool = True, extra_auth: dict | None = None, **scan_targets) -> dict:
    """A synthetic target profile with the given ``scan_targets`` groups."""
    t: dict = {"name": "example-widgets", "scan_targets": scan_targets}
    if authorised:
        t["authorisation"] = {**AUTH, **(extra_auth or {})}
    return t


Matcher = Callable[[list[str]], bool]


def has(*words: str) -> Matcher:
    """A matcher for a command containing every one of ``words`` as an argument."""
    return lambda cmd: all(w in cmd for w in words)


class FakeRun:
    """A stand-in for ``util.run``: answers from a list of (matcher, output) pairs.

    Every call is recorded in :attr:`calls`. A command no matcher accepts
    fails the test, so a collector cannot contact anything unplanned.
    """

    def __init__(self, answers: Sequence[tuple[Matcher, str]] = ()) -> None:
        self.answers = list(answers)
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
        self.calls.append(list(cmd))
        for match, out in self.answers:
            if match(cmd):
                return out
        raise AssertionError(f"unexpected command: {cmd}")


def never_run(cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
    """A ``run`` that fails the test if anything is executed at all."""
    raise AssertionError(f"nothing should have been run, but got: {cmd}")
