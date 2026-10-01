"""Run ``dig`` and read its full response: status, flags and records.

``util.dig`` returns ``+short`` answers, which cannot tell "the name has no
such record" (NOERROR with an empty answer) from "the name does not exist"
(NXDOMAIN) or from "nothing answered". The collectors that need that
difference use :func:`query` and :func:`parse` instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .util import ERROR_PREFIX, run

#: Seconds ``dig`` waits for each try, and how many tries it makes.
TIME = 8
TRIES = 3

_HEADER = re.compile(r"status:\s*([A-Z]+)")
_FLAGS = re.compile(r";; flags:([^;]*);")
_SECTION = re.compile(r"^;; ([A-Z]+) SECTION:")


@dataclass
class RR:
    """One resource record; ``rdata`` is the record data split on whitespace."""

    owner: str
    ttl: int
    rclass: str
    rtype: str
    rdata: list[str]


@dataclass
class Response:
    """One parsed ``dig`` response. ``error`` is set when nothing answered."""

    status: str = ""
    flags: set[str] = field(default_factory=set)
    answer: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    error: str = ""

    @property
    def answered(self) -> bool:
        """True when a server returned a response code (NOERROR, NXDOMAIN, ...)."""
        return not self.error and bool(self.status)

    @property
    def authenticated(self) -> bool:
        """True when the resolver set the AD (authenticated data) flag."""
        return "ad" in self.flags

    def records(self, rtype: str, section: str = "answer") -> list[RR]:
        """The records of type ``rtype`` in the answer (or ``"authority"``) section."""
        rows = self.answer if section == "answer" else self.authority
        return [r for r in rows if r.rtype.upper() == rtype.upper()]


def norm(name: str) -> str:
    """A DNS name lower-cased without its trailing dot, for comparison."""
    return name.strip().rstrip(".").lower()


def parse(text: str) -> Response:
    """Parse ordinary (not ``+short``) ``dig`` output."""
    if text.startswith(ERROR_PREFIX):
        return Response(error=text.strip())
    resp = Response()
    m = _HEADER.search(text)
    if not m:
        reason = next((ln.lstrip(";").strip() for ln in text.splitlines()
                       if "timed out" in ln or "no servers" in ln
                       or "couldn't get address" in ln), "")
        return Response(error=reason or "no response header in dig output")
    resp.status = m.group(1)
    f = _FLAGS.search(text)
    if f:
        resp.flags = set(f.group(1).split())
    section = ""
    for line in text.splitlines():
        s = _SECTION.match(line)
        if s:
            section = s.group(1)
            continue
        if not line.strip() or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 4 or section not in ("ANSWER", "AUTHORITY"):
            continue
        try:
            ttl = int(parts[1])
        except ValueError:
            continue
        rr = RR(owner=parts[0], ttl=ttl, rclass=parts[2], rtype=parts[3], rdata=parts[4:])
        (resp.answer if section == "ANSWER" else resp.authority).append(rr)
    return resp


def query(name: str, rtype: str, resolver: str = "", *, dnssec: bool = False,
          cd: bool = False) -> str:
    """Ask ``resolver`` (default: the system's) for ``name``/``rtype``; return dig's text.

    ``dnssec`` requests signatures (``+dnssec``); ``cd`` sets checking
    disabled, so a validating resolver returns data it could not validate.
    """
    cmd = ["dig"]
    if dnssec:
        cmd.append("+dnssec")
    cmd += [f"+time={TIME}", f"+tries={TRIES}"]
    if cd:
        cmd.append("+cd")
    cmd += [rtype, name]
    if resolver:
        cmd.append(f"@{resolver}")
    return run(cmd, timeout=TIME * TRIES + 10)
