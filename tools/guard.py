#!/usr/bin/env python3
"""takestock's publication guard: no organisation's data in the repository.

takestock is built to measure real estates, so the most likely way for it to go
wrong is for a real estate to end up inside it: a hostname in an example, an
address in a fixture, a measured count in a comment. This guard scans every
tracked file, plus the commit message when run as a hook, for identifiers that
belong to a real organisation instead of to documentation.

It **fails and never skips.** A repository with nothing in it still runs every
check. There is no allow marker a line can carry. The only exemptions are the
exact tokens listed in ``tools/guard-allow.txt``, which is reviewed like code.

A reference-data file whose purpose is to list public domains (for example, which
vendor owns which service domain) can be named on a ``hostname-data`` line in the
allow file. Only the hostname check is lifted for that one file; addresses, emails,
GUIDs and the denylist still apply, and each entry in such a file is reviewed like
code.

What it treats as safe by construction:

* addresses reserved for documentation (RFC 5737, RFC 3849), plus loopback and
  unspecified addresses;
* names under reserved domains (RFC 2606, RFC 6761): ``.test``,
  ``.example``, ``.invalid``, ``.localhost``, and ``example.com``, ``.net``
  and ``.org``;
* the synthetic GUID shape ``00000000-0000-4000-8000-xxxxxxxxxxxx``.

What it cannot see: meaning. A sentence that describes an organisation without
naming anything is invisible to it. A human or model review for meaning is the
check for that, and this guard is only the floor beneath it.

**Optional external denylist.** Anyone who works on takestock alongside their
own private data can point ``git config takestock.denylist`` at a local file
holding one term per line. The file stays outside the repository. Text and
terms are both reduced to word pieces: runs of letters and runs of digits,
case folded, accents stripped, camelCase split. A term matches when its pieces
appear in order, so a name split across lines, string joins, underscores or
punctuation is still caught, while a short term never matches inside a longer
word (the term "abc" does not match "abcde", but does match "abc_region" and
"ABC12"). A term of twelve or more letters and digits is also matched with
every separator removed, which catches a name broken mid-word. A term written
with a leading ``=`` is matched case-sensitively, for codes that are also
ordinary words. When the setting is absent the guard says so and runs the
generic checks.

This check refuses the commit rather than warning, because a leaked
identifier cannot be recalled once published, so there is nothing to put
right afterwards.

Usage::

    python3 tools/guard.py            # scan every tracked file
    python3 tools/guard.py --msg FILE # also scan a commit message (commit-msg hook)
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW_FILE = ROOT / "tools" / "guard-allow.txt"

RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost", ".local")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
    "127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32",
    "2001:db8::/32", "::1/128", "::/128",                   # RFC 3849, loopback
)]
# Top-level domains checked for hostnames. Deliberately short: extensions such
# as .py, .md and .sh are also country codes, so an open list would flag
# every file name.
TLDS = ("nz", "au", "uk", "com", "net", "org", "io", "gov", "edu", "cloud",
        "co", "info", "biz", "dev", "app", "ai", "us", "ca", "ie", "sg")

IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)")
IPV6 = re.compile(r"(?<![\w:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
HOST = re.compile(r"(?<![\w@.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                  r"(?:" + "|".join(TLDS) + r"))(?![\w-])", re.IGNORECASE)
EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
SYNTHETIC_GUID = re.compile(r"^00000000-0000-4000-8000-[0-9a-fA-F]{12}$")


FLAT_MIN = 12
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")
_PIECE = re.compile(r"[^\W\d_]+|\d+")


def pieces(text: str, fold: bool = True) -> list[str]:
    """Letter runs and digit runs, accents stripped, camelCase split."""
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    text = _CAMEL.sub(" ", text)
    return _PIECE.findall(text.casefold() if fold else text)


class Term:
    """One denylist entry, ready to match. The original text is kept only in memory."""

    def __init__(self, line: str) -> None:
        self.case = line.startswith("=")
        found = pieces(line[1:] if self.case else line, fold=not self.case)
        self.seq = " " + " ".join(found) + " "
        flat = "".join(found)
        self.flat = flat if not self.case and len(flat) >= FLAT_MIN else ""
        self.size = len(flat)

    def found_in(self, text: str) -> bool:
        found = pieces(text, fold=not self.case)
        return self.seq in " " + " ".join(found) + " " or bool(self.flat and self.flat in "".join(found))


def make_term(line: str) -> Term:
    return Term(line)


def _allow_lines() -> list[str]:
    if not ALLOW_FILE.exists():
        return []
    return [ln.split("#", 1)[0].strip() for ln in ALLOW_FILE.read_text().splitlines()
            if ln.split("#", 1)[0].strip()]


def load_allow() -> set[str]:
    return {ln.lower() for ln in _allow_lines() if not ln.startswith("hostname-data ")}


def load_hostname_data() -> set[str]:
    """Reference-data files whose job is to list public domains (see guard-allow.txt)."""
    return {ln.split(None, 1)[1] for ln in _allow_lines() if ln.startswith("hostname-data ")}


def load_denylist() -> list[Term]:
    path = subprocess.run(["git", "-C", str(ROOT), "config", "--get", "takestock.denylist"],
                          capture_output=True, text=True).stdout.strip()
    if not path:
        print("guard: no external denylist configured (git config takestock.denylist); "
              "generic checks only.", file=sys.stderr)
        return []
    p = Path(path).expanduser()
    if not p.is_file():
        raise SystemExit(f"guard: takestock.denylist points at {p}, which does not exist. "
                         "Refusing to run with a configured-but-missing denylist.")
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    # Terms are never printed back: the report names the file and line only.
    return [t for t in (Term(ln) for ln in lines) if t.size >= 2]


def host_ok(host: str, allow: set[str]) -> bool:
    h = host.lower().rstrip(".")
    if h.endswith(RESERVED_SUFFIXES) or any(h == d or h.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return any(h == a or h.endswith("." + a) for a in allow)


def ip_ok(text: str, allow: set[str]) -> bool | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None  # not an address at all
    return text.lower() in allow or any(ip in n for n in DOC_NETS if n.version == ip.version)


def scan_text(label: str, text: str, allow: set[str], deny: list[Term],
              hostnames_are_data: bool = False) -> list[str]:
    hits: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        where = f"{label}:{n}"
        for m in IPV4.finditer(line):
            if ip_ok(m.group(1), allow) is False:
                hits.append(f"{where}: IPv4 address outside documentation ranges: {m.group(1)}")
        for m in IPV6.finditer(line):
            tok = m.group(1)
            if tok.count(":") >= 2 and ip_ok(tok, allow) is False:
                hits.append(f"{where}: IPv6 address outside 2001:db8::/32: {tok}")
        for m in EMAIL.finditer(line):
            if not host_ok(m.group(1), allow):
                hits.append(f"{where}: email address at a real domain: {m.group(0)}")
        for m in HOST.finditer(line):
            if hostnames_are_data:
                break
            if not host_ok(m.group(1), allow) and "@" + m.group(1) not in line:
                hits.append(f"{where}: hostname outside reserved domains: {m.group(1)}")
        for m in GUID.finditer(line):
            if not SYNTHETIC_GUID.match(m.group(0)) and m.group(0).lower() not in allow:
                hits.append(f"{where}: GUID not in the synthetic 00000000-0000-4000-8000-… shape")
    for term in deny:
        if term.found_in(text):
            # Locate the line without echoing the term.
            line_no = next((i for i, ln in enumerate(text.splitlines(), 1) if term.found_in(ln)), None)
            at = f"{label}:{line_no}" if line_no else f"{label} (spans lines)"
            hits.append(f"{at}: matches a term in the external denylist")
    return hits


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
                          "--exclude-standard"], capture_output=True, text=True, check=True).stdout
    return [ROOT / p for p in out.split("\0") if p]


def main(argv: list[str]) -> int:
    allow = load_allow()
    host_data = load_hostname_data()
    deny = load_denylist()
    hits: list[str] = []
    for path in tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel == "LICENSE" or not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\0" in raw[:8192]:
            hits.append(f"{rel}: binary file. The guard cannot read it, so it is refused "
                        "(fixtures must be text)")
            continue
        hits += scan_text(rel, raw.decode("utf-8", "replace"), allow, deny, rel in host_data)
    if "--msg" in argv:
        msg = Path(argv[argv.index("--msg") + 1]).read_text()
        body = "\n".join(ln for ln in msg.splitlines() if not ln.startswith("#"))
        hits += scan_text("commit message", body, allow, deny)
    if hits:
        print("guard: FAILED. takestock carries no organisation's data.\n  " + "\n  ".join(hits),
              file=sys.stderr)
        print("Replace each with a reserved stand-in (example.test, 192.0.2.x, 2001:db8::, "
              "00000000-0000-4000-8000-…). A genuinely public reference domain goes in "
              "tools/guard-allow.txt, and that change is reviewed.", file=sys.stderr)
        return 1
    print("guard: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
