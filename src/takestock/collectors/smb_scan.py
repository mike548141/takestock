"""SMB dialects and message signing on named internal file servers.

An inside probe: it reads ``scan_targets.smb_445`` and needs its own
``authorisation.smb_445`` record (:mod:`takestock.inside_scope`). For each
named host it runs nmap's ``smb-protocols``, ``smb2-security-mode`` and
``smb-security-mode`` scripts against 445/tcp and produces two rows:

* **SMB dialects**: every dialect the server accepted at NEGOTIATE, graded
  on the weakest (SMB1 is weak).
* **SMB signing**: whether the server requires message signing. Required is
  ``acceptable``; enabled but not required is ``acceptable`` with a flag,
  since a client that does not insist gets an unsigned session; disabled is
  ``weak``. Where SMB1 and SMB2+ give different readings the row is graded
  on the weaker.

It never authenticates, enumerates shares or users, or runs a vulnerability
script. nmap's SMB library also sends one NetBIOS name query to 137/udp
before negotiating, and the printed budget says so.
"""

from __future__ import annotations

import re
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles
from ..identity import names_by_address, report_as
from ..inside_scope import MAX_HOSTS
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..util import ERROR_PREFIX, is_ipv6_literal, now_date, run, scan_address
from .plaintext_scan import no_answer

SOURCE = "smb_scan"
#: The ``scan_targets`` (and ``authorisation``) key for this probe.
TARGET_KEY = "smb_445"
PORT = "445"
SOURCE_NAME = "Active SMB negotiation probe (nmap) — inside the network"

NMAP_FLAGS = ("-sT", "-Pn", "--max-retries", "1", "--scan-delay", "200ms",
              "--max-rate", "10", "--host-timeout", "120s")
NMAP_SCRIPTS = "smb-protocols,smb2-security-mode,smb-security-mode"
RUN_TIMEOUT = 300
INTER_HOST_SECONDS = 2.0

# Findings.
SIGNING_NOT_REQUIRED = "smb-signing-not-required"
SIGNING_DISABLED = "smb-signing-disabled"
# Limits on what was measured.
NOT_LISTENING = "smb-not-listening"
UNREACHED = "smb-unreached"
NO_NEGOTIATION = "smb-no-negotiation"
SIGNING_NOT_READ = "smb-signing-not-read"
SCAN_NOT_RUN = "smb-scan-not-run"

register_informational_prefixes(NOT_LISTENING, UNREACHED, NO_NEGOTIATION,
                                SIGNING_NOT_READ, SCAN_NOT_RUN)

# nmap's dialect labels to baseline ``smb_dialects`` tokens.
_DIALECTS = {"NT LM 0.12": "SMB1", "2.02": "SMB2.0.2", "2.10": "SMB2.1",
             "3.00": "SMB3.0", "3.02": "SMB3.0.2", "3.11": "SMB3.1.1"}

REQUIRED, NOT_REQUIRED, DISABLED = "required", "enabled-not-required", "disabled"
# Every sentence smb2-security-mode can print.
_SIGNING = {
    "Message signing enabled and required": REQUIRED,
    "Message signing enabled but not required": NOT_REQUIRED,
    "Message signing is disabled and not required!": DISABLED,
    "Message signing is disabled!": DISABLED,
}
# smb-security-mode's message_signing values (before any parenthesis).
_SMB1_SIGNING = {"required": REQUIRED, "supported": NOT_REQUIRED, "disabled": DISABLED}
_SIGNING_ORDER = {DISABLED: 0, NOT_REQUIRED: 1, REQUIRED: 2}

_PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(\S+)")
_SCRIPT_HEAD = re.compile(r"^\|_?\s?([a-z0-9-]+):\s*$")
_ITEM = re.compile(r"^\|_?\s+(.*?)\s*$")


@dataclass
class SmbScan:
    """What nmap read from one host."""

    reached: bool = False
    state: str = ""
    dialects: list[str] = field(default_factory=list)
    signing_dialect: str = ""
    signing_text: str = ""
    smb1_signing: str = ""
    smb1_auth_level: str = ""
    smb1_challenge: str = ""
    detail: str = ""


def parse_nmap(out: str) -> SmbScan:
    """Read the port state and the three scripts' output."""
    scan = SmbScan()
    if out.startswith(ERROR_PREFIX):
        scan.detail = out.strip()[:200]
        return scan
    section = ""
    sub = ""
    for raw in out.splitlines():
        line = raw.rstrip()
        pm = _PORT_LINE.match(line.strip())
        if pm and not line.startswith("|"):
            scan.reached = True
            scan.state = pm.group(3)
            continue
        if not line.startswith("|"):
            section = sub = ""
            continue
        head = _SCRIPT_HEAD.match(line)
        if head and line.startswith(("| ", "|_")) and not line.startswith(("|  ", "|_ ")):
            section, sub = head.group(1), ""
            continue
        item = _ITEM.match(line)
        if not item:
            continue
        text = item.group(1).strip()
        if section == "smb-protocols":
            if text.rstrip(":") == "dialects":
                continue
            scan.dialects.append(text)
        elif section == "smb-security-mode":
            key, sep, value = text.partition(":")
            if sep:
                field_name = {"message_signing": "smb1_signing",
                              "authentication_level": "smb1_auth_level",
                              "challenge_response": "smb1_challenge"}.get(key.strip())
                if field_name:
                    setattr(scan, field_name, value.strip())
        elif section == "smb2-security-mode":
            if text.endswith(":") and not scan.signing_dialect:
                sub = text[:-1].strip()
                scan.signing_dialect = sub
            elif sub:
                scan.signing_text = text
    if not scan.reached:
        for marker in ("Failed to resolve", "skipping host", "Note: Host seems down"):
            if marker in out:
                scan.detail = next(ln.strip() for ln in out.splitlines() if marker in ln)[:200]
                break
        else:
            scan.detail = scan.detail or "nmap produced no port table"
    return scan


def dialect_token(raw: str) -> str:
    """The baseline token for an nmap dialect line; ``SMB?<label>`` when unknown."""
    name = raw.split(" (", 1)[0].strip()
    return _DIALECTS.get(name, f"SMB?{name}")


def signing_state(text: str) -> str:
    """required / enabled-not-required / disabled from smb2-security-mode, or ""."""
    return _SIGNING.get(text.strip(), "")


def smb1_signing_state(text: str) -> str:
    """The same reading from smb-security-mode's ``message_signing`` value, or ""."""
    return _SMB1_SIGNING.get(text.split(" (", 1)[0].strip(), "")


def _smb1_auth_notes(scan: SmbScan) -> list[str]:
    notes = []
    if scan.smb1_auth_level.startswith("share"):
        notes.append("SMB1 advertises share-level authentication (one password per share, "
                     "sent when the share is opened).")
    if scan.smb1_challenge.startswith("plaintext-only"):
        notes.append("SMB1 advertises no challenge/response, so it can only accept "
                     "passwords sent in plaintext.")
    return notes


def check_scope(target: dict) -> list[str]:
    """The authorised hosts, or :class:`~takestock.inside_scope.InsideRefused`."""
    where = f"`scan_targets.{TARGET_KEY}`"
    hosts = [inside_scope.entry_address(entry, f"{where}[{i}]")[0]
             for i, entry in enumerate(inside_scope.entries(target, TARGET_KEY))]
    inside_scope.check_unique(((h,) for h in hosts), where)
    inside_scope.check_ceiling(len(hosts), MAX_HOSTS, where)
    return hosts


def _nmap_command(host: str) -> list[str]:
    family = ["-6"] if is_ipv6_literal(host) else []
    return ["nmap", *NMAP_FLAGS, *family, "-p", PORT, "--script", NMAP_SCRIPTS,
            scan_address(host)]


def budget_lines(hosts: list[str]) -> list[str]:
    """Every host and what will be sent to it, printed before anything runs."""
    return [
        f"[smb_scan] probe budget — {len(hosts)} host(s) (ceiling {MAX_HOSTS}), port "
        f"{PORT}/tcp only",
        f"  method   : one `nmap {' '.join(NMAP_FLAGS)} -p {PORT} --script {NMAP_SCRIPTS}` "
        f"per host, one at a time, {INTER_HOST_SECONDS:g}s between them",
        "  also sent: one NetBIOS name-status query to 137/udp per host (nmap's SMB "
        "library does this before negotiating)",
        "  never    : authentication, share or user enumeration, vulnerability scripts",
        *(f"  host     : {h}" for h in hosts),
    ]


def _settle() -> None:
    time.sleep(INTER_HOST_SECONDS)


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _row(host: str, name: str, role: str, collected_at: str, **kw) -> CryptoAsset:
    kw.setdefault("source_class", "private")
    kw.setdefault("source_name", SOURCE_NAME)
    return CryptoAsset(name=f"{name} {host}:{PORT}", role=role, data_state="in-transit",
                       protocol="smb", host=host, port=PORT, source=SOURCE,
                       internet_facing=False, collected_at=collected_at,
                       software="SMB server", **kw)


def assets_from_scan(host: str, scan: SmbScan, collected_at: str,
                     role: str = "") -> list[CryptoAsset]:
    """The rows for one host: an explanatory ``SMB`` row, or a dialects row and a signing row."""
    state = scan.state.lower()
    if not scan.reached:
        return [_row(host, "SMB", role, collected_at, verdict="unknown", flags=[UNREACHED],
                     notes=f"nmap produced no port table for this host ({scan.detail}); "
                           "nothing is known about SMB here.")]
    if state == "closed":
        return [_row(host, "SMB", role, collected_at, verdict=NA_VERDICT, flags=[NOT_LISTENING],
                     notes="Port 445 refused the connection: no SMB service listens here, "
                           "so there is nothing to grade.")]
    if no_answer(state):
        return [_row(host, "SMB", role, collected_at, verdict="unknown", flags=[UNREACHED],
                     notes=f"Port 445 gave no answer ({scan.state}). A blocked probe and a "
                           "closed port look the same from here, so this is unmeasured, "
                           "not absent.")]
    if not scan.dialects:
        return [_row(host, "SMB", role, collected_at, verdict="unknown", flags=[NO_NEGOTIATION],
                     notes=f"Port 445 is {scan.state} but accepted no SMB dialect nmap "
                           "offered, so neither dialects nor signing could be read.")]

    tokens = [dialect_token(d) for d in scan.dialects]
    rows = [_row(host, "SMB dialects", role, collected_at, protocol_versions=tokens,
                 extra={"smb_dialects_raw": list(scan.dialects)},
                 notes="Dialects the server accepted at NEGOTIATE: " + ", ".join(tokens)
                       + ". Graded on the weakest one accepted.")]

    extra = {"smb_signing_dialect": scan.signing_dialect,
             "smb_signing_raw": scan.signing_text,
             "smb1_signing_raw": scan.smb1_signing,
             "smb1_authentication_level": scan.smb1_auth_level,
             "smb1_challenge_response": scan.smb1_challenge}
    readings: list[tuple[str, str]] = []
    sig2 = signing_state(scan.signing_text)
    if sig2:
        readings.append((f"dialect {scan.signing_dialect}", sig2))
    sig1 = smb1_signing_state(scan.smb1_signing) if "SMB1" in tokens else ""
    if sig1:
        readings.append(("SMB1 (NT LM 0.12)", sig1))
    smb1_unread = "SMB1" in tokens and not sig1
    smb1_notes = _smb1_auth_notes(scan)
    if not readings:
        why = ("the server accepted no SMB2 or later dialect, and nmap's smb-security-mode "
               f"returned no SMB1 signing reading ({scan.smb1_signing or 'none'})"
               if all(t == "SMB1" for t in tokens)
               else f"nmap returned no signing reading it recognises "
                    f"({scan.signing_text or 'none'})")
        rows.append(_row(host, "SMB signing", role, collected_at, verdict="unknown",
                         flags=[SIGNING_NOT_READ], extra=extra,
                         notes="; ".join([f"Signing not read: {why}.", *smb1_notes])))
        return rows
    where, sig = min(readings, key=lambda r: _SIGNING_ORDER[r[1]])
    read_on = " and ".join(f"{w}: {st}" for w, st in readings)
    tail = [f"Read on {read_on}; graded on the weakest."] if len(readings) > 1 else []
    if smb1_unread:
        tail.append("SMB1 is accepted and its signing was not read, so this row speaks for "
                    "SMB2 and later only.")
    tail += smb1_notes
    if sig == REQUIRED:
        rows.append(_row(host, "SMB signing", role, collected_at, verdict="acceptable",
                         extra=extra,
                         notes=" ".join([f"The server advertises that it requires message "
                                         f"signing (read on {where}).", *tail])))
    elif sig == NOT_REQUIRED:
        rows.append(_row(host, "SMB signing", role, collected_at, verdict="acceptable",
                         flags=[SIGNING_NOT_REQUIRED], extra=extra,
                         notes=" ".join([f"Signing is enabled but not required (read on "
                                         f"{where}), so a client that does not insist gets an "
                                         "unsigned session.", *tail])))
    else:
        raw = scan.smb1_signing if where.startswith("SMB1") else scan.signing_text
        rows.append(_row(host, "SMB signing", role, collected_at, verdict="weak",
                         flags=[SIGNING_DISABLED], extra=extra,
                         notes=" ".join([f"The server advertises signing disabled (read on "
                                         f"{where}): {raw}", *tail])))
    return rows


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None,
            announce: Callable[[str], None] | None = None
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every authorised SMB host; return (assets, failures)."""
    say = _announce if announce is None else announce
    try:
        hosts = check_scope(target)
    except inside_scope.InsideRefused as exc:
        return [], [inside_scope.refusal(SOURCE, exc)]
    if not hosts:
        return [], []

    collected_at = now_date(ref_time)
    role_by_host = roles.scan_target_roles(target)
    lines = budget_lines(hosts)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "nmap-smb-budget.txt").write_text("\n".join(lines) + "\n")

    names = names_by_address(target)
    if not shutil.which("nmap"):
        return [report_as(_row(h, "SMB", role_by_host.get(h, ""), collected_at, verdict="unknown",
                     flags=[SCAN_NOT_RUN], source_class="unknown",
                     source_name="SMB probe not performed — nmap unavailable in this "
                                 "environment",
                     notes="nmap is not on PATH, so no SMB probe was sent."), names)
                for h in hosts], []

    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for n, host in enumerate(hosts):
        if n:
            _settle()
        out = run(_nmap_command(host), timeout=RUN_TIMEOUT)
        if raw_dir:
            (raw_dir / f"nmap-smb-{scan_address(host)}.txt").write_text(out)
        scan = parse_nmap(out)
        assets += [report_as(a, names)
                   for a in assets_from_scan(host, scan, collected_at, role_by_host.get(host, ""))]
        if not scan.reached:
            failures.append(f"smb_scan {host}: nmap produced no port table ({scan.detail}); "
                            "this run says nothing about SMB on that host.")
    return assets, failures
