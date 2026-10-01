"""SSH host keys, key exchange, ciphers and MACs, three ways.

* :func:`collect` probes the internet-facing SSH listeners in
  ``scan_targets.ssh_22``.
* :func:`collect_inside` probes internal hosts in ``scan_targets.ssh_inside``,
  which needs its own authorisation record (:mod:`takestock.inside_scope`)
  and names hosts in operator-chosen batches that run one after another.
* :func:`collect_inbox` reads ``ssh-audit -jj`` JSON files someone ran and
  dropped in the inbox, for hosts the tool cannot reach itself.

The preferred instrument is ``ssh-audit`` (set ``TAKESTOCK_SSH_AUDIT`` to its
path, or put it on ``PATH``). Without it the probes fall back to nmap's
``ssh2-enum-algos``, which reads the same algorithm lists but not the
banner, key sizes or known vulnerabilities, and the row says so. With
neither, each host gets an ``unknown`` row saying no probe was sent.

No probe ever attempts a login.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .. import coverage, inside_scope, roles
from ..config import display_path, inbox_path
from ..inside_scope import MAX_HOSTS
from ..model import NA_VERDICT, CryptoAsset
from ..util import ERROR_PREFIX, file_mtime_date, is_ipv6_literal, now_date, run, scan_address

SOURCE = "ssh_audit"
SOURCE_ACTIVE = "Active SSH scan (ssh-audit) — internet-facing endpoint"
SOURCE_ACTIVE_NMAP = ("Active SSH scan (nmap ssh2-enum-algos; ssh-audit unavailable) — "
                      "internet-facing endpoint")
SOURCE_NOT_PERFORMED = ("SSH scan not performed — neither ssh-audit nor nmap available "
                        "in this environment")
INBOX_SOURCE_PREFIX = "ssh-audit JSON export"

#: Environment variable naming the ssh-audit executable.
BINARY_ENV = "TAKESTOCK_SSH_AUDIT"

#: The ``scan_targets`` group of internet-facing SSH listeners.
TARGET_KEY = "ssh_22"


def _binary() -> str | None:
    return os.environ.get(BINARY_ENV) or shutil.which("ssh-audit")


def _safe_json(text: str) -> dict | None:
    """The JSON object in ``text`` (ignoring any noise around it), or None."""
    if not text or text.startswith(ERROR_PREFIX):
        return None
    candidate = text.strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = candidate[start:end + 1]
    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _algs(struct: dict, key: str) -> list[str]:
    entries = struct.get(key)
    out: list[str] = []
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if isinstance(entry, dict) and entry.get("algorithm"):
            out.append(str(entry["algorithm"]))
        elif isinstance(entry, str) and entry:
            out.append(entry)
    return out


def _asset_from_struct(struct: dict, host: str, port: str) -> CryptoAsset:
    """A row from ssh-audit's ``-jj`` JSON (``banner``, ``kex``, ``key``, ``enc``, ``mac``)."""
    banner = struct.get("banner") or {}
    software = str(banner.get("software") or "")
    raw_banner = str(banner.get("raw") or "")
    proto_version = str(banner.get("protocol") or "")

    return CryptoAsset(
        name=f"SSH {host}:{port}", role=roles.ssh_service(host),
        data_state="in-transit", protocol="ssh",
        host=host, port=str(port), source=SOURCE,
        software=software, version=raw_banner,
        protocol_versions=[proto_version] if proto_version else [],
        symmetric=sorted(set(_algs(struct, "enc"))),
        notes=raw_banner,
        extra={"ssh_hostkey": sorted(set(_algs(struct, "key"))),
               "ssh_kex": sorted(set(_algs(struct, "kex"))),
               "ssh_mac": sorted(set(_algs(struct, "mac")))},
    )


def _placeholder(host: str, port: str, note: str, source_class: str, source_name: str,
                 collected_at: str) -> CryptoAsset:
    return CryptoAsset(name=f"SSH {host}:{port}", role=roles.ssh_service(host),
                       data_state="in-transit", protocol="ssh",
                       host=host, port=str(port), source=SOURCE, verdict="unknown",
                       source_class=source_class, source_name=source_name,
                       collected_at=collected_at, notes=note)


def _normalise_target(entry) -> tuple[str, str]:
    if isinstance(entry, dict):
        return str(entry.get("ip") or entry.get("host")), str(entry.get("port", 22))
    return str(entry), "22"


def _probe(binary: str, host: str, port: str, raw_dir: Path | None,
           ref_time: datetime | None = None) -> CryptoAsset:
    out = run([binary, "-jj", "-p", str(port), host], timeout=60)
    if raw_dir:
        (raw_dir / f"ssh-audit-{host}-{port}.json").write_text(out)
    struct = _safe_json(out)
    collected_at = now_date(ref_time)
    if struct is None:
        return _placeholder(host, port, "ssh-audit produced no parseable JSON "
                            "(host unreachable, port closed, or not SSH)",
                            "public", SOURCE_ACTIVE, collected_at)
    asset = _asset_from_struct(struct, host, port)
    asset.source_class, asset.source_name, asset.collected_at = (
        "public", SOURCE_ACTIVE, collected_at)
    return asset


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Probe the internet-facing SSH listeners; return (assets, failures)."""
    entries = [_normalise_target(e)
               for e in (target.get("scan_targets", {}) or {}).get(TARGET_KEY) or []]
    if not entries:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    binary = _binary()
    if binary:
        return [_probe(binary, host, port, raw_dir, ref_time) for host, port in entries], []
    if not shutil.which("nmap"):
        return [_placeholder(host, port, "Not measured: neither ssh-audit (set "
                             f"{BINARY_ENV}) nor nmap is available, so no probe was sent.",
                             "unknown", SOURCE_NOT_PERFORMED, now_date(ref_time))
                for host, port in entries], []
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for host, port in entries:
        out = run(_nmap_command(host, port), timeout=NMAP_RUN_TIMEOUT)
        if raw_dir:
            (raw_dir / f"nmap-ssh2-{host}-{port}.txt").write_text(out)
        asset, failure = asset_from_nmap(InsideHost(host, port, ""), out, ref_time,
                                         inside=False)
        if asset is not None:
            assets.append(asset)
        if failure:
            failures.append(failure)
    return assets, failures


def split_target(value: str) -> tuple[str, str]:
    """(host, port) from ``host:port``, ``[v6]:port``, or a bare host (port "")."""
    v = value.strip()
    if v.startswith("[") and "]" in v:
        host, _, rest = v[1:].partition("]")
        return host, rest.removeprefix(":")
    if v.count(":") == 1:
        host, _, port = v.partition(":")
        return host, port
    return v, ""


def collect_inbox(target: dict, root: Path | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Read ssh-audit JSON exports from the inbox; return (assets, coverage gaps).

    The folder is ``ssh_inbox.dir`` in the profile (default ``inbox/ssh-audit``).
    Each file's ``target`` field names the host; its modification date is
    recorded as when the evidence was collected.
    """
    inbox = target.get("ssh_inbox", {}) or {}
    directory = inbox_path(inbox.get("dir", "inbox/ssh-audit"), root)
    assets: list[CryptoAsset] = []
    gaps: list[str] = []
    harvest = ("An ssh-audit run (`ssh-audit -jj <host>`) against the internal servers, "
               "saved as one JSON file per host in this folder.")

    if not directory.is_dir():
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"{display_path(directory, root)}/ (ssh-audit JSON exports) — internal SSH "
            "host-key, key-exchange and MAC audit",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("Administrators log in to the servers over SSH, and nothing here has "
                    "checked the strength of the encryption it uses. The report cannot say "
                    "whether administrative access is protected to a current standard."),
            harvest=harvest,
            nature=coverage.NO_DATA))
        return assets, gaps

    files = sorted(directory.glob("*.json"))
    if not files:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"{display_path(directory, root)}/ is empty — no ssh-audit JSON exports yet",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("The folder for the SSH audit is in place and empty, so nothing here "
                    "says whether remote administrative access to the servers is "
                    "encrypted to a current standard."),
            harvest=harvest,
            nature=coverage.NO_DATA))
        return assets, gaps

    for path in files:
        struct = _safe_json(path.read_text())
        if struct is None:
            gaps.append(coverage.gap(
                coverage.COULD_NOT_TEST,
                f"{display_path(path, root)} — not parseable ssh-audit JSON, skipped",
                impact_kind=coverage.NARROWS_CONFIDENCE,
                impact=("One machine's SSH audit could not be read, so that machine is "
                        "absent from the administrative-access figures. Every other "
                        "machine's result stands."),
                harvest="Re-export that one file.",
                nature=coverage.NO_DATA))
            continue
        host, port = split_target(str(struct.get("target") or ""))
        asset = _asset_from_struct(struct, host or path.stem, port or "22")
        mtime = file_mtime_date(path)
        asset.source_class = "private"
        asset.collected_at = mtime or ""
        asset.source_name = (f"{INBOX_SOURCE_PREFIX} (internal host, file dated {mtime})"
                             if mtime else
                             f"{INBOX_SOURCE_PREFIX} (internal host, file date unavailable)")
        assets.append(asset)

    return assets, gaps


# ── inside probe ──

#: The ``scan_targets`` (and ``authorisation``) key for internal SSH hosts.
INSIDE_GROUP = "ssh_inside"
MAX_SSH_BATCHES = 3

INTER_HOST_SECONDS = 2.0
INTER_BATCH_SECONDS = 30.0

INSTRUMENT_SSH_AUDIT = "ssh-audit"
INSTRUMENT_NMAP = "nmap ssh2-enum-algos"
SOURCE_INSIDE_SSH_AUDIT = "Active SSH scan (ssh-audit) — internal host, inside probe"
SOURCE_INSIDE_NMAP = ("Active SSH scan (nmap ssh2-enum-algos; ssh-audit unavailable) — "
                      "internal host, inside probe")

NMAP_LIMITS = ("Measured with nmap's ssh2-enum-algos because ssh-audit was not available. "
               "It reads the algorithm lists the server offers in its key-exchange init, "
               "which is what is graded here. It does NOT read the server's version "
               "banner, host-key sizes or fingerprints, or known vulnerabilities, all of "
               "which ssh-audit reports; those are absent from this row, not clean.")

NMAP_SSH_FLAGS = ("-sT", "-Pn", "--max-retries", "1", "--host-timeout", "60s")
NMAP_SSH_SCRIPT = "ssh2-enum-algos"
NMAP_RUN_TIMEOUT = 120

#: Entries in a key-exchange list that are protocol signals, not algorithms
#: (RFC 8308 extension negotiation, and OpenSSH's strict key exchange).
KEX_SIGNALS = frozenset({
    "ext-info-s", "ext-info-c",
    "kex-strict-s-v00@openssh.com",
    "kex-strict-c-v00@openssh.com",
})

_NMAP_PORT = re.compile(r"^(\d{1,5})/tcp\s+(\S+)")
_NMAP_SECTION = re.compile(r"^\|\s{1,3}(\w+):\s*\((\d+)\)\s*$")
_NMAP_ITEM = re.compile(r"^\|[_ ]\s{3,}(\S+)\s*$")


@dataclass(frozen=True)
class InsideHost:
    """One host to probe, with the batch the operator put it in."""

    host: str
    port: str
    batch: str


def _port_of(entry: dict, where: str) -> str:
    raw = entry.get("port", 22)
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 65535:
        raise inside_scope.InsideRefused(
            f"{where}: port {raw!r} is not one TCP port number. Ranges and lists are "
            "refused by construction")
    return str(raw)


def build_inside_plan(target: dict) -> list[list[InsideHost]] | None:
    """The inside batches, or None when the profile declares none.

    Raises :class:`~takestock.inside_scope.InsideRefused` for anything it
    will not run: no authorisation, an entry without a batch, a bad port, a
    duplicate, or a batch or batch count over its ceiling.
    """
    if not inside_scope.declared(target, INSIDE_GROUP):
        return None
    where = f"`scan_targets.{INSIDE_GROUP}`"
    batches: dict[str, list[InsideHost]] = {}
    for i, entry in enumerate(inside_scope.entries(target, INSIDE_GROUP)):
        label = f"{where}[{i}]"
        if not isinstance(entry, dict):
            raise inside_scope.InsideRefused(
                f"{label}: each entry is a mapping naming a `host` and a `batch` — the "
                "batch is named by the operator, never assigned by the tool")
        host, _name = inside_scope.entry_address(entry, label)
        batch = str(entry.get("batch") or "").strip()
        if not batch:
            raise inside_scope.InsideRefused(f"{label}: names no `batch:`")
        port = _port_of(entry, label)
        batches.setdefault(batch, []).append(InsideHost(host, port, batch))
    inside_scope.check_unique(((h.host, h.port) for b in batches.values() for h in b), where)
    for name, hosts in batches.items():
        inside_scope.check_ceiling(len(hosts), MAX_HOSTS, f"{where}: batch {name!r}")
    inside_scope.check_ceiling(len(batches), MAX_SSH_BATCHES, where, "batches")
    return list(batches.values())


def inside_budget_lines(plan: list[list[InsideHost]], instrument: str) -> list[str]:
    """Every host, by batch, printed before anything is contacted."""
    out = ["ssh_audit (inside): PROBE BUDGET — every host, by batch, before anything runs",
           f"  hosts           : {sum(len(b) for b in plan)} in {len(plan)} batch(es) "
           f"(ceiling {MAX_HOSTS} per batch, {MAX_SSH_BATCHES} batches)",
           f"  instrument      : {instrument or 'none available — placeholders only'}",
           f"  method          : one connection per host, hosts one at a time, "
           f"{INTER_HOST_SECONDS:g}s between hosts, {INTER_BATCH_SECONDS:g}s between batches; "
           "no login attempted"]
    for batch in plan:
        out.append(f"  batch {batch[0].batch}:")
        out += [f"      {h.host}:{h.port}" for h in batch]
    return out


def _nmap_command(host: str, port: str) -> list[str]:
    family = ["-6"] if is_ipv6_literal(host) else []
    return ["nmap", *NMAP_SSH_FLAGS, *family, "-p", str(int(port)),
            "--script", NMAP_SSH_SCRIPT, scan_address(host)]


def parse_nmap_ssh2(out: str) -> tuple[str, dict[str, list[str]], list[str]]:
    """(port state, algorithm lists by section, problems) from ``ssh2-enum-algos``.

    A problem is a section whose item count differs from the count nmap
    printed in its heading.
    """
    state = ""
    sections: dict[str, list[str]] = {}
    declared: dict[str, int] = {}
    current = ""
    if out.startswith(ERROR_PREFIX):
        return "", {}, []
    for line in out.splitlines():
        pm = _NMAP_PORT.match(line.strip())
        if pm:
            state = pm.group(2)
            continue
        sm = _NMAP_SECTION.match(line)
        if sm:
            current = sm.group(1)
            sections[current] = []
            declared[current] = int(sm.group(2))
            continue
        im = _NMAP_ITEM.match(line)
        if im and current:
            sections[current].append(im.group(1))
            continue
        if not line.startswith("|"):
            current = ""
    problems = [f"{name}: nmap listed {declared[name]}, {len(items)} read"
                for name, items in sections.items() if len(items) != declared[name]]
    return state, sections, problems


def _inside_asset(h: InsideHost, instrument: str, source_name: str,
                  ref_time: datetime | None) -> CryptoAsset:
    return CryptoAsset(name=f"SSH {h.host}:{h.port}", role=roles.ssh_service(h.host),
                       data_state="in-transit", protocol="ssh", host=h.host, port=h.port,
                       source=SOURCE, internet_facing=False, source_class="private",
                       source_name=source_name, collected_at=now_date(ref_time),
                       extra={"ssh_instrument": instrument, "ssh_batch": h.batch})


def asset_from_nmap(h: InsideHost, out: str, ref_time: datetime | None = None,
                    inside: bool = True) -> tuple[CryptoAsset | None, str]:
    """(row, failure) from one ``ssh2-enum-algos`` run; no port table is a failure."""
    label = f"{SOURCE} (inside)" if inside else SOURCE
    state, sections, problems = parse_nmap_ssh2(out)
    if not state:
        return None, (f"{label} {h.host}:{h.port}: nmap produced no port table, "
                      "so this host was NOT measured")
    a = _inside_asset(h, INSTRUMENT_NMAP, SOURCE_INSIDE_NMAP if inside else SOURCE_ACTIVE_NMAP,
                      ref_time)
    if not inside:
        a.internet_facing, a.source_class = True, "public"
        a.extra.pop("ssh_batch", None)
    a.extra["nmap_state"] = state
    if state == "open" and sections.get("kex_algorithms"):
        kex = sections.get("kex_algorithms", [])
        a.extra.update({
            "ssh_hostkey": sorted(set(sections.get("server_host_key_algorithms", []))),
            "ssh_kex": sorted({k for k in kex if k not in KEX_SIGNALS}),
            "ssh_kex_signals": sorted({k for k in kex if k in KEX_SIGNALS}),
            "ssh_mac": sorted(set(sections.get("mac_algorithms", []))),
            "ssh_compression": sections.get("compression_algorithms", []),
        })
        a.symmetric = sorted(set(sections.get("encryption_algorithms", [])))
        a.notes = NMAP_LIMITS + (f" nmap's report disagreed with itself ({'; '.join(problems)})."
                                 if problems else "")
        return a, ""
    a.verdict = "unknown"
    if state == "open":
        a.notes = (f"Port {h.port} is open but answered no SSH key exchange to nmap's "
                   "ssh2-enum-algos, so it is not measured as SSH. Something else may "
                   "listen there.")
    elif state == "closed":
        a.verdict = NA_VERDICT
        a.notes = (f"nmap reported {h.port}/tcp closed: the host answered and refused, so "
                   "no SSH service listens on this port from where the probe ran. Not a "
                   "finding.")
    else:
        a.notes = (f"nmap reported {h.port}/tcp {state}: no answer, so whether SSH listens "
                   "here is NOT measured. A coverage gap, not a clean result.")
    return a, ""


def _settle(seconds: float) -> None:
    time.sleep(seconds)


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def collect_inside(target: dict, raw_dir: Path | None = None,
                   ref_time: datetime | None = None,
                   announce: Callable[[str], None] | None = None
                   ) -> tuple[list[CryptoAsset], list[str]]:
    """Probe the internal SSH hosts batch by batch; return (assets, failures)."""
    try:
        plan = build_inside_plan(target)
    except inside_scope.InsideRefused as exc:
        return [], [inside_scope.refusal(f"{SOURCE} (inside)", exc)]
    if not plan:
        return [], []

    binary = _binary()
    nmap = None if binary else shutil.which("nmap")
    instrument = INSTRUMENT_SSH_AUDIT if binary else (INSTRUMENT_NMAP if nmap else "")
    say = _announce if announce is None else announce
    lines = inside_budget_lines(plan, instrument)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "ssh-inside-budget.txt").write_text("\n".join(lines) + "\n")

    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for b, batch in enumerate(plan):
        if b:
            _settle(INTER_BATCH_SECONDS)
        for n, h in enumerate(batch):
            if n:
                _settle(INTER_HOST_SECONDS)
            if binary:
                a = _probe(binary, h.host, h.port, raw_dir, ref_time)
                a.source_class, a.internet_facing = "private", False
                a.source_name = SOURCE_INSIDE_SSH_AUDIT
                a.extra.update({"ssh_instrument": INSTRUMENT_SSH_AUDIT, "ssh_batch": h.batch})
                assets.append(a)
            elif nmap:
                out = run(_nmap_command(h.host, h.port), timeout=NMAP_RUN_TIMEOUT)
                if raw_dir:
                    (raw_dir / f"nmap-ssh2-{h.host}-{h.port}.txt").write_text(out)
                asset, failure = asset_from_nmap(h, out, ref_time)
                if asset is not None:
                    assets.append(asset)
                if failure:
                    failures.append(failure)
            else:
                a = _inside_asset(h, "", SOURCE_NOT_PERFORMED, ref_time)
                a.verdict, a.source_class = "unknown", "unknown"
                a.notes = (f"Not measured: neither ssh-audit (set {BINARY_ENV}) nor nmap "
                           "is available, so no probe was sent.")
                assets.append(a)
    return assets, failures
