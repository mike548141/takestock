"""Remote desktop (RDP) security layer on named internal hosts.

An inside probe: it reads ``scan_targets.rdp_3389`` and needs its own
``authorisation.rdp_3389`` record (:mod:`takestock.inside_scope`). For each
named host and port it runs nmap's ``rdp-enum-encryption`` script, which
offers each RDP security layer in turn and records which the server accepts.

The question is whether **network-level authentication** (NLA, which runs
CredSSP before a session exists) is enforced:

* the server accepts native RDP security or plain TLS: not enforced, so a
  login screen is shown to anyone before they authenticate: ``weak``;
* only CredSSP is accepted: enforced: ``acceptable`` (never ``strong``,
  because the TLS underneath is not measured here);
* no negotiation data: ``unknown``.

Native RDP security's own ciphers (RC4 at 40, 56 or 128 bits, or the 3DES
"FIPS" method) are recorded as symmetric tokens and graded too.

It never sends a credential or attempts a login.
"""

from __future__ import annotations

import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles
from ..identity import row_identity
from ..inside_scope import MAX_HOSTS
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..util import ERROR_PREFIX, is_ipv6_literal, now_date, run, scan_address

SOURCE = "rdp_scan"
SOURCE_NAME = "Active remote desktop scan (nmap) — inside the network"

#: The ``scan_targets`` (and ``authorisation``) key for this probe.
TARGET_GROUP = "rdp_3389"
DEFAULT_PORT = 3389
SCRIPT = "rdp-enum-encryption"

NLA_NOT_ENFORCED = "rdp-nla-not-enforced"
STANDARD_SECURITY_ACCEPTED = "rdp-standard-security-accepted"
#: Prefix for every limit on what the probe learned.
INCONCLUSIVE = "rdp-scan-inconclusive:"

register_informational_prefixes(INCONCLUSIVE)

# rdp-enum-encryption's layer labels to short names.
LAYERS: dict[str, str] = {
    "Native RDP": "native-rdp",
    "SSL": "tls",
    "CredSSP (NLA)": "credssp",
    "CredSSP with Early User Auth": "credssp-early-user-auth",
    "RDSTLS": "rdstls",
}
PRE_AUTH_LAYERS = ("native-rdp", "tls")
NLA_LAYERS = ("credssp", "credssp-early-user-auth")

# Native RDP encryption methods to (baseline symmetric token, key bits).
NATIVE_METHODS: dict[str, tuple[str, int]] = {
    "40-bit RC4": ("rc4", 40),
    "56-bit RC4": ("rc4", 56),
    "128-bit RC4": ("rc4", 128),
    "FIPS 140-1": ("3des", 0),
}

TLS_DETAIL_UNMEASURED = (
    "not measured — nmap's ssl-cert script cannot negotiate RDP's X.224 preamble, "
    "so the certificate, TLS versions and cipher suites on this port are unread")


@dataclass
class RdpReading:
    """What the script printed for one host."""

    port_state: str = ""
    script_ran: bool = False
    script_error: str = ""
    unresolved: bool = False
    layers: dict[str, str] = field(default_factory=dict)
    encryption_level: str = ""
    native_methods: list[str] = field(default_factory=list)
    protocol_version: str = ""


_PORT_LINE = re.compile(r"^(\d+)/tcp\s+(\S+)")
_LAYER_LINE = re.compile(r"^\|_?\s{4,}(.+?):\s+(SUCCESS|Unknown)\s*$")
_LEVEL_LINE = re.compile(r"^\|_?\s+RDP Encryption level:\s*(.+?)\s*$")
_VERSION_LINE = re.compile(r"^\|_?\s+RDP Protocol Version:\s*(.+?)\s*$")
_SCRIPT_HEAD = re.compile(rf"^\|(_?){re.escape(SCRIPT)}:\s*(.*?)\s*$")


def parse_rdp_enum(out: str) -> RdpReading:
    """Read ``rdp-enum-encryption`` output: layers, encryption level, native methods."""
    r = RdpReading()
    if "Failed to resolve" in out:
        r.unresolved = True
    section = ""
    for line in out.splitlines():
        pm = _PORT_LINE.match(line)
        if pm:
            r.port_state = pm.group(2)
            continue
        hm = _SCRIPT_HEAD.match(line)
        if hm:
            closing, text = hm.groups()
            if closing and text:
                r.script_error = text
            continue
        if line.strip().lstrip("|_").strip() == "Security layer":
            section, r.script_ran = "layers", True
            continue
        lm = _LEVEL_LINE.match(line)
        if lm:
            section, r.encryption_level = "methods", lm.group(1)
            r.script_ran = True
            continue
        vm = _VERSION_LINE.match(line)
        if vm:
            r.protocol_version = vm.group(1)
            continue
        im = _LAYER_LINE.match(line)
        if im:
            label, state = im.groups()
            if section == "layers" and label in LAYERS:
                r.layers[LAYERS[label]] = "accepted" if state == "SUCCESS" else "unknown"
            elif section == "methods" and label in NATIVE_METHODS and state == "SUCCESS":
                r.native_methods.append(label)
    return r


def nla_state(r: RdpReading) -> str:
    """``not-enforced``, ``enforced`` or ``unknown``.

    A native session negotiated at any encryption level, or a pre-auth layer
    accepted, settles it as not enforced even when other layers are unknown.
    """
    native_negotiated = bool(r.encryption_level)
    if native_negotiated or any(r.layers.get(t) == "accepted" for t in PRE_AUTH_LAYERS):
        return "not-enforced"
    if any(v == "unknown" for v in r.layers.values()):
        return "unknown"
    if any(r.layers.get(t) == "accepted" for t in NLA_LAYERS):
        return "enforced"
    return "unknown"


def nmap_command(host: str, port: int) -> list[str]:
    """The one nmap command sent per entry."""
    family = ["-6"] if is_ipv6_literal(host) else []
    return ["nmap", "-Pn", *family, "-p", str(port), "--script", SCRIPT, scan_address(host)]


@dataclass(frozen=True)
class RdpTarget:
    """One entry: the address probed, the name reported, and the port."""

    probe: str
    ident: str
    port: int


def declared_targets(target: dict) -> list[RdpTarget]:
    """The authorised entries, or :class:`~takestock.inside_scope.InsideRefused`."""
    where = f"`scan_targets.{TARGET_GROUP}`"
    entries = inside_scope.entries(target, TARGET_GROUP)
    inside_scope.check_ceiling(len(entries), MAX_HOSTS, where)
    out: list[RdpTarget] = []
    for i, entry in enumerate(entries):
        label = f"{where}[{i}]"
        probe, ident = inside_scope.entry_address(entry, label)
        raw_port = entry.get("port", DEFAULT_PORT) if isinstance(entry, dict) else DEFAULT_PORT
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) \
                or not 0 < raw_port < 65536:
            raise inside_scope.InsideRefused(f"{label}: port {raw_port!r} is not one port number")
        out.append(RdpTarget(probe=probe, ident=ident, port=raw_port))
    inside_scope.check_unique(((t.probe, t.port) for t in out), where)
    return out


def _base(t: RdpTarget, ref_time: datetime | None, source_class: str,
          source_name: str) -> CryptoAsset:
    return CryptoAsset(
        name=f"RDP {t.ident}:{t.port}", role=roles.remote_desktop_service(t.ident),
        data_state="in-transit", protocol="rdp",
        host=t.ident, ip=row_identity(t.ident, t.probe)[1], port=str(t.port),
        source=SOURCE, internet_facing=False, source_class=source_class,
        source_name=source_name, collected_at=now_date(ref_time))


def _unknown(t: RdpTarget, ref_time: datetime | None, reason: str, why: str,
             source_class: str = "private", source_name: str = SOURCE_NAME) -> CryptoAsset:
    a = _base(t, ref_time, source_class, source_name)
    a.verdict = "unknown"
    a.flags = [f"{INCONCLUSIVE}{reason}"]
    a.notes = why
    return a


def asset_from_reading(t: RdpTarget, r: RdpReading,
                       ref_time: datetime | None = None) -> CryptoAsset:
    """The row for one entry."""
    if r.unresolved:
        return _unknown(t, ref_time, "unresolved",
                        "the host name did not resolve, so nothing was probed")
    if r.port_state == "closed":
        a = _base(t, ref_time, "private", SOURCE_NAME)
        a.verdict = NA_VERDICT
        a.notes = (f"nothing listening on {t.port}: the host answered and refused the "
                   "connection — not a finding")
        return a
    if r.port_state and r.port_state != "open":
        return _unknown(t, ref_time, "no-answer",
                        f"port {t.port} {r.port_state}: nothing answered, so whether a "
                        "remote desktop service is there is unknown, not absent")
    if not r.port_state:
        return _unknown(t, ref_time, "no-answer",
                        "nmap reported no state for the port, so nothing was learned")
    if not r.script_ran:
        detail = f" ({r.script_error})" if r.script_error else ""
        return _unknown(t, ref_time, "no-rdp-negotiation",
                        f"something is listening on {t.port} but it did not complete a "
                        f"remote desktop negotiation{detail}")

    state = nla_state(r)
    tokens = sorted({NATIVE_METHODS[m][0] for m in r.native_methods})
    accepted = sorted(k for k, v in r.layers.items() if v == "accepted")
    unknown_layers = sorted(k for k, v in r.layers.items() if v == "unknown")
    flags: set[str] = set()
    native = bool(r.encryption_level) or r.layers.get("native-rdp") == "accepted"
    if state == "not-enforced":
        flags.add(NLA_NOT_ENFORCED)
    if native:
        flags.add(STANDARD_SECURITY_ACCEPTED)
    if unknown_layers and not r.encryption_level:
        flags.add(f"{INCONCLUSIVE}no-negotiation-data")

    notes: list[str] = []
    if state == "not-enforced":
        via = []
        if native:
            via.append("native RDP security")
        if r.layers.get("tls") == "accepted":
            via.append("plain TLS")
        notes.append(f"network-level authentication NOT enforced: the server accepts "
                     f"{' and '.join(via)}, so a login screen is shown before the caller "
                     "has authenticated")
    elif state == "enforced":
        notes.append("network-level authentication enforced: only CredSSP was accepted; "
                     "native RDP and plain TLS were refused")
    else:
        notes.append("network-level authentication could not be determined: the server "
                     "returned no negotiation data for the layers offered")
    if r.native_methods:
        notes.append(f"native encryption methods offered: {', '.join(r.native_methods)} "
                     f"(level {r.encryption_level})")
    elif r.encryption_level:
        notes.append(f"native RDP negotiated at level {r.encryption_level}, "
                     "no method accepted")
    notes.append("TLS detail on this port not measured")

    a = _base(t, ref_time, "private", SOURCE_NAME)
    a.verdict = {"not-enforced": "weak", "enforced": "acceptable"}.get(state, "unknown")
    a.symmetric = tokens
    a.flags = sorted(flags)
    a.notes = "; ".join(notes)
    a.extra = {
        "rdp_security_layers_accepted": accepted,
        "rdp_security_layers_unknown": unknown_layers,
        "rdp_nla": state,
        "rdp_encryption_level": r.encryption_level,
        "rdp_native_methods": list(r.native_methods),
        "rdp_protocol_version": r.protocol_version,
        "rdp_tls_detail": TLS_DETAIL_UNMEASURED,
    }
    return a


def budget_lines(targets: list[RdpTarget]) -> list[str]:
    """Every entry and what will be sent to it, printed before anything runs."""
    return [
        f"[rdp_scan] probe budget — {len(targets)} entr{'y' if len(targets) == 1 else 'ies'} "
        f"(ceiling {MAX_HOSTS}), one named port each",
        f"  method   : one `nmap -Pn -p <port> --script {SCRIPT}` per entry, one at a time",
        "  never    : a credential, a login, rdp-ntlm-info, or any vulnerability script",
        *(f"  host     : {t.probe}:{t.port}"
          + (f" ({t.ident})" if t.ident != t.probe else "") for t in targets),
    ]


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _probe(t: RdpTarget, raw_dir: Path | None, ref_time: datetime | None) -> CryptoAsset:
    out = run(nmap_command(t.probe, t.port), timeout=180)
    if raw_dir:
        (raw_dir / f"nmap-rdp-{t.probe}-{t.port}.txt").write_text(out)
    if out.startswith(ERROR_PREFIX):
        return _unknown(t, ref_time, "nmap-failed",
                        f"nmap could not run: {out[len(ERROR_PREFIX):].strip()}")
    return asset_from_reading(t, parse_rdp_enum(out), ref_time)


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None,
            announce: Callable[[str], None] | None = None
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every authorised RDP entry; return (assets, failures)."""
    try:
        targets = declared_targets(target)
    except inside_scope.InsideRefused as exc:
        return [], [inside_scope.refusal(SOURCE, exc)]
    if not targets:
        return [], []
    say = _announce if announce is None else announce
    lines = budget_lines(targets)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "nmap-rdp-budget.txt").write_text("\n".join(lines) + "\n")
    if not shutil.which("nmap"):
        return ([_unknown(t, ref_time, "nmap-unavailable",
                          "nmap not found on PATH, so this host was not probed",
                          "unknown", "Remote desktop scan not performed — nmap unavailable")
                 for t in targets],
                ["rdp_scan: nmap not found on PATH — no remote desktop host was probed"])
    return [_probe(t, raw_dir, ref_time) for t in targets], []
