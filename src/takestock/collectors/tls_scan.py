"""Active TLS scan of the organisation's published HTTPS endpoints.

For each endpoint the target profile authorises (remote-access gateways,
published web and mail hosts, and third-party services listed under
``saas_443``) this collector:

1. enumerates protocol versions and cipher suites with nmap's
   ``ssl-enum-ciphers`` script;
2. confirms each version from TLS 1.0 to 1.3 with a pinned ``openssl
   s_client`` handshake, because ``ssl-enum-ciphers`` cannot enumerate
   TLS 1.3 (see :mod:`takestock.tls_session` for how a handshake is read);
3. makes one default handshake to read the key-exchange group actually
   chosen (:mod:`takestock.tls_negotiate`);
4. reads the certificate with nmap's ``ssl-cert`` script for its key,
   signature algorithm, names and expiry.

Raw transcripts are written beside the observation when a directory is
given, with session secrets redacted (:func:`redact_transcript`).

Without nmap the scan does not run at all, and the run records one failure
saying so; an endpoint is never reported as silent because a tool was
missing. An nmap run that fails for one endpoint (a timeout, say) gives that
endpoint an unmeasured row and a failure line, never "no TLS response".
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles, tls_negotiate, tls_session
from ..model import CryptoAsset, cert_expiry_flag, register_informational_prefixes
from ..tls_session import COULD_NOT_ASK, OFFERED, REFUSED, TlsSession
from ..util import (
    ERROR_PREFIX,
    cert_signature_token,
    days_remaining,
    is_ipv6_literal,
    now_date,
    parse_cert_time,
    run,
    scan_address,
)

SOURCE = "tls_scan"
SOURCE_NAME = "Active TLS scan (nmap) — internet-facing endpoint"

_SUITE_LINE = re.compile(r"^\|\s+(TLS_\w+)(?:\s+\(([^)]*)\))?")

# Key-exchange group names as nmap and openssl print them, to baseline tokens.
_NAMED_GROUPS = {
    "secp192r1": "ecdh_p192", "secp224r1": "ecdh_p224", "secp256r1": "ecdh_p256",
    "secp384r1": "ecdh_p384", "secp521r1": "ecdh_p521",
    "ecdh_x25519": "x25519", "x25519": "x25519", "ecdh_x448": "x448", "x448": "x448",
    "x25519mlkem768": "x25519mlkem768", "secp256r1mlkem768": "secp256r1mlkem768",
    "mlkem1024": "mlkem1024", "x25519kyber768": "x25519kyber768",
}


def normalise_tls_group(group: str) -> str:
    """A key-exchange group as a baseline ``key_exchange`` token.

    ``secp256r1`` gives ``ecdh_p256``; ``dh 2048`` gives ``dh_2048``; ``rsa
    2048`` (static RSA key transport) gives ``rsa``. Unknown names are
    lower-cased with punctuation folded to ``_`` so the grader can flag them.
    """
    g = group.strip().lower()
    if not g:
        return ""
    if g in _NAMED_GROUPS:
        return _NAMED_GROUPS[g]
    m = re.fullmatch(r"(dh|rsa|ecdh)\s+(\d+)", g)
    if m:
        kind, bits = m.groups()
        if kind == "rsa":
            return "rsa"
        return f"{kind}_{bits}"
    return re.sub(r"[^a-z0-9_]+", "_", g)


def parse_enum_ciphers(out: str) -> dict:
    """Versions, suites, key-exchange groups and least-strength grade from ``ssl-enum-ciphers``."""
    versions: list[str] = []
    suites: set[str] = set()
    groups: set[str] = set()
    for line in out.splitlines():
        vm = re.search(r"^\|\s+(TLSv1\.\d|SSLv\d):", line)
        if vm:
            versions.append(vm.group(1))
            continue
        sm = _SUITE_LINE.search(line)
        if sm:
            suites.add(sm.group(1))
            if sm.group(2):
                tok = normalise_tls_group(sm.group(2))
                if tok:
                    groups.add(tok)
    strength = re.search(r"least strength:\s*([A-F])", out)
    return {"versions": sorted(set(versions)), "suites": sorted(suites),
            "key_exchange": sorted(groups), "grade": strength.group(1) if strength else None}


_VERSION_PROBES = (("-tls1", "TLSv1.0"), ("-tls1_1", "TLSv1.1"),
                   ("-tls1_2", "TLSv1.2"), ("-tls1_3", "TLSv1.3"))

#: Flag: at least one version could not be asked about, so it is unknown, not absent.
VERSION_PROBE_UNAVAILABLE = "tls-version-probe-unavailable"

register_informational_prefixes(VERSION_PROBE_UNAVAILABLE)

# Transcript redaction. An ``s_client`` transcript carries the session's
# secrets (master key, resumption material, session tickets), which are not
# evidence and must not be kept. Single-line fields are blanked in place;
# labelled multi-line blocks are either secret (dropped), known to be safe
# (kept), or unrecognised, in which case they are kept and marked so a
# reader sees that a new block appeared and decides which list it belongs in.
_SESSION_SECRET_FIELDS = ("Master-Key", "Session-ID", "Session-ID-ctx", "PSK identity",
                          "PSK identity hint", "SRP username", "Resumption PSK")
_SECRET_LINE_RE = re.compile(
    rf"^(\s*(?:{'|'.join(re.escape(f) for f in _SESSION_SECRET_FIELDS)})\s*:\s*)(\S.*)$")

#: Multi-line blocks whose content is key material.
SECRET_BLOCK_LABELS = ("TLS session ticket", "Session ticket", "Master-Key",
                       "Resumption PSK", "PSK identity")

#: Multi-line blocks known to carry nothing secret of their own.
PASSTHROUGH_BLOCK_LABELS = ("SSL-Session",)

_BLOCK_LABEL_RE = re.compile(r"^(\s*)([A-Za-z][A-Za-z0-9 ._/+-]*?)\s*:\s*$")

_HEXDUMP_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]{4,}\s+-\s")

_INDENT_RE = re.compile(r"^(\s*)\S")

UNRECOGNISED_BLOCK_MARKER = "<takestock: UNRECOGNISED multi-line block"

_BLOCK_REDACTION = "<redacted by takestock: session key material (block of {n} lines)>"


def _indent_of(line: str) -> int:
    m = _INDENT_RE.match(line)
    return len(m.group(1)) if m else -1


def _is_continuation(line: str, label_indent: int) -> bool:
    if not line.strip():
        return False
    return bool(_HEXDUMP_LINE_RE.match(line)) or _indent_of(line) > label_indent


def redact_transcript(text: str) -> str:
    """``text`` with session secrets removed and unknown blocks marked."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        label_match = _BLOCK_LABEL_RE.match(line)
        if (label_match and i + 1 < len(lines)
                and _is_continuation(lines[i + 1], len(label_match.group(1)))):
            indent, label = len(label_match.group(1)), label_match.group(2)
            if label in SECRET_BLOCK_LABELS:
                j = i + 1
                while j < len(lines) and _is_continuation(lines[j], indent):
                    j += 1
                out.append(line)
                out.append(" " * indent + _BLOCK_REDACTION.format(n=j - i - 1))
                i = j
                continue
            if label not in PASSTHROUGH_BLOCK_LABELS and not _already_marked(out):
                out.append(" " * indent + _marker(label))
            out.append(line)
            i += 1
            continue
        # A hex dump with no label above it: keep it, but say so.
        if _HEXDUMP_LINE_RE.match(line) and not (
                i and (_HEXDUMP_LINE_RE.match(lines[i - 1])
                       or _BLOCK_LABEL_RE.match(lines[i - 1]))):
            if not _already_marked(out):
                out.append(" " * _indent_of(line) + _marker("(no label)"))
            while i < len(lines) and _HEXDUMP_LINE_RE.match(lines[i]):
                out.append(lines[i])
                i += 1
            continue
        out.append(_SECRET_LINE_RE.sub(
            r"\1<redacted by takestock: session key material>", line))
        i += 1
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _already_marked(out: list[str]) -> bool:
    return bool(out) and UNRECOGNISED_BLOCK_MARKER in out[-1]


def _marker(label: str) -> str:
    return (f'{UNRECOGNISED_BLOCK_MARKER} "{label}" passed through unredacted — '
            "declare it in tls_scan.SECRET_BLOCK_LABELS or "
            "PASSTHROUGH_BLOCK_LABELS and re-run>")


def probe_versions(host: str, port: int, sni: str = "",
                   raw_dir: Path | None = None, starttls: str = "",
                   transcripts: dict[str, str] | None = None) -> dict[str, TlsSession]:
    """Pin each version from TLS 1.0 to 1.3 in turn and read the answer.

    ``starttls`` names an ``s_client -starttls`` protocol (``smtp``) for a
    port that upgrades in band. Raw transcripts go to ``transcripts`` when a
    dict is given, and (redacted) to ``raw_dir``.
    """
    addr = scan_address(host)
    connect = f"[{addr}]:{port}" if is_ipv6_literal(host) else f"{addr}:{port}"
    servername = ["-servername", sni] if sni and not _looks_like_address(sni) else []
    upgrade = ["-starttls", starttls] if starttls else []
    out_by_version: dict[str, TlsSession] = {}
    transcript = []
    for flag, label in _VERSION_PROBES:
        out = run(["openssl", "s_client", "-connect", connect, *servername, *upgrade, flag],
                  timeout=20, stdin_text="")
        out_by_version[label] = tls_session.read_session(out, label)
        if transcripts is not None:
            transcripts[label] = out
        transcript.append(f"===== {flag} ({label})\n{out}")
    if raw_dir:
        (raw_dir / f"openssl-versions-{host}-{port}.txt").write_text(
            redact_transcript("\n".join(transcript)))
    return out_by_version


def _looks_like_address(host: str) -> bool:
    return is_ipv6_literal(host) or bool(re.fullmatch(r"[0-9.]+", host.strip()))


def merge_versions(nmap_versions: list[str],
                   probed: Mapping[str, TlsSession]) -> tuple[list[str], str, set[str]]:
    """Combine nmap's version list with the pinned handshakes.

    Returns (versions, note, flags). A version a handshake confirmed is
    added; a version nmap listed but the handshake refused is kept and noted;
    a version that could not be asked about is flagged as unknown.
    """
    versions = set(nmap_versions)
    gained = {v for v in tls_session.versions_in_state(probed, OFFERED) if v not in versions}
    conflicts = {v for v in tls_session.versions_in_state(probed, REFUSED) if v in versions}
    unknown = tls_session.versions_in_state(probed, COULD_NOT_ASK)
    versions |= gained

    bits = []
    if gained:
        bits.append(f"{', '.join(sorted(gained))} confirmed by handshake "
                    f"(nmap's ssl-enum-ciphers cannot enumerate TLS 1.3)")
    if conflicts:
        bits.append(f"{', '.join(sorted(conflicts))} enumerated by nmap but the "
                    f"handshake probe was refused — kept, and worth a second look")
    flags: set[str] = set()
    if unknown:
        flags.add(VERSION_PROBE_UNAVAILABLE)
        bits.append(tls_session.unknown_note(probed))
    return sorted(versions), "; ".join(bits), flags


NO_TLS_RESPONSE = "no TLS response / port closed / filtered"
_NMAP_PORT_LINE = re.compile(r"^(\d+)/tcp\s+(\S+)", re.M)


def no_tls_notes(out: str, port: int) -> str:
    """Why nmap found no TLS: an open port that did not speak it, a closed port, or no answer."""
    states = {int(m.group(1)): m.group(2) for m in _NMAP_PORT_LINE.finditer(out or "")}
    state = states.get(port, "")
    if state == "open":
        return (f"port {port} open, but no TLS handshake: nmap's ssl-enum-ciphers found no "
                "TLS there, so something is listening that did not speak TLS")
    if state == "closed":
        return f"port {port} closed: the host answered and refused the connection; no TLS"
    return NO_TLS_RESPONSE


#: How the note for an endpoint whose nmap run did not complete begins.
SCAN_FAILED = "the nmap scan did not complete"


def scan_failed_note(out: str) -> str:
    """The note for an endpoint whose nmap run did not complete."""
    reason = out.removeprefix(ERROR_PREFIX).strip() or "no reason given"
    return (f"{SCAN_FAILED} ({reason}), so this endpoint is UNMEASURED: this is not "
            "evidence of a closed, filtered or silent port")


def _scan_host(host: str, port: int = 443, raw_dir: Path | None = None,
               ref_time: datetime | None = None, role: str = "",
               ident: str = "") -> CryptoAsset:
    ident = ident or host
    family = ["-6"] if is_ipv6_literal(host) else []
    out = run(["nmap", "-Pn", *family, "-p", str(port), "--script", "ssl-enum-ciphers",
               scan_address(host)], timeout=180)
    if raw_dir:
        (raw_dir / f"nmap-tls-{host}-{port}.txt").write_text(out)
    if "ssl-enum-ciphers" not in out:
        return CryptoAsset(name=f"TLS {ident}:{port}", role=role,
                           data_state="in-transit", protocol="tls",
                           host=ident, ip=host if ident != host else "",
                           port=str(port), source=SOURCE, internet_facing=True,
                           source_class="public", source_name=SOURCE_NAME,
                           collected_at=now_date(ref_time),
                           verdict="unknown",
                           notes=(scan_failed_note(out) if out.startswith(ERROR_PREFIX)
                                  else no_tls_notes(out, port)))

    parsed = parse_enum_ciphers(out)
    probed = probe_versions(host, port, ident, raw_dir)
    versions, version_note, version_flags = merge_versions(parsed["versions"], probed)
    notes = [f"nmap least-strength grade {parsed['grade']}"] if parsed["grade"] else []
    if version_note:
        notes.append(version_note)
    asset = CryptoAsset(
        name=f"TLS {ident}:{port}", role=role, data_state="in-transit", protocol="tls",
        host=ident, ip=host if ident != host else "",
        port=str(port), source=SOURCE, internet_facing=True,
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        protocol_versions=versions,
        key_exchange=parsed["key_exchange"],
        symmetric=parsed["suites"],
        flags=sorted(version_flags),
        notes="; ".join(notes),
        extra={
            "nmap_grade": parsed["grade"],
            "versions_enumerated": ", ".join(parsed["versions"]),
            "version_probe": tls_session.describe(probed),
        },
    )
    attach_negotiation(asset, host, port, ident, raw_dir)
    attach_cert_detail(asset, host, port, raw_dir, ref_time)
    return asset


#: The default-handshake reader; tests replace it so nothing is contacted.
negotiate: Callable[[str, int, str], tls_negotiate.Negotiation | None] = \
    tls_negotiate.negotiate


def attach_negotiation(asset: CryptoAsset, host: str, port: int, ident: str,
                       raw_dir: Path | None) -> None:
    """Record the default handshake on ``asset``.

    The chosen group is added to ``key_exchange`` only when the client
    offered a post-quantum group: a classical choice from a classical offer
    shows only what the client asked for, and nmap already enumerated the
    classical groups.
    """
    sni = ident if ident and not _looks_like_address(ident) else ""
    n = negotiate(scan_address(host), port, sni)
    if n is None:
        return
    asset.extra.update(n.extra())
    if raw_dir:
        (raw_dir / f"tls-negotiated-{host}-{port}.json").write_text(
            json.dumps(n.extra(), indent=1) + "\n")
    if n.error or not n.group or not n.pq_offered:
        return
    tok = normalise_tls_group(tls_negotiate.kex_token(n.group))
    if tok and tok not in asset.key_exchange:
        asset.key_exchange = sorted([*asset.key_exchange, tok])


def parse_ssl_cert(out: str) -> dict | None:
    """The fields takestock keeps from nmap's ``ssl-cert`` output, or None."""
    if "ssl-cert" not in out:
        return None
    nvb = re.search(r"Not valid before:\s*(\S+)", out)
    nva = re.search(r"Not valid after:\s*(\S+)", out)
    if not (nvb and nva):
        return None
    pk_type = re.search(r"Public Key type:\s*(\S+)", out)
    pk_bits = re.search(r"Public Key bits:\s*(\d+)", out)
    sig_alg = re.search(r"Signature Algorithm:\s*(\S+)", out)
    issuer = re.search(r"\|\s*Issuer:\s*(.+?)(?=\n\|)", out, re.DOTALL)
    return {
        "not_before": nvb.group(1),
        "not_after": nva.group(1),
        "pubkey_type": pk_type.group(1) if pk_type else "",
        "pubkey_bits": int(pk_bits.group(1)) if pk_bits else None,
        "signature_algorithm": sig_alg.group(1) if sig_alg else "",
        "issuer": re.sub(r"\s+", " ", issuer.group(1)).strip() if issuer else "",
        "subject_alt_names": parse_subject_alt_names(out),
    }


_SAN_TYPES = re.compile(r"(?:DNS|IP Address|email|URI):([^,\s]+)")


def parse_subject_alt_names(out: str) -> list[str]:
    """The certificate's subject alternative names, lower-cased and de-duplicated."""
    block = re.search(r"\|\s*Subject Alternative Name:\s*(.+?)(?=\n\s*\||\n\n|\Z)",
                      out, re.DOTALL)
    if not block:
        return []
    return sorted({n.strip().lower() for n in _SAN_TYPES.findall(block.group(1)) if n.strip()})


def attach_cert_detail(asset: CryptoAsset, host: str, port: int, raw_dir: Path | None,
                       ref_time: datetime | None) -> None:
    """Read the certificate on ``host:port`` and record its key, names and expiry."""
    family = ["-6"] if is_ipv6_literal(host) else []
    out = run(["nmap", "-Pn", "-v", *family, "-p", str(port), "--script", "ssl-cert",
               scan_address(host)], timeout=180)
    if raw_dir:
        (raw_dir / f"nmap-cert-{host}-{port}.txt").write_text(out)
    cert = parse_ssl_cert(out)
    if cert is None:
        return

    not_after = parse_cert_time(cert["not_after"])
    not_before = parse_cert_time(cert["not_before"])
    sig = cert_signature_token(cert["pubkey_type"], cert["pubkey_bits"])
    if sig:
        asset.signatures = [sig]

    extra = {
        "cert_not_before": cert["not_before"],
        "cert_not_after": cert["not_after"],
        "cert_issuer": cert["issuer"],
        "cert_signature_algorithm": cert["signature_algorithm"],
    }
    if cert.get("subject_alt_names"):
        extra["cert_san"] = ", ".join(cert["subject_alt_names"])
    note_bits = [asset.notes] if asset.notes else []
    if not_after is not None:
        remaining = days_remaining(not_after, ref_time)
        extra["cert_days_remaining"] = remaining
        lifetime_days = (not_after - not_before).days if not_before else None
        flag = cert_expiry_flag(remaining, lifetime_days)
        if flag == "expired":
            asset.flags = sorted(set(asset.flags) | {"expired"})
            note_bits.append(f"cert expired {not_after.date().isoformat()} ({-remaining}d ago)")
        elif flag == "renewal-overdue":
            asset.flags = sorted(set(asset.flags) | {"renewal-overdue"})
            note_bits.append(
                f"cert renewal OVERDUE: expires {not_after.date().isoformat()} "
                f"({remaining}d remaining) — short-lived certificate past the point its "
                f"automated renewal should already have happened")
        elif flag == "expiry-soon":
            asset.flags = sorted(set(asset.flags) | {"expiry-soon"})
            note_bits.append(f"cert expires {not_after.date().isoformat()} ({remaining}d remaining)")
        else:
            note_bits.append(f"cert expires {not_after.date().isoformat()}")
    asset.extra.update(extra)
    asset.notes = "; ".join(b for b in note_bits if b)


def endpoints(target: dict) -> list[tuple[str, int, str]]:
    """(address to probe, port, name to report) for every endpoint this scan covers."""
    st = target.get("scan_targets", {}) or {}
    hosts: list[tuple[str, int, str]] = []
    for gw in st.get("vpn_gateways", []) or []:
        hosts.append((gw.get("ip") or gw["host"], 443, str(gw.get("host") or "")))
    for h in roles.published_hosts(target):
        hosts.append((h, 443, h))
    for entry in st.get("saas_443", []) or []:
        host = str((entry or {}).get("host") or "").strip()
        if host:
            hosts.append((host, int(entry.get("port") or 443), host))
    return hosts


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Scan every endpoint the target authorises; return (assets, failures)."""
    hosts = endpoints(target)
    if not hosts:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    if not shutil.which("nmap"):
        return [], [f"{SOURCE}: nmap is not on PATH, so the TLS scan did not run against any "
                    f"of the {len(hosts)} authorised endpoint(s). This run holds NO evidence "
                    "about TLS on them; their absence from the results is not a finding."]
    role_by_host = roles.scan_target_roles(target)
    assets = [_scan_host(host, port, raw_dir, ref_time, role_by_host.get(host, ""), ident)
              for host, port, ident in hosts]
    failures = [f"{SOURCE} {a.host}:{a.port}: {a.notes}" for a in assets
                if a.notes.startswith(SCAN_FAILED)]
    return assets, failures
