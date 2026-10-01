"""Active STARTTLS check of the mail gateways that receive the organisation's mail.

Port 25 speaks plain SMTP until the client issues STARTTLS (RFC 3207), so a
direct TLS handshake there fails against a healthy gateway. This collector
asks ``openssl s_client -starttls smtp`` for a session at each version from
TLS 1.0 to 1.3 and reads, per version, whether the gateway agreed and which
suite and key-exchange group it chose.

What it can and cannot conclude:

* A gateway that answers EHLO without advertising STARTTLS is a measured
  cleartext finding: mail delivered to it crosses the network in clear.
* A pinned handshake shows the suite the gateway *chose* at that version,
  not every suite it would accept, so the row says it records a preference
  and not a floor.
* A gateway that could not be reached gives no evidence either way, and the
  run says so as a failure rather than reading as clean.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles, tls_session
from ..config import load_port_encryption
from ..model import CryptoAsset
from ..plaintext import PLAINTEXT_FLAG, apply_posture
from ..tls_session import COULD_NOT_ASK, OFFERED
from ..util import now_date
from . import tls_scan

SOURCE = "smtp_starttls"
SOURCE_NAME = "Active STARTTLS scan (openssl) — internet-facing mail gateway"

#: The ``scan_targets`` group listing the mail gateways.
TARGET_KEY = "smtp_25"
SMTP_PORT = 25

STARTTLS_PROTOCOL = "smtp"

PREFERENCE_ONLY = ("suites shown are what the gateway CHOSE at each version, not "
                   "the full set it accepts — a pinned handshake cannot see a weaker "
                   "suite it would also agree to")

_NO_STARTTLS = re.compile(r"didn't find starttls in server response", re.I)

_TEMP_KEY = re.compile(r"^\s*Server Temp Key:\s*(.+)$", re.M)

_CURVE_ALIASES = {"p192": "secp192r1", "p224": "secp224r1", "p256": "secp256r1",
                  "p384": "secp384r1", "p521": "secp521r1", "prime256v1": "secp256r1"}

#: Flag: the certificate does not carry the name the gateway was reached by.
NAME_MISMATCH_FLAG = "cert-name-mismatch"

# OpenSSL/LibreSSL suite names to IANA names, so suites grade through the
# same baseline rows as nmap's output. TLS 1.3 names as LibreSSL prints them:
_TLS13_SUITES = {
    "AEAD-AES128-GCM-SHA256": "TLS_AES_128_GCM_SHA256",
    "AEAD-AES256-GCM-SHA384": "TLS_AES_256_GCM_SHA384",
    "AEAD-CHACHA20-POLY1305-SHA256": "TLS_CHACHA20_POLY1305_SHA256",
    "AEAD-AES128-CCM-SHA256": "TLS_AES_128_CCM_SHA256",
    "AEAD-AES128-CCM-8-SHA256": "TLS_AES_128_CCM_8_SHA256",
}
_KEX_AUTH = {
    "ECDHE-RSA": "ECDHE_RSA", "ECDHE-ECDSA": "ECDHE_ECDSA",
    "DHE-RSA": "DHE_RSA", "DHE-DSS": "DHE_DSS",
    "ECDH-RSA": "ECDH_RSA", "ECDH-ECDSA": "ECDH_ECDSA",
    "ADH": "DH_ANON", "AECDH": "ECDH_ANON",
}
_BULK = {
    "AES128-GCM": "AES_128_GCM", "AES256-GCM": "AES_256_GCM",
    "AES128-CCM": "AES_128_CCM", "AES256-CCM": "AES_256_CCM",
    "AES128": "AES_128_CBC", "AES256": "AES_256_CBC",
    "CHACHA20-POLY1305": "CHACHA20_POLY1305",
    "CAMELLIA128": "CAMELLIA_128_CBC", "CAMELLIA256": "CAMELLIA_256_CBC",
    "DES-CBC3": "3DES_EDE_CBC", "DES-CBC": "DES_CBC",
    "SEED": "SEED_CBC", "IDEA-CBC": "IDEA_CBC",
    "RC4": "RC4_128", "NULL": "NULL",
}
_MAC_WORDS = {"SHA", "SHA256", "SHA384", "SHA512", "MD5"}


def iana_suite_name(openssl_name: str) -> str:
    """The IANA name for an OpenSSL suite name, or "" when it cannot be placed.

    A name with no key-exchange prefix (``AES128-SHA``) is static RSA key
    transport, the weak reading, so it maps to ``TLS_RSA_WITH_...``.
    """
    name = openssl_name.strip().upper()
    if not name:
        return ""
    if name.startswith("TLS_"):
        return name
    if name in _TLS13_SUITES:
        return _TLS13_SUITES[name]
    parts = name.split("-")
    mac = parts.pop() if parts[-1] in _MAC_WORDS else ""
    kex = ""
    for n in (2, 1):
        if len(parts) > n and "-".join(parts[:n]) in _KEX_AUTH:
            kex, parts = _KEX_AUTH["-".join(parts[:n])], parts[n:]
            break
    bulk = _BULK.get("-".join(parts))
    if not bulk:
        return ""
    if not mac:
        if bulk != "CHACHA20_POLY1305":
            return ""
        mac = "SHA256"
    return f"TLS_{kex or 'RSA'}_WITH_{bulk}_{mac}"


def parse_server_temp_key(out: str) -> str:
    """The key-exchange group from ``Server Temp Key:``, as a baseline token, or ""."""
    m = _TEMP_KEY.search(out)
    if not m:
        return ""
    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
    if not parts:
        return ""
    kind = parts[0].upper()
    if kind.startswith("ECDH") and len(parts) >= 2:
        name = parts[1].strip().lower().replace("-", "")
        return tls_scan.normalise_tls_group(_CURVE_ALIASES.get(name, name))
    if kind.startswith("DH"):
        bits = re.search(r"(\d+)", " ".join(parts[1:]))
        return tls_scan.normalise_tls_group(f"dh {bits.group(1)}") if bits else ""
    return ""


def san_covers(host: str, names: list[str]) -> bool:
    """True when ``names`` covers ``host``; a wildcard matches one label only (RFC 6125)."""
    h = host.strip().lower().rstrip(".")
    for n in names:
        n = n.strip().lower().rstrip(".")
        if n == h:
            return True
        if n.startswith("*.") and h.endswith(n[1:]) and h.count(".") == n.count("."):
            return True
    return False


def measure(host: str, raw_dir: Path | None, ref_time: datetime | None,
            role: str, source: str = SOURCE,
            source_name: str = SOURCE_NAME) -> tuple[CryptoAsset, list[str]]:
    """Probe one gateway; return its row and any failures."""
    transcripts: dict[str, str] = {}
    probed = tls_scan.probe_versions(host, SMTP_PORT, host, raw_dir,
                                     starttls=STARTTLS_PROTOCOL, transcripts=transcripts)
    offered = tls_session.versions_in_state(probed, OFFERED)
    unknown = tls_session.versions_in_state(probed, COULD_NOT_ASK)
    reached = any(s.reached_host for s in probed.values())
    no_starttls = any(_NO_STARTTLS.search(t) for t in transcripts.values())

    suites: list[str] = []
    raw_suites: list[str] = []
    groups: set[str] = set()
    for version in offered:
        out = transcripts.get(version, "")
        cipher = probed[version].cipher
        if cipher:
            raw_suites.append(f"{version}={cipher}")
            suites.append(iana_suite_name(cipher) or cipher)
        group = parse_server_temp_key(out)
        if group:
            groups.add(group)

    flags: set[str] = set()
    if unknown:
        flags.add(tls_scan.VERSION_PROBE_UNAVAILABLE)

    notes = [PREFERENCE_ONLY] if offered else []
    if unknown:
        notes.append(tls_session.unknown_note(probed))

    asset = CryptoAsset(
        name=f"SMTP STARTTLS {host}:{SMTP_PORT}", role=role,
        data_state="in-transit", protocol="tls", host=host, port=str(SMTP_PORT),
        source=source, internet_facing=True,
        source_class="public", source_name=source_name, collected_at=now_date(ref_time),
        protocol_versions=sorted(dict.fromkeys(offered)),
        key_exchange=sorted(groups),
        symmetric=sorted(dict.fromkeys(suites)),
        flags=sorted(flags),
        extra={
            "starttls": "offered" if offered else "no encrypted session established",
            "version_probe": tls_session.describe(probed),
            **({"negotiated_suites": "; ".join(raw_suites)} if raw_suites else {}),
        },
    )

    failures: list[str] = []
    if offered:
        _attach_certificate(asset, host, raw_dir, ref_time)
    elif no_starttls:
        asset.verdict = "weak"
        asset.flags = sorted(set(asset.flags) | {f"{PLAINTEXT_FLAG}smtp"})
        asset.notes = (f"NO ENCRYPTION AVAILABLE — {host} answered EHLO without advertising "
                       "STARTTLS, so mail delivered to this gateway crosses the network in "
                       "clear. Measured, not inferred from the port number.")
    elif not reached:
        failures.append(
            f"{source} {host}: the mail host could not be reached on port "
            f"{SMTP_PORT} ({', '.join(unknown) or 'no version answered'}), so this run "
            "holds NO evidence about the mail path. Absence here is not evidence that "
            "the path is encrypted.")
        _record_unverified(asset, "The probe never reached the gateway, so nothing was "
                                  "observed either way.")
    else:
        _record_unverified(asset, "The gateway answered but completed no handshake at TLS "
                                  "1.0-1.3. That is either a refused STARTTLS command or a "
                                  "refusal of every version pinned, and openssl reports the "
                                  "two identically, so neither is claimed.")

    if notes:
        asset.notes = "; ".join([asset.notes, *notes]) if asset.notes else "; ".join(notes)
    return asset, failures


def _record_unverified(asset: CryptoAsset, evidence: str) -> None:
    apply_posture(asset, load_port_encryption(), "tcp", evidence=evidence)


def _attach_certificate(asset: CryptoAsset, host: str, raw_dir: Path | None,
                        ref_time: datetime | None) -> None:
    tls_scan.attach_cert_detail(asset, host, SMTP_PORT, raw_dir, ref_time)
    san = str(asset.extra.get("cert_san", ""))
    if not san:
        return
    names = [n.strip() for n in san.split(",") if n.strip()]
    if san_covers(host, names):
        return
    asset.flags = sorted(set(asset.flags) | {NAME_MISMATCH_FLAG})
    asset.notes = "; ".join(b for b in [
        asset.notes,
        f"certificate does not cover {host} (it covers {san}) — a sender enforcing "
        "MTA-STS refuses to deliver to a gateway whose certificate does not carry the "
        "name it was routed to",
    ] if b)


def gateways(target: dict) -> list[str]:
    """The mail gateways in ``scan_targets.smtp_25``, de-duplicated, in order."""
    entries = (target.get("scan_targets", {}) or {}).get(TARGET_KEY) or []
    out: list[str] = []
    for entry in entries:
        host = str((entry or {}).get("host") or "").strip() if isinstance(entry, dict) \
            else str(entry or "").strip()
        if host and host not in out:
            out.append(host)
    return out


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every authorised mail gateway; return (assets, failures)."""
    hosts = gateways(target)
    if not hosts:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    role_by_host = roles.scan_target_roles(target)
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for host in hosts:
        asset, host_failures = measure(host, raw_dir, ref_time, role_by_host.get(host, ""))
        assets.append(asset)
        failures += host_failures
    return assets, failures
