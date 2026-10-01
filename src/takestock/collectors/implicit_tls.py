"""TLS on the mail ports where it is inherent: 465, 993 and 995 (RFC 8314).

On these ports TLS starts with the first byte, so a direct handshake (no
STARTTLS) is the right probe. This collector takes its (host, port) pairs
from the same probe plan :mod:`~takestock.collectors.plaintext_scan` builds,
so it contacts nothing that plan has not already enumerated and justified,
and a plan that collector refuses is refused here too.

Per port it pins each TLS version in turn, as the STARTTLS check does, and
reads the certificate. The four ways a port can answer are kept apart:

* a session was agreed: graded like any other TLS endpoint;
* something answered and completed no handshake: flagged, because a port
  whose encryption everything else assumes is not speaking TLS;
* the connection was refused: nothing listens, a measured negative;
* nothing came back: unmeasured, never read as closed.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles, tls_session
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..tls_session import COULD_NOT_ASK, OFFERED
from ..util import ERROR_PREFIX, now_date
from . import plaintext_scan, smtp_starttls, tls_scan

SOURCE = "implicit_tls"
SOURCE_NAME = "Active TLS handshake (openssl) — mail port where TLS is inherent"

#: The implicit-TLS mail ports and the service each carries.
IMPLICIT_TLS_PORTS: dict[int, str] = {
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
}

PREFERENCE_ONLY = smtp_starttls.PREFERENCE_ONLY

#: Flag: nothing came back, so the port is unmeasured (a limit, not a finding).
UNREACHED_FLAG = "implicit-tls-unreached:"

#: Flag: something answered and did not speak TLS (a finding).
NO_HANDSHAKE_FLAG = "implicit-tls-no-handshake:"

NAME_MISMATCH_FLAG = smtp_starttls.NAME_MISMATCH_FLAG

register_informational_prefixes(UNREACHED_FLAG)


def service(port: int) -> str:
    """The service name for an implicit-TLS port, or ""."""
    return IMPLICIT_TLS_PORTS.get(port, "")


def planned(target: dict, plan: plaintext_scan.ProbePlan | None = None
            ) -> list[tuple[str, int, str]]:
    """(host, port, plan section) for every implicit-TLS port in the probe plan."""
    plan = plaintext_scan.build_plan(target) if plan is None else plan
    out: list[tuple[str, int, str]] = []
    for step in plan.steps:
        for spec in step.ports:
            number = int(spec.split("/", 1)[0])
            if number in IMPLICIT_TLS_PORTS:
                out.append((step.host, number, step.section))
    return out


def measure(host: str, port: int, raw_dir: Path | None = None,
            ref_time: datetime | None = None, role: str = "") -> CryptoAsset:
    """Probe one implicit-TLS port and return its row."""
    transcripts: dict[str, str] = {}
    probed = tls_scan.probe_versions(host, port, host, raw_dir, starttls="",
                                     transcripts=transcripts)
    offered = tls_session.versions_in_state(probed, OFFERED)
    unknown = tls_session.versions_in_state(probed, COULD_NOT_ASK)
    reached = any(s.reached_host for s in probed.values())
    refused_connection = any(_connection_refused(t) for t in transcripts.values())

    suites: list[str] = []
    raw_suites: list[str] = []
    groups: set[str] = set()
    for version in offered:
        cipher = probed[version].cipher
        if cipher:
            raw_suites.append(f"{version}={cipher}")
            suites.append(smtp_starttls.iana_suite_name(cipher) or cipher)
        group = smtp_starttls.parse_server_temp_key(transcripts.get(version, ""))
        if group:
            groups.add(group)

    name = service(port)
    flags: set[str] = set()
    if unknown and (offered or reached):
        flags.add(tls_scan.VERSION_PROBE_UNAVAILABLE)

    asset = CryptoAsset(
        name=f"{name} {host}:{port}", role=role,
        data_state="in-transit", protocol="tls", host=host, port=str(port),
        source=SOURCE, internet_facing=True,
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        protocol_versions=sorted(dict.fromkeys(offered)),
        key_exchange=sorted(groups),
        symmetric=sorted(dict.fromkeys(suites)),
        extra={
            "service": f"{port}/tcp",
            "implicit_tls": True,
            "version_probe": tls_session.describe(probed),
            **({"negotiated_suites": "; ".join(raw_suites)} if raw_suites else {}),
        },
    )

    notes: list[str] = []
    if offered:
        _attach_certificate(asset, host, port, raw_dir, ref_time)
        notes.append(PREFERENCE_ONLY)
        if unknown:
            notes.append(f"version probe could not run for {', '.join(unknown)} — those "
                         "versions are unknown, not absent")
    elif reached:
        flags.add(f"{NO_HANDSHAKE_FLAG}{name.lower()}")
        asset.verdict = "unknown"
        notes.append(
            f"SOMETHING IS LISTENING AND IT DID NOT SPEAK TLS — {host} answered on port "
            f"{port}, where TLS is inherent ({name}, RFC 8314), and completed no handshake "
            "at TLS 1.0-1.3. That is either a service that is not TLS on a port whose "
            "encryption everything else assumes, or a TLS version this probe cannot pin; "
            "neither is claimed over the other, and both are worth a look")
    elif refused_connection:
        asset.verdict = NA_VERDICT
        notes.append(f"nothing is listening — {host} refused the connection on port {port}. "
                     "A measured negative: the host answered, with a refusal")
    else:
        flags.add(f"{UNREACHED_FLAG}{name.lower()}")
        asset.verdict = "unknown"
        notes.append(f"NO ANSWER — nothing came back from {host} on port {port}, so this "
                     "port is UNMEASURED rather than shut. A firewall dropping the probe "
                     "and a closed port are identical from here")

    asset.flags = sorted(set(asset.flags) | flags)
    asset.notes = "; ".join(b for b in [asset.notes, *notes] if b)
    return asset


def _connection_refused(transcript: str) -> bool:
    """True when ``s_client`` reports that the host actively refused or was unroutable."""
    if transcript.startswith(ERROR_PREFIX):
        return False
    lowered = transcript.lower()
    return any(f"connect: {phrase}" in lowered
               for phrase in ("connection refused", "network is unreachable",
                              "no route to host", "host is down"))


def _attach_certificate(asset: CryptoAsset, host: str, port: int,
                        raw_dir: Path | None, ref_time: datetime | None) -> None:
    tls_scan.attach_cert_detail(asset, host, port, raw_dir, ref_time)
    san = str(asset.extra.get("cert_san", ""))
    if not san:
        return
    names = [n.strip() for n in san.split(",") if n.strip()]
    if smtp_starttls.san_covers(host, names):
        return
    asset.flags = sorted(set(asset.flags) | {NAME_MISMATCH_FLAG})
    asset.notes = "; ".join(b for b in [
        asset.notes,
        f"certificate does not cover {host} (it covers {san}) — a mail client connecting "
        "to this port validates the name and refuses the session",
    ] if b)


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every implicit-TLS port in the plan; return (assets, failures)."""
    try:
        pairs = planned(target)
    except plaintext_scan.PortListRefused as refusal:
        return [], [f"{SOURCE}: REFUSED to probe — {refusal}. No ports were contacted."]
    if not pairs:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    role_by_host = roles.scan_target_roles(target)
    assets = [measure(host, port, raw_dir, ref_time, role_by_host.get(host, ""))
              for host, port, _section in pairs]
    return assets, []
