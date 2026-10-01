"""Whether each weak finding is bound to hardware or to software.

A finding bound to **hardware** (a device's management controller, an
appliance's own stack) leaves when the device does. A finding bound to
**software** (a service, a certificate, a mail record) travels with the
workload wherever it is hosted. Some protocols run on both, and are placed only
when something else on the row decides it; otherwise they stay ``unknown``.

The split is read only from what each finding attaches to. It describes the
population of findings, not a judgement about any one row.

A collector that emits a protocol or data state of its own registers how it
binds with :func:`register_binding`.
"""

from __future__ import annotations

from collections.abc import Iterable

from .model import CryptoAsset

HARDWARE = "hardware"
SOFTWARE = "software"
UNKNOWN = "unknown"

CAVEAT = (
    "This split is read only from what each finding attaches to (a device or a "
    "service). It shows the shape of the population of findings, not a judgement "
    "about any one row."
)

HARDWARE_STATES: set[str] = set()

# Management interfaces that live in a device's own firmware or controller.
HARDWARE_PROTOCOLS: set[str] = {
    "asf-rmcp", "ipmi-rmcp",
    "intel-amt-http", "intel-amt-https", "intel-amt-redirection", "intel-amt-redirection-tls",
}

SOFTWARE_STATES: set[str] = {"certificate", "email-auth"}

SOFTWARE_PROTOCOLS: set[str] = {
    "tls", "http", "https", "http-alt", "https-alt", "http-proxy", "http-rpc-epmap", "hsts",
    "smb", "netbios-ssn", "netbios-ns", "netbios-dgm", "msrpc",
    "ldap", "ldaps", "ldap-gc", "ldaps-gc",
    "rdp", "winrm-http", "winrm-https",
    "dns", "dns-over-tls", "llmnr", "mdns", "ssdp", "upnp", "wsd", "wsd-tls",
    "smtp", "smtps", "submission", "imap", "imaps", "pop3", "pop3s", "nntps", "sips",
    "amqp", "amqps",
    "ftp", "ftps", "ftp-data", "ftps-data", "tftp",
    "oracle-net", "oracle-tcps", "mssql", "mysql", "postgresql",
    "redis", "memcached",
    "x11", "finger", "exec",
}

#: Protocols that run on both devices and servers, with why they cannot be placed alone.
SPLIT_PROTOCOLS: dict[str, str] = {
    "ssh": "the management shell on a switch or firewall and the login shell on a server "
           "are the same protocol",
    "ike": "a physical VPN appliance and a software gateway negotiate identically",
    "nfs": "exported by a storage array and by an ordinary file server alike",
    "snmp": "the management plane of an appliance and an agent on a server alike",
    "snmp-trap": "the management plane of an appliance and an agent on a server alike",
    "syslog": "emitted by appliances and by workloads alike",
    "syslog-tls": "emitted by appliances and by workloads alike",
    "telnet": "a legacy management plane on appliances and on servers alike",
    "telnets": "a legacy management plane on appliances and on servers alike",
    "rlogin": "a legacy management plane on appliances and on servers alike",
    "rsh": "a legacy management plane on appliances and on servers alike",
}

# Phrases in a role sentence (see roles.py) that decide a split protocol.
ROLE_HARDWARE: tuple[str, ...] = ("vpn gateway",)
ROLE_SOFTWARE: tuple[str, ...] = (" server", "laptop or desktop", "domain controller")


def register_binding(binding: str, *, protocols: Iterable[str] = (),
                     data_states: Iterable[str] = ()) -> None:
    """Declare protocols or data states as bound to ``binding`` (hardware or software)."""
    if binding == HARDWARE:
        HARDWARE_PROTOCOLS.update(protocols)
        HARDWARE_STATES.update(data_states)
    elif binding == SOFTWARE:
        SOFTWARE_PROTOCOLS.update(protocols)
        SOFTWARE_STATES.update(data_states)
    else:
        raise ValueError(f"binding is {HARDWARE!r} or {SOFTWARE!r}, not {binding!r}")


def _place_from_role(role: str) -> str:
    r = (role or "").casefold()
    if not r:
        return ""
    if any(marker in r for marker in ROLE_HARDWARE):
        return HARDWARE
    if any(marker in r for marker in ROLE_SOFTWARE):
        return SOFTWARE
    return ""


def binding_of(data_state: str, protocol: str, role: str = "", software: str = "") -> str:
    """Hardware, software or unknown, from the row's data state, protocol, role and software."""
    if data_state in HARDWARE_STATES:
        return HARDWARE
    if data_state in SOFTWARE_STATES:
        return SOFTWARE
    if protocol in HARDWARE_PROTOCOLS:
        return HARDWARE
    if protocol in SOFTWARE_PROTOCOLS:
        return SOFTWARE
    placed = _place_from_role(role)
    if placed:
        return placed
    # A split protocol with a named software product is running as software.
    if software and protocol in SPLIT_PROTOCOLS:
        return SOFTWARE
    return UNKNOWN


def _class_of(asset: CryptoAsset) -> str:
    return asset.protocol or asset.data_state


def _share(n: int, total: int) -> float:
    return round(n / total, 3) if total else 0.0


def hardware_software_split(assets: Iterable[CryptoAsset]) -> dict:
    """The hardware/software split of weak findings, by class; {} when there are none."""
    findings = [a for a in assets if a.verdict == "weak"]
    if not findings:
        return {}

    counts = {HARDWARE: 0, SOFTWARE: 0, UNKNOWN: 0}
    by_class: dict[str, dict[str, int]] = {HARDWARE: {}, SOFTWARE: {}, UNKNOWN: {}}
    for a in findings:
        b = binding_of(a.data_state, a.protocol, a.role, a.software)
        counts[b] += 1
        cls = _class_of(a)
        by_class[b][cls] = by_class[b].get(cls, 0) + 1

    def _sorted(d: dict[str, int]) -> dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: -kv[1]))

    total = len(findings)
    return {
        "findings": total,
        "caveat": CAVEAT,
        "hardware": counts[HARDWARE],
        "hardware_share": _share(counts[HARDWARE], total),
        "hardware_by_class": _sorted(by_class[HARDWARE]),
        "software": counts[SOFTWARE],
        "software_share": _share(counts[SOFTWARE], total),
        "software_by_class": _sorted(by_class[SOFTWARE]),
        "unknown": counts[UNKNOWN],
        "unknown_share": _share(counts[UNKNOWN], total),
        "unknown_by_class": _sorted(by_class[UNKNOWN]),
        "unplaced": [{"class": c, "reason": SPLIT_PROTOCOLS.get(c, "")}
                     for c in sorted(by_class[UNKNOWN])],
    }
