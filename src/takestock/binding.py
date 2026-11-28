"""Whether each weak finding is bound to hardware or to software.

A finding bound to **hardware** (a device's management controller, an
appliance's own stack) leaves when the device does. A finding bound to
**software** (a service, a certificate, a mail record) travels with the
workload wherever it is hosted. Some protocols run on both, and are placed only
when something else on the row decides it; otherwise they stay ``unknown``.

The split is read only from what each finding attaches to. It describes the
population of findings, not a judgement about any one row.

A collector that emits a protocol or data state of its own registers how it
binds with :func:`register_binding`. The tables below place the states and
protocols that takestock's own readers and collectors emit, so a summary needs
no registration to read correctly; ``tests/test_binding_coverage.py`` fails when
a value in the source, or in the tables the readers draw from, is neither
placed nor given a reason here.
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

HARDWARE_STATES: set[str] = {
    # The weak findings under this state are a machine's boot-chain and firmware
    # enforcement answers (secure boot, firmware level, code-signing and memory
    # protection), physical or virtual. They describe the machine's own firmware,
    # which does not move with a workload. The other rows filed here (scope and
    # census rows) carry no verdict, and a defect record is placed by its
    # protocol, ahead of this state.
    "platform-integrity",
}

# Management interfaces that live in a device's own firmware or controller.
HARDWARE_PROTOCOLS: set[str] = {
    "asf-rmcp", "ipmi-rmcp",
    "intel-amt-http", "intel-amt-https", "intel-amt-redirection", "intel-amt-redirection-tls",
    # The BIOS or UEFI level and settings a platform export lists for a machine.
    "firmware",
    # Encryption the vSphere layer applies: per cluster (vSAN) or per virtual
    # machine through a storage policy, over datastores, between hosts during
    # live migration, with keys from a provider configured on the platform. All
    # of it is set on the hypervisor layer, not inside a workload. The
    # key-management placement assumes that key provider is the virtualisation
    # platform's own.
    "vsan-encryption", "vm-encryption", "datastore", "datastore-encryption",
    "vm-migration", "key-management",
    # Controls that a network device's export reports about the device itself.
    "macsec", "wan-link", "key-store", "storage-encryption",
}

SOFTWARE_STATES: set[str] = {
    "certificate", "email-auth",
    # Rows about accounts, sign-in methods, authentication flows and mailbox
    # access record settings of an identity or mail service, held in its tenant.
    "identity",
}

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
    # The remote-management service settings of a Windows host.
    "winrm",
    # A database's keystore and tablespace or column encryption, and the cipher
    # set on each copy of a backup product's storage policy: settings of the
    # database and backup products, which stay with them when their host changes.
    "tde", "database-encryption", "column-encryption", "database-backup-encryption",
    "backup-encryption", "commvault-backup",
    # Cryptographic libraries and their versions installed per machine, outbound
    # connections counted by destination port, and the inventories and support
    # dates kept about installed software: all describe what the software on a
    # machine contains or does.
    "software", "egress", "inventory", "software-lifecycle",
    # The client secret or certificate an application registration signs in with,
    # and the sign-in methods and legacy-authentication findings of the tenant.
    "oauth-client-credential", "legacy-authentication", "mfa",
    # Zone signing is read from the zone's own records, like the other DNS rows.
    "dnssec",
    # Encryption and key settings of Azure resources, read per resource from the
    # resource graph: a cloud service's configuration, not a device's.
    "azure-storage", "azure-disk", "azure-backup", "azure-keyvault", "azure-at-rest",
    # The components a defect record is filed against (a package name or a Windows
    # component): authentication services and cryptographic libraries. Scoped to
    # those records, the only rows that carry these names.
    "kerberos", "ntlm", "netlogon", "ipsec", "crypto", "signing", "key-material",
}

#: Protocols whose rows are placed by the product they name, ahead of the data state they
#: share with other findings. takestock's one emitter records known-exploited defects
#: against software installed on sensored machines, so a row naming its product is
#: software; one that does not name it is left unknown.
PRODUCT_DEFECT_PROTOCOLS: set[str] = {"vulnerability"}

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
    "fde": "a volume's encryption is a setting of the operating system and a property of the "
           "disk it protects, and the row does not say which a move would change",
    "disk-encryption": "a volume's encryption is a setting of the operating system and a "
                       "property of the disk it protects, and the row does not say which a "
                       "move would change",
    "vulnerability": "the defect record names no product, so there is nothing to say what it "
                     "is attached to",
    "wifi": "an access point's radio settings and a host's wireless client software are the "
            "same protocol",
    "tcp": "a listener the port table does not name carries only its transport, which says "
           "nothing about what it is attached to",
    "udp": "a listener the port table does not name carries only its transport, which says "
           "nothing about what it is attached to",
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
    if protocol in PRODUCT_DEFECT_PROTOCOLS:
        return SOFTWARE if software else UNKNOWN
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
