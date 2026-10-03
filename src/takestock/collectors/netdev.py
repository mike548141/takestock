"""Cryptographic controls on network and out-of-band management equipment.

Switches, routers, firewalls, wireless controllers, server management
processors and wide-area links are administered and protected by settings no
outside probe can reach. This collector reads those settings from a supplied
export, one row per **control** on one device or link, in a small vendor-neutral
vocabulary. Whoever holds the configuration (``show running-config``,
a management console, a configuration backup) writes each control down in
that vocabulary; nothing here parses a vendor's configuration grammar, so a
grammar that changes between releases cannot silently stop finding a control.

**The export** is a CSV, by default ``inbox/netdev-controls.csv`` (set
``netdev_inbox.devices`` to move it). Columns, matched case-blind:

=================  =========================================================
``device``         the device or link name (required)
``control``        one of :data:`CONTROLS` (required)
``device_class``   one of :data:`DEVICE_CLASSES`
``state``          ``enabled``/``disabled`` and synonyms; blank is unknown
``algorithms``     ``;``-separated tokens, bare (``aes256-ctr``) or placed
                   in a baseline table (``ssh_kex=curve25519-sha256``)
``key_custody``    who holds the keys (``device``, ``hsm``, ...)
``vendor``, ``peer``, ``site``, ``evidence``, ``collected_on``: context
=================  =========================================================

**Grading** is the baseline's: each control sets the ``protocol`` that sends
its tokens to the right baseline table, and the token lands in the field that
table is read from. Two verdicts no table can express are set here: a control
recorded **off** is ``weak``, and a control recorded on that names **no
algorithm** stays ``unknown`` and is flagged ``algorithms-not-recorded``. A
control that names only some of the tables it should is flagged
``algorithms-partial:<table>``; the flag never changes the verdict.

**Coverage.** With no export, there is one gap for the file and one per
expected device class. With an export, each expected class that has no row
is its own gap, and a scope row states what the export covers without
claiming a share of the estate.

A missing or unreadable export never stops the run: it becomes a gap that
names the file, so the failure costs one re-run with the file supplied.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping
from pathlib import Path

from .. import coverage
from ..config import display_path, inbox_path, load_baseline, load_port_encryption
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..plaintext import FRONT_UNRESEARCHED, FRONTABLE_NOT_APPLICABLE, fronting_advice
from ..policy import Policy
from ..util import file_mtime_date

SOURCE = "netdev"
DEFAULT_PATH = "inbox/netdev-controls.csv"

#: control → (protocol policy grades it under, data state, baseline tables its tokens may name)
CONTROLS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "ssh-mgmt": ("ssh", "in-transit", ("ssh_kex", "ssh_cipher", "ssh_mac", "ssh_hostkey")),
    "tls-mgmt": ("tls", "in-transit",
                 ("tls_versions", "key_exchange", "signatures", "symmetric", "hashes")),
    "ipsec": ("ike", "in-transit", ("ike_encryption", "ike_dh", "ike_prf")),
    "macsec": ("macsec", "in-transit", ("symmetric",)),
    "wifi": ("wifi", "in-transit", ("symmetric", "hashes")),
    "radius": ("tls", "in-transit",
               ("tls_versions", "key_exchange", "signatures", "symmetric", "hashes")),
    "snmp": ("snmp", "in-transit", ("symmetric", "hashes")),
    "wan-link": ("wan-link", "in-transit", ("symmetric",)),
    "at-rest": ("storage-encryption", "at-rest", ("symmetric",)),
    "key-storage": ("key-store", "key-material", ()),
}

#: Plain-language name for each control.
CONTROL_LABELS = {
    "ssh-mgmt": "administrative login service",
    "tls-mgmt": "management web service",
    "ipsec": "encrypted tunnel",
    "macsec": "link encryption",
    "wifi": "wireless network",
    "radius": "network access authentication service",
    "snmp": "monitoring service",
    "wan-link": "wide-area link",
    "at-rest": "stored data",
    "key-storage": "hardware key store",
}

#: What each control decides, as a role sentence.
CONTROL_ROLES = {
    "ssh-mgmt": ("The command-line service engineers use to configure this equipment — "
                 "whether the instructions and passwords they send it are protected on the way"),
    "tls-mgmt": ("The web interface used to administer this equipment — whether the browser "
                 "session carrying its settings and credentials is protected"),
    "ipsec": ("An encrypted tunnel this equipment builds to another network — the settings "
              "that decide how strong the tunnel is"),
    "macsec": ("Protection of the link itself between two pieces of network equipment — "
               "whether anyone able to tap the cable between them could read what passes"),
    "wifi": ("The over-the-air protection on this wireless network — whether somebody within "
             "range could read what is sent across it"),
    "radius": ("The service that decides who is allowed onto the network — whether the "
               "credentials it carries are protected while it decides"),
    "snmp": ("The monitoring service on this equipment — whether the readings and settings "
             "it exchanges, and the secret that guards them, are protected"),
    "wan-link": ("A link carrying traffic across a network someone else operates — whether it "
                 "is protected while it crosses"),
    "at-rest": "Data stored on this equipment — whether it is unreadable if the device is taken",
    "key-storage": ("Where this equipment keeps its keys — whether a dedicated hardware key "
                    "store protects them"),
}
SCOPE_ROLE = ("What the network equipment export covers — how much was written down, and "
              "which kinds of equipment have no rows")

#: Where a placed token lands, per baseline table ("extra:<key>" for the extra mapping).
TABLE_FIELD: dict[str, str] = {
    "tls_versions": "protocol_versions",
    "key_exchange": "key_exchange",
    "signatures": "signatures",
    "symmetric": "symmetric",
    "hashes": "hashes",
    "ssh_kex": "extra:ssh_kex",
    "ssh_hostkey": "extra:ssh_hostkey",
    "ssh_mac": "extra:ssh_mac",
    "ssh_cipher": "symmetric",
    "ike_encryption": "symmetric",
    "ike_dh": "extra:ike_dh_groups",
    "ike_prf": "extra:ike_prf",
}

#: The tables a control is expected to name when it is on.
EXPECTED_TABLES: dict[str, tuple[str, ...]] = {
    "ssh-mgmt": ("ssh_kex", "ssh_cipher", "ssh_mac", "ssh_hostkey"),
    "tls-mgmt": ("tls_versions", "symmetric"),
    "radius": ("tls_versions", "symmetric"),
    "ipsec": ("ike_encryption", "ike_dh", "ike_prf"),
    "snmp": ("symmetric", "hashes"),
    "macsec": ("symmetric",),
    "wifi": ("symmetric",),
    "wan-link": ("symmetric",),
    "at-rest": ("symmetric",),
}

#: Generic equipment categories an export may declare.
DEVICE_CLASSES = ("switch", "router", "firewall", "wireless", "vpn-gateway", "out-of-band",
                  "wan-link", "storage", "other")
#: The classes expected when a profile sets no ``netdev_inbox.expect``.
EXPECTED_CLASSES_DEFAULT = ("switch", "router", "firewall", "wireless", "out-of-band")

# Findings.
ENCRYPTION_OFF = "encryption-off"
KEY_STORE_ABSENT = "hardware-key-store:absent"
# Facts and measurement limits.
NOT_RECORDED = "algorithms-not-recorded"
PARTIAL = "algorithms-partial:"
STATE_UNKNOWN = "control-state-unknown"
STATE_OTHER = "control-state:"
KEY_STORE_PRESENT = "hardware-key-store:present"
KEY_STORE_UNKNOWN = "hardware-key-store:unknown"
CUSTODY = "key-custody:"
CUSTODY_UNKNOWN = "key-custody-unknown"
UNRECOGNISED_CONTROL = "unrecognised-control:"
UNRECOGNISED_CLASS = "unrecognised-device-class:"
CLASS_UNSTATED = "device-class-unstated"
CLASSES_MISSING = "netdev-classes-missing:"

register_informational_prefixes(
    NOT_RECORDED, PARTIAL, STATE_UNKNOWN, STATE_OTHER, KEY_STORE_PRESENT, KEY_STORE_UNKNOWN,
    f"{CUSTODY}hsm", f"{CUSTODY}external-kms", CUSTODY_UNKNOWN, UNRECOGNISED_CONTROL,
    UNRECOGNISED_CLASS, CLASS_UNSTATED, CLASSES_MISSING)

_OFF = {"disabled", "off", "no", "none", "not-configured", "not configured", "absent", "false",
        "0", "cleartext", "plaintext", "unencrypted"}
_ON = {"enabled", "on", "yes", "configured", "present", "true", "1", "encrypted"}
_UNKNOWN = {"", "unknown", "unverified", "not-checked", "not checked", "?"}

# Common spellings of primitives the baseline already grades. Each is a
# naming difference, never a judgement:
#   MACsec suites (IEEE 802.1AE, and the extended-packet-numbering variants)
#   are AES-GCM at the stated key length; Wi-Fi CCMP is AES-128-CCM (IEEE
#   802.11) and GCMP-256 is AES-256-GCM; TKIP and WEP are RC4 constructions;
#   an open network has no cipher.
ALIASES: dict[str, str] = {
    "gcm-aes-128": "aes128_gcm", "gcm-aes-xpn-128": "aes128_gcm",
    "gcm-aes-256": "aes256_gcm", "gcm-aes-xpn-256": "aes256_gcm",
    "ccmp": "aes128_ccm", "ccmp-128": "aes128_ccm", "aes-ccmp": "aes128_ccm",
    "gcmp-256": "aes256_gcm", "gcmp256": "aes256_gcm",
    "tkip": "rc4", "wep": "rc4",
    "open": "null", "none": "null", "cleartext": "null",
    "aes-128-gcm": "aes128_gcm", "aes-256-gcm": "aes256_gcm",
    "aes-256-cbc": "aes256_cbc", "aes-192-cbc": "aes192_cbc", "aes-256-xts": "aes256_xts",
}

#: Advice for a weak management-plane control the port table has not researched.
FRONTING_REMEDY = (
    "Where the device offers nothing stronger, the remedy is in path rather than in "
    "place: put this management service behind a management network or jump host, or a "
    "reverse proxy, and segment the device so that path is its only ingress. That removes "
    "the exposure, not the weakness: the service still speaks what "
    "it speaks, so the segmentation is what has to be delivered.")

# The port table's protocol name for each management-plane control.
_FRONTING_PROTOCOL = {"ssh-mgmt": "ssh", "tls-mgmt": "https", "snmp": "snmp"}


def fronting_notes_by_control(table: Mapping[str, Mapping[str, str]]) -> dict[str, str]:
    """control → the port table's fronting advice, where the table has researched one."""
    by_protocol: dict[str, Mapping[str, str]] = {}
    for row in table.values():
        protocol = row.get("protocol", "").strip()
        if protocol and protocol not in by_protocol:
            by_protocol[protocol] = row
    notes: dict[str, str] = {}
    for control, protocol in _FRONTING_PROTOCOL.items():
        found = by_protocol.get(protocol)
        if found is None:
            continue
        frontable = found.get("frontable", "").strip()
        if not frontable or frontable in (FRONTABLE_NOT_APPLICABLE, FRONT_UNRESEARCHED):
            continue
        advice = fronting_advice(protocol, found.get("port", ""), frontable)
        if advice:
            notes[control] = advice
    return notes


def management_remedy(control: str, fronting_notes: Mapping[str, str]) -> str:
    """The advice appended to a weak management-plane control; "" for any other control."""
    if control not in _FRONTING_PROTOCOL:
        return ""
    return fronting_notes.get(control) or FRONTING_REMEDY


def _read(path: Path) -> tuple[list[dict], str]:
    if not path.exists():
        return [], ""
    try:
        with path.open(newline="") as f:
            return list(csv.DictReader(f)), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def _col(row: Mapping, *names: str) -> str:
    for n in names:
        for k, v in row.items():
            if k and str(k).strip().lower() == n:
                return (str(v) if v is not None else "").strip()
    return ""


def _slug(text: str) -> str:
    return "-".join(text.strip().lower().split()) or "unstated"


def tokens(raw: str) -> list[str]:
    """The ``algorithms`` cell split on ``;`` (commas are accepted too)."""
    return [t.strip() for t in raw.replace(",", ";").split(";") if t.strip()]


def _normalise(policy: Policy, table: str, token: str) -> str:
    t = ALIASES.get(token.strip().lower(), token.strip())
    if table == "tls_versions":
        return policy.normalise_tls_version(t)
    if table == "ike_dh":
        return policy.normalise_ike_dh(t)
    return t


def place(policy: Policy, token: str, tables: tuple[str, ...]) -> tuple[str, str] | None:
    """(table, token) for one ``algorithms`` entry, or None when it cannot be placed.

    ``table=value`` is taken at its word when the table is allowed for this
    control. A bare token is offered to each allowed table in turn; it is
    placed only when at least one knows it and every table that knows it
    gives the same grade.
    """
    if "=" in token:
        table, _, value = token.partition("=")
        table = table.strip().lower()
        return (table, _normalise(policy, table, value)) if table in tables else None
    found: list[tuple[str, str, str]] = []
    for table in tables:
        norm = _normalise(policy, table, token)
        grade = policy.grade(table, norm)
        if grade != "unknown":
            found.append((table, norm, grade))
    if not found or len({g for _, _, g in found}) > 1:
        return None
    return found[0][0], found[0][1]


def _key_storage_flag(state: str) -> str:
    if state in _ON:
        return KEY_STORE_PRESENT
    if state in _OFF:
        return KEY_STORE_ABSENT
    return KEY_STORE_UNKNOWN


def _expected_classes(inbox: Mapping) -> list[str]:
    declared = inbox.get("expect")
    if declared is None:
        return list(EXPECTED_CLASSES_DEFAULT)
    return [str(c).strip().lower() for c in declared if str(c).strip()]


def _class_gap(cls: str, export_arrived: bool) -> str:
    where = ("the export arrived and carries no row for it" if export_arrived
             else "no export has been supplied")
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"Network device class `{cls}` — {where}, so its management transport, link "
        "encryption and key custody are unmeasured. This limits what was collected and is "
        "never evidence that the class is unprotected",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Nothing here has measured how this kind of equipment is administered, "
                "whether its links are encrypted, or who holds its keys. Read the report as "
                "silent on it; silence is not a pass."),
        harvest="Rows for this class in the network device export.",
        nature=coverage.NO_DATA)


def _unfed_gaps(shown: str, expected: list[str], fatal: str) -> list[str]:
    gaps: list[str] = [coverage.gap(
        coverage.NOT_COLLECTED,
        f"{shown} — the network and out-of-band management export has not been supplied"
        + (f" or could not be read ({fatal})" if fatal else "")
        + ". The management plane and internal links are the part no outside probe can "
        "reach, so nothing else in this observation covers them",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Nothing has measured the encryption on the network equipment itself, so any "
                "answer to 'is internal traffic encrypted' is about the servers, not the "
                "network carrying them."),
        harvest="One export in the documented column layout, one row per control.",
        nature=coverage.NO_DATA)]
    gaps += [_class_gap(cls, export_arrived=False) for cls in expected]
    return gaps


def _source_name(mtime: str, evidence: str) -> str:
    where = f" via {evidence}" if evidence else ""
    dated = f" (file dated {mtime})" if mtime else " (file date unavailable)"
    return f"Network device configuration export{where}{dated}"


def _notes(label: str, state: str, algorithms: str, custody: str, peer: str, site: str,
           control: str, verdict: str, flags: set[str], fronting_notes: Mapping[str, str]) -> str:
    bits = [f"{label}: state={state or 'unstated'}",
            f"algorithms={algorithms or 'none recorded'}",
            f"key custody={custody or 'NOT STATED'}"]
    if peer:
        bits.append(f"other end={peer}")
    if site:
        bits.append(f"site={site}")
    note = "; ".join(bits)
    if ENCRYPTION_OFF in flags:
        note = "NOT ENCRYPTED — " + note
    elif NOT_RECORDED in flags:
        note = ("ENCRYPTION CLAIMED, ALGORITHM NOT STATED — the export says this control is on "
                "and not what it uses, so nothing here has been graded — " + note)
    if verdict == "weak":
        advice = management_remedy(control, fronting_notes)
        if advice:
            note += ". " + advice
    return note


def asset_from_row(r: Mapping, policy: Policy, fronting_notes: Mapping[str, str],
                   mtime: str) -> CryptoAsset | None:
    """The asset for one export row, or None when it names no device or no control."""
    device = _col(r, "device", "name", "hostname", "host")
    control = _col(r, "control", "control_type", "type").lower()
    if not device or not control:
        return None
    device_class = _col(r, "device_class", "class", "category").lower()
    state = _col(r, "state", "status", "enabled").lower()
    algorithms = _col(r, "algorithms", "algorithm", "ciphers", "proposal")
    custody = _col(r, "key_custody", "custody", "key_holder")
    site = _col(r, "site", "location")
    vendor = _col(r, "vendor", "model", "platform")
    peer = _col(r, "peer", "far_end", "remote", "ssid", "interface")
    evidence = _col(r, "evidence", "command", "source")
    collected_on = _col(r, "collected_on", "date", "as_at")

    flags: set[str] = set()
    if device_class and device_class not in DEVICE_CLASSES:
        flags.add(f"{UNRECOGNISED_CLASS}{device_class}")
        device_class = "other"
    elif not device_class:
        flags.add(CLASS_UNSTATED)
        device_class = "other"
    if control not in CONTROLS:
        flags.add(f"{UNRECOGNISED_CONTROL}{control}")
    protocol, data_state, tables = CONTROLS.get(control, ("", "in-transit", ()))

    fields: dict[str, list[str]] = {}
    extra_tokens: dict[str, list[str]] = {}
    named: set[str] = set()
    for token in tokens(algorithms):
        placed = place(policy, token, tables)
        if placed is None:
            flags.add(f"ungraded:{SOURCE}:{token.lower()}")
            continue
        table, value = placed
        named.add(table)
        dest = TABLE_FIELD[table]
        if dest.startswith("extra:"):
            extra_tokens.setdefault(dest[len("extra:"):], []).append(value)
        else:
            fields.setdefault(dest, []).append(value)
    graded_any = bool(fields or extra_tokens)
    if graded_any:
        flags.update(f"{PARTIAL}{t}" for t in EXPECTED_TABLES.get(control, ()) if t not in named)

    verdict = "unknown"
    if control == "key-storage":
        verdict = NA_VERDICT
        flags.add(_key_storage_flag(state))
    elif state in _OFF:
        flags.add(ENCRYPTION_OFF)
        verdict = "weak"
    elif state in _UNKNOWN and not graded_any:
        flags.add(STATE_UNKNOWN)
    elif state in _ON or graded_any:
        if not graded_any:
            flags.add(NOT_RECORDED)
    else:
        flags.add(f"{STATE_OTHER}{_slug(state)}")
    flags.add(f"{CUSTODY}{_slug(custody)}" if custody else CUSTODY_UNKNOWN)

    label = CONTROL_LABELS.get(control, control)
    return CryptoAsset(
        name=f"{device} — {label}", role=CONTROL_ROLES.get(control, ""),
        data_state=data_state, protocol=protocol, host=device, software=vendor,
        source=SOURCE, source_class="private", source_name=_source_name(mtime, evidence),
        collected_at=collected_on or mtime, verdict=verdict, flags=sorted(flags),
        notes=_notes(label, state, algorithms, custody, peer, site, control, verdict, flags,
                     fronting_notes),
        protocol_versions=sorted(set(fields.get("protocol_versions", []))),
        key_exchange=sorted(set(fields.get("key_exchange", []))),
        signatures=sorted(set(fields.get("signatures", []))),
        symmetric=sorted(set(fields.get("symmetric", []))),
        hashes=sorted(set(fields.get("hashes", []))),
        extra={"netdev_control": control, "netdev_device_class": device_class,
               "netdev_state": state, "netdev_peer": peer, "netdev_site": site,
               "netdev_evidence": evidence, "key_custody": custody,
               **{k: sorted(set(v)) for k, v in extra_tokens.items()}})


def scope_row(assets: list[CryptoAsset], shown: str, mtime: str, expected: list[str],
              seen: set[str]) -> CryptoAsset:
    """What the export covers: a count of what was exported, never a share of the estate."""
    devices = sorted({a.host for a in assets if a.host})
    controls = sorted({str(a.extra.get("netdev_control", "")) for a in assets} - {""})
    missing = [c for c in expected if c not in seen]
    return CryptoAsset(
        name="Network device export scope", role=SCOPE_ROLE, data_state="in-transit",
        protocol="", source=SOURCE, source_class="private",
        source_name=_source_name(mtime, ""), collected_at=mtime, verdict=NA_VERDICT,
        flags=sorted({f"{CLASSES_MISSING}{c}" for c in missing}),
        notes=(f"{len(assets)} control(s) across {len(devices)} device(s) or link(s), from "
               f"{shown}: {', '.join(controls)}. Device classes present: "
               f"{', '.join(sorted(seen)) or 'none'}. "
               + (f"Expected and absent: {', '.join(missing)}, each with its own coverage "
                  "gap. " if missing else "")
               + "Nothing in this run says how many network devices the organisation runs, "
                 "so this is a count of what was exported, not a share of the estate."),
        extra={"devices": len(devices), "controls": len(assets),
               "classes_present": sorted(seen), "classes_missing": missing})


def collect(target: Mapping, root: Path | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Read the network device export; return (assets, coverage gaps)."""
    inbox = target.get("netdev_inbox") or {}
    path = inbox_path(str(inbox.get("devices") or DEFAULT_PATH), root)
    shown = display_path(path, root)
    expected = _expected_classes(inbox)
    rows, fatal = _read(path)
    if not rows:
        if path.exists() and not fatal:
            fatal = "no data rows"
        return [], _unfed_gaps(shown, expected, fatal)

    policy = Policy(load_baseline())
    fronting_notes = fronting_notes_by_control(load_port_encryption())
    mtime = file_mtime_date(path) or ""
    assets: list[CryptoAsset] = []
    gaps: list[str] = []
    unusable = 0
    for r in rows:
        a = asset_from_row(r, policy, fronting_notes, mtime)
        if a is None:
            unusable += 1
        else:
            assets.append(a)
    seen = {str(a.extra["netdev_device_class"]) for a in assets}

    if unusable:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            f"{unusable} row(s) in {shown} name no device or no control and could not be "
            "read; they are neither counted nor graded",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("Some rows of the network export were incomplete, so the equipment they "
                    "describe is neither passed nor failed here."),
            harvest="A re-export with the device and control columns filled.",
            nature=coverage.NO_DATA))
    if not assets:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            f"{shown} is present and yielded no usable row, so the network equipment is as "
            "unmeasured as if nothing had been supplied; the format, not the export, is what "
            "needs fixing",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("An export was supplied and none of it could be read, so it must not be "
                    "read as the network having been assessed."),
            harvest="The same data in the documented column layout.",
            nature=coverage.NO_DATA))
        return assets, gaps
    gaps += [_class_gap(cls, export_arrived=True) for cls in expected if cls not in seen]
    assets.append(scope_row(assets, shown, mtime, expected, seen))
    return assets, gaps
