"""Cleartext and unverified-encryption findings from a listening port.

``data/port-encryption.csv`` records, per well-known port, whether the
protocol on it is:

* ``cleartext``: it carries no encryption at all;
* ``opportunistic``: it can upgrade to TLS in band (STARTTLS and the like),
  so a listener alone proves nothing either way;
* ``encrypted``: encryption is inherent (TLS, SSH).

For a cleartext row it also records what the traffic exposes, whether a
remedy exists, and whether an access edge can be put in front of the service
("fronting"). :func:`apply_posture` turns a listener on such a port into a
graded finding with a plain-language note.
"""

from __future__ import annotations

from collections.abc import Mapping

from .model import CryptoAsset

# Postures.
CLEARTEXT = "cleartext"
OPPORTUNISTIC = "opportunistic"
ENCRYPTED = "encrypted"

# Flag prefixes this module writes.
PLAINTEXT_FLAG = "plaintext:"
UNVERIFIED_FLAG = "unverified-encryption:"
EXPOSURE_FLAG = "cleartext-exposure:"

#: What a cleartext service exposes to someone watching the wire.
VALID_EXPOSURES = ("credentials", "control", "content", "metadata")
EXPOSURE_NOT_APPLICABLE = "n/a"
EXPOSURE_UNMEASURED = "unmeasured"

NO_ALTERNATIVE_FLAG = "no-encrypted-alternative:"

#: Whether a cleartext service can be remedied, and how.
VALID_REMEDIABILITIES = ("actionable-by-configuration",
                         "actionable-by-isolation-or-replacement",
                         "accepted-by-necessity",
                         "unconfirmed",
                         "unresearched")
ACCEPTED_BY_NECESSITY = "accepted-by-necessity"
REMEDIABILITY_NOT_APPLICABLE = "n/a"

# Whether an access edge can be put in front of the service, and which kind.
FRONT_REVERSE_WEB_PROXY = "reverse-web-proxy"
FRONT_PRIVATE_APP_BROKER = "private-application-broker"
FRONT_SSH_TUNNEL_ONLY = "ssh-tunnel-only"
FRONT_NOT_OUT_OF_BAND = "not-frontable-out-of-band"
FRONT_NOT_DISCOVERY = "not-frontable-discovery"
FRONT_NOT_CLIENT_CONFIGURED = "not-frontable-client-configured"
FRONT_UNRESEARCHED = "unresearched"
VALID_FRONTABILITIES = (FRONT_REVERSE_WEB_PROXY,
                        FRONT_PRIVATE_APP_BROKER,
                        FRONT_SSH_TUNNEL_ONLY,
                        FRONT_NOT_OUT_OF_BAND,
                        FRONT_NOT_DISCOVERY,
                        FRONT_NOT_CLIENT_CONFIGURED,
                        FRONT_UNRESEARCHED)
FRONTABLE_NOT_APPLICABLE = "n/a"
#: The values that mean an edge can help.
FRONTABLE_POSITIVE = (FRONT_REVERSE_WEB_PROXY, FRONT_PRIVATE_APP_BROKER,
                      FRONT_SSH_TUNNEL_ONLY)

PortTable = Mapping[str, Mapping[str, str]]


def build_index(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    """Index the port table's CSV rows by ``"<port>/<transport>"``.

    A bare ``"<port>"`` key is added too, but only when every transport on
    that port has the same posture; otherwise a caller must say which
    transport it means. Raises ValueError for any row with a wrong field
    count or a value outside the vocabularies above, naming the line.
    """
    index: dict[str, dict[str, str]] = {}
    by_port: dict[str, list[dict[str, str]]] = {}
    for n, row in enumerate(rows, 2):  # line 1 is the header
        if None in row or any(v is None for v in row.values()):
            raise ValueError(f"port-encryption.csv line {n}: wrong number of fields — an "
                             f"unquoted comma in the notes column? {row}")
        port = row["port"].strip()
        transport = row["transport"].strip().lower()
        clean = {k: v.strip() for k, v in row.items()}
        if clean["posture"] not in (CLEARTEXT, OPPORTUNISTIC, ENCRYPTED):
            raise ValueError(f"port-encryption.csv line {n}: unknown posture "
                             f"{clean['posture']!r} for port {port}")
        exposure = clean.get("exposure", "")
        if exposure and exposure != EXPOSURE_NOT_APPLICABLE:
            if exposure not in VALID_EXPOSURES:
                raise ValueError(f"port-encryption.csv line {n}: unknown exposure "
                                 f"{exposure!r} for port {port} — expected one of "
                                 f"{list(VALID_EXPOSURES)} or {EXPOSURE_NOT_APPLICABLE!r}")
            if clean["posture"] != CLEARTEXT:
                raise ValueError(f"port-encryption.csv line {n}: exposure {exposure!r} on a "
                                 f"{clean['posture']} row for port {port} — only a proven "
                                 f"cleartext row has an exposure to classify")
        remediability = clean.get("remediability", "")
        if remediability and remediability != REMEDIABILITY_NOT_APPLICABLE:
            if remediability not in VALID_REMEDIABILITIES:
                raise ValueError(f"port-encryption.csv line {n}: unknown remediability "
                                 f"{remediability!r} for port {port} — expected one of "
                                 f"{list(VALID_REMEDIABILITIES)} or "
                                 f"{REMEDIABILITY_NOT_APPLICABLE!r}")
            if clean["posture"] != CLEARTEXT:
                raise ValueError(f"port-encryption.csv line {n}: remediability "
                                 f"{remediability!r} on a {clean['posture']} row for port "
                                 f"{port} — only a proven cleartext row has a remedy to "
                                 f"assess")
        frontable = clean.get("frontable", "")
        if frontable and frontable != FRONTABLE_NOT_APPLICABLE:
            if frontable not in VALID_FRONTABILITIES:
                raise ValueError(f"port-encryption.csv line {n}: unknown frontable "
                                 f"{frontable!r} for port {port} — expected one of "
                                 f"{list(VALID_FRONTABILITIES)} or "
                                 f"{FRONTABLE_NOT_APPLICABLE!r}")
            if clean["posture"] == ENCRYPTED:
                raise ValueError(f"port-encryption.csv line {n}: frontable {frontable!r} on an "
                                 f"encrypted row for port {port} — an encrypted service has no "
                                 f"cleartext exposure for an edge to remove")
        index[f"{port}/{transport}"] = clean
        by_port.setdefault(port, []).append(clean)
    for port, group in by_port.items():
        if len({r["posture"] for r in group}) == 1:
            index[port] = group[0]
    return index


def lookup(port: str, transport: str, table: PortTable) -> Mapping[str, str] | None:
    """The table row for ``port`` (and ``transport`` when known), or None."""
    port = (port or "").strip()
    if not port:
        return None
    transport = (transport or "").strip().lower()
    if transport:
        row = table.get(f"{port}/{transport}")
        if row is not None:
            return row
    return table.get(port)


CONVENTION_BASIS = ("Port convention, not a probe: an active check of this port "
                    "would confirm it.")
UNVERIFIED_BASIS = ("An active capability probe of this port would settle it; until "
                    "then this is a coverage gap, not a finding.")


# An out-of-band management port seen only as a listening program on the host
# (from an endpoint agent's listener list, not a network probe). The exposure
# cannot be classified from the host, so it is recorded as unmeasured.
LISTENER_ONLY = f"{EXPOSURE_FLAG}{EXPOSURE_UNMEASURED}"
# Asset sources that report host listeners, mapped to the marker in their
# notes after which the collector's own detail begins. Empty until a collector
# registers itself with register_host_listener_source().
HOST_LISTENER_SOURCES: dict[str, str] = {}


def register_host_listener_source(source: str, marker: str) -> None:
    """Declare that assets from ``source`` are host listener rows.

    ``marker`` is the text in such an asset's notes where the collector's own
    detail begins; :func:`rederive_host_listeners` keeps everything from it on.
    """
    HOST_LISTENER_SOURCES[source] = marker


def is_listener_only_class(row: Mapping[str, str] | None) -> bool:
    """True for a cleartext out-of-band management row (seen only from the host)."""
    return (row is not None and row.get("posture") == CLEARTEXT
            and row.get("frontable") == FRONT_NOT_OUT_OF_BAND)


def listener_only_note(protocol: str, port: str) -> str:
    """The note for an out-of-band management port seen only as a host listener."""
    return (f"NO ENCRYPTION — {protocol} on port {port} carries no confidentiality. What "
            f"was seen is a program on the operating system listening on this unencrypted "
            f"port on the host, most likely the vendor's local management software. Whether "
            f"the out-of-band management interface is switched on in the hardware, and whether "
            f"it answers on the network, was not measured: its own traffic is handled below "
            f"the operating system, so a host's listener list cannot see it. A direct probe "
            f"of port {port} would settle it. Where it is switched on it controls the machine "
            f"below the operating system and nothing installed on the host can be put in "
            f"front of it, so the control is to isolate the management network so that only "
            f"named management stations can reach port {port}.")


def listener_only_protocol_note(protocol: str) -> str:
    """A protocol-level explanation of an out-of-band management interface."""
    return (f"{protocol} is an out-of-band management interface. Where it is switched on "
            f"in the hardware it controls the machine below the operating system, whether "
            f"or not the machine is running. For this row only a program on the host was "
            f"seen listening on the port; whether the interface is switched on, or answers "
            f"on the network, was not measured.")


def rederive_host_listeners(assets: list[CryptoAsset], table: PortTable) -> int:
    """Re-apply the listener-only reading to host-listener assets; return how many changed.

    Used when re-rendering a stored observation so it picks up the current
    table. Only cleartext out-of-band rows from a host-listener source are
    touched; the collector's own detail at the end of the note is kept.
    """
    changed = 0
    for a in assets:
        marker = HOST_LISTENER_SOURCES.get(a.source)
        if marker is None:
            continue
        service = str((a.extra or {}).get("service", ""))
        transport = service.partition("/")[2]
        row = lookup(a.port, transport, table)
        if row is None or not is_listener_only_class(row):
            continue
        protocol = row.get("protocol", "")
        if f"{PLAINTEXT_FLAG}{protocol}" not in a.flags:
            continue
        note = listener_only_note(protocol, a.port)
        new_flags = set(a.flags)
        for old in [x for x in new_flags if x.startswith(EXPOSURE_FLAG)]:
            new_flags.discard(old)
        new_flags.add(LISTENER_ONLY)
        notes = a.notes or ""
        if new_flags == set(a.flags) and notes.startswith(note):
            continue
        at = notes.find(marker)
        tail = notes[at:] if at >= 0 else ""
        a.flags = sorted(new_flags)
        a.notes = f"{note} {tail}".strip()
        changed += 1
    return changed


def fronting_advice(protocol: str, port: str, frontable: str) -> str:
    """What putting an access edge in front of the service would and would not fix.

    Returns "" for an unresearched or unknown value: no advice is better than
    a guess.
    """
    if frontable == FRONT_REVERSE_WEB_PROXY:
        return (f"Fronting: a reverse web proxy can be put in front of this listener. Clients "
                f"connect to the proxy over HTTPS and the proxy forwards to port {port}. That "
                f"removes the exposure and not the weakness — {protocol} still carries this "
                f"traffic in clear, so anything that can still reach port {port} directly still "
                f"reads it. It is only fixed once segmentation makes the proxy the only way in.")
    if frontable == FRONT_PRIVATE_APP_BROKER:
        return (f"Fronting: this service can be published through an access platform that brokers "
                f"arbitrary TCP as a private application. Clients then reach it over an encrypted "
                f"tunnel, and have to be re-pointed at the broker to do so. That removes the "
                f"exposure and not the weakness — {protocol} still crosses the last hop in clear, "
                f"so anything that can still reach port {port} directly still reads it. It is "
                f"only fixed once segmentation makes the broker the only way in.")
    if frontable == FRONT_SSH_TUNNEL_ONLY:
        return (f"Fronting: no proxy terminates {protocol}, but it can be carried inside an SSH "
                f"tunnel so it never crosses the network in clear. That removes the exposure and "
                f"not the weakness — the service still speaks {protocol}, so anything that can "
                f"still open port {port} directly still reads it. It is only fixed once port "
                f"{port} stops accepting connections from the network.")
    if frontable == FRONT_NOT_OUT_OF_BAND:
        return (f"Fronting does not apply here. This is an out-of-band management interface: it "
                f"answers below the operating system and whether or not the machine is running, "
                f"so nothing installed on the host can be made the only path to it. The control "
                f"is to isolate the management network so that only named management stations "
                f"can reach port {port}.")
    if frontable == FRONT_NOT_DISCOVERY:
        return ("Fronting does not apply here. This is client-initiated discovery traffic: there "
                "is no client to re-point at an edge and no session for an edge to terminate. "
                "The control is to turn the service off where nothing depends on it, and to "
                "isolate the segment it runs on.")
    if frontable == FRONT_NOT_CLIENT_CONFIGURED:
        return (f"Fronting does not apply here. Clients are configured to reach this service at "
                f"this address and no proxy terminates {protocol}. The control is network "
                f"isolation and monitoring.")
    return ""


def apply_posture(asset: CryptoAsset, table: PortTable, transport: str = "",
                  evidence: str = "", host_listener: bool = False) -> str:
    """Grade a listener by its port's posture and return that posture ("" if unlisted).

    * cleartext: adds ``plaintext:<protocol>`` (and an exposure flag where the
      table classifies one), prepends a note, and sets the verdict to
      ``weak`` unless something measured has already graded it.
    * opportunistic: adds ``unverified-encryption:<protocol>``, a coverage
      gap rather than a finding; the verdict is untouched.
    * encrypted: nothing changes; the protocol's own scanner grades it.

    ``evidence`` replaces the "port convention" wording when a probe actually
    confirmed the posture. ``host_listener`` marks an asset seen only in a
    host's listener list.
    """
    row = lookup(asset.port, transport, table)
    if row is None:
        return ""
    posture = row.get("posture", "")
    protocol = row.get("protocol", "")
    detail = row.get("notes", "")

    if posture == CLEARTEXT and host_listener and not evidence \
            and is_listener_only_class(row):
        note = listener_only_note(protocol, asset.port)
        asset.flags = sorted(set(asset.flags) | {f"{PLAINTEXT_FLAG}{protocol}", LISTENER_ONLY})
        if asset.verdict == "unknown":
            asset.verdict = "weak"
    elif posture == CLEARTEXT:
        note = (f"NO ENCRYPTION — {protocol} on port {asset.port} carries no confidentiality"
                + (f" ({detail})" if detail else "")
                + ". " + (evidence or CONVENTION_BASIS))
        flags = {f"{PLAINTEXT_FLAG}{protocol}"}
        exposure = row.get("exposure", "")
        if exposure in VALID_EXPOSURES:
            flags.add(f"{EXPOSURE_FLAG}{exposure}")
        advice = fronting_advice(protocol, asset.port, row.get("frontable", ""))
        if row.get("remediability", "") == ACCEPTED_BY_NECESSITY:
            flags.add(f"{NO_ALTERNATIVE_FLAG}{protocol}")
            note += (f" There is no encrypted version of {protocol} the organisation can "
                     f"realistically switch to, so the listener itself is accepted by "
                     f"necessity.")
            if row.get("frontable", "") in FRONTABLE_POSITIVE:
                note += " The exposure it creates is still open for remediation."
        if advice:
            note += f" {advice}"
        asset.flags = sorted(set(asset.flags) | flags)
        if asset.verdict == "unknown":
            asset.verdict = "weak"
    elif posture == OPPORTUNISTIC:
        note = (f"ENCRYPTION UNVERIFIED — {protocol} on port {asset.port} can be encrypted in band"
                + (f" ({detail})" if detail else "")
                + ", and a listener alone does not prove it is. "
                + (evidence or UNVERIFIED_BASIS))
        asset.flags = sorted(set(asset.flags) | {f"{UNVERIFIED_FLAG}{protocol}"})
    else:
        return posture

    asset.notes = f"{note} {asset.notes}".strip() if asset.notes else note
    return posture
