"""The kinds of plug-in collector: each kind's record schema, and the rows its records become.

A plug-in (see :mod:`takestock.plugins`) reads an export takestock has no
built-in reader for and returns **records**: plain mappings whose fields are
fixed by the plug-in's kind in ``data/plugin-kinds.yaml``. This module checks
each record against that schema (:func:`validate`) and turns the valid ones
into :class:`~takestock.model.CryptoAsset` rows (:func:`build_rows`), so every
plug-in of one kind is named and graded the same way, whatever product it
reads.

A plug-in may instead return finished rows. :func:`check_asset` holds those to
the kind's row constraints (the data states and protocols the kind's rows use,
and any ``extra`` keys downstream readers rely on).

The schema file is the contract, so it is always read from the package; a
workspace's ``data/`` copy is never consulted.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from typing import Any

from . import coverage, identity
from .collectors import netdev, software_inventory
from .config import BUNDLED_DATA_DIR, load_yaml_strict
from .model import NA_VERDICT, VERDICT_ORDER, CryptoAsset, register_informational_prefixes, worst
from .plaintext import PortTable, apply_posture, lookup
from .policy import Policy
from .util import scan_address

SCHEMA_FILE = BUNDLED_DATA_DIR / "plugin-kinds.yaml"

#: Accepted by every row kind: the date a record was true.
COMMON_FIELDS = ("collected_on",)
#: Fields starting with this are the plug-in's own, copied into ``extra`` unchanged.
CUSTOM_PREFIX = "x_"

#: A kind whose step returns no rows, only coverage gaps; it always runs late.
COVERAGE_CHECK = "coverage-check"
#: A kind whose step adds ``extra`` keys to rows other collectors wrote.
ANNOTATION = "annotation"

# Findings.
ENCRYPTION_OFF = netdev.ENCRYPTION_OFF
ENCRYPTION_SUSPENDED = "encryption-suspended"
RECOVERY_NOT_ESCROWED = "recovery-key-not-escrowed"
CONTROL_OFF = "control-off:"
CONTROL_PARTIAL = "control-partial:"
MAIL_CLEARTEXT = "mail-cleartext-delivery:"
# Facts and measurement limits.
NOT_RECORDED = netdev.NOT_RECORDED
STATE_UNKNOWN = netdev.STATE_UNKNOWN
ENCRYPTION_IN_PROGRESS = "encryption-in-progress"
RECOVERY_ESCROWED = "recovery-key-escrowed"
SCOPE_FLAG = "plugin-scope"

register_informational_prefixes(STATE_UNKNOWN, NOT_RECORDED, ENCRYPTION_IN_PROGRESS,
                                RECOVERY_ESCROWED, SCOPE_FLAG, "key-management:present",
                                "key-management:partial", "key-management:unknown")

#: The note a host-listener row carries after the posture's own note; see
#: :func:`takestock.plaintext.register_host_listener_source`.
LISTENER_MARKER = "Seen listening on the host by plug-in"

# The record field naming the machine a control row is about, for the kinds
# whose subject can be one.
_HOST_FIELD = {"directory": "server", "virtualisation": "object", "database-encryption": "server"}

_FLAG_TRUE = {"true", "yes", "y", "on", "1"}
_FLAG_FALSE = {"false", "no", "n", "off", "0"}
_TLS_SPELLING = re.compile(r"^(tls|ssl)\s*v?\s*(\d)(?:\.(\d))?$", re.IGNORECASE)
_NO_TLS = {"none", "no tls", "notls", "no-tls", "cleartext", "plaintext", "unencrypted", ""}
#: How the mail-transport rows spell a delivery with no transport encryption.
NO_TLS_LABEL = "No TLS"


@cache
def schema() -> dict:
    """The parsed kind schema, read once from the package."""
    doc = load_yaml_strict(SCHEMA_FILE)
    if doc.get("schema") != 1:
        raise ValueError(f"{SCHEMA_FILE}: unsupported schema version {doc.get('schema')!r}")
    return doc


def row_kinds() -> tuple[str, ...]:
    """The kinds whose plug-ins return records or rows."""
    return tuple(schema()["kinds"])


def kinds() -> tuple[str, ...]:
    """Every kind a plug-in may declare."""
    return row_kinds() + (COVERAGE_CHECK, ANNOTATION)


def spec(kind: str) -> dict:
    """The schema entry for a row kind."""
    try:
        return schema()["kinds"][kind]
    except KeyError:
        raise ValueError(f"{kind!r} is not a row kind; expected one of {list(row_kinds())}") from None


def fixed_source(kind: str) -> str:
    """The ``source`` every row of ``kind`` carries, or "" when it is the plug-in's name."""
    return str(spec(kind).get("source") or "")


# ── validation ──

def _choice(field_spec: Mapping, raw: Any) -> tuple[Any, str]:
    values = [str(v) for v in field_spec.get("values") or []]
    synonyms = {str(k): str(v) for k, v in (field_spec.get("synonyms") or {}).items()}
    text = "" if raw is None else str(raw).strip().lower()
    if text in synonyms:
        return synonyms[text], ""
    if text in values:
        return text, ""
    if not text:
        return None, ""
    return None, f"{raw!r} is not one of {values}"


def _coerce(field_spec: Mapping, raw: Any) -> tuple[Any, str]:
    """(value, problem) for one field; value None means absent."""
    kind = field_spec.get("type")
    if kind == "control-state":
        return _choice(schema()["control_states"], raw)
    if kind == "choice":
        return _choice(field_spec, raw)
    if raw is None:
        return None, ""
    if kind == "text":
        if isinstance(raw, (dict, list, tuple, set)):
            return None, f"expected text, got {type(raw).__name__}"
        text = str(raw).strip()
        return (text or None), ""
    if kind in ("count", "port"):
        if isinstance(raw, bool):
            return None, f"expected a whole number, got {raw!r}"
        text = str(raw).replace(",", "").strip()
        if not text:
            return None, ""
        if not text.isdigit():
            return None, f"expected a whole number, got {raw!r}"
        n = int(text)
        if kind == "port" and not 1 <= n <= 65535:
            return None, f"a port is 1 to 65535, got {n}"
        return n, ""
    if kind == "flag":
        if isinstance(raw, bool):
            return raw, ""
        text = str(raw).strip().lower()
        if text in _FLAG_TRUE:
            return True, ""
        if text in _FLAG_FALSE:
            return False, ""
        return (None, "") if not text else (None, f"expected true or false, got {raw!r}")
    if kind == "date":
        return _date(raw)
    if kind == "tokens":
        items = raw if isinstance(raw, (list, tuple)) else str(raw).replace(",", ";").split(";")
        out = [str(t).strip() for t in items if str(t).strip()]
        return (out or None), ""
    raise ValueError(f"unknown field type {kind!r} in {SCHEMA_FILE}")


def _date(raw: Any) -> tuple[str | None, str]:
    if isinstance(raw, date):
        return raw.isoformat()[:10], ""
    text = str(raw).strip()
    if not text:
        return None, ""
    m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    if not m:
        return None, f"expected a date as YYYY-MM-DD, got {raw!r}"
    try:
        date.fromisoformat(m.group(1))
    except ValueError:
        return None, f"{m.group(1)!r} is not a calendar date"
    return m.group(1), ""


def _custom_value_ok(value: Any) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    return isinstance(value, (list, tuple)) and all(isinstance(v, (str, int, float, bool))
                                                    for v in value)


def validate(kind: str, record: Any) -> tuple[dict | None, list[str]]:
    """Check one record against ``kind``'s fields; return (clean record or None, problems).

    The clean record holds each listed field converted to its type (absent
    fields are left out), ``collected_on`` when given, and the plug-in's own
    ``x_`` fields under ``"x"``. Any problem makes the record invalid.
    """
    if not isinstance(record, Mapping):
        return None, [f"a record is a mapping of field to value, not {type(record).__name__}"]
    fields: Mapping[str, Mapping] = spec(kind)["fields"]
    problems: list[str] = []
    clean: dict[str, Any] = {}
    custom: dict[str, Any] = {}
    for key, value in record.items():
        if not isinstance(key, str):
            problems.append(f"field name {key!r} is not text")
        elif key.startswith(CUSTOM_PREFIX):
            if _custom_value_ok(value):
                custom[key] = list(value) if isinstance(value, tuple) else value
            else:
                problems.append(f"{key}: a plug-in's own field holds text, a number, true or "
                                "false, or a list of those")
        elif key == "collected_on":
            day, problem = _date(value)
            if problem:
                problems.append(f"collected_on: {problem}")
            elif day:
                clean["collected_on"] = day
        elif key not in fields:
            problems.append(f"unknown field {key!r} (a plug-in's own fields start "
                            f"{CUSTOM_PREFIX!r})")
    for name, field_spec in fields.items():
        value, problem = _coerce(field_spec, record.get(name))
        if problem:
            problems.append(f"{name}: {problem}")
        elif value is None:
            if field_spec.get("required"):
                problems.append(f"{name}: required, and missing or blank")
        else:
            clean[name] = value
    if custom:
        clean["x"] = custom
    return (None, problems) if problems else (clean, [])


def check_asset(kind: str, asset: Any) -> list[str]:
    """Problems with a finished row a plug-in returned for ``kind``; [] when it is acceptable."""
    if not isinstance(asset, CryptoAsset):
        return [f"expected a record or a CryptoAsset, not {type(asset).__name__}"]
    row = spec(kind).get("row") or {}
    problems = []
    if not str(asset.name or "").strip():
        problems.append("the row has no name")
    states = row.get("data_state") or []
    if states and asset.data_state not in states:
        problems.append(f"data_state {asset.data_state!r} is not one of {states}")
    protocols = row.get("protocol") or []
    if protocols and asset.protocol not in protocols:
        problems.append(f"protocol {asset.protocol!r} is not one of {protocols}")
    for key in row.get("extra") or []:
        if key not in (asset.extra or {}):
            problems.append(f"extra[{key!r}] is required on a {kind} row")
    if asset.verdict not in VERDICT_ORDER:
        problems.append(f"verdict {asset.verdict!r} is not one of {list(VERDICT_ORDER)}")
    try:
        json.dumps(asset.extra)
    except (TypeError, ValueError) as exc:
        problems.append(f"extra cannot be written as JSON: {exc}")
    return problems


# ── building rows ──

@dataclass
class Build:
    """What turning one plug-in's records into rows needs from the observation."""

    plugin: str
    kind: str
    title: str
    policy: Policy
    port_table: PortTable
    target: Mapping
    collected_on: str
    shown: str
    names: dict[str, str] = field(default_factory=dict)

    @property
    def source(self) -> str:
        return fixed_source(self.kind) or self.plugin

    def stamp(self, asset: CryptoAsset, record: Mapping, finished: bool = False) -> CryptoAsset:
        """Fill the provenance fields, and copy the record's own ``x_`` fields into ``extra``.

        ``source`` is always set here, so no plug-in can write rows that read as
        another collector's. A ``finished`` row keeps a ``source_name`` and
        ``collected_at`` the plug-in gave it.
        """
        asset.source = self.source
        asset.source_class = "private"
        if not (finished and asset.source_name):
            asset.source_name = self.title
        if not (finished and asset.collected_at):
            asset.collected_at = str(record.get("collected_on") or self.collected_on)
        asset.extra = {**asset.extra, **(record.get("x") or {}), "plugin": self.plugin}
        return asset

    def name_host(self, raw: str) -> tuple[str, str]:
        """(host, ip) for a machine a record names, by the rule in :mod:`takestock.identity`."""
        named = self.names.get(scan_address(raw).lower(), "")
        return identity.row_identity(named, raw)


def build_rows(kind: str, records: list[dict], b: Build) -> tuple[list[CryptoAsset], list]:
    """Rows and coverage gaps for a plug-in's validated records."""
    shape = spec(kind)["shape"]
    if shape == "software":
        return _software_rows(records, b)
    if shape == "disk":
        return [_disk_row(r, b) for r in records], []
    if shape == "control":
        return [_control_row(kind, r, b) for r in records], []
    if shape == "mail":
        return _mail_rows(records, b), []
    if shape == "listener":
        return [_listener_row(r, b) for r in records], []
    raise ValueError(f"{SCHEMA_FILE}: kind {kind!r} has unknown shape {shape!r}")


def _place(tokens: Iterable[str], tables: tuple[str, ...], aliases: Mapping[str, str],
           b: Build, asset: CryptoAsset) -> list[str]:
    """Put each token in the row field its baseline table grades; return the tokens not placed."""
    unplaced = []
    for raw in tokens:
        token = aliases.get(raw.strip().lower(), raw.strip())
        placed = netdev.place(b.policy, token, tables)
        if placed is None:
            unplaced.append(raw)
            continue
        table, value = placed
        where = netdev.TABLE_FIELD[table]
        if where.startswith("extra:"):
            asset.extra.setdefault(where[len("extra:"):], []).append(value)
        else:
            getattr(asset, where).append(value)
    for raw in unplaced:
        asset.flags.append(f"ungraded:{b.kind}:{raw}")
    return unplaced


def _software_rows(records: list[dict], b: Build) -> tuple[list[CryptoAsset], list]:
    inventory = [{"host": r["device"], "product": r["product"], "version": r.get("version", ""),
                  "vendor": r.get("vendor", ""), "path": r.get("path", "")} for r in records]
    rows, gaps = software_inventory.assess(
        b.target, inventory, shown=b.shown, source_name=b.title, mtime=b.collected_on,
        source=b.source, scope_name=f"{b.title} scope")
    for a in rows:
        a.extra["plugin"] = b.plugin
    return rows, gaps


def _disk_row(r: dict, b: Build) -> CryptoAsset:
    s = spec("endpoint-encryption")
    host, ip = b.name_host(r["device"])
    volume = r["volume"]
    state = r["state"]
    a = CryptoAsset(
        name=f"Disk encryption {host} {volume}", data_state="at-rest",
        protocol="disk-encryption", host=host, ip=ip,
        role=f"Whether volume {volume} on {host} is unreadable if the device is lost or taken",
        extra={"volume": volume, "state": state})
    for key in ("volume_type", "device_id", "method"):
        if key in r:
            a.extra[key] = r[key]
    if "key_protectors" in r:
        a.extra["key_protectors"] = ", ".join(r["key_protectors"])
    method = r.get("method", "")
    if state == "encrypted":
        if method:
            _place([method], tuple(s["tables"]), s.get("aliases") or {}, b, a)
            note = f"Volume {volume} is encrypted with {method}."
        else:
            a.flags.append(NOT_RECORDED)
            note = (f"Volume {volume} is reported encrypted, with no cipher recorded, so its "
                    "strength is not graded.")
    elif state == "not-encrypted":
        a.verdict = "weak"
        a.flags.append(ENCRYPTION_OFF)
        note = f"Volume {volume} is not encrypted: anyone holding the disk can read it."
    elif state == "suspended":
        a.verdict = "weak"
        a.flags.append(ENCRYPTION_SUSPENDED)
        note = (f"Volume {volume} is encrypted with its protection suspended: the key is "
                "stored readable on the disk, so the encryption protects nothing until it is "
                "resumed.")
    elif state == "in-progress":
        a.flags.append(ENCRYPTION_IN_PROGRESS)
        note = f"Volume {volume} was part-way through encrypting or decrypting when read."
    else:
        a.flags.append(STATE_UNKNOWN)
        note = f"Whether volume {volume} is encrypted was not recorded."
    escrowed = r.get("recovery_key_escrowed")
    if escrowed is True:
        a.flags.append(RECOVERY_ESCROWED)
    elif escrowed is False:
        a.flags.append(RECOVERY_NOT_ESCROWED)
        note += (" No recovery key is held anywhere but the device, so a lost unlock method "
                 "loses the data.")
    a.notes = note
    a.flags = sorted(set(a.flags))
    return b.stamp(a, r)


def _control_row(kind: str, r: dict, b: Build) -> CryptoAsset:
    s = spec(kind)
    subject = r[s["subject"]]
    control = r.get("setting") or r["control"]
    c = s["controls"][control]
    host_field = _HOST_FIELD.get(kind, "")
    host, ip = b.name_host(r[host_field]) if r.get(host_field) else ("", "")
    label = c["label"]
    state = r["state"]
    a = CryptoAsset(
        name=f"{label} {subject}", data_state=c["data_state"], protocol=c["protocol"],
        host=host, ip=ip, role=f"{label}: {subject}",
        software=str(r.get("platform") or r.get("engine") or ""), version=str(r.get("version") or ""),
        extra={"control": control, "state": state, s["subject"]: subject})
    for key, value in r.items():
        if key in ("x", "collected_on", "state", "setting", "control", s["subject"], "platform",
                   "engine", "version"):
            continue
        a.extra[key] = ", ".join(value) if isinstance(value, list) else value
    grade = c["grade"]
    algorithms = r.get("algorithms") or []
    if grade == "presence":
        a.verdict = NA_VERDICT
        a.flags.append(f"{control}:{'present' if state == 'on' else 'absent' if state == 'off' else state}")
        note = f"{label} for {subject}: {state}."
    elif state == "off":
        a.verdict = "weak"
        a.flags.append(ENCRYPTION_OFF if grade == "algorithms" else f"{CONTROL_OFF}{control}")
        note = f"{label} is off for {subject}."
    elif state == "partial":
        a.verdict = "weak"
        a.flags.append(f"{CONTROL_PARTIAL}{control}")
        note = (f"{label} is on for only part of {subject}, so the row is graded on the part "
                "without it.")
    elif state == "unknown":
        a.flags.append(STATE_UNKNOWN)
        note = f"Whether {label.lower()} is on for {subject} was not recorded."
    elif grade == "setting":
        a.verdict = "acceptable"
        note = (f"{label} is on for {subject}. An on-or-off setting, not a graded algorithm, so "
                "the row is acceptable and never strong.")
    elif algorithms:
        _place(algorithms, tuple(c.get("tables") or ()), s.get("aliases") or {}, b, a)
        note = f"{label} is on for {subject}, using {', '.join(algorithms)}."
    else:
        a.flags.append(NOT_RECORDED)
        note = f"{label} is on for {subject}, with no algorithm recorded, so its strength is not graded."
    a.notes = note
    a.flags = sorted(set(a.flags))
    return b.stamp(a, r)


def tls_label(raw: str) -> str:
    """A TLS version spelled the way the mail-transport rows spell it (``TLS1.2``), or NO_TLS_LABEL."""
    text = str(raw or "").strip()
    if text.lower() in _NO_TLS:
        return NO_TLS_LABEL
    m = _TLS_SPELLING.match(text)
    if not m:
        return text
    return f"{m.group(1).upper()}{m.group(2)}.{m.group(3) or '0'}"


@dataclass
class _Path:
    direction: str
    path: str
    configured: bool | None = None
    messages: int = 0
    versions: dict[str, int] = field(default_factory=dict)
    domains: set[str] = field(default_factory=set)
    govt: int = 0
    govt_versions: dict[str, int] = field(default_factory=dict)
    govt_domains: set[str] = field(default_factory=set)
    govt_days: set[str] = field(default_factory=set)
    collected: str = ""


def _distribution(counts: Mapping[str, int]) -> str:
    return "; ".join(f"{v}={n}" for v, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _mail_rows(records: list[dict], b: Build) -> list[CryptoAsset]:
    paths: dict[tuple[str, str], _Path] = {}
    split = any("government" in r for r in records)
    basis = next((r["government_basis"] for r in records if r.get("government_basis")), "")
    days = sorted({r["date"] for r in records if r.get("date")})
    for r in records:
        key = (r["direction"], r.get("path") or "direct")
        p = paths.setdefault(key, _Path(*key))
        n = r.get("messages", 1)
        version = tls_label(r["tls_version"])
        p.messages += n
        p.versions[version] = p.versions.get(version, 0) + n
        if "route_configured" in r:
            p.configured = bool(p.configured) or r["route_configured"]
        if r.get("counterparty_domain"):
            p.domains.add(r["counterparty_domain"].lower())
        if r.get("government"):
            p.govt += n
            p.govt_versions[version] = p.govt_versions.get(version, 0) + n
            if r.get("counterparty_domain"):
                p.govt_domains.add(r["counterparty_domain"].lower())
            if r.get("date"):
                p.govt_days.add(r["date"])
        p.collected = max(p.collected, str(r.get("collected_on") or ""))
    window = f"{days[0]} to {days[-1]}" if days else ""
    rows = [_path_row(p, split, basis, window, b) for _, p in sorted(paths.items())]
    rows.append(_mail_scope_row(list(paths.values()), split, basis, window, b))
    return rows


def _path_row(p: _Path, split: bool, basis: str, window: str, b: Build) -> CryptoAsset:
    clear = p.versions.get(NO_TLS_LABEL, 0)
    named = sorted(v for v in p.versions if v != NO_TLS_LABEL)
    flags: list[str] = []
    graded: list[str] = []
    for v in named:
        g = b.policy.grade_tls_version(v)
        if g == "unknown":
            flags.append(f"ungraded:tls_versions:{v}")
            continue
        graded.append(g)
        if g == "weak":
            flags.append(f"deprecated-protocol:{v}")
    if clear:
        flags.append(f"{MAIL_CLEARTEXT}{p.direction}")
        verdict = "weak"
    else:
        verdict = worst(graded)
    verb = "left" if p.direction == "outbound" else "arrived"
    dist = _distribution(p.versions)
    note = (f"{p.messages} message(s) {verb} on this path"
            + (f" over {window}" if window else "") + f": {dist}.")
    if clear:
        note += f" {clear} of them crossed the network with no transport encryption at all."
    note += (" Each reading is the transport negotiated with the immediate peer for one "
             "delivery; it says nothing about what any message contained.")
    extra: dict[str, Any] = {
        "direction": p.direction, "path": p.path,
        "connector_present": "" if p.configured is None else ("yes" if p.configured else "no"),
        "messages": str(p.messages), "no_tls_messages": str(clear),
        "tls_distribution": dist, "counterparty_domains": str(len(p.domains)),
        "plugin": b.plugin,
    }
    if window:
        extra["window"] = window
    if split:
        extra.update({
            "govt_messages": str(p.govt),
            "govt_no_tls_messages": str(p.govt_versions.get(NO_TLS_LABEL, 0)),
            "govt_tls_distribution": _distribution(p.govt_versions) or "none",
            "govt_counterparty_domains": str(len(p.govt_domains)),
            "govt_days": str(len(p.govt_days)),
            "govt_identified_by": basis,
        })
    return CryptoAsset(
        name=f"{p.direction.capitalize()} mail via {p.path}", data_state="in-transit",
        protocol="smtp", role=f"{p.direction.capitalize()} mail on the {p.path} path",
        source=b.source, source_class="private", source_name=b.title,
        collected_at=p.collected or b.collected_on, verdict=verdict, flags=sorted(set(flags)),
        protocol_versions=named, usage_count=p.messages, notes=note, extra=extra)


def _mail_scope_row(paths: list[_Path], split: bool, basis: str, window: str,
                    b: Build) -> CryptoAsset:
    total = sum(p.messages for p in paths)
    by_direction: dict[str, int] = {}
    for p in paths:
        by_direction[p.direction] = by_direction.get(p.direction, 0) + p.messages
    shown = ", ".join(f"{n} {d}" for d, n in sorted(by_direction.items()))
    extra: dict[str, Any] = {"messages": str(total), "paths": str(len(paths)), "plugin": b.plugin,
                             **{f"messages_{d}": str(n) for d, n in by_direction.items()}}
    if window:
        extra["window"] = window
    if split:
        extra["govt_messages_total"] = str(sum(p.govt for p in paths))
        extra["govt_counterparty_domains_total"] = str(len(set().union(*(p.govt_domains
                                                                         for p in paths))))
        extra["govt_identified_by"] = basis
    return CryptoAsset(
        name=f"{b.title} scope", data_state="in-transit", protocol="smtp",
        role="What the mail transport record covers: how many messages, on how many paths",
        source=b.source, source_class="private", source_name=b.title,
        collected_at=b.collected_on, verdict=NA_VERDICT, flags=[SCOPE_FLAG], usage_count=total,
        notes=(f"This record covers {total} message(s) ({shown or 'none'}) on {len(paths)} "
               f"path(s), over {window or 'a window the records do not date'}. Every finding on "
               "the path rows is bounded by it. It is a count of what was supplied, not a share "
               "of all mail."),
        extra=extra)


def _listener_row(r: dict, b: Build) -> CryptoAsset:
    host, ip = b.name_host(r["device"])
    port, transport = str(r["port"]), r["transport"]
    known = lookup(port, transport, b.port_table)
    a = CryptoAsset(
        name=f"Host listener {host}:{port}/{transport}", data_state="in-transit",
        protocol=str((known or {}).get("protocol") or transport), host=host, ip=ip, port=port,
        software_binary=str(r.get("process") or ""),
        role=f"A program listening on {port}/{transport} on {host}",
        notes=f"{LISTENER_MARKER} `{b.plugin}` ({b.title}).",
        extra={"service": f"{port}/{transport}"})
    if r.get("address"):
        a.extra["bound_address"] = r["address"]
    apply_posture(a, b.port_table, transport, host_listener=True)
    return b.stamp(a, r)


def scope_gap(plugin: str, kind: str, shown: str) -> coverage.Gap:
    """The gap for a row-kind plug-in that read its input and returned no records."""
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"plug-in `{plugin}` ({kind}) read {shown} and returned no records, so nothing of that "
        "kind is measured in this observation",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("An empty result is not a clean one: the input may be empty, filtered, or in a "
                "layout the plug-in does not read."),
        harvest="Check the input holds records, and that the plug-in reads its layout.",
        nature=coverage.NO_DATA)
