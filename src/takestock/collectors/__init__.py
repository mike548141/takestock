"""Collectors: each gathers one kind of evidence and returns CryptoAsset rows.

A collector module exposes an entry point, usually ``collect(target, ...)``,
which reads what the target profile names and returns its rows together with
a list of failures or coverage gaps: one line per thing the run cannot vouch
for. Some entry points take further inputs (the certificates already seen,
the run's other rows); each module's docstring says which.

:data:`REGISTRY` names each collector, the module that holds it, its entry
point, and how it gathers evidence:

* ``passive``: reads public sources (DNS, mail-authentication records,
  certificate-transparency logs) and sends nothing to the organisation's
  hosts.
* ``active``: sends probes to hosts. Runs only when the target profile
  carries an ``authorisation:`` stanza (see :mod:`takestock.inside_scope`).
* ``ingest``: reads exports someone supplied in the inbox.

Modules are imported only when asked for, so a collector whose optional
dependencies are missing does not stop the others loading.

A target profile can turn a built-in collector off by name, with a reason,
under ``collectors.disabled`` (see :func:`disabled`). The observation then
records it as not run, with that reason, instead of running it.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from types import ModuleType
from typing import NamedTuple

KINDS = ("passive", "active", "ingest")

#: The target-profile key that settles which built-in collectors run.
PROFILE_KEY = "collectors"
#: Under :data:`PROFILE_KEY`: the collectors turned off, each mapped to its reason.
DISABLED_KEY = "disabled"
#: How the observation records why a collector the profile turned off did not run.
DISABLED_REASON = "turned off by the target profile"


class Collector(NamedTuple):
    """One registry entry: the collector's name, its module, its kind and its entry point."""

    name: str
    module: str
    kind: str
    function: str = "collect"


REGISTRY: dict[str, Collector] = {}


def register(name: str, module: str, kind: str, function: str = "collect") -> None:
    """Add a collector; ``module`` is relative to this package (``tls_scan``)."""
    if kind not in KINDS:
        raise ValueError(f"collector kind {kind!r} is not one of {KINDS}")
    if name in REGISTRY:
        raise ValueError(f"collector {name!r} is registered twice")
    REGISTRY[name] = Collector(name, module, kind, function)


def load(name: str) -> ModuleType:
    """Import and return the module that holds collector ``name``."""
    return import_module(f"{__name__}.{REGISTRY[name].module}")


def names(kind: str | None = None) -> list[str]:
    """Registered collector names, in registration order, optionally of one kind."""
    return [n for n, c in REGISTRY.items() if kind is None or c.kind == kind]


def disabled(target: Mapping) -> dict[str, str]:
    """The built-in collectors ``target`` turns off, each mapped to the profile's reason.

    The profile names them under ``collectors.disabled``, one registered
    collector name to one reason::

        collectors:
          disabled:
            software_inventory: a plug-in reads the same evidence from another source

    No block gives {}. Raises :class:`ValueError` for a name that is not a
    registered collector (a typo must not quietly leave everything running),
    for a missing or empty reason, and for any other key or shape.
    """
    where = f"{target.get('_path')}: " if target.get("_path") else ""
    block = target.get(PROFILE_KEY)
    if block is None:
        return {}
    if not isinstance(block, Mapping):
        raise ValueError(f"{where}`{PROFILE_KEY}:` must be a mapping, not "
                         f"{type(block).__name__}")
    for key in block:
        if key == DISABLED_KEY:
            continue
        if isinstance(key, bool):
            raise ValueError(
                f"{where}`{PROFILE_KEY}:` has the key {key!r}. YAML reads an unquoted `off`, "
                f"`no` or `false` as the value false; the collectors to turn off go under "
                f"`{DISABLED_KEY}:`")
        raise ValueError(f"{where}`{PROFILE_KEY}:` has an unknown key {key!r}; the only key "
                         f"is `{DISABLED_KEY}:`")
    entries = block.get(DISABLED_KEY)
    if entries is None:
        return {}
    if not isinstance(entries, Mapping):
        raise ValueError(f"{where}`{PROFILE_KEY}.{DISABLED_KEY}:` must map each collector's "
                         "name to the reason it is turned off")
    unknown = sorted(str(n) for n in entries if n not in REGISTRY)
    if unknown:
        raise ValueError(
            f"{where}`{PROFILE_KEY}.{DISABLED_KEY}:` names {', '.join(map(repr, unknown))}, "
            f"which is not a registered collector. The registered collectors are: "
            f"{', '.join(REGISTRY)}")
    out: dict[str, str] = {}
    for name, reason in entries.items():
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"{where}`{PROFILE_KEY}.{DISABLED_KEY}.{name}:` needs a reason: "
                             "a sentence saying why the collector is turned off")
        out[str(name)] = reason.strip()
    return out


# ── passive: public DNS, mail authentication and certificate transparency ──
register("ct_dns", "ct_dns", "passive")
register("spf_senders", "spf_senders", "passive")
register("dnssec", "dnssec", "passive")
register("dane", "dane", "passive")
register("caa", "caa", "passive")
register("dns_zones", "dns_zones", "passive")

#: The passive DNS collectors, in run order.
PASSIVE_DNS = tuple(names("passive"))

# ── active probes: outside-in ──
register("tls_scan", "tls_scan", "active")
register("ike_scan", "ike_scan", "active")
register("ssh_audit", "ssh_audit", "active")
register("plaintext_scan", "plaintext_scan", "active")
register("hsts", "hsts", "active")
register("smtp_starttls", "smtp_starttls", "active")
register("implicit_tls", "implicit_tls", "active")
# ── active probes: inside the network (each needs its own authorisation record) ──
register("smb_scan", "smb_scan", "active")
register("rdp_scan", "rdp_scan", "active")
register("ssh_audit_inside", "ssh_audit", "active", "collect_inside")
register("internal_scan", "internal_scan", "active")
register("intel_amt", "intel_amt", "active")
# ── ingest: supplied exports ──
register("ssh_audit_inbox", "ssh_audit", "ingest", "collect_inbox")
register("winrm_config", "winrm_config", "ingest")
register("netdev", "netdev", "ingest")
register("software_inventory", "software_inventory", "ingest")
