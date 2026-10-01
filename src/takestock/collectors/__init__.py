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
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import NamedTuple

KINDS = ("passive", "active", "ingest")


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
# ── ingest: supplied exports ──
register("ssh_audit_inbox", "ssh_audit", "ingest", "collect_inbox")
