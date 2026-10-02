"""How a row about one host is named, so one machine reads as one machine in every collector.

A ``scan_targets`` entry in the target profile can give a host name, an
address, or both (a mapping with ``host:`` and ``ip:``). When both are given
the address is what gets probed. Every collector names its rows by the same
rule:

* ``host`` is the host name when the profile gives one, and the address only
  when it gives nothing else;
* ``ip`` is the probed address when the row is named by a host name, and blank
  otherwise. It never holds a host name;
* the row's ``name`` reads ``<label> <host>:<port>``.

The configuration register (:mod:`takestock.cmdb`) keys a machine by its
``host`` and records its address from ``ip``, so two collectors that probed
the same entry contribute to one item rather than splitting it in two.
"""

from __future__ import annotations

from collections.abc import Mapping

from .model import CryptoAsset
from .util import scan_address


def row_identity(name: str, probe: str) -> tuple[str, str]:
    """``(host, ip)`` for a row named ``name`` (may be blank) whose probe went to ``probe``."""
    name, probe = name.strip(), probe.strip()
    if name and probe and name != probe:
        return name, probe
    return name or probe, ""


def _key(value: str) -> str:
    return scan_address(value).lower()


def names_by_address(target: Mapping) -> dict[str, str]:
    """The host name for each address the profile's ``scan_targets`` pairs with one.

    Read from every mapping entry carrying both ``host:`` and ``ip:``, in any
    group. An address paired with two different names is left out, so its rows
    stay named by the address rather than by a guess.
    """
    found: dict[str, set[str]] = {}
    groups = target.get("scan_targets") or {}
    if not isinstance(groups, Mapping):
        return {}
    for entries in groups.values():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("host") or "").strip()
            addr = str(entry.get("ip") or "").strip()
            if name and addr and _key(name) != _key(addr):
                found.setdefault(_key(addr), set()).add(name)
    return {addr: next(iter(names)) for addr, names in found.items() if len(names) == 1}


def report_as(asset: CryptoAsset, names: Mapping[str, str]) -> CryptoAsset:
    """Rename a row built at its probed address after that address's host name, if one is known.

    ``names`` is :func:`names_by_address`. The address moves to ``ip`` and the
    ``<host>:<port>`` part of the row's name follows the host. A row already
    named by a host name, or at an address with no known name, is unchanged.
    """
    name = names.get(_key(asset.host), "") if asset.host else ""
    host, ip = row_identity(name, asset.host)
    if host != asset.host:
        asset.name = asset.name.replace(f" {asset.host}:", f" {host}:", 1)
        asset.host, asset.ip = host, ip
    return asset
