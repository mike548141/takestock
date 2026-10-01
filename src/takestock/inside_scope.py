"""Authorisation gates for active probes.

An active collector sends real packets to real machines, so whether it may
run is never a property of how it was invoked. It is a property of the
**target profile**, which must carry an ``authorisation:`` stanza naming the
scope, who authorised it, and when::

    authorisation:
      scope: "Published web and mail endpoints of Example Widgets Ltd"
      authorised_by: "Security manager"
      date: "2030-01-31"

Probes that run **inside** a network need more than that: each one also
needs its own named, dated record under the same stanza, keyed by the
``scan_targets`` group it reads::

    authorisation:
      ...
      smb_445:
        scope: "File servers on the office network"
        authorised_by: "Infrastructure lead"
        date: "2030-01-31"

and each host must be named one at a time. Subnets, ranges, wildcards and
lists are refused by construction, a list longer than its ceiling is refused
rather than cut short, and a host named twice is refused.

Guard declaration: every gate here **forbids the act**. A probe that has
already left the machine cannot be recalled, so there is no cheap recovery
to offer instead. The stanza is a record, not a cryptographic control:
anyone who can edit the profile can write one. It exists so that an
embedding program cannot point the probes at hosts nobody authorised, and so
that every run states who authorised it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from .util import is_ipv6_literal, scan_address

#: The fields every authorisation record must fill.
AUTH_FIELDS = ("scope", "authorised_by", "date")

#: The most hosts one probe group may name. Larger lists are refused, not truncated.
MAX_HOSTS = 60

_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_NUMERIC_RANGE = re.compile(r"^[0-9.]*-[0-9.-]*$")
_IPV6 = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+)$")


class InsideRefused(ValueError):
    """A probe will not run: the reason is the message, and nothing was contacted."""


def refusal(source: str, exc: Exception) -> str:
    """The failure line a collector returns when a gate refuses it."""
    return f"{source}: REFUSED, nothing contacted — {exc}"


def scan_authorisation_problems(target: Mapping) -> list[str]:
    """Why ``target`` may not be actively probed at all, or [] if it may."""
    auth = target.get("authorisation")
    if not isinstance(auth, Mapping) or not auth:
        return ["no `authorisation:` stanza in the target profile"]
    return [f"`authorisation.{f}` is missing or empty"
            for f in AUTH_FIELDS if not str(auth.get(f) or "").strip()]


def require_scan_authorisation(target: Mapping) -> None:
    """Raise :class:`InsideRefused` unless the target's general stanza is complete."""
    problems = scan_authorisation_problems(target)
    if problems:
        raise InsideRefused("; ".join(problems))


def scan_refusal(source: str, target: Mapping) -> str:
    """The refusal line for ``source`` when the target is not authorised, else ""."""
    try:
        require_scan_authorisation(target)
    except InsideRefused as exc:
        return refusal(source, exc)
    return ""


def declared(target: Mapping, key: str) -> bool:
    """True when the target profile names ``scan_targets.<key>`` at all, even empty."""
    groups = target.get("scan_targets") or {}
    return isinstance(groups, Mapping) and key in groups


def authorisation_problems(target: Mapping, key: str) -> list[str]:
    """Why the inside probe reading ``key`` may not run, or [] if it may."""
    general = scan_authorisation_problems(target)
    if general:
        return general
    record = target["authorisation"].get(key)
    if not isinstance(record, Mapping):
        return [f"no `authorisation.{key}:` record — this probe runs inside the network "
                "and needs its own named, dated authorisation beside the profile's "
                "general one"]
    return [f"`authorisation.{key}.{field}` is missing or empty"
            for field in AUTH_FIELDS
            if not str(record.get(field) or "").strip()]


def require_authorisation(target: Mapping, key: str) -> None:
    """Raise :class:`InsideRefused` unless the inside probe for ``key`` is authorised."""
    problems = authorisation_problems(target, key)
    if problems:
        raise InsideRefused("; ".join(problems))


def entries(target: Mapping, key: str) -> list:
    """The entries of ``scan_targets.<key>``, once the probe is authorised.

    An undeclared group gives [] without checking anything, so a profile that
    does not ask for a probe never hears from it. A declared group, even an
    empty one, must carry its authorisation.
    """
    if not declared(target, key):
        return []
    require_authorisation(target, key)
    raw = (target.get("scan_targets") or {}).get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise InsideRefused(f"`scan_targets.{key}:` must be a list of named hosts")
    return raw


def host_problem(host: str) -> str:
    """Why ``host`` is not one named host or address, or "" when it is."""
    h = host.strip()
    if not h:
        return "names no host"
    ok = _IPV6.match(h) if is_ipv6_literal(h) else (
        _NAME.match(h) and not _NUMERIC_RANGE.match(h))
    if not ok:
        return (f"{h!r} is not one named host or address. Subnets, ranges, wildcards "
                "and lists are refused by construction — name each host")
    return ""


def check_host(host: str, where: str) -> str:
    """``host`` stripped, or :class:`InsideRefused` naming ``where``."""
    problem = host_problem(host)
    if problem:
        raise InsideRefused(f"{where}: {problem}")
    return host.strip()


def entry_address(entry: object, where: str) -> tuple[str, str]:
    """(address to probe, name to report) for one entry.

    An entry is a host name, or a mapping with ``host:`` and optionally
    ``ip:``. When both are given the address is probed and the name is
    reported, and both must pass :func:`host_problem`.
    """
    if isinstance(entry, Mapping):
        name = str(entry.get("host") or "").strip()
        addr = str(entry.get("ip") or "").strip()
    elif isinstance(entry, str):
        name, addr = entry.strip(), ""
    else:
        raise InsideRefused(f"{where}: {entry!r} is neither a host name nor a mapping "
                            "with `host:`")
    if not (name or addr):
        raise InsideRefused(f"{where}: names no host")
    address = check_host(addr or name, where)
    return address, (check_host(name, where) if name else address)


def _same(value: object) -> object:
    return scan_address(value).lower() if isinstance(value, str) else value


def check_unique(keys: Iterable[tuple], where: str) -> None:
    """Refuse a list that names the same key twice (case-blind, brackets ignored)."""
    seen: set[tuple] = set()
    for key in keys:
        norm = tuple(_same(v) for v in key)
        if norm in seen:
            label = ":".join(str(v) for v in key)
            raise InsideRefused(f"{where} names {label} twice")
        seen.add(norm)


def check_ceiling(count: int, ceiling: int, where: str, noun: str = "hosts") -> None:
    """Refuse, rather than truncate, a list longer than ``ceiling``."""
    if count > ceiling:
        raise InsideRefused(
            f"{where} names {count} {noun}; the ceiling is {ceiling}. REFUSED rather than "
            "truncated — a truncated probe reports what it skipped as though nothing "
            "were there")
