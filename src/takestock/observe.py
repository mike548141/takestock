"""Taking one observation: run the collectors, normalise their rows, write the result.

An observation is a directory ``observations/<UTC stamp>/`` in the workspace
(the stamp looks like ``2030-01-31T0930Z``), holding:

* ``raw/``: every transcript and reply the collectors kept;
* ``assets.json``: every row, graded and placed;
* ``summary.json``: counts, readings across the estate, coverage gaps, any
  collector failures, the findings, and each row's dispensation state (see
  :mod:`takestock.dispensation`), assessed on the observation's date;
* ``bom.cdx.json``: the rows as a CycloneDX 1.6 cryptographic bill of
  materials. It is written last, so its presence marks a finished run.

Which collectors run (see :mod:`takestock.collectors` for the kinds):

* **passive** collectors read public sources and run on every observation,
  unless ``offline`` is set. Offline, the DNS zone collector still reads its
  supplied files but looks nothing up;
* **active** collectors send probes, and run only when ``scan`` is set and
  the target profile carries a complete ``authorisation:`` stanza. Without
  one the observation is refused before anything is written or contacted;
* **ingest** collectors read supplied exports and always run.

Whatever does not run is recorded as a coverage gap on the observation, so
an unread area never reads as a clean one. The same holds for a public
service nobody has configured (a certificate-transparency endpoint, a DNSSEC
validation control, independent resolvers): a collector reports that as a
:class:`~takestock.coverage.Gap` in its failures list, and it is filed as a
gap. Only a real failure, such as a configured service that errors, is a
failure, and only a failure makes the observation unable to judge.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from types import ModuleType

from . import (
    __version__,
    collectors,
    config,
    coverage,
    ctcache,
    dispensation,
    dnsevidence,
    inside_scope,
    normalise,
    sge,
)
from .collectors import ct_dns
from .disposition import load_dispositions_for_target
from .exits import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS
from .model import CryptoAsset, dump_assets, to_cyclonedx, write_json
from .policy import Policy
from .util import ERROR_PREFIX

STAMP_FORMAT = "%Y-%m-%dT%H%MZ"
LATEST = "latest"


class ObserveRefused(Exception):
    """The observation will not be taken; nothing was written and nothing contacted."""


@dataclass
class Options:
    """How to take one observation."""

    scan: bool = False
    offline: bool = False
    refresh_ct: bool = False
    now: datetime | None = None
    announce: Callable[[str], None] = field(
        default=lambda line: print(line, file=sys.stderr, flush=True))


@dataclass
class Result:
    """What one observation produced, and the exit code it earns."""

    observation: Path
    assets: list[CryptoAsset]
    summary: dict
    failures: list[str]
    findings: list[dict]

    @property
    def exit_code(self) -> int:
        """2 when a collector failed (the run could not judge), else 1 with findings, else 0."""
        if self.failures:
            return EXIT_ERROR
        return EXIT_FINDINGS if self.findings else EXIT_CLEAN


@dataclass
class _Run:
    """State shared by the collector steps of one observation."""

    target: dict
    raw: Path
    observations: Path
    options: Options
    assets: list[CryptoAsset] = field(default_factory=list)
    gaps: list = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    ct_deferral: ct_dns.CTDeferral | None = None
    ct_failures: list[str] = field(default_factory=list)
    ct_reused: list[ctcache.Cached] = field(default_factory=list)

    @property
    def ref_time(self) -> datetime | None:
        return self.options.now

    @property
    def say(self) -> Callable[[str], None]:
        return self.options.announce


# A step runs one collector against the run and returns (rows, failures, gaps).
Step = Callable[[_Run], tuple[list[CryptoAsset], list[str], list]]


def split_failures(items: list) -> tuple[list[str], list[coverage.Gap]]:
    """(real failures, gaps) from a collector's failures list.

    A collector reports a service that is not configured as a
    :class:`~takestock.coverage.Gap`: nothing went wrong, so it is a gap.
    """
    gaps = [g for g in items if isinstance(g, coverage.Gap)]
    return [str(f) for f in items if not isinstance(f, coverage.Gap)], gaps


def _mod(module: str) -> ModuleType:
    """A collector module by its module name, imported on first use."""
    return import_module(f"{collectors.__name__}.{module}")


def _ct_failure_gap(failures: list[str]) -> coverage.Gap:
    return coverage.gap(coverage.NOT_COLLECTED, ct_dns.failure_gap(failures),
                        nature=coverage.NO_DATA)


def _ct_dns(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    run.ct_deferral = ct_dns.CTDeferral()
    rows, failures, reused = ct_dns.collect(
        run.target, run.raw, run.ref_time, observations=run.observations,
        refresh=run.options.refresh_ct, progress=run.say, deferral=run.ct_deferral)
    run.ct_reused = reused
    # Mail-record lookups that did not settle are failures, but not transparency ones.
    run.ct_failures = [str(f) for f in failures
                       if not isinstance(f, (coverage.Gap, ct_dns.MailLookupFailure))]
    failures, gaps = split_failures(list(failures))
    if reused:
        gaps.append(coverage.gap(coverage.COULD_NOT_TEST, ctcache.reuse_gap(reused),
                                 nature=coverage.LOW_FIDELITY))
    if run.ct_failures and not run.ct_deferral.pending:
        gaps.append(_ct_failure_gap(run.ct_failures))
    return rows, failures, gaps


def _relay_probe(run: _Run) -> Callable[[str, str], tuple[CryptoAsset, list[str]]] | None:
    if not _active_allowed(run):
        return None

    def probe(host: str, role: str) -> tuple[CryptoAsset, list[str]]:
        return _mod("smtp_starttls").measure(host, run.raw, run.ref_time, role)
    return probe


def _spf_senders(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    rows, gaps = _mod("spf_senders").collect(run.target, run.ref_time,
                                             scan=_active_allowed(run), probe=_relay_probe(run))
    return rows, [], list(gaps)


def _rows_and_failures(module: str, function: str = "collect",
                       **kwargs: Callable[[_Run], object]) -> Step:
    """A step for a collector returning (rows, failures) from ``(target, ...)``.

    Each keyword names an argument of the collector's entry point and gives
    the function that reads its value off the run.
    """
    def step(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
        fn = getattr(_mod(module), function)
        values = {k: v(run) for k, v in kwargs.items()}
        rows, failures = fn(run.target, **values)
        return list(rows), list(failures), []
    return step


def _raw(run: _Run) -> Path:
    return run.raw


def _ref(run: _Run) -> datetime | None:
    return run.ref_time


def _announce(run: _Run) -> Callable[[str], None]:
    return run.say


def _caa(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    certificates = [a for a in run.assets if a.data_state == "certificate"]
    rows, failures = _mod("caa").collect(run.target, certificates, run.ref_time, raw_dir=run.raw)
    return rows, failures, []


def _offline_reader(*_args: object) -> str:
    return f"{ERROR_PREFIX} offline: no lookup was made"


def _dns_zones(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    reader = _offline_reader if run.options.offline else None
    rows, gaps = _mod("dns_zones").collect(run.target, None, list(run.assets), run.ref_time,
                                           reader=reader)
    if run.options.offline and rows:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            "dns_zones: run offline, so no record's target was looked up and no dangling "
            "record could be found",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="The zone files were read; whether their pointers lead anywhere was not.",
            harvest="Run the observation again without --offline.",
            nature=coverage.LOW_FIDELITY))
    return rows, [], list(gaps)


def _ike(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    ike_scan = _mod("ike_scan")
    rows, failures = ike_scan.collect(run.target, run.raw, run.ref_time)
    return rows, failures, list(ike_scan.coverage_gaps(rows))


def _hsts(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    hsts = _mod("hsts")
    rows, failures = hsts.collect(run.target, run.raw, run.ref_time)
    return rows, failures, list(hsts.coverage_gaps(run.target, rows))


def _ports_declared(target: dict) -> bool:
    if target.get(_mod("plaintext_scan").TARGET_KEY) is not None:
        return True
    return config.derived_ports_path_for_target(target) is not None


def _port_probe(module: str, **kwargs: Callable[[_Run], object]) -> Step:
    """A step for a probe whose ports come from the profile's own port list."""
    inner = _rows_and_failures(module, "collect", **kwargs)

    def step(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
        if not _ports_declared(run.target):
            run.skipped[module] = "the target profile declares no ports for it"
            return [], [], []
        return inner(run)
    return step


def _ssh_inbox(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    rows, gaps = _mod("ssh_audit").collect_inbox(run.target)
    return rows, [], list(gaps)


def _ingest(module: str) -> Step:
    """A step for an ingest collector returning (rows, coverage gaps) from ``(target)``."""
    def step(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
        rows, gaps = _mod(module).collect(run.target)
        return list(rows), [], list(gaps)
    return step


def _winrm_config(run: _Run) -> tuple[list[CryptoAsset], list[str], list]:
    # Reads the run's other rows, to name listeners the export does not cover.
    rows, gaps = _mod("winrm_config").collect(run.target, other_assets=list(run.assets))
    return list(rows), [], list(gaps)


@dataclass(frozen=True)
class Plan:
    """How the observation runs one registered collector.

    ``late`` steps read the rows the earlier ones produced, so they run after
    every other step. ``offline`` steps keep themselves off the network and
    may run in an offline observation.
    """

    step: Step
    late: bool = False
    offline: bool = False


#: The step for every registered collector, by registry name.
PLANS: dict[str, Plan] = {
    "ct_dns": Plan(_ct_dns),
    "spf_senders": Plan(_spf_senders),
    "dnssec": Plan(_rows_and_failures("dnssec", ref_time=_ref)),
    "dane": Plan(_rows_and_failures("dane", ref_time=_ref)),
    "caa": Plan(_caa, late=True),
    "dns_zones": Plan(_dns_zones, late=True, offline=True),
    "tls_scan": Plan(_rows_and_failures("tls_scan", raw_dir=_raw, ref_time=_ref)),
    "ike_scan": Plan(_ike),
    "ssh_audit": Plan(_rows_and_failures("ssh_audit", raw_dir=_raw, ref_time=_ref)),
    "plaintext_scan": Plan(_port_probe("plaintext_scan", raw_dir=_raw, ref_time=_ref,
                                       announce=_announce)),
    "hsts": Plan(_hsts),
    "smtp_starttls": Plan(_rows_and_failures("smtp_starttls", raw_dir=_raw, ref_time=_ref)),
    "implicit_tls": Plan(_port_probe("implicit_tls", raw_dir=_raw, ref_time=_ref)),
    "smb_scan": Plan(_rows_and_failures("smb_scan", raw_dir=_raw, ref_time=_ref,
                                        announce=_announce)),
    "rdp_scan": Plan(_rows_and_failures("rdp_scan", raw_dir=_raw, ref_time=_ref,
                                        announce=_announce)),
    "ssh_audit_inside": Plan(_rows_and_failures("ssh_audit", "collect_inside", raw_dir=_raw,
                                                ref_time=_ref, announce=_announce)),
    "internal_scan": Plan(_rows_and_failures("internal_scan", raw_dir=_raw, ref_time=_ref,
                                             announce=_announce)),
    "intel_amt": Plan(_rows_and_failures("intel_amt", raw_dir=_raw, ref_time=_ref,
                                         announce=_announce)),
    "ssh_audit_inbox": Plan(_ssh_inbox, offline=True),
    "winrm_config": Plan(_winrm_config, late=True, offline=True),
    "netdev": Plan(_ingest("netdev"), offline=True),
    "software_inventory": Plan(_ingest("software_inventory"), offline=True),
}


def _active_allowed(run: _Run) -> bool:
    return run.options.scan and not inside_scope.scan_authorisation_problems(run.target)


def _why_not(run: _Run, name: str) -> str:
    """Why collector ``name`` does not run in this observation, or "" when it does."""
    kind = collectors.REGISTRY[name].kind
    plan = PLANS.get(name)
    if plan is None:
        return "no step is defined for it"
    if run.options.offline and kind != "ingest" and not plan.offline:
        return "the observation was run offline"
    if kind == "active" and not run.options.scan:
        return "active probes need --scan"
    return ""


def _run_step(run: _Run, name: str) -> None:
    run.say(f"  · {name}")
    try:
        rows, failures, gaps = PLANS[name].step(run)
    except Exception as exc:  # noqa: BLE001 - one broken collector must not end the run
        run.failures.append(f"{name}: stopped with {type(exc).__name__}: {exc}")
        return
    real, unconfigured = split_failures(list(failures))
    run.assets += rows
    run.failures += real
    run.gaps += list(gaps) + unconfigured
    if name not in run.skipped:
        run.ran.append(name)


def _skip_gaps(run: _Run) -> list[coverage.Gap]:
    """One gap per reason a group of collectors did not run."""
    by_reason: dict[str, list[str]] = {}
    for name, why in run.skipped.items():
        by_reason.setdefault(why, []).append(name)
    out = []
    for why, names in by_reason.items():
        out.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            f"{len(names)} collector(s) not run ({', '.join(names)}): {why}",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("Nothing those collectors would have measured is in this observation, "
                    "so an absent finding there means the question was not asked."),
            harvest="Run the observation again with the collectors enabled.",
            nature=coverage.NO_DATA))
    return out


def _resolver_gaps(target: dict) -> list[coverage.Gap]:
    """A gap when no independent resolvers are configured, so no DNS answer was corroborated."""
    if dnsevidence.resolvers(target) != ("",):
        return []
    return [coverage.gap(
        coverage.COULD_NOT_TEST,
        "not measured: no independent DNS resolvers are configured (`resolvers` in "
        "data/dns-services.yaml or the target's `dns:` block), so every lookup was asked of "
        "this machine's own resolver and no answer was corroborated by a second one",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Each DNS reading rests on one resolver's answer. Readings that need two "
                "resolvers to agree (a name that does not exist, a validated signature) "
                "are left unsettled rather than graded."),
        harvest="Configure two or more independent resolvers and run again.",
        nature=coverage.LOW_FIDELITY)]


def _metadata(target: dict, stamp: str, options: Options, complete: bool) -> dict:
    props = {
        "organisation": _organisation(target),
        "observation": stamp,
        "scan": str(options.scan).lower(),
        "offline": str(options.offline).lower(),
        "complete": str(complete).lower(),
    }
    return {
        "timestamp": _iso(options.now),
        "tools": {"components": [{"type": "application", "name": "takestock",
                                  "version": __version__}]},
        "properties": [{"name": f"takestock:{k}", "value": v} for k, v in props.items()],
    }


def _organisation(target: dict) -> str:
    from .htmlpage import organisation_name
    return organisation_name(target, default=str(target.get("name") or ""))


def _iso(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp_for(now: datetime | None = None) -> str:
    """The observation directory name for ``now`` (default: the current UTC time)."""
    return (now or datetime.now(UTC)).astimezone(UTC).strftime(STAMP_FORMAT)


def _point_latest(observations: Path, stamp: str) -> None:
    link = observations / LATEST
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        return
    try:
        os.symlink(stamp, link)
    except OSError:
        pass


def observe(target: dict, options: Options | None = None) -> Result:
    """Take one observation of ``target`` (a loaded profile) into the workspace.

    Raises :class:`ObserveRefused`, before anything is written or contacted,
    when ``scan`` is asked for and the profile's authorisation stanza is
    missing or incomplete, when both ``scan`` and ``offline`` are asked for,
    or when the observation directory already exists.
    """
    options = options or Options()
    if options.scan and options.offline:
        raise ObserveRefused("--scan and --offline ask for opposite things; choose one")
    if options.scan:
        problems = inside_scope.scan_authorisation_problems(target)
        if problems:
            raise ObserveRefused("--scan needs an authorisation record in the target profile: "
                                 + "; ".join(problems))
    options.now = options.now or datetime.now(UTC)
    stamp = stamp_for(options.now)
    observations = config.observations_dir()
    obs = observations / stamp
    if obs.exists() or obs.is_symlink():
        raise ObserveRefused(
            f"{obs} already exists. Observations are named to the minute; wait for the next "
            "minute, or use another workspace. Do not delete the directory to clear this: "
            "it may be a run still in progress")
    raw = obs / "raw"
    raw.mkdir(parents=True)

    run = _Run(target=target, raw=raw, observations=observations, options=options)
    run.say(f"observing {_organisation(target) or 'the target'} into {config.display_path(obs)}")
    run.say(f"  inbox: {config.inbox_dir()}")

    names = collectors.names()
    for name in names:
        why = _why_not(run, name)
        if why:
            run.skipped[name] = why
    early = [n for n in names if n not in run.skipped and not PLANS[n].late]
    late = [n for n in names if n not in run.skipped and PLANS[n].late]
    for name in early:
        _run_step(run, name)
    if run.ct_deferral is not None and run.ct_deferral.pending:
        rows, resumed = ct_dns.resume(run.ct_deferral)
        failures, gaps = split_failures(list(resumed))
        run.assets += rows
        run.gaps += gaps
        run.failures += failures
        run.ct_failures += failures
        if run.ct_failures:
            run.gaps.append(_ct_failure_gap(run.ct_failures))
    for name in late:
        _run_step(run, name)
    run.gaps += _skip_gaps(run)
    if not options.offline and any(collectors.REGISTRY[n].kind == "passive" for n in run.ran):
        run.gaps += _resolver_gaps(target)

    baseline = config.load_baseline()
    policy = Policy(baseline)
    rules = load_dispositions_for_target(target)
    assets, passes = normalise.finalise(run.assets, policy, config.load_dictionary(),
                                        dispositions=rules,
                                        lifecycle=target.get("lifecycle") or {})
    run.gaps += normalise.not_measured_gaps(assets)
    email_domains = [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]
    marked = sge.apply_conformance(assets, email_domains,
                                   bulk_mail_domains=sge.bulk_mail_domains(target),
                                   parked=sge.parked_domains(target))
    found = normalise.findings(assets, rules.out_of_cycle)
    # The rules carry the ladder's out-of-cycle rungs and the profile's
    # outside-provider list, which a record's `third_party` match reads.
    dispensations = dispensation.payload(assets, baseline,
                                         dispensation.records_for_target(target),
                                         asof=options.now.date(), rules=rules)

    summary = normalise.summarise(assets, run.gaps, rules)
    complete = not run.failures and not coverage.required_gaps(run.gaps)
    rel, _absolute = config.recorded_target_paths(str(target.get("_path") or ""))
    summary.update({
        "observation": {
            "stamp": stamp, "collected_at": _iso(options.now), "tool_version": __version__,
            "organisation": _organisation(target), "target": rel,
            "scan": options.scan, "offline": options.offline,
            "collectors_run": run.ran, "collectors_skipped": run.skipped,
        },
        "complete": complete,
        "collector_failures": run.failures,
        "findings": found,
        "standards_marked": marked,
        "dispensations": dispensations,
        "normalise": passes,
        "ct_cache": ctcache.summarise(
            run.ct_reused, list((target.get("discovery") or {}).get("domains") or []),
            ctcache.CT_CACHE_DAYS, options.refresh_ct),
    })

    write_json(dump_assets(assets), obs / "assets.json")
    write_json(summary, obs / "summary.json")
    write_json(to_cyclonedx(assets, _metadata(target, stamp, options, complete)),
               obs / "bom.cdx.json")
    _point_latest(observations, stamp)
    return Result(observation=obs, assets=assets, summary=summary,
                  failures=run.failures, findings=found)
