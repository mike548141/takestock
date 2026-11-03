"""CrowdStrike Falcon: each machine's environment, from its host groups, on other readers' rows.

An **annotation** (``docs/PLUGINS.md``): it writes no rows. After grading it
puts ``extra.environment`` on every row that names a machine in the host
list, so a configuration register (takestock's ``cmdb`` reads the key) or a
remediation plan can order work production-first.

**The input** (``input:``) is the same sensor-managed host list
``falcon_estate_coverage`` reads; ``settings: columns: {hosts: {...}}``
names its headings as there (``machine``, ``sensor_id``, ``groups``).
``settings: environment: {production: [...], non_production: [...]}`` names
the words, read exactly as ``falcon_estate_coverage`` reads them (its
docstring, *Environments*); a profile can share one mapping between the two
with a YAML anchor. With no words named, no row is labelled.

**Which rows.** A row is matched to a machine by its ``extra.aid`` (the
sensor ID) first, then by its ``host``, ignoring case. A name worn by
several sensors whose labels disagree matches nothing. Rows that are not
about a machine are never labelled: certificates, credentials
(``key-material``), third parties, mail authentication, declared asset
classes (``estate``) and the ``ct_dns`` collector's name rows.

**The label** is a mapping: ``value`` (``production``, ``non-production``,
or blank), ``absent`` (when blank, the configuration register's absence
code: ``could-not-test`` for a machine in no group, ``not-measured`` for one
whose groups name no environment), ``note``, ``contested`` (``yes`` for a
machine in groups on both sides, resolved to production), ``valid_at`` (the
host list's file date) and ``source`` and ``source_name``, because the row
it sits on was read by another reader at another time.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import coverage
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_identity as _fi
from . import falcon_estate_coverage as _cov

#: The plug-in's name.
NAME = "falcon_environment"
#: The ``extra`` key it writes.
KEY = "environment"

#: Row data states that are not about a machine.
NOT_MACHINE_STATES = frozenset({"certificate", "key-material", "third-party", "email-auth",
                                "estate"})
#: Sources whose rows are about a name, not a machine.
NOT_MACHINE_SOURCES = frozenset({"ct_dns"})


def labels(index: _cov.EnvironmentIndex, assets: Iterable[CryptoAsset], valid_at: str,
           source_name: str) -> dict[str, dict]:
    """``{bom_ref: {"environment": label}}`` for every row naming a machine in ``index``."""
    out: dict[str, dict] = {}
    for asset in assets:
        if asset.source in NOT_MACHINE_SOURCES or asset.data_state in NOT_MACHINE_STATES:
            continue
        label = None
        for key in (str(asset.extra.get("aid") or "").strip(),
                    (asset.host or "").strip().casefold()):
            if key:
                label = index.by_key.get(key)
                if label is not None:
                    break
        if label is not None:
            out[asset.bom_ref()] = {KEY: label.payload(valid_at, NAME, source_name)}
    return out


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the labels to add, keyed by each row's ``bom_ref``."""
    words = _cov.environment_words(ctx.settings)
    if ctx.input is None or not words.any:
        return StepResult()
    rows, why = _fi.rows(ctx.input)
    if not rows:
        return StepResult(gaps=[coverage.gap(
            coverage.COULD_NOT_TEST,
            "no machine's environment was labelled: the host list named by "
            f"`falcon_environment`'s `input:` gave no rows ({why or 'the file holds no rows'})",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("No row carries a production or non-production label, so work cannot "
                    "be ordered live-first from the host groups."),
            nature=coverage.NO_DATA)])
    heads = _fi.headings(ctx, {"hosts": _cov.TABLES["hosts"]})["hosts"]
    index = _cov.environment_index(rows, heads, words)
    when = file_mtime_date(ctx.input) or ""
    return StepResult(annotations=labels(index, ctx.assets, when,
                                         _fi.source_name("host group", when)))


#: The declaration. It names no default input; with none given it labels nothing.
PLUGIN = Plugin(name=NAME, kind="annotation", step=step, annotation_keys=(KEY,),
                title="CrowdStrike Falcon environment, from host groups",
                gap_prefix=False)
