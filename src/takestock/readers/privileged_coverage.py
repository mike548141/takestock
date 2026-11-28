"""Privileged access over the declared suppliers: one bounded gap per supplier.

A ``coverage-check`` plug-in (``docs/PLUGINS.md``): it reads the rows the
observation has already produced and returns coverage gaps only. It writes no
rows, so no count, verdict or denominator elsewhere moves, and a gap can never
block a render.

**The question.** Who can act with privilege inside a hosted service, how that
privilege is granted and removed, and what happens to it when the relationship
ends. No instrument that probes a listener can answer that for a hosted
tenancy, because the tenancy exposes none to point one at. So the gap is not
"a probe failed": no source in the run can answer the question for that
supplier, and more scanning will not change it.

**What it will not say.** That privileged access, as a whole area, is
unmeasured. That sentence describes work not yet done, not a bounded unknown,
and :func:`takestock.coverage.gap` refuses to build it. This check finds a
*population* instead: the profile's declared list of suppliers is finite, so
the report can say "no answer for ``n`` of ``N``" and name each. With no list
declared there is no population, and the check says nothing about suppliers.

**The three questions** (:data:`QUESTIONS`) are the same for every supplier,
because they are what decide whether a supplier's privilege is governed at
all, and a per-supplier list would be a judgement about each supplier that
nothing here supports. Where the declaration already says what the supplier
is used for, the gap says so first, so a reader can tell "we hold a coarse
record" from "we have never heard of them".

**Which suppliers.** The profile's ``third_party:`` list: each entry a mapping
with a ``name`` and optionally ``role``, ``uses`` and ``domains``. An entry
with no name is skipped.

**When a supplier has an answer.** Any row in the privileged lens (below)
whose ``host`` is one of the supplier's declared domains, or a name under one,
counts as an answer. This is deliberately generous: a gap for a supplier we
hold partial evidence about would overstate what is missing, which fails in
the flattering direction and is the same defect as understating it.

**The privileged lens** is a row whose data state is ``identity``, whose
``source`` is one of the identity readers (:data:`PRIVILEGED_SOURCES`), or
that carries a flag naming a privilege or credential property
(:data:`PRIVILEGED_FLAG_PREFIXES`). Prefixes, because those flags carry counts
(``privileged-accounts:12``). ``settings: privileged_sources:`` adds instruments
(the ``source`` their rows carry) for a reader takestock does not ship.

**Parties the register names that no declaration knows.** One further gap, over
the information-sharing register that ``flows`` reads (the path its channel
map declares, ``docs/COLLECTORS.md``). A party the register names that appears
in no declaration the profile holds has never been asked who inside it can
act, or how that access is granted. It is one gap, not one per party: the
register's party column can mix organisations with categories of people, and
a gap each would assert that every value names a system whose privileged
access can be characterised, which the data does not support. The count is
exact and the first names are given (:data:`NAME_LIMIT`). With no register, or
one that cannot be read, this check is silent: ``flows`` already says so.

A party counts as declared when any word of more than three characters in its
name appears in the name or domains of a ``third_party:`` entry, or in the
name of an entry of the lists ``settings: declared_lists:`` names (default
``asset_classes`` and ``infrastructure``). Generous for the same reason as
above, and words of three characters or fewer are dropped because they match
by accident.

The gap tokens (:data:`TOKEN_PREFIX`) are this check's own, distinct from every
other coverage check's, so a count of one family's gaps never includes
another's.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from .. import config, coverage, flows
from ..model import CryptoAsset
from ..plugin_kinds import COVERAGE_CHECK
from ..plugins import Context, Plugin, StepResult

#: The plug-in's name.
NAME = "privileged_coverage"
#: Starts every gap this check raises.
TOKEN_PREFIX = "Privileged access coverage"
SUPPLIER_TOKEN = f"{TOKEN_PREFIX} — supplier:"
UNDECLARED_TOKEN = f"{TOKEN_PREFIX} — parties in the information-sharing register:"
PROFILE_TOKEN = f"{TOKEN_PREFIX} — profile:"

#: ``settings:`` key adding instruments to :data:`PRIVILEGED_SOURCES`.
SOURCES_SETTING = "privileged_sources"
#: ``settings:`` key naming the profile lists whose entries' names count as declared.
DECLARED_SETTING = "declared_lists"
#: The profile lists read for declared names unless ``settings:`` names others.
DECLARED_LISTS = ("asset_classes", "infrastructure")

#: Data states that describe who holds access rather than a channel.
PRIVILEGED_STATES = frozenset({"identity"})
#: Readers whose whole subject is a principal and its credential.
PRIVILEGED_SOURCES = frozenset({"falcon_accounts", "falcon_logins", "falcon_logon_events",
                                "entra_app_credentials"})
#: Flag prefixes that name a privilege or credential property.
PRIVILEGED_FLAG_PREFIXES = ("privileged-", "privilege-", "admin-", "credential-",
                            "shared-credential")

#: Register party values that name no organisation, compared after casefolding
#: and stripping surrounding punctuation.
NOT_A_PARTY = frozenset({"", "unspecified", "n/a", "na", "none", "tbc", "-"})

#: How many undeclared parties the gap names before it stops listing. The count
#: is always exact; the naming is capped so one gap does not become a register.
NAME_LIMIT = 12

#: What each supplier gap asks. Fixed, and stated once (see the module docstring).
QUESTIONS = (
    "who administers the tenancy",
    "how privileged access to it is granted and removed",
    "what happens to that access when the relationship ends",
)

_WORDS = re.compile(r"[^A-Za-z0-9]+")


def in_privileged_lens(asset: CryptoAsset, sources: frozenset[str] = PRIVILEGED_SOURCES) -> bool:
    """True where the row speaks to who holds privilege or how a credential behaves."""
    return (asset.data_state in PRIVILEGED_STATES
            or asset.source in sources
            or any(f.startswith(p) for f in (asset.flags or [])
                   for p in PRIVILEGED_FLAG_PREFIXES))


def _suppliers(target: Mapping) -> list[Mapping]:
    return [s for s in (target.get("third_party") or [])
            if isinstance(s, Mapping) and str(s.get("name") or "").strip()]


def _answered(suppliers: Sequence[Mapping], assets: Sequence[CryptoAsset],
              sources: frozenset[str]) -> set[str]:
    """Names of suppliers a privileged-lens row's host sits under."""
    hosts = {(a.host or "").strip().casefold()
             for a in assets if (a.host or "").strip() and in_privileged_lens(a, sources)}
    if not hosts:
        return set()
    answered: set[str] = set()
    for supplier in suppliers:
        for domain in supplier.get("domains") or []:
            d = str(domain).strip().casefold()
            if d and any(h == d or h.endswith("." + d) for h in hosts):
                answered.add(str(supplier.get("name")).strip())
                break
    return answered


def _supplier_gap(supplier: Mapping, unanswered: int, total: int):
    """One declared supplier whose privileged-access arrangements are unstated.

    Bounded three ways, which is what makes it a gap and not an area: the
    supplier is named, the population is exact (``n of N`` declared suppliers),
    and the missing attributes are listed.
    """
    name = str(supplier.get("name")).strip()
    role = str(supplier.get("role") or "").strip()
    uses = [str(u).strip() for u in (supplier.get("uses") or []) if str(u).strip()]
    # What is held, said first: a gap of nature `low-fidelity` has to show the
    # coarse record it is measured against.
    held = f"declared in the third-party register as `{name}`"
    if role:
        held += f", role `{role}`"
    if uses:
        held += f", used for {'; '.join(uses[:3])}"
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"{SUPPLIER_TOKEN} `{name}` — {held}. What this observation cannot say "
        f"is {', '.join(QUESTIONS[:-1])}, and {QUESTIONS[-1]}. No instrument in "
        f"this run can answer any of the three: each measures a listener, and a "
        f"hosted tenancy has none to point one at, so no further scanning closes "
        f"this. One of {unanswered:,} declared supplier(s) out of {total:,} in "
        f"the same position.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact="The organisation depends on this supplier and cannot say who can act with "
               "privilege inside it, how that privilege is granted, or whether it is "
               "removed when someone leaves. Any statement in this report about privileged "
               "access being governed describes the systems the organisation runs itself "
               "and not this one, which for a service holding real data is the difference "
               "between a controlled and an uncontrolled account.",
        harvest="An administrator list and a joiner, mover and leaver statement for this "
                "tenancy, from whoever owns the relationship: a question for a person, not "
                "an export to chase. Folded in on arrival; nothing waits for it.",
        # The declaration names the supplier and what it is used for and says
        # nothing about who administers it: a record that exists and is too
        # coarse to settle the question, the `low-fidelity` case, not `no-data`.
        nature=coverage.LOW_FIDELITY)


def _register_parties(target: Mapping) -> list[str]:
    """Outside organisations the information-sharing register names, deduplicated, in reading order.

    Read straight from the register rather than from ``flows``' join, because
    the question does not need the join: a party is named or it is not,
    whether or not any channel could be measured. The register is found where
    the channel map declares it, as ``flows`` finds it.
    """
    declared = flows.register_path_for_target(target)
    rows, _reason = flows.read_register(config.inbox_path(declared))
    seen: dict[str, str] = {}
    for row in rows:
        name = (row.party or "").strip()
        key = name.strip("()[] ").casefold()
        if key in NOT_A_PARTY or key in seen:
            continue
        seen[key] = name
    return list(seen.values())


def _words(text: str) -> list[str]:
    return [w for w in _WORDS.split(text.casefold()) if len(w) > 3]


def _declared_words(suppliers: Sequence[Mapping], target: Mapping,
                    lists: Sequence[str]) -> set[str]:
    """Words, long enough to identify an organisation, from every declaration the profile holds."""
    sources = [str(s.get("name") or "") for s in suppliers]
    sources += [str(d) for s in suppliers for d in (s.get("domains") or [])]
    for key in lists:
        sources += [str(e.get("name") or "") for e in (target.get(key) or [])
                    if isinstance(e, Mapping)]
    return {w for text in sources for w in _words(text)}


def _undeclared_party_gaps(target: Mapping, suppliers: Sequence[Mapping],
                           lists: Sequence[str]) -> list:
    parties = _register_parties(target)
    if not parties:
        return []
    known = _declared_words(suppliers, target, lists)
    undeclared = [p for p in parties if not any(w in known for w in _words(p))]
    if not undeclared:
        return []
    named = ", ".join(f"`{p}`" for p in undeclared[:NAME_LIMIT])
    more = (f" and {len(undeclared) - NAME_LIMIT:,} more"
            if len(undeclared) > NAME_LIMIT else "")
    return [coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{UNDECLARED_TOKEN} {len(undeclared):,} of the {len(parties):,} outside parties "
        f"the information-sharing register names appear in no declaration the profile "
        f"holds, neither the third-party register nor any declared list of "
        f"infrastructure or asset classes: {named}{more}. For each, nobody has asked who "
        f"inside it can act, how that access is granted, or how it is removed. A party in "
        f"the register is one the organisation already shares information with, so this "
        f"is a shortfall in what has been asked, not in what exists.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact="The register names more outside parties than the supplier list this report "
               "was built from. Any statement here about third-party access covers the "
               "smaller list, so the number of relationships whose access nobody governs is "
               "larger than this report shows, and the difference is measured, not "
               "estimated.",
        harvest="Reconcile the register's party column against the supplier declaration, "
                "and add the organisations that belong there. A review to run, not an "
                "export to chase; folded in on the next run.",
        nature=coverage.NO_DATA)]


def _text_list(value: object) -> list[str] | None:
    """``value`` as a list of non-blank texts, or None when it is not a list."""
    if not isinstance(value, (list, tuple)):
        return None
    return [str(v).strip() for v in value if str(v).strip()]


def collect(target: Mapping, assets: Sequence[CryptoAsset], *,
            extra_sources: Sequence[str] = (),
            declared_lists: Sequence[str] = DECLARED_LISTS) -> list:
    """The privileged-access gaps over ``target``'s declarations and ``assets``.

    ``assets`` is every row the run produced so far, so this can only run late.
    Returns gaps only: nothing here can move a count.
    """
    sources = PRIVILEGED_SOURCES | frozenset(extra_sources)
    suppliers = _suppliers(target)
    gaps: list = []
    if suppliers:
        answered = _answered(suppliers, assets, sources)
        unanswered = [s for s in suppliers if str(s.get("name")).strip() not in answered]
        gaps += [_supplier_gap(s, len(unanswered), len(suppliers)) for s in unanswered]
    # With no declared register there is no bounded population, and a gap without
    # one would be the area-shaped sentence the validity test refuses.
    return gaps + _undeclared_party_gaps(target, suppliers, declared_lists)


def step(ctx: Context) -> StepResult:
    gaps: list = []
    extra = _text_list(ctx.settings.get(SOURCES_SETTING))
    lists = _text_list(ctx.settings.get(DECLARED_SETTING))
    for key, value in ((SOURCES_SETTING, extra), (DECLARED_SETTING, lists)):
        if key in ctx.settings and value is None:
            gaps.append(coverage.gap(
                coverage.COULD_NOT_TEST,
                f"{PROFILE_TOKEN} `settings: {key}:` for `{NAME}` is not a list, so it was "
                "ignored and the built-in default was used",
                impact_kind=coverage.NARROWS_CONFIDENCE,
                impact="A supplier whose privileged-access evidence comes from an instrument "
                       "the setting was meant to name may read as unanswered.",
                harvest="Correct the setting in the target profile.",
                nature=coverage.NO_DATA))
    found = collect(ctx.target, list(ctx.assets), extra_sources=extra or (),
                    declared_lists=lists if lists is not None else DECLARED_LISTS)
    return StepResult(gaps=gaps + found)


#: The declaration. Late by kind: it reads the rows the other steps wrote.
PLUGIN = Plugin(name=NAME, kind=COVERAGE_CHECK, step=step, gap_prefix=False,
                title="privileged access over the declared suppliers")
