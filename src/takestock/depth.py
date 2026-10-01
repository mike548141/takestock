"""Evidence depth: how far the evidence about an asset's protection goes.

A verdict says how good an asset's protection is; the depth says what that
verdict rests on. Each row sits on one rung of a five-rung ladder, from
"it is known to exist" to "how its key is managed is known", or outside the
ladder when it carries no cryptography to grade:

====================  ====================================================
``exists``            nothing about its protection has been measured
``posture``           whether it is protected is known, not by what
``strength``          the cryptography itself is recorded
``key``               a specific key's own properties are recorded
``key-management``    how the key is held, rotated or revoked is recorded
``n/a``               the row has no cryptography to grade
====================  ====================================================

A row reaches a rung by carrying something specific: a flag, a field or an
``extra`` key. The built-in lists below hold what takestock's own modules
emit; a collector adds its own with :func:`register_flags` when imported.
A flag that records an unanswered question (``ungraded:`` and any registered
with ``rung="unanswered"``) never lifts a row, because a recorded absence is
not evidence reached.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .model import NA_VERDICT, CryptoAsset

NOT_APPLICABLE = NA_VERDICT
EXISTS = "exists"
POSTURE = "posture"
STRENGTH = "strength"
KEY = "key"
KEY_MANAGEMENT = "key-management"

#: Rungs from deepest to shallowest: the order :func:`classify` tests them in.
LADDER: tuple[str, ...] = (KEY_MANAGEMENT, KEY, STRENGTH, POSTURE, EXISTS)

#: Rungs from shallowest to deepest, then the value outside the ladder.
ORDER: tuple[str, ...] = (EXISTS, POSTURE, STRENGTH, KEY, KEY_MANAGEMENT, NOT_APPLICABLE)

RUNG = {EXISTS: 1, POSTURE: 2, STRENGTH: 3, KEY: 4, KEY_MANAGEMENT: 5}

LABEL = {
    EXISTS: "Exists",
    POSTURE: "Protected or not",
    STRENGTH: "Strength recorded",
    KEY: "Key recorded",
    KEY_MANAGEMENT: "Key management recorded",
    NOT_APPLICABLE: "No cryptography to grade",
}

MEANS = {
    EXISTS: "The item is known to be here. Nothing about how it is protected has "
            "been measured.",
    POSTURE: "Whether it is protected (encrypted, upgradeable in band, or in the "
             "clear) is known, from the protocol its port carries or from a "
             "configuration record. The cryptography itself is not recorded.",
    STRENGTH: "The cryptography is recorded: a protocol version, a key exchange, "
              "a cipher suite, a hash or a signature algorithm.",
    KEY: "A specific key's own properties are recorded: its algorithm, size, "
         "validity window, or that it is shared.",
    KEY_MANAGEMENT: "How the key is held, rotated or revoked is recorded. This is "
                    "the rung an assurance question usually asks about.",
    NOT_APPLICABLE: "The row carries no cryptography to grade: a census, a scope "
                    "statement, a count or a name.",
}

# What lifts a row to each rung. A name ending in ":" is a prefix, and only
# matches a flag that carries something after it.
_BUILTIN: dict[str, tuple[str, ...]] = {
    # A certificate whose short-lived renewal has visibly failed, and a CAA
    # record that locks issuance to named authorities: both are facts about
    # how the key's lifecycle is controlled.
    KEY_MANAGEMENT: ("renewal-overdue", "issuance-locked"),
    KEY: ("weak-key-1024",),
    # A port whose protocol is known to run in the clear, or may or may not.
    POSTURE: ("plaintext:", "unverified-encryption:"),
    "unanswered": ("ungraded:",),
}

#: Flags that grade a row on its port's convention rather than on anything
#: read off the row itself.
CONVENTION_PREFIXES: tuple[str, ...] = ("plaintext:", "unverified-encryption:")

#: ``extra`` keys whose presence records a specific key's properties.
KEY_EXTRA_KEYS: tuple[str, ...] = (
    "pubkey", "pubkey_sha256", "key_bits", "key_algorithm",
    "not_after", "cert_not_after", "valid_to",
)

#: Asset fields whose content records the cryptography itself.
STRENGTH_FIELDS: tuple[str, ...] = (
    "protocol_versions", "key_exchange", "symmetric", "hashes", "signatures",
)

GRADED_VERDICTS: frozenset[str] = frozenset({"weak", "acceptable", "strong", "pqc"})

_RUNG_NAMES = (KEY_MANAGEMENT, KEY, POSTURE, "unanswered")
_registered: dict[str, list[str]] = {name: [] for name in _RUNG_NAMES}
_convention: list[str] = []


def register_flags(rung: str, *flags: str, convention: bool = False) -> None:
    """Declare that ``flags`` lift a row to ``rung``.

    ``rung`` is ``key-management``, ``key``, ``posture``, or ``unanswered``
    for a flag that records a question the evidence could not answer.
    ``convention=True`` marks posture flags that grade on the port's
    protocol alone. Called by a collector for the flags it emits;
    registering a flag twice has no further effect.
    """
    if rung not in _registered:
        raise ValueError(f"unknown rung {rung!r}: expected one of {list(_RUNG_NAMES)}")
    for f in flags:
        if not f or f == ":":
            raise ValueError("an empty flag would match every row")
        if f not in _registered[rung] and f not in _BUILTIN.get(rung, ()):
            _registered[rung].append(f)
        if convention and f not in _convention and f not in CONVENTION_PREFIXES:
            _convention.append(f)


def flags_for(rung: str) -> tuple[str, ...]:
    """Every flag in effect for ``rung``: the built-in ones, then registered ones."""
    return _BUILTIN.get(rung, ()) + tuple(_registered.get(rung, ()))


def _hits(flag: str, names: Sequence[str]) -> bool:
    for n in names:
        if n.endswith(":"):
            if flag.startswith(n) and len(flag) > len(n):
                return True
        elif flag == n:
            return True
    return False


def _reaches(flags: Iterable[str], rung: str) -> bool:
    unanswered = flags_for("unanswered")
    names = flags_for(rung)
    return any(_hits(f, names) for f in flags if not _hits(f, unanswered))


def _get(asset: CryptoAsset | Mapping[str, Any], name: str) -> Any:
    if isinstance(asset, Mapping):
        return asset.get(name)
    return getattr(asset, name, None)


def classify(asset: CryptoAsset | Mapping[str, Any]) -> str:
    """The deepest rung ``asset`` reaches, or ``n/a``.

    Accepts an asset object or one row of ``assets.json``, and gives the
    same answer for both.
    """
    flags = list(_get(asset, "flags") or ())
    extra = _get(asset, "extra") or {}
    verdict = _get(asset, "verdict") or ""

    if _reaches(flags, KEY_MANAGEMENT):
        return KEY_MANAGEMENT
    if _reaches(flags, KEY) or any(str(extra.get(k, "")).strip() for k in KEY_EXTRA_KEYS):
        return KEY
    if any(_get(asset, f) for f in STRENGTH_FIELDS):
        return STRENGTH
    if verdict in GRADED_VERDICTS or _reaches(flags, POSTURE):
        return POSTURE
    if verdict == NOT_APPLICABLE:
        return NOT_APPLICABLE
    return EXISTS


def by_convention(asset: CryptoAsset | Mapping[str, Any]) -> bool:
    """True when the row's posture comes from its port's protocol alone."""
    names = CONVENTION_PREFIXES + tuple(_convention)
    return any(_hits(f, names) for f in (_get(asset, "flags") or ()))


def stamp(assets: list[CryptoAsset]) -> list[CryptoAsset]:
    """Set ``evidence_depth`` on every asset, and return the list."""
    for a in assets:
        a.evidence_depth = classify(a)
    return assets


def summarise(assets: Sequence[CryptoAsset]) -> dict:
    """Counts per rung, the shares of the gradable population, and two sentences.

    The population excludes ``n/a`` rows. A row never stamped is classified
    here, so an older observation summarises the same way.
    """
    counts = {k: 0 for k in ORDER}
    convention = 0
    for a in assets:
        rung = a.evidence_depth or classify(a)
        counts[rung] = counts.get(rung, 0) + 1
        if rung == POSTURE and by_convention(a):
            convention += 1

    total = len(assets)
    population = total - counts[NOT_APPLICABLE]
    recorded = counts[STRENGTH] + counts[KEY] + counts[KEY_MANAGEMENT]

    def share(n: int) -> float | None:
        return (n / population) if population else None

    rows = [{"depth": k, "rung": RUNG.get(k), "label": LABEL[k], "means": MEANS[k],
             "count": counts[k], "share": share(counts[k]) if k != NOT_APPLICABLE else None}
            for k in ORDER if counts[k]]

    return {
        "total": total,
        "population": population,
        "not_applicable": counts[NOT_APPLICABLE],
        "by_depth": counts,
        "rows": rows,
        "recorded_cryptography": recorded,
        "recorded_share": share(recorded),
        "posture_only": counts[POSTURE],
        "posture_by_convention": convention,
        "posture_by_record": counts[POSTURE] - convention,
        "unmeasured": counts[EXISTS],
        "key_management": counts[KEY_MANAGEMENT],
        "sentence": sentence(population, recorded, convention,
                             counts[POSTURE] - convention, counts[EXISTS]),
        "assurance_sentence": assurance_sentence(counts[KEY_MANAGEMENT], population),
    }


def _pct(n: int, of: int) -> str:
    return f"{round(100 * n / of)}%" if of else ""


def sentence(population: int, recorded: int, convention: int,
             record: int, unmeasured: int) -> str:
    """One sentence splitting the gradable population by what its grade rests on."""
    if not population:
        return ""
    return (
        f"Of the {population:,} items whose protection can be graded, {recorded:,} "
        f"({_pct(recorded, population)}) are graded on recorded cryptography: a "
        f"protocol version, cipher suite, key exchange or key. {convention:,} are "
        f"graded only on the protocol their port carries; {record:,} on a record "
        f"that says whether the item is protected without naming what protects it; "
        f"and {unmeasured:,} carry nothing about their protection either way."
    )


def assurance_sentence(key_management: int, population: int) -> str:
    """One sentence on how many items record how their key is managed."""
    if not population:
        return ""
    if not key_management:
        return ("No item records how its key is held, rotated or revoked, which is "
                "the rung an assurance question usually asks about.")
    return (f"{key_management:,} of {population:,} items record how a key is held, "
            f"rotated or revoked; for the other {population - key_management:,} the "
            f"evidence stops short of that.")
