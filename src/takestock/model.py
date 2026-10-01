"""The data model: one cryptographic asset, its grading vocabulary, and CycloneDX output.

Every collector produces :class:`CryptoAsset` rows. The policy module grades
them, later stages annotate them, and :func:`to_cyclonedx` writes them out as a
CycloneDX 1.6 cryptographic bill of materials (CBOM).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


@dataclass
class CryptoAsset:
    """One observed use of cryptography (or of its absence) in the estate.

    ``data_state`` says what kind of thing the row is: ``in-transit`` for a
    listener, ``certificate``, ``email-auth``, ``at-rest``, ``discovery`` for a
    name found but not probed, and so on. ``verdict`` is the grade from the
    baseline (see :data:`VERDICT_ORDER`); ``flags`` are short machine-readable
    findings and facts. ``extra`` holds whatever a collector measured that has
    no column of its own; its values must read sensibly when printed as text.
    """

    name: str
    data_state: str
    protocol: str = ""
    role: str = ""
    host: str = ""
    ip: str = ""
    port: str = ""
    serial: str = ""
    software: str = ""
    software_binary: str = ""
    version: str = ""
    internet_facing: bool | None = None
    source: str = ""
    source_class: str = ""
    source_name: str = ""
    collected_at: str = ""
    # What to do about the asset, and on what footing (proposed by a rule,
    # or decided by a person), with the condition that ends the decision.
    disposition: str = ""
    disposition_basis: str = ""
    disposition_reason: str = ""
    disposition_until: str = ""
    disposition_review: str = ""
    effort: str = ""
    effort_group: str = ""
    pqc_deadline: str = ""
    protocol_versions: list[str] = field(default_factory=list)
    key_exchange: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    symmetric: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    verdict: str = "unknown"
    flags: list[str] = field(default_factory=list)
    evidence_depth: str = ""
    # Post-quantum readiness of key establishment and of signatures, each one
    # of PQ_VALUES. The *_basis fields say why a row has no reading (a key of
    # PQ_BASES); they are empty whenever the value is a real reading.
    pq_kex: str = ""
    pq_sig: str = ""
    pq_kex_basis: str = ""
    pq_sig_basis: str = ""
    # "<table>/<token>" for every baseline row that graded this asset. The
    # citation text itself is resolved once per report (see citations.py).
    citations: list[str] = field(default_factory=list)
    # A second reading beside ``verdict``: whether a named external standard
    # considers the asset conformant. Blank means no unmet requirement was
    # recorded, never "conformant".
    standards_verdict: str = ""
    standards_requirement: str = ""
    standards_observed: str = ""
    standards_citation: str = ""
    usage_count: int | None = None
    usage_band: str = ""
    # Declared lifecycle facts. ``support_status`` blank reads as unknown.
    migration_strategy: str = ""
    support_status: str = ""
    support_end: str = ""
    hosts_count: int | None = None
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def bom_ref(self) -> str:
        """A stable reference for this asset within a bill of materials.

        Derived from what identifies the asset (state, protocol, host, port,
        name), so the same asset gets the same reference on every run.
        """
        raw = f"{self.data_state}|{self.protocol}|{self.host}|{self.port}|{self.name}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"crypto/{self.protocol or self.data_state}/{h}"


# The four graded verdicts, weakest first, plus two that are not grades:
#   unknown  cryptography is present but nothing observed could be graded;
#            an ``ungraded:<table>:<token>`` flag names what was missing.
#   n/a      the row carries no cryptographic primitive by nature (a
#            discovered name, a mail policy record). It is never a gap.
GRADED_VERDICTS = ("weak", "acceptable", "strong", "pqc")
NA_VERDICT = "n/a"
VERDICT_ORDER = {"weak": 0, "acceptable": 1, "strong": 2, "pqc": 3, "unknown": 4, NA_VERDICT: 5}

# Post-quantum readiness. The first three values are readings and may sit in
# a readiness figure; the last two are not readings and must stay out of one.
PQ_READINGS = ("ready", "hybrid", "classical")
PQ_NON_READINGS = ("gap", NA_VERDICT)
PQ_VALUES = PQ_READINGS + PQ_NON_READINGS

#: Plain-language meaning of each readiness value, for reports.
PQ_MEANING = {
    # "ready" includes a combined construction such as X25519MLKEM768, which
    # the baseline grades as post-quantum. "hybrid" means the row offers both
    # kinds, so the other end chooses which is used.
    "ready": "Every option seen for this job is quantum-resistant, including a "
             "combined construction such as X25519MLKEM768, which the baseline "
             "grades as quantum-resistant. Nothing here needs replacing for "
             "post-quantum reasons.",
    "hybrid": "This row offers both a quantum-resistant option and a "
              "classical-only one for this job, so which is used is the "
              "other end's choice. The migration has started here and has "
              "not finished.",
    "classical": "Only classical primitives do this job here, so it is work "
                 "still to do in the post-quantum migration.",
    "gap": "This job could not be read on this row, so it sits outside the "
           "readiness figure rather than passing or failing it. The basis "
           "beside it says why, and each reason closes by a different action.",
    NA_VERDICT: "There is no such job on this row to read, so it is correctly "
                "outside the readiness figure.",
}

#: Why a row has no readiness reading. Three pair with ``n/a`` and never
#: close; three pair with ``gap`` and each closes by a different action.
PQ_BASES = {
    "no-cryptography": "This row carries no cryptography by nature: a policy "
                       "record, a discovered name, a supplier, or a statement "
                       "about coverage.",
    "cleartext-service": "This service carries traffic in the clear, so there "
                         "is no cryptography here to migrate. That is a "
                         "finding in its own right and is reported as one; "
                         "it is not a post-quantum question.",
    "no-key-establishment": "This is a signed object rather than a "
                            "conversation: a certificate, a mail-signing "
                            "record or a signed DNS zone. It establishes no keys, so it has no key "
                            "establishment to migrate.",
    "not-probed": "This service can carry encryption and nothing has read "
                  "what it negotiates. Pointing a capability scanner at it "
                  "would close this.",
    "not-observed": "Nothing gathered names a primitive for this job on "
                    "this row.",
    # Deliberately does not say the job is absent: an unread class is unknown.
    "not-yet-read": "This class of asset is outside what the readiness axis "
                    "reads today. Whether this job is done here, and by what, "
                    "has not been read.",
}
PQ_GAP_BASES = ("not-probed", "not-observed", "not-yet-read")
PQ_NA_BASES = ("no-cryptography", "cleartext-service", "no-key-establishment")

# Certificate expiry thresholds, in days.
#   EXPIRY_SOON_DAYS       the warning window for a long-lived certificate.
#   RENEWAL_OVERDUE_DAYS   a short-lived certificate this close to expiry means
#                          its renewal automation has probably failed (an ACME
#                          client normally renews well before this point).
#   SHORT_LIVED_CERT_DAYS  below this lifetime a certificate is treated as
#                          automatically renewed (90-day ACME certificates).
EXPIRY_SOON_DAYS = 30
RENEWAL_OVERDUE_DAYS = 10
SHORT_LIVED_CERT_DAYS = 180


def expiry_soon_threshold(lifetime_days: int | None) -> int:
    """Days remaining at which a certificate earns ``expiry-soon``.

    One sixth of the certificate's own lifetime, capped at
    :data:`EXPIRY_SOON_DAYS`. A 90-day certificate is warned at 15 days, so
    one renewing on a normal ACME schedule never trips it; a certificate with
    an unknown lifetime gets the full 30 days. The ratio is a chosen value,
    not one taken from a standard.
    """
    if not lifetime_days or lifetime_days <= 0:
        return EXPIRY_SOON_DAYS
    return min(EXPIRY_SOON_DAYS, lifetime_days // 6)


def cert_expiry_flag(remaining_days: int, lifetime_days: int | None = None) -> str | None:
    """The single expiry flag a certificate earns, or None.

    One of ``expired``, ``renewal-overdue`` (a short-lived certificate whose
    renewal should already have happened) or ``expiry-soon``. They are
    mutually exclusive: the most specific one wins.
    """
    if remaining_days < 0:
        return "expired"
    if (lifetime_days and 0 < lifetime_days < SHORT_LIVED_CERT_DAYS
            and remaining_days < RENEWAL_OVERDUE_DAYS):
        return "renewal-overdue"
    if remaining_days <= expiry_soon_threshold(lifetime_days):
        return "expiry-soon"
    return None


# Flags that state a FACT about an asset, or a limit on what was measured,
# rather than an adverse judgement of it. Comparing two runs, one of these
# appearing is not a regression. The built-in entries are the ones the
# grading modules emit; a collector registers its own with
# register_informational_prefixes() when it is imported. Entries ending in ":"
# are prefixes.
INFORMATIONAL_FLAG_PREFIXES: tuple[str, ...] = (
    "ungraded:",                  # policy: a token the baseline has no row for
    "not-measured:",              # policy: an attribute the evidence did not carry
    "quantum-symmetric-margin:",  # policy: symmetric strength, a reading only
    "unverified-encryption:",     # plaintext: a listener that may or may not use TLS
    "cleartext-exposure:",        # plaintext: classifies a plaintext: finding
    "no-encrypted-alternative:",  # plaintext: classifies a plaintext: finding
)

_registered_prefixes: list[str] = []


def register_informational_prefixes(*prefixes: str) -> None:
    """Declare further flags (or flag prefixes) as informational.

    Called by a collector for the facts and measurement limits it records, so
    that their first appearance is never read as the estate getting worse.
    Registering the same prefix twice has no further effect.
    """
    for p in prefixes:
        if not p:
            raise ValueError("an empty prefix would mark every flag informational")
        if p not in INFORMATIONAL_FLAG_PREFIXES and p not in _registered_prefixes:
            _registered_prefixes.append(p)


def informational_prefixes() -> tuple[str, ...]:
    """Every informational prefix in effect: the built-in ones, then registered ones."""
    return INFORMATIONAL_FLAG_PREFIXES + tuple(_registered_prefixes)


def is_informational_flag(flag: str) -> bool:
    """True when ``flag`` records a fact or a measurement limit, not a finding."""
    return flag.startswith(informational_prefixes())


def worst(verdicts: list[str]) -> str:
    """The weakest graded verdict in ``verdicts``; ``unknown`` if none is graded.

    ``unknown`` and ``n/a`` never pull the result down: a row is as weak as
    the weakest thing that could actually be graded.
    """
    known = [v for v in verdicts if v in GRADED_VERDICTS]
    if not known:
        return "unknown"
    return min(known, key=lambda v: VERDICT_ORDER[v])


def ungraded_tokens(flags: list[str]) -> list[tuple[str, str]]:
    """The (table, token) pairs named by ``ungraded:<table>:<token>`` flags."""
    out = []
    for f in flags:
        if f.startswith("ungraded:"):
            _, table, token = f.split(":", 2)
            out.append((table, token))
    return out


#: Namespace for takestock's own CycloneDX component properties.
PROPERTY_NAMESPACE = "takestock"

# Protocols CycloneDX can describe as a protocol asset; anything else is
# written as related cryptographic material.
_CYCLONEDX_PROTOCOLS = ("tls", "ssh", "ike", "ipsec")


def to_cyclonedx(assets: list[CryptoAsset], meta: dict) -> dict:
    """Render ``assets`` as a CycloneDX 1.6 bill of materials (a plain dict).

    Each asset becomes a ``cryptographic-asset`` component. takestock's own
    readings travel as ``takestock:<field>`` properties; empty values are left
    out. ``meta`` is written as the BOM's ``metadata`` block unchanged.
    """
    components = []
    for a in assets:
        props = [{"name": f"{PROPERTY_NAMESPACE}:{k}", "value": str(v)} for k, v in {
            "verdict": a.verdict,
            "flags": ",".join(a.flags),
            "standards_verdict": a.standards_verdict,
            "standards_requirement": a.standards_requirement,
            "standards_observed": a.standards_observed,
            "standards_citation": a.standards_citation,
            "data_state": a.data_state,
            "role": a.role,
            "software": a.software,
            "version": a.version,
            "usage_count": a.usage_count if a.usage_count is not None else "",
            "usage_band": a.usage_band,
            "migration_strategy": a.migration_strategy,
            "support_status": a.support_status,
            "support_end": a.support_end,
            "hosts_count": a.hosts_count if a.hosts_count is not None else "",
            "internet_facing": a.internet_facing if a.internet_facing is not None else "",
            "source": a.source,
            "source_class": a.source_class,
            "source_name": a.source_name,
            "collected_at": a.collected_at,
            "disposition": a.disposition,
            "disposition_basis": a.disposition_basis,
            "disposition_reason": a.disposition_reason,
            "disposition_until": a.disposition_until,
            "disposition_review": a.disposition_review,
            "effort": a.effort,
            "pqc_deadline": a.pqc_deadline,
        }.items() if v not in ("", None)]

        comp: dict = {
            "type": "cryptographic-asset",
            "name": a.name,
            "bom-ref": a.bom_ref(),
            "properties": props,
        }
        cp: dict = {"assetType": "protocol"}
        if a.protocol in _CYCLONEDX_PROTOCOLS:
            suites = [{"name": s} for s in a.symmetric] or None
            cp["protocolProperties"] = {
                "type": "ike" if a.protocol == "ike" else a.protocol,
                "version": (a.protocol_versions or [""])[0],
                **({"cipherSuites": suites} if suites else {}),
            }
        else:
            cp["assetType"] = "related-crypto-material"
            cp["relatedCryptoMaterialProperties"] = {"type": "key"}
        comp["cryptoProperties"] = cp
        if a.host:
            comp["evidence"] = {"occurrences": [{"location": f"{a.host}:{a.port}".rstrip(":")}]}
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": meta,
        "components": components,
    }


def dump_assets(assets: list[CryptoAsset]) -> list[dict]:
    """Assets as plain dicts, for JSON."""
    return [asdict(a) for a in assets]


def load_assets(rows: list[dict]) -> list[CryptoAsset]:
    """Rebuild assets from :func:`dump_assets` output."""
    return [CryptoAsset(**r) for r in rows]


def write_json(obj, path) -> None:
    """Write ``obj`` as indented JSON; dates and other objects become strings."""
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
