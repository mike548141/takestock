"""DNSSEC: is each domain signed, anchored at its parent, and validating?

For every domain the target profile names, this collector asks several
public resolvers for the zone's SOA record and reads whether they
authenticated it, then reads the DS record at the parent, the zone's own
DNSKEY records, its signature validity windows and how it proves that a name
does not exist (NSEC or NSEC3).

A resolver's "authenticated" flag is worth something only if that resolver
actually validates. So before reading any domain the collector asks each
resolver about a public zone that is deliberately signed wrongly (the
*validation control*, configured in ``data/dns-services.yaml`` or the target's
``dns:`` block): a validating resolver must answer SERVFAIL for it. Only the
resolvers that pass count as validators.

Each domain lands in one state:

* ``signed``: DS at the parent, keys in the zone, two or more validators
  authenticated it;
* ``unsigned``: no DS and no keys;
* ``island``: keys in the zone but no DS at the parent, so nobody can anchor them;
* ``bogus``: signed, and validators refuse every answer;
* ``inconclusive`` or ``unreadable``: the readings settle nothing.

Algorithm and digest strength follow the DNSSEC algorithm implementation
requirements (RFC 8624 and its successors).
"""

from __future__ import annotations

import base64
import binascii
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .. import dnsevidence, roles
from ..digresponse import RR, Response, norm, parse, query
from ..model import CryptoAsset, register_informational_prefixes
from ..util import now_date

#: A name under each domain that should not exist, asked to read its denial proof.
DENIAL_LABEL = dnsevidence.CONTROL_LABEL

SOURCE_NAME = "Public DNS, read through validating public resolvers"

# Algorithm number -> (mnemonic, what the implementation requirements say about signing with it).
ALGORITHMS: dict[int, tuple[str, str]] = {
    1: ("RSAMD5", "MUST NOT"),
    3: ("DSA", "MUST NOT"),
    5: ("RSASHA1", "NOT RECOMMENDED"),
    6: ("DSA-NSEC3-SHA1", "MUST NOT"),
    7: ("RSASHA1-NSEC3-SHA1", "NOT RECOMMENDED"),
    8: ("RSASHA256", "RECOMMENDED"),
    10: ("RSASHA512", "NOT RECOMMENDED"),
    12: ("ECC-GOST", "MUST NOT"),
    13: ("ECDSAP256SHA256", "RECOMMENDED"),
    14: ("ECDSAP384SHA384", "MAY"),
    15: ("ED25519", "RECOMMENDED"),
    16: ("ED448", "MAY"),
}

# DS digest type -> (name, requirement for use in a delegation, baseline hash token).
DS_DIGESTS: dict[int, tuple[str, str, str]] = {
    1: ("SHA-1", "MUST NOT", "sha1"),
    2: ("SHA-256", "RECOMMENDED", "sha256"),
    3: ("GOST R 34.11-94", "MUST NOT", ""),
    4: ("SHA-384", "MAY", "sha384"),
}

_ALG_HASH = {5: "sha1", 7: "sha1", 8: "sha256", 10: "sha512",
             13: "sha256", 14: "sha384"}
_RSA = {5, 7, 8, 10}
_RSA_ROWS = (1024, 2048, 3072, 4096)

# Readings that are limits of the instrument rather than findings about a zone.
register_informational_prefixes(
    "dnssec-unreadable", "dnssec-inconclusive",
    "dnssec-validation-uncorroborated", "dnssec-algorithm-unknown:",
)

#: Reads (name, record type, resolver, checking-disabled) and returns dig's text.
Reader = Callable[[str, str, str, bool], str]


def _live_reader(name: str, rtype: str, resolver: str, cd: bool) -> str:
    return query(name, rtype, resolver, dnssec=True, cd=cd)


def domains(target: dict) -> list[str]:
    """Every domain the profile names under ``discovery.domains`` or ``email_domains``."""
    disc = target.get("discovery", {}) or {}
    seen: list[str] = []
    for d in list(disc.get("domains", []) or []) + list(disc.get("email_domains", []) or []):
        n = norm(str(d))
        if n and n not in seen:
            seen.append(n)
    return seen


def rsa_modulus_bits(key_b64: str) -> int:
    """The modulus size of an RSA DNSKEY (RFC 3110 wire format); 0 when unreadable."""
    try:
        raw = base64.b64decode("".join(key_b64.split()), validate=False)
    except (binascii.Error, ValueError):
        return 0
    if len(raw) < 3:
        return 0
    exp_len, off = raw[0], 1
    if exp_len == 0:
        exp_len, off = int.from_bytes(raw[1:3], "big"), 3
    modulus = raw[off + exp_len:]
    return int.from_bytes(modulus, "big").bit_length() if modulus else 0


def rsa_token(bits: int) -> str:
    """The baseline's ``rsa_<n>`` token for a key of ``bits``, rounded down to a row."""
    fitting = [r for r in _RSA_ROWS if r <= bits]
    return f"rsa_{fitting[-1] if fitting else _RSA_ROWS[0]}"


def algorithm_tokens(algorithm: int, key_b64: str) -> tuple[list[str], list[str], int]:
    """(signature tokens, hash tokens, RSA bits) for one DNSKEY's algorithm and key."""
    hashes = [_ALG_HASH[algorithm]] if algorithm in _ALG_HASH else []
    if algorithm in _RSA:
        bits = rsa_modulus_bits(key_b64)
        return ([rsa_token(bits)] if bits else []), hashes, bits
    sig = {13: "ecdsa_p256", 14: "ecdsa_p384", 15: "ed25519", 16: "ed448"}.get(algorithm)
    return ([sig] if sig else []), hashes, 0


@dataclass
class Keys:
    """The DNSKEY records at a zone apex, each described."""

    keys: list[dict] = field(default_factory=list)

    @classmethod
    def from_response(cls, domain: str, resp: Response) -> Keys:
        out = []
        for rr in resp.records("DNSKEY"):
            if norm(rr.owner) != domain or len(rr.rdata) < 4:
                continue
            try:
                flags, alg = int(rr.rdata[0]), int(rr.rdata[2])
            except ValueError:
                continue
            key = "".join(rr.rdata[3:])
            sigs, hashes, bits = algorithm_tokens(alg, key)
            out.append({"flags": flags, "role": "KSK" if flags & 1 else "ZSK",
                        "algorithm": alg,
                        "mnemonic": ALGORITHMS.get(alg, (f"ALG{alg}", ""))[0],
                        "rsa_bits": bits, "signatures": sigs, "hashes": hashes})
        return cls(out)


def ds_records(domain: str, resp: Response) -> list[dict]:
    """The DS records the parent publishes for ``domain``."""
    out = []
    for rr in resp.records("DS"):
        if norm(rr.owner) != domain or len(rr.rdata) < 4:
            continue
        try:
            tag, alg, digest = int(rr.rdata[0]), int(rr.rdata[1]), int(rr.rdata[2])
        except ValueError:
            continue
        name, force, _ = DS_DIGESTS.get(digest, (f"digest {digest}", "", ""))
        out.append({"key_tag": tag, "algorithm": alg, "digest_type": digest,
                    "digest": name, "delegation_use": force})
    return out


def denial(domain: str, resp: Response) -> dict:
    """How the zone proves non-existence, read from a query for a name that does not exist."""
    inzone = [rr for rr in resp.authority
              if norm(rr.owner) == domain or norm(rr.owner).endswith("." + domain)]
    n3 = [rr for rr in inzone if rr.rtype.upper() == "NSEC3" and len(rr.rdata) >= 4]
    if n3:
        rd = n3[0].rdata
        try:
            flags, iterations = int(rd[1]), int(rd[2])
        except ValueError:
            return {"mechanism": "nsec3", "readable": False}
        salt = "" if rd[3] == "-" else rd[3]
        return {"mechanism": "nsec3", "readable": True, "hash_algorithm": rd[0],
                "opt_out": bool(flags & 1), "iterations": iterations, "salt": salt}
    ns = [rr for rr in inzone if rr.rtype.upper() == "NSEC"]
    if ns:
        types = {t.upper() for t in ns[0].rdata[1:]}
        # Compact denial marks a synthesised record with the NXNAME pseudo-type.
        compact = bool(types & {"NXNAME", "TYPE128"})
        return {"mechanism": "nsec-compact" if compact else "nsec", "readable": True}
    return {"mechanism": "none", "readable": True}


def _sig_time(stamp: str) -> datetime | None:
    try:
        return datetime.strptime(stamp, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def signature_windows(domain: str, *responses: Response,
                      now: datetime) -> list[dict]:
    """Each RRSIG's expiry, hours remaining, and total validity, at ``now``."""
    out = []
    for resp in responses:
        for rr in resp.records("RRSIG"):
            if norm(rr.owner) != domain or len(rr.rdata) < 7:
                continue
            exp, inc = _sig_time(rr.rdata[4]), _sig_time(rr.rdata[5])
            if not exp or not inc:
                continue
            out.append({"covers": rr.rdata[0], "algorithm": rr.rdata[1],
                        "expires": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "remaining_hours": round((exp - now).total_seconds() / 3600, 1),
                        "validity_hours": round((exp - inc).total_seconds() / 3600, 1),
                        "not_yet_valid": inc > now})
    return out


def validating_resolvers(reader: Reader, resolvers: tuple[str, ...],
                         control: str) -> dict[str, dict]:
    """Which resolvers refuse the wrongly signed ``control`` zone, i.e. validate."""
    out = {}
    for r in resolvers:
        resp = parse(reader(control, "SOA", r, False))
        out[dnsevidence.resolver_label(r)] = {"status": resp.status, "error": resp.error,
                                              "validating": resp.status == "SERVFAIL"}
    return out


def classify(has_ds: bool, has_keys: bool, ad_votes: int, servfail_votes: int,
             cd_answers: bool, any_answer: bool) -> str:
    """The domain's state from its readings; see the module docstring for the states."""
    if not any_answer:
        return "unreadable"
    if servfail_votes >= 2 and cd_answers and (has_ds or has_keys):
        return "bogus"
    if has_ds and has_keys and ad_votes >= 2:
        return "signed"
    if not has_ds and has_keys:
        return "island"
    if not has_ds and not has_keys and servfail_votes == 0:
        return "unsigned"
    return "inconclusive"


_STATE_NOTE = {
    "unsigned": "not signed: no DS record at the parent and no keys in the zone, so a "
                "resolver cannot tell a forged answer for this name from a real one",
    "island": "keys published in the zone but no DS record at the parent, so no resolver "
              "can anchor them and the signatures protect nobody",
    "bogus": "signed but failing validation: validating resolvers refuse every answer for "
             "this name",
    "inconclusive": "the readings do not agree with any single state — see extra",
    "unreadable": "no resolver answered",
}

#: The New Zealand Information Security Manual's control on DNSSEC, and its force.
NZISM_FORCE = ("NZISM v3.9 18.5.9.C.03 is a SHOULD: \"Agencies SHOULD consider the use "
               "of DNSSEC\"")


def assess(domain: str, reader: Reader, resolvers: tuple[str, ...],
           control: dict[str, dict], now: datetime, control_zone: str = "") -> CryptoAsset:
    """Read one domain through every resolver and return its DNSSEC row.

    ``control`` is :func:`validating_resolvers`'s result for ``control_zone``.
    """
    label = dnsevidence.resolver_label
    validating = [r for r in resolvers if control.get(label(r), {}).get("validating")]
    per_resolver: dict[str, dict] = {}
    for r in resolvers:
        resp = parse(reader(domain, "SOA", r, False))
        per_resolver[label(r)] = {"status": resp.status, "ad": resp.authenticated,
                                  "error": resp.error, "validating": r in validating}
    primary = next((r for r in resolvers if per_resolver[label(r)]["status"]), resolvers[0])

    soa_cd = parse(reader(domain, "SOA", primary, True))
    ds_resp = parse(reader(domain, "DS", primary, True))
    key_resp = parse(reader(domain, "DNSKEY", primary, True))
    den_resp = parse(reader(f"{DENIAL_LABEL}.{domain}", "A", primary, True))

    ds = ds_records(domain, ds_resp)
    keys = Keys.from_response(domain, key_resp).keys
    ad_votes = sum(1 for r in validating
                   if per_resolver[label(r)]["status"] == "NOERROR"
                   and per_resolver[label(r)]["ad"])
    servfail_votes = sum(1 for r in validating
                         if per_resolver[label(r)]["status"] == "SERVFAIL")
    any_answer = any(p["status"] for p in per_resolver.values()) or soa_cd.answered
    state = classify(bool(ds), bool(keys), ad_votes, servfail_votes,
                     soa_cd.status == "NOERROR", any_answer)

    flags: list[str] = []
    signatures: list[str] = []
    hashes: list[str] = []
    verdict = "unknown"
    den: dict[str, Any] = (denial(domain, den_resp) if keys
                           else {"mechanism": "none", "readable": True})
    windows = signature_windows(domain, soa_cd, key_resp, now=now) if keys else []

    if state in ("unsigned", "island", "bogus"):
        verdict = "weak"
        flags.append({"unsigned": "dnssec-unsigned",
                      "island": "dnssec-no-ds-at-parent",
                      "bogus": "dnssec-validation-fails"}[state])
    elif state == "unreadable":
        flags.append("dnssec-unreadable")
    elif state == "inconclusive":
        flags.append("dnssec-inconclusive")

    if state == "signed":
        for k in keys:
            for t in k["signatures"]:
                if t not in signatures:
                    signatures.append(t)
            for t in k["hashes"]:
                if t not in hashes:
                    hashes.append(t)
            mnemonic, force = ALGORITHMS.get(k["algorithm"], (f"ALG{k['algorithm']}", ""))
            if force == "MUST NOT":
                flags.append(f"dnssec-algorithm-must-not:{mnemonic}")
                verdict = "weak"
            elif force == "NOT RECOMMENDED":
                flags.append(f"dnssec-algorithm-not-recommended:{mnemonic}")
            elif not force:
                flags.append(f"dnssec-algorithm-unknown:{k['algorithm']}")
        digests = {d["digest_type"] for d in ds}
        if 1 in digests:
            flags.append("dnssec-ds-digest-sha1")
            # SHA-1 grades the row only when it is the sole digest a resolver can use.
            if digests <= {1}:
                hashes.append("sha1")
        if den.get("mechanism") == "nsec3" and den.get("readable"):
            # Current guidance is zero extra iterations and no salt.
            if den["iterations"] > 0:
                flags.append(f"nsec3-iterations:{den['iterations']}")
            if den["salt"]:
                flags.append("nsec3-salt")
            if den["opt_out"]:
                flags.append("nsec3-opt-out")
        if any(w["remaining_hours"] < 0 for w in windows):
            flags.append("dnssec-signature-expired")
        if any(w["not_yet_valid"] for w in windows):
            flags.append("dnssec-signature-not-yet-valid")
    if len(validating) < 2:
        flags.append("dnssec-validation-uncorroborated")

    headroom = min((w["remaining_hours"] for w in windows), default=None)
    if state == "signed":
        algs = ", ".join(sorted({k["mnemonic"] for k in keys}))
        note = (f"signed and validating ({ad_votes} of {len(validating)} validating "
                f"resolvers authenticated it); algorithm {algs}; denial "
                f"{den.get('mechanism')}; shortest signature headroom "
                f"{headroom if headroom is not None else 'unread'} hours")
    else:
        note = _STATE_NOTE[state]
    note += f". {NZISM_FORCE}"

    return CryptoAsset(
        name=f"DNSSEC {domain}", role=roles.dns_zone_signing(domain),
        data_state="in-transit", protocol="dnssec", host=domain, source="dnssec",
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(now),
        internet_facing=True,
        signatures=signatures if state == "signed" else [],
        hashes=hashes if state == "signed" else [],
        verdict=verdict, flags=sorted(set(flags)), notes=note,
        extra={
            "state": state,
            "read_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "resolvers": per_resolver,
            "validation_control": {"zone": control_zone, **control},
            "keys_read_from": label(primary),
            "ds": ds, "dnskeys": keys, "denial": den,
            "signature_windows": windows,
            "shortest_signature_headroom_hours": headroom,
            "soa_with_checking_disabled": soa_cd.status or soa_cd.error,
        })


def collect(target: dict, ref_time: datetime | None = None,
            reader: Reader | None = None,
            resolvers: tuple[str, ...] | None = None,
            control_zone: str | None = None,
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Assess every domain the profile names; returns (rows, failures)."""
    population = domains(target)
    if not population:
        return [], []
    if reader is None:
        if not shutil.which("dig"):
            return [], ["dnssec: dig is not on PATH, so no domain's signing was read"]
        reader = _live_reader
    if resolvers is None:
        resolvers = dnsevidence.resolvers(target)
    if control_zone is None:
        control_zone = str(dnsevidence.services(target).get("validation_control") or "")
    if not control_zone:
        return [], ["dnssec: no validation control zone is configured "
                    "(`validation_control` in data/dns-services.yaml or the target's "
                    "`dns:` block), so no resolver could be shown to validate and no "
                    "domain's signing was graded"]
    now = ref_time or datetime.now(UTC)
    control = validating_resolvers(reader, resolvers, control_zone)
    if not any(c["validating"] for c in control.values()):
        return [], [f"dnssec: no resolver rejected the broken control zone {control_zone}, "
                    "so no validation reading this run could be trusted"]
    assets = [assess(d, reader, resolvers, control, now, control_zone) for d in population]
    failures = []
    if all(a.extra["state"] == "unreadable" for a in assets):
        failures.append("dnssec: every domain was unreadable from every resolver")
    return assets, failures


__all__ = ["RR", "collect", "domains", "assess", "classify", "denial", "ds_records",
           "rsa_modulus_bits", "rsa_token", "algorithm_tokens", "validating_resolvers"]
