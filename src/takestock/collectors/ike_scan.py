"""IKE (IPsec key exchange) proposals accepted by the remote-access gateways.

For each gateway in ``scan_targets.vpn_gateways`` this collector uses
``ike-scan`` to find, with a bounded number of probes:

1. **the preferred transform.** It offers a menu of IKEv1 Main Mode
   transforms, weakest first and then strongest first, for each
   authentication method in turn (RFC 2409 pre-shared key and RSA
   signatures, then the XAUTH and hybrid methods remote-access gateways
   commonly require). If both orders get the same answer the gateway
   enforces its own preference; if the answer follows the order offered, the
   initiator chooses, and a client that offers a weak transform first gets
   it.
2. **the floor and ceiling on each axis.** Holding the preferred transform
   fixed, it varies the encryption algorithm, the hash and the
   Diffie-Hellman group one at a time and records which values the gateway
   accepts. The weakest accepted value below the preferred one on any axis
   is a *downgrade surface*: an attacker in the path can force it.
3. **an IKEv2 answer.** One IKEv2 ``IKE_SA_INIT`` with ike-scan's default
   offer, recording whether the gateway speaks IKEv2 and what it chose.

Every accepted value is graded through the baseline's ``ike_encryption``,
``ike_dh`` (by group number, RFC 8247 for IKEv2 and the IANA IKE registry
for IKEv1) and ``ike_prf`` tables.

A sweep that ran out of budget, hit an error, or got silence where the
gateway otherwise answers refusals is reported as a failure, because its
minimum and maximum are then over what was asked, not over what the gateway
accepts. ``ike-scan`` is optional: without it every gateway gets an
``unknown`` row and :func:`coverage_gaps` names them.

Budget and pacing come from ``TAKESTOCK_IKE_MAX_PROBES``,
``TAKESTOCK_IKE_PROBE_DELAY`` (seconds), ``TAKESTOCK_IKE_RETRY`` and
``TAKESTOCK_IKE_TIMEOUT_MS``; the executable from ``TAKESTOCK_IKE_SCAN`` or
``PATH``.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import coverage, inside_scope, roles
from ..identity import row_identity
from ..model import CryptoAsset, register_informational_prefixes
from ..util import ERROR_PREFIX, is_ipv6_literal, now_date, run, scan_address

SOURCE = "ike_scan"
SOURCE_NAME = "Active IKE scan (ike-scan) — internet-facing endpoint"

NOT_PERFORMED_SOURCE_NAME = (
    "IKE scan not performed — ike-scan binary unavailable in this environment")

#: Environment variable naming the ike-scan executable.
BINARY_ENV = "TAKESTOCK_IKE_SCAN"

#: Flag: some probes went unanswered or the budget ran out, so the floor is not settled.
INCONCLUSIVE_FLAG = "ike-sweep-inconclusive:"
#: Flag: the gateway takes the initiator's order instead of enforcing its own preference.
NO_RESPONDER_PREFERENCE_FLAG = "ike-no-responder-preference"

register_informational_prefixes(INCONCLUSIVE_FLAG)


@dataclass(frozen=True)
class AxisValue:
    """One value on one axis: ike-scan's ``--trans`` spec, the baseline token,
    its approximate security strength in bits (for ordering), and a label."""

    spec: str
    token: str
    strength: int
    label: str


# IKEv1 attribute values (RFC 2409 Appendix A; IANA "IPSEC Security
# Association Attributes" for the AES and SHA-2 values). Strengths follow
# NIST SP 800-57 Part 1 Table 2 for the groups and are approximate for the
# hashes; they only order the values.
ENC_VALUES: tuple[AxisValue, ...] = (
    AxisValue("1", "des", 56, "DES-CBC"),
    AxisValue("5", "3des", 112, "3DES-CBC"),
    AxisValue("7/128", "aes-cbc-128", 128, "AES-CBC-128"),
    AxisValue("7/192", "aes-cbc-192", 192, "AES-CBC-192"),
    AxisValue("7/256", "aes-cbc-256", 256, "AES-CBC-256"),
)

HASH_VALUES: tuple[AxisValue, ...] = (
    AxisValue("1", "md5", 64, "MD5"),
    AxisValue("2", "sha1", 80, "SHA1"),
    AxisValue("4", "sha256", 128, "SHA2-256"),
    AxisValue("5", "sha384", 192, "SHA2-384"),
    AxisValue("6", "sha512", 256, "SHA2-512"),
)

GROUP_VALUES: tuple[AxisValue, ...] = (
    AxisValue("1", "1", 64, "MODP-768"),
    AxisValue("2", "2", 80, "MODP-1024"),
    AxisValue("5", "5", 96, "MODP-1536"),
    AxisValue("14", "14", 112, "MODP-2048"),
    AxisValue("15", "15", 128, "MODP-3072"),
    AxisValue("19", "19", 128, "ECP-256"),
    AxisValue("16", "16", 152, "MODP-4096"),
    AxisValue("20", "20", 192, "ECP-384"),
    AxisValue("21", "21", 256, "ECP-521"),
)

#: IKEv1 authentication methods tried, in order: (value, label, menu orders).
#: 1 and 3 are RFC 2409's pre-shared key and RSA signatures. 65001 and 65005
#: are XAUTH with a pre-shared key or RSA signatures
#: (draft-ietf-ipsec-isakmp-xauth); 64221 is hybrid RSA authentication
#: (draft-ietf-ipsec-isakmp-hybrid-auth). The extended methods are tried with
#: one menu order only, to keep the probe count down.
AUTH_METHODS: tuple[tuple[str, str, int], ...] = (
    ("1", "PSK", 2),
    ("3", "RSA-Sig", 2),
    ("65001", "XAUTH-PSK", 1),
    ("65005", "XAUTH-RSA", 1),
    ("64221", "Hybrid-RSA", 1),
)


@dataclass(frozen=True)
class Combination:
    """One IKEv1 transform: encryption, hash, group and authentication method."""

    enc: AxisValue
    hash: AxisValue
    group: AxisValue
    auth: str = "1"

    @property
    def trans(self) -> str:
        """ike-scan's ``--trans=enc,hash,auth,group`` value."""
        return f"{self.enc.spec},{self.hash.spec},{self.auth},{self.group.spec}"

    @property
    def strength(self) -> int:
        return min(self.enc.strength, self.hash.strength, self.group.strength)

    def tokens(self) -> dict[str, str]:
        return {"enc": self.enc.token, "hash": self.hash.token, "group": self.group.token}

    def label(self) -> str:
        return f"{self.enc.label}/{self.hash.label}/{self.group.label}"


def _v(values: Sequence[AxisValue], spec: str) -> AxisValue:
    return next(x for x in values if x.spec == spec)


def _order(v: AxisValue) -> tuple[int, int]:
    lead = v.spec.split("/")[0]
    return (v.strength, int(lead) if lead.isdigit() else 0)


# The preference menu: a spread from very weak to strong, so a gateway that
# accepts anything on it shows its choice.
_MENU_ENTRIES: tuple[Combination, ...] = (
    Combination(_v(ENC_VALUES, "1"), _v(HASH_VALUES, "1"), _v(GROUP_VALUES, "1")),
    Combination(_v(ENC_VALUES, "1"), _v(HASH_VALUES, "2"), _v(GROUP_VALUES, "2")),
    Combination(_v(ENC_VALUES, "5"), _v(HASH_VALUES, "1"), _v(GROUP_VALUES, "2")),
    Combination(_v(ENC_VALUES, "5"), _v(HASH_VALUES, "2"), _v(GROUP_VALUES, "2")),
    Combination(_v(ENC_VALUES, "5"), _v(HASH_VALUES, "2"), _v(GROUP_VALUES, "5")),
    Combination(_v(ENC_VALUES, "7/128"), _v(HASH_VALUES, "2"), _v(GROUP_VALUES, "2")),
    Combination(_v(ENC_VALUES, "7/128"), _v(HASH_VALUES, "4"), _v(GROUP_VALUES, "14")),
    Combination(_v(ENC_VALUES, "7/192"), _v(HASH_VALUES, "4"), _v(GROUP_VALUES, "14")),
    Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "2"), _v(GROUP_VALUES, "14")),
    Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "4"), _v(GROUP_VALUES, "14")),
    Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "5"), _v(GROUP_VALUES, "19")),
    Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "5"), _v(GROUP_VALUES, "20")),
    Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "6"), _v(GROUP_VALUES, "21")),
)
_MENU: tuple[Combination, ...] = tuple(sorted(
    _MENU_ENTRIES,
    key=lambda c: (c.strength, _order(c.enc), _order(c.hash), _order(c.group))))

# Used for an axis the accepted SA did not name.
_DEFAULT_ANCHOR = Combination(_v(ENC_VALUES, "7/256"), _v(HASH_VALUES, "4"), _v(GROUP_VALUES, "14"))


# Probe outcomes.
ACCEPTED = "accepted"
REJECTED = "rejected"
NO_ANSWER = "no-answer"
ERROR = "error"


@dataclass
class ProbeResult:
    """One ike-scan run: what was offered, what came back, and the SA it accepted."""

    trans: tuple[str, ...]
    outcome: str
    sa: str = ""
    raw: str = ""

    def transform_signature(self) -> str:
        """The accepted SA's attributes, for comparing two answers."""
        parts = []
        for key in ("Enc", "KeyLength", "Hash", "Auth", "Group"):
            m = re.search(rf"{key}=(\S+)", self.sa)
            parts.append(f"{key}={m.group(1)}" if m else "")
        return "|".join(parts)


@dataclass(frozen=True)
class SweepBudget:
    """How many probes a gateway may receive, and how they are paced."""

    max_probes: int = 32
    delay: float = 1.0
    retry: int = 2
    timeout_ms: int = 500
    run_timeout: int = 30

    @classmethod
    def from_env(cls) -> SweepBudget:
        """The default budget, adjusted by the ``TAKESTOCK_IKE_*`` variables."""
        def _num(name: str, default: float) -> float:
            raw = os.environ.get(name, "").strip()
            try:
                return float(raw) if raw else default
            except ValueError:
                return default

        return cls(
            max_probes=max(1, int(_num("TAKESTOCK_IKE_MAX_PROBES", cls.max_probes))),
            delay=max(0.0, _num("TAKESTOCK_IKE_PROBE_DELAY", cls.delay)),
            retry=max(1, int(_num("TAKESTOCK_IKE_RETRY", cls.retry))),
            timeout_ms=max(50, int(_num("TAKESTOCK_IKE_TIMEOUT_MS", cls.timeout_ms))),
        )


def _binary() -> str | None:
    return os.environ.get(BINARY_ENV) or shutil.which("ike-scan")


def _parse_sa(out: str) -> list[str]:
    return re.findall(r"SA=\(([^)]*)\)", out)


def classify(out: str) -> tuple[str, str]:
    """(outcome, accepted SA text) for one ike-scan run.

    A handshake with an SA is acceptance; a Notify (such as
    NO-PROPOSAL-CHOSEN) is an answered refusal; anything else is silence.
    """
    if out.startswith(ERROR_PREFIX):
        return ERROR, ""
    sa = _parse_sa(out)
    if sa:
        return ACCEPTED, sa[0]
    if "Notify message" in out:
        return REJECTED, ""
    return NO_ANSWER, ""


Prober = Callable[[Sequence[str]], ProbeResult]


def _base_command(binary: str, ip: str, budget: SweepBudget) -> list[str]:
    cmd = [binary, "--sport=0", f"--retry={budget.retry}", f"--timeout={budget.timeout_ms}"]
    if is_ipv6_literal(ip):
        cmd.append("--ipv6")
    return cmd


def make_prober(binary: str, ip: str, budget: SweepBudget, transcript: list[str]) -> Prober:
    """A function that sends one IKEv1 Main Mode probe offering ``trans`` and classifies it."""
    def probe(trans: Sequence[str]) -> ProbeResult:
        cmd = _base_command(binary, ip, budget) + ["-M"]
        cmd += [f"--trans={t}" for t in trans]
        cmd.append(scan_address(ip))
        out = run(cmd, timeout=budget.run_timeout)
        transcript.append(f"\n$ {' '.join(cmd)}\n{out}")
        outcome, sa = classify(out)
        if budget.delay:
            time.sleep(budget.delay)
        return ProbeResult(tuple(trans), outcome, sa, out)

    return probe


@dataclass
class SweepOutcome:
    """Everything one gateway's sweep learned, and what limits it."""

    preferred: dict[str, str] = field(default_factory=dict)
    preferred_basis: str = ""
    preferred_label: str = ""
    accepted: dict[str, list[str]] = field(default_factory=dict)
    weakest: dict[str, str] = field(default_factory=dict)
    strongest: dict[str, str] = field(default_factory=dict)
    weakest_confirmed: bool = False
    strongest_confirmed: bool = False
    auth_method: str = ""
    anchor: str = ""
    probes: int = 0
    budget: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    unanswered: list[str] = field(default_factory=list)
    rejects_seen: int = 0
    sa_bodies: list[str] = field(default_factory=list)

    @property
    def responded(self) -> bool:
        return bool(self.sa_bodies)

    @property
    def conclusive(self) -> bool:
        """True when nothing was cut short, failed, or went unanswered."""
        return not (self.truncated or self.errors or self.unanswered)

    def failures(self, ip: str) -> list[str]:
        """The run failures this sweep owes."""
        out = []
        if self.truncated:
            out.append(
                f"IKE {ip}: transform sweep TRUNCATED at the {self.budget}-probe budget. "
                "The reported minimum/maximum are over the transforms actually probed, "
                "not the whole space — do not read them as the floor or the ceiling. "
                "Raise TAKESTOCK_IKE_MAX_PROBES and re-run.")
        for e in self.errors:
            out.append(f"IKE {ip}: ike-scan failed during the sweep ({e})")
        if self.unanswered and self.rejects_seen:
            out.append(
                f"IKE {ip}: {len(self.unanswered)} probe(s) unanswered by a gateway that "
                f"answers refusals with NO-PROPOSAL-CHOSEN ({self.rejects_seen} seen) — "
                "the packets were lost or rate-limited, so 'not accepted' cannot "
                f"be concluded for {', '.join(self.unanswered[:6])}"
                f"{' …' if len(self.unanswered) > 6 else ''}. "
                "Raise TAKESTOCK_IKE_PROBE_DELAY and re-run.")
        return out


class _Sweeper:
    """Runs the preference search and the per-axis sweeps within one budget."""

    def __init__(self, probe: Prober, budget: SweepBudget) -> None:
        self.probe = probe
        self.budget = budget
        self.out = SweepOutcome(budget=budget.max_probes)

    def fire(self, trans: Sequence[str]) -> ProbeResult | None:
        """Send one probe, or None (and mark the sweep truncated) once the budget is spent."""
        if self.out.probes >= self.budget.max_probes:
            self.out.truncated = True
            return None
        self.out.probes += 1
        r = self.probe(trans)
        if r.outcome == ERROR:
            self.out.errors.append(",".join(trans) or "default")
        elif r.outcome == REJECTED:
            self.out.rejects_seen += 1
        elif r.outcome == ACCEPTED and r.sa:
            self.out.sa_bodies.append(r.sa)
        return r

    def _menu(self, auth: str) -> list[str]:
        return [Combination(c.enc, c.hash, c.group, auth).trans for c in _MENU]

    def preference(self) -> Combination | None:
        """The transform the gateway picks from the menu, trying each auth method in turn."""
        silent: list[str] = []
        for auth, auth_label, menus in AUTH_METHODS:
            menu = self._menu(auth)
            lo = self.fire(menu)
            if lo is None:
                self.out.unanswered += silent
                return None
            hi = self.fire(list(reversed(menu))) if menus > 1 else lo
            if hi is None:
                self.out.unanswered += silent
                return None

            mine = [f"menu-{auth_label}:{order}"
                    for r, order in ((lo, "low"), (hi, "high"))
                    if r.outcome == NO_ANSWER and (menus > 1 or order == "low")]
            silent += mine

            chosen = hi if hi.outcome == ACCEPTED else lo
            if chosen.outcome != ACCEPTED:
                continue

            # Silence on an earlier auth method is expected once a later one
            # is accepted; only this method's own silence counts.
            self.out.unanswered += mine
            self.out.auth_method = auth_label
            anchor = _combination_from_sa(chosen.sa, auth)
            self.out.preferred = anchor.tokens()
            self.out.preferred_label = anchor.label()
            if menus > 1 and lo.outcome == ACCEPTED and hi.outcome == ACCEPTED:
                self.out.preferred_basis = (
                    "responder-policy"
                    if lo.transform_signature() == hi.transform_signature()
                    else "initiator-order")
            else:
                self.out.preferred_basis = "single-menu"
            self.out.anchor = anchor.label()
            return anchor
        self.out.unanswered += silent
        return None

    def axis(self, name: str, values: Sequence[AxisValue], anchor: Combination) -> list[AxisValue]:
        """The values on one axis the gateway accepts, the others held at the anchor."""
        known = {"enc": anchor.enc, "hash": anchor.hash, "group": anchor.group}[name]
        found = [known]
        for value in values:
            if value.spec == known.spec:
                continue
            trial = Combination(
                value if name == "enc" else anchor.enc,
                value if name == "hash" else anchor.hash,
                value if name == "group" else anchor.group,
                anchor.auth)
            r = self.fire([trial.trans])
            if r is None:
                break
            if r.outcome == ACCEPTED:
                found.append(value)
            elif r.outcome == NO_ANSWER:
                self.out.unanswered.append(f"{name}:{value.token}")
        return sorted(found, key=_order)

    def confirm(self, combo: Combination, anchor: Combination) -> bool:
        """Whether the gateway accepts ``combo`` as one transform."""
        if combo.trans == anchor.trans:
            return True
        r = self.fire([combo.trans])
        return bool(r and r.outcome == ACCEPTED)

    def run(self) -> SweepOutcome:
        anchor = self.preference()
        if anchor is None:
            return self.out

        enc = self.axis("enc", ENC_VALUES, anchor)
        hsh = self.axis("hash", HASH_VALUES, anchor)
        grp = self.axis("group", GROUP_VALUES, anchor)
        self.out.accepted = {"enc": [v.token for v in enc], "hash": [v.token for v in hsh],
                             "group": [v.token for v in grp]}
        self.out.weakest = {"enc": enc[0].token, "hash": hsh[0].token, "group": grp[0].token}
        self.out.strongest = {"enc": enc[-1].token, "hash": hsh[-1].token, "group": grp[-1].token}

        # The per-axis floors may not be accepted together; say whether they are.
        self.out.weakest_confirmed = self.confirm(
            Combination(enc[0], hsh[0], grp[0], anchor.auth), anchor)
        self.out.strongest_confirmed = self.confirm(
            Combination(enc[-1], hsh[-1], grp[-1], anchor.auth), anchor)
        return self.out


def _combination_from_sa(sa: str, auth: str) -> Combination:
    t = parse_transforms([sa])
    enc = next((v for v in ENC_VALUES if v.token in t["enc"]), _DEFAULT_ANCHOR.enc)
    hsh = next((v for v in HASH_VALUES if v.token in t["hashes"]), _DEFAULT_ANCHOR.hash)
    grp = next((v for v in GROUP_VALUES if v.token in t["groups"]), _DEFAULT_ANCHOR.group)
    return Combination(enc, hsh, grp, auth)


# ike-scan's attribute names to baseline tokens. IKEv1 SAs print Enc=, Hash=,
# Group=, Auth=; IKEv2 SAs print Encr=, Integ=, Prf= and DH_Group=.
_ENC_MAP = {"3des": "3des", "des": "des", "aes": "aes-cbc", "aes_cbc": "aes-cbc",
            "aes_gcm_16": "aes-gcm", "aes_gcm_12": "aes-gcm", "aes_gcm_8": "aes-gcm",
            "chacha20_poly1305": "chacha20-poly1305", "idea": "idea",
            "blowfish": "blowfish", "rc5": "rc5", "cast": "cast", "camellia": "camellia"}
_HASH_MAP = {"md5": ("md5", "hmac-md5"), "sha1": ("sha1", "hmac-sha1"),
             "sha2-256": ("sha256", "hmac-sha2-256"), "sha2-384": ("sha384", "hmac-sha2-384"),
             "sha2-512": ("sha512", "hmac-sha2-512")}
_PRF_MAP = {"hmac_md5": "hmac-md5", "hmac_sha1": "hmac-sha1",
            "hmac_sha2_256": "hmac-sha2-256", "hmac_sha2_384": "hmac-sha2-384",
            "hmac_sha2_512": "hmac-sha2-512"}
_INTEG_DIGEST = {"MD5": "md5", "SHA1": "sha1", "SHA2_256": "sha256",
                 "SHA2_384": "sha384", "SHA2_512": "sha512"}


def parse_transforms(accepted: list[str]) -> dict[str, list[str]]:
    """Baseline tokens from accepted SA texts: ``enc``, ``hashes``, ``prf``, ``groups``, ``auth``."""
    enc, hsh, prf, groups, auth = set(), set(), set(), set(), set()
    for sa in accepted:
        e = re.search(r"Encr?=([A-Za-z0-9_-]+)", sa)
        kl = re.search(r"KeyLength=(\d+)", sa)
        if e:
            name = e.group(1).lower()
            base = _ENC_MAP.get(name, name)
            sized = base in ("aes-cbc", "aes-gcm")
            enc.add(f"{base}-{kl.group(1)}" if (kl and sized) else base)
        if m := re.search(r"Hash=(\S+)", sa):
            name = m.group(1).lower()
            digest, hmac = _HASH_MAP.get(name, (name, f"hmac-{name}"))
            hsh.add(digest)
            prf.add(hmac)
        if m := re.search(r"Integ=HMAC_(MD5|SHA1|SHA2_256|SHA2_384|SHA2_512)", sa, re.I):
            hsh.add(_INTEG_DIGEST[m.group(1).upper()])
        if m := re.search(r"Prf=([A-Za-z0-9_]+)", sa):
            name = m.group(1).lower()
            prf.add(_PRF_MAP.get(name, name.replace("_", "-")))
        if m := re.search(r"(?:DH_)?Group=(\d+)", sa):
            groups.add(m.group(1))
        if m := re.search(r"Auth=(\S+)", sa):
            auth.add(m.group(1))
    return {"enc": sorted(enc), "hashes": sorted(hsh), "prf": sorted(prf),
            "groups": sorted(groups), "auth": sorted(auth)}


GAP_AXES = ("enc", "hash", "group")


def _gap_notes(sweep: SweepOutcome) -> list[str]:
    bits = []
    for axis in GAP_AXES:
        lo, pref = sweep.weakest.get(axis), sweep.preferred.get(axis)
        if lo and pref and lo != pref:
            bits.append(f"{axis} {pref}→{lo}")
    return bits


# IKEv2 answers.
IKEV2_ACCEPTED = "answered"
IKEV2_REJECTED = "answered-no-proposal"
IKEV2_SILENT = "no-answer"
IKEV2_ERROR = "error"


def classify_ikev2(out: str) -> tuple[str, str]:
    """(answer, SA text) for one ``ike-scan --ikev2`` run."""
    if out.startswith(ERROR_PREFIX):
        return IKEV2_ERROR, ""
    sa = _parse_sa(out)
    if sa and "IKEv2" in out:
        return IKEV2_ACCEPTED, sa[0]
    if "Notify message" in out:
        return IKEV2_REJECTED, ""
    return IKEV2_SILENT, ""


def probe_ikev2(binary: str, ip: str, budget: SweepBudget,
                transcript: list[str]) -> tuple[str, str]:
    """Send one IKEv2 IKE_SA_INIT with ike-scan's default offer; return (answer, SA text)."""
    cmd = _base_command(binary, ip, budget) + ["--ikev2", scan_address(ip)]
    out = run(cmd, timeout=budget.run_timeout)
    transcript.append(f"\n$ {' '.join(cmd)}\n{out}")
    return classify_ikev2(out)


def _asset_from_transforms(ip: str, accepted: list[str], ref_time: datetime | None = None,
                           sweep: SweepOutcome | None = None, role: str = "",
                           ident: str = "", ikev2: tuple[str, str] | None = None
                           ) -> CryptoAsset:
    """The gateway's row: every accepted transform graded, plus the sweep's readings."""
    graded = list(accepted) + ([ikev2[1]] if ikev2 and ikev2[1] else [])
    t = parse_transforms(graded)
    responded = bool(accepted)
    extra: dict = {"ike_dh_groups": t["groups"], "ike_encryption": t["enc"],
                   "ike_prf": t["prf"], "ike_auth": t["auth"], "responded": responded}
    notes = ("accepted transforms: " + "; ".join(sorted(set(accepted)))[:300]) if responded \
        else "no IKEv1 response (gateway silent to every menu offered)"
    flags: list[str] = []

    if sweep is not None:
        extra.update({
            "ike_preferred": sweep.preferred,
            "ike_preferred_basis": sweep.preferred_basis,
            "ike_weakest": sweep.weakest,
            "ike_strongest": sweep.strongest,
            "ike_accepted": sweep.accepted,
            "ike_weakest_combination_confirmed": sweep.weakest_confirmed,
            "ike_strongest_combination_confirmed": sweep.strongest_confirmed,
            "ike_auth_method": sweep.auth_method,
            "ike_sweep_probes": sweep.probes,
            "ike_sweep_budget": sweep.budget,
            "ike_sweep_conclusive": sweep.conclusive,
            "ike_sweep_unanswered": sweep.unanswered,
            "ike_sweep_truncated": sweep.truncated,
        })
        if responded:
            head = [f"sweep: {sweep.probes}/{sweep.budget} probes",
                    f"preferred {sweep.preferred_label} ({sweep.preferred_basis})"]
            gaps = _gap_notes(sweep)
            head.append("downgrade surface: " + ", ".join(gaps) if gaps
                        else "no downgrade surface: floor == preferred")
            if not sweep.weakest_confirmed:
                head.append("weakest is per-axis only — the combination was refused")
            notes = "; ".join(head) + "; " + notes
        if not sweep.conclusive:
            flags.append(f"{INCONCLUSIVE_FLAG}{len(sweep.unanswered) or 1}")
            notes += (f"; INCONCLUSIVE — {len(sweep.unanswered)} probe(s) got no answer"
                      f"{' and the sweep was truncated' if sweep.truncated else ''}, "
                      "so a weaker accepted transform cannot be ruled out")
        if sweep.preferred_basis == "initiator-order":
            flags.append(NO_RESPONDER_PREFERENCE_FLAG)

    if ikev2 is not None:
        answer, sa = ikev2
        extra["ikev2"] = answer
        extra["ikev2_sa"] = sa
        notes += {
            IKEV2_ACCEPTED: f"; IKEv2 answered and chose {sa} from the probe's default offer",
            IKEV2_REJECTED: "; IKEv2 answered but chose nothing from the probe's default offer",
            IKEV2_SILENT: "; no IKEv2 answer to the probe's default offer",
            IKEV2_ERROR: "; the IKEv2 probe could not run",
        }[answer]

    host, address = row_identity(ident, ip)
    return CryptoAsset(
        name=f"IKE {host}:500", role=role, data_state="in-transit", protocol="ike",
        host=host, ip=address, port="500", source=SOURCE, internet_facing=True,
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        symmetric=t["enc"], hashes=t["hashes"], flags=sorted(flags),
        notes=notes, extra=extra,
    )


def _probe(binary: str, ip: str, raw_dir: Path | None, ref_time: datetime | None = None,
           budget: SweepBudget | None = None, role: str = "",
           ident: str = "") -> tuple[CryptoAsset, list[str]]:
    budget = budget or SweepBudget.from_env()
    transcript: list[str] = []
    sweep = _Sweeper(make_prober(binary, ip, budget, transcript), budget).run()
    ikev2 = probe_ikev2(binary, ip, budget, transcript)
    if raw_dir:
        (raw_dir / f"ike-scan-{scan_address(ip)}.txt").write_text("".join(transcript))
    return (_asset_from_transforms(ip, sweep.sa_bodies, ref_time, sweep, role, ident, ikev2),
            sweep.failures(ip))


def coverage_gaps(assets: Sequence[CryptoAsset]) -> list[coverage.Gap]:
    """A gap naming every gateway whose row exists only because ike-scan was missing."""
    unmeasured = [a for a in assets if a.source_name == NOT_PERFORMED_SOURCE_NAME]
    if not unmeasured:
        return []
    named = ", ".join(sorted(a.host or a.ip for a in unmeasured))
    return [coverage.gap(coverage.NOT_COLLECTED, (
        f"IKE/IPsec transform sweep on {len(unmeasured)} authorised VPN gateway(s) — the "
        f"ike-scan program was not available in this environment, so no probe was sent "
        f"and no transform, downgrade floor or Diffie-Hellman group was measured on any of "
        f"them: {named}. Their rows read `unknown` because nothing was asked, which is NOT "
        f"evidence that they are sound."),
        impact=("No VPN gateway listed has a measured transform, downgrade floor or "
                "Diffie-Hellman group, so there is no evidence either way about IPsec "
                "downgrade exposure or the VPN path's post-quantum readiness. An "
                "unmeasured gateway and a clean one read the same here."),
        impact_kind=coverage.CHANGES_CONCLUSION,
        harvest=(f"Set {BINARY_ENV} to an ike-scan build (or put ike-scan on PATH) and "
                 "re-run the active scans."),
        nature=coverage.NO_DATA)]


def collect(target: dict, raw_dir: Path | None = None, ref_time: datetime | None = None,
            budget: SweepBudget | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Sweep every authorised gateway; return (assets, failures).

    A missing ike-scan is not a failure (nothing went wrong); each gateway
    gets an ``unknown`` row and :func:`coverage_gaps` reports them.
    """
    gws = (target.get("scan_targets", {}) or {}).get("vpn_gateways", []) or []
    if not gws:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    binary = _binary()
    if not binary:
        return [CryptoAsset(name=f"IKE {gw.get('host') or gw['ip']}:500",
                            role=roles.vpn_gateway(gw), data_state="in-transit",
                            protocol="ike", host=str(gw.get("host") or gw["ip"]),
                            ip=row_identity(str(gw.get("host") or ""), str(gw.get("ip") or ""))[1],
                            port="500",
                            source=SOURCE, verdict="unknown",
                            source_class="unknown",
                            source_name=NOT_PERFORMED_SOURCE_NAME,
                            collected_at=now_date(ref_time),
                            notes=f"ike-scan not found (set {BINARY_ENV} or install it)")
                for gw in gws], []
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for gw in gws:
        asset, fails = _probe(binary, gw.get("ip") or gw["host"], raw_dir, ref_time, budget,
                              roles.vpn_gateway(gw), ident=str(gw.get("host") or ""))
        assets.append(asset)
        failures += fails
    return assets, failures
