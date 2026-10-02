"""The IKE transform sweep, against simulated gateways.

ike-scan is not installed where these tests were written, so its output is
composed by hand in its documented line format (``SA=(...)`` for an accepted
proposal, ``Notify message 14 (NO-PROPOSAL-CHOSEN)`` for a refusal). A
simulated gateway decides, per probe, what a real one would answer.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from probe_helpers import FakeRun, has, never_run, target

from takestock import coverage
from takestock.collectors import ike_scan
from takestock.collectors.ike_scan import ProbeResult, SweepBudget, _Sweeper

IP = "192.0.2.50"
GW = {"host": "vpn.example.test", "ip": IP, "site": "Head office"}

_ENC_OUT = {"1": "Enc=DES", "5": "Enc=3DES", "7/128": "Enc=AES KeyLength=128",
            "7/192": "Enc=AES KeyLength=192", "7/256": "Enc=AES KeyLength=256"}
_HASH_OUT = {"1": "MD5", "2": "SHA1", "4": "SHA2-256", "5": "SHA2-384", "6": "SHA2-512"}
_AUTH_OUT = {"1": "PSK", "3": "RSA_Sig", "65001": "XAUTHInitPreShared",
             "65005": "XAUTHInitRSA", "64221": "HybridInitRSA"}


def accepted_line(enc: str, hsh: str, auth: str, group: str) -> str:
    return (f"{IP}\tMain Mode Handshake returned HDR=(CKY-R=0000000000000001) "
            f"SA=({_ENC_OUT[enc]} Hash={_HASH_OUT[hsh]} Group={group}:modp "
            f"Auth={_AUTH_OUT[auth]} LifeType=Seconds LifeDuration=86400)\n")


NOTIFY = f"{IP}\tNotify message 14 (NO-PROPOSAL-CHOSEN) HDR=(CKY-R=0000000000000002)\n"
SILENT = ("Ending ike-scan: 1 hosts scanned in 2.0 seconds (0.50 hosts/sec).  "
          "0 returned handshake; 0 returned notify\n")


class Gateway:
    """A simulated IKEv1 responder.

    It accepts a transform when every attribute is in its allowed sets. With
    ``own_preference`` it picks its favourite acceptable transform from those
    offered, or else the strongest, whatever the order; without, it takes the
    first acceptable one in the order offered.
    """

    def __init__(self, enc: set[str], hsh: set[str], groups: set[str], auth: set[str],
                 favourite: tuple[str, str, str] = ("7/256", "5", "20"),
                 own_preference: bool = True, silent_to: Sequence[str] = ()) -> None:
        self.enc, self.hsh, self.groups, self.auth = enc, hsh, groups, auth
        self.favourite = favourite
        self.own_preference = own_preference
        self.silent_to = set(silent_to)
        self.offers: list[tuple[str, ...]] = []

    def __call__(self, trans: Sequence[str]) -> ProbeResult:
        self.offers.append(tuple(trans))
        if any(t in self.silent_to for t in trans):
            return ProbeResult(tuple(trans), ike_scan.NO_ANSWER, raw=SILENT)
        ok = []
        for t in trans:
            enc, hsh, auth, grp = t.split(",")
            if enc in self.enc and hsh in self.hsh and grp in self.groups and auth in self.auth:
                ok.append((enc, hsh, auth, grp))
        if not ok:
            return ProbeResult(tuple(trans), ike_scan.REJECTED, raw=NOTIFY)
        pick = ok[0]
        if self.own_preference:
            fav = [o for o in ok if (o[0], o[1], o[3]) == self.favourite]
            pick = fav[0] if fav else max(ok, key=_strength)
        out = accepted_line(*pick)
        outcome, sa = ike_scan.classify(out)
        return ProbeResult(tuple(trans), outcome, sa, out)


def sweep(gateway: Gateway, max_probes: int = 32) -> ike_scan.SweepOutcome:
    return _Sweeper(gateway, SweepBudget(max_probes=max_probes, delay=0)).run()


def _strength(t: tuple[str, str, str, str]) -> int:
    enc, hsh, _auth, grp = t
    return min(ike_scan._v(ike_scan.ENC_VALUES, enc).strength,
               ike_scan._v(ike_scan.HASH_VALUES, hsh).strength,
               ike_scan._v(ike_scan.GROUP_VALUES, grp).strength)


# Prefers AES-256/SHA2-384/ECP-384 and also accepts AES-128, SHA2-256 and ECP-256.
TYPICAL = dict(enc={"7/128", "7/256"}, hsh={"4", "5"}, groups={"19", "20"}, auth={"1"})


# ── the sweep ──

def test_a_gateway_with_its_own_preference_is_read_axis_by_axis():
    out = sweep(Gateway(**TYPICAL))
    assert out.auth_method == "PSK"
    assert out.preferred == {"enc": "aes-cbc-256", "hash": "sha384", "group": "20"}
    assert out.preferred_basis == "responder-policy"
    assert out.accepted == {"enc": ["aes-cbc-128", "aes-cbc-256"],
                           "hash": ["sha256", "sha384"], "group": ["19", "20"]}
    assert out.weakest == {"enc": "aes-cbc-128", "hash": "sha256", "group": "19"}
    assert out.weakest_confirmed and out.strongest_confirmed
    assert out.conclusive
    assert out.probes <= out.budget


def test_the_row_grades_the_floor_and_names_the_downgrade_surface(policy):
    out = sweep(Gateway(**TYPICAL))
    a = ike_scan._asset_from_transforms(IP, out.sa_bodies, sweep=out, ident=GW["host"])
    assert (a.host, a.ip, a.port, a.protocol) == ("vpn.example.test", IP, "500", "ike")
    assert ("downgrade surface: enc aes-cbc-256→aes-cbc-128, hash sha384→sha256, "
            "group 20→19") in a.notes
    policy.apply(a)
    assert a.verdict == "acceptable"                     # the floor, not the preference
    # Only an axis whose floor grades below its preference is a downgrade surface.
    assert "downgrade-surface:group" in a.flags
    assert "downgrade-surface:enc" not in a.flags
    assert "downgrade-surface:hash" not in a.flags
    assert not any(f.startswith("ungraded:") for f in a.flags)


def test_a_gateway_that_follows_the_initiator_order_is_flagged():
    out = sweep(Gateway(**TYPICAL, own_preference=False))
    assert out.preferred_basis == "initiator-order"
    a = ike_scan._asset_from_transforms(IP, out.sa_bodies, sweep=out)
    assert ike_scan.NO_RESPONDER_PREFERENCE_FLAG in a.flags


def test_a_gateway_that_only_takes_xauth_is_found_by_the_extended_methods():
    gw = Gateway(enc={"7/256"}, hsh={"6"}, groups={"21"}, auth={"65001"})
    out = sweep(gw)
    assert out.auth_method == "XAUTH-PSK"
    assert out.preferred_basis == "single-menu"
    assert out.weakest == out.preferred                  # nothing below the preferred
    assert out.unanswered == []                          # refusals are answers


def test_a_silent_gateway_measures_nothing_and_says_so():
    gw = Gateway(**TYPICAL, silent_to=[c.trans for c in ike_scan._MENU] +
                 [ike_scan.Combination(c.enc, c.hash, c.group, a).trans
                  for c in ike_scan._MENU for a, _l, _m in ike_scan.AUTH_METHODS])
    out = sweep(gw)
    assert not out.responded and not out.conclusive
    a = ike_scan._asset_from_transforms(IP, out.sa_bodies, sweep=out)
    assert a.notes.startswith("no IKEv1 response")
    assert any(f.startswith(ike_scan.INCONCLUSIVE_FLAG) for f in a.flags)


def test_a_sweep_out_of_budget_is_truncated_and_a_failure():
    out = sweep(Gateway(**TYPICAL), max_probes=5)
    assert out.truncated and not out.conclusive
    assert "TRUNCATED at the 5-probe budget" in out.failures(IP)[0]


def test_silence_from_a_gateway_that_answers_refusals_is_a_failure():
    silent = ike_scan.Combination(ike_scan._v(ike_scan.ENC_VALUES, "1"),
                                  ike_scan._v(ike_scan.HASH_VALUES, "5"),
                                  ike_scan._v(ike_scan.GROUP_VALUES, "20"), "1").trans
    out = sweep(Gateway(**TYPICAL, silent_to=[silent]))
    assert out.unanswered == ["enc:des"]
    [failure] = out.failures(IP)
    assert "cannot be concluded for enc:des" in failure


# ── parsing ──

def test_ikev1_transforms_map_to_baseline_tokens(baseline):
    t = ike_scan.parse_transforms([
        "Enc=DES Hash=MD5 Group=1:modp768 Auth=PSK",
        "Enc=AES KeyLength=192 Hash=SHA2-512 Group=21:ecp521 Auth=RSA_Sig"])
    assert t == {"enc": ["aes-cbc-192", "des"], "hashes": ["md5", "sha512"],
                 "prf": ["hmac-md5", "hmac-sha2-512"], "groups": ["1", "21"],
                 "auth": ["PSK", "RSA_Sig"]}
    assert all(e in baseline["ike_encryption"] for e in t["enc"])
    assert all(p in baseline["ike_prf"] for p in t["prf"])


def test_ikev2_transforms_map_to_baseline_tokens(baseline):
    t = ike_scan.parse_transforms([
        "Encr=AES_GCM_16,KeyLength=256 Prf=HMAC_SHA2_384 DH_Group=20:ecp384"])
    assert (t["enc"], t["prf"], t["groups"]) == (["aes-gcm-256"], ["hmac-sha2-384"], ["20"])
    t = ike_scan.parse_transforms([
        "Encr=AES_CBC,KeyLength=128 Integ=HMAC_SHA1_96 Prf=HMAC_SHA1 DH_Group=2:modp1024"])
    assert (t["enc"], t["hashes"], t["prf"]) == (["aes-cbc-128"], ["sha1"], ["hmac-sha1"])
    assert all(e in baseline["ike_encryption"] for e in t["enc"])


@pytest.mark.parametrize(("out", "outcome"), [
    (accepted_line("7/192", "6", "1", "21"), ike_scan.ACCEPTED),
    (NOTIFY, ike_scan.REJECTED),
    (SILENT, ike_scan.NO_ANSWER),
    ("__ERROR__ no such file", ike_scan.ERROR),
])
def test_each_ike_scan_answer_is_classified(out, outcome):
    assert ike_scan.classify(out)[0] == outcome


IKEV2_ANSWER = (f"{IP}\tIKEv2 SA_INIT Handshake returned HDR=(CKY-R=0000000000000003, IKEv2) "
                "SA=(Encr=AES_GCM_16,KeyLength=256 Prf=HMAC_SHA2_512 "
                "DH_Group=21:ecp521) KeyExchange(136 bytes) Nonce(32 bytes)\n")


def test_an_ikev2_answer_is_recorded_and_graded(policy):
    answer = ike_scan.classify_ikev2(IKEV2_ANSWER)
    assert answer[0] == ike_scan.IKEV2_ACCEPTED
    a = ike_scan._asset_from_transforms(IP, [], ikev2=answer)
    assert a.extra["ikev2"] == "answered"
    assert a.extra["ike_dh_groups"] == ["21"]
    assert "IKEv2 answered and chose" in a.notes
    policy.apply(a)
    assert a.verdict == "strong"


@pytest.mark.parametrize(("out", "answer"), [
    (NOTIFY, ike_scan.IKEV2_REJECTED), (SILENT, ike_scan.IKEV2_SILENT),
    ("__ERROR__ x", ike_scan.IKEV2_ERROR)])
def test_ikev2_non_answers_are_told_apart(out, answer):
    assert ike_scan.classify_ikev2(out) == (answer, "")


# ── commands and collect ──

def test_each_probe_offers_its_transforms_in_main_mode(monkeypatch):
    fake = FakeRun([(has("--trans=7/192,6,1,21"), accepted_line("7/192", "6", "1", "21"))])
    monkeypatch.setattr(ike_scan, "run", fake)
    transcript: list[str] = []
    probe = ike_scan.make_prober("/opt/ike-scan", "2001:db8::50", SweepBudget(delay=0), transcript)
    r = probe(["7/192,6,1,21"])
    assert r.outcome == ike_scan.ACCEPTED
    assert fake.calls == [["/opt/ike-scan", "--sport=0", "--retry=2", "--timeout=500", "--ipv6",
                           "-M", "--trans=7/192,6,1,21", "2001:db8::50"]]
    assert "$ /opt/ike-scan" in transcript[0]


def test_the_budget_can_be_set_from_the_environment(monkeypatch):
    monkeypatch.setenv("TAKESTOCK_IKE_MAX_PROBES", "64")
    monkeypatch.setenv("TAKESTOCK_IKE_PROBE_DELAY", "nonsense")
    b = SweepBudget.from_env()
    assert (b.max_probes, b.delay) == (64, SweepBudget.delay)


def test_without_ike_scan_each_gateway_is_unknown_and_named_in_a_gap(monkeypatch):
    monkeypatch.delenv(ike_scan.BINARY_ENV, raising=False)
    monkeypatch.setattr(ike_scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(ike_scan, "run", never_run)
    assets, failures = ike_scan.collect(target(vpn_gateways=[GW]))
    assert failures == []                       # nothing went wrong; nothing was asked
    [a] = assets
    assert (a.verdict, a.source_name) == ("unknown", ike_scan.NOT_PERFORMED_SOURCE_NAME)
    assert "Head office site" in a.role
    [gap] = ike_scan.coverage_gaps(assets)
    assert gap.kind == coverage.NOT_COLLECTED and "vpn.example.test" in gap


@pytest.mark.parametrize(("ident", "probe", "host", "ip"), [
    ("vpn.example.test", IP, "vpn.example.test", IP),
    ("", IP, IP, ""),
    ("", "vpn.example.test", "vpn.example.test", ""),
])
def test_a_row_is_named_by_the_host_name_and_ip_never_holds_a_name(ident, probe, host, ip):
    a = ike_scan._asset_from_transforms(probe, [], ident=ident)
    assert (a.name, a.host, a.ip) == (f"IKE {host}:500", host, ip)


@pytest.mark.parametrize(("gw", "host", "ip"), [
    ({"host": "vpn.example.test", "ip": IP}, "vpn.example.test", IP),
    ({"ip": IP}, IP, ""),
    ({"host": "vpn.example.test"}, "vpn.example.test", ""),
])
def test_an_unmeasured_gateway_is_named_by_the_same_rule(monkeypatch, gw, host, ip):
    monkeypatch.delenv(ike_scan.BINARY_ENV, raising=False)
    monkeypatch.setattr(ike_scan.shutil, "which", lambda name: None)
    [a], _ = ike_scan.collect(target(vpn_gateways=[gw]))
    assert (a.host, a.ip) == (host, ip)


def test_no_gap_when_the_sweep_ran(monkeypatch):
    a = ike_scan._asset_from_transforms(IP, [])
    assert ike_scan.coverage_gaps([a]) == []


def test_a_full_run_sweeps_then_asks_ikev2(monkeypatch, tmp_path):
    gw = Gateway(**TYPICAL)

    def fake_run(cmd, timeout=60, stdin_text=None):
        if "--ikev2" in cmd:
            return IKEV2_ANSWER
        return gw([c.split("=", 1)[1] for c in cmd if c.startswith("--trans=")]).raw

    monkeypatch.setenv(ike_scan.BINARY_ENV, "/opt/ike-scan")
    monkeypatch.setattr(ike_scan, "run", fake_run)
    monkeypatch.setattr(ike_scan.time, "sleep", lambda _s: None)
    [a], failures = ike_scan.collect(target(vpn_gateways=[GW]), raw_dir=tmp_path)
    assert failures == []
    assert a.extra["ike_sweep_conclusive"] is True
    assert a.extra["ikev2"] == "answered"
    assert "--ikev2" in (tmp_path / f"ike-scan-{IP}.txt").read_text()


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setenv(ike_scan.BINARY_ENV, "/opt/ike-scan")
    monkeypatch.setattr(ike_scan, "run", never_run)
    assets, failures = ike_scan.collect(target(authorised=False, vpn_gateways=[GW]))
    assert assets == [] and failures[0].startswith("ike_scan: REFUSED")
