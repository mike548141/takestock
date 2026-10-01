"""Port posture: cleartext findings, unverified encryption and the port table itself."""

from __future__ import annotations

import pytest

from takestock import plaintext
from takestock.model import CryptoAsset, is_informational_flag

HEADER = ("port", "transport", "protocol", "posture", "exposure", "remediability", "frontable", "notes")


def row(port, transport, protocol, posture, exposure="n/a", remediability="n/a",
        frontable="n/a", notes="") -> dict[str, str]:
    return dict(zip(HEADER, (port, transport, protocol, posture, exposure, remediability,
                             frontable, notes), strict=True))


def listener(port: str) -> CryptoAsset:
    return CryptoAsset(name=f"port {port}", data_state="in-transit", protocol="",
                       host="host1.example.test", port=port)


# ── the index ──

def test_a_shared_port_is_disambiguated_by_transport():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "cleartext", "content"),
                                 row("9", "udp", "beta", "opportunistic")])
    assert plaintext.lookup("9", "tcp", idx)["protocol"] == "alpha"
    assert plaintext.lookup("9", "udp", idx)["protocol"] == "beta"
    assert plaintext.lookup("9", "", idx) is None   # postures disagree: no bare key


def test_a_bare_port_key_exists_when_postures_agree():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "encrypted"),
                                 row("9", "udp", "alpha", "encrypted")])
    assert plaintext.lookup("9", "", idx)["protocol"] == "alpha"


@pytest.mark.parametrize("bad", [
    row("9", "tcp", "alpha", "sometimes"),
    row("9", "tcp", "alpha", "cleartext", exposure="everything"),
    row("9", "tcp", "alpha", "encrypted", exposure="content"),
    row("9", "tcp", "alpha", "cleartext", remediability="maybe"),
    row("9", "tcp", "alpha", "opportunistic", remediability="unresearched"),
    row("9", "tcp", "alpha", "cleartext", frontable="sideways"),
    row("9", "tcp", "alpha", "encrypted", frontable="reverse-web-proxy"),
])
def test_an_invalid_row_is_refused(bad):
    with pytest.raises(ValueError):
        plaintext.build_index([bad])


def test_a_row_with_the_wrong_field_count_is_refused():
    broken = row("9", "tcp", "alpha", "cleartext")
    broken[None] = "extra"   # what csv.DictReader produces for an unquoted comma
    with pytest.raises(ValueError, match="wrong number of fields"):
        plaintext.build_index([broken])


# ── applying a posture ──

def test_a_cleartext_listener_is_weak_flagged_and_classified():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "cleartext", "credentials")])
    a = listener("9")
    assert plaintext.apply_posture(a, idx, "tcp") == "cleartext"
    assert a.verdict == "weak"
    assert {"plaintext:alpha", "cleartext-exposure:credentials"} <= set(a.flags)
    assert a.notes.startswith("NO ENCRYPTION")
    assert plaintext.CONVENTION_BASIS in a.notes


def test_probe_evidence_replaces_the_convention_wording():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "cleartext", "content")])
    a = listener("9")
    plaintext.apply_posture(a, idx, "tcp", evidence="A probe read a plaintext banner.")
    assert "A probe read a plaintext banner." in a.notes
    assert plaintext.CONVENTION_BASIS not in a.notes


def test_a_measured_verdict_is_never_overwritten():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "cleartext", "content")])
    a = listener("9")
    a.verdict = "acceptable"
    plaintext.apply_posture(a, idx, "tcp")
    assert a.verdict == "acceptable"


def test_an_opportunistic_listener_is_a_gap_not_a_finding():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "opportunistic")])
    a = listener("9")
    assert plaintext.apply_posture(a, idx, "tcp") == "opportunistic"
    assert a.verdict == "unknown"
    assert a.flags == ["unverified-encryption:alpha"]
    assert plaintext.UNVERIFIED_BASIS in a.notes


def test_an_encrypted_listener_is_untouched_and_an_unlisted_port_does_nothing():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "encrypted")])
    a = listener("9")
    assert plaintext.apply_posture(a, idx, "tcp") == "encrypted"
    assert (a.verdict, a.flags, a.notes) == ("unknown", [], "")
    b = listener("7")
    assert plaintext.apply_posture(b, idx, "tcp") == ""
    assert b.flags == []


def test_accepted_by_necessity_is_flagged_and_explained():
    idx = plaintext.build_index([row("9", "udp", "alpha", "cleartext", "content",
                                     "accepted-by-necessity", "not-frontable-client-configured")])
    a = listener("9")
    plaintext.apply_posture(a, idx, "udp")
    assert "no-encrypted-alternative:alpha" in a.flags
    assert "accepted by necessity" in a.notes
    assert "Fronting does not apply here" in a.notes


def test_a_frontable_service_is_told_how():
    idx = plaintext.build_index([row("9", "tcp", "alpha", "cleartext", "content",
                                     "actionable-by-configuration", "reverse-web-proxy")])
    a = listener("9")
    plaintext.apply_posture(a, idx, "tcp")
    assert "reverse web proxy" in a.notes
    assert "removes the exposure and not the weakness" in a.notes


def test_unresearched_frontability_gives_no_advice():
    assert plaintext.fronting_advice("alpha", "9", "unresearched") == ""
    assert plaintext.fronting_advice("alpha", "9", "not-a-value") == ""


def test_the_flag_families_are_classified_correctly():
    assert not is_informational_flag("plaintext:alpha")
    assert is_informational_flag("cleartext-exposure:content")
    assert is_informational_flag("unverified-encryption:alpha")
    assert is_informational_flag("no-encrypted-alternative:alpha")


def test_an_out_of_band_port_seen_only_on_the_host_is_listener_only():
    idx = plaintext.build_index([row("9", "tcp", "oob-mgmt", "cleartext", "control",
                                     "actionable-by-configuration", "not-frontable-out-of-band")])
    a = listener("9")
    plaintext.apply_posture(a, idx, "tcp", host_listener=True)
    assert plaintext.LISTENER_ONLY in a.flags
    assert "cleartext-exposure:control" not in a.flags
    assert a.verdict == "weak"
    assert "was not measured" in a.notes


def _agent_row() -> CryptoAsset:
    return CryptoAsset(name="svc", data_state="in-transit", source="endpoint-agent", port="9",
                       flags=["plaintext:oob-mgmt", "cleartext-exposure:control"],
                       notes="old note service=agent-example", extra={"service": "9/tcp"})


def test_no_listener_source_is_registered_by_default(monkeypatch):
    monkeypatch.setattr(plaintext, "HOST_LISTENER_SOURCES", {})
    idx = plaintext.build_index([row("9", "tcp", "oob-mgmt", "cleartext", "control",
                                     "actionable-by-configuration", "not-frontable-out-of-band")])
    assert plaintext.rederive_host_listeners([_agent_row()], idx) == 0


def test_host_listener_rows_are_re_derived_once(monkeypatch):
    monkeypatch.setattr(plaintext, "HOST_LISTENER_SOURCES", {})
    plaintext.register_host_listener_source("endpoint-agent", "service=")
    idx = plaintext.build_index([row("9", "tcp", "oob-mgmt", "cleartext", "control",
                                     "actionable-by-configuration", "not-frontable-out-of-band")])
    a = _agent_row()
    assert plaintext.rederive_host_listeners([a], idx) == 1
    assert plaintext.LISTENER_ONLY in a.flags
    assert "cleartext-exposure:control" not in a.flags
    assert a.notes.endswith("service=agent-example")
    assert plaintext.rederive_host_listeners([a], idx) == 0


# ── the shipped table ──

def test_the_shipped_table_loads_and_covers_common_ports(port_table):
    for key in ("23/tcp", "80/tcp", "443/tcp", "22/tcp", "25/tcp", "53/udp"):
        assert key in port_table, key


def test_every_shipped_cleartext_row_is_fully_classified(port_table):
    rows = {k: r for k, r in port_table.items() if "/" in k}
    for key, r in rows.items():
        assert r["notes"], key
        if r["posture"] == plaintext.CLEARTEXT:
            assert r["exposure"] in plaintext.VALID_EXPOSURES, key
            assert r["remediability"] in plaintext.VALID_REMEDIABILITIES, key
            assert r["frontable"] in plaintext.VALID_FRONTABILITIES, key
        else:
            assert r["exposure"] == "n/a", key
            assert r["remediability"] == "n/a", key


def test_no_shipped_row_is_both_unavoidable_and_frontable(port_table):
    for key, r in port_table.items():
        if r.get("remediability") == plaintext.ACCEPTED_BY_NECESSITY:
            assert r["frontable"] not in plaintext.FRONTABLE_POSITIVE, key
