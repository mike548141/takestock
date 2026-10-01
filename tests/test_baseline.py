"""The bundled baseline is complete, consistent and fully cited."""

from __future__ import annotations

import copy

import pytest

from takestock import citations
from takestock.model import GRADED_VERDICTS
from takestock.policy import Policy

# Every table Policy reads a verdict from.
GRADING_TABLES = ("tls_versions", "key_exchange", "signatures", "symmetric", "hashes", "ssh_hostkey",
                  "ssh_kex", "ssh_mac", "ike_encryption", "ike_dh", "ike_prf", "ssh_cipher",
                  "smb_dialects")


def test_every_grading_table_exists_and_uses_only_the_four_verdicts(baseline):
    for table in GRADING_TABLES:
        assert baseline.get(table), table
        for token, verdict in baseline[table].items():
            assert verdict in GRADED_VERDICTS, (table, token, verdict)


def test_null_is_the_word_not_yaml_null(baseline):
    assert "null" in baseline["symmetric"]
    assert None not in baseline["symmetric"]


def test_ike_groups_are_string_keys(baseline):
    assert all(isinstance(k, str) for k in baseline["ike_dh"])


# One primitive, one verdict: the same group or curve grades the same tier in
# every protocol table it appears in.
SAME_PRIMITIVE = {
    "2048-bit DH": [("key_exchange", "dh_2048"), ("key_exchange", "ffdhe2048"), ("ike_dh", "14"),
                    ("ssh_kex", "diffie-hellman-group14-sha256")],
    "P-256": [("key_exchange", "ecdh_p256"), ("ike_dh", "19"), ("ssh_kex", "ecdh-sha2-nistp256"),
              ("signatures", "ecdsa_p256"), ("ssh_hostkey", "ecdsa-sha2-nistp256")],
    "P-384": [("key_exchange", "ecdh_p384"), ("ike_dh", "20"), ("ssh_kex", "ecdh-sha2-nistp384"),
              ("signatures", "ecdsa_p384"), ("ssh_hostkey", "ecdsa-sha2-nistp384")],
    "P-521": [("key_exchange", "ecdh_p521"), ("ike_dh", "21"), ("ssh_kex", "ecdh-sha2-nistp521")],
    "X25519": [("key_exchange", "x25519"), ("ike_dh", "31"), ("ssh_kex", "curve25519-sha256")],
    "3DES": [("symmetric", "3des"), ("ike_encryption", "3des"), ("ssh_cipher", "3des-cbc")],
}


@pytest.mark.parametrize("primitive", sorted(SAME_PRIMITIVE))
def test_one_primitive_grades_one_way(baseline, primitive):
    verdicts = {baseline[t][k] for t, k in SAME_PRIMITIVE[primitive]}
    assert len(verdicts) == 1, (primitive, verdicts)


def test_symmetric_strengths_are_whole_bits(baseline):
    for token, bits in baseline["symmetric_strength"].items():
        assert isinstance(bits, int) and bits > 0, token


def test_calibration_years_are_read_as_integers(baseline):
    years = citations.calibration_years(baseline)
    assert years == {"signing_and_networking": 2030, "general_infrastructure": 2033,
                     "disallow_quantum_vulnerable": 2035}


def test_every_authority_can_be_cited(baseline):
    for name, entry in baseline["authorities"].items():
        assert entry.get("title") and entry.get("publisher"), name
        assert entry.get("status") in citations.STATUSES, name
        assert citations.authority_line(entry), name


def test_every_citation_resolves(baseline):
    resolved = citations.resolve(baseline)
    for key, cites in resolved.items():
        assert cites, key
        for c in cites:
            assert c["document"], key


def test_every_graded_row_carries_a_citation(baseline):
    resolved = citations.resolve(baseline)
    for table in GRADING_TABLES:
        for token in baseline[table]:
            assert f"{table}/{token}" in resolved, (table, token)


def test_every_cited_token_is_a_real_row(baseline):
    for table, block in baseline["citations"].items():
        for token in block.get("tokens") or {}:
            assert token in baseline[table], (table, token)


def test_every_breach_reading_is_explained(baseline):
    for table, block in baseline["citations"].items():
        for token, cites in (block.get("tokens") or {}).items():
            for c in cites:
                if c.get("breaches"):
                    assert c.get("commentary"), (table, token)


def test_a_breach_cites_a_control_with_a_recorded_level(baseline):
    levels = citations.compliance_index(baseline)
    resolved = citations.resolve(baseline)
    for key, cites in resolved.items():
        for c in cites:
            if c["breaches"]:
                assert (c["authority"], c["control"]) in levels, key
                assert c["compliance"] in citations.BINDING_LEVELS, key


def test_a_conditional_control_carries_its_condition(baseline):
    sha1 = citations.resolve(baseline)["hashes/sha1"]
    nz = [c for c in sha1 if c["authority"] == "nzism"]
    assert nz and nz[0]["condition"]


def test_an_unknown_authority_is_refused(baseline):
    broken = copy.deepcopy(baseline)
    broken["citations"]["tls_versions"]["cites"].append({"authority": "no-such-document"})
    with pytest.raises(citations.UnknownAuthority):
        citations.resolve(broken)


def test_a_breach_without_commentary_is_refused(baseline):
    broken = copy.deepcopy(baseline)
    broken["citations"]["hashes"]["tokens"]["md5"] = [
        {"authority": "nzism", "control": "17.2.26.C.01", "breaches": True}]
    with pytest.raises(citations.UnreasonedBreach):
        citations.resolve(broken)


def test_an_unknown_compliance_level_is_refused(baseline):
    broken = copy.deepcopy(baseline)
    broken["compliance_levels"]["nzism"]["17.2.19.C.01"]["level"] = "ought"
    with pytest.raises(citations.UnknownComplianceLevel):
        citations.compliance_index(broken)


def test_the_payload_ships_only_what_was_used(baseline):
    a = Policy(baseline)
    from takestock.model import CryptoAsset
    asset = a.apply(CryptoAsset(name="t", data_state="in-transit", protocol="tls",
                                protocol_versions=["TLSv1.3"]))
    out = citations.payload(baseline, set(asset.citations))
    assert set(out["cites"]) == {"tls_versions/TLSv1.3"}
    assert "nzism" in out["authorities"]
    assert out["status_notes"]["initial-public-draft"]


# ── NZISM §17.2.13: the AES key-size table is guidance, not a control ──

# Every graded row whose AES key is shorter than the table's 256 bits.
SHORT_AES_ROWS = ("symmetric/aes128_gcm", "symmetric/aes128_ccm", "symmetric/aes128_ccm_8",
                  "symmetric/aes192_cbc", "ike_encryption/aes-gcm-128", "ike_encryption/aes-cbc-128",
                  "ike_encryption/aes-cbc-192", "ssh_cipher/aes128-gcm@openssh.com",
                  "ssh_cipher/aes128-ctr", "ssh_cipher/aes128-cbc", "ssh_cipher/aes192-ctr",
                  "ssh_cipher/aes192-cbc")


def _table_note(cites: list[dict]) -> list[dict]:
    return [c for c in cites if c["authority"] == "nzism" and c["control"] == "§17.2.13"]


@pytest.mark.parametrize("key", SHORT_AES_ROWS)
def test_a_short_aes_key_carries_the_table_as_a_note_not_a_breach(baseline, key):
    cites = citations.resolve(baseline)[key]
    note = _table_note(cites)
    assert len(note) == 1, key
    assert note[0]["breaches"] is False
    assert note[0]["compliance"] == ""
    assert "256-bit" in note[0]["note"] and "not a control" in note[0]["note"]


@pytest.mark.parametrize("key", ["symmetric/aes256_gcm", "ike_encryption/aes-gcm-256",
                                 "ssh_cipher/aes256-ctr"])
def test_a_256_bit_aes_key_carries_no_shortfall_note(baseline, key):
    assert not _table_note(citations.resolve(baseline)[key])


def test_an_aes_128_tls_suite_cites_the_table_and_breaches_nothing(baseline):
    from takestock import dispensation
    from takestock.model import CryptoAsset
    asset = Policy(baseline).apply(CryptoAsset(
        name="t", data_state="in-transit", protocol="tls", host="www.example.test", port="443",
        protocol_versions=["TLSv1.3"], symmetric=["TLS_AES_128_GCM_SHA256"], key_exchange=["x25519"]))
    assert "symmetric/aes128_gcm" in asset.citations
    resolved = citations.resolve(baseline)
    assert _table_note(resolved["symmetric/aes128_gcm"])
    breaches, questions = dispensation.breaches_and_questions(asset, resolved)
    assert breaches == [] and questions == []


def test_marking_a_paragraph_reference_as_breached_is_refused(baseline):
    broken = copy.deepcopy(baseline)
    broken["citations"]["symmetric"]["tokens"]["aes128_gcm"] = [
        {"authority": "nzism", "control": "§17.2.13", "breaches": True,
         "commentary": "Below the table's minimum."}]
    with pytest.raises(citations.UnlevelledBreach):
        citations.resolve(broken)
