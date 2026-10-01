"""Evidence depth: which rung of the ladder a row's evidence reaches."""

from __future__ import annotations

from dataclasses import asdict

import pytest

from takestock import depth
from takestock.model import CryptoAsset


def _asset(**kw) -> CryptoAsset:
    return CryptoAsset(name="row", data_state="in-transit", host="web-01.example.test", **kw)


@pytest.fixture(autouse=True)
def _clean_registry(monkeypatch):
    monkeypatch.setattr(depth, "_registered", {name: [] for name in depth._RUNG_NAMES})
    monkeypatch.setattr(depth, "_convention", [])


def test_a_bare_listener_only_exists():
    assert depth.classify(_asset()) == depth.EXISTS


def test_a_port_convention_reaches_posture_and_says_so():
    row = _asset(flags=["plaintext:telnet"])
    assert depth.classify(row) == depth.POSTURE
    assert depth.by_convention(row)
    assert not depth.by_convention(_asset(verdict="weak"))


def test_a_graded_verdict_alone_reaches_posture():
    assert depth.classify(_asset(verdict="acceptable")) == depth.POSTURE


def test_recorded_primitives_reach_strength():
    assert depth.classify(_asset(protocol_versions=["TLSv1.3"])) == depth.STRENGTH


def test_a_key_of_its_own_reaches_key():
    assert depth.classify(_asset(extra={"pubkey": {"type": "RSA"}})) == depth.KEY
    assert depth.classify(_asset(flags=["weak-key-1024"])) == depth.KEY


def test_key_management_is_the_deepest_rung():
    row = _asset(flags=["renewal-overdue", "weak-key-1024"], protocol_versions=["TLSv1.2"])
    assert depth.classify(row) == depth.KEY_MANAGEMENT


def test_no_cryptography_is_outside_the_ladder():
    assert depth.classify(_asset(verdict="n/a")) == depth.NOT_APPLICABLE


def test_a_bare_prefix_carries_nothing():
    assert depth.classify(_asset(flags=["plaintext:"])) == depth.EXISTS


def test_a_registered_flag_lifts_and_an_unanswered_one_never_does():
    depth.register_flags(depth.KEY_MANAGEMENT, "rotation-recorded")
    depth.register_flags("unanswered", "rotation-unknown:")
    depth.register_flags(depth.KEY_MANAGEMENT, "rotation-unknown:")
    assert depth.classify(_asset(flags=["rotation-recorded"])) == depth.KEY_MANAGEMENT
    assert depth.classify(_asset(flags=["rotation-unknown:vault"])) == depth.EXISTS
    with pytest.raises(ValueError):
        depth.register_flags("deep", "x")
    with pytest.raises(ValueError):
        depth.register_flags(depth.KEY, "")


def test_a_registered_convention_flag_is_marked_as_one():
    depth.register_flags(depth.POSTURE, "port-guess:", convention=True)
    row = _asset(flags=["port-guess:ftp"])
    assert depth.classify(row) == depth.POSTURE and depth.by_convention(row)


def test_an_object_and_its_json_row_classify_alike():
    row = _asset(flags=["unverified-encryption:imap"], extra={"not_after": "2031-01-01"})
    assert depth.classify(row) == depth.classify(asdict(row)) == depth.KEY


def test_summary_excludes_rows_with_nothing_to_grade():
    rows = depth.stamp([_asset(), _asset(flags=["plaintext:ftp"]), _asset(verdict="weak"),
                        _asset(protocol_versions=["TLSv1.2"]), _asset(verdict="n/a")])
    s = depth.summarise(rows)
    assert (s["total"], s["population"], s["not_applicable"]) == (5, 4, 1)
    assert (s["posture_by_convention"], s["posture_by_record"], s["unmeasured"]) == (1, 1, 1)
    assert s["recorded_cryptography"] == 1 and s["recorded_share"] == 0.25
    assert "Of the 4 items" in s["sentence"]
    assert s["assurance_sentence"].startswith("No item")


def test_an_empty_population_says_nothing():
    s = depth.summarise([_asset(verdict="n/a")])
    assert s["sentence"] == "" and s["assurance_sentence"] == "" and s["recorded_share"] is None


def test_the_ladder_and_its_words_stay_in_step():
    assert set(depth.LADDER) | {depth.NOT_APPLICABLE} == set(depth.ORDER)
    assert set(depth.LABEL) == set(depth.MEANS) == set(depth.ORDER)
