"""The authorisation gates every active probe passes before contacting anything."""

from __future__ import annotations

import pytest
from probe_helpers import AUTH, target

from takestock import inside_scope
from takestock.inside_scope import InsideRefused

# ── the general stanza ──

def test_a_complete_stanza_authorises():
    assert inside_scope.scan_authorisation_problems(target()) == []
    assert inside_scope.scan_refusal("tls_scan", target()) == ""


def test_no_stanza_is_refused():
    problems = inside_scope.scan_authorisation_problems(target(authorised=False))
    assert problems == ["no `authorisation:` stanza in the target profile"]
    line = inside_scope.scan_refusal("tls_scan", target(authorised=False))
    assert line.startswith("tls_scan: REFUSED, nothing contacted")


@pytest.mark.parametrize("missing", ["scope", "authorised_by", "date"])
def test_every_field_is_required(missing):
    t = target()
    t["authorisation"][missing] = "  "
    assert inside_scope.scan_authorisation_problems(t) == [
        f"`authorisation.{missing}` is missing or empty"]


def test_a_stanza_that_is_not_a_mapping_is_refused():
    t = target()
    t["authorisation"] = "yes"
    assert inside_scope.scan_authorisation_problems(t)


# ── the per-probe record for inside probes ──

def test_an_undeclared_group_is_inert_and_checks_nothing():
    assert inside_scope.entries(target(authorised=False), "smb_445") == []


def test_a_declared_group_needs_its_own_record():
    t = target(smb_445=["files-01.example.test"])
    with pytest.raises(InsideRefused, match=r"no `authorisation.smb_445:` record"):
        inside_scope.entries(t, "smb_445")


def test_an_empty_declaration_still_needs_its_record():
    with pytest.raises(InsideRefused):
        inside_scope.entries(target(smb_445=[]), "smb_445")


def test_the_general_stanza_is_checked_before_the_record():
    t = target(authorised=False, smb_445=["files-01.example.test"])
    t["authorisation"] = {"smb_445": dict(AUTH)}
    with pytest.raises(InsideRefused, match=r"`authorisation.scope`"):
        inside_scope.entries(t, "smb_445")


def test_a_record_missing_a_field_is_refused():
    t = target(extra_auth={"smb_445": {**AUTH, "date": ""}}, smb_445=["files-01.example.test"])
    with pytest.raises(InsideRefused, match=r"authorisation.smb_445.date"):
        inside_scope.entries(t, "smb_445")


def test_a_complete_record_returns_the_entries():
    t = target(extra_auth={"smb_445": dict(AUTH)}, smb_445=["files-01.example.test"])
    assert inside_scope.entries(t, "smb_445") == ["files-01.example.test"]


def test_a_group_that_is_not_a_list_is_refused():
    t = target(extra_auth={"smb_445": dict(AUTH)}, smb_445="files-01.example.test")
    with pytest.raises(InsideRefused, match="must be a list"):
        inside_scope.entries(t, "smb_445")


# ── one named host at a time ──

@pytest.mark.parametrize("host", ["files-01.example.test", "192.0.2.10", "2001:db8::10",
                                  "[2001:db8::10]", "files-01"])
def test_one_named_host_or_address_passes(host):
    assert inside_scope.host_problem(host) == ""


@pytest.mark.parametrize("host", ["192.0.2.0/24", "192.0.2.1-192.0.2.9", "192.0.2.1-9",
                                  "*.example.test", "a.example.test,b.example.test",
                                  "a.example.test b.example.test", ""])
def test_anything_else_is_refused(host):
    assert inside_scope.host_problem(host)


def test_a_bad_name_cannot_hide_behind_a_good_address():
    with pytest.raises(InsideRefused):
        inside_scope.entry_address({"host": "*.example.test", "ip": "192.0.2.10"}, "entry")


def test_an_entry_gives_the_address_to_probe_and_the_name_to_report():
    assert inside_scope.entry_address({"host": "files-01.example.test", "ip": "192.0.2.10"},
                                      "entry") == ("192.0.2.10", "files-01.example.test")
    assert inside_scope.entry_address("files-01.example.test", "entry") == (
        "files-01.example.test", "files-01.example.test")


def test_a_non_string_entry_is_refused():
    with pytest.raises(InsideRefused):
        inside_scope.entry_address(42, "entry")
    with pytest.raises(InsideRefused, match="names no host"):
        inside_scope.entry_address({}, "entry")


def test_duplicates_are_compared_case_blind_and_without_brackets():
    with pytest.raises(InsideRefused, match="twice"):
        inside_scope.check_unique([("Files-01.example.test",), ("files-01.EXAMPLE.test",)], "g")
    with pytest.raises(InsideRefused, match="twice"):
        inside_scope.check_unique([("[2001:db8::10]", 22), ("2001:db8::10", 22)], "g")
    inside_scope.check_unique([("2001:db8::10", 22), ("2001:db8::10", 2222)], "g")


def test_a_ceiling_refuses_rather_than_truncates():
    inside_scope.check_ceiling(inside_scope.MAX_HOSTS, inside_scope.MAX_HOSTS, "g")
    with pytest.raises(InsideRefused, match="REFUSED rather than truncated"):
        inside_scope.check_ceiling(inside_scope.MAX_HOSTS + 1, inside_scope.MAX_HOSTS, "g")
