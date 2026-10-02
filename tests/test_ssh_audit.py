"""SSH algorithm audit: outside, inside in batches, and supplied ssh-audit exports."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from probe_helpers import AUTH, FakeRun, fixture, has, never_run, target

from takestock import coverage
from takestock.collectors import ssh_audit
from takestock.collectors.ssh_audit import InsideHost
from takestock.util import split_host_port

WHEN = datetime(2030, 1, 31, tzinfo=UTC)

# Composed by hand in the shape of ssh-audit's ``-jj`` JSON output (ssh-audit
# is not installed where these tests were written).
STRONG = {
    "banner": {"protocol": "2.0", "software": "OpenSSH_9.6", "raw": "SSH-2.0-OpenSSH_9.6"},
    "target": "203.0.113.22:22",
    "kex": [{"algorithm": "mlkem768x25519-sha256"}, {"algorithm": "curve25519-sha256"}],
    "key": [{"algorithm": "ssh-ed25519", "keysize": 256}],
    "enc": [{"algorithm": "chacha20-poly1305@openssh.com"},
            {"algorithm": "aes256-gcm@openssh.com"}],
    "mac": [{"algorithm": "hmac-sha2-256-etm@openssh.com"}],
}
WEAK = {
    "banner": {"protocol": "2.0", "software": "ExampleSSH_1.0", "raw": "SSH-2.0-ExampleSSH_1.0"},
    "target": "[2001:db8::22]:2222",
    "kex": [{"algorithm": "diffie-hellman-group1-sha1"}],
    "key": [{"algorithm": "ssh-dss", "keysize": 1024}],
    "enc": [{"algorithm": "3des-cbc"}, "aes128-cbc"],
    "mac": [{"algorithm": "hmac-md5"}],
}


def inside_target(entries: list, authorised: bool = True) -> dict:
    extra = {"ssh_inside": dict(AUTH)} if authorised else {}
    return target(extra_auth=extra, ssh_inside=entries)


@pytest.fixture()
def no_binary(monkeypatch):
    monkeypatch.delenv(ssh_audit.BINARY_ENV, raising=False)
    monkeypatch.setattr(ssh_audit.shutil, "which",
                        lambda name: "/usr/bin/nmap" if name == "nmap" else None)


# ── reading ssh-audit JSON ──

def test_a_strong_host_is_read_and_grades_strong(policy):
    a = ssh_audit._asset_from_struct(STRONG, "203.0.113.22", "22")
    assert a.extra["ssh_kex"] == ["curve25519-sha256", "mlkem768x25519-sha256"]
    assert a.software == "OpenSSH_9.6"
    policy.apply(a)
    assert a.verdict in ("strong", "pqc")
    assert not any(f.startswith("ungraded:") for f in a.flags)


def test_a_weak_host_grades_weak(policy):
    a = ssh_audit._asset_from_struct(WEAK, "2001:db8::22", "2222")
    assert a.symmetric == ["3des-cbc", "aes128-cbc"]
    policy.apply(a)
    assert a.verdict == "weak"


def test_garbage_is_not_json():
    assert ssh_audit._safe_json("") is None
    assert ssh_audit._safe_json("__ERROR__ missing") is None
    assert ssh_audit._safe_json("[1, 2]") is None
    assert ssh_audit._safe_json('noise {"banner": {}} noise') == {"banner": {}}


def test_missing_keys_and_odd_entries_are_tolerated():
    a = ssh_audit._asset_from_struct({"kex": [None, 7, {"x": 1}], "enc": "nope"}, "h", "22")
    assert a.extra["ssh_kex"] == [] and a.symmetric == []


@pytest.mark.parametrize(("value", "split"), [
    ("203.0.113.22:22", ("203.0.113.22", "22")),
    ("[2001:db8::22]:2222", ("2001:db8::22", "2222")),
    ("2001:db8::22", ("2001:db8::22", "")),
    ("bastion.example.test", ("bastion.example.test", "")),
    ("[2001:db8::22]", ("2001:db8::22", "")),
])
def test_an_export_target_is_split_into_host_and_port(value, split):
    assert split_host_port(value) == split


# ── outside probe ──

def test_with_ssh_audit_each_listener_is_audited(monkeypatch):
    monkeypatch.setenv(ssh_audit.BINARY_ENV, "/opt/ssh-audit")
    fake = FakeRun([(has("/opt/ssh-audit", "203.0.113.22"), json.dumps(STRONG))])
    monkeypatch.setattr(ssh_audit, "run", fake)
    [a], failures = ssh_audit.collect(target(ssh_22=["203.0.113.22"]), ref_time=WHEN)
    assert failures == []
    assert (a.source_class, a.source_name) == ("public", ssh_audit.SOURCE_ACTIVE)
    assert fake.calls == [["/opt/ssh-audit", "-jj", "-p", "22", "203.0.113.22"]]
    assert a.role.startswith("Remote administration access")


@pytest.mark.parametrize(("entry", "probed", "port", "name", "ip"), [
    ("203.0.113.22", "203.0.113.22", "22", "SSH 203.0.113.22:22", ""),
    ("203.0.113.22:2222", "203.0.113.22", "2222", "SSH 203.0.113.22:2222", ""),
    ("bastion.example.test:2222", "bastion.example.test", "2222",
     "SSH bastion.example.test:2222", ""),
    ("[2001:db8::22]:2222", "2001:db8::22", "2222", "SSH 2001:db8::22:2222", ""),
    ("2001:db8::22", "2001:db8::22", "22", "SSH 2001:db8::22:22", ""),
    ({"ip": "203.0.113.22", "port": 2222}, "203.0.113.22", "2222", "SSH 203.0.113.22:2222", ""),
    ({"host": "bastion.example.test"}, "bastion.example.test", "22",
     "SSH bastion.example.test:22", ""),
    ({"host": "bastion.example.test", "ip": "203.0.113.22"}, "203.0.113.22", "22",
     "SSH bastion.example.test:22", "203.0.113.22"),
])
def test_each_entry_form_is_probed_and_named_like_the_other_probes(monkeypatch, entry, probed,
                                                                   port, name, ip):
    monkeypatch.setenv(ssh_audit.BINARY_ENV, "/opt/ssh-audit")
    fake = FakeRun([(has("/opt/ssh-audit"), json.dumps(STRONG))])
    monkeypatch.setattr(ssh_audit, "run", fake)
    [a], _ = ssh_audit.collect(target(ssh_22=[entry]), ref_time=WHEN)
    assert fake.calls == [["/opt/ssh-audit", "-jj", "-p", port, probed]]
    assert (a.name, a.port, a.ip) == (name, port, ip)
    assert a.host == name.removeprefix("SSH ").rsplit(":", 1)[0]


def test_a_named_host_keeps_its_name_without_an_instrument(monkeypatch):
    monkeypatch.delenv(ssh_audit.BINARY_ENV, raising=False)
    monkeypatch.setattr(ssh_audit.shutil, "which", lambda name: None)
    monkeypatch.setattr(ssh_audit, "run", never_run)
    [a], _ = ssh_audit.collect(
        target(ssh_22=[{"host": "bastion.example.test", "ip": "203.0.113.22"}]))
    assert (a.name, a.host, a.ip) == ("SSH bastion.example.test:22", "bastion.example.test",
                                      "203.0.113.22")


def test_a_named_host_keeps_its_name_through_nmap(monkeypatch, no_binary):
    fake = FakeRun([(has("ssh2-enum-algos"), fixture("nmap-ssh2-enum-algos.txt"))])
    monkeypatch.setattr(ssh_audit, "run", fake)
    [a], _ = ssh_audit.collect(
        target(ssh_22=[{"host": "bastion.example.test", "ip": "127.0.0.1", "port": 2222}]))
    assert fake.calls[0][-1] == "127.0.0.1"
    assert (a.name, a.host, a.ip) == ("SSH bastion.example.test:2222", "bastion.example.test",
                                      "127.0.0.1")


def test_unparseable_output_is_an_unknown_placeholder(monkeypatch):
    monkeypatch.setenv(ssh_audit.BINARY_ENV, "/opt/ssh-audit")
    monkeypatch.setattr(ssh_audit, "run", FakeRun([(has("/opt/ssh-audit"), "timeout")]))
    [a], _ = ssh_audit.collect(target(ssh_22=[{"ip": "203.0.113.22", "port": 2222}]))
    assert a.verdict == "unknown" and a.port == "2222"


def test_without_ssh_audit_nmap_reads_the_algorithm_lists(monkeypatch, no_binary, policy):
    monkeypatch.setattr(ssh_audit, "run",
                        FakeRun([(has("ssh2-enum-algos"), fixture("nmap-ssh2-enum-algos.txt"))]))
    [a], failures = ssh_audit.collect(target(ssh_22=[{"ip": "127.0.0.1", "port": 2222}]))
    assert failures == []
    assert a.source_name == ssh_audit.SOURCE_ACTIVE_NMAP
    assert a.internet_facing is True and "ssh_batch" not in a.extra
    assert "ext-info-s" not in a.extra["ssh_kex"]
    assert "ext-info-s" in a.extra["ssh_kex_signals"]
    assert "chacha20-poly1305@openssh.com" in a.symmetric
    assert a.notes.startswith(ssh_audit.NMAP_LIMITS)
    policy.apply(a)
    assert a.verdict == "weak"            # the stub server still offers hmac-sha1


def test_with_neither_instrument_no_probe_is_sent(monkeypatch):
    monkeypatch.delenv(ssh_audit.BINARY_ENV, raising=False)
    monkeypatch.setattr(ssh_audit.shutil, "which", lambda name: None)
    monkeypatch.setattr(ssh_audit, "run", never_run)
    [a], failures = ssh_audit.collect(target(ssh_22=["203.0.113.22"]))
    assert a.verdict == "unknown" and a.source_class == "unknown"
    assert failures == []


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(ssh_audit, "run", never_run)
    assets, failures = ssh_audit.collect(target(authorised=False, ssh_22=["203.0.113.22"]))
    assert assets == [] and failures[0].startswith("ssh_audit: REFUSED")


def test_no_listeners_means_nothing_happens(monkeypatch):
    monkeypatch.setattr(ssh_audit, "run", never_run)
    assert ssh_audit.collect(target(authorised=False)) == ([], [])


# ── nmap ssh2-enum-algos ──

def test_the_captured_algorithm_lists_are_read_completely():
    state, sections, problems = ssh_audit.parse_nmap_ssh2(fixture("nmap-ssh2-enum-algos.txt"))
    assert state == "open"
    assert problems == []
    assert len(sections["kex_algorithms"]) == 10
    assert sections["server_host_key_algorithms"] == ["ssh-ed25519", "rsa-sha2-512",
                                                      "rsa-sha2-256"]


def test_a_short_list_is_reported_as_a_problem():
    text = fixture("nmap-ssh2-enum-algos.txt").replace("|       aes192-ctr\n", "")
    _state, _sections, problems = ssh_audit.parse_nmap_ssh2(text)
    assert problems == ["encryption_algorithms: nmap listed 6, 5 read"]


@pytest.mark.parametrize(("state", "verdict"), [("closed", "n/a"), ("filtered", "unknown")])
def test_a_port_with_no_ssh_is_explained(state, verdict):
    h = InsideHost("192.0.2.22", "22", "one")
    a, failure = ssh_audit.asset_from_nmap(h, f"22/tcp {state} ssh\n")
    assert a is not None and a.verdict == verdict and failure == ""


def test_no_port_table_is_a_failure_not_a_row():
    a, failure = ssh_audit.asset_from_nmap(InsideHost("192.0.2.22", "22", "one"), "nothing")
    assert a is None and "NOT measured" in failure


# ── inside, in batches ──

def test_inside_hosts_run_batch_by_batch(monkeypatch, no_binary):
    fake = FakeRun([(has("ssh2-enum-algos"), fixture("nmap-ssh2-enum-algos.txt"))])
    monkeypatch.setattr(ssh_audit, "run", fake)
    pauses: list[float] = []
    monkeypatch.setattr(ssh_audit, "_settle", pauses.append)
    said: list[str] = []
    entries = [{"host": "build-01.example.test", "ip": "192.0.2.31", "batch": "a"},
               {"host": "build-02.example.test", "ip": "192.0.2.32", "batch": "a"},
               {"host": "db-01.example.test", "ip": "192.0.2.41", "batch": "b", "port": 2222}]
    assets, failures = ssh_audit.collect_inside(inside_target(entries), announce=said.append)
    assert failures == []
    assert [a.extra["ssh_batch"] for a in assets] == ["a", "a", "b"]
    assert [(a.name, a.host, a.ip) for a in assets] == [
        ("SSH build-01.example.test:22", "build-01.example.test", "192.0.2.31"),
        ("SSH build-02.example.test:22", "build-02.example.test", "192.0.2.32"),
        ("SSH db-01.example.test:2222", "db-01.example.test", "192.0.2.41")]
    assert all(a.internet_facing is False and a.source_class == "private" for a in assets)
    assert pauses == [ssh_audit.INTER_HOST_SECONDS, ssh_audit.INTER_BATCH_SECONDS]
    assert said[0].startswith("ssh_audit (inside): PROBE BUDGET")
    assert "      192.0.2.41:2222" in said


def test_inside_is_inert_when_undeclared(monkeypatch):
    monkeypatch.setattr(ssh_audit, "run", never_run)
    assert ssh_audit.collect_inside(target()) == ([], [])


@pytest.mark.parametrize(("entries", "reason"), [
    (["192.0.2.31"], "naming a `host` and a `batch`"),
    ([{"host": "192.0.2.31"}], "names no `batch:`"),
    ([{"host": "192.0.2.0/24", "batch": "a"}], "refused by construction"),
    ([{"host": "192.0.2.31", "batch": "a", "port": "22-25"}], "not one TCP port"),
    ([{"host": "192.0.2.31", "batch": "a"}, {"host": "192.0.2.31", "batch": "b"}], "twice"),
    ([{"host": f"192.0.2.{n}", "batch": str(n)} for n in range(1, 5)], "batches"),
])
def test_inside_refuses_what_it_will_not_run(monkeypatch, entries, reason):
    monkeypatch.setattr(ssh_audit, "run", never_run)
    assets, failures = ssh_audit.collect_inside(inside_target(entries), announce=lambda _l: None)
    assert assets == []
    assert failures[0].startswith("ssh_audit (inside): REFUSED, nothing contacted")
    assert reason in failures[0]


def test_inside_needs_its_own_record(monkeypatch):
    monkeypatch.setattr(ssh_audit, "run", never_run)
    entries = [{"host": "192.0.2.31", "batch": "a"}]
    _assets, failures = ssh_audit.collect_inside(inside_target(entries, authorised=False))
    assert "authorisation.ssh_inside" in failures[0]


# ── supplied exports ──

def test_exports_in_the_inbox_are_read(tmp_path):
    folder = tmp_path / "inbox" / "ssh-audit"
    folder.mkdir(parents=True)
    (folder / "strong.json").write_text(json.dumps(STRONG))
    (folder / "weak.json").write_text(json.dumps(WEAK))
    (folder / "broken.json").write_text("{not json")
    assets, gaps = ssh_audit.collect_inbox({}, tmp_path)
    assert sorted((a.host, a.port) for a in assets) == [("2001:db8::22", "2222"),
                                                        ("203.0.113.22", "22")]
    assert all(a.source_class == "private" and a.collected_at for a in assets)
    [gap] = gaps
    assert gap.kind == coverage.COULD_NOT_TEST and "broken.json" in gap


def test_a_missing_inbox_folder_is_a_gap_not_an_error(tmp_path):
    assets, [gap] = ssh_audit.collect_inbox({}, tmp_path)
    assert assets == []
    assert gap.kind == coverage.NOT_COLLECTED
    assert gap.impact_kind == coverage.CHANGES_CONCLUSION


def test_an_empty_inbox_folder_is_a_gap(tmp_path):
    (tmp_path / "exports").mkdir()
    assets, [gap] = ssh_audit.collect_inbox({"ssh_inbox": {"dir": "exports"}}, tmp_path)
    assert assets == [] and "is empty" in gap
