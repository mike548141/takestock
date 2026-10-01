"""SMB dialects and signing on named internal hosts."""

from __future__ import annotations

import pytest
from probe_helpers import AUTH, FakeRun, has, never_run, target

from takestock.collectors import smb_scan
from takestock.model import is_informational_flag

# nmap output composed from the three scripts' documented @output blocks
# (smb-protocols, smb2-security-mode, smb-security-mode), with a
# documentation address.
HEAD = "Nmap scan report for 192.0.2.45\nHost is up (0.0010s latency).\n\nPORT    STATE SERVICE\n"

SMB1_AND_SMB2_NOT_REQUIRED = HEAD + """\
445/tcp open  microsoft-ds

Host script results:
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.11:
|_    Message signing enabled but not required
"""

SMB3_REQUIRED = HEAD + """\
445/tcp open  microsoft-ds

Host script results:
| smb-protocols:
|   dialects:
|     3.00
|     3.02
|_    3.11
| smb2-security-mode:
|   3.11:
|_    Message signing enabled and required
"""

SMB2_DISABLED = SMB3_REQUIRED.replace("Message signing enabled and required",
                                      "Message signing is disabled and not required!")

SMB1_ONLY_NO_READING = HEAD + """\
445/tcp open  microsoft-ds

Host script results:
| smb-protocols:
|   dialects:
|_    NT LM 0.12 (SMBv1) [dangerous, but default]
"""

SMB1_SHARE_LEVEL = SMB1_ONLY_NO_READING + """\
| smb-security-mode:
|   authentication_level: share (dangerous)
|   challenge_response: plaintext-only (dangerous)
|_  message_signing: disabled (dangerous, but default)
"""

OPEN_NOT_SMB = HEAD + "445/tcp open  microsoft-ds\n"
CLOSED = HEAD + "445/tcp closed microsoft-ds\n"
FILTERED = HEAD + "445/tcp filtered microsoft-ds\n"


def rows(out: str) -> dict:
    return {a.name.split(" 192")[0]: a
            for a in smb_scan.assets_from_scan("192.0.2.45", smb_scan.parse_nmap(out), "2030-01-31")}


def smb_target(hosts: list, authorised: bool = True) -> dict:
    extra = {"smb_445": dict(AUTH)} if authorised else {}
    return target(extra_auth=extra, smb_445=hosts)


def test_smb1_and_smb2_with_signing_not_required(policy):
    r = rows(SMB1_AND_SMB2_NOT_REQUIRED)
    dialects, signing = r["SMB dialects"], r["SMB signing"]
    assert dialects.protocol_versions == ["SMB1", "SMB2.0.2", "SMB2.1", "SMB3.0", "SMB3.0.2",
                                          "SMB3.1.1"]
    policy.apply(dialects)
    assert dialects.verdict == "weak"
    assert "deprecated-protocol:SMB1" in dialects.flags
    # SMB1 says disabled, SMB2 says not required: graded on the weaker.
    assert signing.verdict == "weak"
    assert smb_scan.SIGNING_DISABLED in signing.flags
    assert "graded on the weakest" in signing.notes


def test_smb3_only_with_signing_required(policy):
    r = rows(SMB3_REQUIRED)
    assert r["SMB signing"].verdict == "acceptable"
    assert r["SMB signing"].flags == []
    policy.apply(r["SMB dialects"])
    assert r["SMB dialects"].verdict == "acceptable"


def test_signing_disabled_on_smb2_is_weak():
    assert rows(SMB2_DISABLED)["SMB signing"].verdict == "weak"


def test_smb1_with_no_signing_reading_leaves_signing_unknown():
    signing = rows(SMB1_ONLY_NO_READING)["SMB signing"]
    assert signing.verdict == "unknown"
    assert smb_scan.SIGNING_NOT_READ in signing.flags


def test_share_level_and_plaintext_only_smb1_are_recorded():
    signing = rows(SMB1_SHARE_LEVEL)["SMB signing"]
    assert signing.verdict == "weak"
    assert "share-level authentication" in signing.notes
    assert "passwords sent in plaintext" in signing.notes


@pytest.mark.parametrize(("out", "verdict", "flag"), [
    (OPEN_NOT_SMB, "unknown", smb_scan.NO_NEGOTIATION),
    (CLOSED, "n/a", smb_scan.NOT_LISTENING),
    (FILTERED, "unknown", smb_scan.UNREACHED),
    ("Failed to resolve \"files-09.example.test\".\n", "unknown", smb_scan.UNREACHED),
])
def test_anything_short_of_a_negotiation_is_explained(out, verdict, flag):
    [a] = rows(out).values()
    assert (a.verdict, a.flags) == (verdict, [flag])
    assert is_informational_flag(flag)


def test_every_signing_sentence_maps():
    for sentence in ("Message signing enabled and required",
                     "Message signing enabled but not required",
                     "Message signing is disabled and not required!",
                     "Message signing is disabled!"):
        assert smb_scan.signing_state(sentence)
    for value in ("required", "supported", "disabled (dangerous, but default)"):
        assert smb_scan.smb1_signing_state(value)


def test_an_unknown_dialect_is_kept_visibly():
    assert smb_scan.dialect_token("4.00") == "SMB?4.00"


def test_an_authorised_run_sends_the_declared_command(monkeypatch, tmp_path):
    fake = FakeRun([(has("192.0.2.45"), SMB3_REQUIRED)])
    monkeypatch.setattr(smb_scan, "run", fake)
    monkeypatch.setattr(smb_scan.shutil, "which", lambda name: "/usr/bin/nmap")
    said: list[str] = []
    assets, failures = smb_scan.collect(
        smb_target([{"host": "files-01.example.test", "ip": "192.0.2.45"}]),
        raw_dir=tmp_path, announce=said.append)
    assert failures == []
    assert fake.calls == [["nmap", *smb_scan.NMAP_FLAGS, "-p", "445", "--script",
                           smb_scan.NMAP_SCRIPTS, "192.0.2.45"]]
    assert [a.name for a in assets] == ["SMB dialects 192.0.2.45:445", "SMB signing 192.0.2.45:445"]
    assert all(a.internet_facing is False for a in assets)
    assert said[0].startswith("[smb_scan] probe budget")
    assert (tmp_path / "nmap-smb-budget.txt").exists()


def test_inert_without_the_key(monkeypatch):
    monkeypatch.setattr(smb_scan, "run", never_run)
    assert smb_scan.collect(target()) == ([], [])


def test_refused_without_its_own_record(monkeypatch):
    monkeypatch.setattr(smb_scan, "run", never_run)
    assets, failures = smb_scan.collect(smb_target(["192.0.2.45"], authorised=False))
    assert assets == [] and "authorisation.smb_445" in failures[0]


@pytest.mark.parametrize("hosts", [["192.0.2.0/24"], ["192.0.2.45", "192.0.2.45"],
                                   [f"192.0.2.{n}" for n in range(1, 62)]])
def test_ranges_duplicates_and_long_lists_are_refused(monkeypatch, hosts):
    monkeypatch.setattr(smb_scan, "run", never_run)
    assets, failures = smb_scan.collect(smb_target(hosts), announce=lambda _l: None)
    assert assets == [] and "REFUSED, nothing contacted" in failures[0]


def test_missing_nmap_is_an_explicit_unknown(monkeypatch):
    monkeypatch.setattr(smb_scan, "run", never_run)
    monkeypatch.setattr(smb_scan.shutil, "which", lambda name: None)
    [a], failures = smb_scan.collect(smb_target(["192.0.2.45"]), announce=lambda _l: None)
    assert (a.verdict, a.flags, failures) == ("unknown", [smb_scan.SCAN_NOT_RUN], [])
