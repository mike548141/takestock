"""The Microsoft Entra sign-in authentication details reader in takestock's readers library.

The authentication details downloads are composed in each test
(``entra_helpers``), in the seven columns the download writes, with synthetic
request IDs and dates.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import by_name, ctx, guid, write

from takestock import coverage, plugin_kinds
from takestock.readers import entra_auth_methods, library

COLUMNS = ("Request ID", "Date", "Authentication method", "Authentication method detail",
           "Succeeded", "Result detail", "Requirement")


def _step(n: int, method: str, **kw: str) -> dict:
    row = {"Request ID": guid(n // 2), "Date": f"2030-02-01T09:{n % 60:02d}:00Z",
           "Authentication method": method, "Succeeded": "true",
           "Requirement": "Multifactor authentication"}
    row.update(kw)
    return row


def _details(path: Path) -> Path:
    rows = [_step(1, "Password", **{"Authentication method detail": "Password in the cloud"}),
            _step(2, "FIDO2 security key"),
            _step(3, "Password", **{"Authentication method detail":
                                    "Pass-through Authentication agentid: example-agent-a"}),
            _step(4, "Passkey (device-bound)"),
            _step(5, "Password", **{"Authentication method detail":
                                    "Pass-through Authentication agentid: example-agent-b"}),
            _step(6, "Text message"),
            _step(7, "Mobile app notification", Succeeded="false"),
            _step(8, "Previously satisfied"),
            _step(9, "Previously satisfied"),
            _step(10, "Example future method"),
            _step(11, "Password", **{"Result detail":
                                     "MFA requirement skipped due to app password"})]
    return write(path, COLUMNS, rows)


def test_the_reader_is_in_the_library():
    assert library()["entra_auth_methods"] is entra_auth_methods.PLUGIN


def test_classes():
    c = entra_auth_methods.classify
    assert c("Windows Hello for Business") == "phishing-resistant"
    assert c("Passkey (Microsoft Authenticator)") == "phishing-resistant"
    assert c("Phone call approval (Authentication phone)") == "other-second-factor"
    assert c("Password") == "first-factor"
    assert c("Previously satisfied") == "previously-satisfied"
    assert c("") == "unrecorded"
    assert c("Example future method") == "unclassified"


def test_the_mix_and_the_app_password_row(tmp_path):
    path = _details(tmp_path / "interactive.csv")
    result = entra_auth_methods.step(ctx(entra_auth_methods.PLUGIN, path))
    rows = by_name(result.records)
    mix = rows["Authentication methods used — interactive sign-ins"]
    assert mix.verdict == "n/a"
    assert mix.flags == ["authmethod-phishing-resistant:2", "authmethod-other-second-factor:2",
                         "authmethod-scope-window:2030-02-01..2030-02-01",
                         "authmethod-scope-span:11"]
    assert mix.extra["telephone_steps"] == "1"
    assert mix.extra["previously_satisfied_steps"] == "2"
    assert mix.extra["failed_steps"] == "1"
    assert mix.extra["password_pass_through_steps"] == "2"
    assert mix.extra["pass_through_agents"] == "2"
    assert mix.extra["password_cloud_steps"] == "1"
    assert mix.extra["method_example_future_method"] == "1"
    assert "Example future method 1" in mix.notes
    assert "example-agent" not in mix.notes + str(mix.extra)
    app = rows["App passwords standing in for a second check — interactive sign-ins"]
    assert (app.verdict, app.flags) == ("weak", ["authmethod-app-password:1"])
    for row in result.records:
        assert plugin_kinds.check_asset("general", row) == []
    # No non-interactive details were named: one gap for them.
    assert len(result.gaps) == 1 and "non-interactive" in result.gaps[0]
    assert coverage.kind_of(result.gaps[0]) == coverage.NOT_COLLECTED


def test_both_populations(tmp_path):
    a = _details(tmp_path / "interactive.csv")
    b = _details(tmp_path / "noninteractive.csv")
    result = entra_auth_methods.step(ctx(entra_auth_methods.PLUGIN, a, {"noninteractive": str(b)}))
    assert result.gaps == []
    assert "Authentication methods used — non-interactive sign-ins" in by_name(result.records)


def test_a_download_at_its_limit(tmp_path):
    rows = [_step(i, "Previously satisfied") for i in range(1_000)]
    path = write(tmp_path / "i.csv", COLUMNS, rows)
    mix = entra_auth_methods.step(ctx(entra_auth_methods.PLUGIN, path)).records[0]
    assert "authmethod-scope-ceiling:1000" in mix.flags
    assert mix.extra["window_is_ceiling"] == "yes"


def test_nothing_given(tmp_path):
    result = entra_auth_methods.step(ctx(entra_auth_methods.PLUGIN, None))
    assert result.records == [] and len(result.gaps) == 2
    result = entra_auth_methods.step(ctx(entra_auth_methods.PLUGIN, tmp_path / "missing.csv"))
    assert "missing.csv does not exist" in result.gaps[0]
