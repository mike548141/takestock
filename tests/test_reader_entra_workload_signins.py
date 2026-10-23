"""The Microsoft Entra application, managed identity and non-interactive sign-in reader.

The three sign-in logs and the credential export are composed in each test
(``entra_helpers``), with synthetic application names, IDs and dates.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import SERVICE_COLUMNS, SIGNIN_COLUMNS, by_name, ctx, guid, write

from takestock import coverage, plugin_kinds
from takestock.readers import entra_workload_signins as ews
from takestock.readers import library


def _sp(n: int, app: int, *, key: str = "", thumb: str = "", **kw: str) -> dict:
    row = {"Date (UTC)": f"2030-03-0{1 + n % 3}T10:00:{n % 60:02d}Z", "Request ID": guid(n),
           "Service principal ID": guid(50 + app), "Service principal name": f"Example App {app}",
           "Application ID": guid(70 + app), "Resource": "Microsoft Graph",
           "Status": "Success", "Credential key ID": key, "Credential thumbprint": thumb,
           "Conditional Access": "Not Applied"}
    row.update(kw)
    return row


def _logs(tmp: Path) -> dict[str, Path]:
    sp = [_sp(1, 1, key=guid(81)), _sp(2, 1, key=guid(81)), _sp(3, 1, key=guid(82),
                                                                 thumb="AB" * 20),
          _sp(4, 2, key=guid(83), thumb="CD" * 20), _sp(5, 3, Status="Failure"),
          _sp(6, 4, key=guid(84))]
    mi = [_sp(10 + i, 9, Resource="Azure Key Vault" if i % 2 else "Azure Storage")
          for i in range(4)]
    ni = [{"Date (UTC)": f"2030-03-02T11:00:{i:02d}Z", "Request ID": guid(90 + i),
           "Username": f"user-{i % 2:02d}@example.test", "Application": "Example Sync",
           "Application ID ": guid(95), "Status": "Success", "Client app": "Browser",
           "Client credential type": "clientSecret" if i < 3 else "clientAssertion",
           "Conditional Access": "Success"} for i in range(5)]
    creds = write(tmp / "credentials.csv", ("AppId", "KeyId", "CredentialType"), [
        {"AppId": guid(71), "KeyId": guid(81), "CredentialType": "Password"},
        {"AppId": guid(72), "KeyId": guid(83), "CredentialType": "Certificate"},
        {"AppId": guid(74), "KeyId": guid(84), "CredentialType": "Certificate"},
    ])
    return {"sp": write(tmp / "application-signins.csv", SERVICE_COLUMNS, sp),
            "mi": write(tmp / "managed-identity-signins.csv", SERVICE_COLUMNS, mi),
            "ni": write(tmp / "noninteractive-signins.csv", SIGNIN_COLUMNS, ni),
            "creds": creds}


def _run(tmp: Path):
    p = _logs(tmp)
    return ews.step(ctx(ews.PLUGIN, p["sp"], {"managed_identities": str(p["mi"]),
                                              "noninteractive": str(p["ni"]),
                                              "app_credentials": str(p["creds"])}))


def test_the_reader_is_in_the_library():
    assert library()["entra_workload_signins"] is ews.PLUGIN


def test_applications_signing_in_with_a_secret(tmp_path):
    result = _run(tmp_path)
    assert result.gaps == []
    rows = by_name(result.records)
    one = rows[f"application signing in with a secret — Example App 1 [{guid(71)[:8]}]"]
    assert (one.verdict, one.flags) == ("unknown", ["workload-signin-secret:2",
                                                    "workload-signin-certificate:1"])
    assert (one.hosts_count, one.usage_count) == (2, 3)
    assert one.extra["application_id_prefix"] == "00000000"
    four = rows[f"application signing in with a secret — Example App 4 [{guid(74)[:8]}]"]
    assert four.flags == ["workload-signin-secret:1"]
    assert not [n for n in rows if "Example App 2" in n or "Example App 3" in n]
    for row in result.records:
        assert plugin_kinds.check_asset("general", row) == []


def test_the_secret_reading_is_checked_against_the_credential_export(tmp_path):
    scope = by_name(_run(tmp_path).records)["Application sign-in evidence scope"]
    # Key 81 agrees (a secret), 83 agrees (a certificate), 84 disagrees.
    assert (scope.extra["inference_agrees"], scope.extra["inference_disagrees"]) == ("2", "1")
    assert scope.extra["applications_no_credential"] == "1"
    assert scope.extra["failed"] == "1"
    assert "None of these sign-ins had a Conditional Access policy in scope." in scope.notes


def test_managed_identities_are_counted(tmp_path):
    mi = by_name(_run(tmp_path).records)["Managed identity sign-in evidence scope"]
    assert mi.verdict == "n/a"
    assert "workload-managed-identities:1" in mi.flags
    assert mi.extra["resources"] == "2"


def test_non_interactive_sign_ins(tmp_path):
    rows = by_name(_run(tmp_path).records)
    sync = rows[f"application acting for people with a secret — Example Sync [{guid(95)[:8]}]"]
    assert sync.flags == ["delegated-client-secret:3"]
    assert sync.hosts_count == 2
    client = rows["Legacy mail and client protocols — non-interactive sign-ins"]
    assert (client.verdict, client.flags) == ("n/a", ["signin-legacy-client-none"])
    scope = rows["Non-interactive sign-in evidence scope"]
    assert scope.extra["credential_clientsecret"] == "3"
    assert scope.extra["secret_applications"] == "1"


def test_each_log_missing_is_its_own_gap(tmp_path):
    result = ews.step(ctx(ews.PLUGIN, None))
    assert result.records == []
    assert len(result.gaps) == 3
    assert all(coverage.kind_of(g) == coverage.NOT_COLLECTED for g in result.gaps)
    assert "none was named as the reader's input" in result.gaps[0]
