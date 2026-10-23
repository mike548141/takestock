"""The Microsoft Entra application credential reader in takestock's readers library.

The credential, application and permission CSVs are composed in each test
(``entra_helpers``) in the columns ``docs/COLLECTORS.md`` gives, with
synthetic application names and IDs. The reference time is 2030-06-30.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import by_name, ctx, guid, write

from takestock import coverage, plugin_kinds, roles
from takestock.readers import entra_app_credentials as eac
from takestock.readers import library

CRED_COLUMNS = ("AppDisplayName", "AppId", "CredentialType", "CredentialOwner",
                "CredentialDisplayName", "StartDateTimeUtc", "EndDateTimeUtc",
                "PermissionsOfInterest")
APP_COLUMNS = ("AppDisplayName", "AppId", "ApplicationCreatedDateUtc",
               "ServicePrincipalCreatedDateUtc", "PermissionsOfInterest")
PERM_COLUMNS = ("AppId", "PermissionValue", "ResourceName")


def _cred(app: int, kind: str, start: str, end: str, label: str = "", perms: str = "") -> dict:
    return {"AppDisplayName": f"Example App {app}", "AppId": guid(60 + app),
            "CredentialType": kind, "CredentialDisplayName": label, "StartDateTimeUtc": start,
            "EndDateTimeUtc": end, "PermissionsOfInterest": perms}


def _files(tmp: Path) -> tuple[Path, dict]:
    creds = write(tmp / "credentials.csv", CRED_COLUMNS, [
        _cred(1, "Password", "2030-01-02T03:04:05Z", "2031-01-02T03:04:05Z",
              perms="Group.ReadWrite.All"),
        _cred(2, "Password", "2025-12-31T21:43:10Z", "2030-01-03T05:06:07Z",
              perms="Application.ReadWrite.All"),
        _cred(3, "Certificate", "2030-01-02T03:04:05Z", "2199-06-15T07:08:09Z"),
        _cred(4, "Certificate", "2029-02-03T04:05:06Z", "2031-02-03T04:05:06Z",
              label="CN=example-shared"),
        _cred(5, "Certificate", "2029-02-03T04:05:06Z", "2031-02-03T04:05:06Z",
              label="CN=example-shared"),
        _cred(6, "Password", "not a date", "2031-02-03T04:05:06Z"),
    ])
    apps = write(tmp / "applications.csv", APP_COLUMNS, [
        {"AppDisplayName": "Example App 1", "AppId": guid(61)},
        {"AppDisplayName": "Example Vendor App", "AppId": guid(67),
         "ServicePrincipalCreatedDateUtc": "2030-01-02T03:04:05Z",
         "PermissionsOfInterest": "AppRoleAssignment.ReadWrite.All"},
        {"AppDisplayName": "Example Local App", "AppId": guid(68),
         "ApplicationCreatedDateUtc": "2030-01-02T03:04:05Z",
         "ServicePrincipalCreatedDateUtc": "2030-01-02T03:04:05Z"},
    ])
    perms = write(tmp / "permissions.csv", PERM_COLUMNS, [
        {"AppId": guid(61), "PermissionValue": "Group.ReadWrite.All",
         "ResourceName": "Microsoft Graph"},
    ])
    return creds, {"applications": str(apps), "permissions": str(perms)}


def _run(tmp: Path, **settings: str):
    creds, s = _files(tmp)
    return eac.step(ctx(eac.PLUGIN, creds, {**s, **settings}))


def test_the_reader_is_in_the_library():
    assert library()["entra_app_credentials"] is eac.PLUGIN


def test_lifetimes_and_flags(tmp_path):
    result = _run(tmp_path)
    rows = by_name(result.records)
    one = rows[f"application secret — Example App 1 [{guid(61)[:8]}]"]
    assert (one.verdict, one.flags) == ("acceptable", ["credential-key-unknown",
                                                       "credential-shared-secret"])
    assert one.extra["permission_detail"] == ["Group.ReadWrite.All on Microsoft Graph"]
    assert one.extra["valid_from"] == "2030-01-02T03:04:05+00:00"
    assert one.role == roles.application_credential("secret")
    two = rows[f"application secret — Example App 2 [{guid(62)[:8]}]"]
    assert two.verdict == "weak"
    assert two.flags == ["credential-expired", "credential-key-unknown",
                         "credential-lifetime-excessive:4y",
                         "credential-minting-permission:Application.ReadWrite.All",
                         "credential-shared-secret", "credential-unrotated:4y"]
    three = rows[f"application certificate — Example App 3 [{guid(63)[:8]}]"]
    assert "credential-never-expires" in three.flags and three.verdict == "weak"
    six = rows[f"application secret — Example App 6 [{guid(66)[:8]}]"]
    assert six.verdict == "unknown" and "credential-date-unreadable" in six.flags
    for row in result.records:
        assert plugin_kinds.check_asset("general", row) == []
    assert [coverage.kind_of(g) for g in result.gaps] == [coverage.COULD_NOT_TEST] * 2


def test_a_shared_certificate(tmp_path):
    rows = by_name(_run(tmp_path).records)
    four = rows[f"application certificate — Example App 4 [{guid(64)[:8]}]"]
    assert "shared-credential:2" in four.flags
    assert four.extra["shared_credential_apps"] == [guid(65)]


def test_applications_with_no_credential(tmp_path):
    rows = by_name(_run(tmp_path).records)
    vendor = rows[f"application with no visible credential — Example Vendor App "
                  f"[{guid(67)[:8]}]"]
    assert vendor.flags == ["credential-held-by-publisher",
                            "credential-minting-permission:AppRoleAssignment.ReadWrite.All"]
    local = rows[f"application with no visible credential — Example Local App [{guid(68)[:8]}]"]
    assert local.flags == ["credentials-not-visible"]
    assert f"application with no visible credential — Example App 1 [{guid(61)[:8]}]" not in rows


def test_scope_and_the_directory_write_setting(tmp_path):
    scope = by_name(_run(tmp_path).records)["Application credential scope"]
    assert scope.flags == []
    assert scope.extra == {"applications": "8", "credentials": "6", "passwords": "3",
                           "certificates": "3"}
    rows = by_name(_run(tmp_path, scope="directory-write").records)
    assert rows["Application credential scope"].flags == ["scope-directory-write-only"]
    one = rows[f"application secret — Example App 1 [{guid(61)[:8]}]"]
    assert one.role == roles.application_credential("secret", True)


def test_a_date_format_setting(tmp_path):
    creds = write(tmp_path / "c.csv", CRED_COLUMNS, [
        _cred(1, "Password", "8/07/2030 1:02:03 am", "8/07/2031 4:05:06 pm")])
    row = eac.step(ctx(eac.PLUGIN, creds, {"date_format": "%d/%m/%Y %I:%M:%S %p"})).records[0]
    # Day first: 8 July, not 7 August.
    assert row.extra["valid_from"] == "2030-07-08T01:02:03+00:00"
    assert row.extra["valid_to"] == "2031-07-08T16:05:06+00:00"
    # Without the setting the same dates are unreadable, never guessed.
    result = eac.step(ctx(eac.PLUGIN, creds))
    assert "credential-date-unreadable" in result.records[0].flags
    assert "2 application credential date(s)" in result.gaps[1]


def test_nothing_given():
    result = eac.step(ctx(eac.PLUGIN, None))
    assert result.records == [] and "no input was given" in result.gaps[0]
