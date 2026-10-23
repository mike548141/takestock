"""The Microsoft Entra audit log reader in takestock's readers library.

The audit log downloads are composed in each test (``entra_helpers``), in the
columns the reader reads, with Microsoft's audit activity names and
synthetic accounts, IDs and dates.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import by_name, ctx, guid, write

from takestock import coverage, plugin_kinds
from takestock.readers import entra_audit, library

COLUMNS = ("Date (UTC)", "Category", "Service", "Activity", "Result", "ResultReason",
           "ActorType", "ActorDisplayName", "ActorUserPrincipalName",
           "ActorServicePrincipalName", "Target1Type", "Target1DisplayName",
           "Target1UserPrincipalName", "Target2Type", "Target2DisplayName",
           "Target2UserPrincipalName", "Target1ModifiedProperty1Name",
           "Target1ModifiedProperty1OldValue", "Target1ModifiedProperty1NewValue")


def _role(day: int, activity: str, role: str, user: str, actor: str = "it-admin@example.test",
          **kw: str) -> dict:
    row = {"Date (UTC)": f"2030-04-{day:02d}T12:00:00Z", "Category": "RoleManagement",
           "Service": "Core Directory", "Activity": activity, "Result": "success",
           "ActorType": "User", "ActorUserPrincipalName": actor, "Target1Type": "Role",
           "Target1DisplayName": role, "Target2Type": "User", "Target2UserPrincipalName": user}
    row.update(kw)
    return row


def _failure(day: int, n: int, subject: str = "") -> dict:
    reason = (f"Failed to create User '{subject}' at attempt {n}; Error: example detail {n}"
              if subject else f"Example housekeeping exception {n}")
    return {"Date (UTC)": f"2030-04-{day:02d}T13:{n % 60:02d}:00Z",
            "Category": "ProvisioningManagement", "Service": "Account Provisioning",
            "Activity": "Export" if subject else "Synchronization rule action",
            "Result": "failure", "ResultReason": reason, "ActorType": "Application",
            "ActorDisplayName": "Example provisioning app"}


def _download(tmp: Path) -> Path:
    rows = [
        _role(2, "Add member to role completed (PIM activation)", "Example Administrator",
              "holder-a@example.test"),
        _role(2, "Add member to role", "Example Administrator", "holder-a@example.test",
              actor="", ActorDisplayName="MS-PIM", ActorType="Application"),
        _role(3, "Remove member from role (PIM activation expired)", "Example Administrator",
              "holder-a@example.test", actor="", ActorDisplayName="MS-PIM"),
        _role(4, "Add member to role", "Global Administrator", "holder-b@example.test"),
        # A removal names the role only in the modified property's old value.
        _role(5, "Remove member from role", "", "holder-c@example.test", Target1Type="User",
              Target1DisplayName="", Target1UserPrincipalName="holder-c@example.test",
              Target2Type="", Target2UserPrincipalName="",
              Target1ModifiedProperty1Name="Role.DisplayName",
              Target1ModifiedProperty1OldValue='"Example Reader"'),
        _role(5, "Example future role activity", "Example Reader", "holder-d@example.test"),
    ]
    rows += [_failure(1 + i % 6, i, subject=f"person-{i % 4}@example.test") for i in range(12)]
    rows += [_failure(3, 100 + i) for i in range(4)]
    rows += [{"Date (UTC)": "2030-04-06T00:00:00Z", "Category": "UserManagement",
              "Service": "Core Directory", "Activity": "Update user", "Result": "success"}
             for _ in range(84)]
    return write(tmp / "audit.csv", COLUMNS, rows)


def test_the_reader_is_in_the_library():
    assert library()["entra_audit"] is entra_audit.PLUGIN


def test_role_history(tmp_path):
    result = entra_audit.step(ctx(entra_audit.PLUGIN, _download(tmp_path)))
    rows = by_name(result.records)
    admin = rows["Example Administrator — privilege activation history"]
    assert admin.verdict == "unknown"
    assert admin.flags == ["dirlog-role-activated:1", "dirlog-role-actors:1"]
    assert admin.extra["activations_expired"] == "1"
    top = rows["Global Administrator — privilege activation history"]
    assert (top.verdict, top.flags) == ("weak", ["dirlog-role-activated:0",
                                                 "dirlog-role-actors:1",
                                                 "dirlog-role-granted-standing:1"])
    reader = rows["Example Reader — privilege activation history"]
    assert "dirlog-role-revoked:1" in reader.flags
    assert reader.extra["unclassified_changes"] == "1"
    assert any("Example future role activity (1)" in g for g in result.gaps)
    for row in result.records:
        assert plugin_kinds.check_asset("general", row) == []


def test_repeating_failures(tmp_path):
    result = entra_audit.step(ctx(entra_audit.PLUGIN, _download(tmp_path)))
    rows = by_name(result.records)
    export = rows["Account Provisioning · Export — repeating failure"]
    assert export.verdict == "weak"
    assert export.flags == ["dirlog-automation-failing:12", "dirlog-automation-affected:4",
                            "dirlog-automation-onset-unobserved"]
    assert export.extra["median_retries_per_subject"] == "3"
    assert "person-" not in export.notes and "example detail" not in export.notes
    # Four rows of a fault naming nobody, at 4% of the download: weak by its share.
    rule = rows["Account Provisioning · Synchronization rule action — repeating failure"]
    assert (rule.verdict, rule.extra["onset_observed"]) == ("weak", "yes")
    assert [coverage.kind_of(g) for g in result.gaps].count(coverage.EXTENT_UNKNOWN) == 1


def test_failure_settings(tmp_path):
    path = _download(tmp_path)
    rows = by_name(entra_audit.step(ctx(entra_audit.PLUGIN, path,
                                        {"failure_material_share": 0.05})).records)
    assert rows["Account Provisioning · Synchronization rule action — repeating failure"
                ].verdict == "unknown"
    rows = by_name(entra_audit.step(ctx(entra_audit.PLUGIN, path,
                                        {"failure_min_rows": 5})).records)
    assert "Account Provisioning · Synchronization rule action — repeating failure" not in rows


def test_the_filtered_download_supplies_the_role_history(tmp_path):
    full = _download(tmp_path)
    filtered = write(tmp_path / "audit-roles-2030-04.csv", COLUMNS,
                     [_role(1 + i % 9, "Add member to role completed (PIM activation)",
                            "Example Administrator", "holder-a@example.test") for i in range(9)])
    result = entra_audit.step(ctx(entra_audit.PLUGIN, full,
                                  {"role_changes": str(tmp_path / "audit-roles-*.csv")}))
    rows = by_name(result.records)
    assert rows["Example Administrator — privilege activation history"].extra[
        "activations"] == "9"
    assert "Global Administrator — privilege activation history" not in rows
    scope = rows["Directory change-record scope"]
    assert scope.extra["role_history_source"] == "role-management export"
    assert scope.extra["role_changes"] == "6"
    assert rows["Role-change record scope"].extra["changes"] == "9"
    assert filtered.exists()
    # The full download's role rows are counted, not read: its unclassified
    # activity is not reported a second time.
    assert not any("Example future role activity" in g for g in result.gaps)


def test_a_download_at_its_limit(tmp_path):
    rows = [{"Date (UTC)": f"2030-04-0{1 + i // 500}T00:00:00Z", "Category": "UserManagement",
             "Service": "Core Directory", "Activity": "Update user", "Result": "success"}
            for i in range(1_000)]
    path = write(tmp_path / "audit.csv", COLUMNS, rows)
    result = entra_audit.step(ctx(entra_audit.PLUGIN, path))
    assert "dirlog-scope-ceiling:1000" in by_name(result.records)[
        "Directory change-record scope"].flags
    assert any("download limit" in g for g in result.gaps)


def test_nothing_given():
    result = entra_audit.step(ctx(entra_audit.PLUGIN, None))
    assert result.records == [] and len(result.gaps) == 1
    assert coverage.impact_kind_of(result.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_the_failure_shape():
    shape = entra_audit.family("Svc", "Act", "Failed to create User 'x@example.test' id "
                               f"{guid(1)} at 2030-02-03T04:05:06Z try 3; Error: detail")
    assert shape == "Svc · Act · Failed to create User '…' id … at … try N"


def test_a_person_named_like_the_service_is_not_the_service(tmp_path):
    rows = [_role(2, "Add member to role", "Example Administrator", "holder-a@example.test",
                  actor="", ActorDisplayName="Jo Pimm"),
            _role(3, "Add member to role", "Example Administrator", "holder-b@example.test",
                  actor="", ActorDisplayName="Azure AD PIM", ActorType="Application")]
    result = entra_audit.step(ctx(entra_audit.PLUGIN, write(tmp_path / "a.csv", COLUMNS, rows)))
    row = by_name(result.records)["Example Administrator — privilege activation history"]
    assert row.extra["standing_grants"] == "1"


def test_email_addresses_are_replaced_in_the_message_shape():
    shape = entra_audit.family("Svc", "Act", "No mailbox for someone@example.test, retrying")
    assert shape == "Svc · Act · No mailbox for …@…, retrying"
