"""The Microsoft Entra interactive sign-in reader in takestock's readers library.

The sign-in logs and role exports are composed in each test
(``entra_helpers``): synthetic accounts under ``example.test``, one emergency
account, an account named like an administrator that holds no role, two
legacy flows, a legacy client, and two downloads that overlap.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import ROLE_COLUMNS, SIGNIN_COLUMNS, by_name, ctx, guid, write

from takestock import coverage, plugin_kinds, roles
from takestock.readers import entra_signins, library

ADMIN = "admin.one@example.test"
DORMANT = "adm-two@example.test"
EMERGENCY = "breakglass-01@example.test"
SERVICE = "svc-backup@example.test"


def _signin(n: int, day: int, user: str, **kw: str) -> dict:
    row = {"Date (UTC)": f"2030-01-{day:02d}T08:00:{n % 60:02d}Z", "Request ID": guid(n),
           "Correlation ID": f"correlation-{n}", "Username": user, "Application": "Example Mail",
           "Status": "Success", "Client app": "Browser", "Compliant": "true",
           "Authentication requirement": "Multifactor authentication",
           "Conditional Access": "Success"}
    row.update(kw)
    return row


def _roles(tmp: Path) -> list[str]:
    active = write(tmp / "roles-active.csv", ROLE_COLUMNS, [
        {"RoleDisplayName": "Example Administrator", "PrincipalId": guid(1),
         "PrincipalUserPrincipalName": ADMIN, "PrincipalType": "#microsoft.graph.user"},
        {"RoleDisplayName": "Example Administrator", "PrincipalId": guid(2),
         "PrincipalUserPrincipalName": DORMANT, "PrincipalType": "#microsoft.graph.user"},
        {"RoleDisplayName": "Global Administrator", "PrincipalId": guid(3),
         "PrincipalUserPrincipalName": EMERGENCY, "PrincipalType": "#microsoft.graph.user"},
        {"RoleDisplayName": "Global Administrator", "PrincipalId": guid(4),
         "PrincipalDisplayName": "Example admins", "PrincipalType": "#microsoft.graph.group"},
    ])
    eligible = write(tmp / "roles-eligible.csv", ROLE_COLUMNS, [
        {"RoleDisplayName": "Example Reader", "PrincipalId": guid(5),
         "PrincipalDisplayName": "Example readers", "PrincipalType": "#microsoft.graph.group"},
    ])
    return [str(active), str(eligible)]


def _logs(tmp: Path) -> tuple[Path, Path]:
    first = [_signin(i, 1 + i % 5, f"user-{i % 3:02d}@example.test") for i in range(1, 31)]
    first += [_signin(31, 2, ADMIN, **{"Authentication requirement":
                                        "Single-factor authentication"}),
              _signin(32, 3, ADMIN, Compliant=""),
              _signin(33, 4, SERVICE),
              _signin(34, 4, "user-01@example.test", **{"Authentication Protocol": "ROPC"}),
              _signin(35, 5, "user-02@example.test",
                      **{"Original transfer method": "deviceCodeFlow"}),
              _signin(36, 5, "user-02@example.test", **{"Client app": "Exchange ActiveSync"}),
              _signin(37, 5, "user-02@example.test", **{"Client app": "Unknown"})]
    # Twenty-five sign-ins to one application with no policy in scope (an
    # absolute count), and six of ten to another (a share).
    first += [_signin(100 + i, 6, "user-00@example.test", Application="Example Portal",
                      **{"Conditional Access": "Not Applied" if i < 25 else "Success"})
              for i in range(40)]
    first += [_signin(200 + i, 6, "user-01@example.test", Application="Example Wiki",
                      **{"Conditional Access": "Not Applied" if i < 6 else "Success"})
              for i in range(10)]
    a = write(tmp / "signins-a.csv", SIGNIN_COLUMNS, first)
    # The second download repeats two of the first's rows and adds later ones.
    second = [first[30], first[31]] + [_signin(300 + i, 12, "user-00@example.test")
                                      for i in range(5)]
    b = write(tmp / "signins-b.csv", SIGNIN_COLUMNS, second)
    # A third, later download leaves a stretch no download covers.
    write(tmp / "signins-c.csv", SIGNIN_COLUMNS,
          [_signin(400 + i, 20, "user-00@example.test") for i in range(3)])
    return a, b


def _run(tmp: Path, **settings: object):
    a, b = _logs(tmp)
    s = {"also": [str(b), str(tmp / "signins-c*.csv")], "roles": _roles(tmp), **settings}
    return entra_signins.step(ctx(entra_signins.PLUGIN, a, s))


def test_the_reader_is_in_the_library():
    assert library()["entra_signins"] is entra_signins.PLUGIN


def test_role_rows(tmp_path):
    rows = by_name(_run(tmp_path).records)
    admin = rows["Example Administrator — assignment usage"]
    assert admin.verdict == "weak"
    assert admin.flags == ["signin-privileged-used:1", "signin-privileged-unused:1",
                           "signin-single-factor:1", "signin-noncompliant-device:1"]
    assert (admin.hosts_count, admin.usage_count) == (2, 2)
    assert admin.extra["holders_not_seen"] == "1"
    assert admin.role == roles.signin_assignment_usage(2)
    top = rows["Global Administrator — assignment usage"]
    assert top.verdict == "unknown"
    assert top.flags == ["signin-privileged-used:0", "signin-privileged-unused:1",
                         "signin-break-glass-unused:1", "signin-principal-unmatchable:1"]
    unmeasured = rows["Administrative powers whose use cannot be measured here"]
    assert unmeasured.extra["role_names"] == "Example Reader"
    assert unmeasured.flags == ["signin-principal-unmatchable:1"]
    for row in rows.values():
        assert row.source == "entra_signins"
        assert plugin_kinds.check_asset("general", row) == []


def test_application_rows_need_a_count_or_a_share(tmp_path):
    rows = by_name(_run(tmp_path).records)
    portal = rows["Example Portal — sign-ins outside access policy"]
    assert portal.flags == ["signin-policy-not-applied:25"]
    assert portal.extra["share_of_application"] == "62.5%"
    wiki = rows["Example Wiki — sign-ins outside access policy"]
    assert wiki.extra["policy_not_applied"] == "6"
    # Raising the floor behind the share removes the wiki's row.
    rows = by_name(_run(tmp_path, policy_gap_share_floor=7).records)
    assert "Example Wiki — sign-ins outside access policy" not in rows
    rows = by_name(_run(tmp_path, policy_gap_min_rows=30, policy_gap_min_share=1.1).records)
    assert not [n for n in rows if n.endswith("outside access policy")]


def test_legacy_flows_and_clients(tmp_path):
    rows = by_name(_run(tmp_path).records)
    assert rows["ropc — legacy authentication flow"].flags == ["signin-legacy-flow:ropc:1"]
    devicecode = rows["devicecode — legacy authentication flow"]
    assert devicecode.extra["columns"] == "Original transfer method"
    client = rows["Legacy mail and client protocols — interactive sign-ins"]
    assert client.verdict == "weak"
    assert client.flags == ["signin-legacy-client:Exchange ActiveSync:1"]
    assert client.extra["unknown_client_signins"] == "1"


def test_no_legacy_client_is_not_a_pass(tmp_path):
    log = write(tmp_path / "s.csv", SIGNIN_COLUMNS, [_signin(1, 1, ADMIN)])
    rows = by_name(entra_signins.step(ctx(entra_signins.PLUGIN, log)).records)
    client = rows["Legacy mail and client protocols — interactive sign-ins"]
    assert (client.verdict, client.flags) == ("n/a", ["signin-legacy-client-none"])


def test_admin_named_accounts_and_their_patterns(tmp_path):
    result = _run(tmp_path)
    row = by_name(result.records)["Administratively-named accounts with no recorded entitlement"]
    assert row.flags == ["signin-unmatched-admin-shape:1"]
    assert any("roles granted outside" in g for g in result.gaps)
    # Replacing the patterns with ones nothing matches removes the row and its gap.
    result = _run(tmp_path, admin_names={"prefixes": ["zz-"], "suffixes": [], "contains": []})
    assert "Administratively-named accounts with no recorded entitlement" not in by_name(
        result.records)
    assert not any("roles granted outside" in g for g in result.gaps)


def test_downloads_merge_with_duplicates_counted_once(tmp_path):
    scope = by_name(_run(tmp_path).records)["Sign-in evidence scope"]
    assert scope.extra["exports_merged"] == "3"
    assert scope.extra["rows_held_by_two_exports"] == "2"
    assert scope.usage_count == 95
    assert "signin-scope-files:3" in scope.flags
    assert scope.extra["uncovered_stretches"] == "2030-01-12..2030-01-20"
    assert "signin-scope-hole:2030-01-12..2030-01-20" in scope.flags
    assert scope.data_state == "discovery"


def test_a_download_at_its_limit_is_a_ceiling(tmp_path):
    rows = [_signin(i, 1 + i // 400, "user-00@example.test") for i in range(1_000)]
    log = write(tmp_path / "s.csv", SIGNIN_COLUMNS, rows)
    result = entra_signins.step(ctx(entra_signins.PLUGIN, log, {"roles": _roles(tmp_path)}))
    scope = by_name(result.records)["Sign-in evidence scope"]
    assert "signin-scope-ceiling:1000" in scope.flags
    assert scope.extra["window_is_ceiling"] == "yes"
    assert [coverage.kind_of(g) for g in result.gaps] == [coverage.EXTENT_UNKNOWN]


def test_without_a_roster_no_role_rows_and_a_gap(tmp_path):
    a, _ = _logs(tmp_path)
    result = entra_signins.step(ctx(entra_signins.PLUGIN, a))
    assert not [n for n in by_name(result.records) if n.endswith("assignment usage")]
    assert "none was named under settings: roles" in result.gaps[0]
    assert by_name(result.records)["Sign-in evidence scope"].extra["entitlement_roster"] == (
        "not supplied")


def test_no_input_is_one_gap():
    result = entra_signins.step(ctx(entra_signins.PLUGIN, None))
    assert result.records == []
    assert len(result.gaps) == 1 and "no input was given" in result.gaps[0]
    assert coverage.impact_kind_of(result.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_long_application_names_are_split():
    long = "ExampleWidgets-Integration_Service-Production-01"
    assert entra_signins.split_long_app_name(long) == ["ExampleWidgets-Integration",
                                                       "Service-Production-01"]
    assert entra_signins.split_long_app_name("Example Portal") is None


def test_emergency_accounts_by_role_or_by_name():
    held = {"ops@example.test", "breakglass-02@example.test"}
    assert entra_signins.break_glass(held) == {"breakglass-02@example.test"}
    assert entra_signins.break_glass(held, "Example Emergency Access") == held


def test_a_failed_attempt_is_not_a_sign_in(tmp_path):
    # A failed attempt records a single-factor requirement when its first factor
    # failed; it is neither use of the role nor a single-factor sign-in.
    log = write(tmp_path / "s.csv", SIGNIN_COLUMNS, [
        _signin(1, 1, DORMANT, Status="Failure",
                **{"Authentication requirement": "Single-factor authentication"}),
        _signin(2, 1, DORMANT, Status="Interrupted"),
        _signin(3, 2, ADMIN)])
    rows = by_name(entra_signins.step(ctx(entra_signins.PLUGIN, log,
                                          {"roles": _roles(tmp_path)})).records)
    admin = rows["Example Administrator — assignment usage"]
    assert admin.verdict == "unknown"
    assert admin.flags == ["signin-privileged-used:1", "signin-privileged-unused:1"]
    assert (admin.extra["holders_seen"], admin.usage_count) == ("1", 1)
    assert "only failed or were interrupted" in admin.notes
    assert rows["Sign-in evidence scope"].extra["single_factor"] == "0"
