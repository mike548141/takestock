"""Plug-in collectors: discovery, the step contract, each capability, and the example end to end."""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, observe, plaintext, plugin_kinds, plugins, sge
from takestock.model import CryptoAsset
from takestock.plugins import Context, Plugin, StepResult

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
EXAMPLE = ROOT / "examples" / "plugin-disk-encryption"
DOC = ROOT / "docs" / "PLUGINS.md"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)


# ── helpers ──

class _EntryPoint:
    def __init__(self, name: str, obj: object) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> object:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


def _install(monkeypatch: pytest.MonkeyPatch, *items: object) -> None:
    """Make ``items`` the entry points of the plug-in group."""
    eps = [_EntryPoint(getattr(i, "name", f"broken-{n}"), i) for n, i in enumerate(items)]

    def entry_points(group: str = "") -> list[_EntryPoint]:
        return eps if group == plugins.ENTRY_POINT_GROUP else []
    monkeypatch.setattr(plugins.metadata, "entry_points", entry_points)


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The sample organisation in a fresh workspace, with its own inbox."""
    _no_network(monkeypatch)
    _install(monkeypatch)
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    shutil.copytree(SAMPLE / "exports", tmp_path / "inbox")
    config.set_workspace(tmp_path)
    config.set_inbox(tmp_path / "inbox")
    return tmp_path


def _observe(target: dict) -> observe.Result:
    opts = observe.Options(now=NOW, offline=True, announce=lambda _line: None)
    return observe.observe(target, opts)


def _target(*declared: object) -> dict:
    target = config.load_target("example-widgets")
    target["plugins"] = list(declared)
    return target


def _gaps(result: observe.Result, needle: str) -> list[str]:
    return [g for g in result.summary["gaps"] if needle in g]


def _rows(result: observe.Result, source: str) -> list[CryptoAsset]:
    return [a for a in result.assets if a.source == source]


def _disk(**over: object) -> dict:
    record: dict = {"device": "laptop-01.example.test", "volume": "C:", "state": "encrypted",
                    "method": "aes-256-xts"}
    record.update(over)
    return record


def _plugin(name: str, kind: str = "endpoint-encryption", records: list | None = None,
            **kwargs: object) -> Plugin:
    def step(ctx: Context) -> StepResult:
        return StepResult(records=list(records or []))
    return Plugin(name=name, kind=kind, step=kwargs.pop("step", step), **kwargs)  # type: ignore[arg-type]


# ── the schema and its documentation ──

def test_every_kind_and_field_is_documented():
    doc = DOC.read_text()
    for kind, s in plugin_kinds.schema()["kinds"].items():
        assert f"### `{kind}`" in doc, kind
        section = doc.split(f"### `{kind}`", 1)[1].split("\n### ", 1)[0]
        for name in s["fields"]:
            assert f"| `{name}` |" in section, (kind, name)
        for control in (s.get("controls") or {}):
            assert f"`{control}`" in section, (kind, control)


def test_schema_values_are_text_and_controls_are_complete(baseline):
    doc = plugin_kinds.schema()
    states = doc["control_states"]
    assert all(isinstance(v, str) for v in states["values"])
    assert set(states["synonyms"].values()) <= set(states["values"])
    for kind, s in doc["kinds"].items():
        assert s["shape"] in ("software", "disk", "control", "mail", "listener"), kind
        assert any(f.get("required") for f in s["fields"].values()), kind
        for name, f in s["fields"].items():
            if f["type"] == "choice":
                assert all(isinstance(v, str) for v in f["values"]), (kind, name)
                assert set((f.get("synonyms") or {}).values()) <= set(f["values"]), (kind, name)
        for target in (s.get("aliases") or {}).values():
            assert any(target in (baseline.get(t) or {}) for t in ("symmetric", "hashes")), target
        controls = s.get("controls") or {}
        if s["shape"] == "control":
            assert set(controls) == set(s["fields"].get("setting", s["fields"].get("control"))["values"])
        for control, c in controls.items():
            assert c["grade"] in ("algorithms", "setting", "presence"), control
            assert c["data_state"] in s["row"]["data_state"], control
            if "tls_versions" in (c.get("tables") or []):
                assert c["protocol"] == "tls", control


def test_the_schema_is_read_from_the_package_only(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "plugin-kinds.yaml").write_text("schema: 1\nkinds: {}\n")
    config.set_workspace(tmp_path)
    assert "endpoint-encryption" in plugin_kinds.row_kinds()
    assert plugin_kinds.SCHEMA_FILE.parent == config.BUNDLED_DATA_DIR


# ── validating records ──

def test_a_valid_record_is_converted_to_its_types():
    clean, problems = plugin_kinds.validate("endpoint-encryption", _disk(
        state="Protected", key_protectors="tpm; recovery-key", recovery_key_escrowed="yes",
        collected_on="2030-01-15T08:00:00Z", x_owner="Finance"))
    assert problems == []
    assert clean is not None
    assert clean["state"] == "encrypted"
    assert clean["key_protectors"] == ["tpm", "recovery-key"]
    assert clean["recovery_key_escrowed"] is True
    assert clean["collected_on"] == "2030-01-15"
    assert clean["x"] == {"x_owner": "Finance"}


@pytest.mark.parametrize(("record", "problem"), [
    ({"volume": "C:", "state": "encrypted"}, "device: required"),
    (_disk(state="sideways"), "state: 'sideways' is not one of"),
    (_disk(colour="blue"), "unknown field 'colour'"),
    (_disk(recovery_key_escrowed="perhaps"), "expected true or false"),
    (_disk(collected_on="31/01/2030"), "collected_on: expected a date"),
    (_disk(x_nested={"a": 1}), "x_nested"),
    ("laptop-01,C:,encrypted", "a record is a mapping"),
])
def test_an_invalid_record_names_its_problem(record, problem):
    clean, problems = plugin_kinds.validate("endpoint-encryption", record)
    assert clean is None
    assert any(problem in p for p in problems), problems


def test_counts_and_ports_are_whole_numbers():
    _, problems = plugin_kinds.validate("mail-transport", {"direction": "outbound",
                                                           "tls_version": "TLS1.2",
                                                           "messages": "-3"})
    assert any("whole number" in p for p in problems)
    _, problems = plugin_kinds.validate("host-listener", {"device": "a.example.test",
                                                          "port": 70000, "transport": "tcp"})
    assert any("1 to 65535" in p for p in problems)
    clean, _ = plugin_kinds.validate("mail-transport", {"direction": "sent", "tls_version": "TLS1.2",
                                                        "messages": "1,200"})
    assert clean is not None and clean["messages"] == 1200 and clean["direction"] == "outbound"


def test_a_finished_row_is_held_to_the_kinds_row_constraints():
    good = CryptoAsset(name="Disk encryption a C:", data_state="at-rest", protocol="disk-encryption")
    assert plugin_kinds.check_asset("endpoint-encryption", good) == []
    bad = CryptoAsset(name="x", data_state="in-transit", protocol="tls", extra={"s": {1, 2}})
    found = plugin_kinds.check_asset("endpoint-encryption", bad)
    assert any("data_state" in p for p in found) and any("JSON" in p for p in found)
    assert plugin_kinds.check_asset("mail-transport", CryptoAsset(
        name="m", data_state="in-transit", protocol="smtp")) == ["extra['messages'] is required on "
                                                                 "a mail-transport row"]


# ── what each kind's records become ──

def _build(kind: str, policy, port_table, target: dict | None = None) -> plugin_kinds.Build:
    return plugin_kinds.Build(plugin="p", kind=kind, title="Test export", policy=policy,
                              port_table=port_table, target=target or {},
                              collected_on="2030-01-31", shown="inbox/test.csv")


def _one(kind: str, record: dict, policy, port_table) -> CryptoAsset:
    clean, problems = plugin_kinds.validate(kind, record)
    assert problems == [], problems
    rows, _ = plugin_kinds.build_rows(kind, [clean], _build(kind, policy, port_table))
    assert len(rows) == 1
    return rows[0]


def test_disk_records_are_graded_on_state_and_cipher(policy, port_table):
    strong = policy.apply(_one("endpoint-encryption", _disk(), policy, port_table))
    assert strong.verdict == "strong" and strong.symmetric == ["aes256_xts"]
    short = policy.apply(_one("endpoint-encryption", _disk(method="XTS-AES-128"), policy, port_table))
    assert short.verdict == "strong" and short.symmetric == ["aes128_xts"]
    off = policy.apply(_one("endpoint-encryption", _disk(state="not-encrypted", method=None),
                            policy, port_table))
    assert off.verdict == "weak" and "encryption-off" in off.flags
    paused = policy.apply(_one("endpoint-encryption", _disk(state="suspended"), policy, port_table))
    assert paused.verdict == "weak" and "encryption-suspended" in paused.flags
    bare = policy.apply(_one("endpoint-encryption", _disk(method=None), policy, port_table))
    assert bare.verdict == "unknown" and "algorithms-not-recorded" in bare.flags
    odd = policy.apply(_one("endpoint-encryption", _disk(method="rot13"), policy, port_table))
    assert "ungraded:endpoint-encryption:rot13" in odd.flags
    lost = _one("endpoint-encryption", _disk(recovery_key_escrowed=False), policy, port_table)
    assert "recovery-key-not-escrowed" in lost.flags


def test_control_records_grade_settings_and_algorithms(policy, port_table):
    mfa = policy.apply(_one("directory", {"directory": "example.test", "setting": "mfa-required",
                                          "state": "enforced"}, policy, port_table))
    assert mfa.verdict == "acceptable" and mfa.data_state == "identity"
    ntlm = policy.apply(_one("directory", {"directory": "example.test", "setting": "ntlmv1-refused",
                                           "state": "allowed"}, policy, port_table))
    assert ntlm.verdict == "weak" and "control-off:ntlmv1-refused" in ntlm.flags
    kerberos = policy.apply(_one("directory", {"directory": "example.test",
                                               "setting": "kerberos-encryption", "state": "on",
                                               "algorithms": "aes256-cts-hmac-sha1-96; rc4-hmac"},
                                 policy, port_table))
    assert kerberos.verdict == "weak" and sorted(kerberos.symmetric) == ["aes_cbc", "rc4"]
    tde = policy.apply(_one("database-encryption", {"database": "orders", "control": "tde",
                                                    "state": "on", "algorithms": "aes256_cbc",
                                                    "server": "db-01.example.test"},
                            policy, port_table))
    assert tde.verdict == "strong" and tde.host == "db-01.example.test"
    partial = policy.apply(_one("backup-encryption", {"target": "nightly", "control": "at-rest",
                                                      "state": "partial", "algorithms": "aes256_gcm"},
                                policy, port_table))
    assert partial.verdict == "weak" and partial.symmetric == []
    wire = policy.apply(_one("database-encryption", {"database": "orders", "control": "transport",
                                                     "state": "on", "algorithms": "TLSv1.0"},
                             policy, port_table))
    assert wire.protocol == "tls" and wire.verdict == "weak"
    keys = _one("virtualisation", {"object": "cluster-a", "control": "key-management", "state": "on"},
                policy, port_table)
    assert keys.verdict == "n/a" and "key-management:present" in keys.flags


def test_mail_transport_rows_are_what_the_sge_evaluator_reads(policy, port_table):
    records = []
    for n, (direction, version, govt) in enumerate([
            ("outbound", "TLS 1.2", True), ("outbound", "TLSv1.3", False),
            ("outbound", "none", True), ("inbound", "TLS1.2", False)]):
        clean, problems = plugin_kinds.validate("mail-transport", {
            "direction": direction, "tls_version": version, "messages": 10,
            "date": f"2030-01-0{n + 1}", "counterparty_domain": "example.org",
            "government": govt, "government_basis": "a list of counterparty domains"})
        assert problems == []
        records.append(clean)
    rows, _ = plugin_kinds.build_rows("mail-transport", records,
                                      _build("mail-transport", policy, port_table))
    assert {a.source for a in rows} == {sge.TRANSPORT_SOURCE}
    outbound = next(a for a in rows if a.extra.get("direction") == "outbound")
    assert outbound.extra["tls_distribution"] == "No TLS=10; TLS1.2=10; TLS1.3=10"
    assert outbound.verdict == "weak" and "mail-cleartext-delivery:outbound" in outbound.flags
    std = config.load_yaml_strict(config.BUNDLED_DATA_DIR / "secure-government-email.yaml")
    report = sge.evaluate(rows, ["example.com"], std).rows
    sending = [r for r in report if r.requirement == "SGE-TLS-01" and r.subject.startswith("outbound")]
    assert sending and sending[0].status == sge.FAIL and "10 of the 30" in sending[0].reason
    assert "2030-01-01 to 2030-01-04" in sending[0].reason
    itls = next(r for r in report if r.requirement == "SGE-ITLS-01")
    assert itls.observed.startswith("20 messages with government organisations")


def test_listener_records_take_the_ports_posture(policy, port_table):
    row = _one("host-listener", {"device": "files-01.example.test", "port": 23, "transport": "tcp",
                                 "process": "telnetd"}, policy, port_table)
    assert "plaintext:telnet" in row.flags and row.protocol == "telnet"
    assert row.verdict == "weak" and row.extra["service"] == "23/tcp"
    assert row.software_binary == "telnetd"
    assert plugin_kinds.LISTENER_MARKER in row.notes
    upgradable = _one("host-listener", {"device": "files-01.example.test", "port": 21,
                                        "transport": "tcp"}, policy, port_table)
    assert "unverified-encryption:ftp" in upgradable.flags and upgradable.verdict == "unknown"


def test_software_records_use_the_software_inventory_reading(policy, port_table):
    clean, _ = plugin_kinds.validate("endpoint-software", {"device": "files-01.example.test",
                                                           "product": "OpenSSL", "version": "3.0.0"})
    rows, _ = plugin_kinds.build_rows("endpoint-software", [clean],
                                      _build("endpoint-software", policy, port_table))
    names = {a.name for a in rows}
    assert "OpenSSL 3.0.0" in names and "Test export scope" in names
    assert {a.source for a in rows} == {"p"}


def test_every_mapped_row_meets_its_kinds_row_constraints(policy, port_table):
    samples = {
        "endpoint-software": {"device": "a.example.test", "product": "OpenSSL", "version": "3.0.0"},
        "endpoint-encryption": _disk(),
        "directory": {"directory": "example.test", "setting": "ldap-signing-required", "state": "on"},
        "mail-transport": {"direction": "inbound", "tls_version": "TLS1.3"},
        "virtualisation": {"object": "vm-01", "control": "vm-encryption", "state": "on",
                           "algorithms": "aes256_xts"},
        "backup-encryption": {"target": "nightly", "control": "in-transit", "state": "on",
                              "algorithms": "TLSv1.3"},
        "database-encryption": {"database": "orders", "control": "column", "state": "off"},
        "host-listener": {"device": "a.example.test", "port": 443, "transport": "tcp"},
    }
    assert set(samples) == set(plugin_kinds.row_kinds())
    for kind, record in samples.items():
        clean, problems = plugin_kinds.validate(kind, record)
        assert problems == [], (kind, problems)
        rows, _ = plugin_kinds.build_rows(kind, [clean], _build(kind, policy, port_table))
        for row in rows:
            assert plugin_kinds.check_asset(kind, row) == [], (kind, row.name)
            json.dumps(row.extra)


# ── declaring and finding plug-ins ──

def test_a_plugin_declaration_is_checked():
    with pytest.raises(ValueError, match="kind"):
        _plugin("p", kind="telepathy")
    with pytest.raises(ValueError, match="lower-case"):
        _plugin("Has Spaces")
    with pytest.raises(ValueError, match="plain file name"):
        _plugin("p", data_files=("../baseline.yaml",))
    with pytest.raises(ValueError, match="takestock's own"):
        _plugin("p", data_dir=str(config.BUNDLED_DATA_DIR))
    assert _plugin("p", kind=plugin_kinds.COVERAGE_CHECK).late is True


def test_an_installed_plugin_runs_only_when_the_profile_declares_it(workspace, monkeypatch):
    _install(monkeypatch, _plugin("disk-a", records=[_disk()]), _plugin("disk-b", records=[_disk()]))
    result = _observe(_target("disk-a"))
    assert _rows(result, "disk-a") and not _rows(result, "disk-b")
    assert result.summary["plugins"]["disk-a"]["status"] == "ran"
    assert result.summary["plugins"]["disk-a"]["origin"] == "entry point"
    assert result.summary["plugins_installed_not_declared"] == ["disk-b"]


def test_a_plugin_is_found_by_module_path(workspace, monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    (workspace / "inbox" / "disk-encryption.csv").write_text(
        (EXAMPLE / "sample" / "disk-encryption.csv").read_text())
    result = _observe(_target({"name": "example-disk-encryption",
                               "module": "example_disk_encryption"}))
    assert result.summary["plugins"]["example-disk-encryption"]["origin"] == \
        "module example_disk_encryption"
    assert _rows(result, "example-disk-encryption")


def test_a_plugin_is_found_by_file_path(workspace):
    (workspace / "plugins").mkdir()
    (workspace / "plugins" / "reader.py").write_text(
        "from takestock.plugins import Plugin\n"
        "def read(ctx):\n"
        "    return [{'device': 'laptop-09.example.test', 'volume': 'C:', 'state': 'encrypted'}]\n"
        "PLUGIN = Plugin(name='local-disk', kind='endpoint-encryption', step=read)\n")
    result = _observe(_target({"name": "local-disk", "path": "plugins/reader.py"}))
    assert [a.host for a in _rows(result, "local-disk")] == ["laptop-09.example.test"]


@pytest.mark.parametrize(("declared", "reason"), [
    ("not-installed", "is not installed"),
    ({"name": "x", "module": "no_such_module_here"}, "could not be loaded"),
    ({"name": "x", "module": "takestock.plugins:ENTRY_POINT_GROUP"}, "could not be loaded"),
    ({"name": "x", "module": "a", "path": "b"}, "not both"),
    ({"module": "a"}, "needs a `name:`"),
])
def test_a_declared_plugin_that_cannot_be_found_is_a_gap(workspace, declared, reason):
    result = _observe(_target(declared))
    gaps = _gaps(result, "not run")
    assert gaps and reason in gaps[0]
    assert result.summary["complete"] is False


def test_a_broken_entry_point_is_named_in_the_gap(workspace, monkeypatch):
    _install(monkeypatch, ImportError("missing dependency"))
    result = _observe(_target("disk-a"))
    assert "missing dependency" in _gaps(result, "not run")[0]


# ── the step contract ──

def test_a_step_receives_what_an_ingest_collector_gets(workspace, monkeypatch):
    seen: dict = {}

    def step(ctx: Context) -> StepResult:
        seen.update(input=ctx.input, ref=ctx.ref_time, raw=ctx.raw_dir, settings=ctx.settings,
                    policy=ctx.policy, dictionary=ctx.dictionary, ports=ctx.port_table,
                    on=ctx.collected_on, extra=ctx.inbox_path("inbox/more.csv"))
        ctx.target["discovery"] = "changed by a plug-in"
        return StepResult()

    (workspace / "inbox" / "disks.csv").write_text("x\n")
    _install(monkeypatch, Plugin(name="probe", kind="endpoint-encryption", step=step,
                                 input="inbox/default.csv"))
    target = _target({"name": "probe", "input": "inbox/disks.csv", "settings": {"site": "north"}})
    result = _observe(target)
    assert seen["input"] == workspace / "inbox" / "disks.csv"
    assert seen["extra"] == workspace / "inbox" / "more.csv"
    assert seen["ref"] == NOW
    assert seen["raw"] == result.observation / "raw" / "plugins" / "probe" and seen["raw"].is_dir()
    assert seen["settings"] == {"site": "north"}
    assert seen["policy"].grade("symmetric", "aes256_gcm") == "strong"
    assert "posture" in next(iter(seen["ports"].values()))
    assert isinstance(seen["dictionary"], dict)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", seen["on"])
    assert target["discovery"] != "changed by a plug-in"


def test_finished_rows_are_accepted_and_cannot_borrow_another_source(workspace, monkeypatch):
    row = CryptoAsset(name="Disk encryption laptop-05.example.test C:", data_state="at-rest",
                      protocol="disk-encryption", host="laptop-05.example.test", source="ct_dns",
                      verdict="weak", flags=["encryption-off"])
    _install(monkeypatch, _plugin("rows", records=[row]))
    result = _observe(_target("rows"))
    (written,) = _rows(result, "rows")
    assert written.verdict == "weak" and written.source_class == "private"
    assert not [a for a in result.assets if a.source == "ct_dns" and "laptop-05" in a.name]


# ── (a) late steps and coverage checks ──

def test_late_steps_see_earlier_rows_and_early_steps_see_none(workspace, monkeypatch):
    seen: dict[str, set] = {}

    def early(ctx: Context) -> StepResult:
        seen["early"] = {a.source for a in ctx.assets}
        return StepResult(records=[_disk(device="laptop-07.example.test")])

    def check(ctx: Context) -> StepResult:
        seen["late"] = {a.source for a in ctx.assets}
        devices = {a.host for a in ctx.assets if a.source == "early-disk"}
        missing = sorted({"laptop-07.example.test", "laptop-08.example.test"} - devices)
        return StepResult(gaps=[f"no disk encryption record for {', '.join(missing)}"],
                          records=[_disk()])

    _install(monkeypatch, Plugin(name="early-disk", kind="endpoint-encryption", step=early),
             Plugin(name="device-check", kind=plugin_kinds.COVERAGE_CHECK, step=check))
    result = _observe(_target("device-check", "early-disk"))
    assert seen["early"] == set()
    assert {"early-disk", "netdev", "software_inventory"} <= seen["late"]
    assert _gaps(result, "plug-in `device-check`: no disk encryption record for laptop-08")
    assert _gaps(result, "a coverage check returns gaps only")
    assert not _rows(result, "device-check")


# ── (b) annotation ──

def test_an_annotation_adds_keys_and_never_changes_one(workspace, monkeypatch):
    def label(ctx: Context) -> StepResult:
        out: dict = {"crypto/none/000000000000": {"environment": "test"}}
        for a in ctx.assets:
            if a.source == "netdev" and a.host:
                out[a.bom_ref()] = {"environment": "production"}
            if a.source == "software_inventory" and a.extra.get("provides"):
                out[a.bom_ref()] = {"provides": "something else"}
        return StepResult(annotations=out)

    _install(monkeypatch, Plugin(name="labels", kind=plugin_kinds.ANNOTATION, step=label))
    result = _observe(_target("labels"))
    labelled = [a for a in result.assets if a.extra.get("environment") == "production"]
    assert labelled and all(a.source == "netdev" for a in labelled)
    assert all(a.extra.get("provides") != "something else" for a in result.assets)
    assert result.summary["plugins"]["labels"]["annotated"] == len(labelled)
    gap = _gaps(result, "annotation(s) not applied")[0]
    assert "never changes them" in gap and "no row has bom_ref" in gap


# ── (c) summary contributions ──

def test_a_summary_lands_under_the_plugins_own_key(workspace, monkeypatch):
    def step(ctx: Context) -> StepResult:
        return StepResult(records=[_disk(), _disk(volume="D:", state="not-encrypted", method=None)],
                          summary={"volumes": 2})

    def summarise(ctx: Context, rows: list[CryptoAsset]) -> dict:
        return {"weak": sum(r.verdict == "weak" for r in rows)}

    _install(monkeypatch, Plugin(name="disk", kind="endpoint-encryption", step=step,
                                 summarise=summarise),
             Plugin(name="bad-summary", kind="endpoint-encryption",
                    step=lambda ctx: StepResult(records=[_disk()], summary={"when": NOW})))
    result = _observe(_target("disk", "bad-summary"))
    assert result.summary["plugins"]["disk"]["summary"] == {"volumes": 2, "weak": 1}
    on_disk = json.loads((result.observation / "summary.json").read_text())
    assert on_disk["plugins"]["disk"]["summary"]["weak"] == 1
    assert "summary" not in result.summary["plugins"]["bad-summary"]
    assert _gaps(result, "plug-in `bad-summary`: its summary was not written")


# ── (d) a plug-in's own data files ──

def test_a_plugins_data_files_are_never_takestocks(workspace):
    folder = workspace / "plugins"
    folder.mkdir()
    (folder / "baseline.yaml").write_text("symmetric:\n  aes256_xts: weak\n")
    (folder / "reader.py").write_text(
        "from takestock.plugins import Plugin, StepResult\n"
        "def read(ctx):\n"
        "    text = ctx.data_file('baseline.yaml').read_text()\n"
        "    return StepResult(records=[{'device': 'laptop-01.example.test', 'volume': 'C:',\n"
        "                                'state': 'encrypted', 'method': 'aes-256-xts'}],\n"
        "                      summary={'own_file': 'weak' in text})\n"
        "PLUGIN = Plugin(name='own-data', kind='endpoint-encryption', step=read,\n"
        "                data_files=('baseline.yaml',))\n")
    result = _observe(_target({"name": "own-data", "path": "plugins/reader.py"}))
    (row,) = _rows(result, "own-data")
    assert row.verdict == "strong"
    assert result.summary["plugins"]["own-data"]["summary"] == {"own_file": True}
    assert config.data_file("baseline.yaml") == config.BUNDLED_DATA_DIR / "baseline.yaml"


def test_an_undeclared_data_file_is_refused():
    p = _plugin("p", data_files=("mine.csv",))
    ctx = Context(plugin=p, target={}, settings={}, input=None, ref_time=NOW, raw_dir=Path("."),
                  policy=None, baseline={}, dictionary={}, port_table={},  # type: ignore[arg-type]
                  collected_on="2030-01-31")
    assert ctx.data_file("mine.csv") == Path(p.data_dir) / "mine.csv"
    with pytest.raises(KeyError):
        ctx.data_file("baseline.yaml")


# ── (e) not run: a missing input, a failure ──

def test_a_missing_input_is_a_not_run_gap_and_the_step_is_not_called(workspace, monkeypatch):
    called = []
    _install(monkeypatch, Plugin(name="disk", kind="endpoint-encryption",
                                 step=lambda ctx: called.append(1), input="inbox/absent.csv"),
             Plugin(name="optional-disk", kind="endpoint-encryption",
                    step=lambda ctx: called.append(1), input="inbox/absent.csv"))
    result = _observe(_target("disk", {"name": "optional-disk", "required": False}))
    assert called == []
    (gap,) = _gaps(result, "plug-in `disk`")
    assert "not run: its input inbox/absent.csv was not supplied" in gap
    assert result.summary["plugins"]["disk"]["status"] == "not-run"
    assert result.summary["complete"] is False
    texts = result.summary["gaps"]
    optional = texts.index(_gaps(result, "plug-in `optional-disk`")[0])
    assert result.summary["gap_kinds"][optional] == "not-collected"


def test_a_plugin_that_raises_is_a_gap_and_the_observation_finishes(workspace, monkeypatch):
    def boom(ctx: Context) -> StepResult:
        raise RuntimeError("export layout changed")

    _install(monkeypatch, Plugin(name="boom", kind="endpoint-encryption", step=boom),
             Plugin(name="odd", kind="endpoint-encryption", step=lambda ctx: "not records"),
             _plugin("fine", records=[_disk()]))
    result = _observe(_target("boom", "odd", "fine"))
    assert (result.observation / "bom.cdx.json").exists()
    assert result.exit_code != 2 and result.failures == []
    assert "stopped with RuntimeError: export layout changed" in _gaps(result, "`boom`")[0]
    assert "returned str" in _gaps(result, "`odd`")[0]
    assert _rows(result, "fine")


def test_an_empty_result_is_not_a_clean_one(workspace, monkeypatch):
    _install(monkeypatch, _plugin("empty", records=[]))
    result = _observe(_target("empty"))
    assert _gaps(result, "returned no records")


def test_a_step_that_explains_an_empty_result_gets_no_second_gap(workspace, monkeypatch):
    _install(monkeypatch, _plugin("explained", step=lambda ctx: StepResult(
        gaps=["the export held no volumes for the selected sites"])))
    result = _observe(_target("explained"))
    assert _gaps(result, "plug-in `explained`: the export held no volumes")
    assert not _gaps(result, "returned no records")


# ── the general kind ──

def _general_row(name: str = "Configuration audit device-01.example.test",
                 **over: object) -> CryptoAsset:
    fields: dict = {"name": name, "data_state": "configuration", "protocol": "config-audit",
                    "host": "device-01.example.test", "extra": {"compliant": True}}
    fields.update(over)
    return CryptoAsset(**fields)


def test_a_general_plugin_writes_finished_rows_of_any_data_state(workspace, monkeypatch):
    rows = [_general_row(), _general_row("Key store device-02.example.test", data_state="key-store",
                                         protocol="", symmetric=["aes256_gcm"],
                                         source="netdev"),
            _general_row("", data_state="inventory"),
            _general_row("Bad verdict", verdict="excellent"),
            {"device": "device-03.example.test"}]
    _install(monkeypatch, _plugin("audit", kind=plugin_kinds.GENERAL, records=rows))
    result = _observe(_target("audit"))
    written = {a.name: a for a in _rows(result, "audit")}
    assert set(written) == {"Configuration audit device-01.example.test",
                            "Key store device-02.example.test"}
    assert written["Key store device-02.example.test"].verdict == "strong"
    assert written["Key store device-02.example.test"].extra["plugin"] == "audit"
    assert written["Configuration audit device-01.example.test"].source_class == "private"
    record = result.summary["plugins"]["audit"]
    assert (record["records"], record["rows"], record["invalid"]) == (5, 2, 3)
    assert "general kind has no record schema" in record["problems"][0]
    assert _gaps(result, "returns finished rows only, so its record mappings were not written")
    gap = _gaps(result, "2 of 4 row(s) did not meet the constraints every row shares")[0]
    assert "the row has no name" in gap and "verdict 'excellent'" in gap


def test_an_empty_general_result_is_not_a_gap_by_itself(workspace, monkeypatch):
    _install(monkeypatch, _plugin("quiet", kind=plugin_kinds.GENERAL, records=[]))
    result = _observe(_target("quiet"))
    assert result.summary["plugins"]["quiet"]["status"] == "ran"
    assert not _gaps(result, "`quiet`")


def test_general_is_a_kind_with_no_record_schema():
    assert plugin_kinds.GENERAL in plugin_kinds.kinds()
    assert plugin_kinds.GENERAL not in plugin_kinds.row_kinds()
    assert plugin_kinds.fixed_source(plugin_kinds.GENERAL) == ""
    assert plugin_kinds.check_asset(plugin_kinds.GENERAL, _general_row(data_state="anything")) == []
    assert "### `general`" in DOC.read_text()


# ── gaps as the step wrote them ──

def test_gap_prefix_false_files_the_steps_gaps_as_written(workspace, monkeypatch):
    from takestock import coverage
    written = coverage.gap(coverage.EXTENT_UNKNOWN, "Two sites supplied no export",
                           impact_kind=coverage.NARROWS_CONFIDENCE, impact="Those sites are unread.",
                           nature=coverage.NO_DATA)
    _install(monkeypatch,
             _plugin("plain", step=lambda ctx: StepResult(records=[_disk()],
                                                          gaps=[written, "One volume was unreadable"]),
                     gap_prefix=False),
             _plugin("absent", input="inbox/absent.csv", gap_prefix=False))
    result = _observe(_target("plain", "absent"))
    texts = result.summary["gaps"]
    assert "Two sites supplied no export" in texts and "One volume was unreadable" in texts
    assert not _gaps(result, "plug-in `plain`")
    assert _gaps(result, "plug-in `absent` (endpoint-encryption) not run")
    assert result.summary["plugins"]["plain"]["status"] == "ran"


def test_gap_prefix_is_true_or_false():
    assert _plugin("p").gap_prefix is True
    with pytest.raises(TypeError, match="gap_prefix"):
        _plugin("p", gap_prefix="no")


# ── schema validation inside an observation ──

def test_invalid_records_are_a_gap_and_valid_ones_are_written(workspace, monkeypatch):
    _install(monkeypatch, _plugin("mixed", records=[
        _disk(), _disk(volume="D:", state="melted"), {"device": "laptop-02.example.test"}]))
    result = _observe(_target("mixed"))
    assert len(_rows(result, "mixed")) == 1
    record = result.summary["plugins"]["mixed"]
    assert record["records"] == 3 and record["invalid"] == 2 and record["rows"] == 1
    gap = _gaps(result, "2 of 3 record(s) did not match")[0]
    assert "record 2: state" in gap and "record 3: volume: required" in gap


# ── (f) host listeners ──

def test_a_host_listener_plugin_registers_its_source(workspace, monkeypatch):
    monkeypatch.setattr(plaintext, "HOST_LISTENER_SOURCES", {})
    _install(monkeypatch, _plugin("listeners", kind="host-listener", records=[
        {"device": "files-01.example.test", "port": 23, "transport": "tcp", "process": "telnetd"}]))
    result = _observe(_target("listeners"))
    assert plaintext.HOST_LISTENER_SOURCES == {"listeners": plugin_kinds.LISTENER_MARKER}
    (row,) = _rows(result, "listeners")
    assert row.verdict == "weak" and any(f.startswith("plaintext:") for f in row.flags)


# ── the example, end to end ──

def test_the_example_plugin_end_to_end(workspace, monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    sys.modules.pop("example_disk_encryption", None)
    import example_disk_encryption
    _install(monkeypatch, example_disk_encryption.PLUGIN)
    shutil.copyfile(EXAMPLE / "sample" / "disk-encryption.csv",
                    workspace / "inbox" / "disk-encryption.csv")
    result = _observe(_target("example-disk-encryption"))
    rows = {a.name: a for a in _rows(result, "example-disk-encryption")}
    assert len(rows) == 6
    assert rows["Disk encryption laptop-01.example.test C:"].verdict == "strong"
    assert rows["Disk encryption laptop-01.example.test D:"].symmetric == ["aes128_xts"]
    assert rows["Disk encryption laptop-02.example.test C:"].verdict == "weak"
    off = rows["Disk encryption laptop-03.example.test C:"]
    assert off.verdict == "weak" and "recovery-key-not-escrowed" in off.flags
    assert "algorithms-not-recorded" in rows["Disk encryption files-01.example.test /"].flags
    record = result.summary["plugins"]["example-disk-encryption"]
    assert record["summary"] == {"machines": 5, "volumes": 6, "weak_volumes": 2,
                                 "ungraded_volumes": 2}
    assert _gaps(result, "1 row(s) in disk-encryption.csv name no machine or no disk")
    assert (result.observation / "raw" / "plugins" / "example-disk-encryption"
            / "disk-encryption.csv").exists()
    bom = json.loads((result.observation / "bom.cdx.json").read_text())
    assert any(c["name"] == "Disk encryption laptop-03.example.test C:" for c in bom["components"])
