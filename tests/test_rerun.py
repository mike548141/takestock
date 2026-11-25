"""Deriving an observation from an earlier one, reading named plug-ins again (takestock rerun)."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from takestock import carry, cli, cmdb, config, ctcache, observe, plugins, rerun
from takestock.disposition import load_dispositions_for_target, set_digest
from takestock.model import CryptoAsset
from takestock.plugins import Context, Plugin, StepResult
from takestock.util import file_mtime_date

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
BASE_TIME = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)
LATER = BASE_TIME + timedelta(days=3)


# ── helpers ──

class _EntryPoint:
    def __init__(self, name: str, obj: object) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _install(monkeypatch: pytest.MonkeyPatch, *items: Plugin) -> None:
    eps = [_EntryPoint(i.name, i) for i in items]

    def entry_points(group: str = "") -> list[_EntryPoint]:
        return eps if group == plugins.ENTRY_POINT_GROUP else []
    monkeypatch.setattr(plugins.metadata, "entry_points", entry_points)


def _reader(name: str, **kwargs: object) -> Plugin:
    """A general plug-in writing one row per ``host,state`` line of its input."""
    def step(ctx: Context) -> StepResult:
        assert ctx.input is not None
        rows = []
        for line in ctx.input.read_text().splitlines():
            host, state = line.split(",")
            rows.append(CryptoAsset(
                name=f"{name} {host}", data_state="at-rest", protocol="disk-encryption",
                host=host, verdict="weak" if state == "off" else "unknown",
                notes=f"read by {name}: {state}"))
        return StepResult(records=rows, gaps=[f"{name} read {len(rows)} line(s)"])
    return Plugin(name=name, kind="general", step=step, input=f"inbox/{name}.csv", **kwargs)


def _tags() -> Plugin:
    """An annotation labelling every row with the plug-in that wrote it."""
    def step(ctx: Context) -> StepResult:
        return StepResult(annotations={a.bom_ref(): {"tag": f"seen-{a.source}"}
                                       for a in ctx.assets})
    return Plugin(name="tags", kind="annotation", step=step, annotation_keys=("tag",))


def _late() -> Plugin:
    def step(ctx: Context) -> StepResult:
        return StepResult(records=[CryptoAsset(name="late row", data_state="inventory",
                                               host="device-09.example.test", verdict="unknown")])
    return Plugin(name="late-step", kind="general", step=step, late=True)


ALL = ("laptops", "disks", "servers", "tags", "late-step")


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The sample organisation, three readers, an annotation and a late step, nothing on the network."""
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    _install(monkeypatch, _reader("laptops"), _reader("disks"), _reader("servers"), _tags(),
             _late())
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    shutil.copytree(SAMPLE / "exports", tmp_path / "inbox")
    _write(tmp_path, "laptops", "laptop-01.example.test,on", "laptop-02.example.test,off")
    _write(tmp_path, "disks", "disk-01.example.test,on", "disk-02.example.test,on")
    _write(tmp_path, "servers", "server-01.example.test,off")
    config.set_workspace(tmp_path)
    config.set_inbox(tmp_path / "inbox")
    yield tmp_path
    config.set_workspace(None)
    config.set_inbox(None)


def _write(root: Path, name: str, *lines: str) -> None:
    (root / "inbox" / f"{name}.csv").write_text("\n".join(lines) + "\n")


def _target(*declared: str) -> dict:
    target = config.load_target("example-widgets")
    target["plugins"] = list(declared or ALL)
    return target


def _base(target: dict | None = None) -> observe.Result:
    opts = observe.Options(now=BASE_TIME, offline=True, announce=lambda _line: None)
    return observe.observe(target or _target(), opts)


def _rerun(*names: str, target: dict | None = None, base: str | Path = "2030-01-31T0930Z",
           now: datetime = LATER) -> observe.Result:
    return rerun.rerun(target or _target(), base, rerun.Options(plugins=names, now=now))


def _stored(obs: Path) -> list[dict]:
    return json.loads((obs / "assets.json").read_text())


def _observations(root: Path) -> set[str]:
    return {p.name for p in (root / "observations").iterdir() if not p.is_symlink()}


# ── what is carried and what is read again ──

def test_carried_rows_are_written_exactly_as_stored(workspace):
    base = _base()
    _write(workspace, "disks", "disk-01.example.test,off", "disk-03.example.test,on")
    _write(workspace, "laptops", "laptop-09.example.test,off")  # changed, but not re-read
    derived = _rerun("disks")
    # The late step's row is written again by every rerun, so it is not carried.
    before = [r for r in _stored(base.observation) if r["source"] not in ("disks", "late-step")]
    after = [r for r in _stored(derived.observation) if r["source"] not in ("disks", "late-step")]
    assert after == before
    assert {r["host"] for r in after if r["source"] == "laptops"} == {
        "laptop-01.example.test", "laptop-02.example.test"}


def test_the_named_plugins_rows_are_read_again(workspace):
    _base()
    _write(workspace, "disks", "disk-01.example.test,off", "disk-03.example.test,on")
    derived = _rerun("disks")
    disks = {r["host"]: r for r in _stored(derived.observation) if r["source"] == "disks"}
    assert set(disks) == {"disk-01.example.test", "disk-03.example.test"}
    assert disks["disk-01.example.test"]["verdict"] == "weak"
    # Dated as a full observation dates a plug-in row: by its input file.
    assert disks["disk-01.example.test"]["collected_at"] == file_mtime_date(
        workspace / "inbox" / "disks.csv")


def test_new_rows_take_the_place_of_the_old(workspace):
    base = _base()
    _write(workspace, "disks", "disk-07.example.test,on")
    derived = _rerun("disks")
    sources_before = [r["source"] for r in _stored(base.observation)]
    sources_after = [r["source"] for r in _stored(derived.observation)]
    first = sources_before.index("disks")
    assert sources_after[first] == "disks"
    assert sources_after[:first] == sources_before[:first]
    assert sources_after[first + 1:] == [s for s in sources_before[first:] if s != "disks"]


def test_a_plugin_that_wrote_no_rows_goes_after_its_neighbour(workspace):
    (workspace / "inbox" / "disks.csv").unlink()
    base = _base()
    assert not [r for r in _stored(base.observation) if r["source"] == "disks"]
    assert [g for g in base.summary["gaps"] if "plug-in `disks`" in g]
    _write(workspace, "disks", "disk-05.example.test,on")
    derived = _rerun("disks")
    sources = [r["source"] for r in _stored(derived.observation)]
    last_laptop = max(n for n, s in enumerate(sources) if s == "laptops")
    assert sources[last_laptop + 1] == "disks"
    assert not [g for g in derived.summary["gaps"] if "plug-in `disks`" in g and "not run" in g]


def test_annotations_label_the_new_rows(workspace):
    _base()
    _write(workspace, "disks", "disk-08.example.test,on")
    derived = _rerun("disks")
    (row,) = [r for r in _stored(derived.observation) if r["source"] == "disks"]
    assert row["extra"]["tag"] == "seen-disks"


def test_the_named_plugins_gaps_are_replaced_and_others_kept(workspace):
    base = _base()
    _write(workspace, "disks", "disk-01.example.test,on")
    derived = _rerun("disks")
    gaps = derived.summary["gaps"]
    assert "plug-in `disks`: disks read 1 line(s)" in gaps
    assert "plug-in `disks`: disks read 2 line(s)" not in gaps
    assert "plug-in `laptops`: laptops read 2 line(s)" in gaps
    record = derived.summary[rerun.SUMMARY_KEY]
    assert record["gaps_dropped"] == 1
    assert record["gaps_added"] == ["plug-in `disks`: disks read 1 line(s)"]
    assert len(gaps) == len(base.summary["gaps"])


def _quiet(monkeypatch: pytest.MonkeyPatch, *others: Plugin) -> dict:
    """A reader whose gaps do not name it, declared with ``others``."""
    def step(ctx: Context) -> StepResult:
        assert ctx.input is not None
        lines = ctx.input.read_text().splitlines()
        return StepResult(gaps=[f"the quiet reader read {len(lines)} line(s)"])
    _install(monkeypatch, Plugin(name="quiet", kind="general", step=step,
                                 input="inbox/quiet.csv", gap_prefix=False), *others)
    return _target("quiet", *(p.name for p in others))


def test_a_reread_plugins_earlier_gaps_give_way_though_they_do_not_name_it(workspace,
                                                                            monkeypatch):
    target = _quiet(monkeypatch)
    _write(workspace, "quiet", "a", "b")
    _base(target)
    same = _rerun("quiet", target=target)
    assert same.summary["gaps"].count("the quiet reader read 2 line(s)") == 1
    _write(workspace, "quiet", "a")
    moved = _rerun("quiet", target=target, now=LATER + timedelta(hours=1))
    assert "the quiet reader read 1 line(s)" in moved.summary["gaps"]
    assert "the quiet reader read 2 line(s)" not in moved.summary["gaps"]
    record = moved.summary[rerun.SUMMARY_KEY]
    assert record["gaps_added"] == ["the quiet reader read 1 line(s)"]
    assert record["gaps_dropped_by"] == {"origin": 1}
    assert record["gaps_without_origin"] == 0


def _forget_origins(obs: Path) -> None:
    """Make ``obs`` look like an observation written before gap origins were recorded."""
    summary = json.loads((obs / "summary.json").read_text())
    del summary["gap_origins"]
    (obs / "summary.json").write_text(json.dumps(summary))


def test_without_recorded_origins_a_reread_plugins_reworded_gap_gives_way(workspace,
                                                                          monkeypatch):
    target = _quiet(monkeypatch, _reader("laptops"))
    _write(workspace, "quiet", "a", "b")
    _write(workspace, "laptops", "laptop-01.example.test,on")
    base = _base(target)
    _forget_origins(base.observation)
    _write(workspace, "quiet", "a", "b", "c")
    derived = _rerun("quiet", target=target)
    gaps = derived.summary["gaps"]
    assert "the quiet reader read 3 line(s)" in gaps
    assert "the quiet reader read 2 line(s)" not in gaps
    # Another reader's gap, whatever its figures, is not the re-read one's.
    assert "plug-in `laptops`: laptops read 1 line(s)" in gaps
    assert derived.summary[rerun.SUMMARY_KEY]["gaps_dropped_by"] == {"reworded": 1}


@pytest.mark.parametrize("text, shape", [
    ("12 widgets were not read in full: alpha (3), beta (2)", "# widgets were not read in full"),
    ("the reader read 99.5 line(s). The rest were blank", "the reader read # line(s)"),
    ("3 hosts", ""),
])
def test_a_gaps_shape_is_its_first_clause_with_figures_masked(text, shape):
    assert rerun._shape(text) == shape


def test_each_gap_records_the_step_it_is_about(workspace):
    base = _base()
    gaps, origins = base.summary["gaps"], base.summary["gap_origins"]
    assert len(origins) == len(gaps)
    by_text = dict(zip(gaps, origins, strict=True))
    assert by_text["plug-in `disks`: disks read 2 line(s)"] == "disks"
    assert by_text["plug-in `laptops`: laptops read 2 line(s)"] == "laptops"
    # A gap about the run as a whole is no step's.
    assert any(o == "" and "collector(s) not run" in g for g, o in by_text.items())
    derived = _rerun("disks")
    assert len(derived.summary["gap_origins"]) == len(derived.summary["gaps"])


# ── the steps that read the rest of the observation run again ──

def _tally() -> Plugin:
    """A late step writing one row that counts the rows each reader wrote."""
    def step(ctx: Context) -> StepResult:
        counts = {}
        for a in ctx.assets:
            counts[a.source] = counts.get(a.source, 0) + 1
        return StepResult(records=[CryptoAsset(
            name="row tally", data_state="inventory", host="tally.example.test",
            verdict="unknown",
            notes="; ".join(f"{k}: {v}" for k, v in sorted(counts.items())))])
    return Plugin(name="tally", kind="general", step=step, late=True, gap_prefix=False)


def _reach() -> Plugin:
    """A coverage check filing one unprefixed gap over the devices the readers reached."""
    def step(ctx: Context) -> StepResult:
        hosts = {a.host for a in ctx.assets if a.host.startswith(("disk-", "laptop-"))}
        return StepResult(gaps=[f"device coverage: {len(hosts)} device(s) reached"])
    return Plugin(name="reach", kind="coverage-check", step=step, gap_prefix=False)


def _labels() -> Plugin:
    """An annotation filing one gap over every row it labels."""
    def step(ctx: Context) -> StepResult:
        disks = [a for a in ctx.assets if a.source == "disks"]
        return StepResult(annotations={a.bom_ref(): {"label": "disk"} for a in disks},
                          gaps=[f"{len(disks)} disk row(s) labelled"])
    return Plugin(name="labels", kind="annotation", step=step, annotation_keys=("label",),
                  gap_prefix=False)


READ_AGAIN = ("laptops", "disks", "servers", "tally", "reach", "labels")


@pytest.fixture()
def counted(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """The three readers with a late step, a coverage check and an annotation that read them."""
    _install(monkeypatch, _reader("laptops"), _reader("disks"), _reader("servers"), _tally(),
             _reach(), _labels())
    return _target(*READ_AGAIN)


def _late_view(result: observe.Result) -> tuple[list[str], list[str]]:
    """The late step's row notes, and the coverage check's and annotation's gaps."""
    rows = [r["notes"] for r in _stored(result.observation) if r["source"] == "tally"]
    gaps = [g for g in result.summary["gaps"]
            if g.startswith("device coverage") or "labelled" in g]
    return rows, sorted(gaps)


def _grow_disks(workspace: Path) -> None:
    _write(workspace, "disks", "disk-01.example.test,on", "disk-03.example.test,off",
           "disk-04.example.test,on", "disk-05.example.test,on")


def test_the_late_steps_and_checks_match_a_full_observation_on_the_same_inputs(workspace,
                                                                                counted):
    base = _base(counted)
    _grow_disks(workspace)
    derived = _rerun("disks", target=counted)
    full = observe.observe(counted, observe.Options(
        now=LATER + timedelta(hours=1), offline=True, announce=lambda _line: None))
    assert _late_view(derived) == _late_view(full)
    assert _late_view(derived) != _late_view(base)
    rows, gaps = _late_view(derived)
    assert len(rows) == 1 and "disks: 4; " in rows[0] and "tally" not in rows[0]
    assert gaps == ["4 disk row(s) labelled", "device coverage: 6 device(s) reached"]
    assert len(derived.summary["gaps"]) == len(set(derived.summary["gaps"]))
    record = derived.summary[rerun.SUMMARY_KEY]
    assert record["run_over_rows"] == ["tally", "reach", "labels"]
    assert record["rows_added"] == {"disks": 4, "tally": 1}


def test_the_late_step_sees_every_row_but_its_own(workspace, counted):
    _base(counted)
    derived = _rerun("servers", target=counted)
    (row,) = [r for r in _stored(derived.observation) if r["source"] == "tally"]
    assert "tally" not in row["notes"]
    assert row["collected_at"] == derived.summary["observation"]["collected_at"][:10]


def test_an_observation_that_recorded_no_origins_drops_the_later_steps_earlier_gaps(
        workspace, counted):
    base = _base(counted)
    _forget_origins(base.observation)
    _grow_disks(workspace)
    derived = _rerun("disks", target=counted)
    gaps = derived.summary["gaps"]
    assert "device coverage: 4 device(s) reached" not in gaps
    assert "2 disk row(s) labelled" not in gaps
    assert {"device coverage: 6 device(s) reached", "4 disk row(s) labelled"} <= set(gaps)
    assert len(gaps) == len(set(gaps))
    record = derived.summary[rerun.SUMMARY_KEY]
    assert record["gaps_dropped_by"]["replayed"] == 2
    # The derived observation records origins for what it wrote; what it kept stays unknown.
    origins = dict(zip(gaps, derived.summary["gap_origins"], strict=True))
    assert origins["device coverage: 6 device(s) reached"] == "reach"
    assert origins["plug-in `laptops`: laptops read 2 line(s)"] is None
    assert record["gaps_without_origin"] == sum(o is None for o in origins.values())


def test_the_observation_records_that_it_is_derived(workspace):
    base = _base()
    derived = _rerun("disks", "servers")
    record = derived.summary[rerun.SUMMARY_KEY]
    assert record["from_observation"] == base.observation.name
    assert record["from_collected_at"] == "2030-01-31T09:30:00Z"
    assert record["plugins"] == ["disks", "servers"]
    assert record["run_over_rows"] == ["late-step", "tags"]
    assert record["rows_dropped"] == {"disks": 2, "late-step": 1, "servers": 1}
    assert record["rows_added"] == {"disks": 2, "late-step": 1, "servers": 1}
    assert record["rows_carried"] == len(base.assets) - 4
    block = derived.summary["observation"]
    assert block["stamp"] == "2030-02-03T0930Z" and block["offline"] is True
    assert block["scan"] is False
    bom = json.loads((derived.observation / "bom.cdx.json").read_text())
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props[rerun.DERIVED_PROPERTY] == base.observation.name
    assert derived.summary["total_assets"] == len(_stored(derived.observation))
    assert (workspace / "observations" / "latest").resolve() == derived.observation.resolve()


def test_the_carried_rows_dispositions_digest_is_kept(workspace):
    base = _base()
    summary = json.loads((base.observation / "summary.json").read_text())
    summary["observation"]["dispositions_digest"] = "sha256:an-earlier-set"
    (base.observation / "summary.json").write_text(json.dumps(summary))
    derived = _rerun("disks")
    assert derived.summary["observation"]["dispositions_digest"] == "sha256:an-earlier-set"
    assert derived.summary[rerun.SUMMARY_KEY]["dispositions_digest"] == set_digest(
        load_dispositions_for_target(_target()))


def test_raw_files_are_copied_except_the_named_plugins_own(workspace):
    base = _base()
    (base.observation / "raw" / "transcript.txt").write_text("kept\n")
    (base.observation / "raw" / "plugins" / "disks" / "old.txt").write_text("old\n")
    derived = _rerun("disks")
    raw = derived.observation / "raw"
    assert (raw / "transcript.txt").read_text() == "kept\n"
    assert not (raw / "plugins" / "disks" / "old.txt").exists()
    assert (raw / "plugins" / "laptops").is_dir()


def test_what_grading_again_would_change_is_counted_not_applied(workspace):
    base = _base()
    rows = _stored(base.observation)
    changed = next(n for n, r in enumerate(rows) if r["source"] == "laptops")
    # As an earlier version of a rule might have stored it.
    rows[changed]["disposition_reason"] = "a reason an earlier rule wrote"
    (base.observation / "assets.json").write_text(json.dumps(rows))
    derived = _rerun("disks")
    kept = [r for r in _stored(derived.observation) if r["name"] == rows[changed]["name"]]
    assert kept[0]["disposition_reason"] == "a reason an earlier rule wrote"
    differ = derived.summary[rerun.SUMMARY_KEY]["carried_rows_graded_differently"]
    assert differ["rows"] == 1 and differ["by_source"] == {"laptops": 1}
    assert differ["by_field"] == {"disposition_reason": 1}


def test_a_derived_observation_can_be_derived_from_again(workspace):
    _base()
    first = _rerun("disks")
    second = _rerun("servers", base=first.observation, now=LATER + timedelta(hours=1))
    record = second.summary[rerun.SUMMARY_KEY]
    assert record["from_observation"] == first.observation.name
    assert record["from_rerun"]["from_observation"] == "2030-01-31T0930Z"


def test_the_register_dates_each_fact_by_the_observation_that_read_its_row(workspace):
    _base()
    # Each export dated the day it is read again, so its rows' collection
    # date does not come before the read.
    for name, when in (("disks", LATER), ("servers", LATER + timedelta(days=1))):
        os.utime(workspace / "inbox" / f"{name}.csv", (when.timestamp(), when.timestamp()))
    first = _rerun("disks")
    second = _rerun("servers", base=first.observation, now=LATER + timedelta(days=1))
    register = cmdb.build(second.observation)
    recorded: dict[str, set[str]] = {}
    for a in register.assertions:
        if a.attribute == "hostname":
            recorded.setdefault(str(a.value), set()).add(a.recorded_at)
    assert recorded["laptop-01.example.test"] == {"2030-01-31"}
    assert recorded["disk-01.example.test"] == {"2030-02-03"}
    assert recorded["server-01.example.test"] == {"2030-02-04"}
    assert register.recorded_at == "2030-01-31"


# ── never mistaken for a fresh measurement ──

def test_a_derived_observation_is_never_carried(workspace):
    _base()
    derived = _rerun("disks")
    with pytest.raises(carry.CarryRefused, match="derived from an earlier observation"):
        carry.load(derived.observation, _target(), workspace / "observations", LATER,
                   organisation=observe._organisation(_target()))


def _ct_answer(obs: Path, derived: bool) -> None:
    (obs / "raw").mkdir(parents=True)
    (obs / "raw" / ctcache.raw_name("example.com")).write_text("[]")
    (obs / "raw" / ctcache.pages_name("example.com")).write_text('{"exhausted": true}')
    (obs / ctcache.COMPLETION_MARKER).write_text("{}")
    summary = {rerun.SUMMARY_KEY: {"from_observation": "2030-01-17T0815Z"}} if derived else {}
    (obs / "summary.json").write_text(json.dumps(summary))


@pytest.mark.parametrize("derived", [False, True])
def test_a_derived_observations_ct_answers_are_not_reused(tmp_path, derived):
    _ct_answer(tmp_path / "2030-01-31T0930Z", derived)
    found = ctcache.find("example.com", tmp_path, ref_time=BASE_TIME + timedelta(hours=1))
    assert (found is None) is derived


# ── refusals ──

@pytest.mark.parametrize("names, code", [
    ((), "rerun-nothing-named"),
    (("disks", "disks"), "rerun-named-twice"),
    (("nobody",), "rerun-not-declared"),
    (("netdev",), "rerun-not-declared"),
    (("tags",), "rerun-reads-the-observation"),
    (("late-step",), "rerun-reads-the-observation"),
], ids=["nothing", "twice", "nobody", "builtin", "annotation", "late"])
def test_what_cannot_be_read_again_is_refused(workspace, names, code):
    _base()
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun(*names)
    assert exc.value.code == code
    assert _observations(workspace) == {"2030-01-31T0930Z"}


def test_a_builtin_collector_is_named_as_one(workspace):
    _base()
    with pytest.raises(rerun.RerunRefused, match="'netdev' is a built-in collector"):
        _rerun("netdev")


def test_a_plugin_whose_input_has_gone_is_refused_and_nothing_left(workspace):
    _base()
    (workspace / "inbox" / "disks.csv").unlink()
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-not-run" and "was not supplied" in str(exc.value)
    assert _observations(workspace) == {"2030-01-31T0930Z"}


def test_a_malformed_dictionary_overlay_is_refused_and_nothing_left(workspace):
    _base()
    (workspace / "targets" / "example-widgets.daemon-dictionary.yaml").write_text(
        "daemon_dictionary:\n  widgetsrv:\n    product: Widget Server\n")
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-dictionary" and "missing vendor" in str(exc.value)
    assert _observations(workspace) == {"2030-01-31T0930Z"}


def test_a_shared_source_is_refused(workspace, monkeypatch):
    def step(ctx: Context) -> StepResult:
        return StepResult()
    _install(monkeypatch, *(Plugin(name=n, kind="mail-transport", step=step)
                            for n in ("relay-a", "relay-b")))
    target = _target("relay-a", "relay-b")
    _base(target)
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("relay-a", target=target)
    assert exc.value.code == "rerun-shared-source"


def test_two_named_plugins_sharing_a_source_are_refused(workspace, monkeypatch):
    def step(ctx: Context) -> StepResult:
        return StepResult()
    _install(monkeypatch, *(Plugin(name=n, kind="mail-transport", step=step)
                            for n in ("relay-a", "relay-b")))
    target = _target("relay-a", "relay-b")
    _base(target)
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("relay-a", "relay-b", target=target)
    assert exc.value.code == "rerun-shared-source"
    assert _observations(workspace) == {"2030-01-31T0930Z"}


def test_a_row_merged_across_the_line_is_refused(workspace):
    base = _base()
    rows = _stored(base.observation)
    row = next(r for r in rows if r["source"] == "laptops")
    row["extra"]["merged_sources"] = ["laptops", "disks"]
    (base.observation / "assets.json").write_text(json.dumps(rows))
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-merged-row"


def test_a_new_row_that_would_merge_with_a_carried_one_is_refused(workspace):
    _base()
    _write(workspace, "disks", "disk-01.example.test,on")
    rows = _stored(workspace / "observations" / "2030-01-31T0930Z")
    clash = next(r for r in rows if r["source"] == "laptops")
    clash["name"] = "disks disk-01.example.test"
    clash["host"] = "disk-01.example.test"
    (workspace / "observations" / "2030-01-31T0930Z" / "assets.json").write_text(json.dumps(rows))
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-merged-row"
    assert _observations(workspace) == {"2030-01-31T0930Z"}


def test_an_observation_with_no_run_record_is_refused(workspace):
    base = _base()
    summary = json.loads((base.observation / "summary.json").read_text())
    del summary["observation"]
    (base.observation / "summary.json").write_text(json.dumps(summary))
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-no-record"


def test_another_targets_observation_is_refused(workspace):
    base = _base()
    summary = json.loads((base.observation / "summary.json").read_text())
    summary["observation"]["target"] = "targets/another.yaml"
    (base.observation / "summary.json").write_text(json.dumps(summary))
    with pytest.raises(rerun.RerunRefused) as exc:
        _rerun("disks")
    assert exc.value.code == "rerun-other-target"


# ── the command ──

def _declare_in_profile(root: Path) -> None:
    profile = root / "targets" / "example-widgets.yaml"
    profile.write_text(profile.read_text() + "\nplugins: [" + ", ".join(ALL) + "]\n")


def test_the_command_writes_a_derived_observation(workspace, capsys):
    _declare_in_profile(workspace)
    _base()
    code = cli.main(["rerun", "example-widgets", "--from", "2030-01-31T0930Z",
                     "--plugin", "disks", "--workspace", str(workspace)])
    captured = capsys.readouterr()
    out = captured.out
    assert code in (0, 1), captured.err
    assert "carried from 2030-01-31T0930Z" in out
    assert out.splitlines()[0].startswith("observations/")


def test_the_command_reports_a_refusal(workspace, capsys):
    _declare_in_profile(workspace)
    _base()
    code = cli.main(["rerun", "example-widgets", "--from", "2030-01-31T0930Z",
                     "--plugin", "tags", "--workspace", str(workspace)])
    assert code == 2
    assert "REFUSED, nothing written" in capsys.readouterr().err
