"""Archiving past observations, and reusing a recent certificate-transparency answer."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import ctcache, obsarchive

NOW = datetime(2030, 6, 15, 12, 0, tzinfo=UTC)


def _observation(root: Path, stamp: str, *, complete: bool = True, domain: str = "example.com",
                 exhausted: bool | None = True, payload: object = None) -> Path:
    obs = root / stamp
    (obs / "raw").mkdir(parents=True)
    (obs / "evidence").mkdir()
    (obs / "evidence" / "bulk.txt").write_text("evidence\n")
    (obs / "notes.txt").write_text("middle tier\n")
    if complete:
        (obs / "bom.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX"}))
    if payload is not None:
        (obs / "raw" / ctcache.raw_name(domain)).write_text(json.dumps(payload))
    if exhausted is not None:
        (obs / "raw" / ctcache.pages_name(domain)).write_text(json.dumps({"exhausted": exhausted}))
    return obs


def test_stamps_and_tiers():
    assert obsarchive.is_stamp("2030-06-15T1200Z")
    assert not obsarchive.is_stamp("latest")
    assert obsarchive.is_light("bom.cdx.json")
    assert obsarchive.is_light("raw/" + ctcache.raw_name("example.com"))
    assert not obsarchive.is_light("evidence/bulk.txt")


def test_past_observations_are_archived_and_still_readable(tmp_path):
    old = _observation(tmp_path, "2030-06-01T0000Z", payload=[{"id": "1"}])
    _observation(tmp_path, "2030-06-15T1200Z")
    (tmp_path / "latest").symlink_to("2030-06-15T1200Z")
    said: list[str] = []
    done, kept = obsarchive.archive_past(tmp_path, say=said.append)
    assert done == ["2030-06-01T0000Z"] and kept == [] and not old.exists()
    assert (tmp_path / "2030-06-01T0000Z.tgz").is_file()
    entry = obsarchive.read_manifest(tmp_path)["archives"][0]
    assert obsarchive.archive_matches(tmp_path, entry) == []
    paths = [m["path"] for m in entry["members"]]
    assert paths.index("bom.cdx.json") < paths.index("notes.txt") < paths.index("evidence/bulk.txt")

    listed = obsarchive.observations(tmp_path)
    assert [p.name for p in listed] == ["2030-06-01T0000Z", "2030-06-15T1200Z"]
    unpacked = listed[0]
    assert (unpacked / "bom.cdx.json").is_file()
    assert not (unpacked / "evidence" / "bulk.txt").exists()  # light tier only
    full = obsarchive.extract(tmp_path, "2030-06-01T0000Z", tmp_path / "full")
    assert (full / "evidence" / "bulk.txt").read_text() == "evidence\n"


def test_a_dry_run_changes_nothing(tmp_path):
    _observation(tmp_path, "2030-06-01T0000Z")
    _observation(tmp_path, "2030-06-15T1200Z")
    (tmp_path / "latest").symlink_to("2030-06-15T1200Z")
    said: list[str] = []
    assert obsarchive.archive_past(tmp_path, dry_run=True, say=said.append) == ([], [])
    assert said == ["would archive 2030-06-01T0000Z"]
    assert (tmp_path / "2030-06-01T0000Z").is_dir()


def test_a_manifest_may_hold_only_sizes_and_hashes(tmp_path):
    bad = {"archives": [{"observation": "x", "sha256": "0" * 64,
                         "members": [{"path": "a", "type": "file", "sha256": "0" * 64,
                                      "content": "secret"}]}]}
    with pytest.raises(ValueError):
        obsarchive.write_manifest(tmp_path, bad)
    assert obsarchive.check_shape({"archives": [{"observation": "y", "sha256": "nope",
                                                 "members": []}]})


def test_a_tampered_archive_is_detected(tmp_path):
    _observation(tmp_path, "2030-06-01T0000Z")
    entry = obsarchive.archive(tmp_path / "2030-06-01T0000Z")
    entry["members"][0]["sha256"] = "f" * 64
    assert obsarchive.archive_matches(tmp_path, entry)
    assert obsarchive.archive_matches(tmp_path, {**entry, "archive": "missing.tgz"}) == [
        "archive missing: missing.tgz"]


def test_a_recent_complete_answer_is_reused(tmp_path):
    _observation(tmp_path, "2030-06-15T0000Z", payload=[{"id": "7"}])
    got = ctcache.find("example.com", tmp_path, ref_time=NOW)
    assert got is not None and got.payload == [{"id": "7"}]
    assert (got.observation, got.observed, got.age_days) == ("2030-06-15T0000Z", "2030-06-15", 0)


@pytest.mark.parametrize("kwargs", [
    {"complete": False},
    {"exhausted": False},
    {"exhausted": None},
    {"payload": {"not": "a list"}},
])
def test_an_unfinished_or_partial_answer_is_not_reused(tmp_path, kwargs):
    args = {"payload": [{"id": "7"}], **kwargs}
    _observation(tmp_path, "2030-06-15T0000Z", **args)
    assert ctcache.find("example.com", tmp_path, ref_time=NOW) is None


def test_an_old_answer_is_not_reused(tmp_path):
    _observation(tmp_path, "2030-06-01T0000Z", payload=[])
    assert ctcache.find("example.com", tmp_path, ref_time=NOW) is None
    assert ctcache.find("example.com", tmp_path, max_age_days=30, ref_time=NOW) is not None
    assert ctcache.find("example.com", tmp_path / "absent", ref_time=NOW) is None


def test_reuse_is_reported_and_stale_answers_refuse_a_commit():
    fresh = ctcache.Cached([], "2030-06-15", "2030-06-15T0000Z", 0, "example.com")
    stale = ctcache.Cached([], "2030-06-01", "2030-06-01T0000Z", 14, "example.net")
    assert "up to 14d old" in ctcache.reuse_gap([fresh, stale])
    summary = ctcache.summarise([stale, fresh], ["example.com", "example.net", "example.org"],
                                2, False)
    assert (summary["hits"], summary["misses"], summary["oldest_age_days"]) == (2, 1, 14)
    assert ctcache.commit_refusal([fresh]) == ""
    assert "example.net from 2030-06-01T0000Z" in ctcache.commit_refusal([fresh, stale])


def test_rate_limit_detail():
    assert ctcache.rate_limit_detail({}) == ""
    assert ctcache.rate_limit_detail({"status": 429, "headers": {"retry-after": "60"}}) == (
        " (HTTP 429; retry-after=60)")


def test_a_registered_completion_marker_marks_a_finished_observation(tmp_path, monkeypatch):
    monkeypatch.setattr(ctcache, "_registered_markers", [])
    obs = _observation(tmp_path, "2030-06-15T0000Z", complete=False, payload=[{"id": "7"}])
    (obs / "finished.json").write_text(json.dumps({"done": True}))
    assert ctcache.find("example.com", tmp_path, ref_time=NOW) is None
    ctcache.register_completion_marker("finished.json", "finished.json")
    assert ctcache.completion_markers() == ("bom.cdx.json", "finished.json")
    got = ctcache.find("example.com", tmp_path, ref_time=NOW)
    assert got is not None and got.payload == [{"id": "7"}]
    (obs / "finished.json").write_text("{not json")
    assert ctcache.find("example.com", tmp_path, ref_time=NOW) is None


@pytest.mark.parametrize("name", ["", "raw/finished.json", ".."])
def test_a_completion_marker_is_a_plain_file_name(name, monkeypatch):
    monkeypatch.setattr(ctcache, "_registered_markers", [])
    with pytest.raises(ValueError):
        ctcache.register_completion_marker(name)


def _archive_one(root: Path) -> Path:
    obs = _observation(root, "2030-06-01T0000Z")
    (obs / "finished.json").write_text(json.dumps({"done": True}))
    _observation(root, "2030-06-15T1200Z")
    (root / "latest").symlink_to("2030-06-15T1200Z")
    done, kept = obsarchive.archive_past(root, say=lambda _line: None)
    assert done == ["2030-06-01T0000Z"] and kept == []
    return root / obsarchive.UNPACKED / "2030-06-01T0000Z"


def test_a_registered_light_file_is_stored_and_unpacked_with_the_results(tmp_path, monkeypatch):
    monkeypatch.setattr(obsarchive, "_registered_light", [])
    assert not obsarchive.is_light("finished.json")
    obsarchive.register_light_file("finished.json", "finished.json")
    assert obsarchive.light_files() == ("bom.cdx.json", "assets.json", "summary.json",
                                        "finished.json")
    assert obsarchive.is_light("finished.json")
    _archive_one(tmp_path)
    entry = obsarchive.read_manifest(tmp_path)["archives"][0]
    paths = [m["path"] for m in entry["members"]]
    assert paths.index("finished.json") < paths.index("notes.txt")
    (unpacked,) = [p for p in obsarchive.observations(tmp_path) if p.name == "2030-06-01T0000Z"]
    assert (unpacked / "finished.json").is_file()
    assert not (unpacked / "notes.txt").exists() and not (unpacked / "evidence").exists()


def test_a_light_file_registered_after_archiving_is_still_found(tmp_path, monkeypatch):
    monkeypatch.setattr(obsarchive, "_registered_light", [])
    home = _archive_one(tmp_path)
    obsarchive.observations(tmp_path)
    assert not (home / "finished.json").exists()  # unpacked before it was registered
    obsarchive.register_light_file("finished.json")
    (unpacked,) = [p for p in obsarchive.observations(tmp_path) if p.name == "2030-06-01T0000Z"]
    assert (unpacked / "finished.json").is_file()
    assert not (unpacked / "evidence").exists()


@pytest.mark.parametrize("name", ["", "raw/finished.json", ".."])
def test_a_light_file_is_a_plain_file_name(name, monkeypatch):
    monkeypatch.setattr(obsarchive, "_registered_light", [])
    with pytest.raises(ValueError):
        obsarchive.register_light_file(name)
