"""Post-quantum positions: the format, its provenance checks, the overlay and the match."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from takestock import config
from takestock import pqc_positions as pq

TODAY = dt.date(2030, 6, 1)

ENTRY = """\
  - key: example-cloud
    provider: Example Cloud
    state: shipped
    since: release 7
    summary: Hybrid key exchange is on by default
    detail: Applies to the managed load balancer
    source: https://example.com/pq
    publisher: Example Cloud
    published: 2030-01-10
    read: 2030-02-01
    recheck_by: 2030-12-01
    dimensions: key exchange only
    products: [Example Balancer]
"""


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _profile(tmp_path: Path, overlay: str | None = None) -> dict:
    prof = _write(tmp_path / "targets" / "widgets.yaml", "name: widgets\n")
    if overlay is not None:
        _write(tmp_path / "targets" / "widgets.pqc-positions.yaml", overlay)
    return {"_path": str(prof)}


def _bundled(tmp_path: Path, body: str) -> None:
    # A named workspace's data/ copy stands in for the bundled file.
    _write(tmp_path / "data" / pq.BUNDLED_FILE, body)
    config.set_workspace(tmp_path)


def _one(tmp_path: Path, body: str, today: dt.date = TODAY) -> pq.Positions:
    return pq.load(_profile(tmp_path, body), today=today)


# --- the file and its overlay -------------------------------------------------

def test_nothing_ships_and_nothing_is_recorded(tmp_path):
    assert not (config.BUNDLED_DATA_DIR / pq.BUNDLED_FILE).exists()
    got = pq.load(_profile(tmp_path), today=TODAY)
    assert len(got) == 0 and got.sources == () and got.stale == ()


def test_the_suffix_is_an_overlay_not_a_profile(tmp_path):
    _profile(tmp_path, "positions: []\n")
    assert config.is_overlay(tmp_path / "targets" / "widgets.pqc-positions.yaml")
    assert [p.name for p in config.target_profiles(tmp_path / "targets")] == ["widgets.yaml"]


def test_an_entry_reads_with_every_field(tmp_path):
    got = _one(tmp_path, "schema: 1\npositions:\n" + ENTRY)
    (p,) = got.entries
    assert p.key == "example-cloud" and p.provider == "Example Cloud"
    assert p.state == "shipped" and p.since == "release 7"
    assert p.read == dt.date(2030, 2, 1) and p.published == dt.date(2030, 1, 10)
    assert p.recheck_by == dt.date(2030, 12, 1) and p.recheck_stated
    assert p.products == ("Example Balancer",) and p.client_side and not p.stale
    assert got.sources == (str(tmp_path / "targets" / "widgets.pqc-positions.yaml"),)


def test_the_overlay_replaces_a_bundled_entry_with_its_key_and_adds_the_rest(tmp_path):
    _bundled(tmp_path, """\
positions:
  - {key: example-cloud, provider: Example Cloud, state: planned,
     source: "https://example.com/old", read: 2030-01-05}
  - {key: sample-mail, provider: Sample Mail, state: silent,
     source: "https://example.net/faq", read: 2030-01-06}
""")
    got = pq.load(_profile(tmp_path, "positions:\n" + ENTRY), today=TODAY)
    by_key = {p.key: p for p in got}
    assert set(by_key) == {"example-cloud", "sample-mail"}
    assert by_key["example-cloud"].state == "shipped" and by_key["example-cloud"].client_side
    assert by_key["sample-mail"].state == "silent" and not by_key["sample-mail"].client_side
    assert got.sources == (str(tmp_path / "data" / pq.BUNDLED_FILE),
                           str(tmp_path / "targets" / "widgets.pqc-positions.yaml"))


def test_the_key_defaults_to_the_provider(tmp_path):
    got = _one(tmp_path, """\
positions:
  - {provider: Sample Mail, state: planned, source: "https://example.net/x", read: 2030-03-01}
""")
    assert got.entries[0].key == "Sample Mail"


# --- refusals -----------------------------------------------------------------

@pytest.mark.parametrize("drop, says", [
    ("    source: https://example.com/pq\n", "no `source:`"),
    ("    read: 2030-02-01\n", "no `read:` date"),
])
def test_an_entry_without_its_provenance_is_refused(tmp_path, drop, says):
    with pytest.raises(ValueError, match=says):
        _one(tmp_path, "positions:\n" + ENTRY.replace(drop, ""))


@pytest.mark.parametrize("old, new, says", [
    ("state: shipped", "state: rumoured", "is not one of"),
    ("    provider: Example Cloud\n", "", "has no `provider:`"),
    ("read: 2030-02-01", "read: 2030-07-01", "later than today"),
    ("read: 2030-02-01", "read: first of February", "must be a date"),
    ("read: 2030-02-01", "read: 2030-02-01 09:30:00", "not a date and time"),
    ("published: 2030-01-10", "published: 2030-03-10", "later than `read`"),
    ("recheck_by: 2030-12-01", "recheck_by: 2030-01-20", "earlier than `read`"),
    ("recheck_by: 2030-12-01", "recheck-by: 2030-12-01", "unknown field"),
    ("products: [Example Balancer]", "products: Example Balancer", "list of text"),
    ("summary: Hybrid key exchange is on by default", "summary: 42", "must be text"),
])
def test_a_malformed_entry_is_refused(tmp_path, old, new, says):
    assert old in ENTRY
    with pytest.raises(ValueError, match=says):
        _one(tmp_path, "positions:\n" + ENTRY.replace(old, new))


@pytest.mark.parametrize("head, says", [
    ("schema: 2\n", "schema 2"),
    ("notes: hello\n", "unexpected top-level"),
    ("recheck_after_days: 0\n", "whole number of days"),
])
def test_a_malformed_file_is_refused(tmp_path, head, says):
    with pytest.raises(ValueError, match=says):
        _one(tmp_path, head + "positions:\n" + ENTRY)


def test_a_key_given_twice_in_one_file_is_refused(tmp_path):
    with pytest.raises(ValueError, match="given twice"):
        _one(tmp_path, "positions:\n" + ENTRY + ENTRY)


# --- staleness ----------------------------------------------------------------

def test_an_entry_past_its_stated_recheck_date_is_reported(tmp_path):
    got = _one(tmp_path, "positions:\n" + ENTRY, today=dt.date(2030, 12, 2))
    (p,) = got.entries
    assert p.stale
    (warn,) = got.stale
    assert warn.provider == "Example Cloud" and warn.recheck_stated
    assert "2030-12-01" in warn.message and "stated re-check date" in warn.message
    assert p.payload()["stale"] is True
    assert p.line().endswith("Due for re-checking since 2030-12-01: the provider's "
                             "position may have changed since it was read")


def test_on_its_recheck_date_an_entry_is_not_yet_stale(tmp_path):
    got = _one(tmp_path, "positions:\n" + ENTRY, today=dt.date(2030, 12, 1))
    assert got.stale == () and "re-checking" not in got.entries[0].line()


def test_without_a_recheck_date_the_rule_sets_one(tmp_path):
    body = "positions:\n" + ENTRY.replace("    recheck_by: 2030-12-01\n", "")
    (p,) = _one(tmp_path, body).entries
    assert p.recheck_by == dt.date(2030, 2, 1) + dt.timedelta(days=pq.DEFAULT_RECHECK_DAYS)
    assert not p.recheck_stated
    late = _one(tmp_path, body, today=p.recheck_by + dt.timedelta(days=1))
    assert "re-check rule" in late.stale[0].message


def test_the_file_can_set_its_own_rule(tmp_path):
    body = "recheck_after_days: 30\npositions:\n" + ENTRY.replace("    recheck_by: 2030-12-01\n", "")
    got = _one(tmp_path, body, today=dt.date(2030, 3, 4))
    assert got.entries[0].recheck_by == dt.date(2030, 3, 3)
    assert len(got.stale) == 1


# --- the match ----------------------------------------------------------------

MATCHING = """\
positions:
  - {provider: Example Cloud Ltd, state: shipped, source: "https://example.com/a",
     read: 2030-01-01, aliases: [ECX]}
  - {provider: Example, state: planned, source: "https://example.com/b", read: 2030-01-01}
  - {provider: Sample Mail, state: silent, source: "https://example.org/c", read: 2030-01-01,
     products: [Sample Relay]}
"""


@pytest.mark.parametrize("supplier, provider", [
    ("Example Cloud", "Example Cloud Ltd"),          # the legal form is set aside
    ("example cloud (managed hosting)", "Example Cloud Ltd"),  # two match; the longer wins
    ("ECX Platform", "Example Cloud Ltd"),           # by alias
    ("Example Payments", "Example"),                 # only the one-word provider matches
    ("Sample Mail", "Sample Mail"),
])
def test_a_provider_matches_on_the_supplier_names_leading_words(tmp_path, supplier, provider):
    hit = _one(tmp_path, MATCHING).match(supplier)
    assert hit is not None and hit.provider == provider


@pytest.mark.parametrize("supplier", [
    "Hosting by Example Cloud",     # not the leading words
    "Examples Unlimited",           # not a whole word
    "Sample Relay",                 # a product name is not matched
    "Sample",                       # shorter than the provider's name
    "",
])
def test_anything_else_is_not_researched(tmp_path, supplier):
    assert _one(tmp_path, MATCHING).match(supplier) is None


def test_on_a_tie_the_profiles_entry_beats_the_bundled_one(tmp_path):
    _bundled(tmp_path, """\
positions:
  - {key: bundled, provider: Example Cloud, state: planned,
     source: "https://example.com/b", read: 2030-01-01}
""")
    got = pq.load(_profile(tmp_path, """\
positions:
  - {key: own, provider: Example Cloud, state: shipped,
     source: "https://example.com/o", read: 2030-01-01}
"""), today=TODAY)
    hit = got.match("Example Cloud")
    assert hit is not None and hit.key == "own"


# --- the sentence, the payload and resolve -------------------------------------

def test_the_cited_sentence(tmp_path):
    (p,) = _one(tmp_path, "positions:\n" + ENTRY).entries
    assert p.line() == (
        "shipped (release 7). Hybrid key exchange is on by default. "
        "Published by Example Cloud on 2030-01-10, read 2030-02-01 — https://example.com/pq. "
        "Scope of this reading: key exchange only")


def test_a_silent_entry_is_not_credited_with_a_statement(tmp_path):
    got = _one(tmp_path, """\
positions:
  - {provider: Sample Mail, state: silent, source: "https://example.org/c", read: 2030-01-01}
""")
    assert got.entries[0].line() == (
        "silent. Established from the provider's own material, read 2030-01-01 — "
        "https://example.org/c")


def test_the_payload(tmp_path):
    (p,) = _one(tmp_path, "positions:\n" + ENTRY).entries
    assert p.payload() == {
        "key": "example-cloud", "provider": "Example Cloud", "state": "shipped",
        "summary": "Hybrid key exchange is on by default", "since": "release 7",
        "detail": "Applies to the managed load balancer",
        "source": "https://example.com/pq", "publisher": "Example Cloud",
        "published": "2030-01-10", "read": "2030-02-01", "recheck_by": "2030-12-01",
        "stale": False, "dimensions": "key exchange only",
        "products": ["Example Balancer"], "client_side": True,
    }


def test_resolve(tmp_path):
    got = _one(tmp_path, "positions:\n" + ENTRY)
    text, payload = pq.resolve(got, "Example Cloud")
    assert text.startswith("shipped (release 7)") and payload["key"] == "example-cloud"
    # The profile's own record wins and carries no published payload.
    assert pq.resolve(got, "Example Cloud", declared="  contract clause 4  ") == (
        "contract clause 4", {})
    assert pq.resolve(got, "Sample Mail") == ("", {})
    assert pq.resolve(None, "Example Cloud") == ("", {})


def test_states_and_grouping(tmp_path):
    got = _one(tmp_path, MATCHING)
    assert pq.STATES == ("shipped", "partial", "planned", "silent")
    assert {k: [p.provider for p in v] for k, v in got.by_state().items()} == {
        "shipped": ["Example Cloud Ltd"], "planned": ["Example"], "silent": ["Sample Mail"]}
