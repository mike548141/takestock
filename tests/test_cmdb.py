"""The configuration register: schema, assertion model, identity and the build."""

from __future__ import annotations

import copy
import json

import cmdbfake
import pytest

from takestock import cmdb, config

COLLECTOR = cmdb.Actor(kind=cmdb.COLLECTOR, name="Example scanner", artefact="scan.json")


def _say(value, strength=cmdb.MEASURED, valid_at="2030-01-10", basis=cmdb.PROPOSED,
         actor=COLLECTOR, recorded_at="2030-01-15"):
    return cmdb.Assertion(item="CI-000001", attribute="os", value=value,
                          evidence_strength=strength, valid_at=valid_at,
                          recorded_at=recorded_at, actor=actor, basis=basis)


# ── Schema ─────────────────────────────────────────────────────────────────


def test_the_bundled_schema_holds_together():
    schema = cmdb.load_schema()
    assert schema.problems() == []
    assert len(schema.classes) == 25
    assert schema.unassigned_roles() == []


def test_a_schema_file_with_a_repeated_key_is_refused(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / cmdb.SCHEMA_FILE).write_text(
        "schema_version: 1\nclasses: {}\nclasses: {}\n")
    config.set_workspace(tmp_path)
    with pytest.raises(config.DuplicateKeyError, match="'classes' is declared twice"):
        cmdb.raw_schema()


def test_a_broken_schema_is_refused():
    raw = copy.deepcopy(cmdb.raw_schema())
    raw["classes"]["Server"]["attributes"].append("colour")
    raw["classes"]["Site"]["family"] = "Weather"
    raw["relationships"]["part-of"].pop("note")
    raw["attributes"]["name"]["cites"] = ["no-such-document"]
    problems = cmdb.Schema(raw).problems()
    assert any("'colour'" in p for p in problems)
    assert any("'Weather'" in p for p in problems)
    assert any("part-of" in p and "why" in p for p in problems)
    assert any("no-such-document" in p for p in problems)
    with pytest.raises(cmdb.SchemaError):
        cmdb.Schema(raw).check()


def test_the_vocabularies_match_the_code():
    vocab = cmdb.load_schema().vocabularies
    assert tuple(vocab["evidence_strength"]) == cmdb.EVIDENCE_STRENGTH
    assert tuple(vocab["basis"]) == cmdb.BASES
    assert set(cmdb.absence_reasons()) >= {"not-collected", "not-measured", "not-applicable"}


def test_every_class_built_from_nothing_says_so_in_the_census(tmp_path):
    register = cmdb.build(cmdbfake.write_observation(tmp_path))
    census = {row["class"]: row for row in register.census()}
    assert census["Contract"]["items"] == 0 and "declared" in census["Contract"]["empty_because"]
    assert census["Virtual Machine"]["items"] == 0
    assert "unmeasured" in census["Virtual Machine"]["empty_because"]
    assert census["Server"]["empty_because"] == ""


# ── Values and assertions ──────────────────────────────────────────────────


def test_an_absence_is_not_a_value_and_its_code_must_exist():
    assert cmdb.is_absent(cmdb.Absence("not-measured"))
    assert not cmdb.is_absent("")
    assert cmdb.Absence("masked").definition
    with pytest.raises(ValueError):
        cmdb.Absence("probably-fine")


def test_an_assertion_refuses_what_the_model_does_not_know():
    with pytest.raises(ValueError):
        _say("Linux", strength="rumoured")
    with pytest.raises(ValueError):
        _say("Linux", basis="assumed")
    with pytest.raises(ValueError):
        _say("Linux", valid_at="15/01/2030")
    with pytest.raises(ValueError):
        cmdb.Actor(kind=cmdb.PERSON, name=" ")


def test_a_retraction_is_a_new_assertion_and_withdraws_its_target():
    first = _say("Linux")
    withdrawn = cmdb.retraction(first, recorded_at="2030-01-20", actor=COLLECTOR,
                                reason="read from the wrong host")
    log = [first, withdrawn]
    assert cmdb.live(log) == []
    assert cmdb.as_of(log, "2030-01-15") == [first]
    with pytest.raises(ValueError):
        cmdb.retraction(first, recorded_at="2030-01-20", actor=COLLECTOR, reason="")


def test_known_by_and_true_by_are_separate_questions():
    late = _say("Linux", valid_at="2030-01-01", recorded_at="2030-02-01")
    assert cmdb.as_of([late], "2030-01-15") == []
    assert cmdb.as_at([late], "2030-01-15") == [late]


def test_stronger_evidence_wins_and_both_are_kept():
    r = cmdb.resolve([_say("Linux", cmdb.DECLARED, "2030-01-14"), _say("BSD")])
    assert r.value == "BSD" and r.contested and not r.tie and len(r.assertions) == 2


def test_the_freshest_wins_within_one_strength():
    r = cmdb.resolve([_say("Linux", valid_at="2030-01-01"), _say("BSD", valid_at="2030-01-12")])
    assert r.value == "BSD" and not r.tie


def test_a_tie_is_flagged_not_hidden():
    r = cmdb.resolve([_say("Linux"), _say("BSD")])
    assert r.contested and r.tie


def test_a_decided_value_beats_every_instrument():
    person = cmdb.Actor(kind=cmdb.PERSON, name="Register owner")
    r = cmdb.resolve([_say("Linux"), _say("BSD", cmdb.DECLARED, actor=person, basis=cmdb.DECIDED)])
    assert r.value == "BSD" and r.basis == cmdb.DECIDED


def test_an_absence_never_beats_a_value_and_agreement_is_not_a_contest():
    r = cmdb.resolve([_say(cmdb.Absence("not-measured")), _say("Linux", cmdb.INFERRED)])
    assert r.value == "Linux"
    assert not cmdb.resolve([_say("Linux"), _say("Linux", valid_at="2030-01-01")]).contested
    nothing = cmdb.resolve([], "os")
    assert cmdb.is_absent(nothing.value) and nothing.value.reason == "not-collected"


def test_a_strength_is_capped_at_what_the_attribute_can_carry():
    schema = cmdb.load_schema()
    assert cmdb.capped_strength(schema, "encryption_verdict", cmdb.MEASURED) == cmdb.INFERRED
    assert cmdb.capped_strength(schema, "os", cmdb.REPORTED) == cmdb.REPORTED
    assert cmdb.capped_strength(schema, "hostname", cmdb.MEASURED) == cmdb.MEASURED


# ── Identity ───────────────────────────────────────────────────────────────


def test_a_key_survives_a_rename_and_is_never_reused():
    ledger = cmdb.KeyLedger()
    key = ledger.key_for([("hostname", "web-01.example.test"), ("agent-id", cmdbfake.AGENT)])
    assert ledger.key_for([("hostname", "web-99.example.test"), ("agent-id", cmdbfake.AGENT)]) == key
    assert key.startswith("CI-") and "web" not in key
    assert ledger.mint() != key


def test_a_merge_needs_a_date_and_a_reason_and_the_old_key_redirects():
    ledger = cmdb.KeyLedger()
    a = ledger.key_for([("hostname", "web-01.example.test")])
    b = ledger.key_for([("agent-id", cmdbfake.AGENT)])
    both = [("hostname", "web-01.example.test"), ("agent-id", cmdbfake.AGENT)]
    with pytest.raises(ValueError):
        ledger.key_for(both)
    kept = ledger.key_for(both, merged_at="2030-01-15", reason="one row named both")
    assert kept == a and ledger.redirect(b) == a
    assert ledger.merges == [{"at": "2030-01-15", "reason": "one row named both",
                              "kept": a, "retired": b}]


def test_a_mac_address_is_never_an_identifier():
    with pytest.raises(ValueError, match="never be an identifier"):
        cmdb.KeyLedger().key_for([("mac-address", "00:00:5e:00:53:01")])


def test_keys_outlive_a_rebuild(tmp_path):
    obs = cmdbfake.write_observation(tmp_path)
    first = cmdb.build(obs)
    ledger = cmdb.KeyLedger.from_records(first.ledger.records())
    again = cmdb.build(obs, ledger=ledger)
    labels = {k: i.label for k, i in first.items.items()}
    assert {k: i.label for k, i in again.items.items()} == labels
    assert ledger.mint() not in labels


# ── The build ──────────────────────────────────────────────────────────────


@pytest.fixture()
def built(tmp_path):
    return cmdb.build(cmdbfake.write_history(tmp_path))


def _item(register, label):
    return next(i for i in register.items.values() if i.label == label)


def _value(register, label, attribute):
    item = _item(register, label)
    return register.resolved()[item.key][attribute]


def test_rows_become_items_of_the_right_class(built):
    classes = {i.label: i.item_class for i in built.items.values()}
    assert classes["app-01.example.test"] == "Server"
    assert classes["laptop-01.example.test"] == "Endpoint Device"
    assert classes["printer-01.example.test"] == "Host"
    assert classes["www.example.test"] in ("DNS Name", "Certificate")
    assert classes["app-01.example.test 443/tcp"] == "Network Service"
    assert classes["OpenSSL 3.0.13"] == "Software Release"
    assert classes["Example Hosting Co"] == "Vendor"
    assert classes["example.net"] == "Unattributed Dependency"
    assert classes["build-signing-key"] == "Credential"
    assert classes["Linux servers"] == "Declared Asset Class"
    assert "the export's own scope note" not in classes
    assert sum(1 for i in built.items.values() if i.label == "www.example.test") == 2


def test_two_sources_naming_one_machine_make_one_item(built):
    servers = [i for i in built.items.values() if i.item_class == "Server"]
    assert len(servers) == 1
    assert {a.kind for a in servers[0].aliases} == {"hostname", "agent-id"}


def test_probes_of_one_named_address_make_one_machine_carrying_the_address(tmp_path):
    # Rows as the collectors name them for an entry {host: files-01..., ip: 192.0.2.45}.
    rows = [cmdbfake._row(name=f"{label} files-01.example.test:{port}", protocol=proto,
                          host="files-01.example.test", ip="192.0.2.45", port=port,
                          source=source, source_name=source)
            for label, proto, port, source in (("SMB signing", "smb", "445", "smb_scan"),
                                               ("RDP", "rdp", "3389", "rdp_scan"),
                                               ("SSH", "ssh", "22", "ssh_audit"))]
    register = cmdb.build(cmdbfake.write_observation(tmp_path, assets=rows))
    machines = [i for i in register.items.values() if i.label == "files-01.example.test"]
    assert len(machines) == 1
    assert not [i for i in register.items.values() if i.label.startswith("192.0.2.45")]
    address = register.resolved()[machines[0].key]["address"]
    assert {x.value for x in address.assertions} == {"192.0.2.45"}


def _installed_on(register):
    return {(register.items[e.from_key].label, register.items[e.to_key].label)
            for e in register.edges if e.kind == "installed-on"}


def test_software_with_no_host_still_makes_its_product_and_release(tmp_path):
    rows = [cmdbfake._row(name="Example TLS library 41.7.3", data_state="software",
                          software="Example TLS library", version="41.7.3",
                          source="example_inventory", source_name="Example inventory")]
    register = cmdb.build(cmdbfake.write_observation(tmp_path, assets=rows))
    classes = {i.label: i.item_class for i in register.items.values()}
    assert classes == {"Example TLS library": "Software Product",
                       "Example TLS library 41.7.3": "Software Release"}
    assert _value(register, "Example TLS library 41.7.3", "version").value == "41.7.3"
    assert {e.kind for e in register.edges} == {"release-of"}


def test_an_inventory_row_naming_its_hosts_installs_the_release_on_each(tmp_path):
    rows = [
        cmdbfake._row(name="Example TLS library 41.7.3", data_state="software",
                      software="Example TLS library", version="41.7.3",
                      source="example_inventory", source_name="Example inventory",
                      extra={"hosts": "app-02.example.test, build-02.example.test"}),
        cmdbfake._row(name="Example TLS library 39.2.8", data_state="software",
                      software="Example TLS library", version="39.2.8",
                      source="example_inventory", source_name="Example inventory",
                      extra={"hosts": ["build-02.example.test"]}),
        # A count of the versions in service is not an install.
        cmdbfake._row(name="Example TLS library version spread", data_state="software",
                      software="Example TLS library", source="example_inventory",
                      source_name="Example inventory", flags=["version-spread:2"],
                      extra={"hosts": "app-02.example.test, build-02.example.test"}),
        cmdbfake._row(name="tls app-02", host="app-02.example.test", port="443",
                      protocol="tls", source="example_scan", source_name="Example port scan",
                      extra={"host_type": "server"}),
    ]
    register = cmdb.build(cmdbfake.write_observation(tmp_path, assets=rows))
    assert _installed_on(register) == {
        ("Example TLS library 41.7.3", "app-02.example.test"),
        ("Example TLS library 41.7.3", "build-02.example.test"),
        ("Example TLS library 39.2.8", "build-02.example.test")}
    classes = {i.label: i.item_class for i in register.items.values()}
    # The machine a probe typed keeps its class; one only the inventory names is a Host.
    assert classes["app-02.example.test"] == "Server"
    assert classes["build-02.example.test"] == "Host"
    assert "Example TLS library" in classes and "Example TLS library " not in classes
    assert sum(1 for c in classes.values() if c == "Software Release") == 2
    counts = {p.instrument: p.count for p in register.populations}
    assert counts["Example inventory"] == 2 and counts["Example port scan"] == 1


def test_the_software_inventory_rows_reach_the_register(tmp_path):
    from takestock.collectors import software_inventory
    from takestock.model import dump_assets
    export = tmp_path / "software.csv"
    export.write_text("host,product,version\n"
                      "app-02.example.test,OpenSSL,3.0.13\n"
                      "build-02.example.test,OpenSSL,3.0.13\n"
                      "build-02.example.test,OpenSSL,1.1.1w\n")
    assets, _gaps = software_inventory.collect({"software_inbox": {"export": str(export)}})
    register = cmdb.build(cmdbfake.write_observation(tmp_path, assets=dump_assets(assets)))
    assert _installed_on(register) == {("OpenSSL 3.0.13", "app-02.example.test"),
                                       ("OpenSSL 3.0.13", "build-02.example.test"),
                                       ("OpenSSL 1.1.1w", "build-02.example.test")}


def test_disagreeing_sources_are_both_published(built):
    os = _value(built, "app-01.example.test", "os")
    assert os.contested and os.tie
    assert {a.value for a in os.assertions} == {"Linux", "Linux 6"}


def test_lifecycle_never_claims_live(built):
    states = {i.lifecycle_state for i in built.items.values()}
    assert "live" not in states
    assert _item(built, "Linux servers").lifecycle_state == "planned"


def test_every_assertion_names_the_artefact_it_came_from(built):
    assert all(a.actor.artefact == f"{cmdbfake.STAMP}/assets.json" for a in built.assertions)
    assert all(a.actor.artefact_digest.startswith("sha256:") for a in built.assertions)


def test_attributes_land_only_on_classes_that_carry_them(built):
    schema = built.schema
    for a in built.assertions:
        assert a.attribute in schema.class_attributes(built.items[a.item].item_class)


def test_certificate_columns(built):
    cert = next(i for i in built.items.values()
                if i.item_class == "Certificate" and i.label == "www.example.test")
    attrs = built.resolved()[cert.key]
    assert attrs["issuing_ca"].value == "Example Issuing CA 2"
    assert attrs["key_length"].value == "2048 bits"
    assert attrs["certificate_sha256"].value == cmdbfake.CERT_SHA
    assert attrs["encryption_verdict"].evidence_strength == cmdb.INFERRED
    assert attrs["post_quantum_signature"].value == "classical"
    ec = next(i for i in built.items.values() if i.label == "api.example.test")
    assert built.resolved()[ec.key]["key_length"].value == "256 bits (P-256)"


def test_first_discovered_reads_the_earlier_observation(built):
    certs = {i.label: built.resolved()[i.key] for i in built.items.values()
             if i.item_class == "Certificate"}
    assert certs["www.example.test"]["first_discovered"].value == "2030-01-01"
    assert certs["api.example.test"]["first_discovered"].value == cmdbfake.DAY


def test_a_name_carries_its_addresses_and_exposure(built):
    name = next(i for i in built.items.values()
                if i.item_class == "DNS Name" and i.label == "www.example.test")
    attrs = built.resolved()[name.key]
    assert attrs["address"].value == "192.0.2.10, 2001:db8::10"
    assert attrs["internet_facing"].value is True


def test_a_domain_carries_its_name_servers_and_dmarc_reporting_address(tmp_path):
    def mail_row(protocol, host, **extra):
        return cmdbfake._row(name=f"{protocol} {host}", data_state="email-auth",
                             protocol=protocol, host=host, source="ct_dns",
                             source_name="Public DNS", verdict="n/a", extra=extra)
    extra = [
        mail_row("ns", "example.test", name_servers=["ns1.example.net", "ns2.example.net"]),
        mail_row("dmarc", "example.test",
                 record="v=DMARC1; p=reject; rua=mailto:reports@example.test"),
        mail_row("ns", "mail.example.test", name_servers=[]),
        mail_row("dmarc", "mail.example.test", record="v=DMARC1; p=reject"),
        mail_row("dmarc", "old.example.test", present=False, record=""),
    ]
    register = cmdb.build(cmdbfake.write_observation(tmp_path, assets=cmdbfake.rows() + extra))
    assert _value(register, "example.test", "name_servers").value == (
        "ns1.example.net, ns2.example.net")
    assert _value(register, "example.test", "dmarc_report_address").value == (
        "mailto:reports@example.test")
    not_apex = _value(register, "mail.example.test", "name_servers").value
    assert not_apex.reason == "not-applicable" and "parent zone" in not_apex.note
    no_rua = _value(register, "mail.example.test", "dmarc_report_address").value
    assert no_rua.reason == "not-applicable" and "no rua= tag" in no_rua.note
    assert _value(register, "old.example.test", "dmarc_report_address").value.reason == (
        "not-applicable")
    # A name nothing read for either is left open, never blank.
    [www] = [i for i in cmdb.register_payload(register)["items"]
             if i["class"] == "DNS Name" and i["name"] == "www.example.test"]
    for attribute in ("name_servers", "dmarc_report_address"):
        assert www["attributes"][attribute]["absent"] == "not-collected"


def test_relationships_drawn(built):
    kinds = {e.kind for e in built.edges}
    assert kinds == {"contains", "installed-on", "release-of", "presents", "member-of"}
    installed = next(e for e in built.edges if e.kind == "installed-on")
    assert installed.count == 1 and installed.unit
    presents = [e for e in built.edges if e.kind == "presents"]
    assert len(presents) == 1 and "transparency" in presents[0].qualifier
    members = {built.items[e.from_key].label for e in built.edges if e.kind == "member-of"}
    assert members == {"app-01.example.test", "laptop-01.example.test"}


def test_a_listener_carries_its_grading_and_depth(built):
    attrs = _value(built, "printer-01.example.test 9100/tcp", "evidence_depth")
    assert attrs.value == "posture"
    https = built.resolved()[_item(built, "app-01.example.test 443/tcp").key]
    assert https["evidence_depth"].value == "strength"
    assert https["port"].value == "443" and https["transport"].value == "tcp"


def test_declared_and_derived_values_say_so(built):
    vendor = _value(built, "Example Hosting Co", "vendor_name")
    assert vendor.evidence_strength == cmdb.DECLARED
    env = _value(built, "app-01.example.test", "environment")
    assert env.value == "production" and env.evidence_strength == cmdb.INFERRED
    custody = _value(built, "laptop-01.example.test", "key_custody")
    assert cmdb.is_absent(custody.value) and custody.value.reason == "not-measured"
    support = _value(built, "OpenSSL 3.0.13", "support_status")
    assert support.value == "supported" and support.evidence_strength == cmdb.INFERRED


def test_populations_are_held_side_by_side(built):
    counts = {p.instrument: p.count for p in built.populations}
    assert counts == {"Example endpoint agent": 2, "Example port scan": 2,
                      "Example discovery service": 40, "every instrument together": 3}
    assert all(p.contested and p.unit == "machines" for p in built.populations)


def test_a_registered_source_strength_applies(tmp_path, monkeypatch):
    monkeypatch.setattr(cmdb, "_SOURCE_STRENGTH", {})
    cmdb.register_source_strength("example_agent", cmdb.REPORTED)
    register = cmdb.build(cmdbfake.write_observation(tmp_path))
    hostname = _value(register, "laptop-01.example.test", "hostname")
    assert hostname.evidence_strength == cmdb.REPORTED
    with pytest.raises(ValueError):
        cmdb.register_source_strength("x", "hearsay")


def test_the_same_observation_builds_the_same_register(tmp_path):
    obs = cmdbfake.write_observation(tmp_path)
    first, second = cmdb.build_register(obs), cmdb.build_register(obs)
    assert json.dumps(first, default=str) == json.dumps(second, default=str)
    assert first["register"]["recorded_at"] == cmdbfake.DAY


def test_a_torn_observation_is_refused(tmp_path):
    obs = cmdbfake.write_observation(tmp_path)
    (obs / "summary.json").write_text(json.dumps({"total_assets": 3}))
    with pytest.raises(ValueError, match="incomplete"):
        cmdb.build(obs)


def test_the_payload_carries_the_schema_and_never_a_blank(tmp_path):
    payload = cmdb.build_register(cmdbfake.write_observation(tmp_path))
    assert payload["schema"]["version"] == "1.0.0"
    assert len(payload["census"]) == 25
    for item in payload["items"]:
        declared = cmdb.load_schema().class_attributes(item["class"])
        assert list(item["attributes"]) == declared
        for cell in item["attributes"].values():
            assert cell["absent"] or cell["value"] is not None
    counts = payload["register"]["counts"]
    assert counts["configuration_items"] == len(payload["items"])
    assert counts["contested_attributes"] == len(payload["conflicts"]) >= 1
    reasons = {r["relationship"] for r in payload["relationships_not_drawn"]}
    assert "runs-on" in reasons and "contains" not in reasons
