"""The data model: verdict ordering, expiry flags, and CycloneDX output."""

from __future__ import annotations

import json

import pytest

from takestock import model
from takestock.model import CryptoAsset


def test_worst_picks_the_weakest_graded_verdict():
    assert model.worst(["strong", "acceptable", "pqc"]) == "acceptable"
    assert model.worst(["pqc", "weak"]) == "weak"


def test_worst_ignores_unknown_and_not_applicable():
    assert model.worst(["unknown", "n/a", "strong"]) == "strong"
    assert model.worst(["unknown", "n/a"]) == "unknown"
    assert model.worst([]) == "unknown"


@pytest.mark.parametrize("remaining, lifetime, expected", [
    (-1, 365, "expired"),
    (-1, None, "expired"),
    (5, 90, "renewal-overdue"),       # short-lived and past the renewal point
    (12, 90, "expiry-soon"),          # 90 // 6 = 15-day window
    (20, 90, None),                   # inside a normal ACME renewal cycle
    (25, 365, "expiry-soon"),         # long-lived: 30-day window
    (5, 365, "expiry-soon"),          # long-lived is never "renewal-overdue"
    (31, 365, None),
    (25, None, "expiry-soon"),        # unknown lifetime gets the full window
])
def test_certificate_expiry_flag_scales_with_lifetime(remaining, lifetime, expected):
    assert model.cert_expiry_flag(remaining, lifetime) == expected


def test_expiry_threshold_is_capped():
    assert model.expiry_soon_threshold(90) == 15
    assert model.expiry_soon_threshold(800) == model.EXPIRY_SOON_DAYS
    assert model.expiry_soon_threshold(0) == model.EXPIRY_SOON_DAYS


def test_ungraded_tokens_are_read_back_from_flags():
    flags = ["weak-floor", "ungraded:ssh_mac:hmac-example-96", "ungraded:symmetric:foo_cbc"]
    assert model.ungraded_tokens(flags) == [("ssh_mac", "hmac-example-96"), ("symmetric", "foo_cbc")]


def test_informational_flags_are_facts_not_findings():
    assert model.is_informational_flag("ungraded:hashes:example")
    assert model.is_informational_flag("quantum-symmetric-margin:128")
    assert not model.is_informational_flag("weak-floor")
    assert not model.is_informational_flag("plaintext:telnet")
    assert not model.is_informational_flag("quantum-vulnerable-kex")


def test_a_collector_registers_its_own_informational_prefixes(monkeypatch):
    monkeypatch.setattr(model, "_registered_prefixes", [])
    assert not model.is_informational_flag("example-scope:all-hosts")
    model.register_informational_prefixes("example-scope:", "example-mitigated")
    model.register_informational_prefixes("example-scope:", "ungraded:")  # repeats change nothing
    assert model.is_informational_flag("example-scope:all-hosts")
    assert model.is_informational_flag("example-mitigated")
    assert model.informational_prefixes() == model.INFORMATIONAL_FLAG_PREFIXES + (
        "example-scope:", "example-mitigated")
    with pytest.raises(ValueError):
        model.register_informational_prefixes("")


@pytest.fixture
def fresh_flag_registries(monkeypatch):
    monkeypatch.setattr(model, "_registered_prefixes", [])
    monkeypatch.setattr(model, "_adverse_prefixes", [])


def test_an_adverse_declaration_outranks_a_later_registration(fresh_flag_registries):
    model.declare_adverse("example-lapsed")
    model.register_informational_prefixes("example-lapsed")
    assert not model.is_informational_flag("example-lapsed")
    assert "example-lapsed" not in model.informational_prefixes()


def test_an_adverse_declaration_outranks_an_earlier_registration(fresh_flag_registries):
    model.register_informational_prefixes("example-lapsed", "example-note")
    assert model.is_informational_flag("example-lapsed")
    model.declare_adverse("example-lapsed")
    assert not model.is_informational_flag("example-lapsed")
    assert model.is_informational_flag("example-note")
    assert model.informational_prefixes() == model.INFORMATIONAL_FLAG_PREFIXES + ("example-note",)


def test_an_adverse_declaration_outranks_a_built_in_prefix(fresh_flag_registries):
    assert model.is_informational_flag("not-measured:key-size")
    model.declare_adverse("not-measured:key-size")
    assert not model.is_informational_flag("not-measured:key-size")
    # Narrower than the built-in prefix: the prefix stays, the flag does not.
    assert model.is_informational_flag("not-measured:protocol")
    assert "not-measured:" in model.informational_prefixes()


def test_an_adverse_prefix_covers_every_flag_beginning_with_it(fresh_flag_registries):
    model.register_informational_prefixes("example-scope:", "example-scope-note")
    model.declare_adverse("example-scope:")
    assert not model.is_informational_flag("example-scope:all-hosts")
    assert model.is_informational_flag("example-scope-note")
    assert "example-scope:" not in model.informational_prefixes()


def test_adverse_declarations_are_read_back_once_each(fresh_flag_registries):
    assert model.adverse_prefixes() == ()
    model.declare_adverse("example-b", "example-a")
    model.declare_adverse("example-b")
    assert model.adverse_prefixes() == ("example-b", "example-a")
    with pytest.raises(ValueError):
        model.declare_adverse("")


def test_a_collector_registered_flag_can_be_declared_adverse(monkeypatch):
    from takestock.collectors import ct_dns  # registers its expiry flags at import

    monkeypatch.setattr(model, "_adverse_prefixes", [])
    expiry = ("expired", "renewal-overdue", "expiry-soon")
    assert all(model.is_informational_flag(f) for f in expiry)
    model.declare_adverse(*expiry)
    assert not any(model.is_informational_flag(f) for f in expiry)
    assert model.is_informational_flag(ct_dns.NULL_MX_FLAG + ct_dns.NULL_MX_PUBLISHED)  # others untouched


def test_every_shipped_reader_classifies_a_flag_through_is_informational_flag():
    """An adverse declaration reaches a reader only if it asks the one function."""
    import pathlib

    import takestock
    root = pathlib.Path(takestock.__file__).parent
    for path in root.rglob("*.py"):
        if path.name == "model.py" and path.parent == root:
            continue
        text = path.read_text(encoding="utf-8")
        for name in ("informational_prefixes()", "INFORMATIONAL_FLAG_PREFIXES", "_registered_prefixes"):
            assert name not in text, f"{path.relative_to(root)} reads {name} directly"


def test_every_built_in_informational_prefix_is_emitted_by_shipped_code():
    import inspect

    from takestock import plaintext, policy
    shipped = inspect.getsource(policy) + inspect.getsource(plaintext)
    for prefix in model.INFORMATIONAL_FLAG_PREFIXES:
        assert prefix in shipped, prefix


def test_every_readiness_value_and_basis_has_a_meaning():
    assert set(model.PQ_MEANING) == set(model.PQ_VALUES)
    assert set(model.PQ_BASES) == set(model.PQ_GAP_BASES) | set(model.PQ_NA_BASES)


def test_bom_ref_is_stable_and_distinguishes_assets():
    a = CryptoAsset(name="tls", data_state="in-transit", protocol="tls", host="www.example.test", port="443")
    b = CryptoAsset(name="tls", data_state="in-transit", protocol="tls", host="www.example.test", port="443")
    c = CryptoAsset(name="tls", data_state="in-transit", protocol="tls", host="www.example.test", port="8443")
    assert a.bom_ref() == b.bom_ref()
    assert a.bom_ref() != c.bom_ref()
    assert a.bom_ref().startswith("crypto/tls/")


def _assets() -> list[CryptoAsset]:
    return [
        CryptoAsset(name="TLS on www", data_state="in-transit", protocol="tls",
                    host="www.example.test", port="443", protocol_versions=["TLSv1.2", "TLSv1.3"],
                    symmetric=["TLS_AES_128_GCM_SHA256"], verdict="strong", flags=["b", "a"],
                    internet_facing=True, usage_count=0),
        CryptoAsset(name="Disk on host", data_state="at-rest", protocol="disk-encryption",
                    verdict="strong"),
    ]


def test_cyclonedx_document_shape():
    doc = model.to_cyclonedx(_assets(), {"timestamp": "2000-01-01T00:00:00Z"})
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["metadata"] == {"timestamp": "2000-01-01T00:00:00Z"}
    assert len(doc["components"]) == 2
    assert all(c["type"] == "cryptographic-asset" for c in doc["components"])
    json.dumps(doc)  # serialisable as is


def test_cyclonedx_protocol_asset_carries_version_and_suites():
    tls = model.to_cyclonedx(_assets(), {})["components"][0]
    cp = tls["cryptoProperties"]
    assert cp["assetType"] == "protocol"
    assert cp["protocolProperties"]["type"] == "tls"
    assert cp["protocolProperties"]["version"] == "TLSv1.2"
    assert cp["protocolProperties"]["cipherSuites"] == [{"name": "TLS_AES_128_GCM_SHA256"}]
    assert tls["evidence"]["occurrences"] == [{"location": "www.example.test:443"}]


def test_cyclonedx_non_protocol_asset_is_related_material_without_evidence():
    disk = model.to_cyclonedx(_assets(), {})["components"][1]
    assert disk["cryptoProperties"]["assetType"] == "related-crypto-material"
    assert disk["cryptoProperties"]["relatedCryptoMaterialProperties"] == {"type": "key"}
    assert "evidence" not in disk


def test_cyclonedx_properties_are_namespaced_and_omit_empty_values():
    tls = model.to_cyclonedx(_assets(), {})["components"][0]
    props = {p["name"]: p["value"] for p in tls["properties"]}
    assert all(name.startswith("takestock:") for name in props)
    assert props["takestock:verdict"] == "strong"
    assert props["takestock:flags"] == "b,a"
    assert props["takestock:internet_facing"] == "True"
    assert props["takestock:usage_count"] == "0"   # zero is a value, not an absence
    assert "takestock:disposition" not in props
    assert "takestock:hosts_count" not in props


def test_ike_and_ssh_are_protocol_assets():
    for proto in ("ike", "ssh", "ipsec"):
        a = CryptoAsset(name=proto, data_state="in-transit", protocol=proto, host="192.0.2.1")
        comp = model.to_cyclonedx([a], {})["components"][0]
        assert comp["cryptoProperties"]["protocolProperties"]["type"] == proto
        assert "cipherSuites" not in comp["cryptoProperties"]["protocolProperties"]
        assert comp["evidence"]["occurrences"] == [{"location": "192.0.2.1"}]


def test_assets_round_trip_through_json(tmp_path):
    rows = model.dump_assets(_assets())
    path = tmp_path / "assets.json"
    model.write_json(rows, path)
    back = model.load_assets(json.loads(path.read_text()))
    assert back == _assets()
