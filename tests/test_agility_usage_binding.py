"""The three readings beside the verdict: agility positions, usage bands, hardware binding."""

from __future__ import annotations

import pytest

from takestock import agility, binding, usage
from takestock.model import CryptoAsset


def row(**kw) -> CryptoAsset:
    base = {"name": "svc", "data_state": "in-transit", "protocol": "tls", "host": "web-01.example.test"}
    base.update(kw)
    return CryptoAsset(**base)


# ── agility ──

@pytest.mark.parametrize("kw, window, expected", [
    ({"flags": ("capability-ceiling:TLSv1.2", "version-spread:4")}, None, agility.REPLACEMENT),
    ({"flags": ("version-spread:4",)}, 90, agility.LIBRARY),
    ({"data_state": "third-party"}, None, agility.PROVIDER),
    ({"role": "Hosted file-transfer service, run by a supplier. Vendor-operated."}, None, agility.PROVIDER),
    ({"flags": ("key-custody:platform-managed",)}, None, agility.PROVIDER),
    ({}, 90, agility.REISSUANCE),
    ({}, None, agility.UNEVIDENCED),
])
def test_position_of_takes_the_first_measured_placement(kw, window, expected):
    args = {"data_state": "in-transit", "protocol": "tls", "role": "", "flags": ()}
    args.update(kw)
    assert agility.position_of(cert_lifetime_days=window, **args) == expected


def test_certificate_window_reads_either_spelling():
    a = row(extra={"cert_not_before": "2050-01-01T00:00:00Z", "cert_not_after": "2050-03-02T00:00:00Z"})
    assert agility.certificate_window(a) == 60
    assert agility.certificate_window(row(extra={"not_before": "bad", "not_after": "x"})) is None


def test_agility_groups_by_position_and_never_totals():
    rows = [
        row(software="ExampleSSL", version="1.0", hosts_count=12, flags=["capability-ceiling:TLSv1.2"]),
        row(software="ExampleSSL", hosts_count=30, flags=["version-spread:5"]),
        row(data_state="certificate", extra={"not_before": "2050-01-01", "not_after": "2050-04-01",
                                             "issuer": "/C=XX/organizationName=Example CA/CN=R1"}),
        row(data_state="third-party", name="Example Hosting", flags=["pq-roadmap-unrecorded"]),
        row(), row(data_state="at-rest"),
        row(data_state="estate"),
    ]
    out = agility.agility(rows)
    assert [p["position"] for p in out["positions"]] == ["replacement", "library", "reissuance", "provider"]
    assert out["unevidenced"]["count"] == 2 and out["unevidenced"]["of"] == 6
    assert out["excluded"]["count"] == 1
    groups = {p["position"]: p["groups"] for p in out["positions"]}
    assert groups["replacement"][0]["count"] == 12 and "TLSv1.2" in groups["replacement"][0]["detail"]
    assert groups["library"][0]["count"] == 5
    assert "Example CA" in groups["reissuance"][0]["detail"]
    assert groups["provider"][0]["detail"].startswith("1 with no cryptographic roadmap")
    assert "total" not in out
    assert agility.agility([row(data_state="estate")]) == {}


# ── usage ──

def test_usage_bands_compare_within_a_finding_class():
    telnet = [row(flags=["plaintext:telnet"], usage_count=n) for n in (1, 5, 50)]
    ftp = [row(flags=["plaintext:ftp"], usage_count=2)]
    silent = row(flags=["plaintext:telnet"], usage_count=None)
    zero = row(flags=["plaintext:ftp"], usage_count=0)
    encrypted = row(usage_count=900)
    usage.apply_bands([*telnet, *ftp, silent, zero, encrypted])
    assert [a.usage_band for a in telnet] == ["low", "high", "high"]
    assert ftp[0].usage_band == "high"
    assert (silent.usage_band, zero.usage_band, encrypted.usage_band) == ("unknown", "low", "")
    summary = usage.band_summary([*telnet, *ftp, silent, zero, encrypted])
    assert summary["by_band"] == {"high": 3, "low": 2, "unknown": 1}
    assert (summary["total_banded"], summary["measured"]) == (6, 5)


def test_unknown_sorts_between_high_and_low():
    assert usage.BAND_RANK["high"] < usage.BAND_RANK["unknown"] < usage.BAND_RANK["low"]


# ── binding ──

@pytest.mark.parametrize("args, expected", [
    (("in-transit", "ipmi-rmcp"), binding.HARDWARE),
    (("certificate", "x509"), binding.SOFTWARE),
    (("in-transit", "smb"), binding.SOFTWARE),
    (("in-transit", "ssh", "Branch office VPN gateway appliance"), binding.HARDWARE),
    (("in-transit", "ssh", "OpenSSH running on a laptop or desktop"), binding.SOFTWARE),
    (("in-transit", "snmp", "", "net-snmp"), binding.SOFTWARE),
    (("in-transit", "snmp"), binding.UNKNOWN),
    (("in-transit", "made-up"), binding.UNKNOWN),
])
def test_binding_of(args, expected):
    assert binding.binding_of(*args) == expected


def test_the_split_counts_weak_findings_only():
    rows = [row(verdict="weak", protocol="ipmi-rmcp"), row(verdict="weak", protocol="smb"),
            row(verdict="weak", protocol="smb"), row(verdict="weak", protocol="ike"),
            row(verdict="strong", protocol="smb")]
    out = binding.hardware_software_split(rows)
    assert (out["findings"], out["hardware"], out["software"], out["unknown"]) == (4, 1, 2, 1)
    assert out["software_by_class"] == {"smb": 2}
    assert out["unplaced"] == [{"class": "ike", "reason": binding.SPLIT_PROTOCOLS["ike"]}]
    assert binding.hardware_software_split([row(verdict="strong")]) == {}


def test_a_collector_can_register_its_own_binding(monkeypatch):
    monkeypatch.setattr(binding, "HARDWARE_PROTOCOLS", set(binding.HARDWARE_PROTOCOLS))
    binding.register_binding(binding.HARDWARE, protocols=["example-bmc"])
    assert binding.binding_of("in-transit", "example-bmc") == binding.HARDWARE
    with pytest.raises(ValueError):
        binding.register_binding("firmware", protocols=["x"])
