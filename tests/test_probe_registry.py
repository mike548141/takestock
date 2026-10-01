"""The collector registry entries for the active probes."""

from __future__ import annotations

import inspect

import pytest

from takestock import collectors
from takestock.model import is_informational_flag

PROBES = ("tls_scan", "ike_scan", "ssh_audit", "plaintext_scan", "hsts", "smtp_starttls",
          "implicit_tls", "smb_scan", "rdp_scan", "ssh_audit_inside")


@pytest.mark.parametrize("name", PROBES)
def test_every_probe_is_registered_as_active_and_loads(name):
    entry = collectors.REGISTRY[name]
    assert entry.kind == "active"
    fn = getattr(collectors.load(name), entry.function)
    assert list(inspect.signature(fn).parameters)[:3] == ["target", "raw_dir", "ref_time"]


def test_the_export_reader_is_registered_as_ingest():
    assert collectors.REGISTRY["ssh_audit_inbox"].kind == "ingest"


def test_a_name_cannot_be_registered_twice_and_kinds_are_checked():
    with pytest.raises(ValueError, match="twice"):
        collectors.register("tls_scan", "tls_scan", "active")
    with pytest.raises(ValueError, match="kind"):
        collectors.register("something_new", "tls_scan", "sometimes")
    assert "something_new" not in collectors.REGISTRY


def test_names_can_be_filtered_by_kind():
    assert set(PROBES) <= set(collectors.names("active"))
    assert "ssh_audit_inbox" not in collectors.names("active")


@pytest.mark.parametrize("flag", [
    "tls-version-probe-unavailable", "implicit-tls-unreached:smtps", "hsts-unreadable",
    "hsts-preload", "plaintext-scan-unreached:http", "plaintext-scan-inconclusive:80",
    "http-redirect:https", "smb-unreached", "smb-signing-not-read", "rdp-scan-inconclusive:x",
    "ike-sweep-inconclusive:2"])
def test_measurement_limits_register_as_informational(flag):
    for name in PROBES:
        collectors.load(name)
    assert is_informational_flag(flag)


@pytest.mark.parametrize("flag", [
    "implicit-tls-no-handshake:smtps", "hsts-absent", "smb-signing-disabled",
    "rdp-nla-not-enforced", "ike-no-responder-preference", "cert-name-mismatch"])
def test_findings_do_not(flag):
    for name in PROBES:
        collectors.load(name)
    assert not is_informational_flag(flag)


def test_every_registered_entry_point_exists():
    for name, entry in collectors.REGISTRY.items():
        assert callable(getattr(collectors.load(name), entry.function)), name


def test_the_passive_dns_group_is_derived_from_the_registry():
    assert collectors.PASSIVE_DNS == ("ct_dns", "spf_senders", "dnssec", "dane", "caa",
                                      "dns_zones")
    assert collectors.PASSIVE_DNS == tuple(collectors.names("passive"))
