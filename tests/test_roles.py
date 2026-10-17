"""Plain-language role descriptions."""

from __future__ import annotations

import pytest

from takestock import roles


@pytest.mark.parametrize("host, category", [
    ("vpn.example.test", "vpn"),
    ("remote-access.example.test", "vpn"),
    ("sso.example.test", "sign-in"),
    ("login.eu.example.test", "sign-in"),
    ("git.example.test", "devops"),
    ("k8s-api.example.test", "container-platform"),
    ("apps.example.test", "app"),
    ("orders-db2.example.test", "database"),
    ("www-staging.example.test", "non-prod"),
    # A non-production marker outranks the application and database kinds.
    ("demo.portal.example.test", "non-prod"),
    ("widgets-portal.example.test", "app"),
    ("portal.qa1.example.test", "non-prod"),
    ("db.demo.example.test", "non-prod"),
    ("www.example.test", "other"),
    ("example.test", "other"),
])
def test_hosts_are_classified_by_their_own_labels(host, category):
    assert roles.classify_host(host) == category


def test_the_registered_domain_never_decides_the_category():
    # "test" is a non-prod word, but here it is only the reserved top-level domain.
    assert roles.classify_host("www.widgets.test") == "other"
    assert roles.classify_host("www.dev-widgets.example") == "other"


def test_a_category_adds_its_gloss_and_other_adds_none():
    assert roles.public_endpoint("vpn.example.test").startswith("Public internet-facing service — ")
    assert roles.public_endpoint("www.example.test") == "Public internet-facing service"


def test_email_records_describe_the_domain():
    text = roles.email_record("dmarc", "example.test")
    assert "example.test" in text and text.startswith("Email fraud policy")
    assert roles.email_record("unknown-kind", "example.test") == ""
    assert roles.email_record("spf", "") == ""


def test_dkim_key_names_its_selector():
    assert '(published as "sel1")' in roles.email_signing_key("example.test", "sel1")
    assert "published as" not in roles.email_signing_key("example.test", "")


def test_vendor_endpoint_says_who_can_change_it():
    text = roles.vendor_endpoint({"host": "portal.example.com", "vendor": "Example Hosting Co",
                                  "service": "Customer portal", "carries": "order records"})
    assert text.startswith("Customer portal, operated by Example Hosting Co — carries order records")
    assert "procurement requirement" in text
    assert roles.vendor_endpoint({"vendor": "x"}) == ""


def test_scan_target_roles_cover_every_declared_group():
    target = {"scan_targets": {
        "vpn_gateways": [{"ip": "192.0.2.1", "site": "North"}, "not-a-dict"],
        "tls_443": ["www.example.test", "www.example.test"],
        "mail_self": ["mail.example.test"],
        "saas_443": [{"host": "app.example.com", "vendor": "Example SaaS"}],
        "smtp_25": [{"host": "mx.example.net"}],
        "ssh_22": ["192.0.2.22", {"host": "bastion.example.test"}],
        "smb_445": [{"ip": "192.0.2.45"}],
    }}
    out = roles.scan_target_roles(target)
    assert out["192.0.2.1"].startswith("Remote-access VPN gateway (North site)")
    assert set(roles.published_hosts(target)) == {"www.example.test", "mail.example.test"}
    assert "operated by Example SaaS" in out["app.example.com"]
    assert out["mx.example.net"].startswith("Third-party service")
    assert out["192.0.2.22"].startswith("Remote administration access")
    assert out["bastion.example.test"].startswith("Remote administration access")
    assert out["192.0.2.45"].startswith("File-sharing service")


def test_listening_service_names_the_machine_kind_when_known():
    assert roles.listening_service("Example Daemon", "host1.example.test", "server") == \
        "Example Daemon running on a server"
    assert roles.listening_service("Example Daemon", "host1.example.test") == "Example Daemon"
    assert roles.listening_service("", "host1.example.test") == ""


def test_dns_zone_wording():
    assert "3 DNS zone(s)" in roles.dns_zone_scope(3)
    assert roles.dns_zone_dangling_record("old.example.test", "gone.example.net").startswith(
        "A published DNS record at old.example.test")
    assert roles.dns_zone_dangling_record("", "x") == ""
    assert roles.dns_zone_not_delegated("") == ""
    assert roles.dns_zone_signing("example.test").startswith("Signed DNS for example.test")


def test_application_sbom_scope_wording():
    assert "applications read" in roles.application_sbom_scope()


def test_empty_inputs_give_no_role():
    for fn in (roles.ssh_service, roles.remote_desktop_service, roles.file_sharing_service,
               roles.public_endpoint, roles.discovered_endpoint, roles.certificate):
        assert fn("") == ""


def test_stored_data_and_backup_encryption_roles():
    assert roles.database_encryption("orders_a") == (
        "Encryption of the stored data of the database orders_a — whether its data files "
        "could be read if they were copied off its server")
    assert roles.backup_encryption("Example-Daily") == (
        "Encryption of the backups written under the policy Example-Daily — whether the "
        "stored copies could be read without its keys")
    assert roles.database_encryption("") == roles.backup_encryption("") == ""
