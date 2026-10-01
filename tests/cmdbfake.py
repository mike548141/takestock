"""A synthetic observation for the configuration register tests.

Example Widgets Ltd is an invented manufacturer. Every host is under
example.test or example.net, every address is a documentation address, and
every identifier is a synthetic GUID or an obviously invented value.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

STAMP = "2030-01-15T0000Z"
EARLIER = "2030-01-01T0000Z"
DAY = "2030-01-15"

AGENT = "00000000-0000-4000-8000-000000000001"
CERT_SHA = "ab" * 32
OTHER_SHA = "cd" * 32


def _row(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": "", "data_state": "in-transit", "protocol": "", "host": "",
                            "ip": "", "port": "", "software": "", "version": "",
                            "internet_facing": None, "source": "", "source_name": "",
                            "collected_at": DAY, "verdict": "unknown", "flags": [],
                            "protocol_versions": [], "support_status": "", "support_end": "",
                            "migration_strategy": "", "notes": "", "extra": {}}
    base.update(kw)
    return base


ROWS: list[dict[str, Any]] = [
    _row(name="endpoint www.example.test", data_state="discovery", protocol="tls",
         host="www.example.test", source="ct_dns", source_name="Certificate transparency",
         internet_facing=True, verdict="n/a",
         extra={"ip_stack": "dual-stack", "ipv4_addresses": "192.0.2.10",
                "ipv6_addresses": "2001:db8::10"}),
    _row(name="certificate www.example.test", data_state="certificate", protocol="tls",
         host="www.example.test", source="ct_dns", source_name="Certificate transparency",
         verdict="acceptable", extra={
             "not_before": "2029-12-01T00:00:00Z", "not_after": "2030-03-01T00:00:00Z",
             "issuer": "Example CA", "issuer_dn": "C=XX, O=Example CA, CN=Example Issuing CA 2",
             "pubkey": {"type": "RSA", "bit_length": 2048}, "cert_sha256": CERT_SHA},
         pq_sig="classical"),
    _row(name="certificate api.example.test", data_state="certificate", protocol="tls",
         host="api.example.test", source="ct_dns", source_name="Certificate transparency",
         verdict="strong", extra={"pubkey": {"type": "EC", "curve": "P-256"},
                                  "cert_sha256": OTHER_SHA}),
    _row(name="tls app-01", host="app-01.example.test", port="443", protocol="tls",
         source="example_agent", source_name="Example endpoint agent", verdict="strong",
         protocol_versions=["TLSv1.3"], software="OpenSSL", version="3.0.13",
         support_status="supported",
         extra={"agent_id": AGENT, "host_type": "Server", "os": "Linux",
                "environment": {"value": "production", "valid_at": "2030-01-10",
                                "source_name": "group naming"}}),
    _row(name="ssh app-01", host="app-01.example.test", protocol="ssh",
         source="example_scan", source_name="Example port scan",
         extra={"service": "22/tcp", "os": "Linux 6"}),
    _row(name="agent census", source="example_agent", source_name="Example endpoint agent",
         data_state="at-rest", verdict="strong",
         extra={"agent_id": AGENT, "host_type": "server", "os": "Linux"}),
    _row(name="raw print", host="printer-01.example.test", protocol="raw",
         source="example_scan", source_name="Example port scan", flags=["plaintext:raw"],
         extra={"service": "9100/tcp"}),
    _row(name="disk laptop-01", host="laptop-01.example.test", data_state="at-rest",
         source="example_agent", source_name="Example endpoint agent", verdict="strong",
         extra={"host_type": "Laptop"}),
    _row(name="Example Hosting Co", data_state="third-party", source="example_dns",
         extra={"vendor": "Example Hosting Co", "declared": True}),
    _row(name="unattributed", data_state="third-party", source="example_dns",
         extra={"registrable_domain": "Example.net"}),
    _row(name="the export's own scope note", data_state="third-party", source="example_dns"),
    _row(name="build-signing-key", data_state="key-material", source="example_idp",
         extra={"credential_type": "client secret", "not_after": "2031-01-01"}),
    _row(name="Linux servers", data_state="estate", source="estate",
         extra={"estate_class": "Linux servers", "estate_state": "instrumented",
                "declared_crypto": ["TLS", "SSH"], "collectors_live": ["Example endpoint agent"]}),
    _row(name="DNS zone scope", data_state="discovery", protocol="dns", source="dns_zones",
         verdict="n/a"),
    _row(name="discovery count", data_state="discovery", source="example_discovery",
         source_name="Example discovery service", verdict="n/a", extra={"discovered": 40}),
]


def rows() -> list[dict[str, Any]]:
    """A fresh copy of the synthetic rows."""
    return copy.deepcopy(ROWS)


def write_observation(root: Path, stamp: str = STAMP, assets: list[dict[str, Any]] | None = None,
                      *, summary: bool = True) -> Path:
    """Write ``assets`` (default: :data:`ROWS`) as an observation under ``root``."""
    obs = root / stamp
    obs.mkdir(parents=True, exist_ok=True)
    data = rows() if assets is None else assets
    (obs / "assets.json").write_text(json.dumps(data))
    if summary:
        (obs / "summary.json").write_text(json.dumps({"total_assets": len(data)}))
    return obs


def write_history(root: Path) -> Path:
    """An earlier observation that already saw the www certificate, then the current one."""
    earlier = rows()[1]
    earlier["collected_at"] = "2030-01-01"
    write_observation(root, EARLIER, [earlier])
    return write_observation(root)
