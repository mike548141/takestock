"""The sample organisation end to end: observe with --scan, then every report built from it.

Nothing here reaches a network. Every program the collectors start (``dig``,
``curl``, ``nmap``, ``openssl``) is answered by :class:`FakeNet`, and direct
socket connections are refused. DNS answers are composed by hand in ``dig``'s
layout; probe transcripts are the captured loopback fixtures in
``fixtures/probes/``, or composed by hand in nmap's layout where a capture
would need ports the stub did not open. Every name is reserved and every
address is from a documentation range.
"""

from __future__ import annotations

import base64
import json
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import openpyxl
import pytest
from dnsfake import dig_text
from probe_helpers import fixture

from takestock import cli

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example-widgets"
CT_API = "https://ct.example.test/v1/issuances"
RESOLVERS = ("192.0.2.53", "198.51.100.53")

# A stand-in for a 2048-bit RSA key: takestock sizes a DKIM key by its encoded length.
DKIM_KEY = base64.b64encode(b"\x30\x82\x01\x22" + bytes(290)).decode()

#: (name, type) -> record data, as dig prints it after the type.
DNS: dict[tuple[str, str], list[str]] = {
    ("example.com", "MX"): ["10 mx1.example.test."],
    ("example.com", "TXT"): ['"v=spf1 ip4:192.0.2.25 -all"'],
    ("example.com", "CAA"): ['0 issue "ca.example.net"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"'],
    ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=20300131"'],
    ("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:tls-reports@example.com"'],
    ("selector1._domainkey.example.com", "TXT"): [f'"v=DKIM1; k=rsa; p={DKIM_KEY}"'],
    ("example.net", "TXT"): ['"v=spf1 -all"'],
    ("_dmarc.example.net", "TXT"): ['"v=DMARC1; p=reject"'],
    ("www.example.com", "A"): ["192.0.2.80"],
    ("shop.example.com", "A"): ["192.0.2.81"],
    ("shop.example.com", "AAAA"): ["2001:db8:10::81"],
    ("mx1.example.test", "A"): ["192.0.2.25"],
}

#: Names every resolver answers with a status other than NOERROR or NXDOMAIN: the
#: deliberately mis-signed zone a validating resolver must refuse.
CONTROL_ZONE = "broken-signature.example.test"
STATUS = {CONTROL_ZONE: "SERVFAIL"}

MTA_STS_POLICY = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
                  "version: STSv1\nmode: enforce\nmx: mx1.example.test\nmax_age: 604800\n")


def _issuances() -> list[dict]:
    now = datetime.now(UTC)
    start = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + timedelta(days=335)).strftime("%Y-%m-%dT%H:%M:%SZ")
    issuer = {"friendly_name": "Example CA", "name": "CN=Example CA, O=Example CA"}
    key = {"type": "rsa", "bit_length": 2048}
    return [
        {"id": "1", "dns_names": ["www.example.com"], "not_before": start, "not_after": end,
         "issuer": issuer, "pubkey": key, "pubkey_sha256": "aa" * 32, "cert_sha256": "01" * 32},
        {"id": "2", "dns_names": ["shop.example.com"], "not_before": start, "not_after": end,
         "issuer": issuer, "pubkey": key, "pubkey_sha256": "aa" * 32, "cert_sha256": "02" * 32},
    ]


def _plaintext_nmap(host: str) -> str:
    """nmap's connect-scan layout for the five ports the sample profile names."""
    mail = host.startswith("mail.")
    rows = [
        "21/tcp   closed ftp",
        "80/tcp   open   http",
        "|_http-title: Did not follow redirect to https://www.example.test/",
        f"110/tcp  {'open  ' if mail else 'closed'} pop3",
        f"465/tcp  {'open  ' if mail else 'closed'} smtps",
        f"993/tcp  {'open  ' if mail else 'filtered'} imaps",
    ]
    return "\n".join([f"Nmap scan report for {host} (192.0.2.80)",
                      "Host is up (0.010s latency).", "", "PORT     STATE    SERVICE",
                      *rows, "", "Nmap done: 1 IP address (1 host up) scanned in 9.00 seconds",
                      ""])


class FakeNet:
    """Answers every program a collector starts; records each call and anything unplanned."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.unexpected: list[list[str]] = []
        self.sockets: list[tuple] = []
        self.issuances = _issuances()

    def run(self, cmd: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        program = Path(cmd[0]).name
        answer = {"dig": self.dig, "curl": self.curl, "nmap": self.nmap,
                  "openssl": self.openssl, "security": self.keychain}.get(program)
        if answer is None:
            self.unexpected.append(cmd)
            out = f"{program}: not available in this test\n"
        else:
            out = answer(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    def connect(self, address: tuple, *args: object, **kwargs: object) -> socket.socket:
        self.sockets.append(address)
        raise ConnectionRefusedError("no network in tests")

    @staticmethod
    def dig(cmd: list[str]) -> str:
        rtype, name = [c for c in cmd[1:] if not c.startswith(("+", "@"))][:2]
        name = name.rstrip(".").lower()
        records = DNS.get((name, rtype.upper()), [])
        if "+short" in cmd:
            return "".join(f"{r}\n" for r in records)
        known = any(n == name for n, _t in DNS)
        answer = [f"{name}. 300 IN {rtype.upper()} {r}" for r in records]
        status = STATUS.get(name) or ("NOERROR" if known else "NXDOMAIN")
        return dig_text(status, answer)

    def curl(self, cmd: list[str]) -> str:
        url = cmd[-1]
        if url.startswith(CT_API):
            after = parse_qs(urlparse(url).query).get("after")
            domain = parse_qs(urlparse(url).query)["domain"][0]
            page = [] if after else [i for i in self.issuances
                                     if any(n.endswith(domain) for n in i["dns_names"])]
            return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(page)
        if url.startswith("https://mta-sts."):
            return MTA_STS_POLICY
        if url.startswith("https://"):
            return fixture("curl-hsts.txt")
        if url.startswith("http://"):
            return fixture("curl-redirect-https.txt")
        self.unexpected.append(cmd)
        return "curl: (6) Could not resolve host\n"

    def nmap(self, cmd: list[str]) -> str:
        script = cmd[cmd.index("--script") + 1] if "--script" in cmd else ""
        if script == "ssl-enum-ciphers":
            return fixture("nmap-ssl-enum-ciphers.txt")
        if script == "ssl-cert":
            return fixture("nmap-ssl-cert.txt")
        if script == "ssh2-enum-algos":
            return fixture("nmap-ssh2-enum-algos.txt")
        if script == "http-title":
            return _plaintext_nmap(cmd[-1])
        self.unexpected.append(cmd)
        return ""

    def openssl(self, cmd: list[str]) -> str:
        version = next(c for c in cmd if c in ("-tls1", "-tls1_1", "-tls1_2", "-tls1_3"))
        prefix = "smtp" if "-starttls" in cmd else "openssl"
        return fixture(f"{prefix}-{version.lstrip('-')}.txt")

    @staticmethod
    def keychain(cmd: list[str]) -> str:
        return "security: The specified item could not be found in the keychain.\n"


@pytest.fixture()
def net(monkeypatch: pytest.MonkeyPatch) -> FakeNet:
    """Replace every way out of the machine, and the waits between probes."""
    fake = FakeNet()
    present = {"dig", "curl", "nmap", "openssl"}
    monkeypatch.setattr(subprocess, "run", fake.run)
    monkeypatch.setattr(socket, "create_connection", fake.connect)
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: f"/usr/bin/{name}" if name in present else None)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    for var in ("TAKESTOCK_SSH_AUDIT", "TAKESTOCK_IKE_SCAN", "TAKESTOCK_CT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return fake


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """The sample's profiles, with public-service settings naming a synthetic CT endpoint."""
    return _workspace(tmp_path, CONTROL_ZONE)


def _workspace(tmp_path: Path, control_zone: str | None) -> Path:
    """The sample's profiles; with ``control_zone``, every public service is configured."""
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    if control_zone is not None:
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "dns-services.yaml").write_text(
            "schema: 1\n"
            f"resolvers: [{', '.join(RESOLVERS)}]\n"
            f"validation_control: {control_zone}\n"
            f"ct_search_api: {CT_API}\n"
            "caa_issuers: {example ca: [ca.example.net]}\n"
            "takeover_namespaces: {}\n")
    return tmp_path


def _is_reserved(host: str) -> bool:
    h = host.strip("[]").lower().rstrip(".")
    return (h.endswith((".test", ".example")) or h in ("example.com", "example.net")
            or h.endswith((".example.com", ".example.net"))
            or h.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "127.", "2001:db8:")))


def test_the_sample_end_to_end(net: FakeNet, workspace: Path, capsys: pytest.CaptureFixture):
    ws = str(workspace)
    code = cli.main(["observe", "example-widgets", "--scan", "--workspace", ws,
                     "--inbox", str(SAMPLE / "exports")])
    out, err = capsys.readouterr()
    assert code in (0, 1), err
    assert net.unexpected == []

    obs = workspace / out.splitlines()[0]
    summary = json.loads((obs / "summary.json").read_text())
    assets = json.loads((obs / "assets.json").read_text())
    bom = json.loads((obs / "bom.cdx.json").read_text())
    assert summary["collector_failures"] == []
    assert code == (1 if summary["findings"] else 0)
    assert summary["total_assets"] == len(assets) == len(bom["components"])
    assert bom["bomFormat"] == "CycloneDX"
    assert any((obs / "raw").iterdir())

    # Every collector ran except the inside probes, which the sample does not declare.
    ran = set(summary["observation"]["collectors_run"])
    assert {"ct_dns", "spf_senders", "dnssec", "dane", "caa", "dns_zones", "tls_scan",
            "ike_scan", "ssh_audit", "plaintext_scan", "hsts", "smtp_starttls",
            "implicit_tls", "ssh_audit_inbox", "software_inventory"} <= ran
    sources = {a["source"] for a in assets}
    assert {"ct_dns", "tls_scan", "plaintext_scan", "hsts", "ssh_audit", "dns_zones",
            "software_inventory"} <= sources
    shared = [a for a in assets if any(f.startswith("shared-key:") for f in a["flags"])]
    assert {a["host"] for a in shared} == {"www.example.com", "shop.example.com"}

    # Only reserved names and documentation addresses were ever asked about.
    for cmd in net.calls:
        if Path(cmd[0]).name in ("nmap", "openssl"):
            target = cmd[-1] if Path(cmd[0]).name == "nmap" else \
                cmd[cmd.index("-connect") + 1].rsplit(":", 1)[0]
            assert _is_reserved(target), cmd
    assert all(_is_reserved(str(a[0])) for a in net.sockets)

    # The reports built from that observation.
    assert cli.main(["cmdb", str(obs)]) == 0
    register = json.loads((obs / "cmdb" / "cmdb.json").read_text())
    assert register["register"]["counts"]["configuration_items"] > 0
    assert openpyxl.load_workbook(obs / "cmdb" / "cmdb.xlsx").sheetnames
    assert (obs / "cmdb" / "keys.jsonl").read_text().strip()

    code = cli.main(["requirements", str(obs)])
    assert code in (0, 1)
    reqs = json.loads((obs / "requirements" / "requirements.json").read_text())
    assert code == (1 if reqs["requirements"] else 0)
    assert (obs / "requirements" / "requirements.md").read_text().startswith("#")
    assert openpyxl.load_workbook(obs / "requirements" / "requirements.xlsx").sheetnames

    code = cli.main(["comply", "sge", str(obs), "example-widgets", "--format", "html",
                     "--workspace", ws])
    assert code in (0, 1)
    html = (obs / "sge-note.html").read_text()
    assert html.lstrip().lower().startswith("<!doctype html")
    assert html.rstrip().endswith("</html>")
    assert "Example Widgets Ltd" in html
    assert "example.com" in html and "example.net" in html

    plan = workspace / "targets" / "example-widgets.ipam.yaml"
    assert cli.main(["ipam", str(plan), str(obs / "ipam"), "--exports",
                     str(SAMPLE / "exports")]) == 0
    ipam = json.loads((obs / "ipam" / "example-widgets.json").read_text())
    assert ipam["subnets"]
    assert (obs / "ipam" / "example-widgets.csv").read_text().strip()
    page = (obs / "ipam" / "example-widgets.html").read_text()
    assert page.lstrip().lower().startswith("<!doctype html") and "Example Widgets Ltd" in page
    assert net.unexpected == []


def _observe(workspace: Path, *extra: str) -> tuple[int, dict]:
    code = cli.main(["observe", "example-widgets", "--workspace", str(workspace),
                     "--inbox", str(SAMPLE / "exports"), *extra])
    obs = sorted((workspace / "observations").glob("20*"))[-1]
    return code, json.loads((obs / "summary.json").read_text())


def test_services_nobody_configured_are_gaps_not_failures(net: FakeNet, tmp_path: Path):
    code, summary = _observe(_workspace(tmp_path, None))
    assert summary["collector_failures"] == []
    assert code == (1 if summary["findings"] else 0)
    unconfigured = [g for g in summary["gaps"] if g.startswith("not measured: no ")]
    assert len(unconfigured) == 3
    for words in ("certificate-transparency search endpoint", "DNSSEC validation control zone",
                  "independent DNS resolvers"):
        assert any(words in g for g in unconfigured), words
    assert not any(c[0].endswith("curl") and c[-1].startswith(CT_API) for c in net.calls)
    assert net.unexpected == []


def test_a_configured_service_that_errors_is_a_failure(net: FakeNet, tmp_path: Path):
    # The control zone exists, so no resolver refuses it: nothing can be shown to validate.
    code, summary = _observe(_workspace(tmp_path, "accepted-signature.example.test"))
    assert code == 2
    (failure,) = summary["collector_failures"]
    assert failure.startswith("dnssec: no resolver rejected")
    assert summary["observation"]["failed_collectors"] == ["dnssec"]
    assert summary["complete"] is False
    assert not any(g.startswith("not measured: no ") for g in summary["gaps"])
