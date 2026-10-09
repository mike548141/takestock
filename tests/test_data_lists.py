"""Schema checks for the reference lists in src/takestock/data.

These read the shipped files directly, with no network access, and check that each one has the
shape its reader expects and that its values are well formed.
"""
from __future__ import annotations

import csv
import re
import unittest
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency of takestock
    yaml = None

DATA = Path(__file__).resolve().parents[1] / "src" / "takestock" / "data"
BANDS = {"supported", "security-only", "end-of-support", "end-of-life", "unknown"}
KINDS = {"os", "application", "library", "hypervisor"}


def read_csv(name: str) -> tuple[list[str], list[dict[str, str]]]:
    """Header and rows of a data CSV, skipping the leading comment lines."""
    with (DATA / name).open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(line for line in f if not line.startswith("#"))
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def load_yaml(name: str) -> dict:
    with (DATA / name).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def iso_day(value: str) -> date:
    return date.fromisoformat(value) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) else date.min


def first_day(until: str) -> date:
    """The earliest day an `until` value can mean: the day itself, or the first of its month."""
    if re.fullmatch(r"\d{4}-\d{2}", until):
        return date.fromisoformat(until + "-01")
    return date.fromisoformat(until)


def fold(s: str) -> str:
    return " ".join(s.split()).casefold()


def matching_lines(dataset: dict, kind: str, product: str, version: str) -> list[str]:
    """Line ids whose match rules accept this inventory row (exact, full-match semantics)."""
    hits = []
    for line in dataset["lines"]:
        for m in line["match"]:
            if m["kind"] != kind:
                continue
            if "product" in m and fold(m["product"]) != fold(product):
                continue
            pattern = m.get("product_pattern")
            if pattern and not re.fullmatch(pattern, product.strip(), re.IGNORECASE):
                continue
            if "version_pattern" in m and not re.fullmatch(m["version_pattern"], version.strip()):
                continue
            hits.append(line["id"])
            break
    return hits


@unittest.skipIf(yaml is None, "PyYAML is not installed")
class WindowsLifecycleTest(unittest.TestCase):
    GA_TABLES = ("windows_11_enterprise_education", "windows_11_home_pro",
                 "windows_10_enterprise_education", "windows_10_home_pro")

    def setUp(self) -> None:
        self.data = load_yaml("windows-lifecycle.yaml")

    def test_top_level_shape(self) -> None:
        self.assertEqual(self.data["schema"], 1)
        self.assertIsInstance(self.data["editions_covered"], list)
        self.assertTrue(self.data["editions_covered"])
        for key in (*self.GA_TABLES, "windows_ltsc", "windows_server"):
            self.assertIn(key, self.data)

    def test_ga_tables_are_keyed_by_build_with_ordered_dates(self) -> None:
        for table in self.GA_TABLES:
            rows = self.data[table]
            self.assertTrue(rows, table)
            for build, row in rows.items():
                self.assertRegex(build, r"^\d{5}$", f"{table}: key must be an OS build")
                self.assertEqual(set(row), {"version", "start", "end"}, f"{table}/{build}")
                self.assertRegex(row["version"], r"^(\d{4}|\d{2}H[12])$", f"{table}/{build}")
                start, end = iso_day(row["start"]), iso_day(row["end"])
                self.assertLess(start, end, f"{table}/{build}")

    def test_ga_end_of_servicing_falls_on_a_tuesday(self) -> None:
        # Microsoft ends servicing on a monthly security-update day, which is always a Tuesday.
        for table in self.GA_TABLES:
            for build, row in self.data[table].items():
                self.assertEqual(iso_day(row["end"]).weekday(), 1, f"{table}/{build} {row['end']}")

    def test_editions_get_their_own_dates_for_the_same_build(self) -> None:
        ent = self.data["windows_11_enterprise_education"]
        home = self.data["windows_11_home_pro"]
        self.assertEqual(set(ent), set(home))
        for build in ent:
            self.assertGreaterEqual(iso_day(ent[build]["end"]), iso_day(home[build]["end"]), build)

    def test_ltsc_and_server_rows(self) -> None:
        for table in ("windows_ltsc", "windows_server"):
            for row in self.data[table]:
                self.assertIn("product", row)
                if "build" in row:
                    self.assertRegex(row["build"], r"^\d{5}$", row["product"])
                start, main = iso_day(row["start"]), iso_day(row["mainstream_end"])
                self.assertLess(start, main, row["product"])
                if "extended_end" in row:
                    self.assertLess(main, iso_day(row["extended_end"]), row["product"])
                if "esu_end" in row:
                    self.assertLess(iso_day(row["extended_end"]), iso_day(row["esu_end"]), row["product"])


@unittest.skipIf(yaml is None, "PyYAML is not installed")
class SoftwareLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data = load_yaml("software-lifecycle.yaml")

    def test_sources_are_cited(self) -> None:
        self.assertEqual(self.data["schema"], 1)
        for key, src in self.data["sources"].items():
            self.assertTrue(src["url"].startswith("https://"), key)
            date.fromisoformat(src["read"])
            self.assertTrue(src["says"].strip(), key)

    def test_lines_are_well_formed(self) -> None:
        ids = [line["id"] for line in self.data["lines"]]
        self.assertEqual(len(ids), len(set(ids)), "line ids must be unique")
        for line in self.data["lines"]:
            self.assertTrue(line["match"], line["id"])
            for m in line["match"]:
                self.assertIn(m["kind"], KINDS, line["id"])
                self.assertTrue("product" in m or "product_pattern" in m, line["id"])
                for key in ("product_pattern", "version_pattern"):
                    if key in m:
                        re.compile(m[key])
            self.assertTrue(line["variants"], line["id"])
            for v in line["variants"]:
                self.assertIn(v["source"], self.data["sources"], line["id"])
                self.assertIn(v["after"], BANDS, line["id"])
                self.assertTrue(v["phases"], line["id"])
                previous = date.min
                for phase in v["phases"]:
                    self.assertIn(phase["band"], BANDS, line["id"])
                    self.assertRegex(str(phase["until"]), r"^\d{4}-\d{2}(-\d{2})?$", line["id"])
                    current = first_day(str(phase["until"]))
                    self.assertGreater(current, previous, f"{line['id']}: phases out of order")
                    previous = current

    def test_known_names_match_exactly_one_line(self) -> None:
        cases = [
            ("os", "Red Hat Enterprise Linux 8.4", "", "rhel-8"),
            ("os", "Red Hat Enterprise Linux", "9.4", "rhel-9"),
            ("os", "Rocky Linux 9.3", "", "rocky-9"),
            ("os", "AlmaLinux 8.9", "", "almalinux-8"),
            ("os", "CentOS Linux 7.9", "", "centos-7"),
            ("os", "CentOS Stream 9", "", "centos-stream-9"),
            ("os", "Oracle Linux Server 9.2", "", "oracle-linux-9"),
            ("os", "Ubuntu 22.04.4 LTS", "", "ubuntu-22.04"),
            ("os", "Ubuntu", "24.04", "ubuntu-24.04"),
            ("os", "Debian GNU/Linux 12 (bookworm)", "", "debian-12"),
            ("os", "SUSE Linux Enterprise Server 15 SP5", "", "sles-15.5"),
            ("os", "SUSE Linux Enterprise Server 15", "", "sles-15.0"),
            ("os", "Amazon Linux 2", "", "amazon-linux-2"),
            ("os", "Amazon Linux 2023", "", "amazon-linux-2023"),
            ("application", "Microsoft SQL Server 2008 R2", "", "sql-server-2008-r2"),
            ("application", "Microsoft SQL Server 2008", "", "sql-server-2008"),
            ("application", "SQL Server 2019 Standard Edition", "", "sql-server-2019"),
            ("application", "Microsoft SQL Server", "16.0.4003.1", "sql-server-2022"),
            ("application", "PostgreSQL 13.9", "", "postgresql-13"),
            ("application", "MySQL Server 8.0.40", "", "mysql-8.0"),
            ("application", "Oracle Database 21c Enterprise Edition", "", "oracle-database-21c"),
            ("application", "Python 3.12.7", "", "python-3.12"),
            ("application", "Python", "3.9.0", "python-3.9"),
            ("application", "Node.js 20.0.0", "", "nodejs-20"),
            ("application", "Microsoft .NET Runtime - 8.0.0 (x64)", "", "dotnet-8.0"),
            ("application", "Java SE Development Kit 17.0.1", "", "oracle-java-17"),
            ("application", "Eclipse Temurin JDK with Hotspot 21.0.1", "", "temurin-21"),
            ("application", "Apache HTTP Server 2.2.34", "", "apache-httpd-2.2"),
            ("library", "OpenSSL 1.1.1w", "", "openssl-1.1.1"),
            ("library", "openssl", "3.0.0", "openssl-3.0"),
            ("hypervisor", "VMware ESXi 8.0 Update 1", "", "esxi-8.0"),
            ("application", "VMware vCenter Server 7.0.0", "", "vcenter-7.0"),
        ]
        for kind, product, version, expected in cases:
            with self.subTest(product=product, version=version):
                self.assertEqual(matching_lines(self.data, kind, product, version), [expected])

    def test_near_misses_stay_unmatched(self) -> None:
        cases = [
            ("os", "Ubuntu 23.10", ""),            # an interim release, not an LTS line
            ("application", "Red Hat Enterprise Linux 8", ""),  # wrong kind
            ("application", "Python 3.1", ""),     # 3.1 is not 3.12
            ("application", "nginx 1.26.0", ""),   # no published end date, so not in the table
        ]
        for kind, product, version in cases:
            with self.subTest(product=product):
                self.assertEqual(matching_lines(self.data, kind, product, version), [])


class DaemonDictionaryTest(unittest.TestCase):
    CATEGORIES = {
        "remote-access", "web-server", "proxy", "app-server", "database", "cache", "message-broker",
        "directory", "authentication", "dns", "dhcp", "time", "logging", "monitoring", "container",
        "orchestration", "virtualisation", "cloud-agent", "endpoint-security", "vulnerability-scanner",
        "endpoint-management", "backup", "vpn-client", "ztna-client", "file-sharing", "mail", "print",
        "secrets", "runtime", "os-component", "desktop-app",
    }

    def test_shape_and_vocabulary(self) -> None:
        header, rows = read_csv("daemon-dictionary.csv")
        self.assertEqual(header, ["binary", "product", "vendor", "category", "confidence", "notes"])
        binaries = [r["binary"] for r in rows]
        self.assertEqual(len(binaries), len(set(binaries)), "binary names must be unique")
        for r in rows:
            self.assertNotIn(None, r.values(), r["binary"])  # no row has extra or missing cells
            self.assertRegex(r["binary"], r"^[A-Za-z0-9_.+-]+$", r["binary"])
            self.assertTrue(r["product"] and r["vendor"] and r["notes"], r["binary"])
            self.assertIn(r["category"], self.CATEGORIES, r["binary"])
            self.assertIn(r["confidence"], {"certain", "likely", "ambiguous"}, r["binary"])

    def test_runtimes_are_marked_ambiguous(self) -> None:
        _, rows = read_csv("daemon-dictionary.csv")
        by_name = {r["binary"]: r for r in rows}
        for name in ("java", "node", "python3", "svchost.exe", "dotnet", "System",
                     "powershell.exe", "backgroundTaskHost.exe"):
            self.assertEqual(by_name[name]["confidence"], "ambiguous", name)

    def test_the_loader_reads_every_row_by_exact_name(self) -> None:
        from takestock import config

        _, rows = read_csv("daemon-dictionary.csv")
        loaded = config.load_dictionary()
        self.assertEqual(set(loaded), {r["binary"] for r in rows})
        # Windows and Linux spellings are separate keys: the lookup is exact, case included.
        self.assertEqual(loaded["sshd.exe"]["product"], "OpenSSH server for Windows")
        self.assertEqual(loaded["sshd"]["product"], "OpenSSH server")
        self.assertNotIn("system", loaded)
        self.assertEqual(loaded["imap-login"]["vendor"], loaded["dovecot"]["vendor"])


class VendorDomainsTest(unittest.TestCase):
    CATEGORIES = {"cloud", "saas", "collaboration", "cdn", "identity", "security", "pki", "devtools",
                  "infrastructure"}

    def test_shape_and_vocabulary(self) -> None:
        header, rows = read_csv("vendor-domains.csv")
        self.assertEqual(header, ["domain", "vendor", "category", "notes"])
        domains = [r["domain"] for r in rows]
        self.assertEqual(len(domains), len(set(domains)), "domains must be unique")
        for r in rows:
            self.assertNotIn(None, r.values(), r["domain"])
            self.assertRegex(r["domain"], r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", r["domain"])
            self.assertTrue(r["vendor"] and r["notes"], r["domain"])
            self.assertIn(r["category"], self.CATEGORIES, r["domain"])

    def test_the_loader_reads_every_row(self) -> None:
        from takestock import config

        _, rows = read_csv("vendor-domains.csv")
        loaded = config.load_vendor_domains()
        self.assertEqual(set(loaded), {r["domain"] for r in rows})
        for r in rows:
            self.assertEqual(loaded[r["domain"]]["vendor"], r["vendor"], r["domain"])

    def test_a_domain_beneath_another_names_the_same_vendor(self) -> None:
        # The lookup is by suffix, so an entry beneath another entry overrides it for its own
        # names. That is only right where both name the same operator.
        _, rows = read_csv("vendor-domains.csv")
        vendor = {r["domain"]: r["vendor"] for r in rows}
        for domain, owner in vendor.items():
            labels = domain.split(".")
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                if parent in vendor:
                    self.assertEqual(owner, vendor[parent], f"{domain} beneath {parent}")


if __name__ == "__main__":
    unittest.main()
