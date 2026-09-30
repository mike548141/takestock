"""The guard runs over the whole repository and can be shown to fail.

The "real" values each detector must catch are assembled at runtime, so this
file carries none of them as literals. Otherwise the guard would flag its own
tests.
"""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import guard  # noqa: E402


def dotted(*parts: object) -> str:
    return ".".join(str(p) for p in parts)


class RepositoryIsClean(unittest.TestCase):
    def test_guard_passes_on_this_repository(self) -> None:
        # Never skipped: an empty repository still runs every check.
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "guard.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class DetectorsFire(unittest.TestCase):
    allow = guard.load_allow()

    def hits(self, text: str, deny=()) -> list[str]:
        return guard.scan_text("t", text, self.allow, list(deny))

    def test_private_ipv4_is_caught(self) -> None:
        self.assertTrue(self.hits("gateway " + dotted(10, 20, 30, 40)))

    def test_public_ipv4_is_caught(self) -> None:
        self.assertTrue(self.hits("peer " + dotted(8, 8, 4, 4)))

    def test_documentation_ipv4_passes(self) -> None:
        self.assertFalse(self.hits("peer " + dotted(192, 0, 2, 10)))

    def test_ipv6_outside_documentation_is_caught(self) -> None:
        self.assertTrue(self.hits("addr " + ":".join(["2404", "6800", "", "1"])))

    def test_documentation_ipv6_passes(self) -> None:
        self.assertFalse(self.hits("addr " + ":".join(["2001", "db8", "", "1"])))

    def test_real_hostname_is_caught(self) -> None:
        self.assertTrue(self.hits("mx " + dotted("mail", "someorg", "co", "nz")))

    def test_reserved_hostname_passes(self) -> None:
        self.assertFalse(self.hits("mx mail.acme.example.test and www.example.com"))

    def test_file_names_are_not_hostnames(self) -> None:
        self.assertFalse(self.hits("see guard.py, README.md and run.sh"))

    def test_whole_govt_suffix_is_not_allowed(self) -> None:
        self.assertTrue(self.hits("site " + dotted("someagency", "govt", "nz")))

    def test_named_standards_publisher_passes(self) -> None:
        self.assertFalse(self.hits("see nzism.gcsb.govt.nz"))

    def test_real_email_is_caught(self) -> None:
        self.assertTrue(self.hits("contact jo" + "@" + dotted("someorg", "com")))

    def test_real_guid_is_caught(self) -> None:
        self.assertTrue(self.hits("tenant " + "-".join(["6d2fa982", "1b2c", "4d3e", "9f40", "a1b2c3d4e5f6"])))

    def test_synthetic_guid_passes(self) -> None:
        self.assertFalse(self.hits("tenant 00000000-0000-4000-8000-000000000001"))

    def test_denylist_term_is_caught_across_a_line_break_and_joins(self) -> None:
        deny = [("Fictional Widget Co", guard.norm("Fictional Widget Co"))]
        self.assertTrue(self.hits('a = "Fictional"\n  + " Widget-Co"', deny))

    def test_denylist_ignores_accents(self) -> None:
        deny = [("Mōhio Widgets", guard.norm("Mōhio Widgets"))]
        self.assertTrue(self.hits("mohio widgets", deny))


if __name__ == "__main__":
    unittest.main()
