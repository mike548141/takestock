"""CrowdStrike Falcon: open vulnerabilities in the software that provides cryptography.

Every other reader of configuration says how a service is set up: a cipher
offered, a protocol accepted, a drive encrypted. A correctly configured
service on a library with a known defect in its cryptographic code is still
exposed, and no configuration reading can see that. This reader reads the
other half, from a vulnerability list of the kind CrowdStrike's Falcon
Spotlight (Exposure Management) keeps: one record per machine and defect.

**The input** (``input:``) is a CSV with one row per machine and
vulnerability. The default headings are the field paths of Spotlight's
vulnerability records as the CrowdStrike API returns them, joined with dots
(Elastic's CrowdStrike integration documents them; ``docs/COLLECTORS.md``
gives the source), so a CSV made by flattening those records is read as it
is. An export from the Falcon console carries headings of its own; name them
with ``settings: columns:``. The file can be large, so it is read one row at
a time and only the fields below are held.

==================  ================================  ==============================
field               default heading                   what it holds
==================  ================================  ==============================
``machine``         ``host_info.hostname``            the machine's name
``os``              ``host_info.os_version``          its operating system
``machine_type``    ``host_info.product_type_desc``   its type (server, workstation)
``criticality``     ``host_info.asset_criticality``   how critical the machine is marked
``status``          ``status``                        open, closed and so on
``created``         ``created_timestamp``             when the record was raised
``cve``             ``cve.id``                        the CVE identifier
``description``     ``cve.description``               the advisory's text
``severity``        ``cve.severity``                  CRITICAL, HIGH, MEDIUM or LOW
``score``           ``cve.base_score``                the CVSS base score
``exploit``         ``cve.exploit_status``            the exploit status
``kev``             ``cve.cisa_info.is_cisa_kev``     in CISA's Known Exploited Vulnerabilities catalogue
``kev_due``         ``cve.cisa_info.due_date``        the catalogue's due date
``product``         ``app.product_name_normalized``   the affected product
``versions``        ``app.product_name_version``      the affected versions
==================  ================================  ==============================

**Which records are open**: ``status`` equal, ignoring case, to a word in
``settings: open_statuses:`` (default ``open``). Only open records are
counted against products, defects and machines' operating systems; the rest
count only toward the scope row's total. **An exploit in use**: ``exploit``
equal to, or beginning with, a value in ``settings: exploit_in_use:``
(default none, so nothing is counted as exploited until the profile says
which values mean it). **Catalogued**: ``kev`` equal to a value in
``settings: kev_true:`` (default ``true``).

**The unit is the remediation act, never the record.** Three kinds of row:

* **One cryptographic product**, named ``<product> — open defects``: a
  package whose name matches ``settings: packages:`` (a list of
  ``[pattern, what it provides]``, matched against the whole name ignoring
  case), or a Microsoft component named in the advisory text in the form
  "... in Windows <component> allows ...". ``settings: components:`` maps the
  component names counted (``windows kerberos`` and so on) to what
  each provides; a profile's map replaces the default map. Each row carries
  the open records, distinct identifiers, machines, worst published severity
  and highest score. ``weak`` when any
  record has an exploit in use or is catalogued, otherwise ``unknown``;
  flagged ``crypto-defect-open:<n>``, ``crypto-defect-attribution:<how>``
  and, where they apply, ``crypto-defect-exploited:<n>`` and
  ``crypto-defect-catalogued:<n>``.
* **One catalogued defect**, named ``<CVE> — catalogued exploited defect``:
  each open identifier the catalogue names, because there an outside
  authority has put a date on that identifier. ``weak``, flagged
  ``exploited-defect-overdue:<date>`` when the due date had passed by the
  newest record's date, else ``exploited-defect-due:<date>``.
* **One operating system and machine type**, named ``<os> (<type>)``:
  a population (``n/a``, ``os-census:<n>``), the census a fleet upgrade is
  sized against.

**A scope row**, ``Vulnerability evidence scope``, states the records, open
records, identifiers and machines, the span over which the records were
raised (``scope-defect-window:<first>..<last>``), and that every severity
here is technical (``scope-technical-severity-only``): how bad a defect is,
not what is lost if the machine holding it fails.

**A gap** when ``criticality`` is blank, or a value in ``settings:
criticality_unset:``, on any record: the export then gives no business
impact to order a queue by.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_vulnerabilities"

DEFECT_FLAG = "crypto-defect-open:"
EXPLOITED_FLAG = "crypto-defect-exploited:"
CATALOGUED_FLAG = "crypto-defect-catalogued:"
ATTRIBUTION_FLAG = "crypto-defect-attribution:"
OS_CENSUS_FLAG = "os-census:"
OVERDUE_FLAG = "exploited-defect-overdue:"
DUE_FLAG = "exploited-defect-due:"
SCOPE_TECHNICAL_FLAG = "scope-technical-severity-only"
SCOPE_WINDOW_FLAG = "scope-defect-window:"

register_informational_prefixes(OS_CENSUS_FLAG, ATTRIBUTION_FLAG, SCOPE_TECHNICAL_FLAG,
                                SCOPE_WINDOW_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "machine": "host_info.hostname",
    "os": "host_info.os_version",
    "machine_type": "host_info.product_type_desc",
    "criticality": "host_info.asset_criticality",
    "status": "status",
    "created": "created_timestamp",
    "cve": "cve.id",
    "description": "cve.description",
    "severity": "cve.severity",
    "score": "cve.base_score",
    "exploit": "cve.exploit_status",
    "kev": "cve.cisa_info.is_cisa_kev",
    "kev_due": "cve.cisa_info.due_date",
    "product": "app.product_name_normalized",
    "versions": "app.product_name_version",
}

OPEN_STATUSES = ("open",)
KEV_TRUE = ("true",)

#: Packages that provide cryptography, matched against the whole product name
#: ignoring case, with what each provides. Package names as Linux
#: distributions publish them.
PACKAGES: tuple[tuple[str, str], ...] = (
    (r"openssl(-libs)?|libssl\d*(\.\d+)*", "tls"),
    (r"gnutls|libgnutls\d*", "tls"),
    (r"nss|nspr|libnss3", "tls"),
    (r"wolfssl|mbedtls|libressl", "tls"),
    (r"(lib)?curl", "tls"),
    (r"stunnel", "tls"),
    (r"java-\d+-openjdk", "tls"),
    (r"openssh(-clients|-server)?", "ssh"),
    (r"libssh2?", "ssh"),
    (r"krb5(-libs|-workstation|-server)?", "kerberos"),
    (r"libgcrypt\d*", "key-material"),
    (r"nettle", "key-material"),
    (r"p11-kit", "key-material"),
    (r"opensc|softhsm2?", "key-material"),
    (r"python\d?-cryptography", "key-material"),
    (r"libtasn1", "certificate"),
    (r"gnupg2?", "signing"),
    (r"libreswan|strongswan", "ipsec"),
    (r"wpa_supplicant", "wifi"),
)

#: Microsoft components whose work is cryptography or the credentials it
#: protects, as advisory text names them, with what each provides.
COMPONENTS: dict[str, str] = {
    "windows kerberos": "kerberos",
    "windows netlogon": "netlogon",
    "windows ntlm": "ntlm",
    "windows schannel": "tls",
    "windows cryptographic services": "key-material",
    "windows cryptoapi": "key-material",
    "windows bitlocker": "fde",
    "windows ike extension": "ipsec",
    "windows smb server": "smb",
    "windows smb client": "smb",
    "windows smb": "smb",
}

#: "<weakness> in Windows <component> allows ...": the component, as advisory text names it.
_COMPONENT = re.compile(r"\bin (Windows [A-Z][A-Za-z0-9 /()'-]{2,45}?) allows")

#: CVSS's qualitative severity ratings, worst first.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Which axis a defect in each kind of component belongs on.
STATE_OF_PROVIDES: dict[str, str] = {
    "tls": "in-transit", "ssh": "in-transit", "ipsec": "in-transit", "smb": "in-transit",
    "kerberos": "in-transit", "netlogon": "in-transit", "ntlm": "in-transit",
    "wifi": "in-transit",
    "key-material": "key-material", "signing": "key-material",
    "certificate": "certificate", "fde": "at-rest",
}

TECHNICAL_ONLY = (
    "Every severity here is technical: how bad the defect is, from its published score and "
    "whether an exploit is known to be in use. None of it says what would be lost if the "
    "machine holding the defect were taken, so a queue ordered by these figures alone treats "
    "a defect on a test machine and the same defect on a machine the business relies on as "
    "equals")

EVIDENCE_LIMIT = (
    "A record means a scanner matched an installed version against a published advisory. It "
    "does not show that the defect is reachable, that the affected code is in use, or that "
    "nothing else mitigates it")


class Settings:
    """The reader's settings, with their defaults."""

    def __init__(self, ctx: Context) -> None:
        s = ctx.settings or {}
        self.headings = _fp.columns(ctx, HEADINGS)
        self.open_statuses = _fp.words(s.get("open_statuses"), OPEN_STATUSES)
        self.exploit_in_use = _fp.words(s.get("exploit_in_use"), ())
        self.kev_true = _fp.words(s.get("kev_true"), KEV_TRUE)
        self.criticality_unset = _fp.words(s.get("criticality_unset"), ())
        raw_packages = s.get("packages")
        self.packages: tuple[tuple[str, str], ...] = (
            tuple((str(p), str(v)) for p, v in raw_packages) if raw_packages else PACKAGES)
        raw_components = s.get("components")
        self.components: dict[str, str] = (
            {str(k).lower(): str(v) for k, v in dict(raw_components).items()}
            if raw_components else dict(COMPONENTS))


def package_provides(product: str, packages: Sequence[tuple[str, str]]) -> str:
    """What a package-named product provides, or ``""`` when it is not one listed."""
    p = product.strip().lower()
    for pattern, provides in packages:
        if re.fullmatch(pattern, p):
            return provides
    return ""


def component_in(description: str, components: Mapping[str, str]) -> tuple[str, str]:
    """``(component, provides)`` for a listed component named in advisory text, or ``("", "")``."""
    m = _COMPONENT.search(description or "")
    if not m:
        return "", ""
    name = " ".join(m.group(1).split())
    provides = components.get(name.lower())
    return (name, provides) if provides else ("", "")


def worst(a: str, b: str) -> str:
    """The worse of two severity words; a word not in the scale never displaces one that is."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if a not in order:
        return b if b in order else (a or b)
    if b not in order:
        return a
    return a if order[a] <= order[b] else b


def _float(v: str) -> float:
    try:
        return float(v)
    except ValueError:
        return 0.0


class Tally:
    """Everything one pass over the export accumulates; the only things that grow with it."""

    def __init__(self, s: Settings) -> None:
        self.s = s
        self.rows = 0
        self.open_rows = 0
        self.machines: set[str] = set()
        self.cves: set[str] = set()
        self.first_seen = ""
        self.last_seen = ""
        self.criticality: dict[str, int] = {}
        self.os_machines: dict[tuple[str, str], set[str]] = {}
        self.os_open: dict[tuple[str, str], int] = {}
        self.products: dict[str, dict[str, Any]] = {}
        self.catalogued: dict[str, dict[str, Any]] = {}
        self.exploited_uncatalogued: set[str] = set()
        self.exploited_machines: set[str] = set()

    def add(self, r: Mapping[str, str]) -> None:
        self.rows += 1
        machine = r.get("machine", "")
        if machine:
            self.machines.add(machine)
        key = (r.get("os", "") or "unknown", r.get("machine_type", "") or "unknown")
        if machine:
            self.os_machines.setdefault(key, set()).add(machine)
        crit = r.get("criticality", "") or "(blank)"
        self.criticality[crit] = self.criticality.get(crit, 0) + 1
        created = r.get("created", "")[:10]
        if created:
            if not self.first_seen or created < self.first_seen:
                self.first_seen = created
            self.last_seen = max(self.last_seen, created)
        if r.get("status", "").lower() not in self.s.open_statuses:
            return
        self.open_rows += 1
        self.os_open[key] = self.os_open.get(key, 0) + 1
        cve = r.get("cve", "")
        if cve:
            self.cves.add(cve)
        severity = r.get("severity", "").upper()
        score = _float(r.get("score", ""))
        exploit = r.get("exploit", "").lower()
        in_use = bool(exploit) and any(exploit.startswith(w) for w in self.s.exploit_in_use if w)
        catalogued = r.get("kev", "").lower() in self.s.kev_true
        product = r.get("product", "")

        provides = package_provides(product, self.s.packages)
        if provides:
            name, how = product.lower(), "package-name"
        else:
            name, provides = component_in(r.get("description", ""), self.s.components)
            how = "advisory-prose"
        if provides and name:
            p = self.products.setdefault(name, {
                "provides": provides, "attribution": how, "rows": 0, "machines": set(),
                "cves": set(), "exploited": 0, "catalogued": 0, "worst": "", "max_score": 0.0,
                "versions": {}})
            p["rows"] += 1
            if machine:
                p["machines"].add(machine)
            if cve:
                p["cves"].add(cve)
            p["exploited"] += in_use
            p["catalogued"] += catalogued
            p["worst"] = worst(p["worst"], severity)
            p["max_score"] = max(p["max_score"], score)
            for v in r.get("versions", "").split(","):
                v = v.strip()
                if v:
                    p["versions"][v] = p["versions"].get(v, 0) + 1

        if in_use and machine:
            self.exploited_machines.add(machine)
        if catalogued and cve:
            c = self.catalogued.setdefault(cve, {
                "machines": set(), "due": "", "severity": "", "score": 0.0,
                "product": product, "in_use": False})
            if machine:
                c["machines"].add(machine)
            c["due"] = c["due"] or r.get("kev_due", "")[:10]
            c["severity"] = worst(c["severity"], severity)
            c["score"] = max(c["score"], score)
            c["in_use"] = c["in_use"] or in_use
        elif in_use and cve:
            self.exploited_uncatalogued.add(cve)


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon vulnerability export was read"
        + (f" ({why})" if why else "")
        + ": the defects open in the software that provides the estate's cryptography, and "
        "the census of operating systems a fleet upgrade is sized against",
        impact=("Every cryptographic reading says how a service is configured. Without this "
                "export nothing says whether the library underneath is patched, so a "
                "correctly configured service cannot be told apart from a protected one, and "
                "upgrades are planned without knowing how many machines run each operating "
                "system."),
        impact_kind=coverage.CHANGES_CONCLUSION,
        harvest=("Export the vulnerability list with no filter, as CSV, and name it with "
                 "input:; name its headings with settings: columns: if they are not the API's "
                 "field paths."),
        nature=coverage.NO_DATA)


def _product_rows(t: Tally, base: Mapping[str, Any]) -> list[CryptoAsset]:
    out = []
    for name, p in sorted(t.products.items(), key=lambda kv: (-kv[1]["rows"], kv[0])):
        n = len(p["machines"])
        flags = [f"{DEFECT_FLAG}{p['rows']}", f"{ATTRIBUTION_FLAG}{p['attribution']}"]
        if p["exploited"]:
            flags.append(f"{EXPLOITED_FLAG}{p['exploited']}")
        if p["catalogued"]:
            flags.append(f"{CATALOGUED_FLAG}{p['catalogued']}")
        versions = sorted(p["versions"], key=lambda v: -p["versions"][v])[:4]
        how = ("Recognised from the component the advisory text names, not from the product "
               "name." if p["attribution"] == "advisory-prose" else
               "Recognised from the package name.")
        out.append(CryptoAsset(
            name=f"{name} — open defects", data_state=STATE_OF_PROVIDES.get(p["provides"],
                                                                            "key-material"),
            protocol=p["provides"], role=roles.crypto_product_defects(name, n), software=name,
            verdict="weak" if (p["exploited"] or p["catalogued"]) else "unknown", flags=flags,
            hosts_count=n,
            notes=(f"{p['rows']:,} open record(s), {len(p['cves']):,} distinct identifier(s), "
                   f"against {name} on {_fp.plural(n, 'machine')}. Worst published severity "
                   f"{p['worst'] or 'not recorded'}"
                   + (f", highest score {p['max_score']:g}" if p["max_score"] else "")
                   + (f"; {p['exploited']:,} with an exploit known to be in use"
                      if p["exploited"] else "")
                   + (f"; {p['catalogued']:,} in the known exploited vulnerabilities catalogue"
                      if p["catalogued"] else "")
                   + f". {how} This software provides cryptography that other rows measure as "
                     f"configured; a well-configured service on a defective library is not a "
                     f"protected one. {EVIDENCE_LIMIT}."),
            extra={"open_defect_rows": str(p["rows"]), "distinct_defects": str(len(p["cves"])),
                   "hosts": str(n), "installed_on": sorted(p["machines"]),
                   "worst_technical_severity": p["worst"], "max_cvss": f"{p['max_score']:g}",
                   "exploit_in_use_rows": str(p["exploited"]),
                   "catalogued_rows": str(p["catalogued"]), "attribution": p["attribution"],
                   "provides": p["provides"],
                   **({"versions": " | ".join(versions)} if versions else {})},
            **base))
    return out


def _catalogued_rows(t: Tally, as_at: str, base: Mapping[str, Any]) -> list[CryptoAsset]:
    out = []
    for cve, c in sorted(t.catalogued.items(), key=lambda kv: (kv[1]["due"], kv[0])):
        n = len(c["machines"])
        due = c["due"]
        overdue = bool(due and as_at and due < as_at)
        if overdue:
            when = (f"The catalogue's due date was {due}, already past by the newest record "
                    f"in this export ({as_at}).")
        elif due:
            when = f"The catalogue's due date is {due}."
        else:
            when = "The export gives no due date for it."
        out.append(CryptoAsset(
            name=f"{cve} — catalogued exploited defect", data_state="platform-integrity",
            protocol="vulnerability", role=roles.catalogued_exploited_defect(n, overdue),
            software=c["product"], verdict="weak",
            flags=[f"{OVERDUE_FLAG}{due}" if overdue else f"{DUE_FLAG}{due or 'unstated'}"],
            hosts_count=n,
            notes=(f"{cve} is in CISA's catalogue of vulnerabilities known to be exploited, and "
                   f"is open on {_fp.plural(n, 'machine')} running "
                   f"{c['product'] or 'a product the export does not name'}. {when} Published "
                   f"severity {c['severity'] or 'not recorded'}"
                   + (f", score {c['score']:g}" if c["score"] else "")
                   + ". Here the identifier is the unit of work, because an outside authority "
                     "has named it and put a date on it."),
            extra={"cve": cve, "hosts": str(n), "installed_on": sorted(c["machines"]),
                   "due": due, "overdue": "yes" if overdue else "no", "product": c["product"],
                   "technical_severity": c["severity"], "cvss": f"{c['score']:g}",
                   "exploit_in_use": "yes" if c["in_use"] else "no"},
            **base))
    return out


def _os_rows(t: Tally, base: Mapping[str, Any]) -> list[CryptoAsset]:
    out = []
    total = sum(len(m) for m in t.os_machines.values())
    for (os_name, kind), held in sorted(t.os_machines.items(),
                                        key=lambda kv: (-len(kv[1]), kv[0])):
        n = len(held)
        share = f"{n / total:.0%}" if total else "unknown"
        open_rows = t.os_open.get((os_name, kind), 0)
        out.append(CryptoAsset(
            name=f"{os_name} ({kind.lower()})", data_state="discovery", protocol="inventory",
            role=roles.operating_system_census(os_name, kind, n), software=os_name,
            verdict="n/a", flags=[f"{OS_CENSUS_FLAG}{n}"], hosts_count=n,
            notes=(f"{_fp.plural(n, 'machine')}, {share} of the {total:,} in this export, run "
                   f"{os_name} as {kind.lower()}, with {open_rows:,} open record(s) between "
                   "them. A population, not a finding: the count a fleet upgrade is sized "
                   "against, taken machine by machine."),
            extra={"operating_system": os_name, "host_type": kind, "machines": str(n),
                   "open_defect_rows": str(open_rows)},
            **base))
    return out


def read(path: Path, s: Settings) -> tuple[list[CryptoAsset], list]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    if not path.exists():
        return [], [_missing_gap("the file named does not exist")]
    t = Tally(s)
    try:
        for row in _fp.stream(path, s.headings):
            t.add(row)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        # A partial tally would look like an answer, so none is given.
        return [], [_missing_gap(f"the file could not be read: {exc}")]
    if not t.rows:
        return [], [_missing_gap("the file holds no rows")]

    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon vulnerability export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}
    as_at = t.last_seen or when
    out = _product_rows(t, base) + _catalogued_rows(t, as_at, base) + _os_rows(t, base)

    crypto_machines = len({m for p in t.products.values() for m in p["machines"]})
    crypto_rows = sum(p["rows"] for p in t.products.values())
    overdue = sum(1 for c in t.catalogued.values() if c["due"] and as_at and c["due"] < as_at)
    out.append(CryptoAsset(
        name="Vulnerability evidence scope", data_state="discovery", protocol="inventory",
        role=roles.vulnerability_export_scope(), verdict="n/a",
        flags=[SCOPE_TECHNICAL_FLAG, f"{SCOPE_WINDOW_FLAG}{t.first_seen or '?'}..{as_at or '?'}"],
        hosts_count=len(t.machines),
        notes=(f"{t.rows:,} records on {_fp.plural(len(t.machines), 'machine')}, "
               f"{t.open_rows:,} of them open ({len(t.cves):,} distinct identifiers). The "
               f"oldest was raised {t.first_seen or 'on a date not recorded'} and the newest "
               f"{as_at or 'on a date not recorded'}: the export holds every record kept, so "
               f"this is an accumulated backlog, not a fixed window. {crypto_rows:,} of the "
               f"open records are against software that provides cryptography, on "
               f"{_fp.plural(crypto_machines, 'machine')}. {TECHNICAL_ONLY}. "
               f"{EVIDENCE_LIMIT}."),
        extra={"records": str(t.rows), "open_records": str(t.open_rows),
               "distinct_defects": str(len(t.cves)), "hosts": str(len(t.machines)),
               "first_raised": t.first_seen, "last_raised": as_at,
               "crypto_open_records": str(crypto_rows), "crypto_hosts": str(crypto_machines),
               "catalogued_open": str(len(t.catalogued)), "catalogued_overdue": str(overdue),
               "exploited_uncatalogued": str(len(t.exploited_uncatalogued)),
               "exploited_hosts": str(len(t.exploited_machines)),
               **{f"criticality_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in t.criticality.items()}},
        **base))

    gaps = []
    unset = sum(v for k, v in t.criticality.items()
                if k == "(blank)" or k.lower() in s.criticality_unset)
    if unset:
        gaps.append(coverage.gap(
            coverage.NOT_MEASURED,
            f"how critical each machine is: the vulnerability export's criticality field is "
            f"unset on {unset:,} of {t.rows:,} records"
            + (" (all of them)" if unset == t.rows else "")
            + ", so the export gives a technical severity (published score, exploit status, "
            "the exploited vulnerabilities catalogue) and no business impact",
            impact=("Defects can be ordered by how bad each one is, not by what is lost if the "
                    "machine holding it fails, so a queue built on this export alone can put a "
                    "test machine ahead of one the business relies on without anything in the "
                    "data showing it."),
            impact_kind=coverage.CHANGES_CONCLUSION,
            harvest=("Mark each machine's criticality in the endpoint console, where the field "
                     "already exists, and export again."),
            nature=coverage.LOW_FIDELITY))
    return out, gaps


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows and gap, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    assets, gaps = read(ctx.input, Settings(ctx))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon vulnerabilities in cryptographic software",
                gap_prefix=False)
