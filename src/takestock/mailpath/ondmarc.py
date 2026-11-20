"""Fetch DMARC aggregate data from Red Sift OnDMARC, a commercial DMARC reporting service.

**What OnDMARC holds.** A domain whose DMARC record sends its aggregate
reports to OnDMARC has them parsed and kept by the service, which then
names each sending source ("a known source" such as a mail platform, or an
address) and classifies it: ``valid`` (shown as an asset), ``invalid`` (a
threat), ``forwarder``, ``misconfigured``, ``insufficient_data`` or
``unknown``. Its API serves the parsed data back. That naming and
classification is the part an RFC 7489 report does not carry, and
:func:`sources_summary` keeps it.

**What this fetches**, per domain and period (OnDMARC V2 API):

- ``GET /reports/aggregate/sources``: one row per sending source, with its
  name, type, business type, classification, the service's recommended
  classification, and pass counts. Paged by ``page`` and ``page_size``
  (at most 1,000).
- ``GET /reports/aggregate/analyst``: raw per-record rows, close to the
  report rows themselves (receiver, source address, reverse DNS, network
  owner, header-from, envelope-from, aligned SPF and DKIM results,
  disposition, day). It needs the *DMARC Analyst* feature on the account and
  is refused with HTTP 402 without it. Paged by a JSON ``pagination_model``;
  the reference does not state a page-size limit, so 1,000 is used. It rolls
  subdomain traffic into the queried domain, so its volumes can exceed the
  ``/reports/aggregate/*`` figures for the same domain.
- ``GET /reports/aggregate/ips``: one row per sending address for the whole
  period, fetched only when the analyst endpoint is refused. It carries the
  address, its network owner and country, and pass counts, and nothing else
  (see *What is lost* below).
- ``GET /domains/flat``: the account's domain names, when no domain is given.

**What is lost** when the per-address rows stand in for the analyst rows:
the receiver that reported each row, the envelope-from domain, reverse DNS,
the disposition receivers applied (only a count of failures overridden to a
passing disposition survives), the day (each row covers the whole period),
and the header-from subdomain (subdomain mail is counted under the queried
domain; ``subdomain_emails_total_count`` says how much). The aligned SPF and
DKIM results survive: the four pass counts split each address's messages
exactly into both-pass, DKIM-only, SPF-only and neither. They are read as
aligned (policy-evaluated) results because the reference defines
``dmarc_pass_count`` as DKIM or SPF passing.

**What OnDMARC cannot see** is what any DMARC report cannot (see
:mod:`.dmarc`), and only the reports sent to it: a domain reporting
elsewhere is invisible here.

**Refusals are kept.** A call the API refuses (wrong region, a domain not in
the account, a feature not enabled, rate limiting that outlasts the retries)
is returned as a ``refused`` row and a note, so a saved archive records that
a domain was refused rather than reading as a domain with no mail. A
rejected key (HTTP 401) stops the fetch with :class:`FetchError`.

**The key** needs an OnDMARC API key (a super-user creates it in the user
profile; API access is an add-on to the account). It is read from the
environment variable named by ``env`` or the macOS keychain item named by
``keychain_item``, and passed to ``curl`` on standard input as a header,
never on the command line. The account's data lives in one region (UK, EU or
US); a key used against another region's base URL is refused.

The reference documents HTTP 429 for rate limiting but no limits or headers;
a 429 or 5xx answer is retried three times, honouring ``Retry-After`` when
sent.

Sources relied on:

- https://docs.redsift.com/ondmarc.yaml (the OnDMARC V2 OpenAPI 3.1
  specification: base URLs, the ``Authorization: Api-Key`` scheme, every
  path, parameter and field used here)
- https://docs.redsift.com/llms.txt (the index that publishes the
  specification)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

from ..util import _split_response, keychain_secret
from .dmarc import Record

BASES = {
    "uk": "https://rpc.redsift.cloud/api/ondmarc/v2",
    "eu": "https://rpc.eu.redsift.cloud/api/ondmarc/v2",
    "us": "https://rpc.us.redsift.cloud/api/ondmarc/v2",
}
PAGE_SIZE = 1000          # the documented maximum for page/page_size endpoints
MAX_PAGES = 500           # a guard against a paging loop that never ends
RETRIES = 3
ARCHIVE_FORMAT = "takestock.ondmarc/1"

_sleep: Callable[[float], None] = time.sleep


class FetchError(RuntimeError):
    pass


def token(env: str = "ONDMARC_API_KEY", keychain_item: str = "") -> str:
    value = os.environ.get(env, "") or (keychain_secret(keychain_item) if keychain_item else "")
    if not value:
        raise FetchError(f"no OnDMARC API key: set ${env}"
                         + (f" or keychain item {keychain_item!r}" if keychain_item else ""))
    return value


def _get(url: str, api_key: str, timeout: int = 120) -> tuple[int, dict | None, dict]:
    """(HTTP status, parsed JSON body or None, kept headers). Status 0: no HTTP answer."""
    headers = f"Authorization: Api-Key {api_key}\nAccept: application/json\n"
    try:
        proc = subprocess.run(["curl", "-sS", "-D", "-", "-m", str(timeout), "-H", "@-", url],
                              input=headers, capture_output=True, text=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError) as exc:
        return 0, {"message": f"curl failed: {exc}"}, {}
    body, meta = _split_response(proc.stdout)
    try:
        doc = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        doc = None
    if not meta.get("status"):
        return 0, {"message": (proc.stderr.strip() or body.strip())[:200] or "no answer"}, {}
    return int(meta["status"]), doc, meta.get("headers", {})


def _message(status: int, doc: dict | None) -> str:
    if isinstance(doc, dict):
        if doc.get("message"):
            return str(doc["message"])
        errs = doc.get("errors")
        if isinstance(errs, list) and errs:
            return "; ".join(str(e.get("detail") or e.get("title") or e) for e in errs
                             if isinstance(e, dict))
    return f"HTTP {status}"


class _Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _call(base: str, path: str, params: dict, api_key: str) -> dict:
    """One GET, retried on 429 and 5xx. Raises FetchError on 401, _Refused otherwise."""
    url = f"{base}{path}?{urlencode(params)}" if params else f"{base}{path}"
    for attempt in range(RETRIES + 1):
        status, doc, headers = _get(url, api_key)
        if status == 200 and isinstance(doc, dict):
            return doc
        if status == 200:
            raise _Refused(status, "HTTP 200 with a body that is not a JSON object")
        if status == 401:
            raise FetchError(f"OnDMARC rejected the API key (401: {_message(status, doc)}); "
                             "check the key and the region")
        if (status == 429 or status >= 500 or status == 0) and attempt < RETRIES:
            wait = headers.get("retry-after", "")
            _sleep(float(wait) if wait.isdigit() else 2.0 ** (attempt + 1))
            continue
        raise _Refused(status, _message(status, doc))
    raise _Refused(0, "retries exhausted")  # unreachable; keeps the type checker sure


def _paged(base: str, path: str, params: dict, api_key: str, page_size: int) -> tuple[list, int]:
    """Every item from a page/page_size endpoint, and the number of pages read."""
    items: list = []
    for page in range(MAX_PAGES):
        doc = _call(base, path, {**params, "page": page, "page_size": page_size}, api_key)
        data = doc.get("data") or []
        items += data
        pag = doc.get("pagination") or {}
        if not data or pag.get("page_size") == 0 or page + 1 >= int(pag.get("page_count") or 1):
            return items, page + 1
    raise _Refused(0, f"stopped after {MAX_PAGES} pages; the paging never ended")


def _analyst(base: str, domain: str, since: str, until: str, api_key: str,
             page_size: int) -> tuple[list, list[str]]:
    rows: list = []
    notes: list[str] = []
    total = None
    footer: dict = {}
    for page in range(MAX_PAGES):
        params = {"from_date": since, "to_date": until, "domain": domain,
                  "pagination_model": json.dumps({"page": page, "pageSize": page_size})}
        doc = _call(base, "/reports/aggregate/analyst", params, api_key)
        if doc.get("mode") not in (None, "flat"):
            raise _Refused(200, f"analyst answered in {doc.get('mode')!r} mode, not flat rows")
        data = doc.get("data") or []
        rows += data
        if page == 0:
            total = doc.get("rowCount")
            footer = doc.get("aggregateRow") or {}
        if not data or len(data) < page_size or (total is not None and len(rows) >= int(total)):
            break
    else:
        notes.append(f"{domain}: analyst paging stopped at {MAX_PAGES} pages; rows may be missing")
    if total is not None and len(rows) != int(total):
        notes.append(f"{domain}: analyst said {int(total)} rows and gave {len(rows)}")
    want = footer.get("email_volume") if total is not None else None
    got = sum(int(r.get("email_volume") or 0) for r in rows)
    if isinstance(want, (int, float)) and int(want) != got:
        notes.append(f"{domain}: analyst rows sum to {got} messages; its own total says {int(want)} "
                     "(rows may have moved between pages)")
    return rows, notes


def _day(value: str | date) -> str:
    text = value.isoformat() if isinstance(value, date) else str(value)
    try:
        return date.fromisoformat(text[:10]).isoformat()
    except ValueError as exc:
        raise FetchError(f"not a YYYY-MM-DD date: {value!r}") from exc


def domains_in_account(api_key: str, region: str = "uk") -> list[str]:
    """The domain names the key can see (``GET /domains/flat``)."""
    try:
        names, _ = _paged(_base(region), "/domains/flat", {}, api_key, PAGE_SIZE)
    except _Refused as exc:
        raise FetchError(f"OnDMARC refused the domain list ({exc.status}: {exc.message})") from exc
    return [str(n).lower() for n in names]


def _base(region: str) -> str:
    try:
        return BASES[region.lower()]
    except KeyError as exc:
        raise FetchError(f"unknown OnDMARC region {region!r}; one of {', '.join(BASES)}") from exc


def fetch(api_key: str, domains: Iterable[str], region: str, since: str | date, until: str | date,
          analyst: bool = True, page_size: int = PAGE_SIZE) -> tuple[list[dict], list[str]]:
    """(raw rows, notes) for each domain over ``since`` to ``until`` (UTC days).

    Each raw row is ``{"kind", "domain", "from_date", "to_date", "row"}``, where
    ``kind`` is ``source`` (a sources row), ``record`` (an analyst row), ``ip``
    (a per-address row) or ``refused`` (``row`` then holds the endpoint, HTTP
    status and the API's message). No domains: every domain in the account.
    """
    base = _base(region)
    since, until = _day(since), _day(until)
    names = [d.strip().lower() for d in domains if d.strip()] or domains_in_account(api_key, region)
    raw: list[dict] = []
    notes: list[str] = [f"OnDMARC {region.upper()} region, {since} to {until}, {len(names)} domain(s)"]

    def add(kind: str, domain: str, rows: list) -> None:
        raw.extend({"kind": kind, "domain": domain, "from_date": since, "to_date": until, "row": r}
                   for r in rows)

    def refused(domain: str, path: str, exc: _Refused) -> None:
        add("refused", domain, [{"endpoint": path, "status": exc.status, "message": exc.message}])
        notes.append(f"REFUSED {domain} {path}: {exc.status} {exc.message}")

    window = {"from_date": since, "to_date": until}
    for domain in names:
        try:
            rows, pages = _paged(base, "/reports/aggregate/sources", {**window, "domain": domain},
                                 api_key, page_size)
            add("source", domain, rows)
            notes.append(f"{domain}: {len(rows)} sources ({pages} page(s))")
        except _Refused as exc:
            refused(domain, "/reports/aggregate/sources", exc)
        if analyst:
            try:
                rows, extra = _analyst(base, domain, since, until, api_key, page_size)
                add("record", domain, rows)
                notes.append(f"{domain}: {len(rows)} analyst rows")
                notes += extra
                continue
            except _Refused as exc:
                refused(domain, "/reports/aggregate/analyst", exc)
                notes.append(f"{domain}: falling back to per-address totals (no receiver, envelope, "
                             "reverse DNS, disposition or day)")
        try:
            rows, pages = _paged(base, "/reports/aggregate/ips", {**window, "domain": domain},
                                 api_key, page_size)
            add("ip", domain, rows)
            notes.append(f"{domain}: {len(rows)} sending addresses ({pages} page(s))")
        except _Refused as exc:
            refused(domain, "/reports/aggregate/ips", exc)
    return raw, notes


def refusals(raw: list[dict]) -> list[dict]:
    """The refused calls a fetch recorded, as ``{"domain", "endpoint", "status", "message"}``."""
    return [{"domain": r["domain"], **r["row"]} for r in raw if r.get("kind") == "refused"]


def _low(value: object) -> str:
    return str(value or "").strip().lower()


def _record_from_analyst(entry: dict) -> Record:
    r = entry["row"]
    return Record(
        header_from=_low(r.get("header_from") or r.get("ondmarc_domain") or entry["domain"]),
        source_ip=str(r.get("source_ip") or ""),
        count=int(r.get("email_volume") or 0),
        spf=_low(r.get("spf_result")) or "fail",
        dkim=_low(r.get("dkim_result")) or "fail",
        disposition=_low(r.get("disposition")) or "none",
        reporter=str(r.get("receiver") or ""),
        source_ptr=_low(r.get("source_hostname")).rstrip("."),
        source_org=str(r.get("source_asn") or ""),
        envelope_from=_low(r.get("envelope_from")),
        begin=str(r.get("date") or entry["from_date"]),
        end=str(r.get("date") or entry["to_date"]),
        policy=_low(r.get("policy_p")),
    )


def _records_from_ip(entry: dict) -> list[Record]:
    """Split one address's period totals into its four aligned-result combinations."""
    r = entry["row"]
    m = r.get("email_metrics") or {}
    total = int(m.get("total_count") or 0)
    both = int(m.get("dkim_and_spf_pass_count") or 0)
    dkim_only = int(m.get("dkim_only_pass_count") or 0)
    spf_only = int(m.get("spf_only_pass_count") or 0)
    neither = max(0, total - both - dkim_only - spf_only)
    out = []
    for count, spf, dkim in ((both, "pass", "pass"), (dkim_only, "fail", "pass"),
                             (spf_only, "pass", "fail"), (neither, "fail", "fail")):
        if count:
            out.append(Record(
                header_from=entry["domain"], source_ip=str(r.get("ip") or ""), count=count,
                spf=spf, dkim=dkim, disposition="unknown",
                source_org=str(r.get("autonomous_system_org") or ""),
                begin=entry["from_date"], end=entry["to_date"]))
    return out


def to_records(raw: list[dict]) -> list[Record]:
    """DMARC records from analyst rows, or from per-address rows for a domain with none.

    A domain with analyst rows never also counts its per-address rows, so an
    archive holding both is not counted twice.
    """
    detailed = {e["domain"] for e in raw if e.get("kind") == "record"}
    out: list[Record] = []
    for e in raw:
        if e.get("kind") == "record":
            out.append(_record_from_analyst(e))
        elif e.get("kind") == "ip" and e["domain"] not in detailed:
            out += _records_from_ip(e)
    return out


def _from_sources_row(entry: dict) -> dict:
    r = entry["row"]
    m = r.get("email_metrics") or {}
    cls = r.get("classification") or {}
    rec = cls.get("recommendation") or {}
    details = rec.get("details") or {}
    rep = r.get("reputation") or {}
    total = int(m.get("total_count") or r.get("email_count") or 0)
    passed = int(m.get("dmarc_pass_count") or 0)
    return {
        "domain": entry["domain"], "basis": "sources",
        "source_id": r.get("source_id") or "", "source": r.get("display_name") or r.get("source_id") or "",
        "known_source": r.get("known_source_display_name") or "",
        "source_type": r.get("source_type") or "", "business_type": r.get("business_type") or "",
        "classification": cls.get("value") or r.get("classification_value") or "unknown",
        "recommendation": rec.get("value") or "",
        "recommendation_detail": "/".join(str(details[k]) for k in ("subCategory", "confidence")
                                          if details.get(k)),
        "messages": total, "dmarc_pass": passed, "dmarc_fail": max(0, total - passed),
        "spf_pass": int(m.get("spf_pass_count") or 0), "dkim_pass": int(m.get("dkim_pass_count") or 0),
        "fail_overridden_to_pass": int(m.get("dmarc_fail_override_to_passing_disposition_count") or 0),
        "addresses": int(r.get("distinct_ip_count") or 0),
        # The service's own figures; the reference does not say what blocklist_count counts.
        "blocklist_count": r.get("blocklist_count"), "suspicious_addresses": rep.get("suspicious_ip_count"),
        "blocklisted_addresses": None,
        "trusted": rep.get("is_trusted", r.get("reputation_trusted")),
    }


def _from_analyst_rows(entries: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], dict] = {}
    ips: dict[tuple[str, str], set[str]] = {}
    listed: dict[tuple[str, str], set[str]] = {}
    for e in entries:
        r = e["row"]
        key = (e["domain"], str(r.get("source") or r.get("source_ip") or ""))
        g = groups.setdefault(key, {
            "domain": e["domain"], "basis": "records", "source_id": key[1],
            "source": r.get("source_display_name") or key[1], "known_source": "", "source_type": "",
            "business_type": "", "classification": r.get("classification") or "unknown",
            "recommendation": r.get("recommendation") or "", "recommendation_detail": "",
            "messages": 0, "dmarc_pass": 0, "dmarc_fail": 0, "spf_pass": 0, "dkim_pass": 0,
            "fail_overridden_to_pass": None, "addresses": 0, "blocklist_count": None,
            "suspicious_addresses": None, "blocklisted_addresses": 0, "trusted": None})
        g["messages"] += int(r.get("email_volume") or 0)
        g["dmarc_pass"] += int(r.get("pass_volume") or 0)
        g["dmarc_fail"] += int(r.get("fail_volume") or 0)
        g["spf_pass"] += int(r.get("spf_pass_volume") or 0)
        g["dkim_pass"] += int(r.get("dkim_pass_volume") or 0)
        if r.get("source_ip"):
            ips.setdefault(key, set()).add(str(r["source_ip"]))
            if r.get("has_blocklist"):
                listed.setdefault(key, set()).add(str(r["source_ip"]))
    for key, g in groups.items():
        g["addresses"] = len(ips.get(key, ()))
        g["blocklisted_addresses"] = len(listed.get(key, ()))
    return list(groups.values())


def sources_summary(raw: list[dict]) -> list[dict]:
    """OnDMARC's own view of each domain's senders: its name, type and classification
    for every source, with message and pass counts, largest first.

    Built from the sources rows; a domain with none (its sources call was refused)
    is summarised from its analyst rows instead, and ``basis`` says which. A
    figure one basis cannot give is None, never 0: ``blocklist_count``,
    ``suspicious_addresses`` and ``trusted`` come only from sources rows, and
    ``blocklisted_addresses`` (addresses seen on a blocklist) only from analyst rows.
    """
    have = {e["domain"] for e in raw if e.get("kind") == "source"}
    out = [_from_sources_row(e) for e in raw if e.get("kind") == "source"]
    out += _from_analyst_rows([e for e in raw if e.get("kind") == "record" and e["domain"] not in have])
    return sorted(out, key=lambda s: (s["domain"], -s["messages"], s["source"]))


def save(path: Path, raw: list[dict], notes: list[str], region: str) -> None:
    """Write the archive a later run reads: rows older than the account keeps cannot be fetched again."""
    doc = {"format": ARCHIVE_FORMAT, "fetched": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "region": region, "notes": notes, "rows": raw}
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


def load_archive(path: Path) -> tuple[list[dict], list[str]]:
    """(raw rows, notes) from a file :func:`save` wrote."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("format") != ARCHIVE_FORMAT:
        raise ValueError(f"{path} is not an OnDMARC archive ({ARCHIVE_FORMAT})")
    return list(doc.get("rows") or []), list(doc.get("notes") or [])


def is_archive(doc: object) -> bool:
    return isinstance(doc, dict) and doc.get("format") == ARCHIVE_FORMAT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m takestock.mailpath.ondmarc",
        description="Fetch DMARC aggregate data from Red Sift OnDMARC and save it as an archive.")
    ap.add_argument("--domain", action="append", default=[],
                    help="a domain in the OnDMARC account (repeatable; default: every domain)")
    ap.add_argument("--region", choices=sorted(BASES), default="uk", help="the account's region")
    today = datetime.now(UTC).date()
    ap.add_argument("--since", default=(today - timedelta(days=30)).isoformat(), help="first day, YYYY-MM-DD")
    ap.add_argument("--until", default=today.isoformat(), help="last day, YYYY-MM-DD")
    ap.add_argument("--env", default="ONDMARC_API_KEY", help="environment variable holding the API key")
    ap.add_argument("--keychain", default="", help="macOS keychain item holding the API key")
    ap.add_argument("--no-analyst", action="store_true",
                    help="skip the per-record endpoint and fetch per-address totals")
    ap.add_argument("--out", type=Path, required=True, help="archive file to write (.json)")
    args = ap.parse_args(argv)
    try:
        key = token(args.env, args.keychain)
        raw, notes = fetch(key, args.domain, args.region, args.since, args.until,
                           analyst=not args.no_analyst)
    except FetchError as exc:
        print(f"ondmarc: {exc}", file=sys.stderr)
        return 1
    save(args.out, raw, notes, args.region)
    for line in notes:
        print(line, file=sys.stderr)
    recs = to_records(raw)
    print(f"{len(raw)} rows, {len(recs)} records, {sum(r.count for r in recs)} messages -> {args.out}")
    # A refused call is not "no mail": exit non-zero so a script cannot miss it.
    return 3 if refusals(raw) else 0


if __name__ == "__main__":
    sys.exit(main())
