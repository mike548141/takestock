"""Fetch DMARC aggregate rows from Cloudflare DMARC Management.

Cloudflare receives a zone's aggregate reports when the zone's DMARC record
sends them to Cloudflare, and serves the parsed rows through its GraphQL
analytics API as the ``dmarcReportsAdaptive`` dataset. A query may span at
most about a month, and the account's plan sets how far back rows are kept,
so this fetches in 30-day windows from now backwards until the API refuses,
and the caller should keep what it fetched: rows older than the plan's
retention cannot be fetched again.

The token needs the zone permission *Email Security DMARC Reports: Read*
(read-only). It is read from the environment variable named by
``token_env`` or the macOS keychain item named by ``keychain_item``, and is
passed to ``curl`` on standard input, never on the command line.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta

from ..util import keychain_secret

ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"
WINDOW_DAYS = 30
FIELDS = ("datetime disposition dkim domain envelopeFrom envelopeTo evaluatedReason headerFrom "
          "matchingMessages orgName policyDKIMAlignmentMode policyDomain policyPercentage "
          "policySPFAlignmentMode policySubDomain recordId reportBegin reportEnd reportId "
          "sourceIP sourceLocationName sourceOrgName sourcePTR spf spfMFromDomain")


class FetchError(RuntimeError):
    pass


def token(token_env: str = "CLOUDFLARE_API_TOKEN", keychain_item: str = "") -> str:
    value = os.environ.get(token_env, "") or (keychain_secret(keychain_item) if keychain_item else "")
    if not value:
        raise FetchError(f"no Cloudflare token: set ${token_env}"
                         + (f" or keychain item {keychain_item!r}" if keychain_item else ""))
    return value


def _post(query: str, bearer: str, timeout: int = 60) -> dict:
    headers = f"Authorization: Bearer {bearer}\nContent-Type: application/json\n"
    proc = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), "-H", "@-", ENDPOINT,
         "--data-binary", json.dumps({"query": query})],
        input=headers, capture_output=True, text=True, timeout=timeout + 5)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise FetchError(f"Cloudflare returned no JSON: {proc.stderr.strip()[:200]}") from exc


def _retention(message: str) -> timedelta | None:
    """The retention period a refusal names ("older than 4w4d"), or None."""
    m = re.search(r"older than\s+(?:(\d+)w)?(?:(\d+)d)?", message)
    if not m or not (m.group(1) or m.group(2)):
        return None
    return timedelta(weeks=int(m.group(1) or 0), days=int(m.group(2) or 0))


def fetch(zone_id: str, bearer: str, now: datetime | None = None,
          max_windows: int = 13) -> tuple[list[dict], str]:
    """(rows, why fetching stopped), newest window first."""
    end = (now or datetime.now(UTC)).replace(microsecond=0)
    rows: list[dict] = []
    stop = f"{max_windows} windows fetched"
    for _ in range(max_windows):
        start = end - timedelta(days=WINDOW_DAYS)
        since, until = start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")
        q = (f'{{ viewer {{ zones(filter:{{zoneTag:"{zone_id}"}}) {{ dmarcReportsAdaptive(limit:10000, '
             f'filter:{{datetime_geq:"{since}", datetime_lt:"{until}"}}, orderBy:[datetime_ASC]) '
             f'{{ {FIELDS} }} }} }} }}')
        doc = _post(q, bearer)
        if doc.get("errors"):
            msg = str(doc["errors"][0].get("message", ""))
            edge = _retention(msg)
            if edge is None:
                raise FetchError(msg)
            # The plan's retention edge: fetch the part of this window inside it, then stop.
            first = (now or datetime.now(UTC)).replace(microsecond=0) - edge + timedelta(hours=1)
            stop = f"retention reached ({msg.split(',')[0]})"
            if first < end:
                doc = _post(q.replace(since, first.strftime("%Y-%m-%dT%H:%M:%SZ")), bearer)
                zones = doc.get("data", {}).get("viewer", {}).get("zones") or []
                rows += zones[0].get("dmarcReportsAdaptive", []) if zones else []
            break
        zones = doc.get("data", {}).get("viewer", {}).get("zones") or []
        got = zones[0].get("dmarcReportsAdaptive", []) if zones else []
        rows += got
        if len(got) >= 10000:
            stop = "a window returned the 10,000-row limit; narrow the window"
        end = start
    return rows, stop
