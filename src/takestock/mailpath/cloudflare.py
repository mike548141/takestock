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


# ---------------------------------------------------------------------------
# Email Routing and Email Sending
#
# A zone that receives mail through Cloudflare Email Routing, or sends through
# Cloudflare's email sending service, has a per-message analytics dataset of
# each: ``emailRoutingAdaptive`` and ``emailSendingAdaptive``. Each message
# can appear as several events; only its last event is kept, so a message is
# counted once. The subject, message identifier and session are never asked
# for, and addresses are reduced to their domains before anything is kept.
# The token needs the zone's Analytics read permission.
# ---------------------------------------------------------------------------

EMAIL_DATASETS = {
    "routing": ("emailRoutingAdaptive",
                "datetime action status eventType from to spf dkim dmarc arc isSpam isNDR isLastEvent"),
    "sending": ("emailSendingAdaptive",
                "datetime status eventType from to sendingDomain spf dkim dmarc isSpam isNDR "
                "isLastEvent errorCause"),
}


def _domain(address: str) -> str:
    a = (address or "").strip().strip("<>").lower()
    return a.rpartition("@")[2] if "@" in a else ""


def email_rows(raw: list[dict], kind: str) -> list[dict]:
    """Platform-log rows (see :mod:`.platformlog`) from one dataset's raw rows."""
    out = []
    for r in raw:
        if r.get("isLastEvent") == 0:
            continue
        recipients = sorted({_domain(x) for x in str(r.get("to") or "").split(",") if _domain(x)})
        out.append({
            "time": r.get("datetime") or "",
            "direction": "inbound" if kind == "routing" else "outbound",
            "sender_domain": _domain(str(r.get("from") or "")) or str(r.get("sendingDomain") or "").lower(),
            "recipient_domains": recipients,
            "size": None,
            "tls": "",
            "spf": str(r.get("spf") or ""),
            "dkim": str(r.get("dkim") or ""),
            "dmarc": str(r.get("dmarc") or ""),
            "remote_host": "",
            "remote_ip": "",
            "connector": "Cloudflare Email Routing" if kind == "routing" else "Cloudflare email sending",
            "delivery": str(r.get("action") or r.get("status") or r.get("eventType") or ""),
            "source": f"cloudflare-email-{kind}",
        })
    return out


def fetch_email(zone_id: str, bearer: str, kind: str, now: datetime | None = None,
                max_windows: int = 13) -> tuple[list[dict], str]:
    """(platform-log rows, why fetching stopped) for ``kind`` "routing" or "sending"."""
    dataset, fields = EMAIL_DATASETS[kind]
    end = (now or datetime.now(UTC)).replace(microsecond=0)
    raw: list[dict] = []
    stop = f"{max_windows} windows fetched"
    for _ in range(max_windows):
        start = end - timedelta(days=WINDOW_DAYS)
        since, until = start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")
        q = (f'{{ viewer {{ zones(filter:{{zoneTag:"{zone_id}"}}) {{ {dataset}(limit:10000, '
             f'filter:{{datetime_geq:"{since}", datetime_lt:"{until}"}}) {{ {fields} }} }} }} }}')
        doc = _post(q, bearer)
        if doc.get("errors"):
            msg = str(doc["errors"][0].get("message", ""))
            if _retention(msg) is not None or "quota" in msg:
                stop = f"retention or range limit reached ({msg.split(',')[0]})"
                break
            raise FetchError(msg)
        zones = doc.get("data", {}).get("viewer", {}).get("zones") or []
        raw += zones[0].get(dataset, []) if zones else []
        end = start
    return email_rows(raw, kind), stop
