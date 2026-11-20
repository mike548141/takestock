"""Google Workspace mail data beyond headers: Gmail log events, Gmail usage, Postmaster Tools.

Three read-only Google APIs, each with its own reach.

**Gmail log events** (Admin SDK Reports API, ``activities.list`` with
``applicationName=gmail``; https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail).
Every delivery stage Gmail logged for the organisation's mail: one event per
stage, with ``eventName`` always ``delivery`` and ``event_info.mail_event_type``
saying what happened. The fields of an event are those of the Gmail log
schema (https://support.google.com/a/answer/12384955, *Schema for Gmail logs in
BigQuery*, which the activity page refers to): ``message_info.message_set``
(inbound, outbound, internal), ``message_info.source`` and ``destination``
addresses, ``payload_size``, ``num_message_attachments``, and
``connection_info``: ``smtp_tls_state`` and ``smtp_tls_version`` of the SMTP
leg, ``spf_pass``, ``dkim_pass``, ``dmarc_pass``, the remote address and host,
the SMTP reply code. ``message_info.action_type`` gives the delivery outcome.
The Reports API has served these events since September 2025, and only to
editions with audit-log eligible licences
(https://workspaceupdates.googleblog.com/2025/09/updates-to-gmail-log-events.html);
anything else is refused, and a refusal is reported as one, never as "no mail".
A request may span at most 30 days, so a longer period is fetched in windows.

The activity page documents only ``event_info``; how ``message_info`` is nested
in an API response (one nested message per level, or dotted names) is not
documented, so :func:`_flatten` reads any nesting into dotted names and a field
is matched by the end of its name.

Each message becomes one row of the schema the mail-path sources share::

    {"time", "direction", "sender_domain", "recipient_domains", "size", "tls",
     "spf", "dkim", "dmarc", "remote_host", "remote_ip", "connector",
     "delivery", "source": "google-gmail-log"}

with ``""`` where Gmail did not say. Events are grouped by the message's
RFC 5322 Message-ID while reading; the ID itself is never kept, nor any
address (only its domain), subject, attachment name or body. Post-delivery
events (opened, moved, clicked) are not mail flow and are skipped. ``tls`` is
the weakest the leg facing outside recorded: the inbound SMTP leg for inbound
mail, the outbound leg for outbound. ``delivery`` is the worst outcome any
stage recorded.

*What it cannot see.* Hops before Gmail's inbound server or after its
outbound one, the name of the server that connected inbound (only its
address), and anything another platform handled.

**Gmail usage** (Reports API ``customerUsageReports`` and ``userUsageReport``;
https://developers.google.com/workspace/admin/reports/v1/appendix/usage/customer/gmail and
https://developers.google.com/workspace/admin/reports/v1/appendix/usage/user/gmail).
Daily counts for every edition: mail sent, received, delivered, rejected,
rerouted, spam, and inbound and outbound counts encrypted and unencrypted.
Dates are Pacific time, and the latest days may not be available yet (the
response's warnings say which). Per-user rows are
reduced to counts here: how many users, how many sent or received anything,
and their totals. No user is named in the output.

*What it cannot see.* Anything per message: no domains, routes, sizes or TLS
versions, only the encrypted count.

**Postmaster Tools** (Gmail Postmaster Tools API v2,
``domains.domainStats.query`` and ``domains.getComplianceStatus``;
https://developers.google.com/workspace/gmail/postmaster/reference/rest). How
Gmail, as a *receiver*, saw mail from each domain: daily spam rate, SPF, DKIM
and DMARC success rates, the share of mail encrypted with TLS in each
direction, delivery errors, and the bulk-sender compliance status. v2 replaced
v1's ``trafficStats``; v1's discovery document is no longer served. v2 offers
no domain or IP reputation. Only domains verified in Postmaster Tools by the
granting account return data, and only on days with enough mail to Gmail
users; any other domain is refused (``PERMISSION_DENIED``) and reported so.

*What it cannot see.* Mail to anyone but Gmail and Workspace users.

**The grant.** An installed-app OAuth client (Google Cloud console, type
*Desktop app*), authorised with PKCE on a ``127.0.0.1`` loopback redirect
(https://developers.google.com/identity/protocols/oauth2/native-app), for
read-only scopes only: ``admin.reports.audit.readonly``,
``admin.reports.usage.readonly`` and ``postmaster.traffic.readonly``. Listing
Postmaster domains would need ``postmaster.domain``, which can also change
them, so the domains are named by the caller instead. The client's id and
secret come from the environment or a keychain item; the refresh token is
stored in the macOS keychain, fed to ``security`` on standard input, and an
access token is minted from it at run time. Every secret reaches ``curl`` on
standard input, never on its command line, and nothing here prints one.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..util import keychain_secret
from .headers import TLS_UNSTATED

REPORTS = "https://admin.googleapis.com/admin/reports/v1"
POSTMASTER = "https://gmailpostmastertools.googleapis.com/v2"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = (
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/postmaster.traffic.readonly",
)
GMAIL_WINDOW = timedelta(days=30)
SOURCE = "google-gmail-log"


class FetchError(RuntimeError):
    pass


class Refused(FetchError):
    """The API refused the request: no licence, no privilege, or no access to the domain."""

    def __init__(self, status: int, reason: str, message: str):
        super().__init__(f"HTTP {status} {reason}: {message}".strip())
        self.status, self.reason, self.message = status, reason, message


# ---------------------------------------------------------------- HTTP


def _curl(args: list[str], stdin: str, timeout: int) -> tuple[int, str]:
    """Run curl, the status code written after the body on its own last line."""
    proc = subprocess.run(["curl", "-sS", "-m", str(timeout), "-w", "\n%{http_code}", *args],
                          input=stdin, capture_output=True, text=True, timeout=timeout + 5)
    body, _, code = proc.stdout.rpartition("\n")
    if not code.isdigit() or code == "000":
        raise FetchError(f"no response: {proc.stderr.strip()[:200]}")
    return int(code), body


def _http(method: str, url: str, bearer: str, body: dict | None = None,
          timeout: int = 120) -> tuple[int, dict]:
    """One request with the bearer token on curl's standard input. (status, JSON body)."""
    headers = f"Authorization: Bearer {bearer}\nAccept: application/json\n"
    args = ["-X", method, "-H", "@-", url]
    if body is not None:
        headers += "Content-Type: application/json\n"
        args += ["--data-binary", json.dumps(body)]
    status, text = _curl(args, headers, timeout)
    try:
        return status, (json.loads(text) if text.strip() else {})
    except json.JSONDecodeError:
        return status, {"error": {"code": status, "message": text.strip()[:200]}}


_sleep: Callable[[float], None] = time.sleep
_RETRY_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "backendError", "RATE_LIMIT_EXCEEDED"}


def _error(doc: dict) -> tuple[str, str]:
    """(reason, message) from a Google error body."""
    raw = doc.get("error")
    err: dict = raw if isinstance(raw, dict) else {}
    reason = str(err.get("status", ""))
    for e in err.get("errors") or []:
        reason = str(e.get("reason") or reason)
    for d in err.get("details") or []:
        if isinstance(d, dict) and d.get("reason"):
            reason = str(d["reason"])
    return reason, str(err.get("message", ""))


def _call(method: str, url: str, bearer: str, body: dict | None = None, retries: int = 4) -> dict:
    """A request, retried with backoff while Google says it is rate-limited or busy.

    A daily quota running out is not retried: it is reported, because waiting
    seconds will not bring it back.
    """
    for attempt in range(retries + 1):
        status, doc = _http(method, url, bearer, body)
        if 200 <= status < 300:
            return doc
        reason, message = _error(doc)
        busy = status in (429, 500, 502, 503, 504) or reason in _RETRY_REASONS
        if busy and reason != "quotaExceeded" and attempt < retries:
            _sleep(min(60.0, 2.0 ** attempt * 2))
            continue
        if status in (401, 403, 404) or reason == "quotaExceeded":
            raise Refused(status, reason, message)
        raise FetchError(f"HTTP {status} {reason}: {message}".strip())
    raise FetchError("unreachable")  # pragma: no cover


# ---------------------------------------------------------------- OAuth


@dataclass
class Client:
    client_id: str
    client_secret: str = ""


def _parse_client(value: str) -> Client:
    """The Google console's downloaded client JSON, or ``CLIENT_ID:CLIENT_SECRET``."""
    value = value.strip()
    if value.startswith("{"):
        doc = json.loads(value)
        doc = doc.get("installed") or doc.get("web") or doc
        return Client(str(doc.get("client_id", "")), str(doc.get("client_secret", "")))
    cid, _, secret = value.partition(":")
    return Client(cid.strip(), secret.strip())


def client(keychain_item: str = "", id_env: str = "GOOGLE_OAUTH_CLIENT_ID",
           secret_env: str = "GOOGLE_OAUTH_CLIENT_SECRET") -> Client:
    if os.environ.get(id_env):
        return Client(os.environ[id_env], os.environ.get(secret_env, ""))
    found = _parse_client(keychain_secret(keychain_item)) if keychain_item else Client("")
    if not found.client_id:
        raise FetchError(f"no OAuth client: set ${id_env} (and ${secret_env})"
                         + (f" or keychain item {keychain_item!r}" if keychain_item else ""))
    return found


def pkce_pair(verifier: str | None = None) -> tuple[str, str]:
    """(code_verifier, S256 code_challenge), RFC 7636 § 4.1 and § 4.2."""
    verifier = verifier or secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def consent_url(client_id: str, redirect_uri: str, challenge: str, state: str,
                scopes: Iterable[str] = SCOPES) -> str:
    query = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": " ".join(scopes), "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state, "access_type": "offline", "prompt": "consent",
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(query, quote_via=urllib.parse.quote)}"


def parse_redirect(path: str, state: str) -> str:
    """The authorisation code from the loopback redirect's path, checking ``state``."""
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    if q.get("error"):
        raise FetchError(f"consent refused: {q['error'][0]}")
    if q.get("state", [""])[0] != state:
        raise FetchError("the redirect's state does not match this request; ignored")
    code = q.get("code", [""])[0]
    if not code:
        raise FetchError("the redirect carried no authorisation code")
    return code


def _token_request(form: dict[str, str]) -> dict:
    """POST to the token endpoint with the form, secrets and all, on curl's standard input."""
    status, text = _curl(["-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded",
                          "--data-binary", "@-", TOKEN_URL],
                         urllib.parse.urlencode(form), 60)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FetchError(f"token endpoint returned no JSON (HTTP {status})") from exc
    if status != 200:
        # The error and its description name no secret.
        raise FetchError(f"token endpoint refused (HTTP {status}): {doc.get('error', '')} "
                         f"{doc.get('error_description', '')}".strip())
    return doc


def exchange_code(cl: Client, code: str, verifier: str, redirect_uri: str) -> dict:
    form = {"client_id": cl.client_id, "code": code, "code_verifier": verifier,
            "grant_type": "authorization_code", "redirect_uri": redirect_uri}
    if cl.client_secret:
        form["client_secret"] = cl.client_secret
    return _token_request(form)


def store_secret(item: str, value: str, account: str = "takestock") -> None:
    """Write ``value`` to keychain item ``item``; ``security`` reads it from standard input."""
    if not value or "\n" in value:
        raise FetchError("refusing to store an empty or multi-line secret")
    proc = subprocess.run(["security", "add-generic-password", "-U", "-s", item, "-a", account, "-w"],
                          input=f"{value}\n{value}\n", capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise FetchError(f"could not write keychain item {item!r}: {proc.stderr.strip()[:200]}")


def access_token(client_keychain: str = "", token_keychain: str = "",
                 refresh_env: str = "GOOGLE_OAUTH_REFRESH_TOKEN") -> str:
    """A short-lived access token minted from the stored refresh token."""
    refresh = os.environ.get(refresh_env, "") or (keychain_secret(token_keychain) if token_keychain else "")
    if not refresh:
        raise FetchError(f"no refresh token: run the auth command, or set ${refresh_env}"
                         + (f" or keychain item {token_keychain!r}" if token_keychain else ""))
    cl = client(client_keychain)
    form = {"client_id": cl.client_id, "grant_type": "refresh_token", "refresh_token": refresh}
    if cl.client_secret:
        form["client_secret"] = cl.client_secret
    tok = str(_token_request(form).get("access_token", ""))
    if not tok:
        raise FetchError("token endpoint returned no access token")
    return tok


def authorise(client_keychain: str, token_keychain: str, port: int = 0, wait: int = 300,
              say: Callable[[str], None] = print) -> list[str]:
    """Run the consent flow and store the refresh token. Returns the scopes granted.

    Prints the consent URL and waits for the browser's redirect to a listener
    on ``127.0.0.1``. Never prints a token.
    """
    cl = client(client_keychain)
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)
    got: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            got["path"] = self.path
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"takestock: authorisation received. You can close this tab.\n")

        def log_message(self, format: str, *args: Any) -> None:
            return  # the redirect's path carries the code: keep it out of the log

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 5
    redirect = f"http://127.0.0.1:{server.server_address[1]}"
    say("Open this URL in a browser signed in as an administrator, and approve read-only access:")
    say(consent_url(cl.client_id, redirect, challenge, state))
    deadline = time.monotonic() + wait
    try:
        while "path" not in got and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if "path" not in got:
        raise FetchError(f"no redirect within {wait} seconds")
    doc = exchange_code(cl, parse_redirect(got["path"], state), verifier, redirect)
    refresh = str(doc.get("refresh_token", ""))
    if not refresh:
        raise FetchError("Google returned no refresh token; revoke the app's access and run auth again")
    store_secret(token_keychain, refresh)
    granted = str(doc.get("scope", "")).split()
    missing = [s for s in SCOPES if s not in granted]
    say(f"Refresh token stored in keychain item {token_keychain!r}.")
    if missing:
        say("Not granted (the sources needing these will be refused): " + ", ".join(missing))
    return granted


# ---------------------------------------------------------------- Gmail log events


def _dt(value: datetime | date | str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    v = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(v)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _rfc3339(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _windows(since: datetime, until: datetime, span: timedelta) -> list[tuple[datetime, datetime]]:
    out, start = [], since
    while start < until:
        end = min(until, start + span)
        out.append((start, end))
        start = end
    return out


def _scalar(p: dict) -> list[Any]:
    if "boolValue" in p:
        return [p["boolValue"]]
    if "intValue" in p:
        return [int(p["intValue"])]
    if "value" in p:
        return [p["value"]]
    for key, cast in (("multiValue", str), ("multiIntValue", int), ("multiBoolValue", bool)):
        if key in p:
            return [cast(v) for v in p[key]]
    return []


def _flatten(params: Iterable[dict], prefix: str = "", out: dict[str, list[Any]] | None = None
             ) -> dict[str, list[Any]]:
    """Every leaf of an event's parameters by dotted name, repeated values gathered in order."""
    out = {} if out is None else out
    for p in params or []:
        name = f"{prefix}.{p.get('name', '')}" if prefix else str(p.get("name", ""))
        if isinstance(p.get("messageValue"), dict):
            _flatten(p["messageValue"].get("parameter") or [], name, out)
        for m in p.get("multiMessageValue") or []:
            _flatten(m.get("parameter") or [], name, out)
        vals = _scalar(p)
        if vals:
            out.setdefault(name, []).extend(vals)
    return out


def _field(flat: dict[str, list[Any]], name: str) -> list[Any]:
    """Values of the field whose dotted name is ``name`` or ends with ``.name``."""
    vals: list[Any] = []
    for key, v in flat.items():
        if key == name or key.endswith("." + name):
            vals += v
    return vals


def _first(flat: dict[str, list[Any]], name: str) -> Any:
    vals = _field(flat, name)
    return vals[0] if vals else None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _domain(address: Any) -> str:
    """The domain of an address; the local part is never kept."""
    a = str(address or "").strip().strip("<>").rstrip(".")
    return a.rpartition("@")[2].lower() if "@" in a else ""


def _flattened_destination_domains(value: str) -> list[str]:
    """Domains from ``service:selector:address, ...`` (``flattened_destinations``)."""
    return [d for d in (_domain(part.rpartition(":")[2]) for part in value.split(",")) if d]


# mail_event_type values that are things a person did after delivery, not mail flow.
POST_DELIVERY = {3, 4, *range(6, 30), 31, 32, 33}
SMTP_IN = {1, 48}         # action_type: received by inbound SMTP (48: for relay)
SMTP_OUT = {10, 49}       # action_type: sent by outbound SMTP (49: through relay)
_OUTCOMES = (  # worst first
    ("bounced", lambda a, e, ok: 18 in a or 30 in e),
    ("dropped", lambda a, e, ok: 19 in a),
    ("rejected", lambda a, e, ok: 34 in e or False in ok),
    ("quarantined", lambda a, e, ok: 5 in e),
    ("deferred", lambda a, e, ok: 14 in a and not (a & SMTP_OUT or 3 in a)),
    ("sent", lambda a, e, ok: bool(a & SMTP_OUT)),
    ("delivered", lambda a, e, ok: 3 in a),
    ("accepted", lambda a, e, ok: bool(a & {1, 2, 48, 68})),
)
_TLS_RANK = {"none": 0, "TLS 1.0": 1, "TLS 1.1": 2, TLS_UNSTATED: 3, "TLS 1.2": 4, "TLS 1.3": 5}


def _tls_label(state: Any, version: Any) -> str:
    if state is None and not version:
        return ""
    if _int(state) == 0:
        return "none"
    v = str(version or "").strip().upper().replace("TLSV", "").replace("TLS", "").strip()
    return f"TLS {v}" if v else TLS_UNSTATED


def _auth(values: list[Any]) -> str:
    """pass or fail from a boolean field; ``dmarc_pass`` is also documented as a string."""
    seen = [v for v in values if isinstance(v, bool) or str(v).lower() in ("true", "false")]
    if not seen:
        return ""
    return "pass" if any(v is True or str(v).lower() == "true" for v in seen) else "fail"


@dataclass
class _Message:
    times: list[str]
    events: list[dict[str, list[Any]]]


def _direction(sets: set[int], internal: list[Any]) -> str:
    if 10 in sets:
        return "internal"
    if 1 in sets and 2 not in sets:
        return "inbound"
    if 2 in sets and 1 not in sets:
        return "outbound"
    if True in internal:
        return "internal"
    if 11 in sets and 9 in sets and 8 not in sets:
        return "inbound"
    if 11 in sets and 8 in sets and 9 not in sets:
        return "outbound"
    return "unknown"


def _row(msg: _Message) -> dict:
    allf: dict[str, list[Any]] = {}
    for ev in msg.events:
        for k, v in ev.items():
            allf.setdefault(k, []).extend(v)
    sets = {s for s in (_int(v) for v in _field(allf, "message_set.type")) if s is not None}
    direction = _direction(sets, _field(allf, "connection_info.is_internal"))

    # TLS of the leg facing outside, the weakest recorded.
    legs = SMTP_IN if direction == "inbound" else SMTP_OUT if direction == "outbound" else SMTP_IN | SMTP_OUT
    recorded = [(_int(_first(ev, "message_info.action_type")),
                 _tls_label(_first(ev, "smtp_tls_state"), _first(ev, "smtp_tls_version")))
                for ev in msg.events]
    labels = [lab for act, lab in recorded if lab and act in legs]
    if not labels:          # no stage named its leg: take what any stage recorded
        labels = [lab for _, lab in recorded if lab]
    tls = min(labels, key=lambda x: _TLS_RANK.get(x, 3)) if labels else ""
    if not tls and (22 in sets or 21 in sets):
        tls = TLS_UNSTATED

    sender = next((d for d in (_domain(a) for a in _field(allf, "source.from_header_address")
                               + _field(allf, "source.address")) if d), "")
    rcpts = {d for d in (_domain(a) for a in _field(allf, "destination.address")) if d}
    for flat in _field(allf, "flattened_destinations"):
        rcpts.update(_flattened_destination_domains(str(flat)))

    if direction == "inbound":
        remote_ip = next((str(v) for v in _field(allf, "smtp_in_connect_ip") if v), "")
    else:
        remote_ip = next((str(v) for v in _field(allf, "smtp_out_connect_ip") if v), "")
    remote_host = "" if direction == "inbound" else next(
        (str(v) for v in _field(allf, "smtp_out_remote_host") if v), "")

    actions = {a for a in (_int(v) for v in _field(allf, "message_info.action_type")) if a is not None}
    kinds = {e for e in (_int(v) for v in _field(allf, "mail_event_type")) if e is not None}
    ok = set(_field(allf, "event_info.success"))
    delivery = next((name for name, test in _OUTCOMES if test(actions, kinds, ok)), "")

    connector = ", ".join(n for n, hit in (("inbound gateway", 57 in sets),
                                           ("SMTP relay", 29 in sets or bool(actions & {48, 49})))
                          if hit)
    sizes = [s for s in (_int(v) for v in _field(allf, "payload_size")) if s is not None]
    return {
        "time": min(msg.times) if msg.times else "",
        "direction": direction,
        "sender_domain": sender,
        "recipient_domains": sorted(rcpts),
        "size": max(sizes) if sizes else None,
        "tls": tls,
        "spf": _auth(_field(allf, "spf_pass")),
        "dkim": _auth(_field(allf, "dkim_pass")),
        "dmarc": _auth(_field(allf, "dmarc_pass")),
        "remote_host": remote_host,
        "remote_ip": remote_ip,
        "connector": connector,
        "delivery": delivery,
        "source": SOURCE,
    }


def _event_time(activity: dict, flat: dict[str, list[Any]]) -> str:
    t = str((activity.get("id") or {}).get("time", ""))
    if t:
        return t
    usec = _int(_first(flat, "event_info.timestamp_usec"))
    return _rfc3339(datetime.fromtimestamp(usec / 1e6, UTC)) if usec else ""


def normalise(activities: Iterable[dict]) -> tuple[list[dict], int]:
    """Rows, one per message, from Reports API activities; and how many post-delivery events were skipped."""
    messages: dict[str, _Message] = {}
    skipped = 0
    for n, act in enumerate(activities):
        for i, ev in enumerate(act.get("events") or []):
            flat = _flatten(ev.get("parameters") or [])
            _flatten(ev.get("sensitiveParameters") or [], "", flat)
            if _int(_first(flat, "mail_event_type")) in POST_DELIVERY:
                skipped += 1
                continue
            # The Message-ID groups a message's stages and is then dropped.
            key = str(_first(flat, "rfc2822_message_id") or f"\0{n}.{i}")
            msg = messages.setdefault(key, _Message([], []))
            msg.events.append(flat)
            t = _event_time(act, flat)
            if t:
                msg.times.append(t)
    rows = [_row(m) for m in messages.values()]
    rows.sort(key=lambda r: r["time"])
    return rows, skipped


def _list_activities(bearer: str, start: datetime, end: datetime) -> list[dict]:
    items: list[dict] = []
    token = ""
    while True:
        q = {"eventName": "delivery", "startTime": _rfc3339(start), "endTime": _rfc3339(end),
             "maxResults": "1000"}
        if token:
            q["pageToken"] = token
        doc = _call("GET", f"{REPORTS}/activity/users/all/applications/gmail?{urllib.parse.urlencode(q)}",
                    bearer)
        items += doc.get("items") or []
        token = str(doc.get("nextPageToken", ""))
        if not token:
            return items


def gmail_log(token: str, since: datetime | date | str, until: datetime | date | str
              ) -> tuple[list[dict], list[str]]:
    """(rows, notes) for mail Gmail logged between ``since`` and ``until``.

    A refusal ends the fetch and is said in the notes, with what was fetched
    before it kept: an edition without audit-log eligible licences, or an
    administrator without the Reports privilege, is refused, which is not the
    same as an organisation that sent no mail.
    """
    start, end = _dt(since), _dt(until)
    activities: list[dict] = []
    notes: list[str] = []
    for a, b in _windows(start, end, GMAIL_WINDOW):
        try:
            activities += _list_activities(token, a, b)
        except Refused as exc:
            notes.append(f"Gmail log events refused for {_rfc3339(a)} to {_rfc3339(b)} ({exc}). "
                         "They need an edition with audit-log eligible licences and an administrator "
                         "with the Reports privilege; this is a refusal, not an absence of mail.")
            break
        except FetchError as exc:
            notes.append(f"Gmail log events failed for {_rfc3339(a)} to {_rfc3339(b)}: {exc}")
            break
    rows, skipped = normalise(activities)
    notes.append(f"{sum(len(x.get('events') or []) for x in activities)} delivery events read, "
                 f"{skipped} post-delivery events skipped, {len(rows)} messages")
    return rows, notes


# ---------------------------------------------------------------- Gmail usage

CUSTOMER_PARAMETERS = (
    "num_emails_exchanged", "num_emails_received", "num_emails_sent",
    "num_inbound_delivered_emails", "num_inbound_encrypted_emails", "num_inbound_unencrypted_emails",
    "num_inbound_non_spam_emails", "num_inbound_spam_emails", "num_inbound_rejected_emails",
    "num_inbound_rerouted_emails", "num_outbound_delivered_emails", "num_outbound_encrypted_emails",
    "num_outbound_unencrypted_emails", "num_outbound_rejected_emails", "num_outbound_rerouted_emails",
    "num_email_accounts", "num_1day_active_users", "num_1day_imap_users", "num_1day_pop_users",
    "num_1day_webmail_users",
)
USER_PARAMETERS = ("is_gmail_enabled", "num_emails_sent", "num_emails_received", "num_spam_emails_received")


def _days(since: datetime | date | str, until: datetime | date | str) -> list[str]:
    a, b = _dt(since).date(), _dt(until).date()
    return [(a + timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]


def _values(report: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for p in report.get("parameters") or []:
        name = str(p.get("name", "")).removeprefix("gmail:")
        if "intValue" in p:
            out[name] = int(p["intValue"])
        elif "boolValue" in p:
            out[name] = bool(p["boolValue"])
    return out


def _warnings(doc: dict) -> list[str]:
    return [str(w.get("message", w.get("code", ""))) for w in doc.get("warnings") or []]


def usage(token: str, since: datetime | date | str, until: datetime | date | str) -> dict:
    """Daily Gmail totals for the customer, and per-user figures reduced to counts.

    Dates are the Reports API's, Pacific time. No user's address or ID is kept.
    """
    out: dict[str, Any] = {"source": "google-reports-usage", "customer": {}, "users": {}, "notes": []}
    params = ",".join(f"gmail:{p}" for p in CUSTOMER_PARAMETERS)
    uparams = ",".join(f"gmail:{p}" for p in USER_PARAMETERS)
    for day in _days(since, until):
        try:
            doc = _call("GET", f"{REPORTS}/usage/dates/{day}?parameters={params}", token)
            out["notes"] += [f"{day} customer: {w}" for w in _warnings(doc)]
            reports = doc.get("usageReports") or []
            if reports:
                out["customer"][day] = _values(reports[0])
            totals = {"users": 0, "gmail_enabled": 0, "senders": 0, "receivers": 0,
                      "sent": 0, "received": 0, "spam_received": 0}
            page = ""
            while True:
                q = f"parameters={uparams}&maxResults=1000" + (f"&pageToken={quote(page)}"
                                                                 if page else "")
                udoc = _call("GET", f"{REPORTS}/usage/users/all/dates/{day}?{q}", token)
                out["notes"] += [f"{day} users: {w}" for w in _warnings(udoc)]
                for rep in udoc.get("usageReports") or []:
                    v = _values(rep)          # the entity (address, profile ID) is not read
                    totals["users"] += 1
                    totals["gmail_enabled"] += bool(v.get("is_gmail_enabled"))
                    totals["senders"] += int(v.get("num_emails_sent", 0)) > 0
                    totals["receivers"] += int(v.get("num_emails_received", 0)) > 0
                    totals["sent"] += int(v.get("num_emails_sent", 0))
                    totals["received"] += int(v.get("num_emails_received", 0))
                    totals["spam_received"] += int(v.get("num_spam_emails_received", 0))
                page = str(udoc.get("nextPageToken", ""))
                if not page:
                    break
            if totals["users"]:
                out["users"][day] = totals
        except Refused as exc:
            out["notes"].append(f"Gmail usage refused on {day} ({exc}); usage reports need an "
                                "administrator with the Reports privilege. Stopped.")
            break
        except FetchError as exc:
            out["notes"].append(f"Gmail usage failed on {day}: {exc}. Stopped.")
            break
    return out


# ---------------------------------------------------------------- Postmaster Tools

METRICS = (  # (name in the output, v2 standard metric, filter)
    ("spam_rate", "SPAM_RATE", ""),
    ("spf_success_rate", "AUTH_SUCCESS_RATE", 'auth_type = "spf"'),
    ("dkim_success_rate", "AUTH_SUCCESS_RATE", 'auth_type = "dkim"'),
    ("dmarc_success_rate", "AUTH_SUCCESS_RATE", 'auth_type = "dmarc"'),
    ("tls_inbound_rate", "TLS_ENCRYPTION_RATE", 'traffic_direction = "inbound"'),
    ("tls_outbound_rate", "TLS_ENCRYPTION_RATE", 'traffic_direction = "outbound"'),
    ("tls_inbound_count", "TLS_ENCRYPTION_MESSAGE_COUNT", 'traffic_direction = "inbound"'),
    ("tls_outbound_count", "TLS_ENCRYPTION_MESSAGE_COUNT", 'traffic_direction = "outbound"'),
    ("delivery_error_rate", "DELIVERY_ERROR_RATE", ""),
    ("delivery_reject_rate", "DELIVERY_ERROR_RATE", 'error_type = "reject"'),
    ("delivery_temp_fail_rate", "DELIVERY_ERROR_RATE", 'error_type = "temp_fail"'),
    ("delivery_error_count", "DELIVERY_ERROR_COUNT", ""),
)


def _date(d: date) -> dict[str, int]:
    return {"year": d.year, "month": d.month, "day": d.day}


def _stat(value: dict) -> Any:
    for key in ("doubleValue", "floatValue", "stringValue"):
        if key in value:
            return value[key]
    if "intValue" in value:
        return int(value["intValue"])
    if "stringList" in value:
        return list((value["stringList"] or {}).get("values") or [])
    return None


def _domain_stats(token: str, domain: str, start: date, end: date) -> dict[str, dict[str, Any]]:
    days: dict[str, dict[str, Any]] = {}
    page = ""
    while True:
        body: dict[str, Any] = {
            "metricDefinitions": [
                {"name": n, "baseMetric": {"standardMetric": m}, **({"filter": f} if f else {})}
                for n, m, f in METRICS],
            "timeQuery": {"dateRanges": {"dateRanges": [{"start": _date(start), "end": _date(end)}]}},
            "aggregationGranularity": "DAILY",
            "pageSize": 200,
        }
        if page:
            body["pageToken"] = page
        doc = _call("POST", f"{POSTMASTER}/domains/{quote(domain)}/domainStats:query", token, body)
        for st in doc.get("domainStats") or []:
            d = st.get("date") or {}
            key = f"{d.get('year', 0):04d}-{d.get('month', 0):02d}-{d.get('day', 0):02d}" if d else "overall"
            days.setdefault(key, {})[str(st.get("metric", ""))] = _stat(st.get("value") or {})
        page = str(doc.get("nextPageToken", ""))
        if not page:
            return dict(sorted(days.items()))


def _compliance(doc: dict) -> dict[str, Any]:
    data = doc.get("complianceData") or {}
    out: dict[str, Any] = {r.get("requirement", ""): (r.get("status") or {}).get("status", "")
                           for r in data.get("rowData") or []}
    for key in ("oneClickUnsubscribeVerdict", "honorUnsubscribeVerdict", "deliverabilityStatusVerdict"):
        v = data.get(key)
        if v:
            st = v.get("status") or v.get("state") or {}
            out[key] = {"status": st.get("status", ""), "reason": v.get("reason", "")}
    return out


def postmaster(token: str, domains: Iterable[str], since: datetime | date | str,
               until: datetime | date | str) -> dict:
    """Per domain: daily statistics and compliance status, or why Google refused them."""
    start, end = _dt(since).date(), _dt(until).date()
    out: dict[str, Any] = {"source": "google-postmaster-v2", "domains": {}, "notes": [
        "Postmaster Tools v2 offers no domain or IP reputation; statistics appear only on days "
        "with enough mail to Gmail users."]}
    for domain in domains:
        entry: dict[str, Any] = {}
        try:
            entry["days"] = _domain_stats(token, domain, start, end)
        except Refused as exc:
            entry["error"] = (f"{exc}. Only domains verified in Postmaster Tools by the granting "
                              "account return data.")
        except FetchError as exc:
            entry["error"] = str(exc)
        if "error" not in entry:
            try:
                entry["compliance"] = _compliance(
                    _call("GET", f"{POSTMASTER}/domains/{quote(domain)}/complianceStatus", token))
            except FetchError as exc:
                entry["compliance_error"] = str(exc)
        out["domains"][domain] = entry
    return out


# ---------------------------------------------------------------- command line


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m takestock.mailpath.google_workspace",
                                 description="Read-only Google Workspace mail data for takestock mailpath.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("auth", help="grant read-only access and store the refresh token in the keychain")
    a.add_argument("--client-keychain", default="", help="keychain item holding the OAuth client")
    a.add_argument("--token-keychain", required=True, help="keychain item to store the refresh token in")
    a.add_argument("--port", type=int, default=0, help="loopback port (default: any free port)")
    p = sub.add_parser("pull", help="fetch Gmail log events, usage and Postmaster statistics")
    p.add_argument("--client-keychain", default="")
    p.add_argument("--token-keychain", default="")
    p.add_argument("--since", required=True, help="ISO date or time (UTC when no zone is given)")
    p.add_argument("--until", default="", help="ISO date or time (default: now)")
    p.add_argument("--domain", action="append", default=[], help="a domain for Postmaster Tools; repeat")
    p.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "auth":
            authorise(args.client_keychain, args.token_keychain, port=args.port)
            return 0
        tok = access_token(args.client_keychain, args.token_keychain)
        until = args.until or _rfc3339(datetime.now(UTC))
        args.out.mkdir(parents=True, exist_ok=True)
        rows, notes = gmail_log(tok, args.since, until)
        (args.out / "gmail-log.json").write_text(json.dumps({"rows": rows, "notes": notes}, indent=1))
        (args.out / "usage.json").write_text(json.dumps(usage(tok, args.since, until), indent=1))
        (args.out / "postmaster.json").write_text(
            json.dumps(postmaster(tok, args.domain, args.since, until), indent=1))
        for n in notes:
            print(n)
        print(f"wrote gmail-log.json, usage.json and postmaster.json to {args.out}")
        return 0
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
