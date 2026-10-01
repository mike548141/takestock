"""Small helpers shared by the collectors.

Everything here wraps an external program (``dig``, ``curl``, the macOS
``security`` keychain tool) or does a little parsing. Failures are reported in
band rather than raised, so one unreachable host never stops a whole run: a
command that cannot run returns text starting with ``__ERROR__``.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from . import __version__

#: Prefix on the text :func:`run` returns when the command could not run at all.
ERROR_PREFIX = "__ERROR__"


def run(cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
    """Run ``cmd`` and return its stdout and stderr joined.

    Never raises: a missing program, a timeout or any other failure comes back
    as ``"__ERROR__ <reason>"`` so callers can record it as a coverage gap.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=stdin_text)
        return p.stdout + p.stderr
    except Exception as e:  # noqa: BLE001 - any failure is reported in band
        return f"{ERROR_PREFIX} {e}"


def is_ipv6_literal(host: str) -> bool:
    """True when ``host`` is an IPv6 address, bracketed or not."""
    return ":" in host.strip().strip("[]")


def scan_address(host: str) -> str:
    """Strip the brackets from ``[2001:db8::1]`` so a scanner accepts it."""
    h = host.strip()
    return h[1:-1] if h.startswith("[") and h.endswith("]") else h


def dig(name: str, rtype: str = "A", short: bool = True) -> list[str]:
    """Resolve ``name`` with ``dig`` and return the non-empty answer lines."""
    args = ["dig", "+short", rtype, name] if short else ["dig", rtype, name]
    out = run(args, timeout=20)
    if out.startswith(ERROR_PREFIX):
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def keychain_secret(item: str) -> str:
    """Read a generic password from the macOS keychain, or "" when absent."""
    out = run(["security", "find-generic-password", "-s", item, "-w"], timeout=10)
    if out.startswith(ERROR_PREFIX) or "could not be found" in out:
        return ""
    return out.strip()


# Response headers worth keeping: the ones a rate-limited API uses to say when
# to come back.
_KEPT_HEADERS = (
    "retry-after",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
)


def _parse_head(head: str) -> dict:
    lines = head.replace("\r\n", "\n").split("\n")
    meta: dict = {}
    parts = lines[0].split()
    if len(parts) >= 2 and parts[1].isdigit():
        meta["status"] = int(parts[1])
    kept = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep and k.strip().lower() in _KEPT_HEADERS:
            kept[k.strip().lower()] = v.strip()
    if kept:
        meta["headers"] = kept
    return meta


def _split_response(raw: str) -> tuple[str, dict]:
    """Split ``curl -D -`` output into (body, metadata of the last response).

    A redirect or a ``100 Continue`` produces several header blocks before the
    body; only the final one describes the body.
    """
    meta: dict = {}
    text = raw
    while text.startswith("HTTP/"):
        crlf, lf = text.find("\r\n\r\n"), text.find("\n\n")
        if crlf >= 0 and (lf < 0 or crlf <= lf):
            head, text = text[:crlf], text[crlf + 4:]
        elif lf >= 0:
            head, text = text[:lf], text[lf + 2:]
        else:
            break
        meta = _parse_head(head)
    return text, meta


HTTP_CONNECT_TIMEOUT = 10
HTTP_TIMEOUT = 25
USER_AGENT = f"takestock/{__version__}"


def http_get_full(url: str, timeout: int = HTTP_TIMEOUT, bearer: str = "",
                  connect_timeout: int = HTTP_CONNECT_TIMEOUT) -> tuple[str, dict]:
    """GET ``url`` with ``curl`` and return (body, metadata).

    The metadata carries the HTTP status and any rate-limit headers. A bearer
    token is passed on stdin, never on the command line, so it does not appear
    in the process list.
    """
    cmd = ["curl", "-sS", "-D", "-", "--connect-timeout", str(connect_timeout),
           "-m", str(timeout), "-A", USER_AGENT]
    if bearer:
        cmd += ["-H", "@-"]
    cmd.append(url)
    if bearer:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5,
                               input=f"Authorization: Bearer {bearer}")
            return _split_response(p.stdout + p.stderr)
        except Exception as e:  # noqa: BLE001 - reported in band like run()
            return f"{ERROR_PREFIX} {e}", {}
    return _split_response(run(cmd, timeout=timeout + 5))


def http_get(url: str, timeout: int = HTTP_TIMEOUT, bearer: str = "") -> str:
    """GET ``url`` and return the body only."""
    return http_get_full(url, timeout, bearer)[0]


def http_json(url: str, timeout: int = HTTP_TIMEOUT, bearer: str = "", meta: dict | None = None):
    """GET ``url`` and parse the body as JSON; None on any failure.

    Pass a dict as ``meta`` to receive the status and rate-limit headers.
    """
    body, info = http_get_full(url, timeout, bearer)
    if meta is not None:
        meta.update(info)
    if body.startswith(ERROR_PREFIX):
        return None
    try:
        return json.loads(body)
    except Exception:  # noqa: BLE001 - a non-JSON body is simply "no answer"
        return None


def rsa_key_bits_from_dkim(txt: str) -> int | None:
    """Estimate the RSA modulus size of a DKIM record's ``p=`` public key.

    The estimate reads the length of the DER-encoded key and rounds to the
    usual sizes (1024, 2048, 3072, 4096). Returns None when there is no key.
    """
    m = re.search(r"p=([A-Za-z0-9+/=]+)", txt.replace(" ", ""))
    if not m:
        return None
    try:
        der = base64.b64decode(m.group(1) + "==")
    except Exception:  # noqa: BLE001 - malformed base64 means no readable key
        return None
    n = len(der)
    if n < 200:
        return 1024
    if n < 350:
        return 2048
    if n < 500:
        return 3072
    return 4096


def parse_cert_time(s: str) -> datetime | None:
    """Parse an ISO 8601 certificate timestamp; a missing zone means UTC."""
    if not s:
        return None
    s = s.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def days_remaining(expiry: datetime, ref: datetime | None = None) -> int:
    """Whole days from ``ref`` (default now) until ``expiry``; negative once past."""
    ref = ref or datetime.now(UTC)
    return (expiry - ref).days


def now_date(ref: datetime | None = None) -> str:
    """Today's date (UTC) as ``YYYY-MM-DD``."""
    return (ref or datetime.now(UTC)).date().isoformat()


def file_mtime_date(path: Path) -> str | None:
    """A file's modification date (UTC) as ``YYYY-MM-DD``, or None if unreadable.

    Collectors record this beside an exported file so a reader knows how old
    the evidence is.
    """
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(mtime, tz=UTC).date().isoformat()


def cert_signature_token(key_type: str, bits: int | None = None, curve: str | None = None) -> str | None:
    """Map a certificate's key type and size to a ``signatures`` baseline token.

    ``("rsa", 2048)`` gives ``rsa_2048``; an EC key on P-384 gives
    ``ecdsa_p384``. Returns None for a key the baseline has no row shape for.
    """
    t = (key_type or "").strip().lower()
    if t == "rsa" and bits:
        return f"rsa_{bits}"
    if t in ("ecdsa", "ec", "id-ecpublickey"):
        src = curve or (str(bits) if bits else "")
        m = re.search(r"(256|384|521)", src)
        if m:
            return f"ecdsa_p{m.group(1)}"
    if t == "ed25519":
        return "ed25519"
    if t == "ed448":
        return "ed448"
    return None
