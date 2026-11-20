"""Read one message's headers into the route it took.

**Input.** A header block: an RFC 5322 message or ``.eml`` (only the header
block is read; reading stops at the first blank line, so a body is never
parsed), or a file of headers one per line with optional ``#`` comment lines
before them, carrying ``# sizeEstimate N``, ``# internalDate ISO`` and
``# labels A,B``, as a mailbox export that fetched headers only would write.

**What a Received header proves.** Each mail server that accepts a message
adds a ``Received`` line on top. It is written by the *receiving* server and
records the host that connected, the protocol, and (when the server records
it) the TLS version and cipher the *sending* host negotiated. So a message
delivered to a mailbox carries a record of every hop's transport, including
the hops its sender's own systems made, and reading them needs nothing sent.

**What it cannot prove.** A hop's TLS clause is the suite that hop chose, never
the floor the servers would have accepted. A server that writes no TLS clause
proves nothing either way. RFC 3848 says ``with ESMTP`` (rather than
``ESMTPS``) means no TLS was used, but servers write it regardless, so such a
hop is recorded as *not recorded* and flagged ``plain_keyword``: the claim is
the header's, and only the sending system's own log settles it. Hops inside one platform (its
own internal relays) are named, but their transport is the platform's and is
not graded. Headers above the first hop the receiving organisation trusts can
be forged by a sender, so a route is evidence of the path, not proof of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from .systems import INTERNAL, Catalogue

# --- reading the block -------------------------------------------------------


def read_block(text: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """(metadata from ``#`` lines, [(header name, unfolded value)] in file order)."""
    meta: dict[str, str] = {}
    headers: list[tuple[str, str]] = []
    started = False
    for raw in text.replace("\r\n", "\n").split("\n"):
        if not started and raw.startswith("#"):
            key, _, value = raw[1:].strip().partition(" ")
            if key in ("sizeEstimate", "internalDate", "labels"):
                meta[key] = value.strip()
            continue
        if not raw.strip():
            if started:
                break          # end of the header block: never read a body
            continue
        if raw[0] in " \t" and headers:
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {raw.strip()}")
            continue
        name, sep, value = raw.partition(":")
        if not sep or not re.fullmatch(r"[!-9;-~]+", name):
            continue
        started = True
        headers.append((name.strip(), value.strip()))
    return meta, headers


# --- one hop ------------------------------------------------------------------

TLS_NOT_RECORDED = "not recorded"
TLS_NONE = "none"
TLS_UNSTATED = "TLS (version not recorded)"
HTTPS_SUBMISSION = "web or API submission"

_FROM = re.compile(r"^\s*from\s+(\S+)(?:\s+\(([^()]*(?:\([^()]*\)[^()]*)*)\))?", re.I)
_BY = re.compile(r"\bby\s+(\S+)", re.I)
_WITH = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.I)
_FOR = re.compile(r"\bfor\s+<?([^\s<>;]+@[^\s<>;]+)>?", re.I)
_IP = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
_BARE_IP = re.compile(r"^\(?([0-9a-fA-F:.]+)\)?$")
_TLS_VERSION = re.compile(
    r"(?:version=|using\s+|\b)(TLS\s?v?1[._]?[0-3]|TLS1_[0-3]|TLSv1(?:\.[0-3])?|SSLv3)\b", re.I)
_CIPHER = re.compile(r"cipher[=\s]+([A-Z0-9_-]{6,})", re.I)
_TLS_PROTOCOLS = {"esmtps", "esmtpsa", "smtps", "lmtps", "utf8smtps", "utf8smtpsa"}
_PLAIN_PROTOCOLS = {"smtp", "esmtp", "esmtpa", "lmtp", "utf8smtp", "utf8smtpa"}
_WEB_PROTOCOLS = {"http", "https", "httprest", "mapi", "httpsrest"}


def _norm_tls(raw: str) -> str:
    v = re.sub(r"[^0-9.]", "", raw.replace("_", ".").replace("v", ""))
    v = v.lstrip(".")
    if raw.upper().startswith("SSL"):
        return "SSLv3"
    if len(v) == 2 and v.isdigit():          # "TLS13", written with no separator
        v = f"{v[0]}.{v[1]}"
    if v in ("1", "1.0"):
        return "TLS 1.0"
    return f"TLS {v}" if v else TLS_UNSTATED


@dataclass
class Hop:
    """One Received header: who handed the message to whom, and how."""

    from_name: str = ""
    from_rdns: str = ""
    from_ip: str = ""
    by_name: str = ""
    protocol: str = ""
    tls: str = TLS_NOT_RECORDED
    cipher: str = ""
    authenticated: bool = False
    plain_keyword: bool = False
    recipient: str = ""
    when: str = ""
    from_system: str = ""
    by_system: str = ""
    raw: str = ""

    @property
    def crosses(self) -> bool:
        """True when the hop moves the message between two different systems."""
        return bool(self.from_system) and self.from_system != self.by_system


def parse_received(value: str) -> Hop:
    h = Hop(raw=value)
    head, _, when = value.rpartition(";")
    if not head:
        head, when = value, ""
    h.when = when.strip()
    m = _FROM.search(head)
    if m:
        h.from_name = m.group(1).strip("[]")
        inner = m.group(2) or ""
        ip = _IP.search(inner) or _IP.search(m.group(1))
        if ip:
            h.from_ip = ip.group(1)
        else:
            bare = _BARE_IP.match(inner.split()[0]) if inner.split() else None
            if bare and (":" in bare.group(1) or bare.group(1).count(".") == 3):
                h.from_ip = bare.group(1)
        names = [w.rstrip(".") for w in re.split(r"[\s()\[\]]+", inner)
                 if "." in w and not _BARE_IP.match(w) and "=" not in w]
        h.from_rdns = names[0] if names else ""
        if "helo=" in inner.lower():
            helo = re.search(r"helo=([^\s)\]]+)", inner, re.I)
            if helo and _BARE_IP.match(h.from_name):
                h.from_name = helo.group(1)
    b = _BY.search(head)
    if b:
        h.by_name = b.group(1).rstrip(".;")
    w = _WITH.search(head)
    proto = w.group(1) if w else ""
    if re.search(r"with\s+Microsoft SMTP Server", head, re.I):
        proto = "ESMTP"
    h.protocol = proto
    low = proto.lower()
    h.authenticated = ((low.endswith("a") and low.startswith(("esmtp", "utf8smtp")))
                       or "authenticated" in head.lower())
    version = _TLS_VERSION.search(head)
    if version:
        h.tls = _norm_tls(version.group(1))
    elif (low in _TLS_PROTOCOLS or "Google Transport Security" in head
          or re.search(r"\(TLS\)|\btls\s", head, re.I)):
        h.tls = TLS_UNSTATED
    elif low in _WEB_PROTOCOLS:
        h.tls = HTTPS_SUBMISSION
    elif low in _PLAIN_PROTOCOLS:
        h.plain_keyword = True
    c = _CIPHER.search(head)
    h.cipher = c.group(1) if c else ""
    f = _FOR.search(head)
    h.recipient = f.group(1).lower() if f else ""
    return h


# --- authentication results ---------------------------------------------------

_METHOD = re.compile(r"\b(spf|dkim|dmarc|arc|dara|bimi)\s*=\s*([a-z]+)", re.I)


@dataclass
class Auth:
    """The final receiver's verdicts, and every DKIM signature on the message."""

    authserv: str = ""
    spf: str = ""
    dkim: list[str] = field(default_factory=list)
    dkim_domains: list[str] = field(default_factory=list)
    dmarc: str = ""
    dmarc_policy: str = ""
    arc: str = ""
    mailfrom_domain: str = ""


def parse_auth(value: str) -> Auth:
    a = Auth()
    a.authserv = value.split(";", 1)[0].strip().split()[0] if value.strip() else ""
    for part in value.split(";")[1:]:
        m = _METHOD.search(part)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if method == "spf" and not a.spf:
            a.spf = result
            mf = re.search(r"smtp\.mailfrom=\S*?@?([A-Za-z0-9.-]+\.[A-Za-z]{2,})", part)
            a.mailfrom_domain = mf.group(1).lower() if mf else ""
        elif method == "dkim":
            a.dkim.append(result)
            d = re.search(r"header\.(?:i=@?|d=)([A-Za-z0-9.-]*\.[A-Za-z]{2,})", part)
            a.dkim_domains.append(d.group(1).lower() if d else "")
        elif method == "dmarc" and not a.dmarc:
            a.dmarc = result
            p = re.search(r"\bp=([A-Za-z]+)", part)
            a.dmarc_policy = p.group(1).lower() if p else ""
        elif method == "arc" and not a.arc:
            a.arc = result
    return a


@dataclass
class Signature:
    domain: str
    selector: str
    algorithm: str


def parse_dkim_signature(value: str) -> Signature:
    tags = dict((k.strip().lower(), v.strip()) for k, _, v in
                (t.partition("=") for t in value.replace(" ", "").split(";")) if k)
    return Signature(tags.get("d", "").lower(), tags.get("s", ""), tags.get("a", ""))


# --- content protection and generators ----------------------------------------

def mailer_name(value: str) -> str:
    """The product in a mailer string, without its parenthesised detail.

    Bulk senders put a per-message token or a URL in brackets
    (``Example Mailer (dGVzdA==; +https://...)``), which would make every
    message its own sender.
    """
    name = re.sub(r"\([^()]*\)?", " ", value)
    name = " ".join(w for w in name.split() if not re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", w))
    return (name or value).strip()[:60]


def content_protection(content_type: str) -> str:
    """What the outermost Content-Type says about the content's own protection."""
    ct = content_type.lower()
    if "pgp-encrypted" in ct or "multipart/encrypted" in ct:
        return "OpenPGP encrypted"
    if "pkcs7-mime" in ct and ("enveloped" in ct or "authenveloped" in ct):
        return "S/MIME encrypted"
    if "pkcs7-mime" in ct:
        return "S/MIME (opaque)"
    if "pkcs7-signature" in ct:
        return "S/MIME signed"
    if "pgp-signature" in ct:
        return "OpenPGP signed"
    if "rpmsg" in ct:
        return "Microsoft rights-managed"
    return "none visible"


def marking(value: str) -> str:
    """The security classification in an X-Protective-Marking header."""
    m = re.search(r"\bSEC=([A-Z -]+?)(?:,|$)", value, re.I)
    if m:
        return m.group(1).strip().upper()
    # Some senders write the classification as a bare element: "VER=..., NS=..., NAME".
    bare = [p.strip() for p in value.split(",") if p.strip() and "=" not in p]
    return bare[-1].upper() if bare else value.strip()[:40]


def label_names(value: str) -> list[str]:
    """Sensitivity label names from an msip_labels header."""
    return sorted(set(re.findall(r"_Name=([^;]+)", value)))


# --- the message ----------------------------------------------------------------


@dataclass
class Message:
    """Everything a route needs from one message, and nothing else."""

    source: str = ""
    size: int | None = None
    date: str = ""
    labels: list[str] = field(default_factory=list)
    from_domain: str = ""
    original_from_domain: str = ""   # before a list or group rewrote From (ARC i=1)
    envelope_domain: str = ""
    recipient_domain: str = ""
    message_id_domain: str = ""
    hops: list[Hop] = field(default_factory=list)       # origin first
    results: Auth = field(default_factory=Auth)  # secretscan:allow:assigned-secret: dataclass default
    signatures: list[Signature] = field(default_factory=list)
    generators: list[str] = field(default_factory=list)
    submission: str = ""
    mailer: str = ""
    auto: str = ""          # bulk, list, auto-generated, or ""
    protection: str = "none visible"
    marking: str = ""
    sensitivity_labels: list[str] = field(default_factory=list)
    header_names: set[str] = field(default_factory=set)


def _domain_of(address: str) -> str:
    addr = parseaddr(address)[1] or address
    return addr.rpartition("@")[2].strip(" <>").lower() if "@" in addr else ""


def _iso(when: str) -> str:
    try:
        d = parsedate_to_datetime(when)
        return d.isoformat() if isinstance(d, datetime) else ""
    except (TypeError, ValueError, IndexError):
        return ""


def parse(text: str, catalogue: Catalogue, source: str = "") -> Message:
    meta, headers = read_block(text)
    msg = Message(source=source)
    if meta.get("sizeEstimate", "").isdigit():
        msg.size = int(meta["sizeEstimate"])
    msg.labels = [x for x in meta.get("labels", "").split(",") if x]
    first: dict[str, str] = {}
    received: list[str] = []
    auths: list[str] = []
    arcs: list[str] = []
    for name, value in headers:
        low = name.lower()
        msg.header_names.add(name)
        first.setdefault(low, value)
        if low == "received":
            received.append(value)
        elif low == "authentication-results":
            auths.append(value)
        elif low == "arc-authentication-results":
            arcs.append(value)
        elif low == "dkim-signature":
            msg.signatures.append(parse_dkim_signature(value))
    msg.from_domain = _domain_of(first.get("from", ""))
    msg.envelope_domain = _domain_of(first.get("return-path", ""))
    msg.original_from_domain = original_from(arcs)
    msg.date = _iso(first.get("date", "")) or meta.get("internalDate", "")
    mid = first.get("message-id", "")
    msg.message_id_domain = mid.strip("<> ").rpartition("@")[2].lower() if "@" in mid else ""
    rcpt = first.get("delivered-to") or first.get("x-original-to") or ""
    hops = [parse_received(v) for v in reversed(received)]   # origin first
    if not rcpt:
        rcpt = next((hp.recipient for hp in reversed(hops) if hp.recipient), "")
    msg.recipient_domain = _domain_of(rcpt) if "@" in rcpt else ""
    for hp in hops:
        hp.from_system = catalogue.name_host(hp.from_name, hp.from_rdns, hp.from_ip, hp.raw) \
            if (hp.from_name or hp.from_ip) else ""
        hp.by_system = catalogue.name_host(hp.by_name, "", "", hp.raw) if hp.by_name else ""
        # A web or API submission names the client (often an account number),
        # not a mail host: the message starts inside the platform that took it.
        if hp.protocol.lower() in _WEB_PROTOCOLS and hp.by_system:
            hp.from_system = hp.by_system
    _join_platform_hops(hops)
    msg.hops = hops
    # The topmost Authentication-Results was added last: by the final receiver.
    if auths:
        msg.results = parse_auth(auths[0])
    msg.mailer = first.get("x-mailer") or first.get("user-agent") or first.get("x-mimeole") or ""
    gens: list[str] = []
    named = catalogue.by_mailer(msg.mailer) if msg.mailer else None
    if named:
        gens.append(named)
    elif msg.mailer:
        gens.append(f"mailer: {mailer_name(msg.mailer)}")
    by_mid = catalogue.by_message_id(msg.message_id_domain) if msg.message_id_domain else None
    if by_mid:
        gens.append(by_mid)
    elif msg.message_id_domain:
        gens.append(f"message-id host: {msg.message_id_domain}")
    # A platform stamps its own headers on mail it receives, so a header that
    # names the receiving system says nothing about the sender.
    receiver = hops[-1].by_system if hops else ""
    gens += [g for g in catalogue.by_headers(msg.header_names) if g != receiver]
    msg.submission = submission(hops)
    if "x-php-originating-script" in first:
        gens.append("PHP application")
    msg.generators = list(dict.fromkeys(gens))
    if "list-id" in first or "list-unsubscribe" in first:
        msg.auto = "list or bulk"
    elif first.get("precedence", "").lower() in ("bulk", "list", "junk"):
        msg.auto = "list or bulk"
    elif first.get("auto-submitted", "no").lower() != "no":
        msg.auto = "auto-generated"
    msg.protection = content_protection(first.get("content-type", ""))
    if "x-protective-marking" in first:
        msg.marking = marking(first["x-protective-marking"])
    if "msip_labels" in first:
        msg.sensitivity_labels = label_names(first["msip_labels"])
    return msg


def original_from(arc_results: list[str]) -> str:
    """The From domain the first ARC sealer saw (``i=1``), or "".

    A mailing list or group that redistributes a message rewrites its From to
    the list's own address, and an ARC-sealing list records what it received
    first. So ``i=1`` names the original author's domain.
    """
    def instance(v: str) -> int:
        m = re.match(r"\s*i=(\d+)", v)
        return int(m.group(1)) if m else 1_000_000
    for v in sorted(arc_results, key=instance)[:1]:
        m = re.search(r"header\.from=([A-Za-z0-9.-]+\.[A-Za-z]{2,})", v) or \
            re.search(r"fromdomain=([A-Za-z0-9.-]+\.[A-Za-z]{2,})", v)
        return m.group(1).lower() if m else ""
    return ""


def submission(hops: list[Hop]) -> str:
    """How the message entered the mail system, from its first recorded hop."""
    if not hops:
        return ""
    first = hops[0]
    low = first.protocol.lower()
    if low == "mapi":
        return "Outlook desktop (MAPI)"
    if low in ("http", "https", "httprest", "httpsrest"):
        return "web, mobile or API (HTTP)"
    if first.authenticated:
        return "authenticated SMTP submission"
    if first.from_system.startswith(INTERNAL):
        return "relayed from an internal host"
    if first.from_system and first.from_system == first.by_system:
        return "inside the sending platform"
    return "handed over by SMTP"


def _join_platform_hops(hops: list[Hop]) -> None:
    """Fill a hop's missing ``from`` system from the previous hop's receiver.

    Platforms often record internal hops as ``by <address> with SMTP`` and no
    ``from``; the message was already inside the system that received it last.
    """
    previous = ""
    for hp in hops:
        if not hp.from_system and previous:
            hp.from_system = previous
        if hp.by_system:
            previous = hp.by_system


def parse_file(path: Path, catalogue: Catalogue) -> Message:
    return parse(path.read_text(encoding="utf-8", errors="replace"), catalogue, source=path.name)


def internal_origin(msg: Message) -> bool:
    """True when the first recorded hop starts on an internal host."""
    return bool(msg.hops) and msg.hops[0].from_system.startswith(INTERNAL)
