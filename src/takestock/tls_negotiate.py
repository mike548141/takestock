"""Read which key-exchange group a TLS server actually chose.

nmap's ``ssl-enum-ciphers`` lists cipher suites but cannot see TLS 1.3 key
shares, so it cannot say whether a server picks a post-quantum hybrid group
such as X25519MLKEM768. This module makes one ordinary handshake with
Python's ``ssl`` module, records the handshake messages through the
interpreter's message hook, and reads:

* what the client offered (versions, groups in preference order, key shares);
* what the server chose (version, cipher, and the group, from the
  ServerHello key share in TLS 1.3 or the ServerKeyExchange in TLS 1.2).

What it can see is bounded by the client: if the local OpenSSL offers no
post-quantum group, the session says nothing about whether the server would
have chosen one, and :meth:`Negotiation.extra` says so.

Group code points are from the IANA "TLS Supported Groups" registry.
"""

from __future__ import annotations

import socket
import ssl
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

#: IANA TLS Supported Groups code points to names.
GROUP_NAMES = {
    0x0013: "secp192r1", 0x0015: "secp224r1", 0x0017: "secp256r1",
    0x0018: "secp384r1", 0x0019: "secp521r1", 0x001A: "brainpoolP256r1",
    0x001B: "brainpoolP384r1", 0x001C: "brainpoolP512r1",
    0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024", 0x6399: "X25519Kyber768Draft00",
}
#: The groups above that include a post-quantum key encapsulation.
PQ_GROUPS = {0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED, 0x6399}

# Group names whose baseline token is not simply the lower-cased name.
_KEX_TOKENS = {
    "secp192r1": "ecdh_p192", "secp224r1": "ecdh_p224", "secp256r1": "ecdh_p256",
    "secp384r1": "ecdh_p384", "secp521r1": "ecdh_p521",
    "X25519Kyber768Draft00": "x25519kyber768",
}

_VERSIONS = {0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}

# RFC 8446 §4.1.3: a HelloRetryRequest is a ServerHello carrying this random.
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033

HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_SERVER_KEY_EXCHANGE = 1, 2, 12


def _is_grease(v: int) -> bool:
    """True for an RFC 8701 GREASE value, which carries no meaning."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def group_name(code: int) -> str:
    """The registry name for a group code point, or its hex form when unlisted."""
    return GROUP_NAMES.get(code, f"0x{code:04x}")


def kex_token(name: str) -> str:
    """The baseline ``key_exchange`` token for a group name."""
    return _KEX_TOKENS.get(name, name.lower())


class _Reader:
    """A cursor over a handshake message; raises ValueError past the end."""

    def __init__(self, data: bytes) -> None:
        self.d, self.i = data, 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ValueError("truncated handshake message")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def vec(self, len_bytes: int) -> bytes:
        return self.take(int.from_bytes(self.take(len_bytes), "big"))


def _extensions(r: _Reader) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    if r.i >= len(r.d):
        return out
    ext = _Reader(r.vec(2))
    while ext.i < len(ext.d):
        kind = ext.u16()
        out[kind] = ext.vec(2)
    return out


def _u16_list(data: bytes) -> list[int]:
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2)]


def parse_client_hello(msg: bytes) -> dict:
    """Groups, key shares and versions a ClientHello offers (GREASE removed)."""
    r = _Reader(msg)
    if r.u8() != HS_CLIENT_HELLO:
        raise ValueError("not a ClientHello")
    r.take(3)                       # message length
    legacy_version = r.u16()
    r.take(32)                      # random
    r.vec(1)                        # session id
    suites = [s for s in _u16_list(r.vec(2)) if not _is_grease(s)]
    r.vec(1)                        # compression methods
    ext = _extensions(r)
    groups = [g for g in _u16_list(ext.get(_EXT_SUPPORTED_GROUPS, b"")[2:])
              if not _is_grease(g)]
    shares: list[int] = []
    if _EXT_KEY_SHARE in ext:
        ks = _Reader(_Reader(ext[_EXT_KEY_SHARE]).vec(2))
        while ks.i < len(ks.d):
            g = ks.u16()
            ks.vec(2)
            if not _is_grease(g):
                shares.append(g)
    versions: list[int] = [legacy_version]
    if _EXT_SUPPORTED_VERSIONS in ext:
        sv = ext[_EXT_SUPPORTED_VERSIONS]
        versions = [v for v in _u16_list(sv[1:1 + sv[0]]) if not _is_grease(v)]
    return {"groups": groups, "key_shares": shares, "versions": versions,
            "suite_count": len(suites)}


def parse_server_hello(msg: bytes) -> dict:
    """Version, suite, key-share group and HelloRetryRequest marker of a ServerHello."""
    r = _Reader(msg)
    if r.u8() != HS_SERVER_HELLO:
        raise ValueError("not a ServerHello")
    r.take(3)
    legacy_version = r.u16()
    random = r.take(32)
    r.vec(1)
    suite = r.u16()
    r.u8()
    ext = _extensions(r)
    version = legacy_version
    if _EXT_SUPPORTED_VERSIONS in ext and len(ext[_EXT_SUPPORTED_VERSIONS]) >= 2:
        version = int.from_bytes(ext[_EXT_SUPPORTED_VERSIONS][:2], "big")
    ks = ext.get(_EXT_KEY_SHARE, b"")
    group = int.from_bytes(ks[:2], "big") if len(ks) >= 2 else None
    return {"version": version, "suite": suite, "group": group,
            "hello_retry": random == _HRR_RANDOM}


def parse_server_key_exchange(msg: bytes, cipher: str) -> str:
    """The group a TLS 1.2 ServerKeyExchange names: a curve, or ``dh_<bits>``.

    ``cipher`` is the OpenSSL suite name, which says whether the message is
    ECDHE (RFC 8422, named curve) or finite-field DHE (RFC 5246, the prime
    sent in full). Anything else gives "".
    """
    r = _Reader(msg)
    if r.u8() != HS_SERVER_KEY_EXCHANGE:
        raise ValueError("not a ServerKeyExchange")
    r.take(3)
    name = cipher.upper()
    if name.startswith("ECDHE"):
        if r.u8() != 3:             # 3 = named_curve
            return ""
        return group_name(r.u16())
    if name.startswith("DHE"):
        prime = r.vec(2).lstrip(b"\x00")
        return f"dh_{len(prime) * 8}"
    return ""


@dataclass
class Negotiation:
    """What one default handshake offered and what the server chose."""

    client: str = ""
    offer_groups: list[str] = field(default_factory=list)
    offer_key_shares: list[str] = field(default_factory=list)
    offer_versions: list[str] = field(default_factory=list)
    pq_offered: bool = False
    version: str = ""
    cipher: str = ""
    group: str = ""
    group_basis: str = ""
    hello_retry: bool = False
    error: str = ""

    def offer(self) -> str:
        """The client's offer in one line."""
        bits = [self.client]
        if self.offer_versions:
            bits.append("versions " + ",".join(self.offer_versions))
        if self.offer_groups:
            bits.append("groups in order " + ",".join(self.offer_groups))
        if self.offer_key_shares:
            bits.append("key shares " + ",".join(self.offer_key_shares))
        return "; ".join(b for b in bits if b)

    def extra(self) -> dict[str, str]:
        """The reading as ``negotiated_*`` string fields for an asset's ``extra``."""
        out = {"negotiated_client_offer": self.offer()}
        if self.error:
            out["negotiated_error"] = self.error
            return out
        out["negotiated_version"] = self.version
        out["negotiated_cipher"] = self.cipher
        out["negotiated_group"] = self.group or f"not read — {self.group_basis}"
        if self.hello_retry:
            out["negotiated_hello_retry"] = "yes — the server asked for a different key share"
        if not self.pq_offered:
            out["negotiated_pq_limit"] = (
                "the probing client offered no post-quantum group, so this session says "
                "nothing about whether the server supports one")
        return out


def client_label() -> str:
    """Which client made the handshake, so a reader can judge what it could offer."""
    return f"Python {sys.version.split()[0]} ssl, {ssl.OPENSSL_VERSION}, default groups"


def read_negotiation(messages: Sequence[tuple[str, int, bytes]], version: str,
                     cipher: str, client: str) -> Negotiation:
    """Build a :class:`Negotiation` from recorded ``(direction, type, bytes)`` messages.

    ``direction`` is ``"write"`` for what the client sent and ``"read"`` for
    what it received. The offer is taken from the first ClientHello (a second
    one follows a HelloRetryRequest); the choice from the last ServerHello,
    falling back to a ServerKeyExchange in TLS 1.2 and to ``rsa`` for a
    TLS 1.2 session with neither (static RSA key transport).
    """
    n = Negotiation(client=client, version=version, cipher=cipher)
    hellos = [m for d, t, m in messages if d == "write" and t == HS_CLIENT_HELLO]
    if hellos:
        offer = parse_client_hello(hellos[-1])
        first = parse_client_hello(hellos[0])
        n.offer_groups = [group_name(g) for g in first["groups"]]
        n.offer_key_shares = [group_name(g) for g in first["key_shares"]]
        n.offer_versions = [_VERSIONS.get(v, f"0x{v:04x}") for v in first["versions"]]
        n.pq_offered = any(g in PQ_GROUPS for g in first["groups"] + offer["groups"])
    servers = [parse_server_hello(m) for d, t, m in messages
               if d == "read" and t == HS_SERVER_HELLO]
    n.hello_retry = any(s["hello_retry"] for s in servers)
    final = servers[-1] if servers else None
    if final and final["group"] is not None and not final["hello_retry"]:
        n.group = group_name(final["group"])
    else:
        skx = [m for d, t, m in messages if d == "read" and t == HS_SERVER_KEY_EXCHANGE]
        if skx:
            n.group = parse_server_key_exchange(skx[-1], cipher)
        elif final and version != "TLSv1.3":
            n.group = "rsa"
    if not n.group:
        n.group_basis = ("no handshake messages were visible to this client"
                         if not messages else "the server's hello named no group")
    return n


def negotiate(address: str, port: int, sni: str = "", timeout: float = 10.0) -> Negotiation:
    """Make one default handshake with ``address:port`` and read the negotiation.

    Certificates are not verified: this measures what is agreed, not whether
    the certificate is trusted. Never raises; a failed handshake comes back
    with ``error`` set and whatever of the offer was recorded.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    messages: list[tuple[str, int, bytes]] = []
    hooked = hasattr(ctx, "_msg_callback")

    def _cb(conn: object, direction: str, version: object, content_type: object,
            msg_type: object, data: bytes) -> None:
        if int(content_type) == 22:  # type: ignore[call-overload]  # 22 = handshake
            messages.append((direction, int(msg_type), bytes(data)))  # type: ignore[call-overload]

    if hooked:
        ctx._msg_callback = _cb  # type: ignore[attr-defined]
    client = client_label()
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw, \
                ctx.wrap_socket(raw, server_hostname=sni or None) as s:
            version = s.version() or ""
            cipher = (s.cipher() or ("",))[0]
    except (OSError, ssl.SSLError, ValueError) as e:
        n = Negotiation(client=client, error=f"no session with the default client: {e}")
        try:
            if messages:
                hello = read_negotiation(messages, "", "", client)
                n.offer_groups, n.offer_key_shares = hello.offer_groups, hello.offer_key_shares
                n.offer_versions, n.pq_offered = hello.offer_versions, hello.pq_offered
        except ValueError:
            pass
        return n
    try:
        n = read_negotiation(messages, version, cipher, client)
    except ValueError as e:
        n = Negotiation(client=client, version=version, cipher=cipher,
                        group_basis=f"handshake could not be parsed: {e}")
    if not hooked:
        n.group_basis = "this Python has no handshake message hook to read it from"
    return n
