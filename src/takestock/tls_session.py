"""Read one pinned-version TLS handshake from an ``openssl s_client`` transcript.

A collector asks a server, one TLS version at a time, whether it will agree a
session at that version. Each attempt has three possible answers, and they
must stay distinct:

* ``offered``: a session was agreed at the version asked for;
* ``refused``: the server answered and declined that version;
* ``could-not-ask``: the probe never reached a server that could answer, so
  nothing is known about the version either way.

Collapsing the third into the second would report an unreachable host as one
that refuses old protocols, which reads as a clean result when nothing was
measured.

``openssl`` echoes the version it was asked for in its ``Protocol :`` line
even when the handshake failed, so that line alone is never taken as an
offer: a session is offered only when a real cipher was negotiated.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .util import ERROR_PREFIX

SessionState = Literal["offered", "refused", "could-not-ask"]

OFFERED: SessionState = "offered"
REFUSED: SessionState = "refused"
COULD_NOT_ASK: SessionState = "could-not-ask"

# How each state is written into an asset's ``version_probe`` field.
_ARTEFACT_WORD: dict[SessionState, str] = {
    OFFERED: "offered", REFUSED: "refused", COULD_NOT_ASK: "unknown"}

# Printed once a TCP connection exists, before any TLS is attempted.
_CONNECTED = "CONNECTED("

# Wordings OpenSSL and LibreSSL use when the far end declines the version.
_FAR_END_DECLINED = re.compile(
    r"alert protocol version|wrong version number|no protocols available|"
    r"unsupported protocol|alert handshake failure|"
    r"sslv3 alert|tlsv1 alert|version too low", re.I)

# The summary line when no cipher was agreed: "Cipher is (NONE)" or "Cipher : 0000".
_NO_CIPHER_NEGOTIATED = re.compile(r"Cipher\s*(?:is)?\s*:?\s*(?:\(NONE\)|0000\b)", re.I)

_SESSION_CIPHER = re.compile(r"^\s*Cipher\s*:\s*(\S+)", re.M)

_REPORTED_VERSION = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.M)

# openssl spells TLS 1.0 as "TLSv1"; the baseline spells it "TLSv1.0".
_VERSION_SPELLINGS = {"TLSv1": "TLSv1.0"}

_NULL_CIPHERS = {"0000", "(none)", "none"}


@dataclass(frozen=True)
class TlsSession:
    """The answer to one pinned-version handshake.

    ``reported_version`` and ``cipher`` are what the transcript's session
    block says; ``reached_host`` is True once a TCP connection was made.
    """

    state: SessionState
    reported_version: str = ""
    cipher: str = ""
    reached_host: bool = False


def read_session(out: str, expected: str = "") -> TlsSession:
    """Classify an ``s_client`` transcript; ``expected`` is the version that was pinned.

    A session that completed at a different version from the one pinned is a
    refusal of the pinned version, not an offer of it.
    """
    if out.startswith(ERROR_PREFIX):
        return TlsSession(COULD_NOT_ASK)
    reached = _CONNECTED in out
    reported = _reported_version(out)
    if _FAR_END_DECLINED.search(out):
        return TlsSession(REFUSED, reported, "", reached)
    if _NO_CIPHER_NEGOTIATED.search(out):
        return TlsSession(REFUSED if reached else COULD_NOT_ASK, reported, "", reached)
    cipher = negotiated_cipher(out)
    if not cipher:
        return TlsSession(COULD_NOT_ASK, reported, "", reached)
    if expected and reported != expected:
        return TlsSession(REFUSED, reported, cipher, reached)
    return TlsSession(OFFERED, reported, cipher, reached)


def negotiated_cipher(out: str) -> str:
    """The cipher from the session block, or "" when none (or a null marker) was agreed."""
    m = _SESSION_CIPHER.search(out)
    if not m:
        return ""
    value = m.group(1).strip()
    return "" if value.lower() in _NULL_CIPHERS else value


def _reported_version(out: str) -> str:
    m = _REPORTED_VERSION.search(out)
    if not m:
        return ""
    v = m.group(1).strip()
    return _VERSION_SPELLINGS.get(v, v)


def describe(probed: Mapping[str, TlsSession]) -> str:
    """One line for an asset: ``TLSv1.0=refused; TLSv1.2=offered; ...``."""
    return "; ".join(f"{version}={_ARTEFACT_WORD[s.state]}" for version, s in probed.items())


def versions_in_state(probed: Mapping[str, TlsSession], state: SessionState) -> list[str]:
    """The versions whose answer was ``state``, sorted."""
    return sorted(v for v, s in probed.items() if s.state == state)
