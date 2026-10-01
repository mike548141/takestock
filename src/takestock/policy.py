"""Grade observed cryptography against the algorithm baseline.

The baseline (``data/baseline.yaml``) maps every token a collector can report
(a TLS version, a cipher, an SSH MAC, an IKE group) to one of four verdicts:
``weak``, ``acceptable``, ``strong`` or ``pqc``. :class:`Policy` reads those
tables and grades a :class:`~takestock.model.CryptoAsset` as the weakest thing
it accepts, adding flags that say why.

It also reads the post-quantum position of each asset, on two axes:

* exposure flags (``quantum-vulnerable-kex`` and
  ``quantum-vulnerable-signature``), raised when a job is done only by
  classical public-key cryptography;
* readiness values (``pq_kex`` and ``pq_sig``), one of ready, hybrid,
  classical, gap or n/a, with a basis saying why when it is not a reading.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace

from .model import GRADED_VERDICTS, NA_VERDICT, VERDICT_ORDER, CryptoAsset, worst
from .plaintext import PLAINTEXT_FLAG, UNVERIFIED_FLAG

# Rows that carry no cryptographic primitive by nature: mail and certificate
# policy records, discovered names, identities, inventory rows, suppliers.
NON_CRYPTO_PROTOCOLS = {"mx", "spf", "spf-senders", "dmarc", "mta-sts", "caa", "dane"}
NON_CRYPTO_STATES = {"discovery", "identity"}
NON_CRYPTO_ROW_STATES = {"estate", "third-party"}

# A fallback for tokens the baseline has no row for: a name that is plainly
# classical public-key cryptography still counts as classical.
CLASSICAL_NAME = re.compile(
    r"rsa|ecdh|ecdsa|dsa|dss|ed25519|ed448|x25519|x448|curve25519|curve448|"
    r"dh_|dhe|diffie-hellman|p-?(192|224|256|384|521)|secp|nistp|brainpool",
    re.IGNORECASE)

# TLS 1.2 suite components that are classical key exchange or authentication.
CLASSICAL_SUITE_KEX = {"rsa", "dhe", "ecdhe", "dh_static", "ecdh_static", "srp"}
CLASSICAL_SUITE_AUTH = {"rsa", "ecdsa", "dss"}
AEAD_MODES = {"gcm", "ccm", "ccm_8", "poly1305"}

#: The data states the post-quantum axes read.
PQ_DATA_STATES = ("in-transit", "email-auth", "certificate")

_PQ_FLAG_FAMILY = "quantum-"

_SIZE_WORDS = {"40", "56", "64", "112", "128", "192", "256"}


def suite_kex_class(suite: str) -> str:
    """The key-exchange class of an IANA TLS cipher-suite name.

    ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` gives ``ecdhe``; a TLS 1.3 suite
    (no ``_WITH_``) gives ``tls13``. Anything unrecognised gives ``other``.
    """
    s = suite.upper()
    if not s.startswith("TLS_"):
        return "other"
    if "_WITH_" not in s:
        return "tls13"
    head = s[4:].split("_WITH_", 1)[0]
    if head == "AKE":
        return "tls13"
    parts = head.split("_")
    if "ANON" in parts:
        return "anon"
    if parts[0] == "SRP":
        return "srp"
    if parts[0] == "KRB5":
        return "krb5"
    if parts[0] == "ECDHE":
        return "ecdhe"
    if parts[0] == "DHE":
        return "dhe"
    if parts[0] == "ECDH":
        return "ecdh_static"
    if parts[0] == "DH":
        return "dh_static"
    if parts[0] == "PSK":
        return "psk"
    if parts[0] == "RSA":
        return "rsa"
    return "other"


# Cipher words in a suite name -> (baseline ``symmetric`` token, mode).
_CIPHER_SPECS: dict[tuple[str, ...], tuple[str, str]] = {
    ("AES", "128", "GCM"): ("aes128_gcm", "gcm"),
    ("AES", "256", "GCM"): ("aes256_gcm", "gcm"),
    ("AES", "128", "CBC"): ("aes_cbc", "cbc"),
    ("AES", "256", "CBC"): ("aes_cbc", "cbc"),
    ("AES", "128", "CCM"): ("aes128_ccm", "ccm"),
    ("AES", "256", "CCM"): ("aes256_ccm", "ccm"),
    ("AES", "128", "CCM", "8"): ("aes128_ccm_8", "ccm_8"),
    ("AES", "256", "CCM", "8"): ("aes256_ccm_8", "ccm_8"),
    ("CHACHA20", "POLY1305"): ("chacha20_poly1305", "poly1305"),
    ("3DES", "EDE", "CBC"): ("3des", "cbc"),
    ("DES", "CBC"): ("des", "cbc"),
    ("DES40", "CBC"): ("des", "cbc"),
    ("RC4", "128"): ("rc4", "stream"),
    ("RC4", "40"): ("rc4", "stream"),
    ("RC2", "CBC", "40"): ("rc2", "cbc"),
    ("IDEA", "CBC"): ("idea", "cbc"),
    ("SEED", "CBC"): ("seed_cbc", "cbc"),
    ("NULL",): ("null", "null"),
    ("CAMELLIA", "128", "CBC"): ("camellia_cbc", "cbc"),
    ("CAMELLIA", "256", "CBC"): ("camellia_cbc", "cbc"),
    ("CAMELLIA", "128", "GCM"): ("camellia128_gcm", "gcm"),
    ("CAMELLIA", "256", "GCM"): ("camellia256_gcm", "gcm"),
    ("ARIA", "128", "CBC"): ("aria_cbc", "cbc"),
    ("ARIA", "256", "CBC"): ("aria_cbc", "cbc"),
    ("ARIA", "128", "GCM"): ("aria128_gcm", "gcm"),
    ("ARIA", "256", "GCM"): ("aria256_gcm", "gcm"),
}
_HASH_WORDS = {"SHA": "sha1", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512", "MD5": "md5"}


def parse_cipher_suite(suite: str) -> dict:
    """Split an IANA TLS cipher-suite name into baseline tokens.

    Returns ``kex``, ``auth``, ``cipher``, ``mode``, ``mac`` (for a non-AEAD
    suite) or ``prf`` (for an AEAD one), ``export`` and the symmetric key
    ``bits`` where the name states them.
    """
    s = suite.strip().upper()
    kex = suite_kex_class(s)
    body = s.removeprefix("TLS_")
    head, sep, tail = body.partition("_WITH_")
    if not sep:
        head, tail = "", body
    words = [w for w in tail.split("_") if w]
    hash_tok = _HASH_WORDS.get(words[-1], "") if words and words[-1] in _HASH_WORDS else ""
    spec = tuple(words[:-1]) if hash_tok else tuple(words)
    cipher, mode = _CIPHER_SPECS.get(spec, ("_".join(spec).lower(), ""))
    hparts = head.split("_") if head else []
    auth = next((w.lower() for w in reversed(hparts)
                 if w in ("ECDSA", "RSA", "DSS", "PSK", "ANON")), "")
    aead = mode in AEAD_MODES or kex == "tls13"
    return {
        "kex": kex, "auth": auth, "cipher": cipher, "mode": mode,
        "mac": "" if aead else hash_tok,
        "prf": hash_tok if aead else "",
        "export": "EXPORT" in hparts or any(w.startswith("EXPORT") for w in hparts),
        "bits": next((int(w) for w in spec if w in _SIZE_WORDS), 0),
    }


class Policy:
    """The baseline as a grader.

    Every :meth:`grade` call that finds a row records ``"<table>/<token>"``
    so :meth:`apply` can write the asset's ``citations``.
    """

    def __init__(self, baseline: dict):
        self.b = baseline
        self._graded: list[str] = []

    def grade(self, category: str, token: str) -> str:
        """The verdict for ``token`` in baseline table ``category``, or ``unknown``.

        An exact match is tried first, then a case-insensitive one.
        """
        table = self.b.get(category, {})
        t = token.strip()
        if t in table:
            self._graded.append(f"{category}/{t}")
            return table[t]
        tl = t.lower()
        for k, v in table.items():
            if str(k).lower() == tl:
                self._graded.append(f"{category}/{k}")
                return v
        return "unknown"

    def _take(self, table: str, token: str, verdicts: list[str], flags: set[str],
              weak_flag: str | None = None) -> str:
        """Grade one token into ``verdicts``; flag it if ungraded or weak."""
        g = self.grade(table, token)
        if g == "unknown":
            # Surfaced rather than dropped: a token the baseline does not know
            # must never let an asset look stronger than it is.
            flags.add(f"ungraded:{table}:{token}")
            return g
        verdicts.append(g)
        if g == "weak" and weak_flag:
            flags.add(f"{weak_flag}:{token}")
        return g

    @staticmethod
    def normalise_tls_version(v: str) -> str:
        """Normalise the spellings scanners use (``TLS1.2``, ``SSL3``) to baseline keys."""
        v = re.sub(r"SSL(?!v)", "SSLv", v.replace(" ", "").replace("TLS1", "TLSv1"))
        v = v.replace("SSLv2.0", "SSLv2").replace("SSLv3.0", "SSLv3")
        return v.replace("TLSv13", "TLSv1.3")

    def grade_tls_version(self, v: str) -> str:
        """The verdict for a TLS or SSL version string."""
        return self.grade("tls_versions", self.normalise_tls_version(v))

    def grade_cipher_suite(self, suite: str, groups_observed: bool = False) -> tuple[str, list[str]]:
        """Grade one TLS cipher suite; return (verdict, flags).

        ``groups_observed`` says the collector recorded the negotiated key
        exchange group separately. When it did, an ephemeral (EC)DHE suite is
        graded by that group instead of by its class, and when it did not the
        class row grades it and ``not-measured:key-exchange-group`` says so.
        """
        parts = parse_cipher_suite(suite)
        verdicts: list[str] = []
        flags: set[str] = set()

        kex = parts["kex"]
        if kex == "rsa":
            self._take("key_exchange", "rsa", verdicts, flags)
            flags.add("no-forward-secrecy")
        elif kex in ("dh_static", "ecdh_static"):
            self._take("key_exchange", kex, verdicts, flags)
            flags.add("no-forward-secrecy")
        elif kex == "anon":
            self._take("key_exchange", "anon", verdicts, flags)
            flags.add("anonymous-kex")
        elif kex in ("dhe", "ecdhe"):
            if not groups_observed:
                self._take("key_exchange", kex, verdicts, flags)
                flags.add("not-measured:key-exchange-group")
        elif kex in ("psk", "srp", "krb5"):
            self._take("key_exchange", kex, verdicts, flags)

        if parts["cipher"]:
            self._take("symmetric", parts["cipher"], verdicts, flags, "weak-symmetric")
        if parts["mode"] == "cbc":
            flags.add("cbc-mode")
        if parts["cipher"] == "null":
            flags.add("null-cipher")
        if parts["export"]:
            flags.add("export-grade")

        if parts["mac"]:
            g = self._take("hashes", parts["mac"], verdicts, flags)
            if g == "weak":
                flags.add(f"{parts['mac']}-mac")
        elif parts["prf"]:
            self._take("hashes", parts["prf"], verdicts, flags)
        return worst(verdicts), sorted(flags)

    @staticmethod
    def normalise_ike_dh(group: str) -> str:
        """Reduce an IKE group label (``modp1024 (2)``, ``Group 14``) to its number."""
        m = re.search(r"(\d+)", str(group))
        return m.group(1) if m else str(group)

    def downgrade_surface(self, a: CryptoAsset) -> list[str]:
        """``downgrade-surface:<axis>`` flags for an IKE gateway.

        Raised when the weakest transform a gateway accepts on an axis
        (encryption, hash, group) grades below the one it prefers: an
        attacker in the path can force the weaker one.
        """
        tables = {"enc": "ike_encryption", "hash": "hashes", "group": "ike_dh"}
        weakest = a.extra.get("ike_weakest") or {}
        preferred = a.extra.get("ike_preferred") or {}
        out = []
        for axis, table in tables.items():
            lo, pref = weakest.get(axis), preferred.get(axis)
            if not (lo and pref) or lo == pref:
                continue
            g_lo, g_pref = self.grade(table, lo), self.grade(table, pref)
            if (g_lo in GRADED_VERDICTS and g_pref in GRADED_VERDICTS
                    and VERDICT_ORDER[g_lo] < VERDICT_ORDER[g_pref]):
                out.append(f"downgrade-surface:{axis}")
        return out

    def grade_ike_dh(self, group: str) -> str:
        """The verdict for an IKE Diffie-Hellman group, by number."""
        return self.grade("ike_dh", self.normalise_ike_dh(group))

    def is_classical(self, table: str, token: str) -> bool:
        """True when ``token`` is classical (not post-quantum) public-key cryptography."""
        g = self.grade(table, token)
        if g == "pqc":
            return False
        if g != "unknown":
            return True
        return bool(CLASSICAL_NAME.search(token))

    @staticmethod
    def is_non_crypto_record(a: CryptoAsset) -> bool:
        """True for a row that carries no cryptographic primitive by nature."""
        return a.data_state in NON_CRYPTO_STATES or a.protocol in NON_CRYPTO_PROTOCOLS

    def quantum_exposure(self, a: CryptoAsset) -> set[str]:
        """The quantum-vulnerability flags for ``a``.

        Key exchange and signatures are judged separately: a post-quantum key
        exchange does not excuse a classical signature, and the reverse.
        """
        if a.data_state not in PQ_DATA_STATES:
            return set()
        kex_classical, kex_pq, sig_classical, sig_pq = self._pq_primitives(a)
        out = set()
        if kex_classical and not kex_pq:
            out.add("quantum-vulnerable-kex")
        if sig_classical and not sig_pq:
            out.add("quantum-vulnerable-signature")
        return out

    def _pq_primitives(self, a: CryptoAsset) -> tuple[bool, bool, bool, bool]:
        """(kex classical, kex post-quantum, signature classical, signature post-quantum)."""
        kex = [("key_exchange", t) for t in a.key_exchange]
        kex += [("ike_dh", self.normalise_ike_dh(g))
                for g in a.extra.get("ike_dh_groups", [])]
        sig = [("signatures", t) for t in a.signatures]
        if a.protocol == "ssh":
            kex += [("ssh_kex", t) for t in a.extra.get("ssh_kex", [])]
            sig += [("ssh_hostkey", t) for t in a.extra.get("ssh_hostkey", [])]

        kex_classical = any(self.is_classical(tbl, tok) for tbl, tok in kex)
        kex_pq = any(self.grade(tbl, tok) == "pqc" for tbl, tok in kex)
        sig_classical = any(self.is_classical(tbl, tok) for tbl, tok in sig)
        sig_pq = any(self.grade(tbl, tok) == "pqc" for tbl, tok in sig)

        # A TLS 1.2 suite name states its own key exchange and authentication.
        if a.protocol == "tls":
            for name in a.symmetric:
                if not name.upper().startswith("TLS_"):
                    continue
                if suite_kex_class(name) in CLASSICAL_SUITE_KEX:
                    kex_classical = True
                if parse_cipher_suite(name)["auth"] in CLASSICAL_SUITE_AUTH:
                    sig_classical = True
        return kex_classical, kex_pq, sig_classical, sig_pq

    def quantum_readiness(self, a: CryptoAsset) -> tuple[
            tuple[str, str], tuple[str, str]]:
        """((pq_kex, basis), (pq_sig, basis)) for ``a``.

        A real reading has an empty basis. ``n/a`` and ``gap`` always carry a
        basis from :data:`takestock.model.PQ_BASES`.
        """
        if (self.is_non_crypto_record(a)
                or a.data_state in NON_CRYPTO_ROW_STATES
                or (a.data_state == "email-auth" and a.protocol != "dkim")):
            return ((NA_VERDICT, "no-cryptography"),) * 2

        if a.data_state not in PQ_DATA_STATES:
            return (("gap", "not-yet-read"),) * 2

        if a.protocol == "dnssec" and "dnssec-unsigned" in a.flags:
            return ((NA_VERDICT, "no-cryptography"),) * 2

        if any(f.startswith(PLAINTEXT_FLAG) for f in a.flags):
            return ((NA_VERDICT, "cleartext-service"),) * 2

        kex_classical, kex_pq, sig_classical, sig_pq = self._pq_primitives(a)
        # A signed object (certificate, DKIM key, signed zone) agrees no keys.
        no_kex = a.data_state in ("certificate", "email-auth") or a.protocol == "dnssec"
        return (
            self._pq_reading(kex_classical, kex_pq, a,
                             absent=(NA_VERDICT, "no-key-establishment")
                             if no_kex else None),
            self._pq_reading(sig_classical, sig_pq, a, absent=None),
        )

    @staticmethod
    def _pq_reading(classical: bool, pq: bool, a: CryptoAsset,
                    absent: tuple[str, str] | None) -> tuple[str, str]:
        if pq:
            return ("hybrid", "") if classical else ("ready", "")
        if classical:
            return ("classical", "")
        if absent is not None:
            return absent
        if any(f.startswith(UNVERIFIED_FLAG) for f in a.flags):
            return ("gap", "not-probed")
        return ("gap", "not-observed")

    def symmetric_strength(self, token: str, bits: int = 0) -> int:
        """Classical security strength in bits for a symmetric token; 0 if unrated.

        Reads the baseline's ``symmetric_strength`` table, first by the whole
        token, then by family and size (``aes`` + ``256``). ``bits`` supplies
        the size when the token does not carry it.
        """
        table = {str(k).strip().lower(): int(v)
                 for k, v in (self.b.get("symmetric_strength") or {}).items()}
        t = str(token).strip().lower()
        if t in table:
            return table[t]
        m = re.match(r"^([a-z]+)", t)
        family = m.group(1) if m else ""
        sizes = re.findall(r"(?<![0-9])(128|192|256)(?![0-9])", t)
        size = int(sizes[0]) if sizes else bits
        if family and size and f"{family}{size}" in table:
            return table[f"{family}{size}"]
        return 0

    def symmetric_margin(self, a: CryptoAsset) -> set[str]:
        """``quantum-symmetric-margin:<bits>`` for ``a``: an informational reading.

        Names the weakest rated symmetric strength seen, or a range
        ``<floor>-<best>`` when they differ. Empty when nothing is rated.
        """
        if self.is_non_crypto_record(a):
            return set()
        tokens = list(a.symmetric)
        if a.protocol == "ike":
            tokens += list(a.extra.get("ike_encryption", []))
        strengths = []
        for tok in tokens:
            if a.protocol == "tls" and tok.upper().startswith("TLS_"):
                parts = parse_cipher_suite(tok)
                s = self.symmetric_strength(parts["cipher"], parts["bits"])
            else:
                s = self.symmetric_strength(tok)
            if s:
                strengths.append(s)
        if not strengths:
            return set()
        floor, best = min(strengths), max(strengths)
        reading = str(floor) if floor == best else f"{floor}-{best}"
        return {f"quantum-symmetric-margin:{reading}"}

    def apply(self, a: CryptoAsset) -> CryptoAsset:
        """Grade ``a`` in place and return it.

        Sets ``verdict`` to the weakest graded token (or ``n/a`` for a
        non-cryptographic record with nothing ungraded), adds the flags that
        explain it, and writes ``citations`` and the post-quantum readiness
        fields. A verdict a collector set is kept when nothing could be graded.
        """
        verdicts: list[str] = []
        flags = set(a.flags)
        self._graded = []

        if a.protocol == "tls":
            for v in a.protocol_versions:
                nv = self.normalise_tls_version(v)
                g = self._take("tls_versions", nv, verdicts, flags)
                if g == "weak":
                    flags.add(f"deprecated-protocol:{v}")
        if a.protocol == "smb":
            for v in a.protocol_versions:
                if self._take("smb_dialects", v, verdicts, flags) == "weak":
                    flags.add(f"deprecated-protocol:{v}")

        symmetric_table = {"ssh": "ssh_cipher", "ike": "ike_encryption"}.get(a.protocol, "symmetric")
        sym_tokens = list(a.symmetric)
        if a.protocol == "ike":
            sym_tokens = sorted(set(sym_tokens) | set(a.extra.get("ike_encryption", [])))
        for suite in sym_tokens:
            if a.protocol == "tls" and suite.upper().startswith("TLS_"):
                g, f = self.grade_cipher_suite(suite, groups_observed=bool(a.key_exchange))
                if g != "unknown":
                    verdicts.append(g)
                flags.update(f)
            else:
                self._take(symmetric_table, suite, verdicts, flags, "weak-symmetric")

        for kx in a.key_exchange:
            self._take("key_exchange", kx, verdicts, flags, "weak-kex")
            if kx in ("rsa",):
                flags.add("no-forward-secrecy")
            if re.search(r"dh_1024|dh_1536|dh group 2|group2", kx.lower()):
                flags.add("weak-dh")

        for sig in a.signatures:
            self._take("signatures", sig, verdicts, flags, "weak-signature")

        for grp in a.extra.get("ike_dh_groups", []):
            g = self._take("ike_dh", self.normalise_ike_dh(grp), verdicts, flags)
            if g == "weak":
                flags.add(f"weak-dh-group:{grp}")

        for prf in a.extra.get("ike_prf", []):
            self._take("ike_prf", prf, verdicts, flags, "weak-ike-prf")

        flags.update(self.downgrade_surface(a))

        # SSH algorithm lists are graded only on an SSH row.
        if a.protocol == "ssh":
            for hostkey in a.extra.get("ssh_hostkey", []):
                self._take("ssh_hostkey", hostkey, verdicts, flags, "weak-hostkey")
            for kex in a.extra.get("ssh_kex", []):
                self._take("ssh_kex", kex, verdicts, flags, "weak-ssh-kex")
            for mac in a.extra.get("ssh_mac", []):
                self._take("ssh_mac", mac, verdicts, flags, "weak-ssh-mac")

        for h in a.hashes:
            self._take("hashes", h, verdicts, flags, "weak-hash")

        flags.update(self.quantum_exposure(a))

        flags.update(self.symmetric_margin(a))

        if verdicts:
            a.verdict = worst(verdicts)
        elif (a.verdict == "unknown" and self.is_non_crypto_record(a)
              and not any(f.startswith("ungraded:") for f in flags)):
            a.verdict = NA_VERDICT
        if a.verdict == "weak":
            flags.add("weak-floor")
        a.citations = sorted(set(self._graded))
        a.flags = sorted(flags)
        self._stamp_readiness(a)
        return a

    def _stamp_readiness(self, a: CryptoAsset) -> None:
        (a.pq_kex, a.pq_kex_basis), (a.pq_sig, a.pq_sig_basis) = \
            self.quantum_readiness(a)

    def annotate_quantum_exposure(self, assets: Iterable[CryptoAsset]) -> None:
        """Recompute the post-quantum flags and readiness on stored assets.

        Every other flag and the verdict are left alone, so an observation
        re-rendered under a newer baseline gains the current post-quantum
        reading without being re-graded.
        """
        for a in assets:
            keep = [f for f in a.flags if not f.startswith(_PQ_FLAG_FAMILY)]
            graded = list(self._graded)
            a.flags = sorted(set(keep) | self.quantum_exposure(a) | self.symmetric_margin(a))
            self._graded = graded
            self._stamp_readiness(a)

    def annotate_citations(self, assets: Iterable[CryptoAsset]) -> None:
        """Recompute ``citations`` on stored assets without changing anything else.

        Grading runs on a copy, so verdicts and flags are untouched; only the
        list of baseline rows that graded the asset is refreshed.
        """
        for a in assets:
            self.apply(replace(a))
            a.citations = sorted(set(self._graded))
