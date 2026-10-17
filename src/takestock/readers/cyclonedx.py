"""CycloneDX software bills of materials: what an application says it is built with.

A **software bill of materials** (SBOM) lists the components a piece of
software was built from: its libraries, frameworks and their versions.
CycloneDX is the OWASP standard for one, also published by Ecma International
(https://cyclonedx.org/specification/overview/). Build tools for most
languages can write one. This reader takes the JSON form.

The other collectors look at infrastructure: what a server negotiates, what a
device has installed. An SBOM shows a layer they cannot reach, the
cryptographic, identity and transport libraries inside an application itself.

**What a row here means.** An SBOM is written when the software is built, not
while it runs. A library it lists may never be called, and a feature may be
switched off in configuration. So every row is a statement of what the
application *can* do, never a measurement of what it does, and each row's
notes say so.

**Which components become rows.** Each component's name (and its group, for
ecosystems that have one) is split into words, and the words are looked up in
:data:`CLASSES`, in order; the first class with a matching word wins. Whole
words, not substrings, so a package whose name merely contains one of them is
not caught. A component no class matches is counted on the application's row
and the scope row, and not reported: the classes set the limit of what this
reader can see, not the application.

**Flags.**

* ``sbom-declared-dependency`` and ``sbom-provides:<class>`` on every
  component row; ``sbom-direct-dependency`` when the application names the
  component itself in its dependency graph, rather than receiving it through
  another component;
* ``sbom-prerelease-crypto``: a pre-release build of a cryptographic or
  identity component. Not graded weak: a pre-release can be deliberate, and
  the row's job is to make someone ask;
* ``sbom-app-can-originate:ssh``: the application carries its own secure-shell
  code, so it can open SSH connections itself, outside the controls that
  govern SSH on servers and network devices;
* ``sbom-encrypts-by-default``: a library whose documented default is to
  encrypt its connections, from version :data:`ENCRYPTS_BY_DEFAULT` names.
  It never improves a grade: a connection string can still turn it off;
* ``sbom-subject`` and ``sbom-scope`` on the application and scope rows.

All but ``sbom-prerelease-crypto`` are registered as informational: each
states what a bill of materials declares, so the first one read is not the
estate getting worse. A pre-release cryptographic component arriving is a
change worth seeing.

**The input** is one SBOM file, or a folder of them (every ``*.json`` file
directly inside it, in name order). One SBOM describes one application and
nothing else, so the reader never extends what it read to software it did not
read, and records the rest of the applications as a coverage gap.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "sbom"

PRERELEASE_FLAG = "sbom-prerelease-crypto"
SSH_FLAG = "sbom-app-can-originate:ssh"

register_informational_prefixes(
    "sbom-declared-dependency", "sbom-provides:", "sbom-direct-dependency",
    "sbom-app-can-originate:", "sbom-encrypts-by-default", "sbom-subject", "sbom-scope")


@dataclass(frozen=True)
class ComponentClass:
    """One class of component: its key (in flags), a label for a reader, and its words."""

    key: str
    label: str
    words: frozenset[str]


#: The classes, checked in order; the first with a word in the component's
#: name wins. The words are common package names across language ecosystems
#: (npm, PyPI, Maven, NuGet, Go, Rust and others), lower case. Order matters
#: where a name holds words of two classes: an SSH library's own cipher package
#: is an SSH component first, and a token library inside an identity framework
#: is a token component.
CLASSES: tuple[ComponentClass, ...] = (
    ComponentClass("ssh", "secure-shell", frozenset({
        "ssh", "ssh2", "sshnet", "sshj", "jsch", "libssh", "paramiko",
        "asyncssh", "russh", "sshd"})),
    ComponentClass("key-management", "key and secret management", frozenset({
        "keyvault", "kms", "secretsmanager", "secretmanager", "hvac", "vaultsharp",
        "keyring", "pkcs11", "cloudhsm"})),
    ComponentClass("primitives", "cryptographic library", frozenset({
        "cryptography", "crypto", "cryptodome", "cryptodomex", "pycryptodome",
        "pycryptodomex", "openssl", "pyopenssl", "boringssl", "libressl", "wolfssl",
        "mbedtls", "gnutls", "libsodium", "sodium", "nacl", "pynacl", "tweetnacl",
        "bouncycastle", "bcprov", "bcpkix", "bcfips", "conscrypt", "tink", "pkcs",
        "x509", "bcrypt", "scrypt", "protecteddata", "rustls", "jasypt"})),
    ComponentClass("tokens", "security-token", frozenset({
        "jwt", "jose", "jsonwebtoken", "jsonwebtokens", "pyjwt", "jwcrypto", "jjwt",
        "identitymodel", "tokenacquisition", "tokencache", "paseto"})),
    ComponentClass("identity", "authentication and identity", frozenset({
        "identity", "authentication", "authn", "openidconnect", "oidc", "oauth",
        "oauthlib", "authlib", "msal", "saml", "saml2", "keycloak",
        "passport", "kerberos", "gssapi", "spnego", "ntlm", "webauthn", "fido2",
        "ldap", "ldap3"})),
    ComponentClass("transport", "data-transport client", frozenset({
        "sqlclient", "manageddataaccess", "npgsql", "psycopg", "psycopg2", "pymysql",
        "mysqlconnector", "mysql2", "pymongo", "jdbc", "odbc", "pyodbc", "redis",
        "ioredis", "jedis", "stackexchangeredis", "rabbitmq", "amqp", "amqplib", "pika",
        "kafka", "kafkajs", "nats", "mqtt", "paho", "zeromq", "pyzmq"})),
)

#: The classes whose pre-release builds are flagged: those holding keys,
#: secrets or credentials. A pre-release transport client is routine.
CRYPTO_CLASSES = frozenset({"ssh", "key-management", "primitives", "tokens", "identity"})

#: Libraries whose documented default is to encrypt their connections:
#: (package name, lower case; the first major version with that default; the
#: public source for it).
ENCRYPTS_BY_DEFAULT: tuple[tuple[str, int, str], ...] = (
    ("microsoft.data.sqlclient", 4,
     "Microsoft.Data.SqlClient 4.0 release notes: the Encrypt connection setting "
     "defaults to true"),
)

_WORD_SPLIT = re.compile(r"[.\-_/@:+\s]+")
# A labelled pre-release: SemVer (1.0.0-beta.2), Maven (1.0-SNAPSHOT), NuGet
# (2.0.0-preview.1), and Python's .devN.
_PRERELEASE_LABEL = re.compile(
    r"(?:^|[-.+_])(?:alpha|beta|preview|pre|rc|snapshot|dev|nightly|canary)(?:$|[-.+_\d])",
    re.IGNORECASE)
# Python's short forms: 2.0a1, 2.0b1, 2.0rc1.
_PRERELEASE_SHORT = re.compile(r"^\d+(?:\.\d+)*(?:a|b|rc)\d+", re.IGNORECASE)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_MAJOR = re.compile(r"^\s*v?(\d+)")

CAN_DO = ("A bill of materials records what the software was built with, so this is "
          "something the application can do, not a measurement of what it does: nothing "
          "here observed the running service.")


def words(*names: str) -> set[str]:
    """The lower-case words of package names, split on the separators ecosystems use."""
    return {w for n in names for w in _WORD_SPLIT.split(n.lower()) if w}


def classify(name: str, group: str = "") -> ComponentClass | None:
    """The first class with a word in the component's group or name, or None."""
    found = words(name, group)
    return next((c for c in CLASSES if found & c.words), None)


def is_prerelease(version: str) -> bool:
    """Whether a version string labels a pre-release build."""
    v = version.strip()
    return bool(_PRERELEASE_LABEL.search(v) or _PRERELEASE_SHORT.match(v))


def major(version: str) -> int | None:
    m = _MAJOR.match(version or "")
    return int(m.group(1)) if m else None


def _article(text: str) -> str:
    return "an" if text[:1].lower() in "aeiou" else "a"


@dataclass
class Bom:
    """One SBOM file, read."""

    path: Path
    spec: str
    subject: str
    subject_version: str
    subject_ref: str
    date: str
    components: list[dict] = field(default_factory=list)
    direct: set[str] = field(default_factory=set)

    @property
    def label(self) -> str:
        return f"{self.subject} {self.subject_version}".strip()


def _walk(items: Any) -> list[dict]:
    """Every component, nested ones included (a component may hold its own ``components``)."""
    out: list[dict] = []
    for c in items if isinstance(items, list) else []:
        if isinstance(c, dict):
            out.append(c)
            out += _walk(c.get("components"))
    return out


def read_bom(path: Path) -> tuple[Bom | None, str]:
    """``path`` read as a CycloneDX JSON document: (the SBOM, "") or (None, why not)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return None, f"not readable as JSON: {exc}"
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        return None, "not a CycloneDX document (bomFormat is not \"CycloneDX\")"
    meta = doc.get("metadata")
    meta = meta if isinstance(meta, dict) else {}
    subject = meta.get("component")
    subject = subject if isinstance(subject, dict) else {}
    stamp = str(meta.get("timestamp") or "")
    # The SBOM's own timestamp says when its declarations were true of a
    # build; the file's date says only when it was copied here.
    date = stamp[:10] if _DATE.match(stamp) else (file_mtime_date(path) or "")
    bom = Bom(path=path, spec=str(doc.get("specVersion") or ""),
              subject=str(subject.get("name") or path.stem),
              subject_version=str(subject.get("version") or ""),
              subject_ref=str(subject.get("bom-ref") or ""), date=date,
              components=_walk(doc.get("components")))
    for dep in doc.get("dependencies") or []:
        if isinstance(dep, dict) and bom.subject_ref and str(dep.get("ref")) == bom.subject_ref:
            bom.direct = {str(r) for r in dep.get("dependsOn") or []}
            break
    return bom, ""


def _component_row(c: dict, cls: ComponentClass, bom: Bom, source_name: str) -> CryptoAsset:
    name = str(c.get("name") or "").strip()
    version = str(c.get("version") or "").strip()
    flags = ["sbom-declared-dependency", f"sbom-provides:{cls.key}"]
    notes = [f"The bill of materials of {bom.label}, generated "
             f"{bom.date or 'on an unstated date'}, lists {name} {version}".rstrip()
             + f", {_article(cls.label)} {cls.label} component. {CAN_DO}"]
    if str(c.get("bom-ref") or "") in bom.direct:
        flags.append("sbom-direct-dependency")
        notes.append("The application names this component itself, so its version was "
                     "chosen rather than brought in by another component.")
    if cls.key in CRYPTO_CLASSES and is_prerelease(version):
        flags.append(PRERELEASE_FLAG)
        notes.append("This version is a pre-release build of a component that handles keys, "
                     "secrets or credentials. A deliberate choice and an accident look the "
                     "same in a bill of materials, so someone needs to say which it is.")
    if cls.key == "ssh":
        flags.append(SSH_FLAG)
        notes.append("An application with its own secure-shell code can open SSH connections "
                     "itself, outside the controls that govern SSH on servers and network "
                     "devices.")
    for package, first, citation in ENCRYPTS_BY_DEFAULT:
        m = major(version)
        if name.lower() == package and m is not None and m >= first:
            flags.append("sbom-encrypts-by-default")
            notes.append(f"This library encrypts its connections by default ({citation}). A "
                         "connection string can still turn that off, and the running "
                         "configuration is not measured here.")
    return CryptoAsset(
        name=f"{name} {version}".strip(), data_state="discovery", protocol="software",
        role=roles.application_dependency(cls.label), software=name, version=version,
        source_name=source_name, collected_at=bom.date, verdict="unknown", flags=flags,
        notes=" ".join(notes),
        extra={"sbom_subject": bom.label, "provides": cls.key,
               "purl": str(c.get("purl") or ""), "spec_version": bom.spec})


def rows_for(bom: Bom) -> tuple[list[CryptoAsset], int]:
    """One SBOM's rows (its classified components, then the application); and how many classified."""
    source_name = f"CycloneDX {bom.spec} SBOM of {bom.subject}" + (
        f", generated {bom.date}" if bom.date else "")
    rows: list[CryptoAsset] = []
    for c in bom.components:
        name = str(c.get("name") or "").strip()
        cls = classify(name, str(c.get("group") or "")) if name else None
        if cls is not None:
            rows.append(_component_row(c, cls, bom, source_name))
    hashed = sum(1 for c in bom.components if c.get("hashes"))
    rows.append(CryptoAsset(
        name=f"Application {bom.label}", data_state="discovery", protocol="software",
        role=roles.application_sbom_subject(), software=bom.subject,
        version=bom.subject_version, source_name=source_name, collected_at=bom.date,
        verdict="n/a", flags=["sbom-subject"],
        notes=(f"This application has a bill of materials: {len(bom.components)} components "
               f"as at {bom.date or 'an unstated date'}, {len(rows)} of them cryptographic, "
               f"identity or transport components by this reader's classes, and {hashed} "
               f"with an integrity hash. A component list made at build time, which others "
               f"can check, is a strength in itself. {CAN_DO}"),
        # Counts are kept as text, as the bill of materials' other details are.
        extra={"components": str(len(bom.components)), "classified": str(len(rows)),
               "with_hashes": str(hashed), "direct_dependencies": str(len(bom.direct)),
               "spec_version": bom.spec}))
    return rows, len(rows) - 1


def _files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() == ".json")
    return [path]


def read(ctx: Context) -> StepResult:
    """The plug-in's step: every SBOM in the input, then the scope row and the gaps."""
    if ctx.input is None:
        return StepResult(gaps=[_none_found("no input was given")])
    rows: list[CryptoAsset] = []
    gaps: list[coverage.Gap] = []
    read_ok: list[Bom] = []
    unreadable: list[str] = []
    classified = 0
    files = _files(ctx.input)
    for path in files:
        bom, why = read_bom(path)
        if bom is None:
            unreadable.append(f"{path.name} ({why})")
            continue
        got, n = rows_for(bom)
        rows += got
        classified += n
        read_ok.append(bom)
    if unreadable:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            "bill(s) of materials that could not be read: " + "; ".join(unreadable),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("The cryptographic, identity and transport components of the "
                    "application(s) concerned are missing from this observation."),
            harvest="Export each one again as CycloneDX JSON and replace the file.",
            nature=coverage.NO_DATA))
    if not read_ok:
        if not files:
            gaps.append(_none_found(f"{ctx.input.name}/ holds no .json file"))
        return StepResult(records=rows, gaps=gaps)
    components = sum(len(b.components) for b in read_ok)
    rows.append(CryptoAsset(
        name="Application-layer SBOM scope", data_state="discovery", protocol="software",
        role=roles.application_sbom_scope(), verdict="n/a", flags=["sbom-scope"],
        notes=(f"{len(read_ok)} bill(s) of materials read ("
               + "; ".join(b.label for b in read_ok)
               + f"), listing {components} components, {classified} of them in this "
               f"reader's classes. The rest are counted here and not reported: the classes "
               f"set the limit of what this reader sees, not the applications. A bill of "
               f"materials describes only the software it was made from, so nothing here "
               f"says anything about an application without one, and each one read shows "
               f"what an application can do, not what it does."),
        extra={"sboms_read": str(len(read_ok)), "components": str(components),
               "classified": str(classified)}))
    gaps.append(coverage.gap(
        coverage.NOT_COLLECTED,
        f"bills of materials for the other applications: {len(read_ok)} application(s) "
        f"have one here, and no other application does",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Cryptographic, identity and transport components are known only for the "
                "applications whose bills of materials were read, and nothing about any "
                "other application can be inferred from them."),
        harvest=("Produce a CycloneDX bill of materials in each application's build, as "
                 "the builds of those read here already do, and add it to the input."),
        nature=coverage.NO_DATA))
    return StepResult(records=rows, gaps=gaps)


def _none_found(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED, f"no CycloneDX bill of materials was read: {why}",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("The cryptographic, identity and transport components inside applications "
                "are not in this observation; the other collectors see only "
                "infrastructure."),
        harvest=("Add a CycloneDX JSON bill of materials from each application's build to "
                 "the input."),
        nature=coverage.NO_DATA)


#: The declaration. ``date_rows`` is off: each application's rows carry their
#: SBOM's own date, and the scope row summarises what was read rather than
#: recording a reading, so it stays undated.
PLUGIN = Plugin(
    name=NAME, kind="general", step=read, input="inbox/sbom",
    title="CycloneDX software bills of materials", gap_prefix=False, date_rows=False)
