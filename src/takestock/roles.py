"""Plain-language role descriptions for assets.

Every asset carries a ``role``: one sentence saying what the thing is and why
a reader should care, written for someone who is not a cryptographer.
Collectors call the function for their kind of asset rather than writing the
sentence themselves, so the same kind of asset is always described the same
way. Each function returns "" when it has nothing to describe, and a caller
leaves the role blank rather than inventing one.
"""

from __future__ import annotations

import re

# Hostname categories, checked in order; the first match wins. Each is a set
# of whole words looked for in the host's name (the labels before the
# registered domain). These are common naming conventions, not exhaustive.
# A non-production marker is checked before the application and database
# kinds: a test copy of an application is a test system first, so
# ``demo.portal.example.test`` is non-prod, not an application.
HOST_CATEGORIES: tuple[tuple[str, frozenset[str]], ...] = (
    ("vpn", frozenset({"vpn", "remote", "ra"})),
    ("sign-in", frozenset({"auth", "sso", "login", "idp", "sts", "signin"})),
    ("devops", frozenset({"git", "scm", "ci", "build", "registry", "artifacts", "repo"})),
    ("container-platform", frozenset({"k8s", "kube", "kubernetes", "containers"})),
    ("non-prod", frozenset({"sandbox", "preprod", "staging", "stage", "test", "dev", "demo",
                            "uat", "lab", "beta", "nonprod", "qa"})),
    ("app", frozenset({"app", "apps", "portal"})),
    ("database", frozenset({"db", "sql", "database"})),
)


def _name_words(host: str) -> set[str]:
    """The words in a hostname's own labels, with and without a trailing number.

    ``app-db2.eu.example.com`` gives ``{"app", "db2", "db", "eu"}``: the last
    two labels are treated as the registered domain and ignored, so the
    domain's own name never decides the category.
    """
    labels = host.lower().strip(".").split(".")
    own = labels[:-2] if len(labels) > 2 else labels[:1]
    words = {w for w in re.split(r"[^a-z0-9]+", ".".join(own)) if w}
    return words | {w.rstrip("0123456789") for w in words} - {""}


def classify_host(host: str) -> str:
    """A coarse category for a hostname, judged from the name alone.

    Returns one of the keys of :data:`HOST_CATEGORIES`, or ``other``.
    """
    words = _name_words(host)
    for category, markers in HOST_CATEGORIES:
        if words & markers:
            return category
    return "other"


# What each category means to a reader. ``other`` has no gloss on purpose: a
# clause that says nothing is left off rather than repeated on every row.
_CATEGORY_GLOSS = {
    "vpn": "the remote-access service people connect through from outside the network",
    "sign-in": "the sign-in service people go through to reach applications",
    "devops": "a system the software teams use to build and store code",
    "container-platform": "the container platform that runs applications",
    "app": "an application people use",
    "database": "a database system",
    "non-prod": "a test or pre-production system, not the live service",
}


def _gloss(stem: str, category: str) -> str:
    meaning = _CATEGORY_GLOSS.get(category, "")
    return f"{stem} — {meaning}" if meaning else stem


def discovered_endpoint(host: str, category: str = "") -> str:
    """A name found in certificate-transparency logs but not probed."""
    if not host:
        return ""
    return _gloss("Web address found in public certificate records", category)


def certificate(host: str, category: str = "") -> str:
    """A certificate published for ``host``."""
    if not host:
        return ""
    return _gloss("Website certificate published for this address", category)


_EMAIL_ROLES = {
    "mx": "Mail routing record for {domain} — the servers that receive its email",
    "spf": "Email sender policy for {domain} — which servers are allowed to send mail "
           "using this domain name",
    "dmarc": "Email fraud policy for {domain} — what receiving servers do with mail that "
             "fails the sender checks",
    "null-mx": "Mail refusal record for {domain} — whether a domain that takes no email "
               "says so in DNS, so that mail sent to it fails at once",
    "dkim-wildcard": "Signing key record for {domain} — whether a domain that sends no email "
                     "publishes the empty key that tells receivers no mail from it is ever "
                     "signed",
    "mta-sts": "Email transport security policy for {domain} — tells other mail servers to "
               "encrypt when they deliver here",
    "caa": "Certificate issuing policy for {domain} — which certificate providers are "
           "allowed to issue certificates for it",
    "ns": "Name servers for {domain} — the DNS servers that publish its records, which "
          "is who hosts its DNS",
    "tls-rpt": "Encryption failure reporting for {domain} — where other mail servers send "
               "word when they could not deliver to it securely",
    "dane": "Mail server certificate records for {domain} — whether its own DNS names the "
            "certificate that delivering mail servers should expect, as well as relying on "
            "the certificate providers",
    "spf-senders": "Authorised sending surface for {domain} — everyone the sender policy "
                   "permits to send mail as this domain, after following every policy it "
                   "refers to",
    # Records on names beneath the domain that send no mail of their own.
    "ned-spf": "Sender policies on the sub-domains of {domain} — whether each name beneath "
               "it denies senders of its own, which the parent's own policy does not do "
               "for it",
    "ned-dkim": "Signing keys on the sub-domains of {domain} — whether each name beneath it "
                "publishes the empty key that tells receivers no mail from it is ever "
                "signed",
    "ned-dmarc": "Fraud policy records on the sub-domains of {domain} — whether each name "
                 "beneath it publishes its own sp= tag, which the standard says should "
                 "only ever appear at the organisational level",
    # Names beneath the domain that show signs of handling mail.
    "subdomain-mail": "Mail-handling sub-domains of {domain} — names beneath it that send or "
                      "receive mail, read for the sender policy and fraud policy an email "
                      "domain must publish",
}


def dns_zone_signing(domain: str) -> str:
    """DNSSEC signing for ``domain``."""
    return (f"Signed DNS for {domain} — whether the answers it publishes carry a "
            "signature that lets a resolver detect a forged or altered answer"
            if domain else "")


def email_record(protocol: str, domain: str) -> str:
    """A mail-authentication or mail-policy DNS record for ``domain``."""
    template = _EMAIL_ROLES.get(protocol, "")
    return template.format(domain=domain) if (template and domain) else ""


def spf_named_relay(host: str, named_by: list[str]) -> str:
    """A relay that an SPF record permits to send mail."""
    if not host:
        return ""
    which = ", ".join(named_by)
    for_whom = f" by {which}" if which else ""
    return (f"Mail relay {host}, permitted to send{for_whom} — measured on the port it "
            "RECEIVES on, which is not the same as how it encrypts when it sends")


def email_signing_key(domain: str, selector: str) -> str:
    """A DKIM public key published for ``domain`` under ``selector``."""
    if not domain:
        return ""
    published = f' (published as "{selector}")' if selector else ""
    return (f"Email signing key (DKIM) for {domain}{published} — proves a message really "
            "came from this domain")


def vpn_gateway(entry: dict) -> str:
    """A remote-access VPN gateway; ``entry`` may name its ``site``."""
    site = str(entry.get("site") or "").strip()
    where = f" ({site} site)" if site else ""
    return (f"Remote-access VPN gateway{where} — how people reach the internal "
            "network from outside it")


# The target-profile groups whose hosts are the organisation's own published
# TLS services.
PUBLISHED_TLS_GROUPS = ("tls_443", "mail_self")


def published_hosts(target: dict) -> list[str]:
    """Hosts listed in the target profile's published-service groups, de-duplicated."""
    st = target.get("scan_targets", {}) or {}
    out: list[str] = []
    seen: set[str] = set()
    for group in PUBLISHED_TLS_GROUPS:
        for host in st.get(group) or []:
            h = str(host or "").strip()
            if h and h not in seen:
                seen.add(h)
                out.append(h)
    return out


def public_endpoint(host: str) -> str:
    """An internet-facing service the organisation publishes."""
    if not host:
        return ""
    return _gloss("Public internet-facing service", classify_host(host))


def vendor_endpoint(entry: dict) -> str:
    """A service an outside provider operates, from a target-profile entry.

    ``entry`` may carry ``vendor``, ``service`` and ``carries`` (what
    information rides it).
    """
    host = str(entry.get("host") or "").strip()
    if not host:
        return ""
    vendor = str(entry.get("vendor") or "").strip()
    service = str(entry.get("service") or "").strip()
    carries = str(entry.get("carries") or "").strip()
    what = service or "Third-party service"
    by = f", operated by {vendor}" if vendor else ""
    for_what = f" — carries {carries}" if carries else ""
    return (f"{what}{by}{for_what}. Vendor-operated: a weak floor here is a "
            f"procurement requirement, not a setting the organisation can change")


def ssh_service(host: str) -> str:
    """An SSH listener."""
    if not host:
        return ""
    return ("Remote administration access — the encrypted channel "
            "administrators log in through")


def remote_desktop_service(host: str) -> str:
    """A remote desktop (RDP) listener."""
    if not host:
        return ""
    return ("Remote desktop access — the screen-sharing login people use to "
            "work on this computer from elsewhere, and whether it asks who they "
            "are before showing a login screen")


def scan_target_roles(target: dict) -> dict[str, str]:
    """Roles for every host or address the target profile declares, keyed by it."""
    st = target.get("scan_targets", {}) or {}
    out: dict[str, str] = {}
    for gw in st.get("vpn_gateways", []) or []:
        if not isinstance(gw, dict):
            continue
        key = gw.get("ip") or gw.get("host")
        if key:
            out[str(key)] = vpn_gateway(gw)
    for host in published_hosts(target):
        out[host] = public_endpoint(host)
    for entry in st.get("saas_443", []) or []:
        if isinstance(entry, dict) and entry.get("host"):
            out[str(entry["host"])] = vendor_endpoint(entry)
    for entry in st.get("smtp_25", []) or []:
        if isinstance(entry, dict) and entry.get("host"):
            out[str(entry["host"])] = vendor_endpoint(entry)
    for entry in st.get("ssh_22", []) or []:
        key = (entry.get("ip") or entry.get("host")) if isinstance(entry, dict) else entry
        if key:
            out[str(key)] = ssh_service(str(key))
    for entry in st.get("smb_445", []) or []:
        key = (entry.get("ip") or entry.get("host")) if isinstance(entry, dict) else entry
        if key:
            out[str(key)] = file_sharing_service(str(key))
    return out


def listening_service(product: str, host: str, machine_kind: str = "") -> str:
    """A service seen listening on a host."""
    if not (product and host):
        return ""
    return f"{product} running on a {machine_kind}" if machine_kind else product


def file_sharing_service(host: str) -> str:
    """An SMB file-sharing listener."""
    if not host:
        return ""
    return ("File-sharing service (Server Message Block, SMB) — how computers "
            "reach shared folders, and how directory servers hand out logon "
            "policy")


def application_dependency(kind: str) -> str:
    """A component an application declares in its software bill of materials."""
    return (f"A {kind} component the application declares it is built with — "
            f"a capability of the application, not a measurement of it running")


def application_sbom_subject() -> str:
    """The application whose software bill of materials was read."""
    return ("The application whose declared software bill of materials was "
            "read — the one layer no infrastructure scanner can see")


def application_sbom_scope() -> str:
    """The scope row for an application bill-of-materials ingest."""
    return ("What the application-layer ingest covers — the declared dependency "
            "lists of the applications read, not every application in the estate "
            "and not any running service")


def dns_zone_scope(zones: int) -> str:
    """The scope row for a set of DNS zone files."""
    return (f"Every record configured in the organisation's {zones} DNS zone(s) — what "
            f"the zone files show, when they were taken, and what they cannot show")


def dns_zone_dangling_record(owner: str, target: str) -> str:
    """A published DNS record pointing at a name that does not exist."""
    if not owner:
        return ""
    return (f"A published DNS record at {owner} that points to {target}, a name "
            f"which does not exist")


def dns_zone_not_delegated(zone: str) -> str:
    """A held DNS zone its parent does not delegate to."""
    if not zone:
        return ""
    return (f"A DNS zone held for {zone} whose records nobody is sent to, "
            f"because the parent zone does not point to it")


def dns_zone_unmeasured_names(names: int) -> str:
    """Published DNS names no other instrument measured."""
    return (f"Names published in DNS that no other instrument here measured — "
            f"{names} name(s)")


def dns_zone_services(services: int) -> str:
    """Outside services the organisation's DNS records name."""
    return (f"Outside services the organisation's DNS records name — {services} — through "
            f"ownership proofs and pointers to their hosts")
