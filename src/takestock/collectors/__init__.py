"""Collectors: each gathers one kind of evidence and returns CryptoAsset rows.

A collector module exposes ``collect(target, ...)``, which reads what the
target profile names and returns its rows together with a list of failures
or coverage gaps. Collectors are grouped below by how they gather evidence.
"""

# ── Passive: public DNS, mail authentication and certificate transparency ──
PASSIVE_DNS = ("ct_dns", "spf_senders", "dnssec", "dane", "caa", "dns_zones")
