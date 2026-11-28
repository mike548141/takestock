"""The binding tables place every state and protocol takestock's own readers emit.

The first half pins each placement on invented rows. The second half enumerates
what the bundled readers and collectors can emit, from their source and from the
data tables they read, and fails when one is neither placed nor given a reason.
"""

from __future__ import annotations

import ast
import csv
import itertools
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from takestock import binding
from takestock.collectors import netdev
from takestock.model import CryptoAsset
from takestock.readers import falcon_vulnerabilities

SRC = Path(binding.__file__).parent
DATA = SRC / "data"
HW, SW, UNK = binding.HARDWARE, binding.SOFTWARE, binding.UNKNOWN


def row(**kw) -> CryptoAsset:
    base: dict[str, Any] = {"name": "svc", "data_state": "in-transit", "protocol": "tls",
            "host": "app-01.example.test", "verdict": "weak"}
    base.update(kw)
    return CryptoAsset(**base)


# ── each placement, on synthetic rows ──

@pytest.mark.parametrize("state, protocol, expected", [
    # states
    ("platform-integrity", "", HW),
    ("platform-integrity", "firmware", HW),
    ("identity", "account", SW),
    ("identity", "authentication-method", SW),
    ("identity", "mailbox-access", SW),
    # the state decides before the protocol does
    ("identity", "ssh", SW),
    ("platform-integrity", "tls", HW),
    # hardware protocols
    ("in-transit", "firmware", HW),
    ("at-rest", "vsan-encryption", HW),
    ("at-rest", "vm-encryption", HW),
    ("at-rest", "datastore", HW),
    ("at-rest", "datastore-encryption", HW),
    ("in-transit", "vm-migration", HW),
    ("at-rest", "key-management", HW),
    ("in-transit", "macsec", HW),
    ("in-transit", "wan-link", HW),
    ("key-material", "key-store", HW),
    ("at-rest", "storage-encryption", HW),
    # software protocols
    ("in-transit", "winrm", SW),
    ("at-rest", "tde", SW),
    ("at-rest", "database-encryption", SW),
    ("at-rest", "column-encryption", SW),
    ("at-rest", "database-backup-encryption", SW),
    ("at-rest", "backup-encryption", SW),
    ("at-rest", "commvault-backup", SW),
    ("in-transit", "software", SW),
    ("discovery", "software", SW),
    ("discovery", "inventory", SW),
    ("discovery", "software-lifecycle", SW),
    (None, "egress", SW),
    ("key-material", "oauth-client-credential", SW),
    ("in-transit", "dnssec", SW),
    ("at-rest", "azure-storage", SW),
    ("at-rest", "azure-disk", SW),
    ("at-rest", "azure-backup", SW),
    ("key-material", "azure-keyvault", SW),
    ("at-rest", "azure-at-rest", SW),
    ("in-transit", "kerberos", SW),
    ("in-transit", "ntlm", SW),
    ("in-transit", "netlogon", SW),
    ("in-transit", "ipsec", SW),
    ("key-material", "key-material", SW),
    ("key-material", "signing", SW),
    ("key-material", "crypto", SW),
])
def test_placement(state, protocol, expected):
    assert binding.binding_of(state or "", protocol) == expected


@pytest.mark.parametrize("state, protocol", [
    ("at-rest", "fde"), ("at-rest", "disk-encryption"), ("in-transit", "wifi"),
    ("in-transit", "tcp"), ("in-transit", "udp"),
])
def test_a_split_class_stays_unknown_and_says_why(state, protocol):
    assert binding.binding_of(state, protocol) == UNK
    assert binding.SPLIT_PROTOCOLS[protocol]
    # ...unless the row names the software it runs as, the rule every split protocol follows.
    assert binding.binding_of(state, protocol, software="Example Agent") == SW
    # ...or its role places it.
    assert binding.binding_of(state, protocol, role="Branch office VPN gateway") == HW


def test_the_split_table_never_shadows_a_placed_token():
    """A reason beside a token the tables place would never be read."""
    placed = (binding.HARDWARE_STATES | binding.SOFTWARE_STATES | binding.HARDWARE_PROTOCOLS
              | binding.SOFTWARE_PROTOCOLS)
    assert not placed & set(binding.SPLIT_PROTOCOLS)
    # a defect record the product does not name is left unknown, and says why
    assert binding.PRODUCT_DEFECT_PROTOCOLS <= set(binding.SPLIT_PROTOCOLS)
    assert not binding.HARDWARE_PROTOCOLS & binding.SOFTWARE_PROTOCOLS
    assert not binding.HARDWARE_STATES & binding.SOFTWARE_STATES


@pytest.mark.parametrize("state", ["platform-integrity", "in-transit", "key-material", "at-rest"])
def test_a_defect_record_is_software_when_it_names_its_product(state):
    assert binding.binding_of(state, "vulnerability", software="Example Product") == SW
    # the state, a role and the table all stay silent when the product is not named
    assert binding.binding_of(state, "vulnerability") == UNK
    assert binding.binding_of(state, "vulnerability", role="Example server") == UNK


def test_a_defect_record_with_no_product_is_counted_unknown_with_its_reason():
    rows = [row(data_state="platform-integrity", protocol="vulnerability", software="Example Product"),
            row(data_state="platform-integrity", protocol="vulnerability", software="")]
    out = binding.hardware_software_split(rows)
    assert (out["software"], out["unknown"]) == (1, 1)
    assert out["unplaced"] == [{"class": "vulnerability",
                                "reason": binding.SPLIT_PROTOCOLS["vulnerability"]}]


def test_a_summary_reads_right_with_no_registration():
    """The mixed population of a library's own readers, split with nothing registered."""
    rows = [
        row(data_state="platform-integrity", protocol="", host="pc-01.example.test"),
        row(data_state="at-rest", protocol="vsan-encryption"),
        row(data_state="identity", protocol="account"),
        row(data_state="key-material", protocol="oauth-client-credential"),
        row(data_state="at-rest", protocol="tde"),
        row(data_state="platform-integrity", protocol="vulnerability", software="Example Product"),
        row(data_state="at-rest", protocol="fde"),
        row(verdict="strong", data_state="at-rest", protocol="vm-encryption"),
    ]
    out = binding.hardware_software_split(rows)
    assert (out["findings"], out["hardware"], out["software"], out["unknown"]) == (7, 2, 4, 1)
    assert out["unplaced"] == [{"class": "fde", "reason": binding.SPLIT_PROTOCOLS["fde"]}]
    assert out["hardware_by_class"] == {"vsan-encryption": 1, "platform-integrity": 1}


# ── every state and protocol the bundled readers emit is placed or explained ──

#: States a reader files a row under that name nothing by themselves: the protocol
#: decides, or the row is a scope or a declaration and carries no verdict.
NEUTRAL_STATES = {"in-transit", "at-rest", "discovery", "key-material", "estate"}

#: A (state, protocol) pair whose rows describe a scope, a declaration or a name found,
#: never a control that can be graded, so there is nothing to bind.
NOT_A_CONTROL = {
    ("estate", ""): "a declared asset class, not an observation",
    ("discovery", ""): "a scope or coverage row, or a name found and not probed",
    ("in-transit", ""): "a scope row for an export",
}


def _placed(state: str, protocol: str) -> bool:
    return (binding.binding_of(state, protocol) != UNK or protocol in binding.SPLIT_PROTOCOLS)


def _literal_pairs() -> dict[tuple[str, str], set[str]]:
    """(state, protocol) literals from every keyword call in the source, with where seen.

    A conditional (``a if c else b``) gives both branches. A call that sets only a
    protocol has its state from a dictionary spread in (``**common``), so it is paired
    under each state literal its file writes, as a key or a keyword, and one placement
    among them is enough: ``states`` is then a tuple of every state that file uses.
    """
    out: dict[tuple[str, str], set[str]] = defaultdict(set)
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "binding.py":
            continue
        tree = ast.parse(path.read_text())
        consts = {n.targets[0].id: n.value.value for n in tree.body
                  if isinstance(n, ast.Assign) and len(n.targets) == 1
                  and isinstance(n.targets[0], ast.Name)
                  and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}

        def lits(node: ast.expr | None, consts=consts) -> list[str]:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return [node.value]
            if isinstance(node, ast.Name) and node.id in consts:
                return [consts[node.id]]
            if isinstance(node, ast.IfExp):
                return lits(node.body) + lits(node.orelse)
            return []

        calls = []
        states_here: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values, strict=True):
                    if isinstance(k, ast.Constant) and k.value == "data_state":
                        states_here.update(lits(v))
            if isinstance(n, ast.Call):
                kw = {k.arg: k.value for k in n.keywords if k.arg}
                if "data_state" in kw or "protocol" in kw:
                    calls.append((lits(kw.get("data_state")), lits(kw.get("protocol")), n.lineno))
                    states_here.update(lits(kw.get("data_state")))
        where = str(path.relative_to(SRC))
        for states, protocols, line in calls:
            if not states and not protocols:
                continue  # both come from variables; the data-driven tests below cover them
            for protocol in protocols or [""]:
                if states:
                    for state in states:
                        out[(state, protocol)].add(f"{where}:{line}")
                else:
                    # state arrives by spread: one placement among the file's states will do
                    out[("|".join(sorted(states_here)), protocol)].add(f"{where}:{line}")
    return out


def _placed_pair(state: str, protocol: str) -> bool:
    """Placed under the state, or under any one of several ``|``-joined states, or alone."""
    states = state.split("|") if state else [""]
    return any(_placed(s, protocol) for s in states) or _placed("", protocol)


def test_every_literal_the_source_emits_is_placed_or_explained():
    problems = []
    for (state, protocol), places in sorted(_literal_pairs().items()):
        if (state, protocol) in NOT_A_CONTROL or (protocol and _placed_pair(state, protocol)):
            continue
        if not protocol and (_placed(state, "") or state in NEUTRAL_STATES):
            continue
        problems.append(f"{state or '-'}/{protocol or '-'} at {sorted(places)[0]}")
    assert not problems, "emitted but not placed; place it in binding.py: " + "; ".join(problems)


def test_the_port_table_protocols_are_placed_or_explained():
    with (DATA / "port-encryption.csv").open(newline="") as fh:
        protocols = {r["protocol"] for r in csv.DictReader(fh)}
    gaps = sorted(p for p in protocols if not _placed("in-transit", p))
    assert not gaps, gaps


def test_the_network_device_controls_are_placed_or_explained():
    gaps = sorted(f"{state}/{protocol}" for protocol, state, _tables in netdev.CONTROLS.values()
                  if not _placed(state, protocol))
    assert not gaps, gaps


def test_the_components_a_defect_is_recorded_against_are_placed_or_explained():
    provides = {p for _pat, p in falcon_vulnerabilities.PACKAGES}
    provides |= set(falcon_vulnerabilities.COMPONENTS.values())
    with (DATA / "crypto-software.csv").open(newline="") as fh:
        provides |= {r["provides"] for r in csv.DictReader(fh)}
    gaps = []
    for p in sorted(provides):
        state = falcon_vulnerabilities.STATE_OF_PROVIDES.get(p, "key-material")
        # These rows name the product they are about, which the split rule reads.
        if binding.binding_of(state, p, software="Example Product") == UNK:
            gaps.append(f"{state}/{p}")
    assert not gaps, gaps


def _walk_pairs(node, out: set[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        states = node.get("data_state")
        protocols = node.get("protocol")
        if states is not None or protocols is not None:
            ss = [states] if isinstance(states, str) else list(states or [""])
            ps = [protocols] if isinstance(protocols, str) else list(protocols or [""])
            out.update(itertools.product(ss, ps))
        for v in node.values():
            _walk_pairs(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_pairs(v, out)


def test_the_plug_in_kinds_are_placed_or_explained():
    pairs: set[tuple[str, str]] = set()
    _walk_pairs(yaml.safe_load((DATA / "plugin-kinds.yaml").read_text()), pairs)
    assert pairs
    gaps = sorted(f"{s or '-'}/{p or '-'}" for s, p in pairs
                  if p and not _placed(s, p) and not _placed("", p))
    assert not gaps, gaps


def test_the_enumeration_notices_an_unplaced_emission(tmp_path, monkeypatch):
    """The scan is only worth having if it fails on what it is there to catch."""
    fake = tmp_path / "newreader.py"
    fake.write_text("from takestock.model import CryptoAsset\n"
                    "CryptoAsset(name='x', data_state='at-rest', protocol='brand-new-store')\n")
    monkeypatch.setattr(sys.modules[__name__], "SRC", tmp_path)
    pairs = _literal_pairs()
    assert ("at-rest", "brand-new-store") in pairs
    assert not _placed("at-rest", "brand-new-store")
