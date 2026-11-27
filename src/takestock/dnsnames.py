"""DNS names: tidying them, telling public from private, and naming who is behind them.

The pieces shared by the collectors and readers that work from names: names a
zone publishes, or names an organisation's machines asked a resolver for.
Nothing here reads a file. The vendor table comes from
:func:`takestock.config.load_vendor_domains` and the declarations from the
target profile, so a caller can hand in its own of either.

* :func:`normalise` and :func:`is_public` decide whether a name could belong
  to anybody outside the organisation, and :func:`non_public_suffixes` adds a
  profile's own internal endings to the built-in ones;
* :func:`suffix_lookup` attributes a name by the longest of its suffixes a
  table lists, so a table key may be a registered domain or any name under it;
* :func:`registrable` groups a name no table attributes under a best guess at
  its registered domain;
* :func:`declared_vendors` reads every supplier the target profile declares,
  with the domains each is declared with;
* :func:`declared_matches` says which of those declarations a vendor name
  accounts for, by whole words (:func:`vendor_words`, :func:`split_words`);
* :func:`slug` turns a vendor name into the lower-case, hyphenated form used
  in flags.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from itertools import groupby
from typing import TypedDict

#: Name endings treated as never belonging to an outside party, each with a
#: public basis:
#:
#: * ``.test``, ``.example`` and ``.invalid``: reserved from the public DNS
#:   (RFC 2606, RFC 6761);
#: * ``.local``: link-local multicast DNS (RFC 6762);
#: * ``.onion``: Tor onion services, never resolved by the DNS (RFC 7686);
#: * ``.arpa``: the infrastructure zones, reverse lookups among them
#:   (RFC 3172);
#: * ``.internal``: set aside by ICANN for private use, never to be delegated;
#: * ``.lan``, ``.home``, ``.corp`` and ``.localdomain``: endings widely used
#:   by default for names inside a private network (routers, operating
#:   system installers, directory set-up guides). None is a delegated
#:   top-level domain, and ICANN has deferred ``.home`` and ``.corp``
#:   indefinitely because so many private names already end in them.
#:
#: A profile adds its own internal endings through :func:`non_public_suffixes`.
NON_PUBLIC_SUFFIXES = (
    ".local", ".internal", ".arpa", ".lan", ".home", ".corp",
    ".localdomain", ".invalid", ".test", ".example", ".onion")

# Second-level labels that, directly under a two-letter country code, form part
# of a public suffix (``co`` or ``com`` before the country code), so the
# registered domain is the label to their left. Taken from the ICANN section
# of the Public Suffix List: the commercial, network, organisation, academic,
# government, education and military forms it lists under many country codes,
# and the national spellings of "government" (``govt``, ``gob``, ``gouv``),
# each listed under only one or a few country codes but never ordinary words.
# ``go``, ``or`` and ``ne`` are left out because they are ordinary words,
# registered as names under other country codes, where a match would shorten a
# real registered domain. The match is
# by label, not by country code, so it is a best guess, not the list itself. A
# profile may add its own.
SECOND_LEVEL_LABELS = frozenset({
    "co", "com", "net", "org", "ac",
    "gov", "govt", "gob", "gouv", "edu", "mil",
})

#: Words in a company's name that say what kind of company it is rather than
#: which one: legal forms, and the generic nouns many names end with. They are
#: left out when a vendor name is compared with a declaration.
CORPORATE_WORDS = frozenset({
    "inc", "ltd", "corp", "corporation", "co", "llc", "gmbh", "limited",
    "technologies", "technology", "systems", "networks", "the", "and", "&",
})

#: The profile keys holding named declarations, and the kind each entry is.
_NAMED_KEYS = (("third_party", "third-party"), ("infrastructure", "infrastructure"))
#: The ``scan_targets`` lists whose entries name their supplier as ``vendor``.
_SCAN_KEYS = ("saas_443", "smtp_25")
#: The kind given to a supplier declared by a scan target.
SCAN_TARGET_KIND = "scan-target"


class DeclaredVendor(TypedDict):
    """One supplier the target profile declares, merged across every place it is named."""

    name: str
    #: ``third-party``, ``infrastructure`` or ``scan-target``: where it was first declared.
    kind: str
    #: What the declaration says it is used for (its ``uses``, or else ``crypto``, list).
    uses: list[str]
    #: The declaration's own ``pq_roadmap`` text, or "".
    pq_roadmap: str
    #: Every domain declared for it, normalised, in declaration order.
    domains: list[str]


def normalise(raw: object) -> str:
    """``raw`` as a DNS name for comparison: trimmed, lower-cased, no trailing dot."""
    return str(raw or "").strip().lower().rstrip(".")


def non_public_suffixes(extra: Iterable[object] = ()) -> tuple[str, ...]:
    """:data:`NON_PUBLIC_SUFFIXES` plus ``extra`` (a profile's own internal endings).

    Each extra ending is trimmed, lower-cased, given a leading dot and stripped
    of a trailing one, so ``Corp.Example.`` and ``.corp.example`` are the same
    ending. Empty entries and repeats are dropped; the order is kept.
    """
    out = list(NON_PUBLIC_SUFFIXES)
    for raw in extra:
        ending = normalise(raw).lstrip(".")
        if ending and f".{ending}" not in out:
            out.append(f".{ending}")
    return tuple(out)


def is_public(name: str, non_public: Iterable[str] = NON_PUBLIC_SUFFIXES) -> bool:
    """Whether a normalised name could belong to somebody outside the organisation.

    False for an empty name, a single label, and a name ending in one of
    ``non_public`` (:func:`non_public_suffixes` builds a list with a
    profile's own endings added).
    """
    if not name or "." not in name:
        return False
    return not name.endswith(tuple(non_public))


def suffix_lookup(name: str, table: Mapping[str, object]) -> object | None:
    """The value for ``name`` or its nearest listed parent in ``table``.

    The longest suffix with a non-empty value wins, and the top-level label
    alone is never looked up.
    """
    parts = name.split(".")
    for i in range(len(parts) - 1):
        value = table.get(".".join(parts[i:]))
        if value:
            return value
    return None


def second_level_labels(extra: Iterable[object] = ()) -> frozenset[str]:
    """:data:`SECOND_LEVEL_LABELS` plus ``extra`` (a profile's ``second_level_labels``)."""
    return SECOND_LEVEL_LABELS | {str(x) for x in extra}


def registrable(name: str, second_level: Iterable[str] = SECOND_LEVEL_LABELS) -> str:
    """A best guess at the registered domain: the last two labels, or three under a public suffix."""
    parts = name.split(".")
    tail = 3 if (len(parts) >= 3 and parts[-2] in set(second_level)
                 and len(parts[-1]) == 2) else 2
    return ".".join(parts[-tail:])


def declared_vendors(target: Mapping) -> tuple[dict[str, DeclaredVendor], dict[str, str]]:
    """Every supplier the profile declares, and which declared supplier each domain belongs to.

    Read from four places: ``third_party`` and ``infrastructure`` entries (by
    ``name``) and ``scan_targets.saas_443`` and ``smtp_25`` entries (by
    ``vendor``), in that order. A supplier named in more than one place is one
    entry: its kind is where it was first named, its domains are every
    place's together, and a later non-empty ``uses`` (or ``crypto``) list or
    ``pq_roadmap`` replaces an earlier one. A domain declared for two
    suppliers belongs to the later.

    Returns ``(entries by declared name, {domain: declared name})``.
    """
    entries: dict[str, DeclaredVendor] = {}
    domains: dict[str, str] = {}

    def add(raw_name: object, entry: Mapping, kind: str) -> None:
        name = str(raw_name or "").strip()
        if not name:
            return
        rec = entries.setdefault(name, DeclaredVendor(
            name=name, kind=kind, uses=[], pq_roadmap="", domains=[]))
        uses = [str(u) for u in (entry.get("uses") or entry.get("crypto") or [])]
        rec["uses"] = uses or rec["uses"]
        rec["pq_roadmap"] = str(entry.get("pq_roadmap") or "") or rec["pq_roadmap"]
        for d in entry.get("domains") or []:
            dom = normalise(d)
            if dom:
                rec["domains"].append(dom)
                domains[dom] = name

    for key, kind in _NAMED_KEYS:
        for e in target.get(key) or []:
            if isinstance(e, Mapping):
                add(e.get("name"), e, kind)
    scan = target.get("scan_targets") or {}
    if isinstance(scan, Mapping):
        for key in _SCAN_KEYS:
            for e in scan.get(key) or []:
                if isinstance(e, Mapping):
                    add(e.get("vendor"), e, SCAN_TARGET_KIND)
    return entries, domains


def declared_vendor_domains(target: Mapping) -> dict[str, str]:
    """The domains the profile declares for its suppliers: {domain: declared name}."""
    return declared_vendors(target)[1]


def split_words(text: str) -> list[str]:
    """The runs of letters and digits in ``text``; every other character separates words."""
    return ["".join(run) for is_word, run in groupby(text, str.isalnum) if is_word]


def slug(text: object) -> str:
    """``text`` as lower-case words joined by hyphens, or ``unnamed`` when it has none."""
    return "-".join(split_words(str(text).lower())) or "unnamed"


def vendor_words(vendor: object, ignore: Iterable[str] = CORPORATE_WORDS) -> list[str]:
    """The words of a vendor name that identify it, lower-cased.

    The name is split on white space, each piece trimmed of surrounding
    spaces, commas, full stops and brackets, and the words in ``ignore``
    dropped. A name made only of such words is kept whole, lower-cased. A
    word keeps any punctuation inside it (an apostrophe or a hyphen), so
    under :func:`declared_matches` it equals no declared word.
    """
    drop = set(ignore)
    words = [w.strip(" ,.()").lower() for w in str(vendor).split()]
    return [w for w in words if w and w not in drop] or [str(vendor).lower()]


def declared_matches(vendor: object, declared: Iterable[str],
                     ignore: Iterable[str] = CORPORATE_WORDS) -> list[str]:
    """Every declared name ``vendor`` accounts for, in the order given.

    A declared name counts when each of the vendor's identifying words
    (:func:`vendor_words`) is a whole word of it (:func:`split_words`, case
    ignored). Whole words, not substrings, so a vendor is never taken for a
    declared supplier whose name merely contains one of its words: ``Tera
    Labs`` does not match ``Terabyte Cloud``, and ``Blue Finch`` does not
    match ``Blue Harbour Hosting``. ``declared`` may be the entries mapping
    :func:`declared_vendors` returns.
    """
    words = [w for w in vendor_words(vendor, ignore) if w]
    if not words:
        return []
    return [name for name in declared
            if all(w in set(split_words(name.lower())) for w in words)]


def declared_match(vendor: object, declared: Iterable[str],
                   ignore: Iterable[str] = CORPORATE_WORDS) -> str:
    """The first declared name ``vendor`` accounts for (:func:`declared_matches`), or ""."""
    matches = declared_matches(vendor, declared, ignore)
    return matches[0] if matches else ""
