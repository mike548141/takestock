"""Post-quantum positions: what a software provider has published, where, and when it was read.

A *position* is one provider's published stance on post-quantum cryptography,
in one of four states (:data:`STATES`), with where it was published, when, and
when somebody read it. A reader that lists the outside parties an organisation
depends on can put the position beside each one.

Positions come from up to two files, read by :func:`load`:

* an optional bundled ``pqc-positions.yaml`` (through
  :func:`takestock.config.data_file`, so a named workspace's ``data/`` copy is
  preferred). takestock ships none yet; the loader reads one when it exists;
* the profile's own ``<stem>.pqc-positions.yaml`` beside the target profile,
  whose entries are merged over the bundled ones: an entry with the same
  ``key`` replaces the bundled entry whole, and any other is added.

Every entry carries its provenance, and the loader holds it to that:

* ``source`` (a URL) and ``read`` (the date it was read) are required. An
  entry without either is refused, because a position nobody can trace
  should never be printed beside a provider's name;
* ``publisher`` and ``published`` say who published the material and the
  date it carries, when it carries one;
* ``recheck_by`` is the date by which the entry is worth reading again. When
  an entry gives none, it falls due a fixed number of days after ``read``
  (:data:`DEFAULT_RECHECK_DAYS`, or the file's ``recheck_after_days``).

An entry past its re-check date is still used, and it is reported: it is
listed in :attr:`Positions.stale`, its payload says ``stale: true``, and its
cited sentence ends by saying it is due for re-checking. A caller turns
:attr:`Positions.stale` into a gap, so a position that may have moved on is
never shown as current without a word.

A provider with no entry is **not researched**, which is a different answer
from ``silent``. ``silent`` means somebody read the provider's material and
found it says nothing on the question; no entry means nobody has looked.
:meth:`Positions.match` returns None for the second, and a caller shows it as
nothing recorded.

A position is matched to a supplier's name by leading words
(:meth:`Positions.match`): the provider's identifying words, legal forms such
as ``Ltd`` set aside (:func:`takestock.dnsnames.vendor_words`), must be the
first words of the supplier's name, whole and in order. The two ways a match
can go wrong are not equal. Missing a supplier written as a longer phrase
(``Hosting by Example Cloud``) leaves it shown as not researched, which is
true of what the file can tell. Matching too eagerly would attribute a stance
to a company that never took it, so the rule is kept narrow and accepts the
misses. Product names are not matched; a provider known by another name lists
it under ``aliases``.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import config
from .dnsnames import split_words, vendor_words

#: The four states a position may have, from most to least settled.
STATES = ("shipped", "partial", "planned", "silent")

#: The bundled file's name under the package's (or a named workspace's) ``data/``.
BUNDLED_FILE = "pqc-positions.yaml"
#: The suffix of the profile's own positions file beside the profile.
OVERLAY_SUFFIX = config.PQC_POSITIONS_SUFFIX
#: The key holding the list of entries.
POSITIONS_KEY = "positions"
#: The one schema version this module reads.
SCHEMA = 1
#: Days after ``read`` that an entry without ``recheck_by`` falls due for re-checking.
DEFAULT_RECHECK_DAYS = 180

#: The top-level keys a positions file may hold.
FILE_KEYS = ("schema", POSITIONS_KEY, "recheck_after_days")
#: The fields an entry may hold.
ENTRY_FIELDS = ("key", "provider", "state", "since", "summary", "detail", "source",
                "publisher", "published", "read", "recheck_by", "dimensions",
                "products", "aliases")
_TEXT_FIELDS = ("key", "provider", "state", "since", "summary", "detail", "source",
                "publisher", "dimensions")
_LIST_FIELDS = ("products", "aliases")


@dataclass(frozen=True)
class Position:
    """One provider's published post-quantum position, with its provenance.

    ``recheck_by`` is the date in effect: the entry's own, or the one its file's
    rule gives (``recheck_stated`` says which). ``stale`` is whether that date
    had passed on the day the file was loaded. ``client_side`` is True when the
    entry came from the profile's own file rather than the bundled one.
    """

    key: str
    provider: str
    state: str
    source: str
    read: _dt.date
    recheck_by: _dt.date
    recheck_stated: bool = False
    stale: bool = False
    summary: str = ""
    since: str = ""
    detail: str = ""
    publisher: str = ""
    published: _dt.date | None = None
    dimensions: str = ""
    products: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    client_side: bool = False
    file: str = ""

    @property
    def names(self) -> tuple[str, ...]:
        """The provider's name and every alias, the names it is matched by."""
        return (self.provider, *self.aliases)

    def line(self) -> str:
        """The position as one cited sentence, with no closing full stop.

        In order: the state and the release that carries it, what was
        published, where and when it was published and read, which
        cryptographic functions the reading covers (``dimensions``), and, for
        a stale entry, that it is due for re-checking. The scope and the
        re-check notice are never left out: a ``shipped`` read for key exchange
        is no answer about signatures, and an old reading may no longer hold.
        The caller adds the closing stop, since the sentence is usually part
        of a longer one.
        """
        head = f"{self.state} ({self.since})" if self.since else self.state
        parts = [head, self.summary, self._citation()]
        if self.dimensions:
            parts.append(f"Scope of this reading: {self.dimensions}")
        if self.stale:
            parts.append(f"Due for re-checking since {self.recheck_by.isoformat()}: "
                         f"the provider's position may have changed since it was read")
        return ". ".join(p.strip().rstrip(".") for p in parts if p.strip())

    def _citation(self) -> str:
        # `silent` records an absence, so this names what was examined (the
        # provider's pages at `source`) and says nothing was published there.
        if self.state == "silent":
            text = (f"Established from material published by {self.publisher}" if self.publisher
                    else "Established from the provider's own material")
            if self.published:
                text += f" dated {self.published.isoformat()}"
        else:
            text = f"Published by {self.publisher or 'the provider'}"
            if self.published:
                text += f" on {self.published.isoformat()}"
        text += f", read {self.read.isoformat()}"
        return f"{text} — {self.source}"

    def payload(self) -> dict:
        """The position as plain data for a row's payload, dates as ISO text.

        Every field except ``aliases``, ``recheck_stated`` and ``file``, which
        say how the entry was matched and loaded rather than what it records.
        ``recheck_by`` is the date in effect, whether stated or set by the rule.
        """
        return {
            "key": self.key, "provider": self.provider, "state": self.state,
            "summary": self.summary, "since": self.since, "detail": self.detail,
            "source": self.source, "publisher": self.publisher,
            "published": self.published.isoformat() if self.published else "",
            "read": self.read.isoformat(), "recheck_by": self.recheck_by.isoformat(),
            "stale": self.stale, "dimensions": self.dimensions,
            "products": list(self.products), "client_side": self.client_side,
        }


@dataclass(frozen=True)
class StalePosition:
    """An entry past its re-check date on the day it was loaded."""

    key: str
    provider: str
    file: str
    read: _dt.date
    recheck_by: _dt.date
    #: True when the entry gave its own ``recheck_by``; False when the file's rule set it.
    recheck_stated: bool

    @property
    def message(self) -> str:
        """One sentence a caller can put in a gap."""
        basis = "its stated re-check date" if self.recheck_stated else "the file's re-check rule"
        return (f"The post-quantum position recorded for {self.provider} was read "
                f"{self.read.isoformat()} and fell due for re-checking on "
                f"{self.recheck_by.isoformat()} ({basis}, {self.file}); it is still shown, "
                f"but the provider may have published something since")


@dataclass(frozen=True)
class Positions:
    """Every recorded position, the files they came from, and those past re-checking."""

    entries: tuple[Position, ...] = ()
    #: The files actually read, in the order they were read.
    sources: tuple[str, ...] = ()
    #: Every entry past its re-check date, in entry order. Never silently empty:
    #: a caller that shows positions should surface each of these as a gap.
    stale: tuple[StalePosition, ...] = ()

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[Position]:
        return iter(self.entries)

    def match(self, supplier: str) -> Position | None:
        """The position for ``supplier``, or None when none is recorded (*not researched*).

        A provider (or alias) matches when its identifying words are the first
        words of ``supplier``, compared whole and case ignored. Where several
        match, the one with the most words wins; on a tie an entry from the
        profile's own file beats a bundled one, and otherwise the earlier
        entry wins.
        """
        words = split_words(str(supplier).lower())
        if not words:
            return None
        best: Position | None = None
        best_rank = (-1, False)
        for entry in self.entries:
            for name in entry.names:
                want = [w for w in vendor_words(name) if w]
                if not want or words[:len(want)] != want:
                    continue
                rank = (len(want), entry.client_side)
                if rank > best_rank:
                    best, best_rank = entry, rank
        return best

    def by_state(self) -> dict[str, list[Position]]:
        """The entries grouped by state, in entry order within each."""
        out: dict[str, list[Position]] = {}
        for entry in self.entries:
            out.setdefault(entry.state, []).append(entry)
        return out


def overlay_path(target: Mapping | None) -> Path | None:
    """The profile's own ``<stem>.pqc-positions.yaml`` beside a loaded target, or None."""
    if not target:
        return None
    tpath = target.get("_path")
    if not tpath:
        return None
    p = Path(str(tpath))
    if not p.suffix:
        return None
    cand = p.with_name(p.name[: -len(p.suffix)] + OVERLAY_SUFFIX)
    return cand if cand.exists() else None


def _date(value: object, where: str, name: str) -> _dt.date | None:
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        raise ValueError(f"{where}: `{name}` must be a date (YYYY-MM-DD), not a date and time")
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value).strip())
    except ValueError:
        raise ValueError(f"{where}: `{name}` must be a date (YYYY-MM-DD), not {value!r}") from None


def read_file(path: Path, *, client_side: bool, today: _dt.date,
              recheck_after_days: int = DEFAULT_RECHECK_DAYS) -> list[Position]:
    """The entries of one positions file, checked; raises :class:`ValueError` on any fault.

    Refused: a file that is not a mapping, an unknown top-level key, a schema
    other than :data:`SCHEMA`, an entry with an unknown field, no ``provider``,
    a state outside :data:`STATES`, no ``source`` or no ``read``, a date that
    is not ``YYYY-MM-DD``, a ``read`` later than ``today``, a ``published``
    later than ``read``, a ``recheck_by`` earlier than ``read``, and a ``key``
    given twice. ``recheck_after_days`` is the rule for entries with no
    ``recheck_by``; the file's own ``recheck_after_days`` replaces it.
    """
    try:
        doc = config.load_yaml_strict(path)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: not readable as YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: must be a mapping with a `{POSITIONS_KEY}:` list")
    other = sorted(str(k) for k in doc if k not in FILE_KEYS)
    if other:
        raise ValueError(f"{path}: unexpected top-level key(s) {', '.join(other)}; "
                         f"the keys are {', '.join(FILE_KEYS)}")
    if doc.get("schema", SCHEMA) != SCHEMA:
        raise ValueError(f"{path}: schema {doc.get('schema')!r} is not one this version "
                         f"reads ({SCHEMA})")
    rule = doc.get("recheck_after_days", recheck_after_days)
    if isinstance(rule, bool) or not isinstance(rule, int) or rule < 1:
        raise ValueError(f"{path}: `recheck_after_days` must be a whole number of days, "
                         f"1 or more, not {rule!r}")
    raw = doc.get(POSITIONS_KEY) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: `{POSITIONS_KEY}:` must be a list, not {type(raw).__name__}")
    out: list[Position] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        where = f"{path}: entry {i + 1}"
        if not isinstance(entry, Mapping):
            raise ValueError(f"{where} is not a mapping")
        unknown = sorted(str(k) for k in entry if k not in ENTRY_FIELDS)
        if unknown:
            raise ValueError(f"{where}: unknown field(s) {', '.join(unknown)}; "
                             f"the fields are {', '.join(ENTRY_FIELDS)}")
        for name in _TEXT_FIELDS:
            v = entry.get(name)
            if v is not None and not isinstance(v, str):
                raise ValueError(f"{where}: `{name}` must be text, not {type(v).__name__}")
        text = {name: str(entry.get(name) or "").strip() for name in _TEXT_FIELDS}
        if not text["provider"]:
            raise ValueError(f"{where} has no `provider:`")
        where = f"{path}: {text['provider']}"
        lists: dict[str, tuple[str, ...]] = {}
        for name in _LIST_FIELDS:
            v = entry.get(name) or []
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError(f"{where}: `{name}` must be a list of text")
            lists[name] = tuple(x.strip() for x in v if x.strip())
        if text["state"] not in STATES:
            raise ValueError(f"{where}: state {text['state']!r} is not one of "
                             f"{', '.join(STATES)}")
        if not text["source"]:
            raise ValueError(f"{where} has no `source:`; every position names where it "
                             f"was read")
        read = _date(entry.get("read"), where, "read")
        if read is None:
            raise ValueError(f"{where} has no `read:` date; every position says when it "
                             f"was read")
        if read > today:
            raise ValueError(f"{where}: `read` {read.isoformat()} is later than today "
                             f"({today.isoformat()})")
        published = _date(entry.get("published"), where, "published")
        if published is not None and published > read:
            raise ValueError(f"{where}: `published` {published.isoformat()} is later than "
                             f"`read` {read.isoformat()}")
        stated = _date(entry.get("recheck_by"), where, "recheck_by")
        if stated is not None and stated < read:
            raise ValueError(f"{where}: `recheck_by` {stated.isoformat()} is earlier than "
                             f"`read` {read.isoformat()}")
        due = stated if stated is not None else read + _dt.timedelta(days=rule)
        key = text["key"] or text["provider"]
        if key in seen:
            raise ValueError(f"{path}: key {key!r} is given twice")
        seen.add(key)
        out.append(Position(
            key=key, provider=text["provider"], state=text["state"], source=text["source"],
            read=read, recheck_by=due, recheck_stated=stated is not None,
            stale=today > due, summary=text["summary"], since=text["since"],
            detail=text["detail"], publisher=text["publisher"], published=published,
            dimensions=text["dimensions"], products=lists["products"],
            aliases=lists["aliases"], client_side=client_side, file=str(path)))
    return out


def load(target: Mapping | None = None, *, today: _dt.date | None = None,
         recheck_after_days: int = DEFAULT_RECHECK_DAYS) -> Positions:
    """Every recorded position: the bundled file, then the profile's own merged over it.

    Neither file need exist; with neither, the result is empty and every
    supplier is *not researched*. ``today`` (default: the local date) decides
    which entries are stale. Raises :class:`ValueError` when a file is
    malformed (:func:`read_file`).
    """
    day = today or _dt.date.today()
    merged: dict[str, Position] = {}
    sources: list[str] = []
    bundled = config.data_file(BUNDLED_FILE)
    if bundled.exists():
        for p in read_file(bundled, client_side=False, today=day,
                           recheck_after_days=recheck_after_days):
            merged[p.key] = p
        sources.append(str(bundled))
    own = overlay_path(target)
    if own is not None:
        for p in read_file(own, client_side=True, today=day,
                           recheck_after_days=recheck_after_days):
            merged.pop(p.key, None)
            merged[p.key] = p
        sources.append(str(own))
    entries = tuple(merged.values())
    stale = tuple(StalePosition(key=p.key, provider=p.provider, file=p.file, read=p.read,
                                recheck_by=p.recheck_by, recheck_stated=p.recheck_stated)
                  for p in entries if p.stale)
    return Positions(entries=entries, sources=tuple(sources), stale=stale)


def resolve(positions: Positions | None, supplier: str, declared: str = "") -> tuple[str, dict]:
    """The post-quantum text and payload to show for one supplier.

    ``declared`` is what the target profile itself records for the supplier
    (its ``pq_roadmap``), and it wins: the organisation's own record of its
    arrangement is never replaced by a published position, so the payload is
    then empty. Otherwise the matched position's sentence (:meth:`Position.line`)
    and payload. ``("", {})`` when there is neither, which a caller shows as
    not researched.
    """
    own = str(declared or "").strip()
    if own:
        return own, {}
    hit = positions.match(supplier) if positions is not None else None
    if hit is None:
        return "", {}
    return hit.line(), hit.payload()

