"""Standards checks: one registry, one command, ``takestock comply <standard>``.

Each standard takestock can read an observation against registers a
:class:`Standard` here: its id, a one-line title, the bundled requirement data
it reads, and three functions. ``evaluate`` reads one observation and one
target profile and returns that standard's own result object; ``text`` and
``html`` render that result; ``unmet`` says whether it holds an unmet *must*
requirement, which is what makes the command exit 1.

A new standard is added by calling :func:`register` with its :class:`Standard`;
the command line, ``takestock comply --list`` and the exit codes follow from
the registry, so no new command is needed. Registering imports nothing heavy:
each function imports its standard's modules when it is called.

The first standard, ``sge``, wraps :mod:`takestock.sge` (the grading) and
:mod:`takestock.sge_note` (the HTML note) without changing either.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config


class NothingToRead(ValueError):
    """The target profile names nothing this standard applies to.

    A :class:`ValueError`, so the command reports it as an input error and
    exits 2 (see :mod:`takestock.exits`).
    """


@dataclass(frozen=True)
class Standard:
    """One standard an observation can be read against.

    * ``id``: what follows ``takestock comply``, lower case, e.g. ``sge``.
    * ``title``: one line, shown by ``takestock comply --list``.
    * ``data``: the bundled requirement data file it reads, under ``data/``.
    * ``html_name``: the HTML file written inside the observation directory
      when ``--out`` is not given.
    * ``evaluate(observation_dir, target)``: read the observation against the
      standard and return the result. Raise :class:`NothingToRead` when the
      profile names nothing the standard applies to.
    * ``text(result, observation_dir, target)``: the result as plain text.
    * ``html(result, observation_dir, target)``: the result as a complete
      HTML page.
    * ``unmet(result)``: true when a requirement stated as *must* is not met.
    """

    id: str
    title: str
    data: str
    html_name: str
    evaluate: Callable[[Path, dict], Any]
    text: Callable[[Any, Path, dict], str]
    html: Callable[[Any, Path, dict], str]
    unmet: Callable[[Any], bool]


REGISTRY: dict[str, Standard] = {}


def register(standard: Standard, *, replace: bool = False) -> Standard:
    """Add ``standard`` to the registry and return it.

    Registering an id twice is refused unless ``replace`` is true, so two
    modules cannot claim the same id by accident.
    """
    if not standard.id or standard.id != standard.id.strip().lower():
        raise ValueError(f"a standard's id must be non-empty lower case: {standard.id!r}")
    if standard.id in REGISTRY and not replace:
        raise ValueError(f"standard {standard.id!r} is already registered")
    REGISTRY[standard.id] = standard
    return standard


def get(standard_id: str) -> Standard:
    """The registered standard ``standard_id``; a :class:`ValueError` naming the known ids if none."""
    try:
        return REGISTRY[standard_id]
    except KeyError:
        known = ", ".join(sorted(REGISTRY)) or "none"
        raise ValueError(f"unknown standard {standard_id!r}; known standards: {known}") from None


def listing() -> str:
    """One line per registered standard: its id and title."""
    width = max((len(key) for key in REGISTRY), default=0)
    return "\n".join(f"{key:<{width}}  {std.title}" for key, std in sorted(REGISTRY.items()))


def load_assets(observation_dir: Path) -> list[Any]:
    """The rows of ``<observation_dir>/assets.json``; a :class:`ValueError` if it is not a list."""
    path = Path(observation_dir) / "assets.json"
    assets = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(assets, list):
        raise ValueError(f"{path}: expected a list of asset rows")
    return assets


# --- Secure Government Email ------------------------------------------------------------


def _sge_domains(target: dict) -> list[str]:
    return [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]


def _sge_evaluate(observation_dir: Path, target: dict) -> Any:
    from . import sge
    domains = _sge_domains(target)
    if not domains and not sge.parked_domains(target):
        raise NothingToRead("the target profile names no `discovery.email_domains` and no "
                            "parked domain, so there is nothing to read against the framework")
    return sge.evaluate(load_assets(observation_dir), domains,
                        bulk_mail_domains=sge.bulk_mail_domains(target),
                        parked=sge.parked_domains(target))


def _sge_text(report: Any, observation_dir: Path, target: dict) -> str:
    from . import sge
    # The same text ``python -m takestock.sge`` prints.
    return sge._format(report, _sge_domains(target))


def _sge_html(report: Any, observation_dir: Path, target: dict) -> str:
    from . import htmlpage, sge_note
    theme = htmlpage.theme_from_target(target)
    for problem in theme.contrast_failures():
        print(f"warning: branding contrast: {problem}", file=sys.stderr)
    return sge_note.build_note(report, target, evidence=sge_note.evidence_files(observation_dir),
                               observation=Path(observation_dir).resolve().name, theme=theme)


register(Standard(
    id="sge",
    title="Secure Government Email Common Implementation Framework (New Zealand)",
    data="secure-government-email.yaml",
    html_name="sge-note.html",
    evaluate=_sge_evaluate,
    text=_sge_text,
    html=_sge_html,
    unmet=lambda report: bool(report.breaches()),
))


def run(standard_id: str, observation_dir: Path, target_ref: str, *, fmt: str = "html",
        out: Path | None = None) -> tuple[str, Path | None, bool]:
    """Read one observation against one standard.

    Returns ``(rendered, written, unmet)``: the rendered text or HTML, the
    file it was written to (``None`` for text with no ``out``), and whether a
    *must* requirement is unmet. HTML is always written, to ``out`` or to the
    standard's ``html_name`` inside the observation directory.
    """
    standard = get(standard_id)
    target = config.load_target(target_ref)
    obs = Path(observation_dir)
    result = standard.evaluate(obs, target)
    if fmt == "html":
        rendered = standard.html(result, obs, target)
        out = out or obs / standard.html_name
    elif fmt == "text":
        rendered = standard.text(result, obs, target)
    else:
        raise ValueError(f"unknown format {fmt!r}; use text or html")
    if out is not None:
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Text gets the newline ``print`` would add, so the file matches what stdout shows.
        out.write_text(rendered if fmt == "html" else rendered + "\n", encoding="utf-8")
    return rendered, out, standard.unmet(result)
