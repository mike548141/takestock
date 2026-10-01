"""The page shell every takestock HTML output uses.

A page is one self-contained HTML file: semantic markup, an inline
stylesheet with light and dark colour schemes and a print stylesheet, and no
external fonts, scripts or images. The default look is deliberately plain: the
system's own sans-serif font and a neutral palette whose text colours meet the
WCAG 2.2 AA contrast minimum (4.5:1 for body text) on the backgrounds they are
used on.

An organisation may restyle its outputs with an optional ``branding:`` block in
its target profile::

    branding:
      name: Example Widgets Ltd      # alt text for the logo
      logo: brand/logo.svg           # relative to the profile; embedded inline
      font: "Example Sans, sans-serif"
      palette:                       # tokens from DEFAULT_LIGHT; others are
        accent: "#7a1f4d"            # ignored with a warning
      palette_dark:                  # tokens from DEFAULT_DARK
        accent: "#f0b8d8"

Nothing in the block is required, and no office template is ever needed.
:func:`Theme.contrast_failures` reports any override that falls below the
contrast minimum, so a caller can warn rather than ship an unreadable page.
"""

from __future__ import annotations

import base64
import html
import mimetypes
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: The system's own interface font, then the generic family.
SYSTEM_FONT = "system-ui, sans-serif"
SYSTEM_MONO = "ui-monospace, monospace"

#: Colour tokens for the light scheme. Every ``*_fg``/``text``/``muted``/
#: ``accent`` token is used as text on the background named in TEXT_PAIRS.
DEFAULT_LIGHT: dict[str, str] = {
    "bg": "#fdfcf9",
    "surface": "#f2efea",
    "text": "#22201c",
    "muted": "#4b3a2e",
    "accent": "#6b2d5c",
    "border": "#ded3c4",
    "pass_fg": "#1b5e36",
    "pass_bg": "#e2f0e6",
    "fail_fg": "#9b1035",
    "fail_bg": "#f9e3e8",
    "unmeasured_fg": "#6a4500",
    "unmeasured_bg": "#faefd6",
}

#: The same tokens for the dark scheme.
DEFAULT_DARK: dict[str, str] = {
    "bg": "#171615",
    "surface": "#22201e",
    "text": "#eeeae5",
    "muted": "#c9b79f",
    "accent": "#e3a6d3",
    "border": "#3d352e",
    "pass_fg": "#95d5ac",
    "pass_bg": "#15301f",
    "fail_fg": "#f4a7b9",
    "fail_bg": "#3b1622",
    "unmeasured_fg": "#f2cc7e",
    "unmeasured_bg": "#36290e",
}

#: (foreground, background, minimum ratio): every pairing the stylesheet
#: puts text on. 4.5:1 is the WCAG 2.2 AA minimum for normal-size text.
TEXT_PAIRS: list[tuple[str, str, float]] = [
    ("text", "bg", 4.5), ("text", "surface", 4.5),
    ("muted", "bg", 4.5), ("muted", "surface", 4.5),
    ("accent", "bg", 4.5), ("accent", "surface", 4.5),
    ("pass_fg", "pass_bg", 4.5), ("fail_fg", "fail_bg", 4.5),
    ("unmeasured_fg", "unmeasured_bg", 4.5),
]

_HEX = re.compile(r"^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
# A CSS font-family list: names, quotes, commas, spaces and hyphens only, so a
# profile value cannot close the style element or add a rule.
_FONT_LIST = re.compile(r"^[A-Za-z0-9 ,'\"_-]+$")


def esc(value: Any) -> str:
    """``value`` as text, escaped for HTML content or a quoted attribute."""
    return html.escape("" if value is None else str(value), quote=True)


def _channels(colour: str) -> tuple[int, int, int]:
    if not _HEX.match(colour):
        raise ValueError(f"a colour is written #rgb or #rrggbb, not {colour!r}")
    h = colour[1:]
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def relative_luminance(colour: str) -> float:
    """The WCAG relative luminance of a ``#rrggbb`` colour, from 0 (black) to 1 (white)."""
    def linear(c: int) -> float:
        s = c / 255
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(c) for c in _channels(colour))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a: str, b: str) -> float:
    """The WCAG contrast ratio between two colours, from 1 to 21."""
    hi, lo = sorted((relative_luminance(a), relative_luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@dataclass(frozen=True)
class Theme:
    """Colours, fonts and an optional logo for a page."""

    light: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_LIGHT))
    dark: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_DARK))
    font: str = SYSTEM_FONT
    mono: str = SYSTEM_MONO
    logo_uri: str = ""
    logo_alt: str = ""

    def contrast_failures(self) -> list[str]:
        """One line per text pairing below its minimum, in either scheme."""
        out = []
        for scheme, palette in (("light", self.light), ("dark", self.dark)):
            for fg, bg, minimum in TEXT_PAIRS:
                ratio = contrast_ratio(palette[fg], palette[bg])
                if ratio < minimum:
                    out.append(f"{scheme}: {fg} {palette[fg]} on {bg} {palette[bg]} is "
                               f"{ratio:.2f}:1, below {minimum}:1")
        return out


def _palette(base: dict[str, str], override: Any, where: str,
             ignored: list[str]) -> dict[str, str]:
    """``base`` with the override's known tokens applied; unknown names go to ``ignored``.

    An unknown token is skipped, value unread, so a profile written for
    another palette still renders. A known token's value must be a colour.
    """
    out = dict(base)
    if not override:
        return out
    if not isinstance(override, dict):
        raise ValueError(f"branding.{where} must be a mapping of token to colour")
    for key, value in override.items():
        if key not in base:
            ignored.append(f"{where}.{key}")
            continue
        _channels(str(value))
        out[key] = str(value).lower()
    return out


def _font(value: Any, default: str, where: str) -> str:
    text = str(value or "").strip()
    if not text:
        return default
    if not _FONT_LIST.match(text):
        raise ValueError(f"branding.{where} must be a CSS font-family list, not {text!r}")
    return text


def _logo_uri(logo: str, base_dir: Path | None) -> str:
    p = Path(logo).expanduser()
    if not p.is_absolute() and base_dir is not None:
        p = base_dir / p
    kind = mimetypes.guess_type(p.name)[0] or ""
    if not kind.startswith("image/"):
        raise ValueError(f"branding.logo must be an image file, not {logo!r}")
    return f"data:{kind};base64,{base64.b64encode(p.read_bytes()).decode('ascii')}"


def theme_from_target(target: dict) -> Theme:
    """The theme a target profile asks for: the defaults, with its ``branding:`` applied.

    A relative ``logo`` path is read from the directory holding the profile.
    Palette tokens this page does not use are ignored, with one warning on
    standard error naming them; call this once per command.
    """
    branding = target.get("branding") or {}
    if not isinstance(branding, dict):
        raise ValueError("branding: must be a mapping")
    tpath = target.get("_path")
    base_dir = Path(tpath).parent if tpath else None
    logo = str(branding.get("logo") or "")
    ignored: list[str] = []
    theme = Theme(
        light=_palette(DEFAULT_LIGHT, branding.get("palette"), "palette", ignored),
        dark=_palette(DEFAULT_DARK, branding.get("palette_dark"), "palette_dark", ignored),
        font=_font(branding.get("font"), SYSTEM_FONT, "font"),
        mono=_font(branding.get("mono"), SYSTEM_MONO, "mono"),
        logo_uri=_logo_uri(logo, base_dir) if logo else "",
        logo_alt=str(branding.get("name") or organisation_name(target)),
    )
    if ignored:
        print(f"warning: branding: ignored unknown colour token(s) {', '.join(ignored)}; "
              f"known: {', '.join(sorted(DEFAULT_LIGHT))}", file=sys.stderr)
    return theme


def organisation_name(target: dict, default: str = "the organisation") -> str:
    """The organisation's name from a profile's ``organisation:`` (a string or ``{name: ...}``)."""
    for key in ("organisation", "org"):
        block = target.get(key)
        if isinstance(block, dict) and block.get("name"):
            return str(block["name"])
        if isinstance(block, str) and block.strip():
            return block.strip()
    return str(target.get("name") or default)


def _vars(palette: dict[str, str]) -> str:
    return " ".join(f"--{k.replace('_', '-')}: {v};" for k, v in palette.items())


_CSS = """
:root { color-scheme: light dark; __LIGHT__ --font: __FONT__; --mono: __MONO__; }
@media screen and (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { __DARK__ } }
@media screen { :root[data-theme="dark"] { __DARK__ } }
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.55 var(--font); }
.page { max-width: 72rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
header.masthead { border-bottom: 3px solid var(--accent); padding-bottom: 1rem; margin-bottom: 2rem; }
header.masthead img { max-height: 3rem; max-width: 12rem; display: block; margin-bottom: 1rem; }
h1 { font-size: 1.9rem; line-height: 1.2; margin: 0 0 .5rem; }
h2 { font-size: 1.4rem; margin: 2.5rem 0 .75rem; padding-top: .5rem; border-top: 1px solid var(--border); }
h3 { font-size: 1.15rem; margin: 1.75rem 0 .5rem; }
h4 { font-size: 1rem; margin: 1.25rem 0 .4rem; }
p, ul, ol, dl { margin: 0 0 .9rem; }
.lede { font-size: 1.1rem; }
.muted, small, figcaption, caption { color: var(--muted); }
a { color: var(--accent); text-underline-offset: 2px; }
a:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
code, pre { font-family: var(--mono); font-size: .9em; background: var(--surface);
  border-radius: 3px; }
code { padding: .05em .3em; overflow-wrap: anywhere; }
pre { padding: .75rem; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
blockquote { margin: .5rem 0 .75rem; padding: .5rem .9rem; background: var(--surface);
  border-left: 4px solid var(--accent); }
blockquote p { margin: 0; }
.table-wrap { overflow-x: auto; margin: 0 0 1rem; }
table { border-collapse: collapse; width: 100%; font-size: .95rem; }
caption { text-align: left; padding: .25rem 0; }
th, td { text-align: left; vertical-align: top; padding: .45rem .6rem;
  border-bottom: 1px solid var(--border); }
thead th { background: var(--surface); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.status { display: inline-block; padding: .05em .5em; border-radius: 3px; font-weight: 600;
  white-space: nowrap; }
.status-pass { color: var(--pass-fg); background: var(--pass-bg); }
.status-fail { color: var(--fail-fg); background: var(--fail-bg); }
.status-not-measured { color: var(--unmeasured-fg); background: var(--unmeasured-bg); }
section.card, article.card { background: var(--surface); padding: .75rem 1rem; border-radius: 4px;
  margin: 0 0 1rem; }
article.card blockquote, article.card code, article.card pre, article.card thead th { background: var(--bg); }
dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }
dl.facts dt { font-weight: 600; }
dl.facts dd { margin: 0; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted);
  font-size: .9rem; }
@media (max-width: 40rem) {
  dl.facts { grid-template-columns: 1fr; }
  dl.facts dd { margin-bottom: .5rem; }
}
@media print {
  :root { color-scheme: light; __LIGHT__ }
  body { background: #fff; color: #000; font-size: 10.5pt; }
  .page { max-width: none; padding: 0; }
  a { color: inherit; }
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: .85em; }
  h2, h3, h4 { break-after: avoid; }
  tr, blockquote, article.card, dl.facts { break-inside: avoid; }
  thead { display: table-header-group; }
  .table-wrap { overflow: visible; }
  .no-print { display: none; }
}
@page { margin: 16mm 14mm; }
"""


def stylesheet(theme: Theme | None = None) -> str:
    """The page's CSS for ``theme`` (the defaults when None)."""
    t = theme or Theme()
    return (_CSS.replace("__LIGHT__", _vars(t.light))
            .replace("__DARK__", _vars(t.dark))
            .replace("__FONT__", t.font)
            .replace("__MONO__", t.mono)).strip()


def page(title: str, body: str, *, theme: Theme | None = None, lead: str = "",
         description: str = "", lang: str = "en-NZ", footer: str = "") -> str:
    """A complete HTML document.

    ``title`` and ``lead`` are plain text and are escaped here; ``body`` and
    ``footer`` are HTML the caller has already escaped.
    """
    t = theme or Theme()
    logo = (f'<img src="{esc(t.logo_uri)}" alt="{esc(t.logo_alt)}">' if t.logo_uri else "")
    meta = f'<meta name="description" content="{esc(description)}">\n' if description else ""
    return (
        "<!doctype html>\n"
        f'<html lang="{esc(lang)}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"{meta}<title>{esc(title)}</title>\n<style>\n{stylesheet(t)}\n</style>\n</head>\n"
        '<body>\n<div class="page">\n<header class="masthead">\n'
        f"{logo}<h1>{esc(title)}</h1>\n"
        + (f'<p class="lede">{esc(lead)}</p>\n' if lead else "")
        + "</header>\n<main>\n" + body + "\n</main>\n"
        + (f"<footer>\n{footer}\n</footer>\n" if footer else "")
        + "</div>\n</body>\n</html>\n")
