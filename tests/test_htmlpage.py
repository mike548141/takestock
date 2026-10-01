"""The HTML page shell: contrast of the default palette, the schemes, and branding overrides."""

from __future__ import annotations

import re

import pytest

from takestock import htmlpage
from takestock.htmlpage import Theme, contrast_ratio

GENERIC_FAMILIES = {"system-ui", "sans-serif", "serif", "monospace", "ui-monospace",
                    "ui-sans-serif", "ui-serif"}


def test_contrast_ratio_matches_the_wcag_formula_at_its_ends():
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0)
    assert contrast_ratio("#777777", "#777777") == pytest.approx(1.0)
    assert contrast_ratio("#fff", "#ffffff") == pytest.approx(1.0)
    # Mid-grey on white sits just under the AA minimum; a known reference pair.
    assert contrast_ratio("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)


@pytest.mark.parametrize("scheme", [htmlpage.DEFAULT_LIGHT, htmlpage.DEFAULT_DARK])
@pytest.mark.parametrize("fg, bg, minimum", htmlpage.TEXT_PAIRS)
def test_every_default_text_pairing_meets_wcag_aa(scheme, fg, bg, minimum):
    assert minimum >= 4.5
    assert contrast_ratio(scheme[fg], scheme[bg]) >= minimum, (fg, bg)


def test_the_two_schemes_carry_the_same_tokens_and_the_defaults_pass():
    assert set(htmlpage.DEFAULT_LIGHT) == set(htmlpage.DEFAULT_DARK)
    for fg, bg, _ in htmlpage.TEXT_PAIRS:
        assert fg in htmlpage.DEFAULT_LIGHT and bg in htmlpage.DEFAULT_LIGHT
    assert Theme().contrast_failures() == []


def test_the_status_colours_are_distinct_from_each_other():
    for scheme in (htmlpage.DEFAULT_LIGHT, htmlpage.DEFAULT_DARK):
        fgs = [scheme["pass_fg"], scheme["fail_fg"], scheme["unmeasured_fg"]]
        assert len(set(fgs)) == 3


def test_the_default_font_names_no_typeface():
    for stack in (htmlpage.SYSTEM_FONT, htmlpage.SYSTEM_MONO):
        families = {f.strip() for f in stack.split(",")}
        assert families <= GENERIC_FAMILIES, stack


def test_the_stylesheet_has_dark_and_print_schemes():
    css = htmlpage.stylesheet()
    assert "prefers-color-scheme: dark" in css
    assert "@media print" in css
    assert f"--text: {htmlpage.DEFAULT_LIGHT['text']}" in css
    assert f"--text: {htmlpage.DEFAULT_DARK['text']}" in css
    # The dark scheme is screen-only, so a printout always uses the light one.
    dark_rules = re.findall(r"@media[^{]*\{[^{}]*:root[^{]*\{[^}]*"
                            + re.escape(htmlpage.DEFAULT_DARK["bg"]), css)
    assert dark_rules and all("screen" in r.split("{")[0] for r in dark_rules)


def test_a_page_is_self_contained_semantic_html():
    out = htmlpage.page("A <title> & more", "<p>body</p>", lead="lead & text",
                        footer="<p>foot</p>", description="d")
    assert out.startswith("<!doctype html>")
    assert '<html lang="en-NZ">' in out
    assert '<meta name="viewport"' in out
    assert "<title>A &lt;title&gt; &amp; more</title>" in out
    assert "<h1>A &lt;title&gt; &amp; more</h1>" in out
    assert '<p class="lede">lead &amp; text</p>' in out
    for tag in ("<header", "<main>", "<footer>"):
        assert tag in out
    assert "<script" not in out and "<link" not in out and "@import" not in out


def test_branding_overrides_palette_font_and_logo(tmp_path):
    logo = tmp_path / "logo.svg"
    logo.write_text('<svg width="10" height="10"/>')
    target = {
        "_path": str(tmp_path / "widgets.yaml"),
        "organisation": {"name": "Example Widgets Ltd"},
        "branding": {"logo": "logo.svg", "font": "'Example Sans', sans-serif",
                     "palette": {"accent": "#7A1F4D"},
                     "palette_dark": {"accent": "#f0b8d8"}},
    }
    theme = htmlpage.theme_from_target(target)
    assert theme.light["accent"] == "#7a1f4d"
    assert theme.dark["accent"] == "#f0b8d8"
    assert theme.light["text"] == htmlpage.DEFAULT_LIGHT["text"]
    out = htmlpage.page("t", "", theme=theme)
    assert "--accent: #7a1f4d;" in out and "--accent: #f0b8d8;" in out
    assert "--font: 'Example Sans', sans-serif;" in out
    assert '<img src="data:image/svg+xml;base64,' in out
    assert 'alt="Example Widgets Ltd"' in out
    assert theme.contrast_failures() == []


def test_no_branding_gives_the_defaults():
    theme = htmlpage.theme_from_target({})
    default = Theme()
    assert (theme.light, theme.dark, theme.font, theme.logo_uri) == (
        default.light, default.dark, default.font, "")
    assert "<img" not in htmlpage.page("t", "", theme=theme)


def test_an_unreadable_override_is_reported():
    theme = htmlpage.theme_from_target({"branding": {"palette": {"muted": "#dddddd"}}})
    failures = theme.contrast_failures()
    assert failures and all(f.startswith("light: muted #dddddd") for f in failures)


def test_unknown_palette_tokens_are_ignored_with_one_warning(capsys):
    theme = htmlpage.theme_from_target({"branding": {
        "palette": {"headline": "#123456", "callout": "not a colour", "accent": "#7A1F4D"},
        "palette_dark": {"headline": "#654321", "accent": "#f0b8d8"}}})
    assert theme.light == {**htmlpage.DEFAULT_LIGHT, "accent": "#7a1f4d"}
    assert theme.dark == {**htmlpage.DEFAULT_DARK, "accent": "#f0b8d8"}
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1, lines
    assert lines[0].startswith("warning: branding: ignored unknown colour token(s) ")
    for name in ("palette.headline", "palette.callout", "palette_dark.headline"):
        assert name in lines[0], name
    assert "accent" in lines[0].split("known:")[1]


def test_known_palette_tokens_raise_no_warning(capsys):
    htmlpage.theme_from_target({"branding": {"palette": {"accent": "#7a1f4d"}}})
    assert capsys.readouterr().err == ""


def test_the_note_command_warns_about_unknown_tokens_once(tmp_path, capsys):
    from takestock import sge, sge_note
    target = {"organisation": {"name": "Example Widgets Ltd"},
              "branding": {"palette": {"headline": "#123456"}}}
    theme = htmlpage.theme_from_target(target)
    capsys.readouterr()
    report = sge.evaluate([], ["example.com"])
    sge_note.render_note(report, target, tmp_path / "note.html", theme=theme)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("branding, message", [
    ({"palette": {"accent": "plum"}}, "#rgb or #rrggbb"),
    ({"palette_dark": {"accent": "#12345"}}, "#rgb or #rrggbb"),
    ({"palette": ["#000000"]}, "mapping"),
    ({"font": "x; } body { display: none"}, "font-family"),
    ({"logo": "notes.txt"}, "image file"),
])
def test_bad_branding_is_refused(branding, message):
    with pytest.raises(ValueError, match=message):
        htmlpage.theme_from_target({"branding": branding})


@pytest.mark.parametrize("target, name", [
    ({"organisation": {"name": "Example Widgets Ltd"}}, "Example Widgets Ltd"),
    ({"organisation": "Example Widgets Ltd"}, "Example Widgets Ltd"),
    ({"org": {"name": "Example Widgets Ltd"}}, "Example Widgets Ltd"),
    ({"name": "Example Widgets Ltd"}, "Example Widgets Ltd"),
    ({}, "the organisation"),
])
def test_the_organisation_name_comes_from_the_profile(target, name):
    assert htmlpage.organisation_name(target) == name
