"""The ``takestock`` command.

Each subcommand is a thin layer over a module that can also be used from
Python: ``observe`` over :mod:`takestock.observe`, ``cmdb`` over
:mod:`takestock.cmdb`, ``requirements`` over :mod:`takestock.requirements`, ``sge`` over
:mod:`takestock.sge`, ``sge-note`` over :mod:`takestock.sge` and
:mod:`takestock.sge_note`, and ``ipam`` over :mod:`takestock.ipam` where that
module is installed.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import traceback
from importlib import import_module
from pathlib import Path

import yaml

from . import __version__, config
from .observe import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, ObserveRefused, Options, observe

EXIT_CODES = f"""\
exit codes:
  {EXIT_CLEAN}  clean: the command did its work and found nothing adverse
  {EXIT_FINDINGS}  findings present: observe found a weak verdict or work for an
     out-of-cycle rung; sge or sge-note found an unmet MUST requirement;
     requirements derived at least one requirement
  {EXIT_ERROR}  error: bad arguments, an unreadable input, a refused scan, or an
     observation that could not judge because a collector failed (the
     observation is still written, and summary.json lists the failures)
"""

DESCRIPTION = ("Take stock of an IT estate: a cryptographic bill of materials, a draft "
               "configuration register, an IP address plan, standards conformance notes "
               "and requirements derived from the findings.")


class _Formatter(argparse.RawDescriptionHelpFormatter):
    """Keeps the exit-code table's layout."""


def _common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--workspace", metavar="DIR",
                        help="the workspace holding targets/, observations/, inbox/ and "
                             "data/ (default: $TAKESTOCK_HOME, else the current directory)")
    return common


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for every subcommand."""
    common = _common()
    parser = argparse.ArgumentParser(prog="takestock", description=textwrap.fill(DESCRIPTION, 78),
                                     epilog=EXIT_CODES, formatter_class=_Formatter)
    parser.add_argument("--version", action="version", version=f"takestock {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser(
        "observe", parents=[common], formatter_class=_Formatter, epilog=EXIT_CODES,
        help="collect evidence and write an observation",
        description=textwrap.fill(
            "Run the collectors for one target profile and write observations/<UTC stamp>/ "
            "(assets.json, summary.json, bom.cdx.json and raw/). Passive collectors read "
            "public sources; active probes run only with --scan and the profile's "
            "authorisation record; ingest collectors read supplied exports.", 78))
    p.add_argument("target", help="a target profile: a path, or a name under targets/")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true",
                      help="also run the active probes (needs `authorisation:` in the profile)")
    mode.add_argument("--offline", action="store_true",
                      help="send nothing over the network: read supplied exports only")
    p.add_argument("--inbox", metavar="DIR",
                   help="read supplied exports from DIR (default: $TAKESTOCK_INBOX, "
                        "else <workspace>/inbox)")
    p.add_argument("--refresh-ct", action="store_true",
                   help="ask the certificate-transparency service again rather than reuse "
                        "a recent answer from an earlier observation")

    p = sub.add_parser("cmdb", parents=[common], help="build the draft configuration register",
                       description="Build the draft configuration register from one "
                                   "observation, as JSON, CSV per class and a workbook.")
    p.add_argument("observation", type=Path, help="an observation directory")
    p.add_argument("out", type=Path, nargs="?", help="where to write (default: <observation>/cmdb)")
    p.add_argument("--keys", type=Path, help="an earlier build's keys.jsonl, so items keep their keys")

    p = sub.add_parser("ipam", parents=[common], help="build an IP address plan",
                       description="Build an IP address plan from a <stem>.ipam.yaml file.")
    p.add_argument("plan", help="the plan file, <stem>.ipam.yaml")
    p.add_argument("out", help="directory to write the plan's JSON, CSV and HTML into")
    p.add_argument("--exports", metavar="DIR",
                   help="directory the plan's source paths are relative to "
                        "(default: the workspace inbox)")
    p.add_argument("--lookup-asn", action="store_true",
                   help="first look up the plan's public addresses with the internet "
                        "registries (sends them over the network)")

    p = sub.add_parser("sge", parents=[common],
                       help="print the Secure Government Email conformance report",
                       description="Read one observation against the Secure Government "
                                   "Email framework for the profile's email domains, and "
                                   "print the conformance report as plain text.")
    p.add_argument("observation", type=Path, help="an observation directory")
    p.add_argument("target", help="the target profile the observation was taken for")

    p = sub.add_parser("sge-note", parents=[common],
                       help="write the Secure Government Email conformance note",
                       description="Read one observation against the Secure Government "
                                   "Email framework for the profile's email domains, and "
                                   "write the conformance note as HTML.")
    p.add_argument("observation", type=Path, help="an observation directory")
    p.add_argument("target", help="the target profile the observation was taken for")
    p.add_argument("--out", type=Path, help="the HTML file (default: <observation>/sge-note.html)")

    p = sub.add_parser("requirements", parents=[common],
                       help="derive requirements from an observation's findings",
                       description="Derive requirements from one observation's findings "
                                   "and gaps, as Markdown, a workbook and JSON.")
    p.add_argument("observation", type=Path, help="an observation directory")
    p.add_argument("out", type=Path, nargs="?",
                   help="where to write (default: <observation>/requirements)")
    p.add_argument("--catalogue", type=Path, help="a requirements catalogue to use instead")

    sub.add_parser("version", help="print the version")
    return parser


def _observe(args: argparse.Namespace) -> int:
    if args.inbox:
        config.set_inbox(args.inbox)
    target = config.load_target(args.target)
    options = Options(scan=args.scan, offline=args.offline, refresh_ct=args.refresh_ct)
    try:
        result = observe(target, options)
    except ObserveRefused as exc:
        print(f"takestock: REFUSED, nothing written or contacted: {exc}", file=sys.stderr)
        return EXIT_ERROR
    s = result.summary
    print(config.display_path(result.observation))
    print(f"{s['total_assets']} assets; verdicts {s['by_verdict']}; "
          f"{len(s['gaps'])} coverage gap(s); {len(result.findings)} finding(s)")
    if result.failures:
        print(f"takestock: {len(result.failures)} collector failure(s); this observation "
              "could not judge everything it was asked to:", file=sys.stderr)
        for f in result.failures:
            print(f"  · {f}", file=sys.stderr)
    return result.exit_code


def _cmdb(args: argparse.Namespace) -> int:
    from . import cmdb
    register = cmdb.build_register(args.observation, keys=args.keys)
    for path in cmdb.write_outputs(register, args.out or args.observation / "cmdb"):
        print(path)
    return EXIT_CLEAN


def _ipam(args: argparse.Namespace) -> int:
    try:
        ipam = import_module(f"{__package__}.ipam")
    except ImportError:
        print("takestock: the ipam module is not installed in this build", file=sys.stderr)
        return EXIT_ERROR
    argv = [args.plan, args.out] + (["--exports", args.exports] if args.exports else [])
    if args.lookup_asn:
        argv.append("--lookup-asn")
    return int(ipam.main(argv))


def _sge_inputs(args: argparse.Namespace) -> tuple[dict, list[str], list] | None:
    """(target, email domains, assets) for the sge commands; None when there are no domains."""
    target = config.load_target(args.target)
    domains = [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]
    if not domains:
        print("takestock: the target profile names no `discovery.email_domains`, so there "
              "is nothing to read against the framework", file=sys.stderr)
        return None
    path = args.observation / "assets.json"
    assets = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(assets, list):
        raise ValueError(f"{path}: expected a list of asset rows")
    return target, domains, assets


def _sge(args: argparse.Namespace) -> int:
    from . import sge
    inputs = _sge_inputs(args)
    if inputs is None:
        return EXIT_ERROR
    target, domains, assets = inputs
    report = sge.evaluate(assets, domains, bulk_mail_domains=sge.bulk_mail_domains(target))
    # The same text ``python -m takestock.sge`` prints.
    print(sge._format(report, domains))
    return EXIT_FINDINGS if report.breaches() else EXIT_CLEAN


def _sge_note(args: argparse.Namespace) -> int:
    from . import htmlpage, sge, sge_note
    inputs = _sge_inputs(args)
    if inputs is None:
        return EXIT_ERROR
    target, domains, assets = inputs
    obs = args.observation
    results = sge.evaluate(assets, domains,
                           bulk_mail_domains=sge.bulk_mail_domains(target))
    theme = htmlpage.theme_from_target(target)
    for problem in theme.contrast_failures():
        print(f"warning: branding contrast: {problem}", file=sys.stderr)
    out = sge_note.render_note(results, target, args.out or obs / "sge-note.html",
                               evidence=sge_note.evidence_files(obs),
                               observation=obs.resolve().name, theme=theme)
    print(out)
    return EXIT_FINDINGS if results.breaches() else EXIT_CLEAN


def _requirements(args: argparse.Namespace) -> int:
    from . import requirements
    assets, gaps = requirements.load_observation(args.observation)
    reqs = requirements.derive(assets, requirements.load_catalogue(args.catalogue), gaps)
    paths = requirements.write_outputs(reqs, args.out or args.observation / "requirements",
                                       source=args.observation.resolve().name)
    for p in paths.values():
        print(p)
    print(f"{len(reqs)} requirement(s) derived")
    return EXIT_FINDINGS if reqs else EXIT_CLEAN


_COMMANDS = {
    "observe": _observe,
    "cmdb": _cmdb,
    "ipam": _ipam,
    "sge": _sge,
    "sge-note": _sge_note,
    "requirements": _requirements,
}


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return its exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return EXIT_CLEAN if exc.code in (0, None) else EXIT_ERROR
    if args.command is None:
        parser.print_help()
        return EXIT_ERROR
    if args.command == "version":
        print(f"takestock {__version__}")
        return EXIT_CLEAN
    if getattr(args, "workspace", None):
        config.set_workspace(args.workspace)
    try:
        return _COMMANDS[args.command](args)
    except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
        print(f"takestock {args.command}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception:  # noqa: BLE001 - the exit-code contract holds even for a defect
        print(f"takestock {args.command}: internal error", file=sys.stderr)
        traceback.print_exc()
        return EXIT_ERROR
