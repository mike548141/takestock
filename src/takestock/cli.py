"""The ``takestock`` command.

Each subcommand is a thin layer over a module that can also be used from
Python: ``observe`` over :mod:`takestock.observe`, ``cmdb`` over
:mod:`takestock.cmdb`, ``requirements`` over :mod:`takestock.requirements`,
``comply`` over the standards registered in :mod:`takestock.comply`, and
``ipam`` over :mod:`takestock.ipam` where that module is installed.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from importlib import import_module
from pathlib import Path

from . import __version__, carry, comply, config
from .exits import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, guarded
from .observe import ObserveRefused, Options, observe

EXIT_CODES = f"""\
exit codes:
  {EXIT_CLEAN}  clean: the command did its work and found nothing adverse
  {EXIT_FINDINGS}  findings present: observe found a weak verdict or work for an
     out-of-cycle rung; comply found an unmet MUST requirement;
     requirements derived at least one requirement
  {EXIT_ERROR}  error: bad arguments, an unreadable input, a refused scan or carry, or an
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
            "authorisation record; ingest collectors read supplied exports. With "
            "--carry-scan the active probes do not run: the rows an earlier --scan "
            "observation measured are carried in, each keeping the date it was measured.",
            78))
    p.add_argument("target", help="a target profile: a path, or a name under targets/")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true",
                      help="also run the active probes (needs `authorisation:` in the profile)")
    mode.add_argument("--offline", action="store_true",
                      help="send nothing over the network: read supplied exports only")
    mode.add_argument("--carry-scan", metavar="OBSERVATION",
                      help="instead of probing, carry the active-probe rows (and their raw "
                           "transcripts) of an earlier --scan observation of this target: a "
                           "stamp under observations/, or a path. Each row keeps the date it "
                           "was measured; passive and ingest collectors run afresh. Carried "
                           "rows graded cleartext-served are re-checked with one plain-HTTP "
                           "request each, which needs the authorisation record. Refused past "
                           "--carry-max-age days")
    p.add_argument("--inbox", metavar="DIR",
                   help="read supplied exports from DIR (default: $TAKESTOCK_INBOX, "
                        "else <workspace>/inbox)")
    p.add_argument("--carry-max-age", metavar="DAYS", type=int,
                   default=carry.CARRY_MAX_AGE_DAYS,
                   help="the oldest an observation may be, in days, and still be carried "
                        f"(default: {carry.CARRY_MAX_AGE_DAYS})")
    p.add_argument("--refresh-ct", action="store_true",
                   help="ask the certificate-transparency service again rather than reuse "
                        "a recent answer from an earlier observation")

    p = sub.add_parser("cmdb", parents=[common], help="build the draft configuration register",
                       description="Build the draft configuration register from one "
                                   "observation, as JSON, CSV per class and a workbook.")
    p.add_argument("observation", type=Path, help="an observation directory")
    p.add_argument("out", type=Path, nargs="?", help="where to write (default: <observation>/cmdb)")
    p.add_argument("--keys", type=Path, help="an earlier build's keys.jsonl, so items keep their keys")
    p.add_argument("--ip-plan", type=Path,
                   help="an IP address plan's JSON (from takestock ipam); each machine it names "
                        "at an address becomes an item. Off unless given")

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

    standards = "\n".join("  " + line for line in comply.listing().splitlines())
    p = sub.add_parser(
        "comply", parents=[common], formatter_class=_Formatter, epilog=EXIT_CODES,
        help="read an observation against a standard",
        usage="takestock comply [-h] [--workspace DIR] [--format {html,text}] [--out FILE]\n"
              "                        <standard> <observation> <target>\n"
              "       takestock comply --list",
        description=textwrap.fill(
            "Read one observation against one standard and report every requirement as "
            "met, not met or not measured: as a self-contained HTML note written to a "
            "file (the default), or with --format text as plain text on the terminal.", 78)
        + f"\n\nstandards:\n{standards}")
    p.add_argument("standard", nargs="?", metavar="<standard>",
                   help="the standard's id (see --list)")
    p.add_argument("observation", type=Path, nargs="?", metavar="<observation>",
                   help="an observation directory")
    p.add_argument("target", nargs="?", metavar="<target>",
                   help="the target profile the observation was taken for")
    p.add_argument("--format", choices=("html", "text"), default="html",
                   help="html writes the note and prints its path; text prints the "
                        "report (default: html)")
    p.add_argument("--out", type=Path, metavar="FILE",
                   help="write to FILE (default: html writes the standard's note file "
                        "inside the observation directory, e.g. sge-note.html; text "
                        "prints to the terminal)")
    p.add_argument("--list", action="store_true", help="list the standards and exit")

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
    options = Options(scan=args.scan, offline=args.offline, refresh_ct=args.refresh_ct,
                      carry_scan=args.carry_scan, carry_max_age_days=args.carry_max_age)
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
    register = cmdb.build_register(args.observation, keys=args.keys, ip_plan=args.ip_plan)
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


def _comply(args: argparse.Namespace) -> int:
    if args.list:
        print(comply.listing())
        return EXIT_CLEAN
    if args.standard is None:
        raise ValueError("name a standard (takestock comply --list shows them)")
    comply.get(args.standard)      # an unknown id is refused before any input is read
    if args.observation is None or args.target is None:
        raise ValueError("name the observation directory and the target profile: "
                         f"takestock comply {args.standard} <observation> <target>")
    rendered, written, unmet = comply.run(args.standard, args.observation, args.target,
                                          fmt=args.format, out=args.out)
    print(written if written is not None else rendered)
    return EXIT_FINDINGS if unmet else EXIT_CLEAN


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
    "comply": _comply,
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
    return guarded(f"takestock {args.command}", _COMMANDS[args.command], args)
