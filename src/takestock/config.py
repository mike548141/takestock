"""Where takestock finds its inputs, and how it loads its data files.

A **workspace** is a directory holding one organisation's material:

* ``targets/``: target profiles (YAML) saying what to collect, plus
  *overlays*, files beside a profile that add to it
  (``<stem>.dispositions.yaml`` and the like);
* ``observations/``: what each run produced;
* ``inbox/``: exports supplied by hand (CSV, JSON and so on) for the ingest
  collectors to read;
* ``data/`` (optional): replacements for any of the data files that ship
  with the package.

The workspace is chosen, in order, by :func:`set_workspace` (the CLI's
``--workspace``), the ``TAKESTOCK_HOME`` environment variable, or the current
directory. Keeping the workspace outside the package means the tool can be
installed once and pointed at any number of estates.

A workspace's ``data/`` replaces the bundled data files only when the
workspace was named explicitly (by ``--workspace`` or ``TAKESTOCK_HOME``).
Falling back to the current directory never does, so a ``data/`` folder that
happens to sit wherever the command is run cannot change how anything is
graded.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import yaml

from .plaintext import build_index

PACKAGE_DIR = Path(__file__).resolve().parent

#: Environment variable naming the workspace.
ENV_VAR = "TAKESTOCK_HOME"

#: Data files that ship with the package.
BUNDLED_DATA_DIR = PACKAGE_DIR / "data"

_override: Path | None = None


def set_workspace(path: str | Path | None) -> None:
    """Use ``path`` as the workspace from now on; None returns to the default."""
    global _override
    _override = Path(path).expanduser().resolve() if path is not None else None


def explicit_workspace() -> Path | None:
    """The workspace when one was named (the override, then ``TAKESTOCK_HOME``), else None."""
    if _override is not None:
        return _override
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return None


def workspace_root() -> Path:
    """The workspace in effect: the override, then ``TAKESTOCK_HOME``, then the cwd."""
    named = explicit_workspace()
    return named if named is not None else Path.cwd().resolve()


def targets_dir() -> Path:
    """The workspace's ``targets/`` directory."""
    return workspace_root() / "targets"


#: The suffix of an IP address plan file (see :mod:`takestock.ipam`).
IPAM_PLAN_SUFFIX = ".ipam.yaml"

# Files beside a target profile that extend it rather than being a profile.
# The ones the package itself writes about are listed here, so the list does
# not depend on which modules happen to have been imported. Any other module
# that reads an overlay of its own registers the suffix with
# register_overlay_suffix().
OVERLAY_SUFFIXES: list[str] = [".dispositions.yaml", ".derived-ports.yaml", IPAM_PLAN_SUFFIX]


def register_overlay_suffix(*suffixes: str) -> None:
    """Declare further file suffixes as overlays, so they are never read as profiles."""
    for s in suffixes:
        if not s.startswith(".") or not s.endswith(".yaml"):
            raise ValueError(f"an overlay suffix looks like '.name.yaml', not {s!r}")
        if s not in OVERLAY_SUFFIXES:
            OVERLAY_SUFFIXES.append(s)


def is_overlay(path: Path) -> bool:
    """True when ``path`` is an overlay rather than a target profile."""
    return path.name.endswith(tuple(OVERLAY_SUFFIXES))


def target_profiles(directory: Path | None = None) -> list[Path]:
    """Every target profile in ``directory`` (default ``targets/``), overlays excluded."""
    d = targets_dir() if directory is None else directory
    return sorted(p for p in d.glob("*.yaml") if not is_overlay(p))


def observations_dir() -> Path:
    """The workspace's ``observations/`` directory."""
    return workspace_root() / "observations"


INBOX_DIRNAME = "inbox"
#: Environment variable that puts the inbox somewhere other than the workspace.
INBOX_ENV_VAR = "TAKESTOCK_INBOX"


_inbox_override: Path | None = None


def set_inbox(path: str | Path | None) -> None:
    """Read supplied exports from ``path`` from now on; None returns to the default."""
    global _inbox_override
    _inbox_override = Path(path).expanduser().resolve() if path is not None else None


def inbox_dir(root: Path | None = None) -> Path:
    """Where supplied exports are read from.

    In order: :func:`set_inbox` (the CLI's ``--inbox``), ``TAKESTOCK_INBOX``,
    then ``<workspace>/inbox``.
    """
    if _inbox_override is not None:
        return _inbox_override
    env = os.environ.get(INBOX_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    base = workspace_root() if root is None else Path(root).expanduser()
    return base / INBOX_DIRNAME


def inbox_path(rel: str | Path, root: Path | None = None) -> Path:
    """Resolve a path a target profile names.

    An absolute path is returned as given. A path starting ``inbox/`` resolves
    inside :func:`inbox_dir`, so the inbox can be moved without editing
    profiles. Anything else is relative to the workspace.
    """
    p = Path(rel).expanduser()
    if p.is_absolute():
        return p
    parts = p.parts
    if parts and parts[0] == INBOX_DIRNAME:
        return inbox_dir(root).joinpath(*parts[1:])
    base = workspace_root() if root is None else Path(root).expanduser()
    return base / p


def display_path(path: Path | str, root: Path | None = None) -> str:
    """``path`` relative to the workspace when it is inside it, else unchanged."""
    base = workspace_root() if root is None else Path(root)
    try:
        return str(Path(path).relative_to(base))
    except ValueError:
        return str(path)


def data_file(name: str) -> Path:
    """The data file ``name``: a named workspace's ``data/`` copy if present, else the bundled one.

    Only a workspace named explicitly (:func:`explicit_workspace`) is
    consulted; the current directory never is. When neither file exists the
    bundled path is returned, so the caller's error names where the file was
    expected.
    """
    named = explicit_workspace()
    candidates = ([named / "data" / name] if named is not None else []) + [BUNDLED_DATA_DIR / name]
    for c in candidates:
        if c.exists():
            return c
    return candidates[-1]


# Ports a target profile derives from other evidence live in an overlay
# beside the profile, under one key.
DERIVED_PORTS_SUFFIX = ".derived-ports.yaml"
DERIVED_PORTS_KEY = "derived_ports"


def derived_ports_path_for_target(target: dict) -> Path | None:
    """The derived-ports overlay beside a loaded target, or None if there is none."""
    tpath = target.get("_path")
    if not tpath:
        return None
    p = Path(tpath)
    if not p.suffix:
        return None
    cand = p.with_name(p.name[: -len(p.suffix)] + DERIVED_PORTS_SUFFIX)
    return cand if cand.exists() else None


def load_derived_ports(target: dict) -> dict:
    """The ``derived_ports:`` mapping from a target's overlay, with its ``_path``; {} if none."""
    path = derived_ports_path_for_target(target)
    if path is None:
        return {}
    doc = load_yaml_strict(path) or {}
    derived = doc.get(DERIVED_PORTS_KEY) or {}
    if not isinstance(derived, dict):
        raise ValueError(
            f"{path}: `{DERIVED_PORTS_KEY}:` must be a mapping, not "
            f"{type(derived).__name__}")
    derived["_path"] = str(path)
    return derived


def dispositions_path() -> Path:
    """The generic disposition rules file."""
    return data_file("dispositions.yaml")


class DuplicateKeyError(ValueError):
    """A YAML mapping declares the same key twice."""


class _StrictLoader(yaml.SafeLoader):
    """A safe YAML loader that refuses duplicate mapping keys."""


def _no_duplicate_keys(loader: _StrictLoader, node: yaml.MappingNode,
                       deep: bool = False) -> dict:
    # Plain YAML keeps the second of two identical keys and silently drops the
    # first; for hand-edited data that hides a mistake, so refuse instead.
    seen: dict = {}
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise DuplicateKeyError(
                f"{node.start_mark.name}: mapping key {key!r} is declared twice "
                f"(first at line {seen[key] + 1}, again at line "
                f"{key_node.start_mark.line + 1}). YAML would keep only the "
                f"second block and discard the first without a word. Merge the "
                f"two blocks by hand."
            )
        seen[key] = key_node.start_mark.line
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


def load_yaml_strict(path: Path) -> dict:
    """Load a YAML file safely, refusing duplicate keys; an empty file gives {}."""
    with path.open() as f:
        doc = yaml.load(f, Loader=_StrictLoader)  # _StrictLoader is a SafeLoader
    return doc if doc is not None else {}


def load_target(name_or_path: str, fallback: str = "") -> dict:
    """Load a target profile and record where it came from in ``_path``.

    ``name_or_path`` may be a path relative to the workspace, an absolute
    path, or a bare name looked up as ``targets/<name>.yaml``. ``fallback`` is
    a path to use when the first choice does not exist.
    """
    p = Path(name_or_path)
    relative = bool(name_or_path) and not p.is_absolute()
    in_workspace = workspace_root() / p
    if relative and in_workspace.is_file():
        p = in_workspace
    elif fallback and Path(fallback).exists() and (relative or not p.exists()):
        p = Path(fallback)
    elif relative and fallback:
        p = in_workspace
    elif not p.exists():
        p = targets_dir() / f"{name_or_path}.yaml"
    cfg = load_yaml_strict(p)
    cfg["_path"] = str(p)
    return cfg


def recorded_target_paths(read: str) -> tuple[str, str]:
    """(workspace-relative, absolute) forms of a target path, for an observation's record."""
    if not read:
        return "", ""
    absolute = Path(read).expanduser().resolve()
    try:
        relative = absolute.relative_to(workspace_root().resolve()).as_posix()
    except ValueError:
        relative = str(absolute)
    return relative, str(absolute)


def load_baseline() -> dict:
    """The algorithm baseline."""
    return load_yaml_strict(data_file("baseline.yaml"))


# The next four data files describe software and vendors. They ship as
# placeholders and may be filled from public sources; a missing or minimal
# file loads as empty rather than failing, so a lookup simply finds nothing.

def _optional_yaml(name: str) -> dict:
    path = data_file(name)
    return load_yaml_strict(path) if path.exists() else {}


def load_windows_lifecycle() -> dict:
    """Windows end-of-servicing data; {} or ``{"schema": 1}`` when not populated."""
    return _optional_yaml("windows-lifecycle.yaml")


def load_software_lifecycle() -> dict:
    """Vendor end-of-support data for software lines; {} or ``{"schema": 1}`` when not populated."""
    return _optional_yaml("software-lifecycle.yaml")


def _csv_rows(f) -> csv.DictReader:
    """Rows of a data CSV; lines starting with ``#`` are comments and are skipped."""
    return csv.DictReader(line for line in f if not line.lstrip().startswith("#"))


def load_dictionary() -> dict[str, dict]:
    """The daemon dictionary (process binary name to product), keyed by ``binary``."""
    path = data_file("daemon-dictionary.csv")
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    with path.open(newline="") as f:
        for row in _csv_rows(f):
            key = str(row.get("binary") or "").strip()
            if key:
                out[key] = row
    return out


def load_port_encryption() -> dict[str, dict[str, str]]:
    """The port-encryption table, indexed by :func:`takestock.plaintext.build_index`."""
    with data_file("port-encryption.csv").open(newline="") as f:
        return build_index(list(_csv_rows(f)))


def load_vendor_domains() -> dict[str, dict[str, str]]:
    """Known vendor domains, keyed by lower-cased domain."""
    path = data_file("vendor-domains.csv")
    out: dict[str, dict[str, str]] = {}
    if not path.exists():
        return out
    with path.open(newline="") as f:
        for row in _csv_rows(f):
            key = str(row.get("domain", "")).strip().lower()
            if key:
                out[key] = row
    return out
