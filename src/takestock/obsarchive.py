"""Archive past observations into compressed files, with a hash manifest.

Each run writes an observation directory named by its UTC time stamp
(``2030-01-01T0000Z``) under ``observations/``. Past ones are rarely read and
take room, so :func:`archive_past` packs each one older than ``latest`` into
``<stamp>.tgz``, records every member's size and SHA-256 in
``ARCHIVE-MANIFEST.json``, checks the archive against the folder, and only
then removes the folder.

Readers never need to know which observations are archived:
:func:`observations` lists folders and archives together, unpacking an
archive on demand into ``observations/.unpacked/``.

Members are stored in three tiers, lightest first, so a reader wanting only
the bill of materials stops early: the top-level results and the raw
certificate-transparency answers, then everything else, then the bulky
evidence and register directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

MANIFEST = "ARCHIVE-MANIFEST.json"
SCHEMA = "takestock.observation-archive/1"
SUFFIX = ".tgz"
UNPACKED = ".unpacked"
_DONE = ".complete"
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{4}Z$")

_LIGHT = ("bom.cdx.json", "assets.json", "summary.json")
_LIGHT_RAW = "raw/ct-"
_HEAVY = ("evidence/", "cmdb/")


def is_light(rel: str) -> bool:
    """True for members in the first tier: results and raw transparency answers."""
    return rel in _LIGHT or rel.startswith(_LIGHT_RAW)


def _tier(rel: str) -> int:
    if is_light(rel):
        return 0
    return 2 if rel.startswith(_HEAVY) else 1


def is_stamp(name: str) -> bool:
    """True when ``name`` is an observation time stamp."""
    return bool(_STAMP.match(name))


def _hash_stream(f: IO[bytes]) -> str:
    h = hashlib.sha256()
    while chunk := f.read(1 << 20):
        h.update(chunk)
    return h.hexdigest()


def _sha256(path: Path) -> str:
    with path.open("rb") as f:
        return _hash_stream(f)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_manifest(root: Path) -> dict:
    """The manifest under ``root``; an empty one when none exists yet."""
    path = root / MANIFEST
    if not path.is_file():
        return {"schema": SCHEMA, "archives": []}
    return json.loads(path.read_text())


# The only keys a member entry may carry: anything more could smuggle content
# (a file's text, say) into a manifest meant to hold only sizes and hashes.
_MEMBER_KEYS = {"path", "type", "bytes", "sha256", "mtime", "target"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def check_shape(manifest: dict) -> list[str]:
    """Problems with a manifest's shape: a non-digest hash, or an unexpected key."""
    problems = []
    for a in manifest["archives"]:
        if not _HEX64.match(str(a.get("sha256", ""))):
            problems.append(f"{a.get('observation')}: archive sha256 is not a digest")
        for m in a["members"]:
            extra = set(m) - _MEMBER_KEYS
            if extra:
                problems.append(f"{a['observation']}/{m.get('path')}: unexpected {sorted(extra)}")
            if m.get("type") == "file" and not _HEX64.match(str(m.get("sha256", ""))):
                problems.append(f"{a['observation']}/{m.get('path')}: sha256 is not a digest")
    return problems


def write_manifest(root: Path, manifest: dict) -> None:
    """Write the manifest atomically, refusing one that fails :func:`check_shape`."""
    problems = check_shape(manifest)
    if problems:
        raise ValueError(f"{MANIFEST} would hold more than it may: {problems[0]}")
    manifest["archives"].sort(key=lambda a: a["observation"])
    text = json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    tmp = root / f"{MANIFEST}.part"
    tmp.write_text(text)
    os.replace(tmp, root / MANIFEST)


def entry_for(manifest: dict, stamp: str) -> dict | None:
    """The manifest entry for one observation, or None."""
    return next((a for a in manifest["archives"] if a["observation"] == stamp), None)


def archive_file(root: Path, entry: dict) -> Path | None:
    """The archive file an entry names, or None when it is not on this machine."""
    here = root / entry["archive"]
    return here if here.is_file() else None


def _members(obs: Path) -> list[tuple[str, Path]]:
    """Every file and symlink under ``obs``, as (relative path, path), lightest tier first."""
    found: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(obs):
        base = Path(dirpath)
        for d in list(dirnames):
            if (base / d).is_symlink():
                dirnames.remove(d)
                filenames.append(d)
        for f in filenames:
            p = base / f
            found.append((p.relative_to(obs).as_posix(), p))
    found.sort(key=lambda m: (_tier(m[0]), m[0]))
    return found


def _describe(rel: str, p: Path) -> dict:
    st = p.lstat()
    if p.is_symlink():
        return {"path": rel, "type": "symlink", "target": os.readlink(p),
                "mtime": _iso(st.st_mtime)}
    return {"path": rel, "type": "file", "bytes": st.st_size,
            "sha256": _sha256(p), "mtime": _iso(st.st_mtime)}


def folder_matches(obs: Path, entry: dict) -> list[str]:
    """Differences between an observation folder and its manifest entry; [] when equal."""
    want = {m["path"]: m for m in entry["members"]}
    have = {rel: _describe(rel, p) for rel, p in _members(obs)}
    problems = [f"not in the folder: {r}" for r in sorted(want.keys() - have.keys())]
    problems += [f"not in the manifest: {r}" for r in sorted(have.keys() - want.keys())]
    for rel in sorted(want.keys() & have.keys()):
        a, b = want[rel], have[rel]
        if a.get("sha256") != b.get("sha256") or a.get("target") != b.get("target"):
            problems.append(f"differs: {rel}")
    return problems


def archive(obs: Path) -> dict:
    """Pack ``obs`` into ``<stamp>.tgz`` beside it and return its manifest entry."""
    dest = obs.parent / f"{obs.name}{SUFFIX}"
    tmp = obs.parent / f"{obs.name}{SUFFIX}.part"
    described = []
    with tarfile.open(tmp, "w:gz") as tar:
        for rel, p in _members(obs):
            info = tar.gettarinfo(p, arcname=f"{obs.name}/{rel}")
            if info.islnk():
                # A hard link is stored as a copy, so each member stands alone.
                info.type, info.linkname, info.size = tarfile.REGTYPE, "", p.stat().st_size
            if info.isfile():
                with p.open("rb") as f:
                    tar.addfile(info, f)
            else:
                tar.addfile(info)
            described.append(_describe(rel, p))
    os.replace(tmp, dest)
    files = [m for m in described if m["type"] == "file"]
    return {
        "observation": obs.name,
        "archive": dest.name,
        "sha256": _sha256(dest),
        "bytes": dest.stat().st_size,
        "archived_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": len(files),
        "content_bytes": sum(m["bytes"] for m in files),
        "members": described,
    }


def archive_matches(root: Path, entry: dict) -> list[str]:
    """Differences between an archive file and its manifest entry; [] when equal."""
    path = archive_file(root, entry)
    if path is None:
        return [f"archive missing: {entry['archive']}"]
    if _sha256(path) != entry["sha256"]:
        return [f"archive hash differs: {entry['archive']}"]
    want = {m["path"]: m for m in entry["members"]}
    seen: set[str] = set()
    problems: list[str] = []
    prefix = f"{entry['observation']}/"
    with tarfile.open(path, "r:gz") as tar:
        for info in tar:
            rel = info.name.removeprefix(prefix)
            seen.add(rel)
            m = want.get(rel)
            if m is None:
                problems.append(f"not in the manifest: {rel}")
            elif info.issym():
                if m.get("target") != info.linkname:
                    problems.append(f"differs: {rel}")
            elif info.isfile():
                f = tar.extractfile(info)
                if f is None or _hash_stream(f) != m.get("sha256"):
                    problems.append(f"differs: {rel}")
    problems += [f"not in the archive: {r}" for r in sorted(want.keys() - seen)]
    return problems


def extract(root: Path, stamp: str, dest: Path, *, upto: int = 2) -> Path:
    """Unpack members up to tier ``upto`` into ``dest``, checking every file's hash."""
    entry = entry_for(read_manifest(root), stamp)
    if entry is None:
        raise FileNotFoundError(f"{stamp} is not in {MANIFEST}")
    hashes = {m["path"]: m.get("sha256") for m in entry["members"]}
    prefix = f"{stamp}/"
    dest.mkdir(parents=True, exist_ok=True)
    path = archive_file(root, entry)
    if path is None:
        raise FileNotFoundError(f"{entry['archive']} is not on this machine")
    with tarfile.open(path, "r:gz") as tar:
        for info in tar:
            rel = info.name.removeprefix(prefix)
            # Members are stored lightest tier first, so the first heavier one ends the read.
            if _tier(rel) > upto:
                break
            tar.extract(info, dest, filter="tar")
            got = dest / stamp / rel
            if info.isfile() and _sha256(got) != hashes.get(rel):
                raise ValueError(f"{stamp}/{rel} does not match {MANIFEST}")
    return dest / stamp


def unpacked(root: Path, stamp: str, upto: int = 0) -> Path:
    """An archived observation unpacked to at least tier ``upto``, reusing earlier unpacking."""
    home = root / UNPACKED
    got = home / stamp
    marker = got / _DONE
    if marker.is_file() and int(marker.read_text() or 0) >= upto:
        return got
    shutil.rmtree(got, ignore_errors=True)
    extract(root, stamp, home, upto=upto)
    marker.write_text(str(upto))
    return got


def observations(root: Path) -> list[Path]:
    """Every observation under ``root``, folders and archives alike, oldest first."""
    if not root.is_dir():
        return []
    found: dict[str, Path] = {}
    for p in root.iterdir():
        if is_stamp(p.name) and p.is_dir() and not p.is_symlink():
            found[p.name] = p
    for entry in read_manifest(root)["archives"]:
        stamp = entry["observation"]
        if stamp in found or archive_file(root, entry) is None:
            continue
        try:
            found[stamp] = unpacked(root, stamp)
        except (OSError, ValueError, tarfile.TarError):
            continue
    return [found[s] for s in sorted(found)]


def find(root: Path, stamp: str) -> Path:
    """The observation named ``stamp``, unpacking it if archived."""
    return next((p for p in observations(root) if p.name == stamp), root / stamp)


def past(root: Path) -> list[Path]:
    """Observation folders older than the one ``latest`` points at."""
    latest = root / "latest"
    if not latest.exists():
        return []
    current = latest.resolve().name
    return sorted(p for p in root.iterdir()
                  if is_stamp(p.name) and p.is_dir() and not p.is_symlink()
                  and p.name < current)


def archive_past(root: Path, *, dry_run: bool = False,
                 say: Callable[[str], object] = print) -> tuple[list[str], list[str]]:
    """Archive every past observation; returns (archived, kept with the reason)."""
    manifest = read_manifest(root)
    done: list[str] = []
    kept: list[str] = []
    for obs in past(root):
        if dry_run:
            say(f"would archive {obs.name}")
            continue
        entry = entry_for(manifest, obs.name)
        if entry is None or folder_matches(obs, entry):
            say(f"archiving {obs.name} …")
            entry = archive(obs)
            manifest["archives"] = [a for a in manifest["archives"]
                                    if a["observation"] != obs.name] + [entry]
            write_manifest(root, manifest)
        problems = archive_matches(root, entry) or folder_matches(obs, entry)
        if problems:
            kept.append(f"{obs.name}: {problems[0]}"
                        + (f" (+{len(problems) - 1} more)" if len(problems) > 1 else ""))
            continue
        shutil.rmtree(obs)
        done.append(obs.name)
    return done, kept
