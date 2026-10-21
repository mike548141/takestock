"""takestock's library of readers: plug-ins for exports of named products and standard formats.

Each module here holds one reader, written to the plug-in contract
(:mod:`takestock.plugins`, ``docs/PLUGINS.md``) exactly as a reader in another
package would be. The difference is only where it lives: these ship with
takestock, so every installation has them, and a target profile names one in
its ``plugins:`` list by name alone, as it would an installed plug-in. Like any
plug-in, a library reader runs only when a profile names it.

takestock finds them here, from its own package, rather than through
installed package metadata, so a source checkout and an installed copy find
the same readers. A plug-in of the same name offered by an installed package
as well is not run by name: the profile must say which one it means (see
``docs/PLUGINS.md``).

To add a reader: its module here, with a ``PLUGIN``; the module named in
:data:`MODULES`; its section in ``docs/COLLECTORS.md``; tests on synthetic
fixtures.
"""

from __future__ import annotations

from importlib import import_module

from ..plugins import Plugin

#: The library's modules, in the order their readers are listed.
MODULES: tuple[str, ...] = ("cyclonedx", "oracle_tde", "commvault", "exchange_online", "vmware",
                            "rvtools", "vsphere_lists")


def _load() -> list[Plugin]:
    out = []
    for name in MODULES:
        plugin = import_module(f"{__name__}.{name}").PLUGIN
        if not isinstance(plugin, Plugin):
            raise TypeError(f"{__name__}.{name}.PLUGIN is not a takestock Plugin")
        out.append(plugin)
    return out


#: Every reader in the library. A profile may also name them all with
#: ``module: takestock.readers:PLUGINS``.
PLUGINS: list[Plugin] = _load()


def library() -> dict[str, Plugin]:
    """The library's readers, by plug-in name."""
    return {p.name: p for p in PLUGINS}


def is_library_reader(plugin: object) -> bool:
    """Whether ``plugin`` is one of the library's own readers (the same object, not a namesake)."""
    return any(plugin is p for p in PLUGINS)
