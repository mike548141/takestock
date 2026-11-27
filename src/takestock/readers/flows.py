"""Information flows: a register of what is shared, joined to the channels measured.

An **annotation** (``docs/PLUGINS.md``): it writes no rows. It reads the
information-sharing register and the channel map (:mod:`takestock.flows`,
``docs/COLLECTORS.md``), joins them to the rows the observation graded, and

* puts ``extra.flows`` (one sentence: how many recorded flows ride the row,
  to how many organisations, how many at or above the sensitivity floor,
  and by which channels) on every row a channel's legs select;
* raises a coverage gap for each data request the map names, for each
  declared leg no row matched, and for each declared hop no instrument can
  measure;
* writes the whole join (per flow, per channel, per row and in total) as the
  plug-in's record in ``summary.json``.

**The input.** None is declared: the channel map is the profile's
``<stem>.flows.yaml`` overlay, and it names the register's path
(``register: path:``). ``settings: map:`` names another map file. A profile
with no map gets the empty payload and no gap.

The key is cleared from every row first, so a row carried from an earlier
observation never keeps an earlier join's sentence.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import config, coverage, flows
from ..plugins import Context, Plugin, StepResult

#: The plug-in's name.
NAME = "flows"
#: The ``extra`` key it writes.
KEY = flows.EXTRA_KEY
#: ``settings:`` key naming a channel map other than the profile's overlay.
MAP_SETTING = "map"


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the sentences to add, keyed by each row's ``bom_ref``."""
    named = ctx.settings.get(MAP_SETTING)
    map_path = config.inbox_path(str(named)) if named else None
    if map_path is not None and not Path(map_path).exists():
        return StepResult(gaps=[coverage.gap(
            coverage.COULD_NOT_TEST,
            f"no information flow was joined: the channel map {named} named by `flows`'s "
            "`settings: map:` does not exist",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("No row carries the flows that ride it, so findings cannot be ordered "
                    "by what each would expose."),
            nature=coverage.NO_DATA)])
    rows = list(ctx.assets)
    payload, gaps = flows.build(ctx.target, config.workspace_root(), rows, map_path=map_path)
    return StepResult(gaps=list(gaps), annotations=flows.row_annotations(rows, payload),
                      summary=json.loads(json.dumps(payload, default=str)))


#: The declaration. It names no input: the map beside the profile says where the register is.
PLUGIN = Plugin(name=NAME, kind="annotation", step=step, annotation_keys=(KEY,),
                gap_prefix=False, title="information flows joined to the channels they ride")
