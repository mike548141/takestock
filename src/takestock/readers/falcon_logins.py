"""CrowdStrike Falcon: sign-in activity on machines with the endpoint sensor, from login exports.

Two CSV exports of sign-in activity the sensor observed, one row per account
and sign-in record, such as the Falcon console's successful and failed login
lists: ``input:`` names the successful sign-ins and ``settings: failed:``
the failed ones. Either may be given alone. No public description of a
console export's headings was found, so the reader's default headings are
plain names of its own (:data:`HEADINGS`) and ``settings: columns:`` names
the export's: ``{columns: {successful: {logon_type: "<heading>"}, failed:
{...}}}``.

What it reads from them, and why it belongs in a cryptographic inventory:

* **Logon type 8, NetworkCleartext.** Microsoft's logon type table for
  security event 4624 (learn.microsoft.com) says that for this type "the
  user's password was passed to the authentication package in its unhashed
  form", that "the built-in authentication packages all hash credentials
  before sending them across the network", and that "the credentials don't
  traverse the network in plaintext". So the receiving machine got a
  password it could read. Whether it crossed the network readable turns on
  the protocol that carried it (an inference, not Microsoft's statement),
  which the export does not say.
  Any such record, succeeded or failed, is one ``weak`` row.
* **Where sign-in activity concentrates**: how much of it the busiest
  accounts carry, as shares; accounts are ranked, never named.
* **Local against domain accounts**: a local account cannot be reviewed or
  disabled from the directory, so a local majority is ``weak``.
* **The sign-in paths in use**, by logon type, and **the failed sign-ins**,
  with the export's own suspicious-record marking carried through and not
  re-judged.

Logon types are read by Microsoft's number or name (:mod:`._falcon_identity`).
Every row but the cleartext and local-majority ones is ``n/a``: a share or a
failure count is context for a finding, not a weakness of a primitive. A
scope row says the activity is what the sensor observed, not every sign-in.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_logins"

CLEARTEXT_FLAG = "cleartext-credential-logon"
SCOPE_FLAG = "scope-observed-not-enumerated"
#: How many of the busiest accounts the concentration row gives a share for.
RANKS = 5

_LOGIN_FIELDS = {"account": "account", "account_type": "account_type",
                 "logon_type": "logon_type", "attempts": "attempts"}
#: Each export's fields and the headings they are read from unless ``settings: columns:`` names others.
HEADINGS: dict[str, dict[str, Any]] = {
    "successful": dict(_LOGIN_FIELDS),
    "failed": {**_LOGIN_FIELDS, "suspicious": "suspicious"},
}

NOT_RECORDED = "(not recorded)"


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of sign-in activity was read"
        + (f" ({why})" if why else "")
        + ": where sign-in activity concentrates, whether the accounts in use can be disabled "
        "centrally, and whether any sign-in handed a machine a password it could read",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without sign-in records nobody can say whether people and programs sign in "
                "with accounts that one central directory can disable, or with local accounts "
                "that would each have to be found on their own machine."),
        harvest=("Export the successful and failed sign-in lists from the Falcon console as CSV, "
                 "name them with input: and settings: failed:, and name their headings with "
                 "settings: columns:."),
        nature=coverage.NO_DATA)


def _tally(rows: list[dict[str, str]], heads: Mapping[str, Any], field: str) -> dict[str, int]:
    """Attempts summed per value of ``field``, largest first (blank as ``(not recorded)``)."""
    out: dict[str, int] = {}
    for r in rows:
        key = _fi.value(r, heads[field]) or NOT_RECORDED
        out[key] = out.get(key, 0) + _fi.number(_fi.value(r, heads["attempts"]))
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _by_type(tally: Mapping[str, int]) -> dict[str, int]:
    """A tally keyed by logon type value, summed per Microsoft logon type number."""
    out: dict[str, int] = {}
    for k, v in tally.items():
        number = _fi.logon_type("" if k == NOT_RECORDED else k)
        out[number] = out.get(number, 0) + v
    return out


def read(successful: Path | None, failed: Path | None = None, *,
         headings: Mapping[str, Mapping[str, Any]] | None = None,
         ranks: int = RANKS) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows for the two exports, or one gap when neither holds a row."""
    heads = headings or HEADINGS
    sh, fh = heads["successful"], heads["failed"]
    ok, ok_why = _fi.rows(successful)
    bad, bad_why = _fi.rows(failed)
    if not ok and not bad:
        why = ok_why or bad_why or ("the files named hold no rows" if (successful or failed)
                                    else "")
        return [], [_missing_gap(why)]

    dated = successful if ok else failed
    when = (file_mtime_date(dated) if dated else None) or ""
    base: dict[str, Any] = {"data_state": "identity", "protocol": "login", "source": NAME,
                            "source_class": "private",
                            "source_name": _fi.source_name("sign-in activity", when),
                            "collected_at": when}
    out: list[CryptoAsset] = []

    # ── a password the receiving machine could read ──
    ct_ok = [r for r in ok if _fi.logon_type(_fi.value(r, sh["logon_type"])) == _fi.NETWORK_CLEARTEXT]
    ct_bad = [r for r in bad
              if _fi.logon_type(_fi.value(r, fh["logon_type"])) == _fi.NETWORK_CLEARTEXT]
    if ct_ok or ct_bad:
        attempts = (sum(_fi.number(_fi.value(r, sh["attempts"])) for r in ct_ok)
                    + sum(_fi.number(_fi.value(r, fh["attempts"])) for r in ct_bad))
        records = len(ct_ok) + len(ct_bad)
        outcome = (f"{len(ct_ok):,} of them succeeded, so a working password was handed over."
                   if ct_ok else
                   "All of them failed; a sign-in that succeeds by the same path hands over a "
                   "working password the same way.")
        out.append(CryptoAsset(
            name="Cleartext network logons", role=roles.signin_activity_cleartext(records),
            verdict="weak", flags=[CLEARTEXT_FLAG], hosts_count=records,
            notes=(f"{records:,} sign-in record(s), {attempts:,} attempt(s), used logon type 8, "
                   "NetworkCleartext. For this type Microsoft says the password was passed to "
                   "the authentication package in unhashed form, and that the credentials do "
                   "not traverse the network in plaintext: the machine that received it could "
                   "read it. Whether it crossed the network readable turns on the protocol "
                   f"that carried it, which this export does not show. {outcome}"),
            extra={"successful": str(len(ct_ok)), "failed": str(len(ct_bad)),
                   "attempts": str(attempts)},
            **base))

    if ok:
        # ── how concentrated sign-in activity is ──
        by_account = _tally(ok, sh, "account")
        total = sum(by_account.values())
        top = list(by_account.values())[:max(ranks, 0)]
        top_share = sum(top) / total if total else 0.0
        two_share = sum(top[:2]) / total if total else 0.0
        shares = {f"rank_{i + 1}_share": (f"{v / total:.3f}" if total else "0")
                  for i, v in enumerate(top)}
        out.append(CryptoAsset(
            name="Authentication concentration", role=roles.signin_activity_concentration(),
            verdict="n/a", flags=[f"identity-concentration:{round(two_share * 100)}"],
            hosts_count=len(by_account),
            notes=(f"{len(by_account):,} accounts made {total:,} successful sign-in attempts. "
                   f"The two busiest made {two_share:.0%} of them and the busiest {len(top)} "
                   f"made {top_share:.0%}. A credential that carries a large share of sign-ins "
                   "is worth more to whoever steals it, which makes it worth considering early "
                   "in any credential rotation. Accounts are ranked here, not named; the "
                   "export names them."),
            extra={"identities": str(len(by_account)), "attempts": str(total),
                   "top2_share": f"{two_share:.3f}", **shares},
            **base))

        # ── local against domain accounts ──
        kinds: dict[str, int] = {}
        for k, v in _tally(ok, sh, "account_type").items():
            kinds[k.strip().lower()] = kinds.get(k.strip().lower(), 0) + v
        local, domain = kinds.get("local", 0), kinds.get("domain", 0)
        majority = local > domain
        out.append(CryptoAsset(
            name="Local versus domain authentication", role=roles.signin_activity_account_kind(),
            verdict="weak" if majority else "acceptable",
            flags=[f"local-authentication-majority:{local}"] if majority else [],
            hosts_count=local + domain,
            notes=(f"{local:,} successful sign-in attempts used a local account and {domain:,} "
                   "a domain account. A local account lives on one machine: the directory "
                   "cannot review it, time-limit it or disable it, and disabling a person in "
                   "the directory leaves it working. "
                   + ("Local accounts carry the majority here." if majority else
                      "Domain accounts carry the majority here.")),
            extra={"local": str(local), "domain": str(domain)},
            **base))

        # ── the sign-in paths in use ──
        by_login = _tally(ok, sh, "logon_type")
        numbered = _by_type(by_login)
        service = numbered.get(_fi.SERVICE, 0)
        interactive = numbered.get(_fi.INTERACTIVE, 0) + numbered.get(_fi.REMOTE_INTERACTIVE, 0)
        attempts_all = sum(by_login.values())
        mix = "; ".join(f"{k} {v:,}" for k, v in by_login.items())
        out.append(CryptoAsset(
            name="Authentication paths in use", role=roles.signin_activity_paths(),
            verdict="n/a", flags=[], hosts_count=attempts_all,
            notes=(f"Of {attempts_all:,} successful sign-in attempts, {interactive:,} used an "
                   f"interactive or remote interactive logon and {service:,} a service logon. "
                   "A program that signs in by a path made for people holds a credential "
                   "shaped for a person, which is worth comparing with the account list. "
                   f"By logon type: {mix}."),
            extra={k.lower().replace(" ", "_"): str(v) for k, v in by_login.items()},
            **base))

    if bad:
        # ── failed sign-ins, and the export's own reading of them ──
        failed_total = sum(_fi.number(_fi.value(r, fh["attempts"])) for r in bad)
        suspicious = sum(1 for r in bad if _fi.is_yes(_fi.value(r, fh["suspicious"])))
        by_failed = _tally(bad, fh, "account")
        two = sum(list(by_failed.values())[:2])
        share = two / failed_total if failed_total else 0.0
        out.append(CryptoAsset(
            name="Failed authentication", role=roles.signin_activity_failures(),
            verdict="n/a",
            flags=[f"suspicious-failed-logins:{suspicious}"] if suspicious else [],
            hosts_count=len(by_failed),
            notes=(f"{failed_total:,} failed sign-in attempts by {len(by_failed):,} accounts; "
                   f"the two with the most failures made {share:.0%} of them. The export does "
                   "not say why a sign-in failed. It marks "
                   f"{suspicious:,} of its {len(bad):,} records suspicious; that is its own "
                   "assessment, carried through and not re-judged here."),
            extra={"attempts": str(failed_total), "identities": str(len(by_failed)),
                   "suspicious_records": str(suspicious), "records": str(len(bad))},
            **base))

    # ── what the exports cover ──
    out.append(CryptoAsset(
        name="Login activity scope", role=roles.signin_activity_scope(), verdict="n/a",
        flags=[SCOPE_FLAG], hosts_count=len(ok) + len(bad),
        notes=("These are the sign-ins the endpoint sensor observed on the machines that run "
               "it. A sign-in that never touched such a machine, such as a program signing in "
               "to a cloud service, is not here, so every share above is a share of what was "
               "observed, not of all sign-in activity, and not the identity provider's own "
               "record."),
        extra={"successful_records": str(len(ok)), "failed_records": str(len(bad))},
        **base))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the two exports' rows, or a gap saying none was read."""
    assets, gaps = read(ctx.input, _entra.newest(ctx, "failed"),
                        headings=_fi.headings(ctx, HEADINGS),
                        ranks=int(_entra.setting_number(ctx, "ranks", RANKS)))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon sign-in activity (where authentication concentrates)",
                gap_prefix=False)
