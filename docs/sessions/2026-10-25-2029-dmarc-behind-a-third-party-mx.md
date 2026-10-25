# 2026-10-25 — Inbound DMARC behind a third-party MX graded as not measured

## What was done

- **`sge._eval_inbound_dmarc` (SGE-DMARC-02).** Where the domain's MX points
  to a service in front of Exchange Online and the platform does not apply
  the sender's DMARC policy on that route (no enabled inbound connector has
  Enhanced Filtering for every recipient), the row is now *not measured*
  instead of *not met*. The requirement's scope is the organisation, and
  the service in front may check DMARC and act on it before the platform
  sees the mail, which an export of the platform's settings cannot show.
  The observed text reads *"policy: honours DMARC; platform: not applied on
  this route; the service in front of the platform: not measured"*, and the
  reason still names Enhanced Filtering for Connectors as the change at the
  platform. A governing policy that ignores DMARC is still *not met*,
  whatever the route.
- **`sge._eval_dmarc_quarantine` (SGE-DMARC-R04).** The same rule: a
  failure at the platform on such a route (junk folder, or a quarantine
  recipients can release) is now *not measured*, with the platform's answer
  kept in the reason and observed text. A pass on such a route stays a pass.
- `docs/COLLECTORS.md` (the `exchange_online` table), `docs/SGE-NOTE.md`,
  `docs/SECURE-GOVERNMENT-EMAIL.md` and the changelog say so.

## Checks

- Tests on exports composed in the tests, with a synthetic gateway MX
  (`mx1.gateway.example.net`): the two SGE-DMARC-02 route tests and the
  SGE-DMARC-R04 spoof-action test were rewritten, and three were added (the
  policy row is not marked non-conformant behind the gateway; a policy
  ignoring DMARC behind the gateway is still not met; both R04 platform
  failures behind the gateway are not measured).
- Run against the code before this change, four of those tests fail; with
  it, all 49 in `tests/test_reader_exchange_online.py` pass.
- `make check`: guard, ruff, mypy and the whole test suite.

## Left

- A governing policy that ignores DMARC behind a service in front of the
  platform is still graded *not met*, although that service could also
  check DMARC first. Whether that case should follow the same rule is open.
