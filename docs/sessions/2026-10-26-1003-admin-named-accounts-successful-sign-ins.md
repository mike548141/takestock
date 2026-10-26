# 2026-10-26 — Administrator-named accounts: successful sign-ins only

## What was done

- **`entra_signins`, the administrator-named accounts row.** Its count of
  sign-ins (`usage_count` and `extra.signins`) is now the accounts'
  successful sign-ins, as on the role rows, where a failed or interrupted
  attempt has not counted as use since the reader was added. An account is
  still counted once it appears in the log, whatever its attempts' status.
  The note says *"with N successful sign-in(s) between them (failed and
  interrupted attempts are not counted)"*.
- The per-application rows outside Conditional Access still count attempts,
  successful or not, for the reason `docs/COLLECTORS.md` gives.
- `docs/COLLECTORS.md` says which rows count what.

## Checks

- A new test composes a log with two accounts named like administrators and
  holding no role: one with two successful sign-ins, a failed and an
  interrupted attempt, one with failed attempts only. It expects two
  accounts and two sign-ins. It fails against the code before this change
  and passes with it.
- `make check`: guard, ruff, mypy and the whole test suite.
