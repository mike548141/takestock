# Security policy

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**, or go straight to
<https://github.com/mike548141/takestock/security/advisories/new>.

Please do not open a public issue, pull request or discussion for a
vulnerability, and do not include real hosts, addresses or exports from an
estate in the report. A synthetic reproduction (`example.test`, `192.0.2.0/24`)
is all that is needed.

A useful report says:

- the takestock version (`takestock --version`) and Python version;
- what you ran, with a synthetic target profile or input that shows the
  problem;
- what happened, and what you expected.

## What counts

takestock probes hosts and reads exports, so these matter most:

- an active collector that contacts a host or port the target profile did not
  name, runs without a complete authorisation record, or sweeps a range;
- input (an export, a DNS answer, a certificate, a zone file) that makes
  takestock run code, read or write outside its workspace, or hang;
- an output that carries something it should not, such as a credential read
  from an export;
- a way past `tools/guard.py` for an identifier it is meant to refuse.

A weak grade you disagree with, or a standard read differently, is not a
vulnerability: open an ordinary issue for it.

## Supported versions

takestock is at version 0.x. Fixes go into the next release, and only the
latest release is supported.

## What happens next

The report is acknowledged, investigated and, if confirmed, fixed in a
release, with an advisory published once the fix is available. You will be
credited in the advisory unless you ask not to be. There is no fixed response
time while takestock is at 0.x.
