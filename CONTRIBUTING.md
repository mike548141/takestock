# Contributing to takestock

Thank you for helping. This guide covers the development loop, the one rule
that outranks everything else here, and how to write tests and fixtures that
keep to it.

## The development loop

```bash
make venv    # once: .venv with takestock in editable mode, plus ruff, mypy and pytest
make hooks   # once per clone: the guard runs on every commit and commit message
make check   # the whole gate: guard, lint, type checks and tests
```

`make check` runs, in order:

| Target | Runs |
|---|---|
| `guard` | `tools/guard.py`, which needs only the standard library |
| `lint` | `ruff check src tests tools` (line length 110) |
| `types` | `mypy src` |
| `test` | `pytest -q` |

From a second working tree, point the gate at an existing virtualenv with
`make check VENV=/path/to/.venv`. Tests must send nothing over the network.

To try a change end to end, run the commands in the README's quick start
against a copy of `examples/example-widgets/`.

A change a user would notice gets a line under *Unreleased* in
[`CHANGELOG.md`](CHANGELOG.md). Continuous integration runs the same
`make check` on every push and pull request. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md) rather than opening an issue.

## The rule: no organisation's data

takestock is public. **Nothing in this repository may carry an
organisation's data, or anything from which an organisation could be
inferred.** That covers code, comments, docstrings, tests, fixtures, data
files and documentation, and the records too: commit messages, the
changelog, issue notes and decision records.

**The check is reading for meaning.** Before you commit, read your whole
diff and your commit message as a stranger would, and ask whether any of it
points at a particular organisation through:

- its **name**, initials or brand, or the name of one of its systems;
- its **assets**: domain names, IP addresses, host names, site codes,
  tenant or account identifiers, certificates, naming conventions;
- its **services**, its **customers**, or its **sector**;
- its **size, places and timeline**: counts, cities, buildings, data
  centres, programme dates;
- its **suppliers, partners and people**;
- a **measured figure** someone could match against public DNS or
  certificate logs.

Removing a name is not enough: remove the description too. *"The
warehouse's ageing label printer"* identifies as well as a name does.

**Write the capability, never the circumstance.** Work is often prompted by
a real situation. Say what takestock now does and the general problem it
solves, with a synthetic example, and leave out where the need arose: write
*"reads printer firmware versions from a CSV export"*, never *"because an
estate's printers needed checking"*. This matters most in commit
messages and other records, which is where circumstances slip in.

**Public reference material is welcome.** Standards and guidance from public
bodies (NZISM, NCSC, the Protective Security Requirements, Secure Government
Email, NIST, IETF RFCs, IANA and the like) can be cited, quoted with their
sources, and encoded as data. Much of the tool's value is there.

**Unsure? Leave it out.**

## The guard

`tools/guard.py` scans every tracked file and every commit message for
addresses, host names, email addresses and GUIDs outside the reserved and
documentation ranges. It fails and never skips, and a line cannot carry an
allow marker. The only exemptions are exact entries in
`tools/guard-allow.txt`: public standards bodies and software projects. A
change to that file is reviewed like code.

If you work alongside private data, you can give the guard terms of your own
without putting them in the repository:

```bash
git config takestock.denylist /path/outside/the/repo/terms.txt
git config takestock.extraHook "<command>"
```

The denylist is one term per line, matched case-folded, accent-stripped and
across line breaks, as whole words; a leading `=` makes a term
case-sensitive. The extra hook is called as `<command> pre-commit` and
`<command> commit-msg FILE`, and a failure blocks the commit.

The guard is the floor, not the check. It catches exact identifiers, which
are finite, and nothing else. Reading for meaning is the check.

## Tests and fixtures

### Everything synthetic

| Kind | Use |
|---|---|
| Domain names | `example.com`, `example.net`, `example.org`, and names under `.test` or `.example` (RFC 2606, RFC 6761) |
| IPv4 addresses | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) |
| IPv6 addresses | `2001:db8::/32` (RFC 3849) |
| GUIDs | `00000000-0000-4000-8000-` followed by twelve digits of your choosing |
| Organisation | Example Widgets Ltd, a fictional manufacturer |
| People | role titles such as *IT manager*, never a name |
| Numbers and dates | round, obviously invented figures; dates plainly invented, such as 2030 |

`tests/probe_helpers.py` gives a synthetic, authorised target profile
(`target(...)`) for probe tests.

### Never from a real export

**Never build a fixture from an organisation's export or capture, however
well "anonymised".** An anonymised capture keeps timestamps, counts, ordering
and naming conventions that identify where it came from. Compose a fixture
by hand from the format's documentation, or capture one from a stub you ran
yourself.

### Capturing a fixture from a local stub

Where a parser needs a program's real output (an `openssl s_client`
transcript, an `nmap` script's report, `curl` headers), run the program
against a stub on your own machine, on the loopback address, with a
synthetic name:

```bash
# A self-signed certificate for a synthetic name
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=web-01.example.test" -keyout stub.key -out stub.crt

# A TLS stub on loopback (leave it running)
openssl s_server -accept 18443 -cert stub.crt -key stub.key -www

# In another shell: the transcript the parser reads
openssl s_client -connect 127.0.0.1:18443 -servername web-01.example.test \
    -tls1_2 < /dev/null > openssl-tls1_2.txt 2>&1
```

Python's `http.server`, or a few lines of `socketserver`, make an HTTP, SMTP
or IMAP stub just as easily; the point is that you wrote the server and
chose every name it gives out.

Then, before the file goes under `tests/fixtures/`:

1. **Remove what varies by machine or run**: build paths, session start
   times, session identifiers and keys that the parser does not read. Replace
   a value the parser does read with a fixed, obviously invented one (the
   existing fixtures use `1900000000` for session start times).
2. **Say how it was made on its first line**, as a comment the test skips:
   the tool and version, that the server was a loopback stub, and what you
   edited. For example:

   ```text
   # Captured with LibreSSL s_client from a loopback stub server (synthetic example.test certificate); session start times are replaced with 1900000000.
   ```

3. **Read it through.** A capture can carry your own machine's host name, a
   user name in a path, or a local address. Run `make check`; the guard
   catches some of these, not all.

In the test, answer the collector's command from the fixture with
`tests/probe_helpers.FakeRun` in place of `util.run`. `FakeRun` fails the
test on any command it was not told about, so a collector cannot contact
anything unplanned.

### What a test should show

- the parser reads the fixture correctly, including a value that would grade
  differently if misread;
- an active collector refuses, contacting nothing, without its
  authorisation record, and refuses rather than truncates a list over its
  ceiling;
- a missing input or tool becomes a coverage gap or an `unknown` row, never
  a clean result.

Delete the line a test protects and watch the test fail before you trust it.

## Documentation

Write in plain New Zealand English, with correct macrons on te reo Māori.
Define a term the first time you use it. Cite a standard by its publisher,
document and section. When a change adds a collector, a profile key or an
output, update the guide that describes it; [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
lists which guide covers what.

## Licence

takestock is licensed under the Apache License 2.0, and section 5 of that
licence covers contributions. See `LICENSE` and `NOTICE`.
