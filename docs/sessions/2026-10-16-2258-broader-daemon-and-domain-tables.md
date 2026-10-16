# 2026-10-16 — Broader daemon dictionary and vendor-domain table

## What was done

Two bundled reference tables were widened so that each reads as general
reference data, chosen by market presence across mainstream platforms.

- **`data/daemon-dictionary.csv`** more than doubled in size. The new
  rows cover the standard services of Linux distributions, Windows and
  Windows Server components and Microsoft server products, databases and
  connection poolers, proxies, application servers, virtualisation and
  container runtimes, Kubernetes networking, cloud guest agents, monitoring
  and logging agents, backup software, configuration management agents,
  remote-access servers, and host and network security sensors.
- **`data/vendor-domains.csv`** grew by more than three-quarters: more
  of the large cloud and enterprise platforms, collaboration and
  software-as-a-service platforms, identity and password managers, security
  services, certificate authorities' status domains, Linux distributions'
  mirrors and language package registries.
- **Both headers** now describe the two ways rows reach the table (for
  breadth, by market presence; and when a contributor needs a name looked
  up) and the one rule every row meets: the vendor, project or distribution
  documents the name or domain as its own; in the daemon dictionary, the
  row's notes say which document.

## How the rows were sourced

Every new row was taken from a public page fetched for the purpose: the
vendor's or project's own documentation, a distribution's manual page, or
the provider's published list of domains to allow through a firewall or
proxy. Blogs, forums and third-party "what is this process" sites were not
used. A random sample of fourteen new rows from each table was then
fetched again from its cited page, and all twenty-eight pages contained
the row's name or domain.

Rows were left out where the cited page could not settle the exact name. The
daemon lookup is exact, case included, and some Windows pages print an
executable in a case the running image may not have. Also left out: names
the user chooses at install time, domains for one country, region or
government cloud, and advertising, analytics and link-redirect domains.

## Checks

- `make check`: guard clean, ruff and mypy clean, the full test suite
  passing, including the tables' shape, vocabulary, unique-key and loader
  tests. No category was added, so no test changed.

## Left to do

- Some well-known products are not yet in either table because no public
  vendor page naming the executable or domain could be read: several
  database servers whose documentation names only a service or a package,
  some endpoint agents with no public page naming their executable, and
  some providers whose domain lists sit behind a sign-in. A row can be
  added for any of them once a public page gives the name.
