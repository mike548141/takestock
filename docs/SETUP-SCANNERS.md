# Setting up the scanners

takestock's active collectors drive external tools: `nmap`, `openssl`,
`ssh-audit` and `ike-scan`. None is a Python dependency and none is
installed with takestock. This guide says which collector needs which tool,
how to install each, and the **authorisation record** a target profile must
carry before any active probe will contact a host.

What each collector reads and concludes is in
[`COLLECTORS.md`](COLLECTORS.md).

## Before you probe anything

Active probes send real packets to real machines. Run them only against
hosts you are authorised to test, and record that authorisation in the
target profile (see [The authorisation record](#the-authorisation-record)).
Without the record, every active collector contacts nothing.

## Which tool each collector needs

| Tool | Used by | Without it |
|---|---|---|
| `dig` | `ct_dns`, `spf_senders`, `dnssec`, `dane`, `caa`, `dns_zones`, `hsts` (HTTPS records) | DNS readings fail; `dnssec`, `dane` and `caa` read nothing and say so |
| `curl` | `ct_dns` (search service, MTA-STS policy), `hsts`, `plaintext_scan` (cleartext confirmation), internet-registry lookups for the IP plan | `hsts` does not run and says the run holds no HSTS evidence |
| `nmap` | `tls_scan`, `plaintext_scan`, `smb_scan`, `rdp_scan`; fallback for `ssh_audit` | `plaintext_scan`, `smb_scan` and `rdp_scan` report that they did not run. `tls_scan` writes an `unknown` row per endpoint whose note reads like an endpoint that did not answer, so check `nmap` is installed before trusting those rows |
| `openssl` | `tls_scan` (version pins), `smtp_starttls`, `implicit_tls` | Versions that could not be asked about are flagged unknown, not absent |
| `ssh-audit` | `ssh_audit`, `ssh_audit_inside` (preferred) | The probe falls back to `nmap`, which reads the algorithm lists but not the banner, key sizes or known vulnerabilities |
| `ike-scan` | `ike_scan` | Each gateway gets an `unknown` row and a coverage gap |

`dig` and `curl` are needed by the passive collectors as well, so install
them first.

## Installing

### macOS (Homebrew)

```bash
brew install nmap bind
pipx install ssh-audit
```

`bind` provides `dig`; macOS already has `curl`, and an `openssl` (which is
LibreSSL; see [Which `openssl`](#which-openssl)). For `ike-scan`, build from
source (below) if your package manager has no package for it.

### Debian and Ubuntu

```bash
sudo apt install nmap openssl dnsutils curl ike-scan
pipx install ssh-audit
```

Package names vary between releases (`dnsutils` is `bind9-dnsutils` on some);
check with `apt search` if one is not found.

### ike-scan from source

```bash
git clone https://github.com/royhills/ike-scan.git
cd ike-scan
autoreconf --install
./configure
make
```

Then either install it (`sudo make install`) or point takestock at the
binary:

```bash
export TAKESTOCK_IKE_SCAN=/path/to/ike-scan/ike-scan
```

takestock asks `ike-scan` for a random source port (`--sport=0`), so it does
not need the privileged port 500.

### Check what is on the path

```bash
for t in dig curl nmap openssl ssh-audit ike-scan; do printf '%-10s ' "$t"; command -v "$t" || echo MISSING; done
openssl version
python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
```

Run this in the same shell, with the same `PATH`, that will run takestock.
A tool installed under a user directory is easy to miss from a scheduled job
or a different shell.

## Which `openssl`

`tls_scan`, `smtp_starttls` and `implicit_tls` ask a server about one TLS
version at a time with `openssl s_client`. The question can only be asked if
the local `openssl` is willing to offer that version.

OpenSSL 3.0 and later no longer offer SSL 3, TLS 1.0 or TLS 1.1 at their
default security level ("This results in SSL 3, TLS 1.0, TLS 1.1 and DTLS 1.0
no longer working at the default security level of 1 and instead requires
security level 0", OpenSSL 3.0 migration guide). takestock does not lower
the security level. A local refusal can then look like the server declining
the version, which would make an old version read as refused when it was
never asked about. For the version pins, use an `openssl` that still offers
TLS 1.0 and 1.1, and read a "refused" TLS 1.0 or 1.1 from `smtp_starttls` or
`implicit_tls` with that in mind. (`tls_scan` also enumerates versions with
`nmap`, which does not rely on the local `openssl`, and keeps any version
`nmap` saw.)

The single default handshake `tls_scan` makes to read the server's chosen
key-exchange group uses Python's own TLS library, so whether the client
offers post-quantum hybrid groups depends on the OpenSSL that Python is
linked to (the last line of the check above). If it offers none, the row
says so rather than concluding anything about the server.

## Settings from the environment

| Variable | Used by | Sets |
|---|---|---|
| `TAKESTOCK_SSH_AUDIT` | `ssh_audit` | The `ssh-audit` executable, else `PATH` |
| `TAKESTOCK_IKE_SCAN` | `ike_scan` | The `ike-scan` executable, else `PATH` |
| `TAKESTOCK_IKE_MAX_PROBES` | `ike_scan` | Probes per gateway (default 32). A sweep that runs out is reported as truncated |
| `TAKESTOCK_IKE_PROBE_DELAY` | `ike_scan` | Seconds between probes (default 1) |
| `TAKESTOCK_IKE_RETRY` | `ike_scan` | `ike-scan` retries per probe (default 2) |
| `TAKESTOCK_IKE_TIMEOUT_MS` | `ike_scan` | Per-probe timeout in milliseconds (default 500) |
| `TAKESTOCK_HSTS_THIRD_PARTY_READS` | `hsts` | Reads of each outside provider's endpoint (default 3) |
| `TAKESTOCK_CT_TOKEN` | `ct_dns` | The certificate-transparency search service's API token, if it issues one |

On macOS the certificate-transparency token may instead be kept in the
keychain as a generic password named `takestock-ct-token`. The token is
passed to `curl` on standard input, never on the command line.

## The authorisation record

Whether an active probe may run is a property of the **target profile**,
never of how the tool was started. Every active collector checks the
profile's `authorisation:` stanza before it contacts anything:

```yaml
authorisation:
  scope: Published web and mail endpoints of Example Widgets Ltd
  authorised_by: Security manager
  date: 2030-01-31
```

All three fields must be present and non-empty. If any is missing, the
collector returns one failure line, `REFUSED, nothing contacted`, naming
what is missing, and no rows.

### Probes inside the network

Probes that run inside the organisation's network (`smb_scan`, `rdp_scan`,
`ssh_audit_inside`) each need their own named, dated record under the same
stanza, keyed by the `scan_targets` group they read:

```yaml
authorisation:
  scope: Published web and mail endpoints of Example Widgets Ltd
  authorised_by: Security manager
  date: 2030-01-31
  smb_445:
    scope: File servers on the head-office network
    authorised_by: Infrastructure lead
    date: 2030-01-31

scan_targets:
  smb_445:
    - files-01.example.test
    - {host: files-02.example.test, ip: 192.0.2.21}
```

They are off unless the profile asks for them: a profile that does not
declare `scan_targets.smb_445` never hears from `smb_scan`. A profile that
declares the group, even empty, must carry its record.

Hosts must be named **one at a time**. Subnets, ranges, wildcards and lists
are refused by construction; a host named twice is refused; a list longer
than its ceiling (60 hosts) is refused rather than cut short, because a
truncated probe reports the hosts it skipped as though nothing were there.

### What the record is, and is not

Every one of these checks refuses to probe rather than warning afterwards,
because a probe that has left the machine cannot be recalled.

The stanza is a record, not a security control. Anyone who can edit the
profile can write one. It exists so that a program embedding takestock
cannot point the probes at hosts nobody authorised, and so that every run
states who authorised it and when.

## What the probes send

Each active collector prints or saves its plan where it has one, and is
deliberately slow. In outline:

| Collector | Per target |
|---|---|
| `tls_scan` | nmap `ssl-enum-ciphers`, four pinned `openssl` handshakes (TLS 1.0 to 1.3), one default handshake, nmap `ssl-cert` |
| `smtp_starttls` | four `openssl -starttls smtp` handshakes |
| `implicit_tls` | a pinned handshake per TLS version on each of 465, 993 and 995 that the plan names |
| `hsts` | one HTTPS request to `/` (three for an outside provider's endpoint), and a DNS HTTPS-record query |
| `plaintext_scan` | one `nmap -sT` connect scan of the named ports only, at most 10 packets a second with a 200 ms delay, one retry and a 2-minute host timeout; two seconds between hosts; one `curl` request to confirm a cleartext page |
| `ike_scan` | up to the probe budget of IKEv1 Main Mode probes, one second apart, and one IKEv2 probe |
| `ssh_audit` | one `ssh-audit` connection, or one nmap `ssh2-enum-algos` run; never a login |
| `ssh_audit_inside` | as `ssh_audit`, one host at a time, two seconds between hosts and thirty between batches |
| `smb_scan` | nmap's three SMB negotiation scripts on 445/tcp, plus one NetBIOS name query to 137/udp; never authenticates |
| `rdp_scan` | nmap `rdp-enum-encryption` on the named port; never sends a credential |

## What the results contain

Raw transcripts are saved beside each observation so a finding can be
checked later. Session secrets are redacted from TLS transcripts, and
cookies, authorisation headers and per-request trace ids from HTTP captures.
What remains still maps where an estate's cryptography is weak and how its
hosts are named. Treat observations, and every report built from them, as
sensitive, and keep them out of any repository you publish.
