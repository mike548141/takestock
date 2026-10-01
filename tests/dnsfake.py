"""Synthetic ``dig`` transcripts for the DNS collector tests.

Composed by hand in the layout ``dig`` prints (a header line with the
status, a flags line, then ANSWER and AUTHORITY sections). Every name is
under a reserved domain and every address is from a documentation range.
"""

from __future__ import annotations

from collections.abc import Callable

#: Documentation-range addresses standing in for three public resolvers.
RESOLVERS = ("192.0.2.53", "198.51.100.53", "203.0.113.53")


def dig_text(status: str = "NOERROR", answer: list[str] | None = None,
             authority: list[str] | None = None, flags: str = "qr rd ra") -> str:
    """One ``dig`` transcript. Records are ``"<owner> <ttl> IN <type> <rdata...>"``."""
    answer = answer or []
    authority = authority or []
    lines = [
        "; <<>> DiG <<>> example",
        ";; global options: +cmd",
        ";; Got answer:",
        f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1",
        f";; flags: {flags}; QUERY: 1, ANSWER: {len(answer)}, "
        f"AUTHORITY: {len(authority)}, ADDITIONAL: 1",
        "",
    ]
    if answer:
        lines += [";; ANSWER SECTION:", *answer, ""]
    if authority:
        lines += [";; AUTHORITY SECTION:", *authority, ""]
    lines += [";; Query time: 1 msec", ";; SERVER: 192.0.2.53#53(192.0.2.53)", ""]
    return "\n".join(lines)


def table_reader(table: dict[tuple, str], default: str | None = None) -> Callable[..., str]:
    """A reader that looks its arguments up in ``table``; unknown questions get NXDOMAIN."""
    fallback = default if default is not None else dig_text("NXDOMAIN")

    def read(*args: object) -> str:
        return table.get(tuple(args), fallback)
    return read
