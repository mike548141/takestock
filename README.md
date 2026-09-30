# takestock

Take stock of an IT estate: what it runs, how it is protected, and what it
needs next.

takestock collects evidence from an estate (network probes, DNS, certificate
logs, and exports from the management tools you already run) and produces:

- **a cryptographic bill of materials**: every protocol, algorithm, key and
  certificate found, graded against current guidance and ready for
  post-quantum planning (CycloneDX CBOM);
- **a draft configuration register**: a CMDB schema plus every configuration
  item found, cryptographic or otherwise;
- **an IP address plan** built from the addresses the evidence actually shows;
- **standards conformance notes**, starting with New Zealand's Secure
  Government Email framework: every mandatory and recommended requirement,
  measured or explicitly marked unmeasurable;
- **requirements derived from the findings**, ready to hand to a procurement.

> **Status:** early. The repository holds its skeleton and its publication
> guard; the tool is being built. Nothing here is ready to use yet.

## Contributing

Run `make hooks` once, then `make check`. takestock carries **no
organisation's data**: every example and fixture is synthetic (see
`CLAUDE.md` § *The rule that outranks everything else here*), and
`tools/guard.py` enforces the parts of that a machine can check.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
