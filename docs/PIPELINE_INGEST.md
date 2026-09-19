# Pipeline ingest evaluation (Goal 22)

Question: is DFXML enough as findbtc's pipeline ingest format, or do
real cases need another interchange?

## Demand sought

- `pauljones0/findbtc` (this repo): issues are disabled, so there is
  no public channel where toolchain asks could have landed.
- `jakewins/findbtc` (upstream): 8 issues total (2026-09-19), all
  usage/build questions — "I found some traces, whats next", "Scan
  for encrypted wallet.dat", "Howto scan an image file", "Building /
  compiling", "how to get the wallet.dat file from the scan result",
  two open bug reports (gzip header, Windows scan). None asks for an
  ingest or export format.
- User interviews: no operators were available in this session.

Result: zero documented toolchain asks for another format.

## What already ships

DFXML is not the only interchange, only the only *forensic-XML*
one. Every scan already emits:

- `hits.jsonl`: versioned JSONL (`schema/hits-v1.json`) — the
  universal interchange; every SIEM, log pipeline, and `jq`-shaped
  toolchain ingests newline-delimited JSON.
- DFXML (`-dfxml`): for fiwalk-style forensics pipelines and
  feature-file annotators.
- CSV/JSON address lists (`-watch -watch-format`).
- Case-log JSONL (`-case-log`) for verification pipelines.

Any consumer that takes JSON can already take findbtc output today;
anything needing DFXML gets it. A new exporter (SARIF, STIX, …)
would serve a toolchain nobody has named.

## Decision: DFXML-only, no new exporter

No exporter ships without demonstrated demand (goal non-goal), and
none was demonstrated. Re-open this evaluation when a concrete ask
arrives with a sample consumer to validate a prototype against —
that validation step is part of the goal for a reason.

One structural gap is worth fixing regardless: with issues disabled,
future demand stays invisible. Enabling issues (or discussions) on
this repo would give toolchain asks somewhere to land.
