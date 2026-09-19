## Goal

Produce a ranked, evidence-grounded set of improvement directions that make
findbtc more generally useful, then get approval on the top slice to pursue
as follow-up goals. This plan covers the brainstorm itself: survey,
rank, and define the next evidence step per idea. No implementation in
this plan.

## Success Criteria

- Every proposed direction traces to a cited workspace fact (code path,
  doc gap, CI/release observation, or recorded non-goal) or is marked
  an assumption.
- Directions are ranked by expected impact × effort with the ranking
  rationale stated.
- The top 3 directions each have a defined next evidence step (spike or
  measurement) that fits one focused session.
- The user approves, amends, or cancels the ranked list.

## Context And Current Facts

- findbtc scans block devices/images for cryptocurrency wallet traces:
  Core wallet markers, BIP39 (exact/fuzzy), WIF/xkeys, ETH keystores,
  Electrum, descriptors, SLIP39, Lightning, MetaMask vaults
  (`README.md` 1-25). Secrets never print by default.
- CLI is one binary with ~20 flags across 8 modes: scan, `-report`,
  `-dfxml`, `-verify-case-log`, `-hashes`, `-salvage`, `-watch`,
  `-fs`/`-unallocated-only` (`main.go` 22-44). No subcommands, config
  file, shell completions, or man page.
- Scan pipeline (`detector/detector.go`): single `scanBlocks` goroutine,
  4 KB blocks, 20-block pool, overlap window; zip/gzip nested targets
  to depth 8; one zip member may inflate up to 1 GiB in RAM
  (`maxZipMemberBytes`). No `Benchmark*` functions anywhere; no
  directory-tree mode (no `WalkDir`/`ReadDir` outside tests).
- Inputs: raw, EnCase E01 (compressed/stored, multi-segment;
  EWF2 `Ex01`/`Lx01` and SMART `S01` refused per `detector/ewf.go`
  header), split raw `.001…`, NTFS/ext via `-fs` with manual
  `-fs-offset`. Partition tables are not followed (`README.md`:
  "partition tables are not followed"). Checkpoint/resume refused for
  range scans (`detector.go` 264, `main.go` 86/172).
- Outputs: human text, `-json` JSONL hits (no published JSON Schema),
  `-report` triage, `-dfxml` (NIST-validated), `-case-log` JSONL +
  `-verify-case-log`, carves, watch CSV/JSON.
- Recorded non-goals that bound past scope (`GOALS.md`): old-style
  Electrum seeds, APFS "unless demand proves it", RAID rebuild,
  Sleuth-Kit clone, case management, timeline analysis,
  altcoin-of-the-week, closed formats without a spec, private-key
  derivation (never), online-by-default anything.
- Known code limitations: zip resilience TODO
  (`zip_scanner.go` 68); ext double/triple-indirect out of scope
  (`fsext.go` 264); descriptor/MetaMask size caps; fuzzy-phrase
  spacing limits (`bip39.go` 35).
- CI (`.github/workflows/ci.yml`): `gofmt`, build, vet, tests on
  ubuntu/macos/windows, fuzz smoke on ubuntu. Pins Go `stable` only.
  This session proved version sensitivity twice: Go 1.27 `flate`
  stores tiny inputs that 1.24 compressed (7 test failures), and
  Windows CRLF checkouts broke `gofmt` plus embedded wordlists (fixed
  via `.gitattributes` + `splitWordlist`).
- Release (`.goreleaser.yaml`, `release.yml`): 6 platform archives,
  checksums, per-archive SPDX SBOMs, SLSA v1 build-provenance
  attestation; Homebrew cask generated but upload-skipped (tap repo
  does not exist). No Linux packages, no container image, no Windows
  package-manager metadata.
- Distribution drift: `README.md` install section points at
  `jakewins/findbtc` releases and a `jakewins/findbtc` Homebrew tap;
  live releases and CI actually run at `pauljones0/findbtc`, and the
  named tap repo returns 404. `go.mod` module path and SBOM still say
  `github.com/jakewins/findbtc`.
- Library surface: `detector` package is importable (`ScanWithOptions`,
  `Options`, `Detection`) but has no `doc.go`, no worked example, and
  no stability statement.

## Constraints And Non-goals

- Privacy and offline-by-default stay absolute (Goals 1-8 global
  criteria): no idea may weaken them; broadening detection must keep
  the per-format false-positive bar (silence on random bytes + repo
  prose, enforced by tests).
- This plan proposes and ranks; it does not implement, and it does not
  pre-approve any code change.
- Ideas that contradict standing safety non-goals (private-key
  derivation, online-by-default, seed brute force) are excluded, not
  ranked.
- Assumption: "24 hour" signals depth of investigation, not a
  wall-clock schedule; output is this durable proposal plus approved
  follow-ups. If a scheduled revisit was meant instead, say so (see
  Open Questions).

## Key Decisions

1. **Broaden inputs before detections.** Recommend prioritizing input
   breadth (partition tables, directory-tree mode, refused image
   variants) over new secret types. Rationale: input gaps block entire
   user classes (anyone with a full-disk image; anyone sweeping a live
   system), while each new detector adds FP risk against the standing
   bar. Rejected alternative: lead with general secret scanning —
   higher FP risk and dilutes the forensic-wallet positioning before
   the input story is complete.
2. **Keep the flag-based CLI; generate around it.** Recommend no
   subcommand rewrite: 8 modes share global flags (`-json`,
   `-case-log`) that a rewrite would churn. Instead add generated
   shell completions and a man page, which need no UX migration.
   Rejected: full CLI framework migration (churn without new
   capability).
3. **Test the Go versions users build with.** Recommend a CI matrix of
   current stable plus the previous minor Go release after two
   version-sensitive failures in one session. Cheap, prevents
   recurrence. Also adopt supply-chain and static-analysis gates
   alongside it (see idea 2).
4. **Resolve release ownership before polishing distribution.**
   `pauljones0` vs `jakewins` changes README URLs, tap owner,
   attestation `--repo`, and module path. Recommend deciding this
   first; distribution ideas below are conditional on it.

## Recommended Approach

Rank by (new users or workflows unlocked) × (days to first value),
grounded in the facts above. Fix drift first (ideas 1-3: hours),
then unlock inputs (4-6: days each), then expand outputs, robustness,
and distribution (7-12). Pursue the top 3 as the next goals after
approval; keep the rest as a parked backlog with defined first steps.

## Work Plan

Ranked idea list. Each item: grounding, sketch, next evidence step.

### 1. Fix install/distribution drift (hours)

- Grounding: README install URLs vs observed reality (Context).
- Sketch: point install/verify/tap instructions at the true release
  home (pending Decision 4); correct or drop the Homebrew stanza;
  align `docs/RELEASE.md` repo references.
- Next evidence step: list every `jakewins` reference
  (`grep -rn jakewins -- . ':!dist'`) and classify keep vs rewrite.

### 2. CI Go-version matrix + static gates (hours)

- Grounding: two version-sensitive failures in one session; CI pins
  `stable` only; `go.mod` says `go 1.24.0`.
- Sketch: matrix of current stable plus the previous minor; add
  vulnerability scanning and a static analyzer to CI; decide the
  documented minimum Go version from the matrix result.
- Next evidence step: draft matrix edit, run it on a branch, confirm
  both toolchains green.

### 3. Publish a hits JSON Schema (hours)

- Grounding: `-json` JSONL is the interchange for `-report`,
  `-dfxml`, `-watch`, carves — with no schema document.
- Sketch: versioned schema file + `Detection`-struct conformance test
  (generate sample from tests, validate).
- Next evidence step: enumerate `Detection` JSON tags and optional
  fields; confirm one schema covers raw/fs/reveal variants.
- Sources: `https://json-schema.org/`

### 4. Partition-table parsing (days)

- Grounding: `-fs-offset` is manual; "partition tables are not
  followed" (`README.md`); every full-disk image hits this.
- Sketch: partition-table parser covering the common PC schemes,
  locating NTFS/ext partitions and auto-seeding `-fs` ranges;
  unknown/hybrid layouts error loudly.
- Next evidence step: build a 3-partition fixture (empty NTFS, empty
  ext, raw), parse with a spike, cross-check offsets against system
  partitioning tools.

### 5. Directory-tree scan mode (days, biggest generality unlock)

- Grounding: no directory support in non-test code; single-path input
  only. Unlocks live-system sweeps (leaked secrets on a laptop,
  repo audits) with the existing detectors.
- Sketch: new walk mode reusing `fileScanTarget` per file + case log
  per file (JSONL already appends); symlink/permission policy explicit
  (no follow by default); per-file isolation so one unreadable file
  never aborts the walk.
- Next evidence step: spike the walker over this repo; assert it
  finds the documented fixture needles and stays silent on prose.

### 6. Refused image variants, evaluated (days)

- Grounding: `detector/ewf.go` refuses EWF2 `Ex01`/`Lx01` and SMART
  `S01`; acquisition tools increasingly default to newer variants.
- Sketch: evaluate one variant at a time against real tooling
  (acquire → parse → byte-compare, mirroring the E01 method);
  refuse-with-message until then.
- Next evidence step: acquire the smallest possible sample of one
  variant and document section layout vs E01.

### 7. Benchmarks + throughput pass (days)

- Grounding: no benchmarks; single reader goroutine, 4 KB blocks,
  20-block pool; 1 GiB in-RAM zip inflation cap.
- Sketch: add `Benchmark*` scans (raw, nested zip, E01) on fixed
  fixtures; then parallelize read/decode or widen blocks guided by
  profiles, keeping the overlap/exact-offset contract; revisit the
  inflation cap with streaming members.
- Next evidence step: land benchmarks, publish MB/s table for the
  three fixtures on one machine.

### 8. Hostile-image resource audit (days)

- Grounding: scanner ingests untrusted bytes; 1 GiB RAM cap per zip
  member, unbounded E01 chunk-table trust, depth cap 8 (all
  `detector.go` / `ewf.go` constants without adversarial tests).
- Sketch: threat-model the parsers (zip bombs, E01 table lies,
  gzip streams), add worst-case fixtures with time/RAM assertions.
- Next evidence step: craft a 1 GiB-claim zip and an E01 with
  maximal chunk table; measure time/RAM vs caps.

### 9. Checkpoint/resume for range scans (days)

- Grounding: explicitly refused (`detector.go` 264); `-fs` and
  `-unallocated-only` runs on large images cannot resume.
- Sketch: journal `(range_index, offset)` instead of a single offset;
  resume validates the range list still matches before continuing.
- Next evidence step: prototype the journal schema against a
  3-range fixture with a mid-run kill.

### 10. OS packages via nFPM (days)

- Grounding: releases ship only tarballs/zips; Linux users get no
  managed install. nFPM documents deb/rpm/apk/archlinux/msix
  generation from GoReleaser config.
- Sketch: add `nfpms` section (deb+rpm first), install/upgrade smoke
  in containers.
- Next evidence step: snapshot build with nFPM locally; install the
  deb in a container and run `-version` + one fixture scan.
- Sources: `https://goreleaser.com/customization/nfpm/`

### 11. Library API pass: docs, example, stability (days)

- Grounding: importable `detector` package with no `doc.go`,
  example, or compatibility statement.
- Sketch: `doc.go` with end-to-end example (scan bytes → handle
  detections), document `Options`/`Detection` stability tiers,
  keep `Detection` JSON tags frozen per the Idea 3 schema.
- Next evidence step: draft the example against the current API;
  list every wart it exposes (naming, error values, options gaps).

### 12. Opt-in general secret profiles (weeks, product decision)

- Grounding: detectors are wallet-shaped; the pipeline is generic
  (blocks → matchers → carves). Broadens audience to secret
  hygiene (repos, laptops, images) once Idea 5 exists.
- Sketch: profile flag (e.g. `-profile=secrets`) adding
  non-wallet matchers (private-key blocks, credential shapes)
  under the same FP bar and carve/DFXML machinery; default
  profile unchanged.
- Next evidence step: depends on Idea 5; spike one matcher
  (e.g. an armored private-key block) with FP fixtures first.

### 13. Container image (conditional)

- Grounding: no image published; labs often prefer pinned images
  over host binaries.
- Sketch: evaluate the current GoReleaser-supported container path
  (the v1 Docker pipe is marked deprecated in its docs) or a
  minimal Dockerfile + container-registry workflow; pin by digest
  in docs.
- Next evidence step: read the current container docs and build one
  image locally; record size, USER, and volume-mount scan story.
- Sources: `https://goreleaser.com/customization/docker/`
  (deprecation notice; replacement path unverified — evaluate, do
  not assume).

### 14. Forensic-pipeline ingest evaluation (conditional)

- Grounding: DFXML export validates; no other pipeline ingest
  exists. Demand unknown.
- Sketch: survey which ingest formats real cases request, prototype
  the cheapest one against a sample toolchain, keep DFXML canonical.
- Next evidence step: collect three concrete toolchain asks (user
  interviews / issues) before writing any exporter.

## Validation Plan

- Proposal quality: each idea above cites its grounding; no
  external product claim appears without a Sources URL or an
  explicit "evaluate" framing. Verify by re-reading this file.
- Idea 1: `grep` inventory complete; README install steps executed
  verbatim on a clean machine (or container) for one platform.
- Idea 2: branch CI run green on both Go versions; new gates fail
  on an intentionally introduced finding (negative control), then
  pass on revert.
- Idea 3: sample `hits.jsonl` from existing tests validates;
  schema rejects a mutated field (negative control).
- Idea 4: spike offsets match system tool output on the fixture;
  unknown layouts error with the volume id attached.
- Idea 5: repo self-scan finds documented needles, silent on
  prose; symlink loop + unreadable file fixtures pass.
- Idea 6: byte-compare vs vendor tool export on the sample image.
- Idea 7: benchmark numbers committed; any optimization keeps the
  full suite green and moves the table measurably.
- Idea 8: worst-case fixtures run within documented time/RAM
  bounds in CI (generous margins, no flakes).
- Idea 9: kill mid-run, resume, byte-identical detection set vs
  uninterrupted run.
- Idea 10: container install + `-version` + fixture scan green
  from the built package.
- Idea 11: example compiles under `go test` (`Example*`) and a
  second reader follows it without asking questions.
- Idea 12: new matcher silent on the 1 MB random + prose
  fixtures; documented recall fixture found.
- Idea 13: digest-pinned pull + mount-scan works per docs.
- Idea 14: three documented asks exist before code.
- Highest-risk validation: Idea 5's FP bar on real-world files —
  live systems contain far messier bytes than fixtures; start
  with a small opt-in file set.

## Risks / Rollback

- Scope creep: 14 ideas exceed any single session; mitigation is
  the ranking — approve a top slice, park the rest here.
- Product dilution (Idea 12): new profiles could erode the FP bar
  and forensic focus; mitigation is the opt-in flag, unchanged
  defaults, and per-format tests.
- Ownership churn (Decision 4): renaming module paths or release
  homes breaks existing install instructions and SBOM identity;
  do it once, with redirects/notes, before Ideas 1/10/13.
- Rollback: this plan changes nothing; each future idea lands
  behind its own tests and can revert independently.

## Open Questions

- Release ownership: is `pauljones0/findbtc` the permanent home
  (update module path/docs/attestation repo), or is this work
  headed back upstream to `jakewins/findbtc`? Blocks Ideas 1, 10,
  13 as specified.
- "24 hour": depth signal (assumed) vs a scheduled 24h-later
  follow-up — want a recurring check-in scheduled?
- Idea 12 direction: any categorically off-limits secret types
  beyond the standing exclusions?

## Sources

- `https://json-schema.org/` — JSON Schema standard site; supports
  Idea 3.
- `https://goreleaser.com/customization/nfpm/` — nFPM formats
  (apk, deb, rpm, archlinux, msix) generated from GoReleaser
  config; supports Idea 10.
- `https://goreleaser.com/customization/docker/` — v1 Docker
  pipe marked deprecated; Idea 13 stays conditional pending
  evaluation of the current path.
