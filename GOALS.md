# findbtc goal queue

Ranked pain-point goals. Exactly one is the active session goal at a time.
Each goal is complete only when its audit answers YES to: **"did we
completely solve the pain point?"**

## Chain rule (read this when any goal completes)

1. Check every audit box of the active goal, with `gofmt`/`build`/`vet`/`test`
   green (note: on this machine Go needs `GOCACHE`/`GOMODCACHE` pointed at
   writable dirs, e.g. `/tmp/fbt-gocache` and `/tmp/fbt-gomodcache`).
2. Mark the goal `complete` in the status table with the commit hash.
3. Create the next `queued` goal as the new active session goal, using its
   Goal text below as the objective.
4. Continue. Never skip, never run two at once. If blocked, mark `blocked`
   with the reason and stop for the user.

## Status

| # | Goal | Status | Done commit |
|---|------|--------|-------------|
| 1 | Scan triage report | complete | a06a5c8 |
| 2 | Crack-ready export for encrypted wallets | complete | a06a5c8 |
| 3 | Fuzzy / partial BIP39 finder | complete | a06a5c8 |
| 4 | Fragment-aware salvage | complete | a06a5c8 |
| 5 | Watch-only balance triage | complete | a06a5c8 |
| 6 | More wallet formats by demand | complete | a06a5c8 |
| 7 | Filesystem-aware layer | complete | a06a5c8 |
| 8 | Forensics packaging | complete | a06a5c8 |
| 9 | Fix install/distribution drift | complete | f5056bf |
| 10 | CI Go-version matrix + static gates | complete | cf4c69d |
| 11 | Hits JSON Schema | active | - |
| 12 | Partition-table parsing | queued | - |
| 13 | Directory-tree scan mode | queued | - |
| 14 | Refused image variants | queued | - |
| 15 | Benchmarks + throughput | queued | - |
| 16 | Hostile-image resource audit | queued | - |
| 17 | Checkpoint/resume for range scans | queued | - |
| 18 | OS packages via nFPM | queued | - |
| 19 | Library API pass | queued | - |
| 20 | Opt-in secret profiles | queued | - |
| 21 | Container image | queued | - |
| 22 | Pipeline ingest evaluation | queued | - |

## Global done criteria (every goal)

- `gofmt -l .` clean; `go build ./...`, `go vet ./...`,
  `go test ./... -count=1` green.
- Committed tests proving the pain is solved (fixtures/golden files, plus an
  independent oracle where feasible — never a test that just repeats the
  implementation's assumption).
- README/docs updated for user-facing changes.
- Privacy: no key/seed material in stdout, logs, or JSON by default. Carved
  `.bin` files are the only place secrets may land, with warnings.
- Offline by default; any network access is opt-in with explicit consent.

## Goal 1 — Scan triage report

**Pain to completely solve:** after a scan, the user stares at raw hits and
cannot answer "is there anything here worth pursuing?" Hope-scans of old
drives and pro triage both die in a pile of undifferentiated detections.

**Completely solved when:**
- [x] One offline step turns `-json` hits into a report: per-type counts,
      deduped hits, per-hit confidence, likely-encrypted flags, byte-offset
      distribution, and a prioritized next-step playbook per wallet type.
- [x] Report works from saved `hits.jsonl` (no rescan) and is documented in
      the README triage workflow.

**Execute:**
1. Report schema + needle→wallet-type classifier + dedupe + JSON writer +
   golden tests on fixture JSONL.
2. CLI `-report hits.jsonl` (human + JSON output) + README.
3. Confidence tuning + per-type playbook text.
4. Optional: disk-map/HTML rendering.

**Non-goals:** balance lookups (Goal 5), cracking (Goal 2), new detectors.

**Verify:** golden test on a fixture `hits.jsonl` covering every detection
kind; dedupe test (same needle+block reported once); gates green.

## Goal 2 — Crack-ready export for encrypted wallets

**Pain to completely solve:** the user found an encrypted wallet but forgot
the password — the highest-volume recovery pain (recovery services report
~70 requests/day). Today they must hand-extract hashes with version-fragile
scripts (`bitcoin2john` fails on wallets newer than it understands).

**Completely solved when:**
- [x] For encrypted hits (`mkey`/`crypted_key`/keystore crypto params),
      findbtc emits a crack-ready hash in a documented,
      BTCRecover/hashcat/John-compatible form, plus KDF metadata and the
      exact follow-up commands.
- [x] Works offline from carved bytes; partial/corrupt records produce a
      clear "not enough material" error instead of a bogus hash.

**Execute:**
1. Parse `mkey` record (salt, iterations, method, encrypted key) from
   carved BDB bytes; golden tests on synthetic wallets old + new.
2. Hash writer in the documented format + self-check (re-derive and compare
   where the password is known in tests only — never log it).
3. Keystore crypto-params export path.
4. Docs: end-to-end password-recovery runbook with BTCRecover.

**Non-goals:** cracking passwords inside findbtc; cloud cracking services.

**Verify:** synthetic `wallet.dat` old and new → hashes byte-identical to an
independent extractor; corrupt-truncation fixtures → clean errors; gates.

## Goal 3 — Fuzzy / partial BIP39 finder

**Pain to completely solve:** findbtc only reports perfect checksum-valid
phrases, but the realistic recovery case is a *nearly*-complete phrase
(1–4 missing words, typos, wrong order). Today those recoverable phrases
are silently missed.

**Completely solved when:**
- [x] 12/15/18/21/24-word windows with up to N unknown/invalid words are
      detected; typo candidates (bounded edit distance) and 12-word
      reorder hints are reported.
- [x] Default output reports positions and gap patterns, never words; an
      explicit `--reveal` exists for owner recovery with loud warnings.
- [x] False-positive rate measured on a noise corpus and documented.

**Execute:**
1. Near-miss window scanner + gap-pattern reporting + fixtures.
2. Typo candidates via bounded edit distance against the wordlist.
3. 12-word reorder hints (checksum-guided, capped work).
4. `--reveal` flag + FP measurement + docs.

**Non-goals:** full-seed brute force (astronomical; scam-adjacent); online
"seed recovery services".

**Verify:** synthetic fragments with missing/typo/shuffled words are found
with correct gap patterns; noise corpus FP rate under the documented bar;
privacy test asserts words appear nowhere in default output; gates.

## Goal 4 — Fragment-aware salvage

**Pain to completely solve:** file carving fails on fragmentation — the #1
carver limitation. findbtc's fixed context window cannot reassemble a
wallet scattered across non-contiguous clusters.

**Completely solved when:**
- [x] BDB page-chain stitching and SQLite page reassembly turn
      multi-fragment fixtures into openable/salvageable databases (or
      validated page sets), falling back to window carve when stitching
      is impossible; the report says what was stitched.
- [x] Carve sidecars record page maps and provenance (which offsets
      contributed).

**Execute:**
1. BDB page-header parser + chain stitching + fixtures.
2. SQLite page reassembly + `sqlite3` open check on fixtures.
3. Stitch-aware carve mode + sidecar page maps.
4. Docs: when salvage can/can't work (TRIM, overwrite).

**Non-goals:** filesystem-level undelete (Goal 7); repairing logically
corrupt records beyond page salvage.

**Verify:** fragmented synthetic BDB/SQLite wallets → salvaged output opens
in independent tools; single-fragment case still works; gates.

## Goal 5 — Watch-only balance triage

**Pain to completely solve:** the user found key material but cannot tell
whether any funds exist — and the obvious move (pasting keys/xpubs into a
website) is both a privacy leak and the #1 phishing pattern.

**Completely solved when:**
- [x] findbtc derives addresses locally from extended public keys (correct
      script type per version, sane gap limit) and exports an address list
      the user can check anywhere.
- [x] Any balance lookup is opt-in via an explicit endpoint flag with
      consent + local-node/Tor docs; the default path makes zero network
      calls (test-enforced).

**Execute:**
1. xpub parse + address derivation (P2PKH/P2SH-P2WPKH/P2WPKH per version;
   evaluate `btcsuite` hdkeychain vs minimal deps).
2. Address-list export (CSV/JSON) from hits or carved xpubs.
3. Optional `--balance-endpoint` plugin + privacy docs.
4. Playbook wiring into the Goal 1 report.

**Non-goals:** private-key derivation (never); built-in explorer API keys;
online-by-default anything.

**Verify:** testnet vectors → expected addresses; default path performs no
network I/O under test; gates.

## Goal 6 — More wallet formats by demand

**Pain to completely solve:** non-Core wallets are invisible: Electrum (own
seed format + files), SLIP39 shares, descriptor checksums, Lightning static
channel backups, browser/mobile vaults.

**Completely solved when:**
- [x] Each shipped format has a validator, FP tests, report classification,
      and a playbook entry. Ship order: Electrum files+seeds → output
      descriptor checksums → SLIP39 → lnd SCB/channel.db → MetaMask vault.

**Execute:** per format: read the spec, add detector + fixtures + noise
corpus FP test, wire classifier/playbook, document.

**Non-goals:** altcoin-of-the-week; closed formats without a spec.

**Verify:** per-format fixtures found, noise FP rate documented, gates.

## Goal 7 — Filesystem-aware layer

**Pain to completely solve:** raw scanning is slow and noisy on big disks,
filenames are lost, and deleted-but-referenced files are missed even though
filesystem metadata still describes them.

**Completely solved when:**
- [x] NTFS MFT and ext inode parsing recover deleted wallet entries with
      names; `--unallocated-only` raw mode skips live data; report shows
      filenames; SSD/TRIM limits documented.

**Execute:**
1. MFT deleted-entry parser + synthetic-image tests.
2. ext inode parser + synthetic-image tests.
3. Unallocated-only scan mode.
4. Report integration + docs.

**Non-goals:** APFS (unless demand proves it); RAID rebuild; Sleuth Kit
clone.

**Verify:** synthetic NTFS/ext images with deleted `wallet.dat` → found by
name; gates.

## Goal 8 — Forensics packaging

**Pain to completely solve:** professional recovery needs a court-ready
workflow: provenance, chain of custody, and image-format support that a raw
scanner does not provide.

**Completely solved when:**
- [x] Case log records source SHA-256, tool version, flags, bad-sector
      ranges, and checkpoint; DFXML/Autopsy-compatible hit export;
      E01/raw/split-image input; write-blocker docs.

**Execute:**
1. Case log + streaming source hash.
2. DFXML export of the Goal 1 report.
3. E01 input support (evaluate libs) + split raw.
4. Docs: forensic workflow end to end.

**Non-goals:** case management; timeline analysis.

**Verify:** sample case export validates against DFXML tooling where
available; tampered source detected via hash; gates.

## Goal 9 — Fix install/distribution drift

**Pain to completely solve:** a new user follows the README install steps
and lands nowhere: install URLs point at `jakewins/findbtc` releases and
a `jakewins/findbtc` Homebrew tap, while live releases and CI actually
run at `pauljones0/findbtc` and the named tap repo returns 404. Every
distribution path below this (packages, images, SBOM identity) inherits
the confusion until ownership is decided and docs match reality.

**Completely solved when:**
- [x] Release ownership is decided and recorded (`pauljones0` permanent
      vs headed back upstream), and README install/verify/tap
      instructions, `docs/RELEASE.md`, and attestation `--repo`
      examples all name the true home.
- [x] The Homebrew stanza is corrected or dropped; no doc points at a
      URL that 404s.
- [x] `go.mod` module path decision recorded (rename now or keep with a
      stated reason); SBOM identity consistent with the decision.

Decision record (Goal 9): `pauljones0/findbtc` is the permanent home
(user-confirmed). Module path renamed to
`github.com/pauljones0/findbtc`; SBOM spot-check confirms the new
identity. `FindbtcDFXMLNS` deliberately keeps the old host: namespace
identifiers must stay stable for existing DFXML consumers. Historical
references in this file and the brainstorm plan are kept as evidence.
Note: `go install ...@latest` resolves only after the rename is pushed;
re-run it verbatim post-push.

**Execute:**
1. Inventory every `jakewins` reference (`grep -rn jakewins -- .
   ':!dist'`) and classify keep vs rewrite.
2. Get the ownership decision from the user.
3. Rewrite docs; rename module path if decided (update imports, SBOM
   spot-check via snapshot build).
4. Execute the README install steps verbatim on one clean platform.

**Non-goals:** new packages/images (Goals 18/21); creating the tap repo.

**Verify:** install steps run verbatim on a clean machine/container;
zero `jakewins` references outside the decided set; gates.

## Goal 10 — CI Go-version matrix + static gates

**Pain to completely solve:** CI pins Go `stable` only, yet this codebase
has proven version-sensitive twice in one session (Go 1.27 `flate`
stores tiny inputs 1.24 compressed; CRLF checkouts broke `gofmt` and
wordlists). A green main today says nothing about the toolchain a user
builds with, and no gate watches for vulnerable deps or static defects.

**Completely solved when:**
- [x] CI tests current stable plus the previous minor Go release on all
      three OSes, green.
- [x] Vulnerability scanning and a static analyzer run in CI and fail
      the build on findings.
- [x] The documented minimum Go version matches the matrix result.

Evidence (Goal 10): branch run 35411949094 green on
stable+oldstable × ubuntu/macos/windows plus the gates job
(govulncheck binary mode clean, staticcheck clean). Negative controls:
staticcheck flags the reintroduced SA5001 in scratch; govulncheck
exits 3 on a scratch binary calling a vulnerable `x/net/html`
symbol. Gates also fixed a real nil-Close bug
(`detector/filesize_linux.go`) and two error-string findings.

**Execute:**
1. Draft the matrix edit + new gates on a branch; confirm green.
2. Negative controls: each new gate must fail on an intentionally
   introduced finding, then pass on revert.
3. Document the minimum version in README/CONTRIBUTING-adjacent docs.

**Non-goals:** supporting EOL Go versions; fixing pre-existing static
findings beyond what the gates require.

**Verify:** branch CI run green on both toolchains x three OSes; negative
controls demonstrated; gates.

## Goal 11 — Hits JSON Schema

**Pain to completely solve:** `-json` JSONL is the interchange every
downstream mode consumes (`-report`, `-dfxml`, `-watch`, carves), but
no schema document exists — integrators guess field shapes, and a
`Detection` struct change can silently break them.

**Completely solved when:**
- [x] A versioned JSON Schema for `hits.jsonl` is published in-repo.
- [x] A committed test generates sample hits from existing tests and
      validates them against the schema; a mutated field fails
      (negative control).
- [x] One schema covers raw/fs/reveal variants, or the variants are
      documented with per-variant schemas.

**Execute:**
1. Enumerate `Detection` JSON tags and optional fields.
2. Write the schema (JSON Schema standard); conformance test +
   negative control.
3. Document stability expectations (ties to Goal 19).

**Non-goals:** changing the hit format; new output formats.

**Verify:** sample hits validate; mutated field rejected; gates.

## Goal 12 — Partition-table parsing

**Pain to completely solve:** every full-disk image forces the user to
hand-find partition offsets for `-fs-offset`; "partition tables are not
followed", so the filesystem layer is unreachable without external
sleuthing on exactly the images that need it most.

**Completely solved when:**
- [x] A partition-table parser covering the common PC schemes locates
      NTFS/ext partitions and auto-seeds `-fs` ranges; no manual offset
      needed for the standard layouts.
- [x] Unknown/hybrid layouts error loudly with the volume identified,
      never silently scan the wrong bytes.

**Execute:**
1. Build a 3-partition fixture (empty NTFS, empty ext, raw).
2. Parser spike; cross-check offsets against system partitioning tools.
3. Wire auto-seeding into `-fs`; error paths + docs.

**Non-goals:** RAID rebuild; APFS (unless demand proves it); exotic
partition schemes without fixtures.

**Verify:** fixture offsets match system tools; unknown layout errors
with volume id; manual `-fs-offset` still works; gates.

## Goal 13 — Directory-tree scan mode

**Pain to completely solve:** findbtc takes a single path — an image or
device. Nobody can sweep a live system, laptop, or repo for leaked
secrets with the existing detectors, which is the largest adjacent
audience for this tool.

**Completely solved when:**
- [x] A walk mode scans directory trees reusing per-file targets, with
      an explicit symlink/permission policy (no symlink follow by
      default).
- [x] Per-file isolation: one unreadable file never aborts the walk;
      per-file case-log records (JSONL already appends).
- [x] Self-scan over this repo finds the documented fixture needles and
      stays silent on prose; symlink-loop + unreadable-file fixtures
      pass.

**Execute:**
1. Walker spike over this repo; needle/silence assertions.
2. Policy (symlinks, permissions, max depth?) + per-file records.
3. Docs: live-system sweep runbook.

**Non-goals:** new secret types (Goal 20); network shares; file watching.

**Verify:** repo self-scan fixtures; loop/unreadable fixtures; gates.

## Goal 14 — Refused image variants

**Pain to completely solve:** `detector/ewf.go` refuses EWF2 `Ex01`/`Lx01`
and SMART `S01`, and acquisition tools increasingly default to newer
variants — users with modern acquisitions cannot scan at all.

**Completely solved when:**
- [x] At least one refused variant is evaluated against real tooling
      (acquire → parse → byte-compare, mirroring the E01 method) and
      either supported with fixtures or refused with a documented,
      actionable message.
- [x] Any supported variant gets the E01 treatment: eager parse,
      checksums verified, stored-hash cross-check where the format has
      one, committed fixture.

**Execute:** per variant: acquire the smallest possible sample, document
section layout vs E01, implement or document refusal, fixtures + docs.

**Non-goals:** closed formats without a spec; RAID/multi-volume spanning
unless the fixture exists.

**Verify:** byte-compare vs vendor tool export on the sample image; gates.

## Goal 15 — Benchmarks + throughput

**Pain to completely solve:** nobody knows how fast findbtc is or where
time goes — no `Benchmark*` exists, the reader is a single goroutine on
4 KB blocks, and one zip member may inflate 1 GiB in RAM. Large-image
scans are slow for unknown reasons, and optimizations would be blind.

**Completely solved when:**
- [x] Committed `Benchmark*` scans (raw, nested zip, E01) on fixed
      fixtures with a published MB/s table for one reference machine.
- [x] The top bottleneck found by profiling is addressed (parallelize
      read/decode or widen blocks) while keeping the
      overlap/exact-offset contract and the full suite green, with
      a measured table improvement.

**Execute:**
1. Land benchmarks + MB/s table.
2. Profile; implement the top win; re-measure.
3. Revisit the inflation cap if streaming members land.

**Non-goals:** GPU/SIMD rewrites; changing detection semantics for speed.

**Verify:** benchmark numbers committed and reproducible; optimization
moves the table measurably; gates.

## Goal 16 — Hostile-image resource audit

**Pain to completely solve:** the scanner ingests untrusted bytes, but
its trust boundaries were never adversarially tested: 1 GiB RAM cap per
zip member, unbounded E01 chunk-table trust, depth cap 8. A malicious or
pathological image could exhaust RAM or time with no documented bound.

**Completely solved when:**
- [x] Parsers (zip bombs, E01 table lies, gzip streams) are threat-
      modeled and worst-case fixtures assert documented time/RAM bounds
      in CI (generous margins, no flakes).
- [x] Every bound is documented next to the constant that enforces it.

**Execute:**
1. Craft a 1 GiB-claim zip and an E01 with maximal chunk table.
2. Measure time/RAM vs caps; tighten code or document.
3. CI fixtures with margins.

**Non-goals:** sandboxing the process; formal verification.

**Verify:** worst-case fixtures pass within bounds in CI; gates.

## Goal 17 — Checkpoint/resume for range scans

**Pain to completely solve:** checkpoint/resume is explicitly refused for
range scans, so `-fs` and `-unallocated-only` runs on large images start
over from zero after any interruption — hours lost on exactly the
longest runs.

**Completely solved when:**
- [x] The journal records `(range_index, offset)`; resume validates the
      range list still matches before continuing, and refuses loudly on
      mismatch.
- [x] Kill mid-run → resume → byte-identical detection set vs an
      uninterrupted run, proven by test.

**Execute:**
1. Prototype the journal schema against a 3-range fixture.
2. Mid-run kill test; mismatch-refusal test.
3. Docs update.

**Non-goals:** checkpointing nested-archive internals; cross-machine
resume.

**Verify:** kill/resume byte-identity test; mismatch test; gates.

## Goal 18 — OS packages via nFPM

**Pain to completely solve:** releases ship only tarballs/zips — Linux
users get no managed install/upgrade path, which is table stakes for
lab deployment.

**Completely solved when:**
- [x] GoReleaser builds deb+rpm via nFPM; snapshot build proven locally
      and the next tag publishes working packages.
- [x] Container install + `-version` + fixture scan passes from the
      built deb.

**Execute:**
1. Add `nfpms` section (deb+rpm first).
2. Snapshot build; container install/upgrade smoke.
3. Docs: install-from-package path.

**Non-goals:** AUR/Windows package managers (separate evaluations);
Homebrew tap creation.

**Verify:** container install + version + fixture scan green; gates.

## Goal 19 — Library API pass

**Pain to completely solve:** the `detector` package is importable but
undocumented as a library — no `doc.go`, no worked example, no
stability statement — so every integrator reverse-engineers
`ScanWithOptions` from the CLI source.

**Completely solved when:**
- [x] `doc.go` with an end-to-end example (scan bytes → handle
      detections) that compiles under `go test` (`Example*`).
- [x] `Options`/`Detection` stability tiers documented; `Detection`
      JSON tags frozen per the Goal 11 schema.
- [x] A second reader follows the example without asking questions
      (review bar, not a test).

**Execute:**
1. Draft the example against the current API; list every wart it
   exposes.
2. Fix or document the warts; stability tiers.
3. JSON tag freeze vs Goal 11 schema.

**Non-goals:** API redesign for its own sake; new API surface.

**Verify:** `Example*` tests pass; schema conformance still green; gates.

## Goal 20 — Opt-in secret profiles

**Pain to completely solve:** the pipeline is generic (blocks → matchers
→ carves) but the detectors are wallet-shaped, so the whole adjacent
audience doing secret hygiene on repos, laptops, and images gets
nothing — while standing up a second scanner for the same bytes.

**Completely solved when:**
- [x] A profile flag (e.g. `-profile=secrets`) adds non-wallet matchers
      (private-key blocks, credential shapes) under the same FP bar and
      carve/DFXML machinery; the default profile is byte-identical in
      behavior.
- [x] Each new matcher is silent on the 1 MB random + prose fixtures
      and finds its documented recall fixture.

**Execute:**
1. Spike one matcher (e.g. an armored private-key block) with FP
   fixtures (depends on Goal 13 for live-system relevance).
2. Profile flag + per-matcher tests + playbook/docs.
3. Default-profile equivalence test.

**Non-goals:** changing default detections; private-key derivation
(never); online verification of found secrets.

**Verify:** FP silence + recall fixtures per matcher; default-profile
equivalence; gates.

## Goal 21 — Container image

**Pain to completely solve:** labs that standardize on pinned container
images have no blessed findbtc image — they roll their own Dockerfiles
with unknown provenance instead of a digest-pinned, attested one.

**Completely solved when:**
- [x] One supported container path is evaluated, built, and documented
      (GoReleaser-supported path or minimal Dockerfile + registry
      workflow); digest-pinned pull + volume-mount scan works per docs.

**Execute:**
1. Read the current container docs (v1 Docker pipe is deprecated).
2. Build one image locally; record size, USER, mount-scan story.
3. Wire publishing + docs.

**Non-goals:** multi-arch matrix beyond what the evaluation justifies;
Helm charts.

**Verify:** digest-pinned pull + mount-scan per docs; gates.

## Goal 22 — Pipeline ingest evaluation

**Pain to completely solve:** DFXML is the only pipeline ingest format;
if real cases need another interchange, that demand is currently
invisible and unactionable.

**Completely solved when:**
- [x] Three concrete toolchain asks are collected (user interviews or
      issues) and one cheapest-format prototype is validated against a
      sample toolchain — or the evaluation concludes DFXML-only with
      written rationale. No exporter ships without demonstrated demand.

**Execute:**
1. Collect three documented asks.
2. Prototype the cheapest; validate against sample tooling.
3. Ship or write the rationale.

**Non-goals:** building exporters on speculation; replacing DFXML.

**Verify:** asks documented; prototype validated or rationale written;
gates.

## Commit policy

Commits and pushes need the user's explicit ask in the session (per Git
safety rules). The chain rule's "done commit" column may read
`(uncommitted — awaiting user's commit)` when no commit was requested;
that never blocks picking up the next goal.
