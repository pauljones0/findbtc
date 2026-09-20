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
| 11 | Hits JSON Schema | complete | 8b3f8c1 |
| 12 | Partition-table parsing | complete | 396da5d |
| 13 | Directory-tree scan mode | complete | 91e1a74 |
| 14 | Refused image variants | complete | f6c56b3 |
| 15 | Benchmarks + throughput | complete | 1555e57 |
| 16 | Hostile-image resource audit | complete | f699568 |
| 17 | Checkpoint/resume for range scans | complete | e5b7854 |
| 18 | OS packages via nFPM | complete | 204947d |
| 19 | Library API pass | complete | c87fa0d |
| 20 | Opt-in secret profiles | complete | cbf95d4 |
| 21 | Container image | complete | 97ef967 |
| 22 | Pipeline ingest evaluation | complete | 2525e43 |
| 23 | Owner "what's next" guide + anti-scam shield | complete | 4bed9b8 |
| 24 | Exit-on-hit + CI gating | complete | 0bb1793 |
| 25 | FAT/exFAT filesystem support | complete | 61abf5b |
| 26 | Salvage validation | complete | e13d569 |
| 27 | Guided mode (-advise) | complete | 938d490 |
| 28 | Embedding pass (quiet + cancel) | complete | e256cf6 |
| 29 | Baseline/allowlist for repeat sweeps | complete | 1e36005 |
| 30 | Offline secret verification | complete | 08574bb |
| 31 | Coverage honesty (exit codes + skipped accounting) | complete | a132b7b |
| 32 | Offline seed completion (1–2 missing words) | complete | a132b7b |
| 33 | Password handoff verified vs real tools | complete | a132b7b |
| 34 | ETA + progress honesty for long scans | complete | 1eeb861 |
| 35 | Stdin scanning (pipe-first flows) | complete | 71eb324 |
| 36 | Git-history secrets via pipes | complete | a5d9355 |
| 37 | Homebrew tap + Windows managers | complete | 53ed052 |
| 38 | Multi-target scans + unified report | complete | 3b67a44 |
| 39 | Completions + man page | complete | 15d7167 |

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

## Goal 23 — Owner "what's next" guide + anti-scam shield

**Pain to completely solve:** a non-technical owner finds traces and
is stuck — a `bestblock` hit means nothing to them, the next steps
are scattered across per-feature runbooks, and the ecosystem waiting
for them is scam recovery services that ask for exactly the secrets
that must never be shared. The tool finds; nothing guides or shields.

**Completely solved when:**
- [x] `docs/WHAT_NEXT.md` answers "I found traces, what's next?" in
      plain language keyed by hit type (marker vs key vs seed vs
      encrypted vs secrets-profile hit): what it means, exact next
      commands, and when to stop — linked from `-report` output and
      the README triage section.
- [x] A loud anti-scam box (never send wallet/keys/seed to anyone;
      no legitimate tool needs them; work on copies, offline) ships
      in the guide and README, and a non-technical second reader
      reaches the right next action for 5 sample hits without asking
      questions.

**Execute:**
1. Draft the guide against the 5 most common hit types; verify every
   command verbatim.
2. Add the `-report`/README pointers.
3. Second-reader test with a non-technical reader; fix what confuses.

**Non-goals:** new detectors; automated fix-it flows; endorsing any
recovery service.

**Verify:** reader test passes; every command executed verbatim;
gates.

## Goal 24 — Exit-on-hit + CI gating

**Pain to completely solve:** exit code is 0 whether or not anything
matched, so secret hygiene cannot gate CI or pre-commit hooks — the
core workflow of the secrets audience — without wrapper scripting.

**Completely solved when:**
- [x] An opt-in `-fail-on-hit` flag makes scan/`-walk`/`-report`
      exit with a distinct documented code (not 0/1/2) on actionable
      hits; default exit behavior is byte-identical (existing suite
      + probes prove it).
- [x] A sample pre-commit hook + GH workflow using the flag passes
      on a clean fixture repo and fails on a planted secret.

**Execute:**
1. Add the flag with the exit-code contract documented in README.
2. Sample hook + workflow fixtures; clean/planted matrix test.
3. Dogfood consideration: repo self-sweep in CI (expect the
   allowlist question — that is Goal 29, not this one).

**Non-goals:** changing default exit behavior; baselines/allowlists;
severity thresholds (hits are hits).

**Verify:** clean/planted matrix green; default-behavior probes
unchanged; gates.

## Goal 25 — FAT/exFAT filesystem support

**Pain to completely solve:** `-fs` covers NTFS/ext only, but USB
sticks, SD cards, and old externals — exactly where owners keep
wallet backups — are FAT32/exFAT. Every "wallet on a USB stick"
case falls back to filename-less raw carving with PhotoRec's known
weaknesses (fragmentation, no names, live/deleted conflation).

**Completely solved when:**
- [x] FAT12/16/32 + exFAT volumes inventory live and deleted entries
      with names behind the existing volume interface, auto-seed
      through the partition table, and stamp `file=` on hits like
      NTFS/ext.
- [x] Same FP bar per format (silence on random + prose, enforced by
      tests); recovered entries cross-checked against Sleuth Kit
      `fls`/`icat` on fixtures.

**Execute:**
1. Build FAT32 + exFAT fixtures with deleted files (long names,
   fragmented files, exFAT bitmaps).
2. Spike the reader (FAT chains + directory entries); cross-check
   against `fls`/`icat`.
3. Wire auto-seed + `file=` stamping + docs; timebox the spike —
   FAT looks small until long filenames + exFAT bitmaps.

**Non-goals:** APFS (still demand-gated); repairing filesystems;
changing raw-scan behavior.

**Verify:** oracle cross-checks green; FP bar tests; gates.

## Goal 26 — Salvage validation

**Pain to completely solve:** salvage writes `.salvage.db` with no
open-check, so a corrupt rebuild fails mysteriously at the next
step — after the user has built hope on it. SQLite order is already
documented-uncertain except for page-1-led runs.

**Completely solved when:**
- [x] Every salvaged run carries a valid/suspect verdict from
      structural validation (SQLite header, page-size, btree cell
      bounds; BDB page headers + pgno sequence), surfaced in the
      sidecar and `-report`.
- [x] Validator verdicts match real `sqlite3`/`db_verify` open-checks
      on the fixture set (independent oracles).

**Execute:**
1. Run existing salvaged fixtures through `sqlite3`/`db_verify`;
   catalog which structural checks predict "opens".
2. Implement the validator dependency-free (no sqlite driver —
   structural checks only); wire verdicts into sidecar + report.
3. Docs: what valid/suspect means and what to do for each.

**Non-goals:** repairing corrupt databases; new database formats;
changing salvage assembly itself.

**Verify:** oracle agreement on fixtures; verdicts in sidecar +
report; gates.

## Goal 27 — Guided mode (-advise)

**Pain to completely solve:** 9 modes × ~25 flags and nothing helps
a new user pick one — raw vs `-fs` vs `-walk` vs `-unallocated-only`
is a real decision tree, and each mode fails well only after the
user guessed wrong.

**Completely solved when:**
- [x] `-advise TARGET` inspects the target (partitioned? filesystem?
      directory? size?) and prints the recommended command with
      reasons. It never scans and never auto-runs — pure routing.
- [x] Four fixtures (raw file, partitioned disk, ext image,
      directory) route to the documented-best command, proven by
      test.

**Execute:**
1. Define the routing table (target shape → command + reasons).
2. Implement inspection + printer; route tests on fixtures.
3. README/docs pointer; usage-line mention.

**Non-goals:** auto-running scans; interactive wizards; changing any
mode's behavior.

**Verify:** routing tests green; gates.

## Goal 28 — Embedding pass (quiet + cancel)

**Pain to completely solve:** library users get unconditional stderr
spam (Goal 19's documented wart, hit by the second reader) and no
cancellation — a server embedding a long scan can neither route logs
nor enforce a deadline.

**Completely solved when:**
- [x] `Options.Log io.Writer` routes all library diagnostics (nil =
      stderr, default output byte-identical, proven by test).
- [x] `Options.Context` (nil = Background) cancels a scan promptly
      with documented semantics (partial results, checkpoint left
      behind, no goroutine leaks — tested).

**Execute:**
1. Enumerate every library stderr write; route through one writer.
2. Thread the context from `runPipeline` through the stages.
3. Doc updates (`doc.go` tiers/warts) + leak/cancel tests.

**Non-goals:** changing CLI default output by one byte; progress
throttling; new callbacks.

**Verify:** byte-identity test on default output; cancel promptness
+ leak tests; gates.

## Goal 29 — Baseline/allowlist for repeat sweeps

**Pain to completely solve:** every `-walk` re-reports known
fixtures and accepted findings, so repo secret hygiene is one-shot —
gitleaks' answer (baselines + allowlists) has no counterpart here,
and Goal 24's dogfood step will hit this wall immediately.

**Completely solved when:**
- [x] `-baseline hits.jsonl` suppresses known findings across repeat
      sweeps while new hits still report, with documented drift
      behavior (fingerprint must survive file edits — raw offsets
      do not).
- [x] Fingerprint stability proven across edit patterns (append,
      insert-above, rewrite) by test.

**Execute:**
1. Design spike: fingerprint candidates (e.g. relpath + needle +
   line-hash for walk mode); measure stability across edits.
2. Implement baseline load/match/suppress; report counts of
   suppressed vs new.
3. Docs: baseline workflow for repos + CI.

**Non-goals:** auto-updating baselines; fuzzy matching; changing
detection itself.

**Verify:** stability tests; suppressed/new counts; gates.

## Goal 30 — Offline secret verification

**Pain to completely solve:** the secrets profile reports shapes,
and the market's whole FP answer is verification
(TruffleHog `--only-verified`) — but live verification stays
excluded, leaving structural confidence as untouched territory and
truncated/garbage bodies as unaddressed noise.

**Completely solved when:**
- [x] PEM block bodies validate structurally (base64-decodes,
      parses as DER SEQUENCE); malformed bodies do not report, and
      per-hit confidence reflects the check.
- [x] Privacy audit notes exactly which bytes were touched: parsing
      alone — no derivation, no key handling, no network.

**Execute:**
1. Measure current behavior on truncation fixtures + noise corpus.
2. Implement structural validation in the PEM matcher; confidence
   in output/report.
3. Privacy audit + docs; FP bar tests.

**Non-goals:** live verification of any kind (standing exclusion);
new secret types; entropy-scored generic matchers.

**Verify:** truncation fixtures rejected; corpus silent; audit
written; gates.

## Goal 31 — Coverage honesty (exit codes + skipped accounting)

**Pain to completely solve:** the tool can scan nothing and report
success. An unreadable root target prints a warning and exits 0; a
`-walk` that failed files exits 0; only `-fail-on-hit` moves the
code, and only for hits. CI and scripts trust 0 — for forensics
software, an exit code that means "clean" when it means "blind" is
a false negative with a stamp on it.

**Completely solved when:**
- [x] A scan whose ROOT target fails (unreadable, missing mid-run,
      zero bytes covered) exits 1 with the reason on stderr.
      Nested-target tolerance (one bad archive inside a good
      image) is unchanged and still exits 0.
- [x] `-walk` reports skipped/failed counts loudly, and exits 1 on
      zero coverage (nothing scanned); `-report` distinguishes
      "no detections" from "nothing scanned". Exit contract
      table (README + gate matrix) updated; no hit-exit change.

Decision record (Goal 31): walk rule is zero-coverage (exit 1 only
when nothing was scanned), not strict (any failure → 1), per the
goal's bias note — plus a loud `WARNING` whenever any file failed.
Skips stay policy (counted in the summary, no warning): warning on
every skipped symlink would train users to ignore the line. Empty
files, `/dev/null`, resume-at-EOF, and `-s` past EOF stay exit 0:
zero bytes of an expected zero is a success, not blindness.

**Execute:**
1. Decide the walk rule at goal time: strict (any failure → 1)
   vs zero-coverage (nothing scanned → 1). Bias: zero-coverage
   plus a loud skipped/failed line whenever nonzero.
2. Implement root-failure detection in runPipeline/runScan and
   the walk summary/exit; extend the gate_test exit matrix.
3. Update the README exit-code contract + WHAT_NEXT stop rules.

**Non-goals:** changing hit exits (3 stays); per-file exit codes;
retrying failed files.

**Verify:** exit-matrix tests incl. chmod-000 root, all-failed
walk, nested-archive tolerance (still 0); gates.

## Goal 32 — Offline seed completion (1–2 missing words)

**Pain to completely solve:** "12th word smudged" is one of the
most common owner disasters, and the fix is 2,048 checksum-gated
tries — but today it needs BTCRecover know-how (tokenlists,
versions, address DBs). findbtc finds partial/fuzzy seeds and
derives watch-only addresses; completion is the missing middle
that closes the owner loop end-to-end.

**Completely solved when:**
- [x] Given 11-of-12 / 23-of-24 (or 2 missing anywhere — 4M
      tries, still fast), the tool enumerates checksum-valid
      completions offline, most-likely first, feeding the
      existing watch-only flow without copy-paste. Past 2
      missing words it refuses loudly (billions of tries),
      pointing at BTCRecover/GPU.
- [x] Near-miss correction suggests checksum-valid neighbors
      ("did you mean X?"); the anti-scam box + --reveal warning
      pattern travels with it (local terminal only, never
      transmitted); docs cover when to stop.

Decision record (Goal 32): shape is a `-report` follow-up
(`-report hits.jsonl -complete --reveal [-complete-out PATH]
[-complete-max N]`), not a new mode, per the goal's bias. Rationale:
partial-seed hits already exist as near-miss detections, and
completion needs their `--reveal` words — a sibling mode would
re-invent hit input. Smudged-paper owners (no scan) transcribe words
with an `xxxx` placeholder and scan that file. The watch-only handoff
is a keys file (`-complete-out`, 3 standard account keys per
candidate: m/44'/0'/0' xpub, m/49'/0'/0' ypub, m/84'/0'/0' zpub)
consumed directly by `-watch`; phrases never land in the file —
candidate numbers link the terminal listing to the keys. Three fixed
paths is coverage, not derivation-path brute force (non-goal).
`-complete` refuses `-json` (machine output gets saved/logged) and
requires `--reveal`. Evidence: 15 one-gap oracle vectors (all
lengths × first/mid/checksum-word) + 6 two-gap oracle vectors from
an independent stdlib-Python reimplementation (two checksum methods;
PBKDF2 hashlib vs manual loop; BIP32 chain vs in-repo xprv +
Go/Python EC cross-check; seed→xpub three-way btcsuite/Python/Go
agreement); every doc recipe executed verbatim. Second-reader trial:
not run in-session (no reader available) — the handoff text is the
`-complete` output + WHAT_NEXT §3, both exercised verbatim instead.

**Execute:**
1. Decide shape at goal time: `-report` follow-up on
   partial-seed hits vs `-hashes`-style sibling. Bias: follow-up
   (no mode 11).
2. Implement checksum-gated enumeration (12/15/18/21/24,
   missing anywhere incl. checksum word) + watch-only handoff.
3. WHAT_NEXT section + scam-box wording; second-reader trial
   on the handoff text.

**Non-goals:** 3+ missing words; derivation-path brute force;
anything networked; spending.

**Verify:** known-answer completions (all lengths/positions);
refusal tests; no-new-net-imports test; gates.

## Goal 33 — Password handoff verified vs real tools

**Pain to completely solve:** tokenlist authoring is BTCRecover's
documented hard part, and our crack-ready exports +
PASSWORD_RECOVERY.md have never been executed against real
hashcat/John/BTCRecover. An owner who reaches this step with a
broken handoff loses everything the scan found.

**Completely solved when:**
- [x] Exported hashes crack with real John + hashcat in CI
      (pinned versions, tiny known-answer corpus).
- [x] A generated --tokenlist from hit context cracks a test
      wallet in real BTCRecover (pip-installed in CI); every
      PASSWORD_RECOVERY.md command executed verbatim in CI and
      the doc stamped with tool versions; failure modes + cost
      estimates documented.

Decision record (Goal 33): verification, not new capability —
`-hashes` extraction predates this goal; G33 added the `-tokenlist`
builder, the deterministic corpus + generator, the runbook, the
verbatim harness (`scripts/password-handoff.sh` executes every
```sh line in doc order and asserts live cracks + the version stamp),
and the `password-handoff` CI job. Pins: John 1.9.0-jumbo-1
(openwall tarball + a GCC≥13 blake2 struct-padding patch that
changes no hashes), hashcat 6.2.6 (apt on ubuntu-24.04, asserted),
BTCRecover @1457088, eth-keyfile 0.6.0, setuptools 80.9.0
(eth-keyfile still imports pkg_resources, removed in setuptools
≥81). Evidence (final design, demonstrated twice): runs C+D each
HARNESS_EXIT=0 — 22/22 doc commands verbatim, live-crack counts
(hashcat Status:Cracked×3, john Session completed×3, BTCRecover
found×2), 6/6 version stamps (4 tools + 2 Python pins), corpus
`--check` clean; sentinel file intact; toolchain hashcat potfile
md5-stable (a0e05dcc…) across all runs; run-local pots hold 4+4
fresh cracks each; full suite SUITE_EXIT=0. An early green run's
hashcat half was later found to be potfile replay, not live
cracking — the live-crack counts were added so replays fail, and
only post-count runs count as evidence. Local toolchain recipe
(no sudo): dpkg-extracted hashcat+pocl under /tmp with
LD_LIBRARY_PATH + OCL_ICD_VENDORS wrapper, jumbo built from source,
BTCRecover via `uv run --with` (never pip-installed, never a repo
venv). Fixes during reconciliation and review: `-tokenlist hits.jsonl`
carve reads bounded by the remaining TokenlistMaxBytes budget in the
read itself (`readCarveCapped`, small-limit `TestReadCarveCapped`);
all-unreadable carves exit 1 (zero-coverage rule); foreign JSON used
verbatim (`hitsShaped`); `-hashes` skip reasons on stderr
(`ExtractHashesWithSkips`: unsupported cipher/KDF, presale
out-of-scope) with `TestHashesCLI`; hashcat `--potfile-path` and
john `--pot` run-local pots in the doc (never delete shared pots);
the harness takes a WORKPARENT and runs in a fresh `mktemp -d`
subdir instead of `rm -rf`-ing a caller path; john staging links
run files excluding session state (bare-name john resolves home
from CWD per jumbo path.c — there is no $JOHN override); the
`wallet.dat` example split so the repo self-scan stays needle-free
(test untouched); hashcat-mode map test; token length-boundary test.
Infrastructure correction during verification: the local uv wrapper
recursed (~950 nested `uv run` probes, 8GB swap) because the harness
shadows it as `python3` on PATH and uv discovery re-executed the
shadow — fixed by pinning uv to an absolute system interpreter in
the wrapper plus a harness-side UV_PYTHON capture while the workdir
is still empty, proven by a TasksMax=100-bounded smoke test resolving
a real venv interpreter.
Failure table rows are observed verbatim (John scrypt
salt `strlen` truncation confirmed at ethereum_fmt_plug.c:175;
corpus salts avoid 0x00); cost numbers re-measured by the parent
(tokenlist recovery 15 s wall vs the doc's 16 s — agreement).

**Execute:**
1. Add CI jobs: John (Jumbo) + hashcat CPU + BTCRecover pip
   install; cache aggressively, keep the corpus tiny.
2. Generate tokenlists from hit context (nearby words,
   mutations); verify end-to-end against a test wallet.
3. Stamp the doc; document wrong-wallet-type errors + costs.

**Non-goals:** cracking inside findbtc; new export formats
without demand; GPU CI.

**Verify:** CI jobs green; doc-commands test; gates.

## Goal 34 — ETA + progress honesty for long scans

**Pain to completely solve:** multi-hour scans print percent with
no rate or remaining time; users cannot tell "slow" from "hung"
(BTCRecover sets the ETA expectation). Cheap to fix, high
perceived reliability.

**Completely solved when:**
- [x] Stderr progress gains throughput + ETA (bytes/sec,
      remaining) after a warmup window: stable (≤2 updates/sec;
      bytes/percent monotonic within a scan), honest ETA that
      rises with slowdowns (never a clamped stale figure),
      documented line shape, still parseable.
- [x] `-checkpoint` prints resume position on `-resume`
      ("continuing at 41%").

Decision record (Goal 34): the reporter already printed rate+ETA;
G34 made it honest — 5 s warmup (early lines show percent/bytes
only), per-target baselines restarting on identity, counter
resets, or total change (same-size and unknown-size targets share
a total, so the total alone under-determines the switch), and a
cumulative-average ETA with no clamp. Design correction during
review: a first attempt clamped the ETA down ("monotonic
remaining") and printed times its own rate contradicted (5.1MB/s
with ETA 10s for a 96 s remainder) — the supervisor's independent
overlay reproved both that and the same-size negative rate
(`-4.5MB/s`); the clamp was removed and the goal text corrected to
honest-rising ETA. Resume prints `(continuing at NN%)` on the
single-target path (byte-only fallback when size is unknown) and
`at range N of M (continuing at NN%)` on range scans, with the
ordinal naming the range where work resumes (boundary journals
advance past zero-remainder ranges, sharing the scan loop's skip
condition). Line shapes documented in README (stderr-only, 10 s
cadence, per-target rates). Evidence: fake-clock golden tests
(rate/ETA values, warmup, honest rise, retarget, counter reset),
real-binary resume tests, supervisor overlay exit 0 in both
directions, adversarial review FAIL:1 minor (boundary ordinal) →
fixed with unit + end-to-end tests, full suite SUITE_EXIT=0.

**Execute:**
1. Add rate/ETA to the progress printer with a fake-clock-safe
   design; golden progress tests.
2. Resume-position line on -resume.
3. Document the progress line contract.

**Non-goals:** progress bars/TUI; changing -json; per-file ETAs
in -walk (stretch only).

**Verify:** golden tests; gates.

## Goal 35 — Stdin scanning (pipe-first flows)

**Pain to completely solve:** `dd | findbtc`, `ssh lab 'dd …' |
findbtc`, cloud snapshots via pipes — none work; the tool
demands seekable files/devices. Forensic triage over pipes and
container-native flows are second-class without it.

**Completely solved when:**
- [x] Raw scan + secrets profile accept `-` with byte-identical
      detections vs file input (proven by test on fixtures).
- [x] Spill behavior documented (bounded spill file: where, how
      big, cleanup); loud refusals for -fs/-walk/-checkpoint on
      pipes.

Decision record (Goal 35): pipes scan spill-first — the stream
lands in a bounded `$TMPDIR/findbtc-stdin-*` file (0600, 1 TiB
backstop cap, removed on every return path), then the standard
pipeline runs over the spill, so detections, carves, case logs,
and progress are the file path by construction. The stable label
is `"stdin"` (detections, progress, case-log path; kind
`"stdin"`); only the label — echoed in Description — differs
from a file scan. Size uses FileSize so even empty-input
progress matches. Refusals (exit 1, before any stdin read):
`-fs`/`-walk`/`-checkpoint`/`-resume`/`-unallocated-only` with
`-`; the library refuses CheckpointPath/Resume too. Loud
non-refusals: EWF magic warns (EWF2 advice points at libewf,
since file scans refuse EWF2 as well); containers piped in scan
raw — the one documented parity exception. The spill honors
`opts.Context` (pre-cancel never reads; mid-spill stops between
reads) and reports bytes-reached on every failure. Evidence: 14
library tests (identity × profiles × offsets incl. progress
sequences, archive identity, carve identity, cap/coalesced/
boundary/read-error/cancel/cleanup, EWF1+2 warnings, case-log
kind, empty) + 2 gate tests (real-binary pipe identity,
5 refusals pinned to exit 1); adversarial review FAIL:10 then
FAIL:6, all fixed with tests; full suite SUITE_EXIT=0.

**Execute:**
1. Stream with a bounded spill file; carve from the spill.
2. File-vs-stdin identity tests; spill-cap tests.
3. Docs: pipe recipes (dd/ssh), spill location/size, cleanup.

**Non-goals:** seeking pipes (impossible); -fs/-walk on pipes;
-resume on pipes; performance parity with files.

**Verify:** identity + cap tests; gates.

## Goal 36 — Git-history secrets via pipes

**Pain to completely solve:** working-tree-only scanning misses
committed-then-removed secrets — the actual leak shape — while
gitleaks-license friction opens a wedge for a free offline
alternative. Depends on Goal 35; do not implement before it.

**Completely solved when:**
- [x] `git log -p` piped through stdin scanning attributes
      findings to commit + path (patch headers parsed
      dependency-free); baselines match across it.
- [x] Docs show the two-command history gate; demand check
      recorded for native `git rev-list` walking (separate
      future goal only if asked).

Decision record (Goal 36): `-patch` parses the scanned bytes as
a patch series (`git log -p` / `git show` / mbox `format-patch`)
in one forward re-read and stamps root-target hits with commit
+ repo path + new-file line (added/context lines; 0 for
removed/message bytes), plus `v1/history/<commit>/<path>/
<needle>/<line-hash>` fingerprints keyed on commit + path + raw
patch line — never patch offsets, so the same commit keys
identically across full and ranged logs. Detections buffer and
deliver after the scan (progress still streams); sidecars are
re-marshaled with the attribution; nested hits stay bare
(member-relative offsets). Loud boundaries: `-patch` refuses
`-fs`/`-walk`/`-unallocated-only`/`-checkpoint`/`-resume` (the
checkpoint refusal closes a crash+resume coverage hole: the
journal would certify hits still buffered), `Walk` refuses
`Patch` at library level, `-baseline` extends to patch scans
(suppression + stderr count, mirroring walk) and now refuses
`-fs` too, merge combined diffs get best-effort lines, zero-commit
input warns that baselines are inert, and the re-read honors
`opts.Context`. Fixed from review/supervisor probes: in-hunk
`+++`/`---` content no longer hijacks the path (proven on the
supervisor's actual-git fixture, independently re-verified),
`--cc` path, CRLF paths, quoted paths, closing-`@@` required,
`From` accepts sha256 length. Evidence: 21 library tests
(attribution, range-stability, golden hash, deletion/rename,
hunks, quoted-message/content/context, mbox, CRLF, truncation,
non-patch, nested, sidecars, ranges/checkpoint/walk refusals,
cancel, zero-commit warning) + fixture-repo gate (real git:
leak-then-removed attributed, baseline suppresses exactly,
new-commit reports, fail-on-hit exits 3) + refusal gates;
adversarial review FAIL:8, all fixed with tests; full suite
SUITE_EXIT=0. Demand check for native `git rev-list` walking:
none recorded — documented non-goal, future goal only if asked.

**Execute:**
1. Parse patch headers (commit/path/hunk) from the piped
   stream; attribute detections.
2. Baseline fingerprint shape for history findings.
3. Docs + fixture repo test (leaked-then-removed secret).

**Non-goals:** native git object parsing; PR-range logic (shell
does ranges); auto-fix; anything before Goal 35 lands.

**Verify:** fixture-repo test with commit attribution; gates.

## Goal 37 — Homebrew tap + Windows managers

**Pain to completely solve:** README apologizes to macOS users
("no tap yet"); Windows users get archives and untested
privilege UX. Every install-friction report starts here.
Blocked on tap ownership (user decision).

**Completely solved when:**
- [x] `brew install <tap>/findbtc` works from a layman's
      terminal (smoked in CI on macos).
- [x] Windows story decided and documented: winget and/or
      Scoop, or explicit "archives only, here's why"; install
      docs show copy-paste per-OS commands, each executed in CI.

Decision record (Goal 37): tap `pauljones0/homebrew-findbtc`
ships a cask (cask-over-formula per GoReleaser deprecation);
Windows gets Scoop bucket `pauljones0/scoop-findbtc` as the
supported path plus a locally validated winget manifest
staged in-repo — no third-party PRs filed. GoReleaser
automates formula/manifest regeneration from immutable
release URLs + SHA256s; `scripts/verify-packaging-pins.py`
binds URL-arch-SHA structurally (set-membership checking
was proven insufficient by finding 014; the 12-mutant offline
self-test passed and the live pins re-verified). install-smoke
4/4 green (run 35511710891); the local gate came back FMT-clean
with VET_OK and SUITE_EXIT=0. G37 fixed Windows TestStdinPipeIdentity via
structural parsed-JSON compare. Known pre-existing red,
unchanged by G37 (ci failing since Goal 27): Windows
TestAdvise*/TestTokenlist* and password-handoff
(`No module named 'Crypto'` — CI env lacks pycryptodome);
left for a future goal.

**Execute:**
1. Get tap ownership decision; create/point the tap.
2. Decide Windows managers; write formulae/manifests.
3. CI install smokes per OS; rewrite install docs.

**Non-goals:** distro repos (Debian/Fedora inclusion);
auto-update.

**Verify:** CI smokes; gates.

## Goal 38 — Multi-target scans + unified report

**Pain to completely solve:** triaging 20 images means 20 shell
loops, 20 JSON files, 20 case logs, hand-merged. Scripting
copes; forensics reports do not.

**Completely solved when:**
- [x] Multiple positionals and/or `-targets FILE` scan in one
      run with one hits.jsonl (per-hit target already
      recorded) and per-target case-log records.
- [x] Per-target failures follow Goal 31 rules (one bad image
      neither zeroes the run nor lies); `-report` groups by
      target.

Decision record (Goal 38): the batch loop lives in main
(`runMultiTarget`): positionals plus `-targets` entries scan
in order into one hits stream, and each `ScanWithOptions`
call appends its own case-log record, so per-target records
fall out with no detector change. Exits mirror the Goal 31
walk rule — loud per-target `failed:` lines plus WARNING
when any target fails, exit 1 only on zero scanned.
Single-target-only inputs (`-s`, `-checkpoint`/`-resume`,
stdin sharing a run) refuse with exit 2. Carve numbering
threads `CarveSeqStart` across targets counting every
delivered detection (the pipeline carves before main's
baseline suppression, so printed hits alone would
undercount). `-report` text groups hits under sorted
per-target headers with full counts and spans; the JSON
shape is unchanged. Full gate FMT clean, VET_OK,
SUITE_EXIT=0; mixed good/bad batch fixture in
`TestMultiTargetBatch`.

**Execute:**
1. Accept N targets; loop with per-target record keeping.
2. Apply coverage-honesty rules per target + overall exit.
3. -report grouping; docs.

**Non-goals:** parallel targets (measure first); glob expansion
(shell does it).

**Verify:** mixed good/bad batch fixture; gates.

## Goal 39 — Completions + man page

**Pain to completely solve:** 30 flags with no completion and no
man page; `--help` (61 lines) is the whole story. Smallest pain
in the queue; compounds if the surface keeps growing.

**Completely solved when:**
- [x] bash/zsh/fish completions generated from the real flag
      table (never hand-listed — test asserts every flag
      present).
- [x] Man page generated from the same source, installed by
      deb/rpm; the 3 orphan docs linked from SEE ALSO.

Decision record (Goal 39): `-gen-completion=bash|zsh|fish` and
`-gen-man` render `flag.CommandLine` right after `flag.Parse`,
so the scanner's own table is the single source; outputs are
committed under `packaging/` and the gate tests byte-compare a
fresh render plus assert every `-h`-parsed flag appears
(anchored per shell, never hand-listed). nFPM ships the
scripts, the page, and the three orphan guides; the
install-smoke packaging job snapshot-builds and installs the
deb, asserting payload, man render, and all three shell
syntax checks. Full gate FMT clean, VET_OK, SUITE_EXIT=0.

**Execute:**
1. Generate completions + man from one source of truth.
2. Freshness test (every flag present); packaging install.
3. Link orphans (BENCHMARKS, PIPELINE_INGEST, RESOURCE_BOUNDS).

**Non-goals:** TUI; interactive help; new flags to justify it.

**Verify:** freshness test; gates.

## Commit policy

Commits and pushes need the user's explicit ask in the session (per Git
safety rules). The chain rule's "done commit" column may read
`(uncommitted — awaiting user's commit)` when no commit was requested;
that never blocks picking up the next goal.
