## Goal

Produce a ranked, evidence-grounded set of improvement directions that make
findbtc more generally useful after the Goals 9–22 chain, then get approval
on the top slice to pursue as follow-up goals. This plan covers the
brainstorm itself: survey, rank, and define the next evidence step per
idea. No implementation in this plan.

## Success Criteria

- Every proposed direction traces to a cited workspace fact (code path,
  doc gap, hands-on probe, or recorded non-goal), a cited web source,
  or is marked an assumption.
- Directions are ranked by expected pain relieved × effort, with the
  ranking rationale stated.
- The top 3 directions each have a defined next evidence step (spike or
  measurement) that fits one focused session.
- The user approves, amends, or cancels the ranked list.

## Context And Current Facts

Post-chain state (v0.2.0 tagged, CI green, tree clean):

- findbtc scans raw bytes for wallet traces (Core markers, BIP39
  exact/fuzzy/near-miss, WIF/xkeys, ETH keystores, Electrum,
  descriptors, SLIP39, Lightning, MetaMask) plus an opt-in secrets
  profile (PEM blocks, AWS IDs, GitHub tokens). Secrets never print
  by default; offline by default with one explicit opt-in
  (`-balance-endpoint`).
- Inputs: raw devices/files, E01/S01/split-raw images (EWF2 refused
  with a pointer), NTFS/ext via `-fs` with partition-table auto-seed,
  directory trees via `-walk`, checkpoint/resume everywhere except
  `-walk` (documented refusal). No FAT/exFAT/APFS; no EWF2.
- Outputs: human text, versioned `-json` JSONL (`schema/hits-v1.json`,
  frozen tags enforced by test), `-report` triage with playbooks,
  `-dfxml` (namespace deliberately frozen at the old host per Goal 9
  decision record), case-log JSONL + verify, carves with sidecars,
  salvage DBs, watch CSV/JSON, deb/rpm packages, GHCR container
  image (digest-pinned docs).
- Library: `detector` has `doc.go`, stability tiers, a runnable
  example, nil-callback tolerance. Known documented warts: stderr
  logging is unconditional (no quiet switch), no caller
  cancellation (context is created internally in `runPipeline`).
- CLI: one binary, ~25 flags, 9 modes. Hands-on probes this session:
  exit codes are 2 (usage) / 1 (runtime error) / 0 (ran) — and 0
  whether or not anything matched. Garbage inputs fail gracefully
  with specific next actions (`-hashes`/`-salvage` exit 0 with
  "not found" guidance; `-fs` names what it tried). `-json` output
  parses as JSONL. Usage synopsis omits `-profile`.
- Docs: 12 files under `docs/`, no scam warnings anywhere, no single
  "I found traces, what's next?" owner guide. `GOALS.md` status table
  is stale (says Goal 11 active; all 22 complete).
- Distribution: releases + attestations at `pauljones0/findbtc`,
  deb/rpm, GHCR image. No Homebrew tap (documented gap, tap repo
  does not exist), no Windows package-manager metadata, no shell
  completions, no man page (completions/man were recommended in the
  2026-09-18 brainstorm, Decision 2, and never scheduled).
- Demand channels: repo issues disabled; upstream `jakewins/findbtc`
  has 8 issues, none asking for formats (Goal 22). No other user
  contact exists. Standing exclusions carry over: private-key
  derivation (never), online-by-default anything, seed brute force,
  case management, timeline analysis, RAID rebuild.

## Flows, "Just Works?", Consumer Contract

Five jobs, audited hands-on:

1. **Owner recovery** ("I lost my wallet"). Core scan just works:
   `findbtc /dev/sda` finds traces on deleted/corrupt/reformatted
   media. The break is the last mile: a `bestblock` hit means nothing
   to a panicking non-technical user, and the ecosystem waiting for
   them is scam recovery services (multiple sources warn most
   "unlock" services are scams). Runbooks exist per feature
   (`PASSWORD_RECOVERY.md`, `-report` playbooks) but there is no one
   "what's next" path, no "don't send your wallet to anyone" shield,
   and nothing confirms a salvaged DB actually opens before the user
   builds hope on it.
2. **Lab forensics** (image → hits → defensible case). Strongest
   contract: case logs, hashes, DFXML, frozen schemas, container.
   Gaps are inputs (FAT/exFAT USB sticks, APFS Macs, EWF2) not
   workflow.
3. **Secret hygiene** (repo/laptop sweep → rotate). Detectors work,
   but the workflow contract is thin: exit code is always 0 (CI
   gating and pre-commit hooks need fail-on-hit — gitleaks' whole CI
   story), no baseline/allowlist (every sweep re-reports known
   fixtures), no verification story (TruffleHog's `--only-verified`
   is the market's FP answer; online verification stays a non-goal,
   but offline structure checks are unexplored).
4. **Library integrators**. Tier docs + example work (a second reader
   ran the example first try). Friction: unconditional stderr spam
   and no cancellation/deadline — both fine for CLIs, both wrong for
   servers.
5. **Pipeline ingest**. JSONL + DFXML + CSV, DFXML-only decision
   recorded with rationale. Contract clear; demand channel missing
   (issues disabled).

Contract verdict: exit codes, stdout/stderr split, frozen wire
formats, and the offline default are clear and verified. The holes
are "did anything match" (no machine signal), embedding behavior
(logging, cancellation), and the owner last mile (guidance, trust).

## Constraints And Non-goals

- Privacy and offline-by-default stay absolute: no idea may weaken
  them; new detection keeps the per-format FP bar (silence on random
  bytes + repo prose, enforced by tests).
- Standing exclusions hold: private-key derivation, online-by-default
  or online verification of secrets, seed brute force, case
  management, timeline analysis, RAID rebuild.
- This plan proposes and ranks; it does not implement, and it does
  not pre-approve any code change.

## Key Decisions

1. **Last mile before new surface.** Recommend prioritizing the owner
   "what's next" flow and the secrets CI-gating flow over new
   detectors or inputs. Rationale: both convert existing capability
   into completed jobs; the web pain is overwhelmingly "I have
   traces/leads, now what?" not "I need more trace types."
   Rejected alternative: lead with FAT/APFS — bigger unlocks, but
   each is weeks and serves users who already complete the flow.
2. **Docs that prevent harm rank with code.** The anti-scam shield
   outranks several code ideas: the cost of a user sending their
   wallet to a scammer dwarfs any feature gap, and no code change
   addresses it.
3. **Offline verification only, and narrow.** Any secret-confidence
   work must be structural/offline (parse checks, never liveness
   probes). Rejected: TruffleHog-style live verification — violates
   the standing exclusion and the offline contract.
4. **Demand gates stay.** APFS, EWF2, and new exporters remain parked
   behind demonstrated demand per the Goal 22 precedent. FAT/exFAT
   is the exception: USB-stick wallet backup is a mainstream owner
   shape, not a speculation.

## Recommended Approach

Rank by (pain relieved) × (days to first value). Do hygiene in
minutes (idea 0), then the last-mile pair (1–2, days), then the big
input unlock (3) alongside embedding fixes (5–6), then workflow
depth (4, 7–9) and distribution polish (10–11). Park 12 behind
demand. Pursue the top 3 after approval.

## Work Plan

### 0. Hygiene (minutes, do immediately)

- Grounding: `GOALS.md` status table says Goal 11 active (all 22
  complete); usage synopsis omits `-profile`; DFXML namespace freeze
  is recorded only in `GOALS.md`, invisible to consumers.
- Sketch: fix the table, add `-profile` to usage, note the frozen
  namespace in `docs/HITS_SCHEMA.md` or the DFXML docs.
- Next evidence step: none needed — verify by reading.

### 1. "I found traces, what's next?" owner guide + anti-scam shield (days, top pain)

- Grounding: upstream issue #12 is literally this question; every
  wallet-recovery source funnels owners toward pros and warns most
  "unlock" services are scams; repo has zero scam warnings (grep).
- Sketch: `docs/WHAT_NEXT.md` in plain language keyed by hit type
  (marker hit vs key hit vs seed hit vs encrypted hit), each with:
  what it means, what to do next (with exact commands), when to stop.
  Loud anti-scam box on top (never send wallet/keys/seed to anyone;
  no legitimate tool needs them; work on copies, offline). Link it
  from `-report` output and the README triage section.
- Next evidence step: draft against the 5 most common hit types;
  test with a non-technical second reader (same bar as Goal 19).
- Sources: `https://walletrecovery.info/articles/how-to-recover-your-corrupt-or-deleted-bitcoin-core-wallet/`,
  `https://cointimeatm.com/how-to-recover-my-lost-bitcoin-wallet/`
  (scam warnings),
  `https://github.com/jakewins/findbtc` issues (what's-next ask).

### 2. Exit-on-hit + CI gating for secret hygiene (days)

- Grounding: probes show exit 0 with or without hits for scan and
  `-report`; gitleaks' CI story is exit codes; pre-commit/CI cannot
  consume findbtc without wrapper scripting.
- Sketch: opt-in `-fail-on-hit` (scan/`-walk`/`-report`) exiting 2 —
  hmm, 2 already means usage error; use a distinct code (e.g. 3 =
  actionable hits) and document the contract. Keep default exit
  behavior frozen for forensics. Dogfood: a secrets sweep of this
  repo in CI (fixtures will force the allowlist question — see 7).
- Next evidence step: prototype the flag; wire a sample pre-commit
  hook + GH workflow against a fixture repo in one session.
- Sources: `https://dev.to/chintanshah35/trufflehog-vs-gitleaks-vs-github-secret-scanning-why-most-ci-scanners-fail-2026-1372`
  (CI scanner expectations).

### 3. FAT/exFAT filesystem support (weeks, biggest input unlock)

- Grounding: `-fs` covers NTFS/ext only; USB sticks, SD cards, and
  old externals — exactly where owners keep wallet backups — are
  FAT32/exFAT. PhotoRec's documented weaknesses (fragmentation, no
  filenames, live/deleted conflation) are precisely what `-fs`
  already solves for NTFS/ext.
- Sketch: FAT12/16/32 + exFAT readers behind the existing volume
  interface (deleted-entry recovery via FAT chains + directory
  entries), auto-seed through the partition table, same FP bar.
- Next evidence step: build FAT32 + exFAT fixtures with deleted
  files; spike the reader; cross-check recovered entries against
  Sleuth Kit `fls`/`icat` as the independent oracle.
- Sources: `https://www.cgsecurity.org/testdisk_doc/photorec_video.html`
  (carver fragmentation limits),
  `https://www.neuralgrimoire.com/i-lost-my-bitcoin-wallet/`
  (clone-first recovery guidance).

### 4. Salvage validation: prove the rebuilt DB opens (days)

- Grounding: salvage writes `.salvage.db` with no open-check;
  SQLite order is already documented-uncertain except page-1-led
  runs; a corrupt rebuild fails mysteriously at the next step.
- Sketch: post-salvage structural validation (SQLite header,
  page-size, btree cell bounds; BDB page headers + pgno sequence),
  reported per run as valid/suspect; dependency-free (no sqlite
  driver — structural checks only).
- Next evidence step: run existing salvaged fixtures through real
  `sqlite3`/`db_verify` as oracles; catalog which structural checks
  predict "opens".
- Sources: `https://cryptorecovers.com/wallet-recovery/bitcoin-core/`
  ("damaged structure vs lost keys are different problems").

### 5. Guided mode: tell me which command to run (days, just-works multiplier)

- Grounding: 9 modes × ~25 flags; probes show each mode fails well,
  but nothing helps a new user pick one. Raw vs `-fs` vs `-walk` vs
  `-unallocated-only` is a real decision tree.
- Sketch: `-advise TARGET` inspects the target (partitioned?
  filesystem? directory? size?) and prints the recommended command
  with reasons — no scanning, pure routing. Never auto-runs.
- Next evidence step: prototype the advisor over 4 fixtures (raw
  file, partitioned disk, ext image, directory); assert each routes
  correctly.

### 6. Embedding pass: quiet logging + cancellation (days)

- Grounding: Goal 19 second reader hit unconditional stderr spam
  (documented wart); `Options` has no writer and no context
  (`runPipeline` mints `context.Background()` internally).
- Sketch: `Options.Log io.Writer` (nil = stderr, default output
  byte-identical) and `Options.Context` (nil = Background)
  threaded to the pipeline; document cancel semantics (prompt
  return, checkpoint left behind, no goroutine leaks — tested).
- Next evidence step: enumerate library stderr writes; spike both
  fields; prove default behavior byte-identical + cancel prompt.

### 7. Baseline/allowlist for repeat sweeps (days)

- Grounding: every `-walk` re-reports known fixtures; gitleaks'
  answer is baselines + allowlist config. Without it, repo hygiene
  is one-shot. (Idea 2's dogfood step will hit this immediately.)
- Sketch: `-baseline hits.jsonl` suppresses known findings.
  Fingerprint design is the work: raw offsets drift as files
  change — likely (relpath, needle, line-hash) for walk mode, with
  documented drift behavior.
- Next evidence step: design spike — fingerprint stability across
  3 edit patterns (append, insert-above, rewrite).
- Sources: `https://rafter.so/blog/secrets/gitleaks-vs-trufflehog`
  (allowlist/baseline practice).

### 8. Offline secret verification, narrow (days)

- Grounding: TruffleHog's `--only-verified` is the market's FP
  answer and the top-cited secret-scanning pain; online checks stay
  excluded, but structural checks are untouched territory.
- Sketch: validate PEM block bodies (base64-decodes, parses as DER
  SEQUENCE) to kill truncated/garbage matches; report confidence
  per hit. Parsing only — still never derivation, never key use.
- Next evidence step: measure FP reduction on the noise corpus +
  crafted truncations; confirm no key-material handling beyond
  structure (privacy audit).
- Sources: `https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools`
  (verified vs pattern matching).

### 9. Password-recovery handoff hardening (days)

- Grounding: forgotten passwords are the mass pain (most sources;
  BTCRecover/Hashcat workflows are expert-only: token lists, `-m
  11300`, salt-type mapping). `-hashes` emits crack-ready hashes;
  the runbook is unverified prose.
- Sketch: verify every `PASSWORD_RECOVERY.md` command against real
  hashcat/John in a container (mode numbers, hash formats), add a
  "which mode for my wallet" decision table. No new brute-force
  code — handoff only.
- Next evidence step: run each emitted hash format through
  `hashcat --help`/benchmark in a container; fix what fails.
- Sources: `https://github.com/bleaknarratives/cipher_digital_invesigation/blob/HEAD/carter-university/resources/cheat-sheets/wallet-recovery.md`
  (hashcat `-m 11300` flow).

### 10. Install polish: Homebrew tap + Windows managers (days, needs decisions)

- Grounding: documented gaps (README: no tap; Goal 18 non-goal:
  Windows managers unevaluated). macOS users unzip archives.
- Sketch: create the tap repo + install smoke on macOS; evaluate
  winget (and decline or do chocolatey with rationale). Blocked on
  tap-ownership decision (open since the last brainstorm).
- Next evidence step: user decision on tap ownership; then tap +
  smoke in one session.

### 11. Completions + man page (hours, previously recommended, never scheduled)

- Grounding: 2026-09-18 brainstorm Decision 2 recommended generated
  completions + man page instead of a CLI rewrite; neither exists.
- Sketch: generate both from the flag table (no new deps —
  hand-rolled generator over `flag.VisitAll`); install via deb/rpm
  + container.
- Next evidence step: generate, install the deb, tab-complete and
  `man findbtc` in a container.

### 12. Parked behind demand: APFS, EWF2, new exporters

- Grounding: Goal 22 precedent (no code without demonstrated
  demand); APFS matters to Mac owners, EWF2 to labs with newer
  acquisition defaults — neither has an ask.
- Sketch: nothing until an ask arrives with a sample to validate
  against. Revisit trigger is a user interview or an enabled
  demand channel (issues/discussions — themselves a recommendation
  from Goal 22).

## Validation Plan

- Proposal quality: each idea cites grounding; no external product
  claim without a Sources URL. Verify by re-reading this file.
- Idea 0: table matches `git log`; `-profile` in usage; namespace
  note present.
- Idea 1: non-technical second reader reaches the right next action
  for 5 sample hits without asking questions (Goal 19 bar).
- Idea 2: fixture repo fails pre-commit on a planted secret, passes
  clean; default exit behavior unchanged (existing suite + probe).
- Idea 3: recovered entries match `fls`/`icat` on fixtures; FP bar
  tests per format.
- Idea 4: validator verdicts match real `sqlite3`/`db_verify`
  open-checks on the fixture set.
- Idea 5: 4 fixtures route to the documented-best command.
- Idea 6: default stderr byte-identical; cancel returns promptly
  with no goroutine leak (test with leak detection).
- Idea 7: baseline suppresses known hits across the 3 edit patterns;
  new hits still report.
- Idea 8: truncation fixtures rejected; noise corpus still silent;
  privacy audit notes what bytes were touched.
- Idea 9: every runbook command executed verbatim in a container.
- Idea 10: tap install + winget install smoke green.
- Idea 11: completion + man render from the generator in a container.
- Highest-risk validation: idea 1's reader test (plain-language
  quality can't be unit-tested) and idea 3's scope (FAT looks small
  until long filenames + exFAT bitmaps — timebox the spike).

## Risks / Rollback

- Scope creep: 12 ideas exceed any single session; mitigation is the
  ranking — approve a top slice, park the rest here.
- Trust risk (idea 1): guidance for desperate users must be
  conservative and scam-aware; every claim needs a source or a test,
  and "when to stop" sections are mandatory, not optional.
- Contract churn (idea 2): exit codes are a consumer contract;
  mitigation is opt-in flag + frozen defaults + documented codes.
- Detector dilution (idea 8): new matching logic risks the FP bar;
  mitigation is the standing per-format bar + privacy audit.
- Rollback: this plan changes nothing; each future idea lands behind
  its own tests and can revert independently.

## Open Questions

- Top slice: approve ideas 0–2 as the next goals, amend, or cancel?
- Tap ownership (carried, second ask): create
  `pauljones0/homebrew-findbtc`, or keep declining?
- Secret types categorically off-limits beyond standing exclusions
  (carried, still open)?
- Demand channel: enable issues or discussions so toolchain asks
  have somewhere to land (Goal 22 recommendation)?
- "24 hour": depth signal (assumed, as last time) vs a scheduled
  24h-later follow-up — want a recurring check-in scheduled?

## Sources

- `https://walletrecovery.info/articles/how-to-recover-your-corrupt-or-deleted-bitcoin-core-wallet/`
  — corrupt/deleted wallet triage; supports idea 1.
- `https://cointimeatm.com/how-to-recover-my-lost-bitcoin-wallet/`
  — scam warnings in recovery guides; supports idea 1.
- `https://www.neuralgrimoire.com/i-lost-my-bitcoin-wallet/` —
  clone-first recovery discipline; supports ideas 1, 3.
- `https://cryptorecovers.com/wallet-recovery/bitcoin-core/` —
  structure-vs-keys distinction; supports idea 4.
- `https://www.cgsecurity.org/testdisk_doc/photorec_video.html` —
  carver fragmentation limits; supports idea 3.
- `https://dev.to/chintanshah35/trufflehog-vs-gitleaks-vs-github-secret-scanning-why-most-ci-scanners-fail-2026-1372`
  — CI scanner expectations; supports idea 2.
- `https://rafter.so/blog/secrets/gitleaks-vs-trufflehog` —
  allowlist/baseline practice; supports idea 7.
- `https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools`
  — verified vs pattern matching; supports idea 8.
- `https://github.com/bleaknarratives/cipher_digital_invesigation/blob/HEAD/carter-university/resources/cheat-sheets/wallet-recovery.md`
  — hashcat wallet flow; supports idea 9.
- `https://github.com/jakewins/findbtc` issues — what's-next ask;
  supports idea 1.
