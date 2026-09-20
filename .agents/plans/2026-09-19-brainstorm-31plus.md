# Brainstorm — 2026-09-19 (Goals 31+)

Session goal: find the next ranked pain-point goals after the 23–30
chain. Inputs: leftover triage from the 09-19 brainstorm (ideas 9–12,
open questions), a hands-on just-works audit (fresh build, first
runs, error paths, exit codes), a consumer-contract inventory (CLI,
exits, schema, library, docs), a re-audit of the five user flows,
and web pain-mining (wallet-recovery guides, PhotoRec complaints,
gitleaks/TruffleHog friction, BTCRecover know-how barriers, DFIR
filesystem gaps, seed-recovery math).

Decisions:

- Rank by pain observed outside this repo, not by symmetry with
  what we already built. "More of the same" loses to "a whole job
  that currently fails."
- Leftovers 9–11 survive, re-ranked by fresh evidence: password
  handoff (9) moves UP (tokenlist pain is well documented);
  Homebrew (10) stays (README still apologizes to macOS users);
  completions/man (11) stays last (still polish).
- Idea 12 stays parked, with one correction: APFS is covered by
  TSK upstream, so the real filesystem gap is Btrfs/XFS/ZFS (see
  web notes). Still demand-gated — no demand arrived.
- Assumed again: "24 hour" is a depth signal for the brainstorm,
  not a scheduled follow-up. Correct me if it means a 24h-later
  check-in.
- Proposed top slice for approval: Goals 31–33 (coverage honesty,
  offline seed completion, password-handoff verification). Details
  below; nothing is implemented until the slice is approved.

## Flows re-audit (post-23–30)

The five jobs from the last session, re-scored:

1. Owner triage — STRONG. -advise routes, WHAT_NEXT answers,
   -report summarizes, scam shield posted. Remaining hole: the
   loop after "you have a partial seed / encrypted wallet" still
   exits the tool into know-how barriers (BTCRecover tokenlists,
   missing-word math). Ideas 1–2 close it.
2. Forensics sweep — STRONG, one lie. Case logs, DFXML, carve
   custody, checkpoints, four filesystems + salvage verdicts.
   The lie: a scan that scanned nothing exits 0 (see just-works).
   Idea 0 fixes the contract; idea 7 extends filesystem demand.
3. Password recovery — WEAK (unchanged). Crack-ready export and
   PASSWORD_RECOVERY.md exist but are unverified against real
   tools. Idea 2.
4. Secret hygiene — STRONG but narrow. Gating, baselines,
   offline verification, privacy audit. The narrowness: working
   trees only — git history (where leaked secrets actually live)
   needs pipes we cannot yet read. Ideas 4–5.
5. Deep forensics — ADEQUATE. DFXML-only rationale stands; the
   parked exporters got no demand signal. No new goal.

New cross-flow finding: the tool is 10 modes × 30 flags with a
61-line usage screen. -advise papers over it for new users, but
every new mode makes the surface worse. Prefer flags on existing
modes over new modes from here on (ideas below add zero modes;
the seed completer should be a -report follow-up or a -hashes
sibling, not mode 11 — decide at goal time).

## Does it "just work"? (hands-on audit)

Fresh build + first runs, 2026-09-19 (dev binary from HEAD):

- `go build` clean; no-arg prints usage, exits 2; `-version`
  prints `findbtc dev`; missing path errors loudly, exits 1.
- Noise scan: silent on stdout, `[COMPLETE]` on stderr. FP bar
  holds by hand, not just by test.
- `-fs` on garbage: loud specific error, exit 1. Good.
- `-report` on empty input: "no detections — nothing to pursue",
  exit 0. Good.
- HOLE 1 (contract): unreadable root target (`chmod 000`) prints
  "Unable to scan target" and exits 0. A caller/CI reading 0 as
  "clean" gets a false negative. -walk with failed files is the
  same class (failures never touch the exit code). Raw-scan
  tolerance exists for nested targets; for the ROOT target it is
  just wrong. Idea 0.
- HOLE 2 (long scans): progress shows percent, never rate or ETA.
  BTCRecover shows an ETA; multi-hour scans without one feel
  hung. stderr progress is unversioned, so this is additive.
  Idea 3.
- HOLE 3 (pipes): `-` stdin works for report/dfxml/hashes/
  salvage/watch inputs, but no SCAN mode reads stdin. `dd`,
  `ssh`, and cloud-image pipes cannot feed the tool. Idea 4.
- HOLE 4 (batch): one positional target; 20 images means 20
  shell loops and 20 fragmented outputs. Idea 8 (ranked low:
  scripting mostly copes).
- macOS: still "install from archives" (idea 6). Windows: same,
  plus untested privilege UX (not probed; no Windows box here).

## Consumer contract audit

- CLI: 10 modes, 30 flags, exit contract 0/1/2/3 — minus hole 1.
  Usage screen is complete but is now the longest doc most users
  will ever read; completions/man still absent (idea 9).
- `-json`: hits-v1 frozen with optional-only growth; two new
  optional fields this chain (fingerprint, verified) followed
  the rule. Strongest part of the contract.
- Library: 37 exported funcs, doc.go tiers, Log/Context
  embedding (G28). Nits: no `detector.Version` const (version
  lives in main; library case logs stamp whatever the caller
  passes); no CHANGELOG consumed by humans (git log only).
- Docs: 13 files, good README discovery except 3 orphans
  (BENCHMARKS, PIPELINE_INGEST, RESOURCE_BOUNDS — linked from
  nowhere user-facing). WHAT_NEXT is the best doc; PASSWORD_
  RECOVERY is the least trustworthy (unverified commands).
- Demand channel: issues AND discussions both disabled. There
  is still no way for a stranger to ask for APFS/Btrfs/XFS,
  more secret types, or anything else. Process question, not a
  goal — but every demand-gated item is secretly decided by it.

## Web pain notes (2026-09-19)

- Wallet recovery guides all funnel to: Recuva/PhotoRec (file-
  NAME search: useless if the name is gone), pywallet (Python 2
  era) for corrupt wallets, or $$$ professional services — with
  "don't run unfamiliar repair tools" as standard advice. Our
  content-addressed + named-FS recovery is positioned against
  exactly this; nothing found contradicts the approach. Scam
  warnings are universal (validates the G23 shield).
- PhotoRec's missing filenames is THE canonical complaint
  (Tom's Hardware, TestDisk docs, every guide). Fragmented
  files are the second ("PhotoRec expects non-fragmented").
  Our FS layer answers both for covered filesystems.
- gitleaks: orgs now need a GITLEAKS_LICENSE key for the v2
  action (free trial tier — friction + monetization direction,
  not a hard paywall). TruffleHog `--only-verified` is the
  documented migration for zero-FP gating; complaints are rate
  limits, prose-scan cost, and CVEs. Wedge for us: free,
  offline, no license key, no verification callbacks — but ONLY
  if we reach git history (idea 5), where the secrets are.
- BTCRecover: the tool works; the pain is know-how — tokenlist
  authoring ("easy tokenlist" test threads), version confusion,
  address-DB setup. A generated tokenlist + verified handoff
  (idea 2) attacks the documented hard part.
- Seed recovery: single-missing-word brute force is well
  trodden (BTCRecover, bip39-word-finder); the math (2048
  tries, checksum-gated) is settled. The gap is the handoff:
  findbtc FINDS partial seeds but cannot complete them (idea
  1). 3+ missing words is billions of tries — must refuse.
- DFIR: free tools lag on XFS/Btrfs/ZFS (SleuthKit/Autopsy
  stuck at ext + TSK-covered APFS); commercial tools also
  thin. If demand ever arrives, this is the filesystem order
  (idea 7), not APFS.

## Idea 0 — Coverage honesty (exit codes + skipped accounting)

Goal 31 candidate. Pain: the tool can scan nothing and report
success. Unreadable root target exits 0; a walk that failed
files exits 0; only -fail-on-hit moves the code, and only for
hits. CI and scripts trust 0. Forensics tools must not lie
about coverage; ours does, in exactly the case (dead drive,
bad permissions) where the truth matters most.
Complete when: (a) a scan whose ROOT target fails exits 1 with
the reason on stderr (nested-target tolerance unchanged);
(b) -walk exits 1 when files failed AND nothing was scanned...
no — decide at goal time between "any failure → 1" (strict,
breaks dirty-tree sweeps) and "zero coverage → 1" (lenient).
Recommend: exit 1 on zero coverage, plus a loud
`N skipped/failed` line whenever nonzero, and a -report note
distinguishing "no detections" from "nothing scanned". (c) The
exit contract table in README + exit-code test matrix updated.
Non-goals: changing hit exits (3 stays); per-file exit codes.
Verify: exit-matrix tests incl. the chmod-000 root, all-failed
walk, and nested-archive tolerance (still 0); gates.
Rank: FIRST. It is the only known case where the tool's own
contract misleads, and every downstream consumer (CI, library
servers, forensics reports) inherits the lie.

## Idea 1 — Offline seed completion (1–2 missing words)

Goal 32 candidate. Pain: "12th word smudged" is one of the
most common owner disasters, and the fix is 2,048 checksum-
gated tries — but today it requires BTCRecover know-how (see
web notes). findbtc already finds partial/fuzzy seeds (Goal 3)
and derives watch-only addresses (Goal 5); completion is the
missing middle that closes the owner loop end-to-end.
Complete when: (a) given 11-of-12 (or 23-of-24, or 2 missing
anywhere — 4M tries, still fast), the tool enumerates
checksum-valid completions offline, most-likely first, with a
loud refusal past 2 missing words (billions of tries — say
so, point at BTCRecover/GPU); (b) output feeds the existing
watch-only flow (candidates → addresses → balances) without
copy-paste; (c) near-miss correction: a wrong word with valid
checksum neighbors suggests them ("did you mean X?"); (d) the
anti-scam box travels with it (completing seeds is scam-adjacent
work; never ask for, print, or transmit full seeds beyond the
local terminal — reuse the --reveal warning pattern).
Non-goals: 3+ missing words; derivation-path brute force;
anything networked; spending. Verify: known-answer completions
(test vectors, all positions incl. checksum word); refusal
tests; no-network test (no new net imports in the path);
second-reader trial on the handoff text. Rank: SECOND. Highest
external pain per unit scope; turns two existing features into
one finished job.

## Idea 2 — Password-handoff hardening (verify vs real tools)

Goal 33 candidate. Pain: unchanged from last brainstorm, now
with fresh evidence — tokenlist authoring is BTCRecover's
documented hard part, and our crack-ready exports +
PASSWORD_RECOVERY.md have never been executed against real
hashcat/John/BTCRecover. An owner who reaches this step with
a broken handoff loses everything the scan found.
Complete when: (a) exported hashes crack with real John +
hashcat in CI (pinned versions, tiny known-answer corpus);
(b) a generated --tokenlist from hit context cracks a test
wallet in real BTCRecover (pip-installed in CI); (c) every
PASSWORD_RECOVERY.md command executed verbatim in CI and the
doc stamped with tool versions; (d) failure modes documented
(wrong wallet type → which error, cost estimates).
Non-goals: cracking inside findbtc; new export formats without
demand. Verify: CI jobs green; doc-commands test; gates.
Rank: THIRD. Closes the last unverified owner handoff; cost
is CI plumbing, not design risk.

## Idea 3 — ETA + progress honesty for long scans

Goal 34 candidate. Pain: multi-hour scans print percent with
no rate or remaining time; users cannot tell "slow" from
"hung" (BTCRecover sets the expectation with an ETA). Cheap
to fix, high perceived reliability.
Complete when: (a) stderr progress gains throughput + ETA
(bytes/sec, remaining) after a warmup window, stable (no
flicker: update at most 2×/sec, monotonic remaining); (b) the
default line shape stays parseable and documented; (c) -checkpoint
prints resume position on -resume ("continuing at 41%").
Non-goals: progress bars/TUI; changing -json. Verify:
golden progress tests with fake clock; gates. Rank: FOURTH.
Pure UX warranty work; no new capability.

## Idea 4 — stdin scanning (pipe-first flows)

Goal 35 candidate. Pain: `dd if=/dev/sdb | findbtc`,
`ssh lab 'dd ...' | findbtc`, cloud snapshots via pipes —
none work; the tool demands seekable files/devices. Forensic
triage over pipes and container-native flows (G21 image!) are
second-class without it. Design risk is real (carve needs
seek; checkpoints need offsets) so scope hard: stream with a
bounded spill file (documented location/size cap), carve
from the spill, no -resume on pipes (refuse loudly).
Complete when: (a) raw scan + secrets profile accept `-` with
byte-identical detections vs file input (proven by test on
fixtures); (b) spill behavior documented (where, how big,
cleanup); (c) loud refusals for -fs/-walk/-checkpoint on
pipes. Non-goals: seeking pipes (impossible); performance
parity with files. Verify: file-vs-stdin identity tests;
spill-cap tests; gates. Rank: FIFTH. Unlocks idea 5 and the
container story; ranked below the owner-loop closers.

## Idea 5 — Git-history secrets (meet leaks where they live)

Goal 36 candidate. Pain: working-tree-only scanning misses
committed-then-removed secrets — the actual leak shape — and
the gitleaks-license friction is a live wedge for a free
offline alternative. BUT: full git plumbing (rev-list,
diffs, renames, baselines-per-commit) is a second product.
Complete when (minimal honest slice): (a) `git log -p` piped
via idea 4 scans with findings attributed to commit + path
(parsed from the patch headers, dependency-free);
(b) baselines match across it (fingerprint = commit-independent
line hash — decide exact shape at goal time); (c) docs show
the two-command history gate; (d) demand check: only then
decide whether native `git rev-list` walking earns a goal.
Depends on idea 4; do not schedule before it. Non-goals:
native git object parsing; PR-range logic (shell already
does ranges); auto-fix. Verify: fixture repo with a leaked-
then-removed secret reports it with commit attribution;
gates. Rank: SIXTH (and gated). The wedge is real but the
slice depends on stdin; scheduling it now would be scope
smuggling.

## Idea 6 — Homebrew tap + Windows managers

Goal 37 candidate. Pain: unchanged — README apologizes to
macOS users; Windows users get archives and untested
privilege UX. Every install-friction report we will ever get
starts here. Blocked only on the ownership question (below):
tap under pauljones0 vs third-party.
Complete when: (a) `brew install pauljones0/tap/findbtc`
works from a layman's terminal (smoke in CI on macos);
(b) Windows story decided and documented: winget and/or
Scoop, or an explicit "archives only, here's why";
(c) install docs show copy-paste commands per OS, each
executed in CI. Non-goals: distro repos (Debian/Fedora
inclusion); auto-update. Verify: CI install smokes;
gates. Rank: SEVENTH. Distribution, not capability — but
the apology is in our own README.

## Idea 7 — Filesystems by demand: Btrfs/XFS/ZFS

Demand-gated, unscheduled. Pain (validated, no demand):
DFIR sources confirm free tools lag on XFS/Btrfs/ZFS while
TSK covers APFS — so if a stranger ever asks, THIS is the
order, and APFS leaves the list. Read-only deleted-entry
recovery with names, same bar as Goal 25 (fls/icat-class
oracle per format). Do not schedule without a named
requester; the demand channel question below is the actual
blocker. (Also note: ZFS deleted recovery may be
architecturally hopeless — copy-on-write + no undelete
trail; spike before promising.)

## Idea 8 — Multi-target scans + unified report

Goal 38 candidate. Pain: triaging 20 images means 20 shell
loops, 20 JSON files, 20 case logs, hand-merged. Low but
real; scripting copes, forensics reports do not.
Complete when: (a) multiple positionals and/or `-targets
FILE` scan in one run with one hits.jsonl (per-hit target
already recorded) and per-target case-log records;
(b) per-target failures follow the idea-0 rules (one bad
image must not zero the run, must not lie either);
(c) -report groups by target. Non-goals: parallel targets
(measure first); glob expansion (shell does it). Verify:
mixed good/bad batch fixture; gates. Rank: EIGHTH. Real,
narrow, unglamorous.

## Idea 9 — Completions + man page

Goal 39 candidate. Pain: unchanged, still smallest — 30
flags with no completion and no man page; `--help` (61
lines) is the whole story. Fold the 3 orphan docs into the
man page's SEE ALSO while here.
Complete when: (a) bash/zsh/fish completions generated from
the real flag table (never hand-listed — test asserts every
flag present); (b) man page generated from the same source,
installed by deb/rpm; (c) orphans linked. Non-goals: TUI;
interactive help. Verify: completion freshness test; gates.
Rank: NINTH (last). Polish that compounds if the surface
keeps growing — which idea 0's "no new modes" rule should
prevent.

## Parked (no change, with notes)

- EWF2 write path: still conversion-pointer only; no demand.
- New DFXML exporters (CSV/Elastic): no demand; DFXML-only
  rationale stands.
- Live secret verification (TruffleHog-style API callbacks):
  NEVER — contradicts the offline posture and the G23 shield.
  The `verified` field means parses, and must keep meaning
  exactly that.
- Interactive wizards: still a non-goal pattern (-advise is
  the armature; do not grow it a prompt loop).
- Password cracking inside findbtc: still out; handoff only.
- APFS: removed from the gap list (TSK covers it); see idea 7.

## Open questions for the user

1. Tap ownership (3rd ask): `pauljones0/homebrew-tap` blessed,
   or third-party tap + docs pointer? Blocks idea 6.
2. Demand channel (2nd ask, now louder): issues + discussions
   are both disabled, so every demand-gated item (idea 7,
   secret types, exporters) is decided by silence. Enable
   discussions (low-noise) to give strangers a door? Or keep
   the moat and let demand arrive by email?
3. "24 hour" (2nd ask): still assuming depth signal. If it
   means a scheduled 24h-later follow-up, say so and I'll put
   the check-in on the calendar instead.
4. Seed-completer shape: `-report` follow-up on partial-seed
   hits, or a `-hashes`-style sibling mode? Leaning follow-up
   (no mode 11).
5. Secret-type boundaries: still no asks, so no new matchers
   proposed. Confirm the standing rule: named victim + corpus
   evidence before any new secret type?

## Proposed top slice (Goals 31–33)

For approval — implement in chain order, per-goal audits as
before:

- Goal 31 (idea 0): coverage honesty — the tool stops lying
  about unscanned bytes. Smallest scope, highest trust value;
  every other consumer inherits it.
- Goal 32 (idea 1): offline seed completion — closes the
  owner loop find → complete → watch, the most common disaster
  class on the web.
- Goal 33 (idea 2): password handoff verified against real
  BTCRecover/hashcat/John in CI — closes the last unverified
  handoff.

Then 34 (ETA), 35 (stdin), 36 (git history, gated on 35),
37 (tap), 38 (batch), 39 (completions) in rank order unless
demand reorders them.

