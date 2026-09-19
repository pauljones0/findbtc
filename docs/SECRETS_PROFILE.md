# The secrets profile (`-profile=secrets`)

The default scan looks for wallet traces. The secrets profile adds
non-wallet matchers for secret hygiene on repos, laptops, and images —
same pipeline (blocks → matchers → carves), same FP bar, same
carve/DFXML/report machinery:

    findbtc -profile=secrets -walk ~/src > secrets.jsonl
    findbtc -report secrets.jsonl

The profile applies to every scan mode (`-walk`, `-fs`,
`-unallocated-only`, raw). The default profile is byte-identical in
behavior whether secrets exist in the input or not
(`TestDefaultProfileEquivalence`); an unknown `-profile` value fails
loudly instead of scanning with a guessed detector set.

## Matchers

All credential material in this section is fake.

| Needle label | Shape | Notes |
|---|---|---|
| `pem-private-key` | A `-----BEGIN ... PRIVATE KEY-----` header line (`PRIVATE KEY`, `RSA`, `DSA`, `EC`, `OPENSSH`, `ENCRYPTED`, `PGP PRIVATE KEY BLOCK` variants) | Only the header line matches; the key body is never inspected, hashed, or derived from. Public-key headers (`PUBLIC KEY`) do not match. |
| `aws-access-key` | `AKIA` + 16 uppercase alphanumerics, e.g. `AKIAIOSFODNN7EXAMPLE` | The access key ID only; the paired secret is a 40-char base64 string with no anchor and is not matched. |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 base62 chars | Classic PATs plus the OAuth/user/server/refresh families. Short or truncated bodies do not match. |

Detections carry labels and offsets only — never key, token, or block
bytes. Reports classify all three at high confidence with
rotate/revoke next steps (`TestSummarizeSecretsPlaybook`).

## Recall and false-positive bar

Each matcher has a documented recall fixture in
`detector/secrets_test.go` (`TestSecretsRecall`, `secret*cue`
constants) and meets the same bar as the wallet detectors
(`TestSecretsNoiseCorpus`): silence on 1 MB of deterministic random
bytes and on the project's own prose (LICENSE, README, GOALS,
main.go).

## Gating CI and commits

`-fail-on-hit` exits 3 when a scan, `-walk`, or `-report` finds
anything (without it, finding hits still exits 0). Two samples ship
in `samples/`:

- Pre-commit hook: `cp samples/pre-commit .git/hooks/pre-commit`.
  Fails the commit on secrets; override the binary with
  `FINDBTC=/path/to/findbtc`. It sweeps the whole worktree, so for
  large repos prefer the CI gate below.
- GitHub workflow: copy `samples/secrets-gate.yml` to
  `.github/workflows/`. It runs the same sweep from the blessed
  container image.

Both run `-walk -profile=secrets -fail-on-hit`, so local and CI
gates agree by construction.

## Baselines for repeat sweeps

Accepted findings (reviewed false alarms, fixture secrets) would
otherwise fail every future gate. Record them once, then suppress by
fingerprint:

    findbtc -walk ~/src -profile=secrets -json > sweep.jsonl
    # review sweep.jsonl, then keep the accepted hits as the baseline:
    findbtc -walk ~/src -profile=secrets -fail-on-hit -baseline sweep.jsonl

Add the same `-baseline known.jsonl` to the pre-commit hook and the
CI workflow so local and remote gates agree. The sweep reports
`N suppressed by baseline` on stderr; suppressed hits never reach
stdout and never trip `-fail-on-hit`.

Each finding is keyed by repository path + needle + a hash of the
full line holding the match — never raw offsets, which edits move.
Appending lines, inserting lines above a hit, and rewriting the file
around it all keep the key stable, so accepted hits stay silent.
Changing the line (rotating a secret), adding a same-type secret
elsewhere in the file, or converting line endings changes the key,
so the finding reports again: when in doubt the baseline re-reports
rather than swallows. Baselines store hashes, not secret bytes, but
a low-entropy line stays guessable from its hash — keep baseline
files with the swept tree, not in a public place. There is no fuzzy
matching and baselines never auto-update: re-review and re-record
deliberately.

## Responding to hits

1. Treat any carve as a live secret: move it to encrypted storage,
   never paste hits into tickets, chats, or websites.
2. `pem-private-key`: rotate the key, then purge it from the repo or
   image it leaked from (rewriting history if it was committed).
3. `aws-access-key`: revoke it in IAM unless you own it and it is
   still needed, then check CloudTrail for misuse between leak and
   revocation.
4. `github-token`: revoke it at github.com/settings/tokens, audit
   what it touched, and rotate anything it could reach.

## Non-goals

- Private-key derivation is never attempted.
- Found secrets are never verified online (no AWS/GitHub API calls).
- The secrets profile never changes default-profile detections.
