# Releases: verification and redistribution

Every tagged release (`v*`) is built by GitHub Actions via GoReleaser
and ships with checksums, per-archive SBOMs, and SLSA build
provenance. Verify a download before trusting it with evidence.

## What a release contains

Each platform archive (`findbtc_<version>_<os>_<arch>.tar.gz`,
`.zip` on Windows) holds the `findbtc` binary plus `LICENSE` and
`README.md`. Linux users should prefer the managed packages
(`findbtc_<version>_linux_<arch>.deb` / `.rpm`, per arch), which
install the binary to `/usr/bin` plus docs under
`/usr/share/doc/findbtc`. Alongside the archives, the release page
carries:

- `checksums.txt` — SHA-256 of every archive, package, and SBOM.
- `<archive>.sbom.json` — SPDX 2.3 software bill of materials per
  archive (the binary is nearly dependency-free: Go stdlib plus
  `golang.org/x/sys`).
- A SLSA v1 provenance attestation per archive and SBOM, signed by
  the build's GitHub OIDC identity.

## Verifying a download

1. Fetch the archive, `checksums.txt`, and the `.sbom.json` files
   from the release page.
2. Check integrity:

       sha256sum -c checksums.txt

3. Check provenance (needs a `gh` CLI with `attestation`
   support) against the archive you will run:

       gh attestation verify findbtc_*_linux_amd64.tar.gz \
         -R pauljones0/findbtc

   A passing report binds the archive to the exact repository commit
   and workflow run that produced the release. Repeat for the
   `.sbom.json` files if you rely on them.
4. Optionally inspect the SBOM for the platform you run:

       python3 -c "import json,sys; \
         [print(p['name'], p.get('versionInfo')) \
          for p in json.load(open(sys.argv[1]))['packages']]" \
         findbtc_*_linux_amd64.tar.gz.sbom.json

   Expect `github.com/pauljones0/findbtc` at the release commit,
   `golang.org/x/sys`, and the Go toolchain — nothing else fetches
   code at build time.

## Reproducing a build

Tagged builds stamp `main.version` with the tag. To rebuild from
source and compare:

    git checkout vX.Y.Z
    go build -o findbtc-repro .
    ./findbtc-repro -version   # findbtc vX.Y.Z

Byte-identical reproduction is not promised (Go build IDs embed
paths), but `-version`, the SBOM module list, and behavior must
match the release.

## Redistribution

findbtc is GPL-3.0-or-later; `LICENSE` ships inside every archive.
When you redistribute a release — to a lab machine, a case share,
or a customer — include the archive, its `.sbom.json`, and
`checksums.txt` together so the recipient can repeat the checks
above.

Snapshot builds (version `*-SNAPSHOT-*`) are CI/dev artifacts, never
published to releases; treat them as untrusted for casework.

## Package-manager automation (maintainers)

The Homebrew tap ([homebrew-findbtc](https://github.com/pauljones0/homebrew-findbtc))
and Scoop bucket ([scoop-findbtc](https://github.com/pauljones0/scoop-findbtc))
pin immutable release assets; the bootstrap copies live under
`packaging/` and `scripts/verify-packaging-pins.py` fails CI if any
entry's URL, architecture, version, or hash stops matching the
release's `checksums.txt` (its `--self-test` proves the binding
checks against offline fixtures, so swapped hashes cannot pass).

- Tap: GoReleaser's `homebrew_casks` block rewrites the cask per
  release, but `skip_upload` stays true until cross-repo push
  credentials exist — the default `GITHUB_TOKEN` cannot push to
  the tap repo. Until then, update `Casks/findbtc.rb` by hand
  from `packaging/homebrew` on each release. To automate:
  create a classic PAT with `repo` scope on both `findbtc` and
  `homebrew-findbtc`, store it as the `TAP_GITHUB_TOKEN` repo
  secret, flip `skip_upload` to false, and point the release
  workflow's GoReleaser `GITHUB_TOKEN` at that secret. (External
  step; the PAT is a long-lived credential — rotate it
  deliberately and never broaden its scopes.)
- Bucket: self-updating. The manifest's `checkver`/`autoupdate`
  stanzas plus the bucket's scheduled `checkver` workflow bump
  `bucket/findbtc.json` after each release with no extra token;
  just confirm the workflow stays green.
- Winget: manifests under `packaging/winget` are prepared and
  CI-validated (`winget validate` + local `--manifest` install
  on Windows), but community submission stays a manual,
  separately-authorized step: place them under
  `manifests/p/pauljones0/findbtc/<version>/` in a
  `microsoft/winget-pkgs` PR. Until that PR merges, users
  install from the local files (see README).
