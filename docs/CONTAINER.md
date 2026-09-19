# Blessed container image

Labs that standardize on pinned container images should use
`ghcr.io/pauljones0/findbtc`, published by the tag release workflow.
Pull it digest-pinned and scan a mounted evidence file:

    docker pull ghcr.io/pauljones0/findbtc:vX.Y.Z
    docker pull ghcr.io/pauljones0/findbtc@sha256:<digest from the release notes>
    docker run --rm -v ./evidence:/evidence:ro \
      ghcr.io/pauljones0/findbtc@sha256:<digest> /evidence/disk.img

Tags per release: the version (`vX.Y.Z`) and `latest`. Pin the digest
for casework — `latest` moves.

## Image facts

- Base: `scratch` + the exact release binaries (no shell, no package
  manager). amd64 image is ~10 MB on disk.
- Platforms: `linux/amd64`, `linux/arm64` (one manifest).
- User: `65534:65534` (non-root). Entrypoint: `findbtc`, so image
  arguments are findbtc arguments (`-version`, `-json`, `-profile`,
  ...).
- Ships `LICENSE` and `README.md` under `/usr/share/doc/findbtc`.

Raw-device scans need the device plus privileges (drop back to root
for the device nodes):

    docker run --rm --privileged --user 0 \
      -v /dev:/dev:ro ghcr.io/pauljones0/findbtc:vX.Y.Z /dev/sda

Prefer carving and case logs onto a mounted volume, never onto the
evidence mount.

## Provenance

The image wraps the release binaries byte-for-byte (same files as the
tarballs, covered by `checksums.txt` and the SLSA provenance
attestation — see [RELEASE.md](RELEASE.md)). A digest pin therefore
binds the image to one attested build. The image itself carries no
separate attestation.

## Evaluation record (Goal 21)

Chosen: GoReleaser `dockers_v2` (the supported path; the v1 Docker
pipe is deprecated). One pipeline builds archives, packages, and the
image from the same binaries, and multi-arch packaging needs no
emulation (scratch + `COPY` only), so both release arches ship with
no extra cost. Rejected: a standalone Dockerfile + registry workflow
— a second Go build path whose binaries would differ from (and lack
the provenance of) the release binaries.

Verified locally (snapshot build): per-arch images build, `-version`
and a volume-mount fixture scan pass from the amd64 image, and a
digest-pinned pull + mount-scan passes against a local registry.
GHCR publishing itself runs on the next tag via `release.yml`
(buildx + registry login already wired). Multi-arch beyond
amd64/arm64 was not justified: those are the arches the releases
ship. No Helm chart (non-goal).
