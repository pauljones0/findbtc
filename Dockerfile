# findbtc release image. GoReleaser builds this per platform from the
# prebuilt release binaries (never `go build` here): the context holds
# one $TARGETPLATFORM directory per platform with the binary plus the
# nFPM packages and extra_files.
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/findbtc /usr/bin/findbtc
COPY LICENSE /usr/share/doc/findbtc/LICENSE
COPY README.md /usr/share/doc/findbtc/README.md
# Non-root by default; raw-device scans need --privileged --user 0
# (see docs/CONTAINER.md).
USER 65534:65534
ENTRYPOINT ["/usr/bin/findbtc"]
