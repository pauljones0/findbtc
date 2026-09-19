#!/bin/sh
# Regenerate the Goal 12 sfdisk oracle: real partitioned images plus
# `sfdisk -d` dumps that TestPartitionOracleCrossCheck replays.
# Unprivileged (plain files, no loop mounts). Usage:
#   sh scripts/part-oracle.sh [DIR]   # default DIR=/tmp/fbt-part-oracle
#   FBT_PART_ORACLE_DIR=DIR go test ./detector/ -run TestPartitionOracleCrossCheck -v
set -eu
DIR="${1:-/tmp/fbt-part-oracle}"
mkdir -p "$DIR"

# GPT: three Linux partitions.
truncate -s 64M "$DIR/gpt-3part.img"
sfdisk --force "$DIR/gpt-3part.img" <<'EOF'
label: gpt
start=2048, size=32768, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="p1"
start=34816, size=32768, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="p2"
start=67584, size=32768, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="p3"
EOF
sfdisk -d "$DIR/gpt-3part.img" > "$DIR/gpt-3part.sfdisk"

# MBR: one primary plus an extended container holding two logicals.
truncate -s 64M "$DIR/mbr-ebr.img"
sfdisk --force "$DIR/mbr-ebr.img" <<'EOF'
label: dos
start=2048, size=32768, type=83
start=34816, size=94208, type=5
start=36864, size=32768, type=83
start=71680, size=32768, type=7
EOF
sfdisk -d "$DIR/mbr-ebr.img" > "$DIR/mbr-ebr.sfdisk"

echo "oracle images in $DIR:"
ls -la "$DIR"
