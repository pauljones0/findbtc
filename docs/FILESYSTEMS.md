# Filesystem-aware recovery

Raw scanning finds wallet traces anywhere, but it loses filenames, wastes
time on live data, and cannot tell a deleted file from noise. The
filesystem layer reads NTFS and ext metadata so deleted-but-referenced
files come back **with their names**, and raw scans can skip everything
still allocated.

## Modes

List and scan deleted entries (names on every hit):

    findbtc -fs /path/to/image.bin [-json] [-extract-dir DIR]
    findbtc -fs /dev/sdb1 -fs-offset 1048576   # volume starts mid-file

Scan only free space (deleted content, no filenames):

    findbtc -unallocated-only /dev/sdb1 [-json]

`-fs-offset` points at the volume boot sector when the image starts
earlier (full-disk captures, concatenated evidences). Partition tables
are not followed: point at the volume (e.g. `/dev/sdb1`), not the disk.

`-report` shows `file=` for hits that carry a filename.

## What each filesystem yields

**NTFS** parses the MFT: every record with a `$FILE_NAME` is inventoried
live or deleted (in-use flag), Win32 names preferred over 8.3 aliases,
content from resident values or data runs (extension records merged).
`$Bitmap` drives unallocated-only. Deleted entries usually keep names,
runs, and content until the record or clusters are reused.

**ext** (2/3/4) walks the inode tables and directories: unlinked inodes
(link count 0) give content via extents, direct, or single-indirect
blocks; names come from live entries, unlinked directories (which
re-associate names to deleted inodes), and residual zeroed entries —
including names hiding in merged `rec_len` slack. Block bitmaps drive
unallocated-only. Orphan content with no surviving name is stamped
`inode:N`.

**Out of scope:** APFS; RAID rebuild; double/triple-indirect ext blocks;
compressed/encrypted/sparse NTFS content (parsed structurally, read back
raw); directories themselves (files only); live-file name attribution in
raw scans.

## SSDs, TRIM, and when recovery is hopeless

Filesystem metadata describes where content *was*, not where it still
is. On a spinning disk, freed clusters keep their bytes until reused —
deleted-file recovery works well. On an SSD, TRIM proactively erases
freed blocks, often within seconds of deletion:

- If TRIM ran (any modern OS on a TRIM-enabled SSD), unallocated space
  reads back zeros or garbage regardless of what metadata says. The
  inventory may name a deleted `wallet.dat` whose extents are blank:
  that is expected, not a parser bug.
- `--unallocated-only` on a TRIMmed SSD finishes suspiciously fast with
  nothing found. Cross-check with a full raw scan: identical silence
  confirms erasure rather than a metadata miss.
- Imaging through a TRIM-passing path (some USB bridges, RAID
  controllers, `fstrim`'d snapshots) destroys the same data the
  original would have kept.
- The only fix is an older image: backups, volume shadows, or a capture
  taken before deletion.

Rule of thumb: metadata recovery answers "what was deleted and where";
only the bytes answer "what survives". Always image before browsing —
every mount and every boot risks TRIM and reuse.
