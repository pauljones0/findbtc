# Live-system sweep runbook

`-walk` sweeps every regular file under a directory with the standard
detectors — the mode for laptops, live systems, and repos:

    findbtc -walk /home/user -json > sweep.jsonl
    findbtc -report sweep.jsonl

Add `-extract-dir ./carve` to keep bytes around each hit, and
`-case-log sweep-case.jsonl` for one JSON record per file swept
(source identity, streaming hashes, counts).

## Policy

- **Symlinks are not followed by default.** Symlink entries are
  counted as skipped and left alone, so loops are impossible.
  `-walk-follow-symlinks` opts in; looped or broken links then fail
  safe per link (recorded, sweep continues). A symlinked `-walk`
  root itself is refused unless following is on.
- **Only regular files are scanned.** Directories are descended;
  sockets, fifos, and devices are counted as skipped, never opened.
- **One unreadable file never aborts the sweep.** The path and error
  join the failure list (first 32 printed, all counted) and the sweep
  continues. The summary line reports files, detections, skips, and
  failures, plus a loud `WARNING` whenever any file failed. Exit
  stays 0 once at least one file was scanned; a sweep that scanned
  nothing (empty tree, every file failed) exits 1.
- **The sweep skips its own output.** A carve directory or case-log
  file inside the walked tree is never scanned.
- `-checkpoint`/`-resume` and `-s` are refused with `-walk`: a single
  offset cannot resume a file list. `-walk-maxdepth N` bounds descent
  (root is depth 0, 0 means unlimited).

## Live-system notes

- Sweeping `/` reads pseudo-filesystems: `/proc` and `/sys` entries
  report odd sizes and can stall or error per file (recorded, swept
  on). Prefer concrete roots (`/home`, `/etc`, `/var`, `/opt`) and
  add pseudo-filesystems only deliberately.
- Run with the privileges your coverage needs: unreadable files are
  reported, not bypassed. Compare the swept-files count against your
  inventory — a sweep that skipped half the tree to permissions is
  honest but incomplete.
- On SSDs with TRIM, deleted content is gone; `-walk` sees live
  files only. Pair with `-unallocated-only` on an image for deleted
  recovery (see [FILESYSTEMS.md](FILESYSTEMS.md)).
- `-walk` output is the same `hits.jsonl` contract as scans
  ([HITS_SCHEMA.md](HITS_SCHEMA.md)): `target` is the file path,
  and `-report`/`-dfxml` consume it unchanged.
