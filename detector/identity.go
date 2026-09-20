package detector

import "os"

// FileIdentity is the cheap metadata rejection tier in front of
// content-proof verification (see proof.go): kernel change
// evidence that lets a resume skip the re-read cost when the
// bytes obviously moved. It NEVER authorizes offset or covered
// reuse by itself — only a verified prefix proof does that — so
// every weakness below costs at most a wasted verification, never
// a silent skip:
//
//   - posix (linux, darwin, BSDs): device + inode + size +
//     nanosecond mtime + nanosecond ctime. Replacements change
//     the inode; in-place writes advance ctime (utime restores
//     mtime but always bumps ctime). Residuals, all closed by
//     proof verification: coarse-timestamp filesystems (FAT
//     granularity can collide a rewrite+restore inside one tick),
//     stale NFS attribute caches (plain stat; the handle-based
//     check revalidates), hostile clock or filesystem subversion.
//   - windows: volume + file index + size + mtime + creation
//     time. New-file swaps change the index and creation time.
//     Residual, closed by proof verification: in-place same-size
//     overwrite plus explicit mtime restore is invisible here,
//     as are SMB servers with unstable file IDs.
//
// Non-regular targets (volumes, pipes) have no attestable byte
// identity — a block device node never reflects disk content —
// so FileIdentityOf reports ok=false and callers proceed straight
// to proof verification. Unknown/exotic platforms also report
// ok=false, and there regular files refuse all reuse (full
// rescan): sound but slow, and outside the CI matrix.
type FileIdentity struct {
	Kind string `json:"kind,omitempty"` // "posix" | "windows" | "" (unknown)
	Dev  uint64 `json:"dev,omitempty"`  // device (posix) / volume serial (windows)
	Ino  uint64 `json:"ino,omitempty"`  // inode (posix) / file index (windows)
	Size int64  `json:"size,omitempty"`
	// MtimeNS is modification time; CtimeNS is status-change time
	// (posix) or creation time (windows), both Unix nanos.
	MtimeNS int64 `json:"mtimeNs,omitempty"`
	CtimeNS int64 `json:"ctimeNs,omitempty"`
}

// Matches reports whether two identities attest the same bytes.
// Unknown identities (empty Kind) never match: legacy journals
// and unattestable targets re-cover instead of inheriting.
func (a FileIdentity) Matches(b FileIdentity) bool {
	if a.Kind == "" || b.Kind == "" || a.Kind != b.Kind {
		return false
	}
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size &&
		a.MtimeNS == b.MtimeNS && a.CtimeNS == b.CtimeNS
}

// FileIdentityOf stats path for the metadata rejection tier. It
// reports ok=false for missing files, non-regular targets
// (volumes, pipes, stdin names), and platforms without an
// attestation implementation; see cheapTierPass for how callers
// combine that with proof verification.
func FileIdentityOf(path string) (FileIdentity, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileIdentity{}, false
	}
	if !fi.Mode().IsRegular() {
		return FileIdentity{}, false
	}
	return fileIdentityStat(path, fi)
}

// FileIdentityOfFile stats an already-opened handle: open-then-
// fstat, so the identity describes the bytes about to be consumed
// (revalidating stale attribute caches) instead of whatever the
// path names at a second stat. It returns the raw FileInfo for
// regularity checks plus the converted identity with ok.
func FileIdentityOfFile(f *os.File) (os.FileInfo, FileIdentity, bool) {
	fi, err := f.Stat()
	if err != nil {
		return nil, FileIdentity{}, false
	}
	if !fi.Mode().IsRegular() {
		return fi, FileIdentity{}, false
	}
	att, ok := fileIdentityFile(f, fi)
	return fi, att, ok
}
