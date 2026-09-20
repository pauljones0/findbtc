package detector

import "os"

// FileIdentity attests the exact bytes at a path at stat time, so
// a resume can tell whether journaled progress (offsets, covered
// members) still describes the current content. Size and whole-
// second mtime alone are forgeable (same-size rewrite plus mtime
// restore) and subsecond-blind, so identity binds the kernel's
// change evidence:
//
//   - posix (linux, darwin): device + inode + size + nanosecond
//     mtime + nanosecond ctime. Any content change replaces the
//     inode (new file) or advances ctime (in-place write — utime
//     restores mtime but always bumps ctime), so equality is
//     exact short of clock or filesystem-subversion games.
//   - windows: volume + file index + size + mtime + creation
//     time. New-file swaps (copies, renames, re-extractions —
//     including timestamp-preserving ones) change the index and
//     creation time. Residual: a deliberate in-place same-size
//     overwrite plus explicit mtime restore is invisible to
//     stdlib attestable metadata; that forgery shape is
//     documented, not silently trusted.
//
// Non-regular targets (volumes, pipes) have no attestable byte
// identity — a block device node never reflects disk content —
// so FileIdentityOf reports ok=false and callers fall back to
// legacy behavior (offsets trusted as before, covered sets
// dropped). Unknown/exotic platforms also report ok=false, and
// there callers refuse all reuse (full rescan): sound but slow,
// and outside the CI matrix.
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

// FileIdentityOf stats path for resume-identity purposes. It
// reports ok=false for missing files, non-regular targets
// (volumes, pipes, stdin names), and platforms without an
// attestation implementation; callers must refuse covered reuse
// and (for regular files) offset reuse in that case.
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
