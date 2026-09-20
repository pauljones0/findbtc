//go:build !linux && !darwin && !windows && !freebsd && !openbsd && !netbsd && !dragonfly

package detector

import "os"

// fileIdentityStat on unattested platforms always declines: without
// kernel change evidence, reuse cannot be authorized, so callers
// fall back to full rescan. Sound but slow; outside the CI matrix.
func fileIdentityStat(path string, fi os.FileInfo) (FileIdentity, bool) {
	return FileIdentity{}, false
}
