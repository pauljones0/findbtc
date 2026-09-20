package detector

import (
	"os"
	"syscall"
)

func fileIdentityStat(path string, fi os.FileInfo) (FileIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileIdentity{}, false
	}
	_ = path
	return FileIdentity{
		Kind:    "posix",
		Dev:     uint64(st.Dev),
		Ino:     st.Ino,
		Size:    st.Size,
		MtimeNS: st.Mtim.Nano(),
		CtimeNS: st.Ctim.Nano(),
	}, true
}

// fileIdentityFile attests an opened handle; posix needs only the
// fstat, so this shares the path-based conversion.
func fileIdentityFile(f *os.File, fi os.FileInfo) (FileIdentity, bool) {
	_ = f
	return fileIdentityStat("", fi)
}
