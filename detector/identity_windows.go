package detector

import (
	"os"
	"syscall"
)

// fileIdentityStat attests a regular file via handle information:
// volume serial + file index + size + write + creation times, all
// in 100ns ticks. New-file swaps always change the index and
// creation time, including timestamp-preserving copies. Residual
// (documented in identity.go): deliberate in-place same-size
// overwrite plus explicit mtime restore is invisible here.
func fileIdentityStat(path string, fi os.FileInfo) (FileIdentity, bool) {
	_ = fi
	f, err := os.Open(path)
	if err != nil {
		return FileIdentity{}, false
	}
	defer f.Close()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info); err != nil {
		return FileIdentity{}, false
	}
	size := int64(info.FileSizeHigh)<<32 + int64(info.FileSizeLow)
	mtime := int64(info.LastWriteTime.HighDateTime)<<32 + int64(info.LastWriteTime.LowDateTime)
	ctime := int64(info.CreationTime.HighDateTime)<<32 + int64(info.CreationTime.LowDateTime)
	const tick100ns = 100 // FILETIME ticks to nanos
	return FileIdentity{
		Kind:    "windows",
		Dev:     uint64(info.VolumeSerialNumber),
		Ino:     uint64(info.FileIndexHigh)<<32 + uint64(info.FileIndexLow),
		Size:    size,
		MtimeNS: mtime * tick100ns,
		CtimeNS: ctime * tick100ns,
	}, true
}
