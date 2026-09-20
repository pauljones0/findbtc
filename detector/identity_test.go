package detector

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Kernel identity must bind journaled progress to exact bytes: a
// same-size rewrite with restored mtime changes content the
// size/mtime pair cannot see. Only kernel change evidence
// (posix ctime/inode, Windows index/creation) authorizes reuse —
// and the changed-middle controls below pin that no content
// sampling is involved: prefix and suffix are byte-identical,
// only the middle differs, yet reuse must refuse.
func TestFileIdentitySameSizeRestoredMtime(t *testing.T) {
	mkcontent := func(middle byte) []byte {
		content := append([]byte{}, bytes.Repeat([]byte{'P'}, 1024)...)
		content = append(content, bytes.Repeat([]byte{middle}, 4096)...)
		return append(content, bytes.Repeat([]byte{'S'}, 1024)...)
	}
	// assertSwapShape verifies the control holds size, mtime,
	// prefix, and suffix constant while changing the middle.
	assertSwapShape := func(t *testing.T, before, after []byte, fixed time.Time, path string) {
		t.Helper()
		if len(before) != len(after) {
			t.Fatalf("control shapes differ in size: %d vs %d", len(before), len(after))
		}
		if !bytes.Equal(before[:1024], after[:1024]) || !bytes.Equal(before[len(before)-1024:], after[len(after)-1024:]) {
			t.Fatal("control shapes differ outside the middle")
		}
		if bytes.Equal(before[1024:len(before)-1024], after[1024:len(after)-1024]) {
			t.Fatal("control middles unexpectedly identical")
		}
		if fi, _ := os.Stat(path); !fi.ModTime().Equal(fixed) {
			t.Fatalf("control mtime not restored: %v", fi.ModTime())
		}
	}
	assertRefused := func(t *testing.T, cpPath, path, key string) {
		t.Helper()
		cp, err := ReadCheckpoint(cpPath)
		if err != nil {
			t.Fatal(err)
		}
		if trustOff, trustCov, _ := IdentityTrust(cp.Ident, path); trustOff || trustCov {
			t.Fatal("swapped bytes inherited offset/covered reuse")
		}
		g := newPubGate(nil)
		seedCoveredFromJournal(g, Options{CheckpointPath: cpPath}, &fileScanTarget{path: path})
		if g.isCovered(key) {
			t.Fatal("stale covered key seeded for different bytes with same size+mtime")
		}
	}

	t.Run("replace", func(t *testing.T) {
		// Replace-shape swap (rename over the path): new inode
		// / file index everywhere. Must refuse on ALL
		// platforms, including Windows.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		fixed := time.Unix(1780000000, 0)
		if err := os.WriteFile(path, mkcontent('A'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		identA, ok := FileIdentityOf(path)
		if !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "swap.cp")
		writeCheckpointData(nil, cpPath, Checkpoint{
			Path: path, Offset: 1024, Ident: identA,
			Covered: []string{"member-key-that-belongs-to-A"},
		})
		tmp := filepath.Join(dir, "new.bin")
		if err := os.WriteFile(tmp, mkcontent('B'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tmp, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		assertSwapShape(t, before, after, fixed, path)
		assertRefused(t, cpPath, path, "member-key-that-belongs-to-A")
	})

	t.Run("inplace", func(t *testing.T) {
		// In-place rewrite plus mtime restore: same inode,
		// forged mtime. Posix ctime catches it. Windows
		// stdlib cannot (documented residual), so this leg
		// runs on posix only; the replace leg above covers
		// the realistic Windows swap shapes.
		if runtime.GOOS == "windows" {
			t.Skip("in-place mtime forgery is invisible to Windows stdlib identity (documented residual)")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		fixed := time.Unix(1780000000, 0)
		if err := os.WriteFile(path, mkcontent('A'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		identA, ok := FileIdentityOf(path)
		if !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "swap.cp")
		writeCheckpointData(nil, cpPath, Checkpoint{
			Path: path, Offset: 1024, Ident: identA,
			Covered: []string{"member-key-that-belongs-to-A"},
		})
		if err := os.WriteFile(path, mkcontent('B'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		assertSwapShape(t, before, after, fixed, path)
		assertRefused(t, cpPath, path, "member-key-that-belongs-to-A")
	})

	t.Run("positive", func(t *testing.T) {
		// Unchanged bytes keep full reuse: banning reuse
		// outright would revive the liveness failure.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		if err := os.WriteFile(path, mkcontent('A'), 0600); err != nil {
			t.Fatal(err)
		}
		identA, ok := FileIdentityOf(path)
		if !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "same.cp")
		writeCheckpointData(nil, cpPath, Checkpoint{
			Path: path, Offset: 1024, Ident: identA,
			Covered: []string{"banked-member"},
		})
		cp, err := ReadCheckpoint(cpPath)
		if err != nil {
			t.Fatal(err)
		}
		if trustOff, trustCov, note := IdentityTrust(cp.Ident, path); !trustOff || !trustCov {
			t.Fatalf("unchanged bytes refused reuse: %s", note)
		}
		g := newPubGate(nil)
		seedCoveredFromJournal(g, Options{CheckpointPath: cpPath}, &fileScanTarget{path: path})
		if !g.isCovered("banked-member") {
			t.Fatal("unchanged bytes dropped banked coverage")
		}
	})

	t.Run("legacy", func(t *testing.T) {
		// Journals without identity (older binaries) rescan
		// once on upgrade instead of inheriting.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		if err := os.WriteFile(path, mkcontent('A'), 0600); err != nil {
			t.Fatal(err)
		}
		if _, ok := FileIdentityOf(path); !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "legacy.cp")
		writeCheckpointData(nil, cpPath, Checkpoint{
			Path: path, Offset: 1024, Covered: []string{"banked-member"},
		})
		cp, err := ReadCheckpoint(cpPath)
		if err != nil {
			t.Fatal(err)
		}
		if trustOff, trustCov, _ := IdentityTrust(cp.Ident, path); trustOff || trustCov {
			t.Fatal("legacy journal without identity inherited reuse")
		}
	})
}
