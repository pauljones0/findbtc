package detector

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic ext4 image: 64 blocks of 4096 bytes, one group, 32 inodes.
// Block 0 boot+superblock, 1 GDT, 2 block bitmap, 3 inode bitmap,
// 4 inode table, 5 root dir, 6 live hello.txt, 8 deleted wallet content,
// 10 deleted direct-mapped content, 11 deleted subdir, 12 its file.

const (
	extTestBlocks = 64
	extTestBlock  = 4096
	extTestInodes = 32
)

func extExtentLeaf(startBlock int64, nblocks int) []byte {
	leaf := make([]byte, 60)
	binary.LittleEndian.PutUint16(leaf[0:2], extExtentMagic)
	binary.LittleEndian.PutUint16(leaf[2:4], 1)
	binary.LittleEndian.PutUint16(leaf[4:6], 4)
	binary.LittleEndian.PutUint32(leaf[12:16], 0) // ee_block
	binary.LittleEndian.PutUint16(leaf[16:18], uint16(nblocks))
	binary.LittleEndian.PutUint16(leaf[18:20], 0)
	binary.LittleEndian.PutUint32(leaf[20:24], uint32(startBlock))
	return leaf
}

func mkExtInode(mode uint16, links uint16, size int64, dtime uint32, extents bool, iblock []byte) []byte {
	in := make([]byte, 128)
	binary.LittleEndian.PutUint16(in[0:2], mode)
	binary.LittleEndian.PutUint32(in[4:8], uint32(size))
	binary.LittleEndian.PutUint32(in[20:24], dtime)
	binary.LittleEndian.PutUint16(in[26:28], links)
	binary.LittleEndian.PutUint32(in[28:32], 8) // i_blocks_lo: one block
	if extents {
		binary.LittleEndian.PutUint32(in[32:36], extExtentsFlag)
	}
	copy(in[40:100], iblock)
	return in
}

func mkExtDirent(ino uint32, recLen int, name string) []byte {
	e := make([]byte, recLen)
	binary.LittleEndian.PutUint32(e[0:4], ino)
	binary.LittleEndian.PutUint16(e[4:6], uint16(recLen))
	e[6] = byte(len(name))
	e[7] = 1 // regular file (2 would be dir; unused by the parser)
	copy(e[8:], name)
	return e
}

func buildTestExt(t *testing.T) string {
	t.Helper()
	img := make([]byte, extTestBlocks*extTestBlock)
	// Superblock at byte 1024.
	sb := img[1024:2048]
	binary.LittleEndian.PutUint32(sb[0:4], extTestInodes)
	binary.LittleEndian.PutUint32(sb[4:8], extTestBlocks)
	binary.LittleEndian.PutUint32(sb[20:24], 1)
	binary.LittleEndian.PutUint32(sb[24:28], 2) // 4096-byte blocks
	binary.LittleEndian.PutUint32(sb[32:36], extTestBlocks)
	binary.LittleEndian.PutUint32(sb[40:44], extTestInodes)
	binary.LittleEndian.PutUint16(sb[56:58], extMagic)
	binary.LittleEndian.PutUint32(sb[84:88], 11)
	binary.LittleEndian.PutUint16(sb[88:90], 128)
	// Group descriptor at block 1.
	gdt := img[extTestBlock : 2*extTestBlock]
	binary.LittleEndian.PutUint32(gdt[0:4], 2) // block bitmap
	binary.LittleEndian.PutUint32(gdt[4:8], 3) // inode bitmap
	binary.LittleEndian.PutUint32(gdt[8:12], 4)
	// Block bitmap: blocks 0-9 allocated.
	img[2*extTestBlock] = 0xFF
	img[2*extTestBlock+1] = 0x03
	// Inode bitmap: root + live file set; deleted 13-16 cleared.
	img[3*extTestBlock] = 0x02
	img[3*extTestBlock+1] = 0x08
	// Inode table at block 4.
	putIno := func(num int, in []byte) {
		copy(img[4*extTestBlock+(num-1)*128:], in)
	}
	putIno(2, mkExtInode(extModeDir|0x1FF, 2, extTestBlock, 0, true, extExtentLeaf(5, 1)))
	putIno(12, mkExtInode(extModeFile|0x1A4, 1, 5, 0, true, extExtentLeaf(6, 1)))
	putIno(13, mkExtInode(extModeFile|0x1A4, 0, 100, 12345, true, extExtentLeaf(8, 1)))
	direct := make([]byte, 60)
	binary.LittleEndian.PutUint32(direct[0:4], 10)
	putIno(14, mkExtInode(extModeFile|0x1A4, 0, 50, 12346, false, direct))
	putIno(15, mkExtInode(extModeDir|0x1FF, 0, extTestBlock, 12347, true, extExtentLeaf(11, 1)))
	putIno(16, mkExtInode(extModeFile|0x1A4, 0, 40, 12348, true, extExtentLeaf(12, 1)))
	// Root dir block 5: hello.txt hides in ".." slack with its inode
	// intact (merged rec_len, as a real unlink leaves), plus
	// chain-visible residual deleted names.
	root := make([]byte, extTestBlock)
	copy(root[0:], mkExtDirent(2, 12, "."))
	copy(root[12:], mkExtDirent(2, 44, ".."))
	copy(root[24:], mkExtDirent(12, 20, "hello.txt"))
	copy(root[56:], mkExtDirent(0, 20, "wallet.dat"))
	copy(root[76:], mkExtDirent(0, extTestBlock-76, "gone.txt"))
	copy(img[5*extTestBlock:], root)
	// Deleted subdir block 11: live-shaped entry to unlinked inode 16.
	sub := append(mkExtDirent(2, 12, "."), mkExtDirent(16, extTestBlock-12, "wallet2.dat")...)
	copy(img[11*extTestBlock:], sub)
	copy(img[6*extTestBlock:], "hello")
	copy(img[8*extTestBlock:], "BDB wallet remnants bestblock orderposnext ")
	copy(img[10*extTestBlock:], "direct-block-residue bestblock ")
	copy(img[12*extTestBlock:], "associated-residue defaultkey ")
	path := filepath.Join(t.TempDir(), "ext.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func openTestExt(t *testing.T, path string) (*ExtVol, *os.File) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	vol, err := OpenExt(f, 0)
	if err != nil {
		t.Fatalf("OpenExt: %s", err)
	}
	return vol, f
}

func TestExtDeletedWallet(t *testing.T) {
	vol, f := openTestExt(t, buildTestExt(t))
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	byNote := map[string]FSEntry{}
	var names []string
	for _, e := range entries {
		byNote[e.Note] = e
		names = append(names, e.Name)
	}
	// Residual name without content.
	res, ok := byNote["residual dir entry"]
	if !ok {
		t.Fatalf("no residual names recovered: %v", names)
	}
	_ = res
	foundWalletName := false
	for _, e := range entries {
		if e.Name == "wallet.dat" && e.Deleted && len(e.Extents) == 0 {
			foundWalletName = true
		}
	}
	if !foundWalletName {
		t.Errorf("deleted wallet.dat name not recovered: %v", names)
	}
	// Unlinked inode content without a name.
	w, ok := byNote["inode:13"]
	if !ok || !w.Deleted {
		t.Fatalf("inode 13 content missing: %v", byNote)
	}
	if len(w.Extents) != 1 || w.Extents[0].Start != 8*extTestBlock {
		t.Errorf("inode 13 extents %v, want block 8", w.Extents)
	}
	content := make([]byte, 100)
	if _, err := f.ReadAt(content, w.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("orderposnext")) {
		t.Errorf("deleted extent content lost: %q", content)
	}
	// Classic direct-block mapping still resolves.
	d, ok := byNote["inode:14"]
	if !ok || len(d.Extents) != 1 || d.Extents[0].Start != 10*extTestBlock {
		t.Errorf("direct-mapped inode 14 extents wrong: %+v", d)
	}
	// Name+content associated through the unlinked subdir.
	var assoc *FSEntry
	for i, e := range entries {
		if e.Name == "wallet2.dat" {
			assoc = &entries[i]
		}
	}
	if assoc == nil || !assoc.Deleted || len(assoc.Extents) != 1 {
		t.Errorf("wallet2.dat association failed: %+v", assoc)
	} else if assoc.Extents[0].Start != 12*extTestBlock {
		t.Errorf("wallet2.dat extent %v, want block 12", assoc.Extents)
	}
	// Live file keeps its name and content.
	h, ok := byNote["inode:12"]
	if !ok || h.Deleted || h.Name != "hello.txt" {
		t.Errorf("live hello.txt wrong: %+v", h)
	}
}

func TestExtUnallocated(t *testing.T) {
	vol, _ := openTestExt(t, buildTestExt(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	if len(free) != 1 {
		t.Fatalf("free ranges %v, want 1 merged range", free)
	}
	if free[0].Start != 10*extTestBlock || free[0].Len != (extTestBlocks-10)*extTestBlock {
		t.Errorf("free range %v, want blocks 10-63", free[0])
	}
}

func TestExtRejectsNonExt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.img")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xBB}, 8192), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := OpenExt(f, 0); err == nil {
		t.Error("garbage must not open as ext")
	}
}
