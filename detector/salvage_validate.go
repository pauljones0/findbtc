package detector

import (
	"encoding/binary"
	"fmt"
)

// Salvage validation (Goal 26): every salvaged image carries a
// valid/suspect verdict from dependency-free structural checks that
// predict whether the real database tools will open it. The checks
// were calibrated against db_verify (BDB) and SQLite quick_check on
// the fixture set:
//
//   - BDB: meta magic/version/page-size, last_pgno matching the image
//     size, every page's pgno positional, no zero pages, and per-page
//     header bounds (index array inside the high-water mark). Notably
//     NOT per-page magic: real files carry magic only on meta pages
//     (pgno 0 plus one per sub-database), and db_verify accepts that.
//     And NOT prev/next link range checks: unreferenced pages carry
//     garbage links that db_verify ignores.
//   - SQLite: header magic, page size, size multiple, header page
//     count matching, every page passing the strict b-tree check —
//     plus Ordered, because a shuffled-but-complete page set fails
//     quick_check while passing every byte-level check. Page order is
//     proven by provenance (single page-1-led source run), never
//     guessed.
//
// Verdicts are predictions, not proofs: a structurally valid image
// with corrupt cell bodies can still fail to open. "valid" means
// "worth opening"; "suspect" names concrete reasons and means "lead,
// not a database".

// Salvage verdicts.
const (
	SalvageValid   = "valid"
	SalvageSuspect = "suspect"
)

// ValidateSalvage predicts whether image opens in the real database
// tool. info carries the assembly provenance (runs, order); image is
// the assembled bytes. It returns the verdict plus human-readable
// reasons (empty when valid).
func ValidateSalvage(info SalvageInfo, image []byte) (string, []string) {
	switch info.Kind {
	case "bdb":
		return validateBDBImage(info, image)
	case "sqlite":
		return validateSQLiteImage(info, image)
	default:
		return SalvageSuspect, []string{"unknown salvage kind " + info.Kind}
	}
}

// bdbPageTypes admits non-meta page types: internal/leaf btree and
// recno, overflow (whose entries field is a refcount, exempt from
// index bounds), duplicate, and hash/queue data pages.
var bdbPageTypes = map[byte]bool{3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 12: true, 13: true}

func validateBDBImage(info SalvageInfo, image []byte) (string, []string) {
	var reasons []string
	suspect := func(f string, args ...any) {
		reasons = append(reasons, fmt.Sprintf(f, args...))
	}
	ps := 0
	if len(image) >= 24 {
		if m := binary.LittleEndian.Uint32(image[12:]); m != bdbBtreeMagic && m != bdbHashMagic {
			suspect("meta page: bad magic %#x", m)
		}
		if v := binary.LittleEndian.Uint32(image[16:]); v < 5 || v > 10 {
			suspect("meta page: version %d outside 5..10", v)
		}
		ps = int(binary.LittleEndian.Uint32(image[20:]))
		if !isBDBPageSize(ps) {
			suspect("meta page: page size %d not a BDB size", ps)
			ps = 0
		}
	} else {
		suspect("image shorter than a page header (%d bytes)", len(image))
		return SalvageSuspect, reasons
	}
	if ps == 0 || len(image)%ps != 0 {
		suspect("image size %d is not a multiple of page size %d", len(image), ps)
		return SalvageSuspect, reasons
	}
	npages := len(image) / ps
	if npages < 2 {
		suspect("image holds %d page, need 2+", npages)
		return SalvageSuspect, reasons
	}
	if last := binary.LittleEndian.Uint32(image[32:]); last != uint32(npages-1) {
		suspect("meta last_pgno %d, image holds %d pages", last, npages)
	}
	for i := 0; i < npages; i++ {
		pg := image[i*ps : (i+1)*ps]
		if pgno := binary.LittleEndian.Uint32(pg[8:]); pgno != uint32(i) {
			suspect("page index %d carries pgno %d", i, pgno)
			continue
		}
		if isZeroPage(pg) {
			suspect("page %d is all zero (unfilled gap)", i)
			continue
		}
		// Meta-shaped pages (pgno 0, sub-database metas) carry the
		// database header layout, not page items: check the header.
		if m := binary.LittleEndian.Uint32(pg[12:]); m == bdbBtreeMagic || m == bdbHashMagic {
			if v := binary.LittleEndian.Uint32(pg[16:]); v < 5 || v > 10 {
				suspect("page %d: meta version %d outside 5..10", i, v)
			}
			if s := int(binary.LittleEndian.Uint32(pg[20:])); s != ps {
				suspect("page %d: meta page size %d, image uses %d", i, s, ps)
			}
			continue
		}
		t := pg[25]
		if !bdbPageTypes[t] {
			suspect("page %d: type %d is not a database page type", i, t)
			continue
		}
		if t == 7 { // overflow: entries/hf reused, bounds meaningless
			continue
		}
		entries := int(binary.LittleEndian.Uint16(pg[20:]))
		hf := int(binary.LittleEndian.Uint16(pg[22:]))
		if hf > ps || 26+2*entries > hf {
			suspect("page %d: %d index entries overrun free space at %d", i, entries, hf)
		}
	}
	if len(reasons) > 0 {
		return SalvageSuspect, reasons
	}
	return SalvageValid, nil
}

func validateSQLiteImage(info SalvageInfo, image []byte) (string, []string) {
	var reasons []string
	if len(image) < 100 || string(image[:16]) != string(sqliteMagic) {
		return SalvageSuspect, []string{"no SQLite header at image start (page 1 missing or not first)"}
	}
	ps := int(binary.BigEndian.Uint16(image[16:]))
	if ps == 1 {
		ps = 65536
	}
	if !isSQLitePageSize(ps) {
		return SalvageSuspect, []string{fmt.Sprintf("header page size %d is not a SQLite size", ps)}
	}
	if len(image)%ps != 0 {
		return SalvageSuspect, []string{fmt.Sprintf("image size %d is not a multiple of page size %d", len(image), ps)}
	}
	npages := len(image) / ps
	var total uint32
	if len(image) >= 32 {
		if v := binary.BigEndian.Uint32(image[28:]); v >= 1 && v < 1<<24 {
			total = v
		}
	}
	if total == 0 {
		reasons = append(reasons, "header page count unreadable")
	} else if npages != int(total) {
		reasons = append(reasons, fmt.Sprintf("image holds %d pages, header says %d", npages, total))
	}
	for o := 0; o < npages; o++ {
		hdr := o * ps
		if o == 0 {
			hdr += 100
		}
		if !validSQLiteBTree(image, o*ps, hdr, ps, total) {
			reasons = append(reasons, fmt.Sprintf("page %d fails b-tree validation", o+1))
		}
	}
	// Order is invisible in the bytes (a shuffled page set passes every
	// check above yet fails quick_check), so provenance decides: only a
	// single page-1-led source run preserves file order.
	if !info.Ordered {
		reasons = append(reasons, fmt.Sprintf("%d source runs (page order uncertain)", len(info.Runs)))
	}
	if len(reasons) > 0 {
		return SalvageSuspect, reasons
	}
	return SalvageValid, nil
}

func isZeroPage(pg []byte) bool {
	for _, b := range pg {
		if b != 0 {
			return false
		}
	}
	return true
}
