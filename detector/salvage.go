package detector

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// Fragment-aware salvage: fixed-window carving cannot reassemble a database
// scattered across non-contiguous clusters. Salvage instead identifies
// database pages inside carved bytes, orders them where the format allows,
// and emits a reassembled image plus a page map recording which source
// offsets contributed.
//
// Two engines, honest about what each format permits:
//
//   - BDB pages carry their page number in the header, so stitching is
//     exact: pages order by pgno with zero-filled gaps. A complete set
//     reassembles byte-identical to the original file.
//   - SQLite pages carry no numbers, so only validated page sets are
//     claimed: page 1 (which names the page size) plus strictly validated
//     b-tree pages, grouped into offset-contiguous runs. Order is reported
//     only for the single-run case, where file order is certain.
//
// Anything unusable yields nil and the window carve stands: salvage never
// emits a bogus database.

// SalvageMaxBytes caps salvage input and assembled images alike.
const SalvageMaxBytes = 256 << 20

// SalvagePage is one validated database page with its provenance.
type SalvagePage struct {
	// PgNo is the page number (BDB only; SQLite pages lack numbers).
	PgNo uint32 `json:"pgno,omitempty"`
	// Offset is the absolute source offset of the page.
	Offset int64 `json:"offset"`
	Size   int   `json:"size"`
	// Kind is bdb-meta, bdb-page, sqlite-master, or sqlite-btree.
	Kind string `json:"kind"`
}

// SalvageRun is a maximal run of offset-contiguous pages.
type SalvageRun struct {
	StartOffset int64 `json:"start_offset"`
	Pages       int   `json:"pages"`
}

// SalvageInfo describes a salvage result for sidecars and reports.
type SalvageInfo struct {
	// Path is set by the caller (carve file or CLI output); empty for
	// analysis-only results.
	Path     string        `json:"path,omitempty"`
	Kind     string        `json:"kind"` // "bdb" or "sqlite"
	PageSize int           `json:"page_size"`
	Pages    []SalvagePage `json:"pages"`
	Runs     []SalvageRun  `json:"runs"`
	// Complete means every page is present (BDB: pgnos contiguous from 0;
	// SQLite: validated count equals the header page count).
	Complete bool `json:"complete"`
	// Ordered means the image is in file order (BDB: always, via pgno;
	// SQLite: only for a single page-1-led run).
	Ordered bool `json:"ordered"`
}

// SalvageResult bundles the info with the assembled image bytes.
type SalvageResult struct {
	Info  SalvageInfo
	Image []byte
}

// Salvage attempts database salvage on data, a carve or file window with
// data[0] at absolute baseAbs. It returns nil when nothing worth writing
// was found — fewer than two pages, unknown page size, or an image that
// would exceed SalvageMaxBytes.
func Salvage(data []byte, baseAbs int64) *SalvageResult {
	if len(data) == 0 || len(data) > SalvageMaxBytes {
		return nil
	}
	if r := salvageBDB(data, baseAbs); r != nil {
		return r
	}
	return salvageSQLite(data, baseAbs)
}

// ---------------------------------------------------------------------------
// BDB
// ---------------------------------------------------------------------------

const (
	bdbBtreeMagic = 0x053162
	bdbHashMagic  = 0x061561
	// bdbMaxPgNo bounds sane page numbers (16M pages = 64GB at 4K).
	bdbMaxPgNo = 1 << 24
)

var bdbPageSizes = []int{512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

type bdbPage struct {
	pgno    uint32
	magic   uint32
	ver     uint32
	lsnFile uint32 // log file number: same DB generation shares it
	offset  int64  // absolute
}

// scanBDBHeaders finds candidate page headers at every offset. Layout per
// dbinc/db.in, confirmed against test_wallet.dat: lsn(8) pgno(4) magic(4)
// version(4). Magic plus a small version set keeps random data silent.
func scanBDBHeaders(data []byte, baseAbs int64) []bdbPage {
	var out []bdbPage
	for i := 0; i+20 <= len(data); i++ {
		magic := binary.LittleEndian.Uint32(data[i+12:])
		if magic != bdbBtreeMagic && magic != bdbHashMagic {
			continue
		}
		if ver := binary.LittleEndian.Uint32(data[i+16:]); ver < 5 || ver > 10 {
			continue
		}
		if pgno := binary.LittleEndian.Uint32(data[i+8:]); pgno < bdbMaxPgNo {
			out = append(out, bdbPage{pgno: pgno, magic: magic,
				ver:     binary.LittleEndian.Uint32(data[i+16:]),
				lsnFile: binary.LittleEndian.Uint32(data[i:]),
				offset:  baseAbs + int64(i)})
		}
	}
	return out
}

// bdbPageSize determines the page size: the meta page (pgno 0) names it at
// offset 20, else an alignment vote over common sizes (file pages share one
// offset class modulo the true size). Zero means unknown.
func bdbPageSize(data []byte, baseAbs int64, pages []bdbPage) int {
	for _, p := range pages {
		if p.pgno != 0 {
			continue
		}
		if off := int(p.offset - baseAbs); off+24 <= len(data) {
			if ps := int(binary.LittleEndian.Uint32(data[off+20:])); isBDBPageSize(ps) {
				return ps
			}
		}
	}
	best, bestN := 0, 0
	for _, ps := range bdbPageSizes {
		groups := map[int]int{}
		for _, p := range pages {
			rel := int((p.offset - baseAbs) % int64(ps))
			groups[rel]++
			if groups[rel] > bestN {
				best, bestN = ps, groups[rel]
			}
		}
	}
	if bestN >= 2 {
		return best
	}
	return 0
}

func isBDBPageSize(ps int) bool {
	for _, s := range bdbPageSizes {
		if s == ps {
			return true
		}
	}
	return false
}

func salvageBDB(data []byte, baseAbs int64) *SalvageResult {
	headers := scanBDBHeaders(data, baseAbs)
	if len(headers) == 0 {
		return nil
	}
	// Group by database identity; salvage the largest group. Pages are
	// deliberately NOT alignment-filtered: junk between fragments shifts
	// each page's offset class, so alignment only votes the size.
	type dbID struct {
		magic, ver, lsnFile uint32
	}
	groups := map[dbID][]bdbPage{}
	var order []dbID
	for _, h := range headers {
		k := dbID{h.magic, h.ver, h.lsnFile}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], h)
	}
	var pages []bdbPage
	for _, k := range order {
		if len(groups[k]) > len(pages) {
			pages = groups[k]
		}
	}
	if len(pages) < 2 {
		return nil
	}
	ps := bdbPageSize(data, baseAbs, pages)
	if ps == 0 {
		return nil
	}
	seen := map[uint32]bool{}
	var kept []bdbPage
	for _, p := range pages {
		if int(p.offset-baseAbs)+ps > len(data) {
			continue // clipped page
		}
		if seen[p.pgno] {
			continue
		}
		seen[p.pgno] = true
		kept = append(kept, p)
	}
	if len(kept) < 2 {
		return nil
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].pgno < kept[j].pgno })
	if max := kept[len(kept)-1].pgno; (uint64(max)+1)*uint64(ps) > SalvageMaxBytes {
		return nil
	}
	maxPgno := kept[len(kept)-1].pgno
	image := make([]byte, (maxPgno+1)*uint32(ps)) // gaps stay zero-filled
	info := SalvageInfo{Kind: "bdb", PageSize: ps, Ordered: true}
	info.Complete = len(kept) == int(maxPgno+1) && kept[0].pgno == 0
	for _, p := range kept {
		copy(image[p.pgno*uint32(ps):], data[p.offset-baseAbs:p.offset-baseAbs+int64(ps)])
		kind := "bdb-page"
		if p.pgno == 0 {
			kind = "bdb-meta"
		}
		info.Pages = append(info.Pages, SalvagePage{PgNo: p.pgno, Offset: p.offset, Size: ps, Kind: kind})
	}
	// Runs: consecutive pgnos at consecutive source offsets.
	for i, p := range kept {
		if i == 0 || p.pgno != kept[i-1].pgno+1 || p.offset != kept[i-1].offset+int64(ps) {
			info.Runs = append(info.Runs, SalvageRun{StartOffset: p.offset})
		}
		info.Runs[len(info.Runs)-1].Pages++
	}
	return &SalvageResult{Info: info, Image: image}
}

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

var sqliteMagic = []byte("SQLite format 3\x00")

// sqlitePageSizes is tried only when no page 1 names the size.
var sqlitePageSizes = []int{1024, 2048, 4096, 8192}

type sqlitePage struct {
	offset int64 // absolute
	first  bool  // is page 1
}

// sqliteHeader finds a valid page 1: magic, sane size, parseable b-tree
// header at +100. Returns offset, size, total pages (0 when unknown).
func sqliteHeader(data []byte) (off, ps int, total uint32, ok bool) {
	for i := 0; i+100 <= len(data); {
		j := bytes.Index(data[i:], sqliteMagic)
		if j < 0 {
			return 0, 0, 0, false
		}
		o := i + j
		size := int(binary.BigEndian.Uint16(data[o+16:]))
		if size == 1 {
			size = 65536
		}
		var n uint32
		if o+32 <= len(data) {
			if v := binary.BigEndian.Uint32(data[o+28:]); v >= 1 && v < 1<<24 {
				n = v
			}
		}
		if isSQLitePageSize(size) && validSQLiteBTree(data, o, o+100, size, n) {
			return o, size, n, true
		}
		i = o + 1
	}
	return 0, 0, 0, false
}

func isSQLitePageSize(ps int) bool {
	return ps >= 512 && ps <= 65536 && ps&(ps-1) == 0
}

// validSQLiteBTree strictly validates one b-tree page: known type, cell
// count fitting the page, every cell pointer in-bounds, distinct, with room
// for a minimal cell, and interior children within the known page count.
func validSQLiteBTree(data []byte, pageOff, hdrOff, ps int, totalN uint32) bool {
	if pageOff+ps > len(data) {
		return false
	}
	t := data[hdrOff]
	if t != 2 && t != 5 && t != 10 && t != 13 {
		return false
	}
	hdrLen := 8
	if t == 2 || t == 5 {
		hdrLen = 12
	}
	nc := int(binary.BigEndian.Uint16(data[hdrOff+3:]))
	cs := int(binary.BigEndian.Uint16(data[hdrOff+5:]))
	if cs == 0 {
		if ps != 65536 {
			return false
		}
		cs = 65536
	}
	if cs > ps {
		return false
	}
	base := hdrOff - pageOff // 100 for page 1, else 0
	if base+hdrLen+2*nc > cs {
		return false
	}
	if nc == 0 {
		return cs == ps
	}
	minTail := 3
	switch t {
	case 10:
		minTail = 2
	case 2, 5:
		minTail = 5
	}
	used := map[int]bool{}
	for k := 0; k < nc; k++ {
		p := int(binary.BigEndian.Uint16(data[hdrOff+hdrLen+2*k:]))
		if p < cs || p+minTail > ps || used[p] {
			return false
		}
		used[p] = true
	}
	if totalN > 0 && (t == 2 || t == 5) {
		if rc := binary.BigEndian.Uint32(data[hdrOff+8:]); rc == 0 || rc > totalN {
			return false
		}
	}
	return true
}

func salvageSQLite(data []byte, baseAbs int64) *SalvageResult {
	if off, ps, total, ok := sqliteHeader(data); ok {
		if r := salvageSQLiteSized(data, baseAbs, ps, total, baseAbs+int64(off)); r != nil {
			return r
		}
	}
	var best *SalvageResult
	for _, ps := range sqlitePageSizes {
		if r := salvageSQLiteSized(data, baseAbs, ps, 0, -1); r != nil {
			if best == nil || len(r.Info.Pages) > len(best.Info.Pages) {
				best = r
			}
		}
	}
	return best
}

func salvageSQLiteSized(data []byte, baseAbs int64, ps int, totalN uint32, p1abs int64) *SalvageResult {
	var found []sqlitePage
	for o := 0; o+ps <= len(data); o++ {
		if int64(o)+baseAbs == p1abs {
			if validSQLiteBTree(data, o, o+100, ps, totalN) {
				found = append(found, sqlitePage{baseAbs + int64(o), true})
			}
			continue
		}
		if validSQLiteBTree(data, o, o, ps, totalN) {
			found = append(found, sqlitePage{baseAbs + int64(o), false})
		}
	}
	// Overlapping hits: keep the first; aligned pages never overlap.
	var pages []sqlitePage
	for _, p := range found {
		if len(pages) == 0 || p.offset >= pages[len(pages)-1].offset+int64(ps) {
			pages = append(pages, p)
		}
	}
	if len(pages) < 2 {
		return nil
	}
	if len(pages)*ps > SalvageMaxBytes {
		return nil
	}
	info := SalvageInfo{Kind: "sqlite", PageSize: ps}
	var image []byte
	var firstSeen bool
	for _, p := range pages {
		rel := p.offset - baseAbs
		image = append(image, data[rel:rel+int64(ps)]...)
		kind := "sqlite-btree"
		if p.first {
			kind = "sqlite-master"
			firstSeen = true
		}
		info.Pages = append(info.Pages, SalvagePage{Offset: p.offset, Size: ps, Kind: kind})
		if len(info.Runs) == 0 || p.offset != info.Runs[len(info.Runs)-1].StartOffset+int64(info.Runs[len(info.Runs)-1].Pages*ps) {
			info.Runs = append(info.Runs, SalvageRun{StartOffset: p.offset})
		}
		info.Runs[len(info.Runs)-1].Pages++
	}
	info.Complete = firstSeen && totalN > 0 && len(pages) == int(totalN)
	info.Ordered = len(info.Runs) == 1 && pages[0].first
	return &SalvageResult{Info: info, Image: image}
}
