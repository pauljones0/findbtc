package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Patch attribution (Goal 36): `git log -p` piped through a scan
// attributes each root-target hit to its commit + repo path (+
// new-file line for added/context lines) by parsing patch headers
// dependency-free. Only column-0 headers count, so quoted diffs
// inside indented commit messages cannot hijack attribution.

// patchHeaderCap bounds how much of one line the header matcher
// keeps: real headers (commit/diff/hunk) are short, while committed
// minified files can hold megabyte `+` lines. Past the cap a line is
// content, never a header; its bytes still hash into fingerprints.
const patchHeaderCap = 64 * 1024

// patchReadChunk sizes the attribution re-read; lines may span
// chunks and the hash streams, so giant lines never fully allocate.
const patchReadChunk = 64 * 1024

// patchCtx is the parser's running position in the patch series.
type patchCtx struct {
	commit  string // enclosing commit sha, "" outside any commit
	path    string // enclosing file (b-side repo path), "" outside any diff
	minus   string // --- side path, kept for deleted files (+++ /dev/null)
	inHunk  bool
	newLine int64 // next new-file line number while inHunk
}

// attributePatch maps root-target detections to their patch
// position in a single forward pass over the scanned bytes,
// stamping Commit/Path/Line/Fingerprint in place. Detections keep
// their order; nested-archive hits (member-relative offsets) and
// bytes outside any commit stay unattributed and unfingerprinted,
// so they always report. A mid-stream re-read failure keeps the
// attributions already stamped and warns; only a failure before
// the first byte leaves everything bare. Cancellation aborts the
// pass and returns ctx.Err() for the caller to propagate.
func attributePatch(ctx context.Context, r io.Reader, target string, dets []Detection, log io.Writer) error {
	order := make([]int, 0, len(dets))
	for i := range dets {
		if dets[i].Target == target {
			order = append(order, i)
		}
	}
	// Detection offsets arrive in scan order (nearly sorted); the
	// sort makes the single-pass merge exact regardless.
	sort.SliceStable(order, func(a, b int) bool { return dets[order[a]].Offset < dets[order[b]].Offset })
	p := &patchWalker{ctx: patchCtx{}, dets: dets, order: order}
	if err := p.walk(ctx, r); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logLinef(log, "[patch] warning: attribution incomplete (%s); unattributed findings report without commit/path\n", err.Error())
		return err
	}
	if p.commits == 0 && len(order) > 0 {
		logLinef(log, "[patch] warning: no patch commits found; findings report unattributed and baselines cannot match\n")
	}
	return nil
}

// patchWalker streams patch lines, attributing detection offsets as
// their lines complete.
type patchWalker struct {
	ctx     patchCtx
	dets    []Detection
	order   []int
	next    int // first unattributed index into order
	off     int64
	commits int // commit/From headers seen (zero warns: baselines inert)
}

func (p *patchWalker) walk(ctx context.Context, r io.Reader) error {
	var (
		lineStart int64
		hdr       []byte
		sum       hash.Hash
		first     byte
		haveLine  bool
	)
	// feed appends bytes to the current line's hash and header
	// window in slice ranges, so giant lines stream without
	// per-byte allocations.
	feed := func(chunk []byte) {
		if len(chunk) == 0 {
			return
		}
		if !haveLine {
			first, haveLine, sum = chunk[0], true, sha256.New()
		}
		sum.Write(chunk)
		if len(hdr) < patchHeaderCap {
			hdr = append(hdr, chunk...)
			if len(hdr) > patchHeaderCap {
				hdr = hdr[:patchHeaderCap]
			}
		}
	}
	flush := func() {
		// Empty lines hold no bytes: nothing to attribute, and
		// the hunk state passes through untouched.
		if lineStart < p.off {
			p.attributeLine(lineStart, p.off, hdr, first, haveLine, sum)
		}
		hdr = hdr[:0]
		sum = nil
		haveLine = false
	}
	buf := make([]byte, patchReadChunk)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := r.Read(buf)
		seg := 0
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				feed(buf[seg:i])
				p.off += int64(i - seg)
				flush()
				p.off++
				lineStart = p.off
				seg = i + 1
			}
		}
		feed(buf[seg:n])
		p.off += int64(n - seg)
		if rerr == io.EOF {
			if haveLine {
				flush()
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// attributeLine classifies one completed patch line (bytes
// [start,end), header prefix hdr) and stamps every detection offset
// it holds.
func (p *patchWalker) attributeLine(start, end int64, hdr []byte, first byte, haveFirst bool, sum hash.Hash) {
	// Headers and hunk ends apply before attribution (a detection
	// on the hunk-ending line is not on a hunk line); the new-file
	// line advance applies after (a `+` line holds the current
	// number, not the next one).
	p.classifyPre(hdr, first, haveFirst)
	for p.next < len(p.order) && p.dets[p.order[p.next]].Offset < end {
		d := &p.dets[p.order[p.next]]
		p.next++
		if d.Offset < start {
			continue
		}
		line := 0
		if p.ctx.inHunk && haveFirst && (first == '+' || first == ' ') {
			line = int(p.ctx.newLine)
		}
		d.Commit, d.Path, d.Line = p.ctx.commit, p.ctx.path, line
		if p.ctx.commit != "" && sum != nil {
			raw := sum.Sum(nil)
			d.Fingerprint = "v1/history/" + p.ctx.commit + "/" + p.ctx.path + "/" + d.Needle + "/" + hex.EncodeToString(raw[:8])
		}
	}
	p.classifyPost(first, haveFirst)
}

// classifyPre applies headers and hunk ends before attribution.
// Inside a hunk only [+- \\] lines are content; anything else ends
// the hunk first.
func (p *patchWalker) classifyPre(hdr []byte, first byte, haveFirst bool) {
	c := &p.ctx
	// Inside a hunk, +/-/space lines are always content — even
	// `+++ foo` (an added "++ foo" line) or `--- bar` (a removed
	// "-- bar" line), which must not parse as file headers.
	if c.inHunk && haveFirst && (first == '+' || first == '-' || first == ' ' || first == '\\') {
		return
	}
	s := string(hdr)
	switch {
	case strings.HasPrefix(s, "commit ") && isHexToken(field(s, 1), 4, 64):
		c.commit, c.path, c.minus, c.inHunk = field(s, 1), "", "", false
		p.commits++
		return
	case strings.HasPrefix(s, "From ") && isHexToken(field(s, 1), 4, 64):
		// mbox format-patch series carry the sha on From lines;
		// 64-hex covers sha256 repos like commit does.
		c.commit, c.path, c.minus, c.inHunk = field(s, 1), "", "", false
		p.commits++
		return
	case strings.HasPrefix(s, "diff --git "):
		c.path, c.minus, c.inHunk = patchBPath(s), "", false
		return
	case strings.HasPrefix(s, "diff --cc ") || strings.HasPrefix(s, "diff --combined "):
		rest := strings.TrimPrefix(strings.TrimPrefix(s, "diff --cc "), "diff --combined ")
		c.path, c.minus, c.inHunk = unquotePath(strings.TrimSpace(rest)), "", false
		return
	case strings.HasPrefix(s, "--- "):
		c.minus, c.inHunk = stripSide(strings.TrimSpace(s[4:]), "a/"), false
		return
	case strings.HasPrefix(s, "+++ "):
		if plus := stripSide(strings.TrimSpace(s[4:]), "b/"); plus != "" {
			c.path = plus
		} else if c.minus != "" {
			c.path = c.minus // deleted file: +++ /dev/null
		}
		c.inHunk = false
		return
	case strings.HasPrefix(s, "@@"):
		if start, ok := hunkNewStart(s); ok {
			c.newLine, c.inHunk = start, true
			return
		}
	case strings.HasPrefix(s, "Binary files ") && strings.HasSuffix(strings.TrimRight(s, "\r"), " differ"):
		c.inHunk = false
		return
	}
	// Anything reaching here inside a hunk is a non-content
	// line (content returned early): the hunk ends here.
	if c.inHunk && haveFirst {
		c.inHunk = false
	}
}

// classifyPost advances the new-file line past added/context lines.
// Removed lines and "\ No newline" markers hold no new-file line.
func (p *patchWalker) classifyPost(first byte, haveFirst bool) {
	if p.ctx.inHunk && haveFirst && (first == '+' || first == ' ') {
		p.ctx.newLine++
	}
}

// field returns the whitespace-separated field i of s, or "".
func field(s string, i int) string {
	n := 0
	for _, f := range strings.Fields(s) {
		if n == i {
			return f
		}
		n++
	}
	return ""
}

// isHexToken reports whether tok is hex of length within [lo,hi].
func isHexToken(tok string, lo, hi int) bool {
	if len(tok) < lo || len(tok) > hi {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(tok[i])) {
			return false
		}
	}
	return true
}

// patchBPath takes the b-side path from a `diff --git a/X b/Y`
// line, stripped of its `b/` prefix. Quoted paths (spaces,
// non-ASCII) unquote C-style; anything unparseable yields "".
func patchBPath(s string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(s, "diff --git "))
	a, b, ok := splitDiffSides(rest)
	if !ok {
		return ""
	}
	_ = a
	return stripSide(b, "b/")
}

// splitDiffSides cuts `a/X b/Y` at the unquoted ` b/` boundary.
func splitDiffSides(rest string) (a, b string, ok bool) {
	var inQuote bool
	for i := 0; i+2 < len(rest); i++ {
		switch rest[i] {
		case '"':
			inQuote = !inQuote
		case 'b':
			if !inQuote && i > 0 && rest[i-1] == ' ' && rest[i+1] == '/' {
				return rest[:i-1], rest[i:], true
			}
		}
	}
	return "", "", false
}

// stripSide removes a diff-side prefix (`a/`, `b/`) after
// unquoting; /dev/null (birth/deletion marker) maps to "".
func stripSide(p, side string) string {
	p = unquotePath(strings.TrimSpace(p))
	if p == "/dev/null" {
		return ""
	}
	return strings.TrimPrefix(p, side)
}

// unquotePath unquotes git's C-style path quoting, falling back to
// the raw inner text when it is not valid quoting.
func unquotePath(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		if u, err := strconv.Unquote(p); err == nil {
			return u
		}
		return p[1 : len(p)-1]
	}
	return p
}

// hunkNewStart takes the new-file start line from a hunk header.
// Combined diffs (`@@@ -a -b +c @@@`) carry several old groups; the
// last `+` group is the new side. The closing marker is required:
// a truncated `@@ -1 +1` opens no hunk, so later bytes keep
// commit+path with line 0 instead of a confident wrong line.
func hunkNewStart(s string) (int64, bool) {
	start, ok, closed := int64(0), false, false
	fields := strings.Fields(s)
	for i, f := range fields {
		// Only the range list (between the @@ markers) counts;
		// a hunk heading like "+5 volts" must not override it.
		if i > 0 && strings.HasPrefix(f, "@@") {
			closed = true
			break
		}
		if !strings.HasPrefix(f, "+") || strings.HasPrefix(f, "+++") {
			continue
		}
		num := strings.TrimPrefix(f, "+")
		if i := strings.Index(num, ","); i >= 0 {
			num = num[:i]
		}
		n, err := strconv.ParseInt(num, 10, 64)
		if err != nil || n < 0 {
			continue
		}
		start, ok = n, true
	}
	return start, ok && closed
}

// rewritePatchSidecars re-marshals carve sidecars with attributed
// detections: carves (and their sidecars) are written during the
// scan, before the post-pass attribution exists.
func rewritePatchSidecars(dets []Detection, log io.Writer) {
	for i := range dets {
		d := &dets[i]
		if d.CarvePath == "" || d.Commit == "" {
			continue
		}
		sidecar, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			logLinef(log, "[patch] warning: could not re-marshal %s: %s\n", d.CarvePath, err.Error())
			continue
		}
		if err := os.WriteFile(sidecarPathFor(d.CarvePath), append(sidecar, '\n'), 0644); err != nil {
			logLinef(log, "[patch] warning: could not rewrite sidecar for %s: %s\n", d.CarvePath, err.Error())
		}
	}
}
