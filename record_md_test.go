//go:build !js

// Holds RECORD.md to what its review found. Nothing RECORD.md specifies is built yet, so these tests read
// the document itself: each takes a normative row, puts the review's failing case through the rule that row
// states, and fails while the document would still let that case through. A figure is recomputed, not
// compared with itself. A later build's own tests prove the behavior; these keep the specification honest
// until then, and section 20's cases name what the build must add. A row reworded on purpose changes its test
// with it. The js leg opens no files, so these stay off it, as style_test.go does.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/bits"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One RECORD.md, cut by its numbered headings.
type recordMd struct {
	text string
}

// Reads the document beside this package, where go test runs and a release's moved tree keeps it.
func newRecordMd(t *testing.T) *recordMd {
	t.Helper()
	text, err := os.ReadFile("RECORD.md")
	if err != nil {
		t.Fatal(err)
	}
	return &recordMd{text: string(text)}
}

// From a numbered heading to the next heading of its level or above.
func (self *recordMd) section(t *testing.T, number string) string {
	t.Helper()
	level := "## "
	heading := "## " + number + ". "
	if strings.Contains(number, ".") {
		level = "### "
		heading = "### " + number + " "
	}
	start := strings.Index(self.text, "\n"+heading)
	if start < 0 {
		t.Fatalf("RECORD.md has no section %s", number)
	}
	body := self.text[start+1:]
	lines := strings.Split(body, "\n")
	end := len(lines)
	for i, line := range lines[1:] {
		if strings.HasPrefix(line, "## ") || (level == "### " && strings.HasPrefix(line, "### ")) {
			end = i + 1
			break
		}
	}
	return strings.Join(lines[:end], "\n")
}

// Joins a wrapped passage, so a phrase may span a line break.
func recordMdFlat(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// One row of a section's fenced text blocks, keyed at column 0 or, for a sub-row, column 2, flattened with its
// continuation lines. Empty when the section has no such row, which a stale document shows as a failed phrase.
func (self *recordMd) row(t *testing.T, number string, key string) string {
	t.Helper()
	pattern := regexp.MustCompile(`^ {0,2}` + regexp.QuoteMeta(key) + `( +|$)`)
	fenced := false
	lines := strings.Split(self.section(t, number), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "```") {
			fenced = strings.HasPrefix(line, "```text")
			continue
		}
		if !fenced || !pattern.MatchString(line) {
			continue
		}
		row := []string{line}
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, "        ") {
				break
			}
			row = append(row, next)
		}
		return recordMdFlat(strings.Join(row, " "))
	}
	return ""
}

// Fails for each phrase text does not hold, line wraps aside.
func recordMdRequire(t *testing.T, where string, text string, phrases ...string) {
	t.Helper()
	flat := recordMdFlat(text)
	for _, phrase := range phrases {
		if !strings.Contains(flat, phrase) {
			t.Errorf("%s does not say %q", where, phrase)
		}
	}
}

// Fails for each phrase text still holds, line wraps aside.
func recordMdForbid(t *testing.T, where string, text string, phrases ...string) {
	t.Helper()
	flat := recordMdFlat(text)
	for _, phrase := range phrases {
		if strings.Contains(flat, phrase) {
			t.Errorf("%s still says %q", where, phrase)
		}
	}
}

// One field of a message in RECORD.md's proto blocks.
type recordMdField struct {
	name     string
	typeName string
	number   int
	comment  string
}

var recordMdFieldPattern = regexp.MustCompile(`(?:repeated )?([A-Za-z0-9_]+) ([a-z0-9_]+) = (\d+);`)

// Every message of RECORD.md's proto blocks, by name.
func (self *recordMd) messages(t *testing.T) map[string][]recordMdField {
	t.Helper()
	nameMessages := map[string][]recordMdField{}
	fenced := false
	name := ""
	for _, line := range strings.Split(self.text, "\n") {
		if strings.HasPrefix(line, "```") {
			fenced = strings.HasPrefix(line, "```proto")
			continue
		}
		if !fenced {
			continue
		}
		code, comment, _ := strings.Cut(line, "//")
		comment = strings.TrimSpace(comment)
		if rest, found := strings.CutPrefix(code, "message "); found {
			head, _, _ := strings.Cut(rest, "{")
			name = strings.TrimSpace(head)
			nameMessages[name] = []recordMdField{}
		}
		if name == "" {
			continue
		}
		matches := recordMdFieldPattern.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			number, err := strconv.Atoi(match[3])
			if err != nil {
				t.Fatal(err)
			}
			field := recordMdField{name: match[2], typeName: match[1], number: number, comment: comment}
			nameMessages[name] = append(nameMessages[name], field)
		}
		if len(matches) == 0 && strings.TrimSpace(code) == "" && comment != "" {
			fields := nameMessages[name]
			if len(fields) > 0 {
				fields[len(fields)-1].comment += " " + comment
			}
		}
		if strings.Contains(code, "}") {
			name = ""
		}
	}
	return nameMessages
}

// One message's field by name, failing the test when the message has none.
func (self *recordMd) field(t *testing.T, message string, name string) recordMdField {
	t.Helper()
	for _, field := range self.messages(t)[message] {
		if field.name == name {
			return field
		}
	}
	t.Errorf("message %s has no field %s", message, name)
	return recordMdField{}
}

// One row of section 6.3's registry.
type recordMdKind struct {
	number   int
	name     string
	class    string
	personal string
	team     string
	writer   string
	source   string
	since    string
}

// Section 6.3's rows by kind name.
func (self *recordMd) registry(t *testing.T) map[string]recordMdKind {
	t.Helper()
	nameKinds := map[string]recordMdKind{}
	for _, line := range strings.Split(self.section(t, "6.3"), "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if len(cells) != 8 {
			continue
		}
		number, err := strconv.Atoi(cells[0])
		if err != nil {
			continue
		}
		name := strings.Trim(cells[1], "`")
		nameKinds[name] = recordMdKind{
			number:   number,
			name:     name,
			class:    cells[2],
			personal: cells[3],
			team:     cells[4],
			writer:   cells[5],
			source:   cells[6],
			since:    cells[7],
		}
	}
	if len(nameKinds) == 0 {
		t.Fatal("section 6.3 holds no registry rows")
	}
	return nameKinds
}

// Section 18's Go block.
func (self *recordMd) goFile(t *testing.T) *ast.File {
	t.Helper()
	section := self.section(t, "18")
	_, rest, found := strings.Cut(section, "```go\n")
	if !found {
		t.Fatal("section 18 holds no go block")
	}
	block, _, _ := strings.Cut(rest, "```")
	file, err := parser.ParseFile(token.NewFileSet(), "record.go", "package sidecar\n"+block, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// A struct section 18's block declares, failing the test when it declares none by that name.
func recordMdStruct(t *testing.T, file *ast.File, name string) *ast.StructType {
	t.Helper()
	var found *ast.StructType
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if ok && spec.Name.Name == name {
			found, _ = spec.Type.(*ast.StructType)
		}
		return true
	})
	if found == nil {
		t.Fatalf("section 18 declares no struct %s", name)
	}
	return found
}

// A decimal as the document writes it, with commas.
func recordMdNumber(t *testing.T, text string) int64 {
	t.Helper()
	value, err := strconv.ParseInt(strings.ReplaceAll(text, ",", ""), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// One length-delimited field, as a body RECORD.md sketches and record.proto does not yet hold is marshaled.
func recordMdAppendBytes(message []byte, number protowire.Number, value []byte) []byte {
	message = protowire.AppendTag(message, number, protowire.BytesType)
	return protowire.AppendBytes(message, value)
}

// One varint field, as above.
func recordMdAppendVarint(message []byte, number protowire.Number, value uint64) []byte {
	message = protowire.AppendTag(message, number, protowire.VarintType)
	return protowire.AppendVarint(message, value)
}

// Finding: "entries in no run take false" labeled an unbound session's record_append untainted, which §16.6
// holds tainted, failing open on I-9.
func TestRecordMdUnboundSessionEntriesSealTainted(t *testing.T) {
	doc := newRecordMd(t)
	recordMdForbid(t, "section 5.3", doc.section(t, "5.3"), "entries in no run take false")
	cases := []struct {
		filer  string
		row    string
		phrase string
	}{
		{filer: "a bound run", row: "run", phrase: "takes the run's bit at sealing"},
		{filer: "a run whose file is gone", row: "run", phrase: "a missing or unreadable run file reads true"},
		{filer: "an MCP session no run binds", row: "unbound", phrase: "an MCP session"},
		{filer: "a ur command under a harness", row: "unbound", phrase: "a ur command with a harness process as its ancestor"},
		{filer: "either of those", row: "unbound", phrase: "takes true"},
		{filer: "the daemon's own act", row: "none", phrase: "false only for an entry no session touched"},
	}
	for _, c := range cases {
		recordMdRequire(t, "section 5.3's "+c.row+" row, for "+c.filer, doc.row(t, "5.3", c.row), c.phrase)
	}
	// The labels a request and an announcement carry take the same answer.
	recordMdRequire(t, "section 5.3's tainted row", doc.row(t, "5.3", "tainted"), "ApprovalRequest.tainted", "DirectoryRequest.tainted", "Announcement.tainted")

	// The draft's zero value has to fail closed, so a caller who forgets the field seals tainted.
	draft := recordMdStruct(t, doc.goFile(t), "RecordDraft")
	noSession := false
	for _, field := range draft.Fields.List {
		for _, name := range field.Names {
			if name.Name == "NoSession" {
				noSession = true
				if field.Comment == nil || !strings.Contains(field.Comment.Text(), "seals tainted") {
					t.Errorf("RecordDraft.NoSession does not say a nil RunId without it seals tainted")
				}
			}
			if name.Name == "RunId" && field.Comment != nil && strings.Contains(field.Comment.Text(), "entry in no run") {
				t.Errorf("RecordDraft.RunId still reads as an entry in no run, with no taint rule")
			}
		}
	}
	if !noSession {
		t.Errorf("RecordDraft has no field telling a session's entry from an entry no session touched")
	}
	recordMdRequire(t, "section 6.3", doc.section(t, "6.3"), "a claim or handoff from a session no run binds answers FAILED_PRECONDITION")
}

// Finding: two ingesters each hold a slot row for one key, and an erasure naming one row leaves the body
// open from the other stream.
func TestRecordMdErasureReachesEveryCopyOfAnEntry(t *testing.T) {
	doc := newRecordMd(t)
	type slotRow struct {
		stream string
		live   bool
	}
	rows := []*slotRow{{stream: "ingester-a", live: true}, {stream: "ingester-b", live: true}}

	// What a reader keeps decides what an eraser can name.
	twice := doc.row(t, "5.4", "twice")
	named := rows[:1]
	if strings.Contains(twice, "keep every copy's (ref, path, key_slot_id, key_index)") &&
		strings.Contains(recordMdFlat(doc.section(t, "8")), "names in one ERASE each copy's `(key_slot_id, key_index)`") {
		named = rows
	}
	for _, row := range named {
		row.live = false
	}
	for _, row := range rows {
		if row.live {
			t.Errorf("the erased body still opens from %s's slot row", row.stream)
		}
	}

	section := doc.section(t, "8")
	recordMdRequire(t, "section 8", section,
		"any unconsumed deposit's slot holding the entry",
		"That slot's key opens a whole batch, so the eraser first ingests the deposit",
		"ERASEs that copy's row under the same `erasure_id`",
	)
	recordMdRequire(t, "section 5.4's erased step", doc.row(t, "5.4", "6 erased"), "consume unrecorded")
	recordMdRequire(t, "section 5.5's states", doc.row(t, "5.5", "states"), "an ERASE named a key of any copy")

	// Two copies have two push times, and expiry must read the same one on every device.
	recordMdRequire(t, "section 5.5's push time row", doc.row(t, "5.5", "push time"), "the time_ms of the earliest push holding a copy of it")
	recordMdRequire(t, "section 8's keep_days row", doc.row(t, "8", "keep_days"), "their push time", "two ingesters' copies of an entry expire together, on the earlier push")

	// Search keeps §11.14's locator, the path a hit opens in its ref, and a doc_key is built over that path, so each
	// copy is its own document, and the erasure's CUT has to list both or one stays findable.
	recordMdRequire(t, "section 7.1's row", doc.row(t, "7.1", "row"), "locator the stream path", "are two documents, each under its own ref and doc_key")
	recordMdRequire(t, "section 8", section, "so the erasure's CUT lists each")
}

// Finding: e/<n div 2048>/<n> made e/ one directory, so a stream hit 409 DIRECTORY_FULL at about 7.3 million
// entries, inside T's 400 days at section 13.2's rates.
func TestRecordMdStreamPathFitsTheDirectoryBound(t *testing.T) {
	doc := newRecordMd(t)
	row := doc.row(t, "5.2", "stream path")
	// §11.7 and §16.8 count a row at about 128 B, of which a name is under 64 B.
	recordMdForbid(t, "section 5.2's stream path row", row, "each row under 64 B")
	recordMdRequire(t, "section 5.2's stream path row", row, "each name under 64 B and so each row about 128 B")
	path := regexp.MustCompile(`e/(?:<[^>]*>/?)+`).FindString(row)
	if path == "" {
		t.Fatalf("the stream path row states no path: %q", row)
	}
	// Each level as a function of n, in order from e/.
	levels := []func(n int64) int64{}
	for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "e/"), "/"), "/") {
		if part == "<n>" {
			levels = append(levels, func(n int64) int64 { return n })
		} else if match := regexp.MustCompile(`^<n div ([0-9,]+)>$`).FindStringSubmatch(part); match != nil {
			divisor := recordMdNumber(t, match[1])
			levels = append(levels, func(n int64) int64 { return n / divisor })
		} else if match := regexp.MustCompile(`^<\(n div ([0-9,]+)\) mod ([0-9,]+)>$`).FindStringSubmatch(part); match != nil {
			divisor, modulus := recordMdNumber(t, match[1]), recordMdNumber(t, match[2])
			levels = append(levels, func(n int64) int64 { return (n / divisor) % modulus })
		} else {
			t.Fatalf("cannot read path level %q", part)
		}
	}

	// §11.7: names under 64 B take 128 B a row, and 448 KiB of name table binds at 3,584 children.
	const nameRowByteCount = 128
	const directoryChildCount = 448 * 1024 / nameRowByteCount
	// §16.8: a stream's directories stay within 256 KiB of name table.
	const streamDirectoryChildCount = 256 * 1024 / nameRowByteCount

	// Section 13.2's Team limit, kept for section 8's 400 days at 5 working days in 7.
	const keptEntryCount = 400 * 5 * 400000 / 7
	if rootChildCount := levels[0](keptEntryCount) + 1; rootChildCount > directoryChildCount {
		t.Errorf("e/ needs %d children for %d kept entries, past §11.7's %d", rootChildCount, keptEntryCount, directoryChildCount)
	}

	// Every directory below e/, over enough of a stream to cross each level.
	samePrefix := func(depth int, a int64, b int64) bool {
		for _, level := range levels[:depth] {
			if level(a) != level(b) {
				return false
			}
		}
		return true
	}
	for depth := 1; depth < len(levels); depth++ {
		childCount, maxChildCount := int64(1), int64(1)
		for n := int64(2); n < 3*2048*2048; n++ {
			if !samePrefix(depth, n-1, n) {
				childCount = 1
			} else if levels[depth](n-1) != levels[depth](n) {
				childCount++
			}
			if childCount > maxChildCount {
				maxChildCount = childCount
			}
		}
		if maxChildCount > streamDirectoryChildCount {
			t.Errorf("level %d holds %d children, past §16.8's %d", depth, maxChildCount, streamDirectoryChildCount)
		}
	}

	// The whole life of a stream: how far n runs before e/ fills, with nothing removed.
	low, high := int64(1), int64(1000000000000)
	for low+1 < high {
		middle := (low + high) / 2
		if levels[0](middle) < directoryChildCount {
			low = middle
		} else {
			high = middle
		}
	}
	if low < 15000000000 {
		t.Errorf("a stream fills at %d entries, short of the 15 billion section 5.2 states", low)
	}

	// A path stays a function of seq, which DecisionRef needs, and the document's vectors say so.
	vectors := doc.row(t, "20", "stream path")
	cases := []struct {
		n    int64
		path string
	}{
		{n: 1, path: "e/0/0/1"},
		{n: 2047, path: "e/0/0/2047"},
		{n: 2048, path: "e/0/1/2048"},
		{n: 4194303, path: "e/0/2047/4194303"},
		{n: 4194304, path: "e/1/0/4194304"},
	}
	for _, c := range cases {
		parts := []string{"e"}
		for _, level := range levels {
			parts = append(parts, strconv.FormatInt(level(c.n), 10))
		}
		if path := strings.Join(parts, "/"); path != c.path {
			t.Errorf("n %d names %s, want %s", c.n, path, c.path)
		}
		recordMdRequire(t, "section 20's stream path vector", vectors, c.path)
	}
}

// Finding: section 5.7 said format 1 needs no change on four checks that left out what decides the question.
func TestRecordMdFormatOneFindingNamesWhatItRestsOn(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "5.7")
	recordMdForbid(t, "section 5.7", section, "The answer in this draft is that format 1 needs no change")
	recordMdRequire(t, "section 5.7", section,
		"the review cannot confirm it until the open rows below settle",
		"plan-EVS1-v1-unspecified",
		"plan-RECORD-depositor-spool",
		"plan-RECORD-stream-names",
		"`consumed_through`",
	)
	recordMdRequire(t, "section 20's G0 row", doc.row(t, "20", "G0, M2-in"), "section 5.7's open rows settled")
	// A listing no reader can see is no check.
	recordMdForbid(t, "section 8", doc.section(t, "8"), "lists every class 7 entry", "finds one unlisted")

	// Slot object: §11.8's 8 KiB, 64 rows of 64 B with a 24 B nonce and a 16 B tag.
	const slotRowByteCount = 64 + 24 + 16
	if byteCount := 64 * slotRowByteCount; byteCount != 6656 || byteCount > 8*1024 {
		t.Errorf("a full slot object is %d B", byteCount)
	}
	recordMdRequire(t, "section 5.7", section, "6,656 B of its 8 KiB")

	// Read receipt: every field at its largest, in record.proto's own envelope, through a deposit batch, §11.6's
	// record framing and Padmé. ReadBody and RecordDeposit are RECORD.md's, so they are built by their field numbers.
	id := make([]byte, 16)
	hash := make([]byte, 32)
	body := []byte{}
	for i := 0; i < 64; i++ {
		body = recordMdAppendBytes(body, 1, hash)
	}
	body = recordMdAppendVarint(body, 2, 4)
	body = recordMdAppendBytes(body, 3, id)
	header, err := proto.Marshal(&protocol.RecordHeader{
		EntryId:         id,
		LogId:           id,
		WriterSidecarId: id,
		Seq:             math.MaxUint64,
		PrevSha256:      hash,
		AgentId:         id,
		RunId:           id,
		ActionId:        hash,
		Kind:            35,
		TimeMillis:      math.MaxInt64,
		Source:          1,
		Tainted:         true,
		BodyCommitment:  hash,
		PolicyVersion:   math.MaxUint64,
		GrantId:         hash,
		AgentSource:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := proto.Marshal(&protocol.RecordEntry{
		Header: &bridge.Signed{
			Body:      header,
			SignerId:  id,
			KeyId:     id,
			Signature: make([]byte, 64),
			Type:      uint32(bridge.SignedType_SIGNED_RECORD_HEADER),
		},
		SealedBody: make([]byte, 24+len(body)+16),
		Version:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	deposit := []byte{}
	deposit = recordMdAppendBytes(deposit, 1, entry)
	deposit = recordMdAppendBytes(deposit, 2, hash)
	deposit = recordMdAppendBytes(deposit, 3, hash)
	batch := recordMdAppendBytes(nil, 1, deposit)
	// §11.6's Padmé, over its 160 B record header and 16 B frame tag.
	length := len(batch) + 160 + 16
	exponent := bits.Len(uint(length)) - 1
	mask := (1 << (exponent - bits.Len(uint(exponent)))) - 1
	if padded := (length + mask) &^ mask; padded >= 3*1024 {
		t.Errorf("a worst-case read receipt pads to %d B, and section 5.7 says under 3 KiB", padded)
	}
	recordMdRequire(t, "section 5.7", section, "under 3 KiB at worst, Padmé included")
}

// Finding: membership and key rows had the statement's signer write each affected vault, which §8.5 and owner
// decision 126 give it no right to.
func TestRecordMdVaultEntriesComeOnlyFromTheMatrixWriters(t *testing.T) {
	doc := newRecordMd(t)
	// Roles §16.8's matrix does not give V. Each may write T, so its cell must keep it to T.
	outsiders := []string{"statement's signer", "alarming device", "rotator", "registrar"}
	for _, kind := range doc.registry(t) {
		if !strings.Contains(kind.team, "vault") && !regexp.MustCompile(`\bV\b`).MatchString(kind.team) {
			continue
		}
		for _, clause := range strings.Split(kind.writer, ";") {
			clause = strings.TrimSpace(clause)
			if strings.HasPrefix(clause, "T:") {
				continue
			}
			for _, outsider := range outsiders {
				if strings.Contains(clause, outsider) {
					t.Errorf("kind %s lands in a vault with writer %q", kind.name, clause)
				}
			}
		}
		if strings.Contains(kind.team, "affected vault") {
			recordMdRequire(t, "kind "+kind.name+"'s writer", kind.writer, "a vault: only its own member's devices")
		}
	}
	recordMdRequire(t, "section 4.2's mirrors row", doc.row(t, "4.2", "mirrors"),
		"comes only from M's own devices",
		"an admin's device never writes to M's vault",
		"a removed member has no device left to write",
	)
	// The matrix narrows §16.8's "each affected log", which section 16.2 has to own up to.
	recordMdRequire(t, "section 16.2", doc.section(t, "16.2"), `§16.8's "into each affected log" reads, for a member's vault, as what §8.5's matrix lets in`)
}

// Finding: a re-open held only while the run file lasts, and §16.6 deletes that file 30 days after Coverage, so
// a tainted session resumed later bound as new and started untainted.
func TestRecordMdTaintOutlivesTheRunFile(t *testing.T) {
	doc := newRecordMd(t)
	reopen := doc.row(t, "4.3", "re-open")
	binding := doc.row(t, "4.3", "binding")
	resumed := doc.row(t, "4.3", "resumed")

	// A tainted session, its Coverage sealed, its run file gone at day 30, the harness resuming it at day 40.
	rebinds := !strings.Contains(reopen, "while its run file lasts") && strings.Contains(binding, "for as long as its state lives")
	tainted := rebinds && strings.Contains(binding, "starts tainted whatever the old bit was")
	if !tainted {
		t.Errorf("a tainted session resumed after its run file's deletion starts clean")
	}
	recordMdRequire(t, "section 4.3's binding row", binding, "binds that run_id", "no session binds as new")
	recordMdRequire(t, "section 4.3's resumed row", resumed, "source resume, fork or compact", "starts tainted")
	recordMdRequire(t, "section 6.4", doc.section(t, "6.4"), "`run_file_missing`")
	recordMdRequire(t, "section 18", doc.section(t, "18"), "session rows")
	recordMdRequire(t, "D-RECORD-5", doc.section(t, "15"), "A row per session outlasts the run file")
	// Starting tainted departs from §16.6's "a new run starts untainted", in the closed direction, and says so.
	recordMdRequire(t, "section 16.2", doc.section(t, "16.2"), "A session with no row that reports earlier context starts tainted too")
}

// Finding: ur record erase asked for no person, so an agent's shell could destroy record bodies for good, class 7
// among them.
func TestRecordMdErasureTakesAPerson(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "8")
	recordMdRequire(t, "section 8", section,
		"signs only once confirmed on /dev/tty or in an app's UI",
		"no MCP tool reaches it",
		"a command with a harness process as its ancestor is refused",
		"It refuses a class 7 entry",
	)
	recordMdRequire(t, "section 8's floor row", doc.row(t, "8", "floor"), "no policy blocks, class 7 aside")
	// A shorter keep_days erases at the next expiry pass, so it is the same act by another door.
	recordMdRequire(t, "section 8's change row", doc.row(t, "8", "change"), "on existing entries too")
	recordMdRequire(t, "section 8", section, "A `ur record retention set` that shortens a class's life takes the same refusal")
	recordMdRequire(t, "kind erasure's source", doc.registry(t)["erasure"].source, "approver for reasons 1 and 3")

	// Every command that files a person's act says so where it is listed.
	flat := recordMdFlat(doc.text)
	commands := []string{
		"ur record retention set",
		"ur record erase",
		"ur record ledger set",
		"ur record log on",
		"ur record log off",
		"ur record model set",
	}
	for _, command := range commands {
		found := false
		for _, line := range strings.Split(doc.text, "\n") {
			if strings.HasPrefix(line, command) {
				found = true
				usage := line
				if !strings.Contains(usage, "/dev/tty") {
					// A usage that wraps states the rule on its next line.
					index := strings.Index(doc.text, line)
					rest := doc.text[index+len(line):]
					next, _, _ := strings.Cut(strings.TrimPrefix(rest, "\n"), "\n")
					usage += next
				}
				if !strings.Contains(usage, "/dev/tty") {
					t.Errorf("%s does not say it needs a person: %q", command, usage)
				}
			}
		}
		if !found {
			t.Errorf("RECORD.md lists no usage for %s", command)
		}
	}
	recordMdRequire(t, "section 11", doc.section(t, "11"), "`ur record attest` on /dev/tty or in an app's UI")

	// Section 18's list holds every ur record command the document names.
	provides := recordMdFlat(doc.section(t, "18"))
	for _, match := range regexp.MustCompile(`ur record ([a-z]+)`).FindAllStringSubmatch(flat, -1) {
		if !strings.Contains(provides, "`"+match[1]+"`") {
			t.Errorf("section 18 does not list ur record %s", match[1])
		}
	}
}

// Finding: an export's record could be a deposited disclosure entry from a reader that only deposits, which ingest
// discards with a false alarm, so no record landed.
func TestRecordMdReceiptOnlyExportRecordReachesTheLog(t *testing.T) {
	doc := newRecordMd(t)
	recordMdRequire(t, "section 5.4's class step", doc.row(t, "5.4", "5 class"), "a receipt-only depositor: only kind read with source observed")
	record := doc.row(t, "9", "record")
	recordMdForbid(t, "section 9's record row", record, "is deposited by a reader that only deposits")
	// Each reader's path must end in something its log's ingest keeps.
	cases := []struct {
		reader string
		phrase string
	}{
		{reader: "a writer of the log", phrase: "a writer of the log commits a disclosure entry"},
		{reader: "a depositor beyond receipts", phrase: "a reader that deposits more than receipts deposits one and holds evs's 200"},
		{reader: "a receipt-only reader", phrase: "a receipt-only reader files none, since ingest takes only read from it"},
		{reader: "a receipt-only reader", phrase: "its purpose 3 receipts stand as the record"},
		{reader: "neither", phrase: "a reader that can do neither cannot export"},
	}
	for _, c := range cases {
		recordMdRequire(t, "section 9's record row, for "+c.reader, record, c.phrase)
	}
	if purpose := doc.field(t, "ReadBody", "purpose"); !strings.Contains(purpose.comment, "3 export") {
		t.Errorf("ReadBody.purpose has no export value: %q", purpose.comment)
	}

	// A packet is the same act: the reader that only deposits receipts cannot land a disclosure entry there either.
	packet := doc.row(t, "11", "record")
	recordMdForbid(t, "section 11's record row", packet, "the disclosure entry commits in the log before the file is written, and an act")
	recordMdRequire(t, "section 11's record row", packet,
		"by section 9's record row",
		"a receipt-only reader files none, since ingest takes only read from it",
		"purpose 4, which stand as the record",
		"an act that cannot land is refused",
	)
	if purpose := doc.field(t, "ReadBody", "purpose"); !strings.Contains(purpose.comment, "4 disclosure") {
		t.Errorf("ReadBody.purpose has no disclosure value: %q", purpose.comment)
	}
	recordMdRequire(t, "D-RECORD-10", doc.section(t, "15"), "a `disclosure` entry, or a receipt-only reader's read receipts")
}

// Finding: ur evs export emitted bodies from T, R and D with no person, taint or disclosure entry, and a
// disclosure entry could not show that bodies left.
func TestRecordMdEvsExportFollowsEveryExportRule(t *testing.T) {
	doc := newRecordMd(t)
	section := recordMdFlat(doc.section(t, "9"))
	recordMdForbid(t, "section 9", section, "`ur evs export` of a vault follows")
	_, paragraph, found := strings.Cut(section, "**`ur evs export`** of a log")
	if !found {
		t.Fatal("section 9 has no ur evs export paragraph")
	}
	paragraph, _, _ = strings.Cut(paragraph, "**`ocsf`**")
	recordMdRequire(t, "section 9's ur evs export paragraph", paragraph,
		"counts as `ur record export --bodies`",
		"on every log, V, D, T and R alike",
		"the `who`, `confirm`, `receipt`, `record` and `copies` rows above bind it",
		"format 4 and bodies true",
	)
	recordMdRequire(t, "section 9's confirm row", doc.row(t, "9", "confirm"), "first taints each such run")

	// An export's entry has to show what left, so readers see who exported what.
	for _, name := range []string{"bodies", "kinds", "run_id", "format", "since_millis", "until_millis"} {
		doc.field(t, "DisclosureBody", name)
	}
	if format := doc.field(t, "DisclosureBody", "format"); !strings.Contains(format.comment, "4 git") {
		t.Errorf("DisclosureBody.format has no value for ur evs export: %q", format.comment)
	}
	recordMdRequire(t, "D-RECORD-8", doc.section(t, "15"), "`ur evs export` of a log among them")
}

// Finding: section 5.5 judged a writer's right at the ingester's pin, so a member removed between deposit and ingest
// lost what it filed while admitted.
func TestRecordMdIngestedEntryIsJudgedWhereItCameIn(t *testing.T) {
	doc := newRecordMd(t)
	// A member removed at log position 100; it sealed at 90 and deposited at 95, and an admin's laptop ingests at 120.
	const removedPosition, sealedPosition, depositPosition, ingesterPosition = 100, 90, 95, 120
	admitted := func(position int) bool { return position < removedPosition }

	reader := doc.row(t, "5.5", "3 right")
	readerPosition := ingesterPosition
	if strings.Contains(reader, "in an ingester's stream") && strings.Contains(reader, "at the position policy_version names") {
		readerPosition = sealedPosition
	}
	if !admitted(readerPosition) {
		t.Errorf("a reader judges the ingested entry at position %d, after the writer's removal", readerPosition)
	}
	ingest := doc.row(t, "5.4", "3 right")
	ingestPosition := ingesterPosition
	if strings.Contains(ingest, "at the auth pin of the deposit's own push") {
		ingestPosition = depositPosition
	}
	if !admitted(ingestPosition) {
		t.Errorf("ingest judges the entry at position %d, after the writer's removal", ingestPosition)
	}

	// A later position must still fail, or a removed writer could date past its removal.
	recordMdRequire(t, "section 5.5's right step", reader, "which may not pass the ingester's pin", "no compromise revocation of the writer from a since_n at or before that position")
	recordMdRequire(t, "section 5.4's right step", ingest, "policy_version does not pass that pin", "no log entry after it ending the right more than 10 min before that push's time_ms")
	// The writer's own stream keeps the push's pin.
	recordMdRequire(t, "section 5.5's right step", reader, "in the writer's own stream, at that push's auth pin")
}

// Finding: newest by (writer, seq) ordered nothing across writers, so an old policy from a higher id beat a later
// one for good, and a handoff from a lower id never closed a claim.
func TestRecordMdNewestOrdersAcrossWriters(t *testing.T) {
	doc := newRecordMd(t)
	type policy struct {
		writer   byte
		seq      uint64
		pushMs   int64
		keepDays uint32
	}
	const dayMs = 24 * 60 * 60 * 1000
	policies := []policy{
		{writer: 0x02, seq: 5, pushMs: 0, keepDays: 400},
		{writer: 0x01, seq: 1000, pushMs: 365 * dayMs, keepDays: 800},
		// The same writer's clock stepped back: its later seq still replaces its earlier one.
		{writer: 0x03, seq: 7, pushMs: 200 * dayMs, keepDays: 500},
		{writer: 0x03, seq: 8, pushMs: 100 * dayMs, keepDays: 600},
	}
	row := doc.row(t, "5.5", "newest")
	byPushTime := strings.Contains(row, "each writer's newest by seq stands for that writer") && strings.Contains(row, "the latest push time wins")
	newest := func() policy {
		writerNewests := map[byte]policy{}
		for _, candidate := range policies {
			if held, found := writerNewests[candidate.writer]; !found || candidate.seq > held.seq {
				writerNewests[candidate.writer] = candidate
			}
		}
		winner := policy{}
		for _, candidate := range writerNewests {
			if byPushTime {
				if candidate.pushMs > winner.pushMs || (candidate.pushMs == winner.pushMs && candidate.writer > winner.writer) {
					winner = candidate
				}
			} else if candidate.writer > winner.writer {
				winner = candidate
			}
		}
		return winner
	}()
	if newest.keepDays != 800 {
		t.Errorf("keep_days %d governs, from writer %d's seq %d, not the policy signed a year later", newest.keepDays, newest.writer, newest.seq)
	}

	// Every rule that picks one entry across writers cites that row, and none falls back on seq alone.
	recordMdRequire(t, "section 8's newest row", doc.row(t, "8", "newest"), "section 5.5's newest row")
	recordMdRequire(t, "section 6.5", doc.section(t, "6.5"), "section 5.5's `newest` row")
	recordMdRequire(t, "section 10.2's who row", doc.row(t, "10.2", "who"), "section 5.5's newest row")
	for _, number := range []string{"6.5", "7.3", "8"} {
		recordMdForbid(t, "section "+number, doc.section(t, number), "by (writer, seq)")
	}

	// A claim: its opener at a high id, a handoff from a low id.
	fold := doc.row(t, "7.3", "fold")
	closed := strings.Contains(fold, "a handoff naming the claim from any writer makes it handed_off") && strings.Contains(fold, "neither is undone")
	if !closed {
		t.Errorf("a handoff from a lower id does not close the claim")
	}
}

// Finding: the witness POST is a new carrier D-ARCH-2 reserves to the owner, and nothing gated it.
func TestRecordMdWitnessCarrierWaitsOnTheOwner(t *testing.T) {
	doc := newRecordMd(t)
	questions := recordMdFlat(doc.section(t, "16.1"))
	recordMdRequire(t, "section 16.1", questions, "**Q-RECORD-8.**", "D-ARCH-2", "no device POSTs a note")
	recordMdRequire(t, "section 10.2's witness step", doc.row(t, "10.2", "6 witness"), "once Q-RECORD-8 is answered")
	recordMdRequire(t, "section 10.2's on row", doc.row(t, "10.2", "on"), "--witness refuses", "while Q-RECORD-8 is open")
	recordMdRequire(t, "section 18", doc.section(t, "18"), "*pending Q-RECORD-8*", "each row naming a Q-RECORD item waits on the owner", "another way | Q-RECORD-8 |")
	recordMdForbid(t, "section 18", doc.section(t, "18"), "the first four wait on the owner")
	recordMdRequire(t, "section 20's M6 row", doc.row(t, "20", "M6"), "Q-RECORD-1, 3, 4, 5, 6, 7, 8")
	recordMdRequire(t, "D-RECORD-9", doc.section(t, "15"), "Pending Q-RECORD-1, Q-RECORD-8")
}

// Finding: a note a witness cosigned could live only in a dead checkpointer's journal, so a successor signed an
// inconsistent tree.
func TestRecordMdEveryWitnessedNoteIsInTheLog(t *testing.T) {
	doc := newRecordMd(t)
	steps := []string{}
	for _, line := range strings.Split(doc.section(t, "10.2"), "\n") {
		if match := regexp.MustCompile(`^  \d ([a-z]+) `).FindStringSubmatch(line); match != nil {
			steps = append(steps, match[1])
		}
	}
	if len(steps) == 0 {
		t.Fatal("section 10.2 lists no steps")
	}
	// Crash after each step, the device never returning: whatever a witness holds, a successor must replay.
	for crash := range steps {
		signed, filed, witnessed := false, false, false
		for _, step := range steps[:crash+1] {
			switch step {
			case "sign":
				signed = true
			case "entry":
				filed = signed
			case "witness":
				witnessed = signed
			}
		}
		if witnessed && !filed {
			t.Errorf("a crash after step %q leaves a note at a witness that no successor can replay", steps[crash])
		}
	}

	// A crash must not file a second entry for one batch.
	recordMdRequire(t, "section 10.2's resume row", doc.row(t, "10.2", "resume"), "an entry already in this stream counts as sent", "so a crash files no second entry for a batch")
	recordMdRequire(t, "section 10.2's who row", doc.row(t, "10.2", "who"), "a second entry for one batch with the same note is a copy, and with another note a fork")

	// Cosignatures now land after the note, so the message has somewhere to hold them.
	doc.field(t, "LogCheckpointBody", "cosigned")
	doc.field(t, "LogCosigned", "lines")

	// A successor's key waits on each witness's operator, and the risks and tests say that.
	recordMdRequire(t, "section 10.2's successor row", doc.row(t, "10.2", "successor"),
		"its tree extends each of them",
		"answers 403 to another",
		"a new key waits on each witness's operator",
	)
	recordMdRequire(t, "section 10.2's old signer row", doc.row(t, "10.2", "old signer"), "409 or 422")
	recordMdRequire(t, "section 19", doc.section(t, "19"), "each witness's operator must add the successor's key", "each witness's operator drops the old key")
	recordMdRequire(t, "section 20", doc.section(t, "20"), "a witness without the successor's key answering 403")

	// A client holds every key the log has used, so a packet spanning a rotation can verify.
	section := doc.section(t, "11")
	recordMdRequire(t, "section 11", section, "--log-key vkey... [--witness", "`--log-key` repeats", "verifies under both keys and fails under one")
	recordMdForbid(t, "section 11", section, "pins them once")
}

// Finding: "stays off" had no enforcement point, ledger_scope could move cost out of V, and Q-RECORD-1 understated
// what it blocks.
func TestRecordMdEveryPendingGateNamesItsEnforcementPoint(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "16.1")
	questions := regexp.MustCompile(`\*\*(Q-RECORD-\d+)\.\*\*`).FindAllStringSubmatch(section, -1)
	if len(questions) < 8 {
		t.Fatalf("section 16.1 holds %d questions", len(questions))
	}
	for _, question := range questions {
		pattern := regexp.MustCompile(`(?m)^\| ` + question[1] + ` \| ([^|]+) \| ([^|]+) \|$`)
		match := pattern.FindStringSubmatch(section)
		if match == nil {
			t.Errorf("%s has no row saying what stays off and what enforces it", question[1])
		}
	}
	recordMdRequire(t, "Q-RECORD-1", section, "which is most T logs, and so disclosure packets from them")
	recordMdRequire(t, "section 10.2's read step", doc.row(t, "10.2", "1 read"), "while Q-RECORD-1 is open, if the log holds more than one stream")
	recordMdRequire(t, "section 10.2's on row", doc.row(t, "10.2", "on"), "refuses on a log with more than one stream")
	recordMdRequire(t, "section 11's checkpoint row", doc.row(t, "11", "checkpoint"), "refuses on a log whose verifiable log is off")
	// A reader holds the gate too, as it does Q-RECORD-8's, so an old or rogue checkpointer gets nowhere.
	recordMdRequire(t, "section 10.2's monitor row", doc.row(t, "10.2", "monitor"), "while Q-RECORD-1 is open, a batch whose frontier names more than one stream is ignored with an alarm")
	if kinds := doc.field(t, "LedgerScopeBody", "kinds"); !strings.Contains(kinds.comment, "Q-RECORD-6") {
		t.Errorf("LedgerScopeBody.kinds can still list cost past V: %q", kinds.comment)
	}
	recordMdRequire(t, "section 4.2", doc.section(t, "4.2"), "until the owner answers no daemon files one")
	recordMdRequire(t, "section 11", doc.section(t, "11"), "Until the owner answers, `ur record attest` refuses")
}

// Finding: three failed checks had no stated outcome, so a forged entry's fate at ingest was undefined.
func TestRecordMdEveryCheckStatesItsOutcome(t *testing.T) {
	doc := newRecordMd(t)
	cases := []struct {
		section string
		row     string
		outcome string
	}{
		{section: "5.4", row: "1 parse", outcome: "consume unrecorded, alarm"},
		{section: "5.4", row: "2 signer", outcome: "any failure: consume unrecorded, alarm"},
		{section: "5.4", row: "3 right", outcome: "any failure: consume unrecorded, alarm"},
		{section: "5.4", row: "4 body", outcome: "a body that does not open or a mismatch: consume unrecorded, alarm"},
		{section: "5.4", row: "5 class", outcome: "else consume unrecorded, alarm"},
		{section: "5.4", row: "6 erased", outcome: "consume unrecorded"},
		{section: "5.4", row: "7 chain", outcome: "kept and alarmed, never dropped"},
		{section: "5.5", row: "1 push", outcome: "a failure: ignore and alarm"},
		{section: "5.5", row: "2 header", outcome: "any failure: ignore and alarm"},
		{section: "5.5", row: "3 right", outcome: "any failure: ignore and alarm"},
		{section: "5.5", row: "5 body", outcome: "a body that does not open or a mismatch alarms"},
		{section: "5.5", row: "6 kind", outcome: "ignore and alarm"},
	}
	for _, c := range cases {
		recordMdRequire(t, "section "+c.section+"'s "+c.row+" step", doc.row(t, c.section, c.row), c.outcome)
	}
	recordMdRequire(t, "section 5.4's order row", doc.row(t, "5.4", "order"), "no outcome holding the ref back")
}

// Finding: D-RECORD-2 said section 5.1 names every hashed value, and three had no bytes.
func TestRecordMdHashedValuesAreAllNamed(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "5.1")
	recordMdRequire(t, "section 5.1", section,
		"hook_event entry of event ur-tty-confirm",
		"namespace urnetwork-sidecar-attestation",
		`"urnetwork-sidecar-v1/model-weights"`,
	)
	if sshsig := doc.field(t, "AttestationBody", "sshsig"); !strings.Contains(sshsig.comment, "section 5.1") {
		t.Errorf("AttestationBody.sshsig does not point at section 5.1: %q", sshsig.comment)
	}
	recordMdRequire(t, "section 11's ssh step", doc.row(t, "11", "7 ssh"), "the approval's or the attestation's")
	recordMdRequire(t, "section 12's measured row", doc.row(t, "12", "evidence"), "section 5.1's weights_digest")

	// Every hash and signature field this document declares has its bytes named there.
	flat := recordMdFlat(section)
	for message, fields := range doc.messages(t) {
		for _, field := range fields {
			name := field.name
			if name == "sha256" {
				name = message + ".sha256"
			} else if !strings.HasSuffix(name, "_sha256") && name != "sshsig" {
				continue
			}
			if !strings.Contains(flat, name) {
				t.Errorf("section 5.1 does not name %s.%s", message, field.name)
			}
		}
	}
}

// Recomputes section 20's vectors, so a value quoted there cannot drift from section 5.1's bytes.
func TestRecordMdVectorsRecompute(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "20")
	u16 := func(value int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(value)) }
	u32 := func(value int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(value)) }
	repeated := func(value byte, count int) []byte { return bytes.Repeat([]byte{value}, count) }
	leaf := func(body string) []byte {
		sum := sha256.Sum256(append([]byte{0x00}, body...))
		return sum[:]
	}
	node := func(left []byte, right []byte) []byte {
		sum := sha256.Sum256(bytes.Join([][]byte{{0x01}, left, right}, nil))
		return sum[:]
	}
	commitment := sha256.Sum256(bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/record-body"),
		repeated(0x11, 32),
		{0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
	}, nil))
	rootTwo := node(leaf("h0"), leaf("h1"))
	rootThree := node(rootTwo, leaf("h2"))
	toolId := []byte("toolu_01")
	action := sha256.Sum256(bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/action-tool"),
		repeated(0x77, 16),
		u16(len(toolId)),
		toolId,
	}, nil))
	approval := bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/approval-sshsig"),
		{0x00},
		u16(16),
		repeated(0x22, 16),
		repeated(0x33, 32),
		repeated(0x44, 32),
		u32(1),
		u32(1),
		binary.BigEndian.AppendUint64(nil, 1762387200000),
		u16(16),
		repeated(0x55, 16),
		u16(16),
		repeated(0x66, 16),
	}, nil)
	oids := [][]byte{bytes.Repeat([]byte("1"), 40), bytes.Repeat([]byte("2"), 40)}
	attestation := bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/attestation-sshsig"),
		{0x00},
		u32(1),
		u16(len(oids)),
		u16(len(oids[0])),
		oids[0],
		u16(len(oids[1])),
		oids[1],
		u16(16),
		repeated(0x66, 16),
	}, nil)
	weights := sha256.Sum256(bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/model-weights"),
		{0x00},
		u32(2),
		u16(5),
		[]byte("a.bin"),
		repeated(0x11, 32),
		u16(7),
		[]byte("b/c.bin"),
		repeated(0x22, 32),
	}, nil))
	approvalSum := sha256.Sum256(approval)
	attestationSum := sha256.Sum256(attestation)
	wants := []string{
		hex.EncodeToString(commitment[:]),
		hex.EncodeToString(leaf("h0")),
		hex.EncodeToString(leaf("h1")),
		hex.EncodeToString(leaf("h2")),
		hex.EncodeToString(rootTwo),
		hex.EncodeToString(rootThree),
		base64.StdEncoding.EncodeToString(rootThree),
		hex.EncodeToString(action[:]),
		fmt.Sprintf("%d bytes, SHA-256 %x", len(approval), approvalSum),
		fmt.Sprintf("%d bytes, SHA-256 %x", len(attestation), attestationSum),
		hex.EncodeToString(weights[:]),
	}
	recordMdRequire(t, "section 20's vectors", section, wants...)

	// The formulas above are the document's, or a value here could drift from the bytes section 5.1 states.
	recordMdRequire(t, "section 5.1", doc.section(t, "5.1"),
		`SHA-256(0x00 || E.header.body)`,
		`SHA-256("urnetwork-sidecar-v1/record-body" || salt || body)`,
		`"urnetwork-sidecar-v1/approval-sshsig" || 0x00 || u16be(len) || approval_id || request_sha256 || payload_sha256 || u32be(decision) || u32be(uses) || i64be(not_after_millis) || u16be(len) || requester_sidecar_id || u16be(len) || approver_member_id`,
		`"urnetwork-sidecar-v1/attestation-sshsig" || 0x00 || u32be(statement) || u16be(count) || each commit's oid in hex, in order, u16be(len) || oid || u16be(len) || member_id`,
		`SHA-256("urnetwork-sidecar-v1/model-weights" || 0x00 || u32be(file count) || per file, by path bytes: u16be(len) || path || the file's SHA-256)`,
	)
	recordMdRequire(t, "section 4.4", doc.section(t, "4.4"), `SHA-256("urnetwork-sidecar-v1/action-tool" || run_id || u16be(len(tool_use_id)) || tool_use_id)`)
	recordMdRequire(t, "section 10.1", doc.section(t, "10.1"), `node SHA-256(0x01 || left || right)`)
}

// Finding: the head and the journal were two durable writes with no order, so a crash left a gap or a reused seq and
// a false tamper alarm.
func TestRecordMdWriterCrashRaisesNoAlarm(t *testing.T) {
	doc := newRecordMd(t)
	journal := doc.row(t, "5.3", "journal")
	// Crash at each point; the writer's next seq after restart must follow what readers can see.
	atomic := strings.Contains(journal, "one fsynced append holds the signed entry and its head")
	cases := []struct {
		point     string
		headMoved bool
		entryKept bool
		nextSeq   uint64
	}{
		{point: "before the append", headMoved: false, entryKept: false, nextSeq: 5},
		{point: "after the append", headMoved: true, entryKept: true, nextSeq: 6},
		// Two separate writes could leave either of these, the failures the review named.
		{point: "between a head write and a journal write", headMoved: true, entryKept: false, nextSeq: 5},
		{point: "between a journal write and a head write", headMoved: false, entryKept: true, nextSeq: 6},
	}
	for _, c := range cases {
		if atomic && c.headMoved != c.entryKept {
			continue
		}
		nextSeq := uint64(5)
		if c.headMoved {
			nextSeq = 6
		}
		if nextSeq != c.nextSeq {
			t.Errorf("a crash %s leaves next seq %d, want %d", c.point, nextSeq, c.nextSeq)
		}
	}
	recordMdRequire(t, "section 5.3's restart row", doc.row(t, "5.3", "restart"), "every writer first replays its journal")
	recordMdForbid(t, "section 5.3's chain row", doc.row(t, "5.3", "chain"), "fsynced before a signed entry leaves")
}

// Finding: two reader signals fired in normal operation, skew on nearly every T entry and gaps while two ingesters'
// pushes crossed.
func TestRecordMdNormalOperationRaisesNoSignal(t *testing.T) {
	doc := newRecordMd(t)
	row := doc.row(t, "5.3", "time")
	// An entry captured an hour before an ingester's push, and one stamped an hour past it.
	onlyAfter := strings.Contains(row, "a reader shows as skewed only a time over 10 min after the time_ms of the push carrying it")
	skewed := func(captureMs int64, pushMs int64) bool {
		const toleranceMs = 10 * 60 * 1000
		if onlyAfter {
			return captureMs-pushMs > toleranceMs
		}
		return captureMs-pushMs > toleranceMs || pushMs-captureMs > toleranceMs
	}
	const hourMs = 60 * 60 * 1000
	if skewed(0, hourMs) {
		t.Errorf("a deposit waiting an hour for ingest reads as skewed")
	}
	if !skewed(2*hourMs, hourMs) {
		t.Errorf("a time an hour past its push does not read as skewed")
	}
	chain := doc.row(t, "5.5", "4 chain")
	recordMdRequire(t, "section 5.5's chain step", chain, "from a writer that deposits held open and alarmed only past ChainGapTimeout (1 h)", "from a writer with no deposit ref on this log")

	// An entry captured before a batch closed and ingested after it sits past that frontier, and waits for the next
	// batch. A rule by time would alarm on every such deposit.
	monitor := doc.row(t, "10.2", "monitor")
	byTime := strings.Contains(monitor, "entry older than a frontier")
	entryPush, frontierVersion := uint64(9), uint64(7)
	entryMs, frontierMs := int64(500), int64(1000)
	alarmed := entryPush <= frontierVersion
	if byTime {
		alarmed = entryMs < frontierMs
	}
	if alarmed {
		t.Errorf("a deposit ingested after a batch closed alarms as missing from the tree")
	}
	recordMdRequire(t, "section 10.2's monitor row", monitor, "an entry at or below a frontier's version of its stream and not in the tree alarms too")
}

// Finding: two checks could not be evaluated after GC, so routine expiry raised alarms.
func TestRecordMdChecksHoldAfterExpiry(t *testing.T) {
	doc := newRecordMd(t)
	recordMdForbid(t, "section 5.5", doc.section(t, "5.5"), "each lies past its class's keep_days")
	expired := doc.row(t, "5.5", "expired")
	recordMdRequire(t, "section 5.5's expired row", expired,
		"where n equals seq, they removed those seqs' own paths",
		"in an ingested stream, where paths do not map to seqs",
		"any other gap stands",
		"only a reader that held the entry can test its class's keep_days",
	)
	monitor := doc.row(t, "10.2", "monitor")
	recordMdRequire(t, "section 10.2's monitor row", monitor, "for the entries it still holds", "a leaf no held entry backs is no miss")
	recordMdForbid(t, "section 10.2's monitor row", monitor, "for streams it reads, its own derivation gives the same leaves")
}

// Finding: ur record cost summed every cost entry, counting a re-opened run twice. A seq counts one (log, writer)
// chain, so a run's entries in two logs are no ladder to climb either.
func TestRecordMdCostCountsARunOnce(t *testing.T) {
	doc := newRecordMd(t)
	section := recordMdFlat(doc.section(t, "13.1"))
	type entry struct {
		log   string
		runId string
		seq   uint64
		total uint64
	}
	// Whole-run totals: the second entry follows a re-open and restates the first, and the last, once Q-RECORD-6 lets
	// cost past V, is the same run in T, where its chain stands at a lower seq.
	entries := []entry{
		{log: "V", runId: "a", seq: 11, total: 100},
		{log: "V", runId: "a", seq: 12, total: 150},
		{log: "V", runId: "b", seq: 13, total: 10},
		{log: "T", runId: "a", seq: 2, total: 150},
	}
	onlyNewest := strings.Contains(section, "sums, per run, only the newest `cost` entry by seq")
	oneLog := strings.Contains(section, "reads one log, the vault by default")
	sum := uint64(0)
	logRunNewests := map[string]entry{}
	for _, e := range entries {
		if oneLog && e.log != "V" {
			continue
		}
		key := e.log + "/" + e.runId
		if !onlyNewest {
			sum += e.total
		} else if held, found := logRunNewests[key]; !found || e.seq > held.seq {
			logRunNewests[key] = e
		}
	}
	for _, e := range logRunNewests {
		sum += e.total
	}
	if sum != 160 {
		t.Errorf("ur record cost reports %d, want 160", sum)
	}
}

// Finding: inventory was Personal none and M6, though §16.8 sends every kind to the vault in a personal network and
// P5:893 puts run inventory in the first release.
func TestRecordMdInventoryReachesPersonalNetworks(t *testing.T) {
	doc := newRecordMd(t)
	kinds := doc.registry(t)
	if kind := kinds["inventory"]; kind.personal != "V" || !strings.HasPrefix(kind.since, "M3") {
		t.Errorf("inventory is Personal %q since %q", kind.personal, kind.since)
	}
	recordMdRequire(t, "section 20's M3 row", doc.row(t, "20", "M3"), "32-37")
	// Each remaining none has a reason.
	allowed := map[string]bool{
		"announce": true, "request": true, "decision": true, "erasure_request": true,
		"copy": true, "log_settings": true, "checkpoint": true, "ledger_scope": true,
	}
	for _, kind := range kinds {
		if kind.personal == "none" && !allowed[kind.name] {
			t.Errorf("kind %s is Personal none with no reason in section 6.3", kind.name)
		}
	}
	recordMdRequire(t, "section 6.3", doc.section(t, "6.3"), "Personal `none` marks a kind no personal network can hold")
}

// Finding: the 1 MiB deposit cap could not hold bodies the document allows.
func TestRecordMdDepositCarriesEveryBody(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "5.4")
	alone := strings.Contains(recordMdFlat(section), "an entry that would pass 1 MiB goes alone in a batch of its own")
	const batchByteCount = 1024 * 1024
	const envelopeByteCount = 1024
	bodyByteCounts := map[string]int{"a blob": 8 * 1024 * 1024, "a tool body": 1024 * 1024, "a transcript chunk": 1024 * 1024}
	for name, byteCount := range bodyByteCounts {
		if byteCount+envelopeByteCount > batchByteCount && !alone {
			t.Errorf("%s of %d B has no way into a deposit", name, byteCount)
		}
	}
	if batch := doc.messages(t)["RecordDepositBatch"]; len(batch) != 1 {
		t.Errorf("RecordDepositBatch holds %d fields", len(batch))
	}
	recordMdRequire(t, "section 18", doc.section(t, "18"), "1 MiB a deposit batch")
}

// Finding: source and evidence labels overstated what happened.
func TestRecordMdSourceLabelsMatchTheAct(t *testing.T) {
	doc := newRecordMd(t)
	kinds := doc.registry(t)
	recordMdRequire(t, "disclosure's source", kinds["disclosure"].source, "observed for an unconfirmed plain export")
	recordMdRequire(t, "request's source", kinds["request"].source, "approver for `filed_by` 1")
	recordMdRequire(t, "announce's source", kinds["announce"].source, "approver for a repo item a person's confirmed command signed")
	recordMdRequire(t, "hook_event's source", kinds["hook_event"].source, "observed for `ur-tty-confirm`")
	recordMdRequire(t, "section 12's evidence row", doc.row(t, "12", "evidence"), "confirmed on /dev/tty or in an app's UI")
}

// Finding: T's projection departed from §16.7 both ways, undeclared: base names kept, file hashes dropped.
func TestRecordMdProjectionMatchesTheIngestedTable(t *testing.T) {
	doc := newRecordMd(t)
	cases := []struct {
		message   string
		field     string
		vaultOnly bool
	}{
		{message: "ContextBody", field: "truncations", vaultOnly: true},
		{message: "InstructionFile", field: "name", vaultOnly: true},
		{message: "InstructionFile", field: "sha256", vaultOnly: false},
		{message: "ChangedPath", field: "path", vaultOnly: true},
		{message: "ChangedPath", field: "blob_entry_id", vaultOnly: true},
		{message: "ChangedPath", field: "before_sha256", vaultOnly: false},
		{message: "ChangedPath", field: "after_sha256", vaultOnly: false},
		{message: "ChangeBody", field: "paths", vaultOnly: false},
		{message: "ContextBody", field: "title", vaultOnly: true},
	}
	for _, c := range cases {
		field := doc.field(t, c.message, c.field)
		if strings.HasPrefix(field.comment, "V:") != c.vaultOnly {
			t.Errorf("%s.%s has comment %q, want V: mark %v", c.message, c.field, field.comment, c.vaultOnly)
		}
	}
	recordMdForbid(t, "section 7.2", doc.section(t, "7.2"), "each instruction file's name")

	// Keeping hashes in T grows a change entry, and section 13.2's bytes rest on its size.
	hash := make([]byte, 32)
	row := recordMdAppendBytes(nil, 2, hash)
	row = recordMdAppendBytes(row, 3, hash)
	row = recordMdAppendVarint(row, 4, 0o100644)
	row = recordMdAppendVarint(row, 5, 3)
	if byteCount := len(recordMdAppendBytes(nil, 10, row)); 80 < byteCount {
		t.Errorf("a ChangedPath row in T is %d B, past section 13.2's 80 B a path", byteCount)
	}
	recordMdRequire(t, "section 13.2", doc.section(t, "13.2"), "at about 80 B a path")
	section := doc.section(t, "16.2")
	recordMdRequire(t, "section 16.2", section, "§16.7's \"instruction files by hash\" and \"a `change` entry with hashes\" bind T's projection", "flag bit 0 is the header's `tainted`")
}

// Finding: membership and key bodies invented names §5.4 does not hold, and some of its kinds had no number.
func TestRecordMdMembershipEventsAreSectionFiveNames(t *testing.T) {
	doc := newRecordMd(t)
	event := doc.field(t, "MembershipBody", "event")
	for _, name := range []string{"member_added", "member_removed", "admission_alarm", "recovery_rebind", "recovery_window", "recovery_unseen"} {
		if !strings.Contains(event.comment, name) {
			t.Errorf("MembershipBody.event has no number for %s: %q", name, event.comment)
		}
	}
	if key := doc.field(t, "KeyBody", "event"); !strings.Contains(key.comment, "key_changed") {
		t.Errorf("KeyBody.event does not name key_changed: %q", key.comment)
	}
	doc.field(t, "MembershipBody", "signed_type")
	doc.field(t, "KeyBody", "signed_type")
	recordMdForbid(t, "RECORD.md", doc.text, "sidecar_admitted", "sidecar_revoked", "owner_confirmed", "generation_rotated", "key_registered", "key_revoked", "recovery_changed")
}

// Findings: no IP appears was false with --bodies; a line does not verify alone; a plain export was not header-only.
func TestRecordMdExportClaimsHold(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "9")
	recordMdForbid(t, "section 9", section, "No IP address appears", "verify a line with no other file")
	recordMdRequire(t, "section 9", section,
		"so neither `ocsf` nor `otel` carries an IP address the record holds",
		"verify a line given its writer's public key",
		"`salt`, `body`, `fields` and `agent_label`",
	)
	// Every field that can hold an address goes, not only the two with the word in their comments: an action's host
	// and cidrs ride canonical_action, and any tool's output can quote one.
	_, unmapped, found := strings.Cut(recordMdFlat(section), "`unmapped` carries")
	if !found {
		t.Fatal("section 9 does not say what unmapped carries")
	}
	unmapped, _, _ = strings.Cut(unmapped, "(I-13)")
	_, left, found := strings.Cut(unmapped, "never ")
	if !found {
		t.Fatalf("unmapped's row leaves nothing out: %q", unmapped)
	}
	for _, name := range []string{"prose", "captured bytes", "`canonical_action`", "`relays`", "`cidrs`"} {
		if !strings.Contains(left, name) {
			t.Errorf("unmapped does not leave out %s: %q", name, left)
		}
	}
	recordMdRequire(t, "section 9's unmapped row", unmapped, "`otel`'s `recurd.*` attributes are the same set")
	recordMdRequire(t, "section 9's confirm row", doc.row(t, "9", "confirm"), "--bodies, --format ocsf and --format otel, which carry body data, and --follow")
	tests := doc.section(t, "20")
	recordMdForbid(t, "section 20", tests, "no IP appears in any format", "a line verifies from itself")
	recordMdRequire(t, "section 20", tests, "a fixture's relay, route and action addresses appear in neither `ocsf`, `otel` nor a plain `jsonl`")
}

// Finding: section 18's settings renamed the fields settings_mcp.go holds, dropped three, and left tunables with no
// field, and a doc comment repeated its type's name.
func TestRecordMdSettingsExtendTheBranchStruct(t *testing.T) {
	doc := newRecordMd(t)
	file := doc.goFile(t)
	declared := map[string]string{}
	for _, field := range recordMdStruct(t, file, "SidecarRecordSettings").Fields.List {
		typeName := ""
		switch fieldType := field.Type.(type) {
		case *ast.Ident:
			typeName = fieldType.Name
		case *ast.SelectorExpr:
			typeName = fieldType.X.(*ast.Ident).Name + "." + fieldType.Sel.Name
		}
		for _, name := range field.Names {
			declared[name.Name] = typeName
		}
	}
	settings := reflect.TypeOf(SidecarRecordSettings{})
	for i := 0; i < settings.NumField(); i++ {
		field := settings.Field(i)
		if declared[field.Name] != field.Type.String() {
			t.Errorf("section 18 declares %s as %q, and settings_mcp.go as %s", field.Name, declared[field.Name], field.Type)
		}
	}
	for _, name := range []string{"ExpiryDelay", "WitnessFreshInterval", "WitnessMissCount", "TimeSkewTimeout", "ChainGapTimeout"} {
		if declared[name] == "" {
			t.Errorf("section 18 has no field for %s", name)
		}
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			name := spec.(*ast.TypeSpec).Name.Name
			if general.Doc == nil {
				t.Errorf("section 18's %s has no doc comment", name)
			} else if strings.HasPrefix(general.Doc.Text(), name) {
				t.Errorf("the doc comment on %s repeats its name", name)
			}
		}
	}
}

// Finding: the T floor refused keep_days 0 and searchable_days 0, which section 8 defines as the longest retention.
func TestRecordMdFloorAcceptsKeepForever(t *testing.T) {
	doc := newRecordMd(t)
	row := doc.row(t, "8", "floor")
	match := regexp.MustCompile(`a keep_days of (\d+) to (\d+) or a searchable_days of (\d+) to (\d+) is refused`).FindStringSubmatch(row)
	if match == nil {
		t.Fatalf("section 8's floor row states no refused range: %q", row)
	}
	keepLow, keepHigh := recordMdNumber(t, match[1]), recordMdNumber(t, match[2])
	searchableLow, searchableHigh := recordMdNumber(t, match[3]), recordMdNumber(t, match[4])
	cases := []struct {
		keepDays       int64
		searchableDays int64
		refused        bool
	}{
		{keepDays: 0, searchableDays: 0, refused: false},
		{keepDays: 400, searchableDays: 90, refused: false},
		{keepDays: 365, searchableDays: 0, refused: false},
		{keepDays: 364, searchableDays: 90, refused: true},
		{keepDays: 1, searchableDays: 90, refused: true},
		{keepDays: 400, searchableDays: 89, refused: true},
		{keepDays: 0, searchableDays: 1, refused: true},
	}
	for _, c := range cases {
		refused := (keepLow <= c.keepDays && c.keepDays <= keepHigh) || (searchableLow <= c.searchableDays && c.searchableDays <= searchableHigh)
		if refused != c.refused {
			t.Errorf("keep_days %d, searchable_days %d: refused %v, want %v", c.keepDays, c.searchableDays, refused, c.refused)
		}
	}

	// Keeping entries forever must not cap how long they stay searchable at zero days.
	searchable := doc.row(t, "8", "searchable")
	bounded := strings.Contains(searchable, "at most keep_days")
	exempt := strings.Contains(searchable, "where keep_days is not 0")
	keepDays, searchableDays := int64(0), int64(90)
	if bounded && !exempt && keepDays < searchableDays {
		t.Errorf("keep_days %d, which keeps entries forever, refuses searchable_days %d", keepDays, searchableDays)
	}
}

// Finding: "a RepoCreate and no later RepoDelete" left a restored repo not live for good.
func TestRecordMdRestoredRepoIsLive(t *testing.T) {
	doc := newRecordMd(t)
	row := doc.row(t, "4.2", "team mode")
	recordMdForbid(t, "section 4.2's team mode row", row, "a RepoCreate and no later RepoDelete")
	recordMdRequire(t, "section 4.2's team mode row", row, "a RepoRestore of that deletion_id follows")
}

// Finding: section 8 reads archived entries with a filter section 5.6 did not have.
func TestRecordMdRecordQueryReadsArchived(t *testing.T) {
	doc := newRecordMd(t)
	recordMdRequire(t, "section 8's archive row", doc.row(t, "8", "archive"), "with archived true")
	recordMdRequire(t, "section 5.6", doc.section(t, "5.6"), "untrusted?, archived?, cursor?) -> rows", "archived true adds archived entries")
}

// Finding beside the review's: section 3 said no record.proto exists, which stopped being true when it landed.
func TestRecordMdStatesWhatIsBuilt(t *testing.T) {
	doc := newRecordMd(t)
	section := doc.section(t, "3")
	if _, err := os.Stat("protocol/record.proto"); err != nil {
		t.Fatal(err)
	}
	recordMdForbid(t, "section 3", section, "no `record.proto`")
	recordMdRequire(t, "section 3", section, "`protocol/record.proto` holds §16.8's messages")
}

// Every section the document cites is one it holds, and every § and id it takes from DESIGN.md is there, so a
// renumbering here or a renamed item there leaves no rule pointing at nothing.
func TestRecordMdReferencesResolve(t *testing.T) {
	doc := newRecordMd(t)
	flat := recordMdFlat(doc.text)
	headings := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^#{2,3} (\d+(?:\.\d+)?)[. ]`).FindAllStringSubmatch(doc.text, -1) {
		headings[match[1]] = true
	}
	separator := regexp.MustCompile(`, | and |-`)
	for _, match := range regexp.MustCompile(`\b[Ss]ections? ((?:\d+(?:\.\d+)?(?:, | and |-)?)+)`).FindAllStringSubmatch(flat, -1) {
		for _, number := range separator.Split(match[1], -1) {
			if number != "" && !headings[number] {
				t.Errorf("RECORD.md cites section %s in %q, and holds none", number, match[0])
			}
		}
	}

	// a release branch keeps DESIGN.md at the repository's top, beside the module moved into v2026/
	design, err := os.ReadFile("DESIGN.md")
	if errors.Is(err, os.ErrNotExist) {
		design, err = os.ReadFile("../DESIGN.md")
	}
	if err != nil {
		t.Fatal(err)
	}
	designHeadings := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^#{2,4} (\d+(?:\.\d+)?)[. ]`).FindAllSubmatch(design, -1) {
		designHeadings[string(match[1])] = true
	}
	for _, match := range regexp.MustCompile(`(RFC \d+ )?§(\d+(?:\.\d+)?)`).FindAllStringSubmatch(flat, -1) {
		if match[1] == "" && !designHeadings[match[2]] {
			t.Errorf("RECORD.md cites §%s, and DESIGN.md holds none", match[2])
		}
	}
	idPattern := regexp.MustCompile(`\b(?:[DRQ]-[A-Z0-9]+-\d+|FS-\d+|FI-\d+|I-\d+|evs-\d+)\b`)
	designIds := map[string]bool{}
	for _, id := range idPattern.FindAll(design, -1) {
		designIds[string(id)] = true
	}
	for _, id := range idPattern.FindAllString(flat, -1) {
		if strings.Contains(id, "-RECORD-") {
			continue
		}
		if !designIds[id] {
			t.Errorf("RECORD.md cites %s, and DESIGN.md holds none", id)
		}
	}

	// Its own ids are defined where each kind of id lives.
	definitions := map[string]string{
		"R": `| %s |`,
		"D": `**%s (proposed).**`,
		"Q": `**%s.**`,
	}
	for _, id := range regexp.MustCompile(`\b[DRQ]-RECORD-\d+\b`).FindAllString(flat, -1) {
		if !strings.Contains(flat, fmt.Sprintf(definitions[id[:1]], id)) {
			t.Errorf("RECORD.md cites %s, and defines none", id)
		}
	}
}

// Sections 6.3, 7.2 and 8 each list the kinds, so a kind added to one and missed in another is a kind with no
// class, or a search text nobody wrote.
func TestRecordMdRegistryHoldsTogether(t *testing.T) {
	doc := newRecordMd(t)
	kinds := doc.registry(t)
	numberNames := map[int]string{}
	for _, kind := range kinds {
		if held, found := numberNames[kind.number]; found {
			t.Errorf("kinds %s and %s share number %d", held, kind.name, kind.number)
		}
		numberNames[kind.number] = kind.name
		block := (kind.number >= 1 && kind.number <= 15 && (kind.class == "coordination" || kind.class == "announce" || kind.class == "request")) ||
			(kind.number >= 16 && kind.number <= 47 && (kind.class == "action" || kind.class == "accounting" || kind.class == "log")) ||
			(kind.number >= 48 && kind.number <= 63 && kind.class == "capture")
		if !block {
			t.Errorf("kind %s at %d sits outside section 6.1's block for class %s", kind.name, kind.number, kind.class)
		}
	}

	// Section 8's class rows name each kind, and agree with section 6.3's column.
	classRow := regexp.MustCompile(`^(?:class)? +\d ([a-z]+) +(.*)$`)
	kindClasses := map[string]string{}
	class := ""
	for _, line := range strings.Split(doc.section(t, "8"), "\n") {
		text := ""
		if match := classRow.FindStringSubmatch(line); match != nil {
			class, text = match[1], match[2]
		} else if class != "" && strings.HasPrefix(line, strings.Repeat(" ", 31)) {
			text = strings.TrimSpace(line)
		} else {
			class = ""
			continue
		}
		listed, _, ended := strings.Cut(text, ":")
		if !ended {
			listed, _, ended = strings.Cut(text, "(")
		}
		for _, name := range strings.Split(listed, ",") {
			name = strings.TrimSpace(name)
			if name == "the approval family" {
				for _, member := range []string{"approval", "approval_decision", "approval_cancel", "approval_use"} {
					kindClasses[member] = class
				}
			} else if name != "" {
				kindClasses[name] = class
			}
		}
		if ended {
			class = ""
		}
	}
	for _, kind := range kinds {
		if kindClasses[kind.name] != kind.class {
			t.Errorf("kind %s is class %q in section 6.3 and %q in section 8", kind.name, kind.class, kindClasses[kind.name])
		}
	}
	for name := range kindClasses {
		if _, found := kinds[name]; !found {
			t.Errorf("section 8 classes %s, which section 6.3 does not hold", name)
		}
	}

	// Section 7.2 gives each kind its text, but those section 7.1 never indexes.
	indexed := map[string]bool{}
	for _, line := range strings.Split(doc.section(t, "7.2"), "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if len(cells) != 4 {
			continue
		}
		for _, match := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(cells[0], -1) {
			indexed[match[1]] = true
		}
	}
	for _, kind := range kinds {
		never := kind.class == "capture" || kind.class == "log" || kind.name == "copy"
		if indexed[kind.name] == never {
			t.Errorf("kind %s: section 7.2 lists it %v, and section 7.1 never indexes it %v", kind.name, indexed[kind.name], never)
		}
	}
}
