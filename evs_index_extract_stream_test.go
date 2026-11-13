//go:build !ios_extension

// Extraction in one pass (SEARCH-M10-44; DESIGN-DETAILS 11.2.8, 11.3's R4 and 11.4): every conformance vector written
// to the stream in one piece, byte by byte and in seeded random pieces gives the whole-value form's documents, key
// sets and rows; files read in blocks of every small size likewise; generated messages of nested multiparts, every
// transfer encoding, charsets, HTML and line breaks, cut at random, and texts across many small chunks, the same; and
// a 50 MiB message in each of 11.4's shapes holds the heap within 256 KiB of the normalizer's own at every document.

package sidecar

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The whole-value form's documents of content at path, as one pass hands them: chunk, key set and row, or skipped.
// False for a binary file.
func testIndexWholeDocuments(t testing.TB, mail bool, path []byte, content []byte, settings *IndexFormatSettings) ([]*indexStreamDocument, bool) {
	t.Helper()
	var documents []*IndexDocument
	if mail {
		documents = indexExtractMail(path, content, settings)
	} else {
		var ok bool
		if documents, ok = indexExtractFile(path, content, settings); !ok {
			return nil, false
		}
	}
	normalizer := testIndexNormalizer(t)
	whole := []*indexStreamDocument{}
	for _, document := range documents {
		prepared, err := document.prepare(normalizer, false, Id{}, settings)
		if err != nil {
			t.Fatal(err)
		}
		whole = append(whole, &indexStreamDocument{chunk: document.Chunk, keys: prepared.keys, row: prepared.row, skipped: prepared.skipped})
	}
	return whole, true
}

// The stream's args for content of byteCount bytes at path, appending each document it finishes to documents.
func testIndexStreamArgs(t testing.TB, mail bool, path []byte, byteCount int, settings *IndexFormatSettings, documents *[]*indexStreamDocument) *indexStreamArgs {
	t.Helper()
	kind := IndexDocFile
	if mail {
		kind = IndexDocMail
	}
	return &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: path},
		byteCount:  uint64(byteCount),
		normalizer: testIndexNormalizer(t),
		settings:   settings,
		emit: func(document *indexStreamDocument) error {
			*documents = append(*documents, document)
			return nil
		},
	}
}

// A message through the stream, written in the pieces cut gives: each call the length of the next piece.
func testIndexStreamMail(t testing.TB, path []byte, content []byte, settings *IndexFormatSettings, cut func(remaining int) int) []*indexStreamDocument {
	t.Helper()
	documents := []*indexStreamDocument{}
	stream := indexExtractMailStream(testIndexStreamArgs(t, true, path, len(content), settings, &documents))
	for rest := content; 0 < len(rest); {
		piece := max(1, min(len(rest), cut(len(rest))))
		if _, err := stream.Write(rest[:piece]); err != nil {
			t.Fatal(err)
		}
		rest = rest[piece:]
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	return documents
}

// A file through the stream, read in blocks of ExtractReadByteCount.
func testIndexStreamFile(t testing.TB, path []byte, content []byte, settings *IndexFormatSettings) ([]*indexStreamDocument, bool) {
	t.Helper()
	documents := []*indexStreamDocument{}
	ok, err := indexExtractFileStream(testIndexStreamArgs(t, false, path, len(content), settings, &documents), bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	return documents, ok
}

// Every difference between two forms' documents, empty when there is none.
func testIndexStreamDifferences(t testing.TB, whole []*indexStreamDocument, stream []*indexStreamDocument) []string {
	t.Helper()
	differences := []string{}
	if len(whole) != len(stream) {
		return append(differences, fmt.Sprintf("%d documents, whole %d", len(stream), len(whole)))
	}
	for index := range whole {
		want, got := whole[index], stream[index]
		if want.chunk != got.chunk || want.skipped != got.skipped {
			differences = append(differences, fmt.Sprintf("document %d: chunk %d skipped %v, whole %d %v", index, got.chunk, got.skipped, want.chunk, want.skipped))
			continue
		}
		if want.skipped {
			continue
		}
		if !slices.Equal(want.keys, got.keys) {
			differences = append(differences, fmt.Sprintf("document %d: %d keys, whole %d", index, len(got.keys), len(want.keys)))
		}
		wantRow, err := want.row.appendEncoded(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		gotRow, err := got.row.appendEncoded(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantRow, gotRow) {
			differences = append(differences, fmt.Sprintf("document %d: row %+v, whole %+v", index, got.row, want.row))
		}
	}
	return differences
}

// The cuts a test writes a message in: whole, byte by byte, and seeded random pieces of up to 1, 7 and 300 bytes.
func testIndexStreamCuts(seed int64) map[string]func(remaining int) int {
	random := rand.New(rand.NewSource(seed))
	return map[string]func(remaining int) int{
		"whole":       func(remaining int) int { return remaining },
		"bytes":       func(remaining int) int { return 1 },
		"small":       func(remaining int) int { return 1 + random.Intn(7) },
		"medium":      func(remaining int) int { return 1 + random.Intn(300) },
		"around-1024": func(remaining int) int { return 1000 + random.Intn(50) },
	}
}

// Every message of mail.json, in one piece, byte by byte and in random pieces: the whole-value form's documents.
func TestIndexStreamConformanceMail(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	for index, vector := range testConformanceVectors(t, testConformanceMailPath, indexExtractorId) {
		path, input := vector.pathAndInput(t)
		whole, _ := testIndexWholeDocuments(t, true, path, input, settings)
		for name, cut := range testIndexStreamCuts(int64(index)) {
			if name == "bytes" && 256*1024 < len(input) {
				continue
			}
			for _, difference := range testIndexStreamDifferences(t, whole, testIndexStreamMail(t, path, input, settings, cut)) {
				t.Errorf("%s (%s), %s: %s", vector.Name, vector.Rule, name, difference)
			}
		}
	}
}

// Every file of file.json read in blocks of 1, 2, 3, 5 and 7 bytes and of the default: the whole-value form's
// documents, and no document of a binary.
func TestIndexStreamConformanceFile(t *testing.T) {
	for _, vector := range testConformanceVectors(t, testConformanceFilePath, indexExtractorId) {
		path, input := vector.pathAndInput(t)
		for _, readByteCount := range []int{1, 2, 3, 5, 7, DefaultIndexFormatSettings().ExtractReadByteCount} {
			settings := DefaultIndexFormatSettings()
			settings.ExtractReadByteCount = readByteCount
			whole, wholeOk := testIndexWholeDocuments(t, false, path, input, settings)
			stream, streamOk := testIndexStreamFile(t, path, input, settings)
			if wholeOk != streamOk {
				t.Errorf("%s, blocks of %d: text %v, whole %v", vector.Name, readByteCount, streamOk, wholeOk)
				continue
			}
			for _, difference := range testIndexStreamDifferences(t, whole, stream) {
				t.Errorf("%s (%s), blocks of %d: %s", vector.Name, vector.Rule, readByteCount, difference)
			}
		}
	}
}

// A random message: nested multiparts whose boundaries and lines sit near the line window, delimiters of outer parts
// inside inner ones, every transfer encoding with soft line breaks and broken groups, charsets, HTML with tags,
// comments, scripts and references cut anywhere, CR LF and bare LF, and headers folded, repeated and past HeaderMax.
func testIndexGeneratedMail(random *rand.Rand, settings *IndexFormatSettings) []byte {
	message := &bytes.Buffer{}
	newline := func() string {
		return []string{"\n", "\r\n", "\r\r\n"}[random.Intn(3)]
	}
	words := []string{"alpha", "Beta", "gamma", "δέλτα", "日本語", "x", "", " ", "\t", "=", "==", "=3D", "=\r\n", "= \n", "&amp;", "&ampx", "&#65", "&#x;", "&notit;", "&", "<p>", "</div>", "<!-- c -->", "<!--", "-->", "<script>s</script>", "<style>", "</style >", "<a href='>'>", "<", ">", "\"", "'", "\x00", "\xff", "\xe2\x82", "\xac"}
	text := func(count int) string {
		parts := []string{}
		for range count {
			parts = append(parts, words[random.Intn(len(words))])
		}
		return strings.Join(parts, []string{" ", "", newline()}[random.Intn(3)])
	}
	header := func(name string, value string) {
		message.WriteString(name + ":" + value + newline())
		if random.Intn(4) == 0 {
			message.WriteString(" " + text(3) + newline())
		}
	}
	var entity func(depth int, boundaries []string)
	entity = func(depth int, boundaries []string) {
		kind := random.Intn(6)
		if 3 < depth {
			kind = 1 + random.Intn(5)
		}
		switch kind {
		case 0:
			boundary := fmt.Sprintf("b%d%s", depth, strings.Repeat("x", random.Intn(4)*300))
			header("Content-Type", fmt.Sprintf(" multipart/%s; boundary=\"%s\"", []string{"mixed", "alternative", "digest"}[random.Intn(3)], boundary))
			if random.Intn(3) == 0 {
				header("Content-Type", " text/plain")
			}
			message.WriteString(newline())
			message.WriteString(text(random.Intn(4)) + newline())
			for range 1 + random.Intn(3) {
				message.WriteString("--" + boundary + []string{"", " ", "\t\r", strings.Repeat(" ", 1020)}[random.Intn(4)] + newline())
				entity(depth+1, append(boundaries, boundary))
				message.WriteString(newline())
			}
			switch random.Intn(4) {
			case 0:
				// no close delimiter
			case 1:
				if 0 < len(boundaries) {
					// an outer part's delimiter ends this one
					message.WriteString("--" + boundaries[random.Intn(len(boundaries))] + newline())
				}
			default:
				message.WriteString("--" + boundary + "--" + newline() + text(2) + newline())
			}
		default:
			mediaType := []string{"text/plain", "text/html", "application/pdf", "", "TEXT/HTML; charset=windows-1252", "text/plain; charset=iso-2022-jp", "text/plain; charset=koi8-r"}[random.Intn(7)]
			if mediaType != "" {
				header("Content-Type", " "+mediaType)
			}
			if random.Intn(3) == 0 {
				header("Content-Disposition", []string{" attachment; filename=a.txt", " inline; filename*0*=utf-8''n%C3%A9; filename*1=e.txt", " inline"}[random.Intn(3)])
			}
			encoding := []string{"", "base64", "quoted-printable", "7bit", " BASE64 "}[random.Intn(5)]
			if encoding != "" {
				header("Content-Transfer-Encoding", encoding)
			}
			if random.Intn(8) != 0 {
				message.WriteString(newline())
			}
			body := text(5 + random.Intn(40))
			switch strings.TrimSpace(strings.ToLower(encoding)) {
			case "base64":
				encoded := []byte{}
				const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				for range len(body) {
					encoded = append(encoded, alphabet[random.Intn(len(alphabet))])
					if random.Intn(60) == 0 {
						encoded = append(encoded, []byte(newline())...)
					}
				}
				if random.Intn(4) == 0 {
					encoded = append(encoded, '=')
				}
				body = string(encoded)
			case "quoted-printable":
				body = strings.ReplaceAll(body, "x", "="+strings.Repeat(" ", random.Intn(3)*600)+newline())
			}
			message.WriteString(body)
		}
	}
	header("Subject", " =?UTF-8?Q?a_b?= =?utf-8?B?w6k=?= "+text(3))
	header("From", " Ann <ann@example.com>")
	if random.Intn(3) == 0 {
		header("Subject", " "+strings.Repeat("s", settings.HeaderMaxByteCount+10))
	}
	header("To", " bob@example.com")
	header("Cc", " carol@example.com")
	entity(0, nil)
	return message.Bytes()
}

// Generated messages, each cut at random a few ways, and with small chunks so documents and their overlaps meet every
// stage: the whole-value form's documents.
func TestIndexStreamEqualsWholeOnGeneratedMail(t *testing.T) {
	for seed := range int64(300) {
		random := rand.New(rand.NewSource(seed))
		settings := DefaultIndexFormatSettings()
		if seed%2 == 1 {
			settings.ChunkByteCount = 16 + random.Intn(200)
			settings.OverlapByteCount = random.Intn(settings.ChunkByteCount)
		}
		content := testIndexGeneratedMail(random, settings)
		path := []byte(fmt.Sprintf("m/202611/%d", seed))
		whole, _ := testIndexWholeDocuments(t, true, path, content, settings)
		for name, cut := range testIndexStreamCuts(seed) {
			for _, difference := range testIndexStreamDifferences(t, whole, testIndexStreamMail(t, path, content, settings, cut)) {
				t.Errorf("seed %d, %s: %s", seed, name, difference)
			}
		}
	}
}

// Files of text across many small chunks, UTF-16 with cut surrogates and odd lengths, marks, and titles far in or past
// a block: the whole-value form's documents at every read size.
func TestIndexStreamEqualsWholeOnGeneratedFiles(t *testing.T) {
	for seed := range int64(200) {
		random := rand.New(rand.NewSource(seed))
		settings := DefaultIndexFormatSettings()
		settings.ChunkByteCount = 8 + random.Intn(100)
		settings.OverlapByteCount = random.Intn(settings.ChunkByteCount)
		settings.ExtractReadByteCount = 1 + random.Intn(20)
		content := []byte{}
		switch random.Intn(4) {
		case 0:
			content = append(content, 0xFE, 0xFF)
		case 1:
			content = append(content, 0xFF, 0xFE)
		case 2:
			content = append(content, 0xEF, 0xBB, 0xBF)
		}
		lines := []string{"", "###", "# ", "   ", "\t", "\r", "## Title of it  \t\r", "\xff\xfe", "\xe2\x82", "héllo wörld", strings.Repeat("y", 100), strings.Repeat("# ", 60) + "Late title", "\x00"}
		for range random.Intn(30) {
			content = append(content, lines[random.Intn(len(lines))]...)
			if random.Intn(4) != 0 {
				content = append(content, '\n')
			}
			if random.Intn(10) == 0 {
				content = append(content, byte(random.Intn(256)), byte(random.Intn(256)))
			}
		}
		path := []byte(fmt.Sprintf("notes/%d.md", seed))
		whole, wholeOk := testIndexWholeDocuments(t, false, path, content, settings)
		stream, streamOk := testIndexStreamFile(t, path, content, settings)
		if wholeOk != streamOk {
			t.Errorf("seed %d: text %v, whole %v", seed, streamOk, wholeOk)
			continue
		}
		for _, difference := range testIndexStreamDifferences(t, whole, stream) {
			t.Errorf("seed %d: %s", seed, difference)
		}
	}
}

// A message generated as it is written, never held: shape writes it to w in pieces.
type testIndexStreamShape struct {
	name  string
	write func(w io.Writer, byteCount int)
}

// 11.4's four shapes at 50 MiB: two quoted-printable alternatives; one base64 attachment; all one base64 text/plain
// part; and windows-1252 HTML whose every byte grows when decoded.
func testIndexStreamShapes() []testIndexStreamShape {
	repeat := func(w io.Writer, line []byte, byteCount int) {
		for written := 0; written < byteCount; written += len(line) {
			w.Write(line)
		}
	}
	// "Alpha " nine times, 72 alphabet bytes a line
	base64Line := []byte(strings.Repeat("QWxwaGEg", 9) + "\r\n")
	return []testIndexStreamShape{
		{name: "two quoted-printable alternatives", write: func(w io.Writer, byteCount int) {
			io.WriteString(w, "Subject: =?UTF-8?Q?numbers?=\r\nFrom: ann@example.com\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
			repeat(w, []byte("The quarterly numbers are in, caf=C3=A9 and all, with a soft line break here=\r\n and more words.\r\n"), byteCount/2)
			io.WriteString(w, "\r\n--alt\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
			repeat(w, []byte("<p>The quarterly <b>numbers</b> are in, caf=C3=A9 &amp; all, a soft break=\r\n here.</p>\r\n"), byteCount/2)
			io.WriteString(w, "\r\n--alt--\r\n")
		}},
		{name: "one base64 attachment", write: func(w io.Writer, byteCount int) {
			io.WriteString(w, "Subject: report\r\nContent-Type: multipart/mixed; boundary=\"m\"\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nSee the attached report.\r\n--m\r\nContent-Type: application/pdf; name=\"q3.pdf\"\r\nContent-Disposition: attachment; filename=\"q3.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
			repeat(w, base64Line, byteCount)
			io.WriteString(w, "--m--\r\n")
		}},
		{name: "all one base64 text part", write: func(w io.Writer, byteCount int) {
			io.WriteString(w, "Subject: long\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
			repeat(w, base64Line, byteCount)
		}},
		{name: "windows-1252 HTML, every byte growing", write: func(w io.Writer, byteCount int) {
			io.WriteString(w, "Subject: grows\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n")
			line := []byte{}
			for b := 0x80; b <= 0xFF; b += 1 {
				line = append(line, byte(b))
			}
			line = append(line, "<br>\r\n"...)
			repeat(w, line, byteCount)
		}},
	}
}

// Counts what is written, so a shape's length is known before it is extracted.
type testIndexCountingWriter struct {
	byteCount int
}

func (self *testIndexCountingWriter) Write(p []byte) (int, error) {
	self.byteCount += len(p)
	return len(p), nil
}

// R4's fixed memory, 11.4's bound: a 50 MiB message in each of 11.4's shapes, written in 64 KiB pieces and never held,
// grows the heap, sampled after a collection at every document, by less than 256 KiB over the normalizer's own buffers
// and the document's key set beside them.
func TestIndexStreamMemory(t *testing.T) {
	if testing.Short() || runtime.GOOS == "js" {
		// 50 MiB a shape; the Worker's own memory is FS-77's to measure
		t.Skip("50 MiB a shape, measured natively")
	}
	const messageByteCount = 50 * 1024 * 1024
	const growthByteCount = 256 * 1024
	for _, shape := range testIndexStreamShapes() {
		counter := &testIndexCountingWriter{}
		shape.write(counter, messageByteCount)
		settings := DefaultIndexFormatSettings()
		normalizer := testIndexNormalizer(t)
		// the collector at its largest, the normalizer's own, so its growth is not counted as the stream's
		normalizer.collector = indexNewTrigramCollector()
		normalizer.collector.touchedWords = make([]uint32, 0, indexTrigramWordCount)
		documentCount := 0
		peak := uint64(0)
		var baseline runtime.MemStats
		var stream *indexMailStream
		stream = indexExtractMailStream(&indexStreamArgs{
			template:   &IndexDocument{Kind: IndexDocMail, Name: []byte("m/202611/50")},
			byteCount:  uint64(counter.byteCount),
			normalizer: normalizer,
			settings:   settings,
			emit: func(document *indexStreamDocument) error {
				documentCount += 1
				var sample runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&sample)
				own := uint64(cap(document.keys)) * 4
				if baseline.HeapAlloc+own < sample.HeapAlloc {
					peak = max(peak, sample.HeapAlloc-baseline.HeapAlloc-own)
				}
				return nil
			},
		})
		runtime.GC()
		runtime.ReadMemStats(&baseline)
		pieces := &testIndexPieceWriter{stream: stream, piece: make([]byte, 0, 64*1024)}
		shape.write(pieces, messageByteCount)
		pieces.flush()
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if documentCount == 0 {
			t.Fatalf("%s: no document", shape.name)
		}
		if growthByteCount <= peak {
			t.Errorf("%s: the heap grew %d B over the normalizer's own across %d documents", shape.name, peak, documentCount)
		}
		t.Logf("%s: %d B of message, %d documents, the heap at most %d B over the normalizer's own", shape.name, counter.byteCount, documentCount, peak)
	}
}

// Writes to a stream in pieces of the piece buffer's capacity.
type testIndexPieceWriter struct {
	stream *indexMailStream
	piece  []byte
}

func (self *testIndexPieceWriter) Write(p []byte) (int, error) {
	written := len(p)
	for 0 < len(p) {
		take := min(len(p), cap(self.piece)-len(self.piece))
		self.piece = append(self.piece, p[:take]...)
		p = p[take:]
		if len(self.piece) == cap(self.piece) {
			self.flush()
		}
	}
	return written, nil
}

// Writes what the piece buffer holds.
func (self *testIndexPieceWriter) flush() {
	if 0 < len(self.piece) {
		self.stream.Write(self.piece)
		self.piece = self.piece[:0]
	}
}

// A stream closed after another length than it declared is refused, and one written after Close too.
func TestIndexStreamRefusesAnotherLength(t *testing.T) {
	documents := []*indexStreamDocument{}
	args := testIndexStreamArgs(t, true, []byte("m/1"), 10, DefaultIndexFormatSettings(), &documents)
	stream := indexExtractMailStream(args)
	stream.Write([]byte("Subject: a\r\n\r\nbody"))
	if err := stream.Close(); err != errIndexStreamLength {
		t.Fatalf("another length closed: %v", err)
	}
	if _, err := stream.Write([]byte("more")); err != errIndexStreamClosed {
		t.Fatalf("a write after Close: %v", err)
	}
}

// A stage that keeps what it is given, and whether it finished.
type testIndexCollectStage struct {
	text     []byte
	finished bool
}

// Keeps text.
func (self *testIndexCollectStage) write(text []byte) {
	self.text = append(self.text, text...)
}

// Marks the end.
func (self *testIndexCollectStage) finish() {
	self.finished = true
}

// Each stage against its whole-value function on random text from the bytes each rule turns on, cut at random:
// quoted-printable with a small line window too, base64, and html_to_text's tags then references.
func TestIndexStreamStagesEqualWhole(t *testing.T) {
	alphabet := []byte("<>!-/&#xX;= \t\r\n\"'aAbBpPsScCrRiItTyYlLeE019Fqumz\x80\xe2\xff")
	words := []string{"script", "style", "SCRIPT", "</script", "</style", "<!--", "-->", "amp", "amp;", "notin;", "nLt;", "AElig", "frac12", "&#x110000;", "&#00065", "blockquote", "figcaption", "br"}
	for seed := range int64(3000) {
		random := rand.New(rand.NewSource(seed))
		text := []byte{}
		for range random.Intn(120) {
			if random.Intn(4) == 0 {
				text = append(text, words[random.Intn(len(words))]...)
			} else {
				text = append(text, alphabet[random.Intn(len(alphabet))])
			}
		}
		settings := DefaultIndexFormatSettings()
		if seed%3 == 0 {
			settings.LineWindowByteCount = 1 + random.Intn(4)
		}
		run := func(stage indexStreamStage, sink *testIndexCollectStage) []byte {
			for rest := text; 0 < len(rest); {
				piece := min(len(rest), 1+random.Intn(5))
				stage.write(rest[:piece])
				rest = rest[piece:]
			}
			stage.finish()
			if !sink.finished {
				t.Fatalf("seed %d: a stage did not pass its finish on", seed)
			}
			return sink.text
		}
		quoted := &testIndexCollectStage{}
		if got, want := run(indexNewStreamTransfer("quoted-printable", quoted, settings), quoted), indexQuotedPrintable(text, settings); !bytes.Equal(got, want) {
			t.Errorf("seed %d quoted-printable of %q: %q, whole %q", seed, text, got, want)
		}
		decoded := &testIndexCollectStage{}
		if got, want := run(indexNewStreamTransfer("base64", decoded, settings), decoded), indexBase64Body(text); !bytes.Equal(got, want) {
			t.Errorf("seed %d base64 of %q: %q, whole %q", seed, text, got, want)
		}
		html := &testIndexCollectStage{}
		if got, want := run(indexNewStreamTags(indexNewStreamReferences(html)), html), indexStripHtml(text); !bytes.Equal(got, want) {
			t.Errorf("seed %d html of %q: %q, whole %q", seed, text, got, want)
		}
	}
}
