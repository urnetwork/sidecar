//go:build !ios_extension

// Extraction in one pass, in fixed memory (DESIGN-DETAILS 11.2.8; R-CORE-19, R-EVS-24, D-SDK-25; QD-641, QD-691;
// SEARCH-M10-44): the function indexExtractMail and indexExtractFile compute over whole values, computed instead over
// a message written front to back in pieces of any size, or a file read through an io.ReaderAt, each finished
// document handed to the caller as its key set and row, never as text. The whole-value functions stay as the form the
// conformance vectors and the oracle are held to, and FuzzIndexExtractStreamEqualsWhole holds this one to them on any
// input and any split of it into writes.
//
// A stage reads the bytes the stage before it gives, and keeps what 11.2.8's table gives it:
//
//	lines and delimiters    the current line's first LineWindowByteCount bytes and one held line break; the open
//	                        boundaries, at most MimeMaxDepth, each at most LineWindowByteCount - 2
//	header blocks           the logical line being read, at most HeaderMaxByteCount; the entity's first Content-Type,
//	                        -Disposition and -Transfer-Encoding; the message's four joined values
//	base64, quoted-printable, the charset decoder, tags, references    evs_index_extract_stream_mime.go and _html.go
//	pieces                  whether anything was given yet
//	chunks                  the OverlapByteCount bytes two documents share
//	normalizer and key set  normalizer 1's own buffers and one key bitmap
//
// A line is tested as a delimiter against every open boundary, outermost first, once its LF arrives or
// LineWindowByteCount bytes have passed without one, and the line break before it is held until it is known not to be
// a delimiter, and dropped when it is one (B2). A document's keys are collected while its text passes; at a chunk's
// end the next OverlapByteCount bytes are fed to it, it is finished, and the same bytes begin the next, so one key
// bitmap is live at a time. Nothing buffers a part, a line or a header block to learn its length.
//
// A message's row carries its whole length, so the caller says it at the start; Close refuses a message whose length
// was another. Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
)

var (
	// A stream closed with another length than it was opened for: the rows it handed out carry the wrong size.
	errIndexStreamLength = errors.New("index stream of another length than declared")
	// A stream written or closed after its Close.
	errIndexStreamClosed = errors.New("index stream closed")
)

// One document a one-pass extraction finished: its chunk, its key set and row, or skipped when its key set passes
// its cap or it alone would not fit a shard (D6), in which case neither is set.
type indexStreamDocument struct {
	chunk   uint32
	keys    indexKeySet
	row     *indexRow
	skipped bool
}

// What every one-pass extraction shares: the document template its rows take their name, kind and flags from, the
// normalizer, the root's companion flag and ref, and the sink each finished document goes to.
type indexStreamArgs struct {
	// Kind, Name and the flags; the extraction sets the fields, the chunk and the length.
	template *IndexDocument
	// The source's whole length in bytes, which every row carries.
	byteCount  uint64
	normalizer *indexNormalizer
	companion  bool
	refId      Id
	settings   *IndexFormatSettings
	// Takes each document as it finishes, in chunk order. An error stops the extraction.
	emit func(document *indexStreamDocument) error
}

// The body text's chunks as documents (D4, D6): one document live at a time, its keys collected while its text
// passes. Field 5 of document k is the text's bytes [k × ChunkByteCount, (k+1) × ChunkByteCount + OverlapByteCount);
// the overlap is fed to document k, kept, and replayed into k + 1. The fields before field 5 are the same on every
// chunk, normalized once.
type indexStreamDocuments struct {
	args *indexStreamArgs
	// The documents' fields 1 to 4, normalized and padded as step 7 writes them, the same on every chunk.
	prefix []byte
	// The body text's bytes so far.
	position int
	// The live document's chunk, and whether one is live.
	chunk int
	live  bool
	// The live document's field 5: the normalizer's writer, and whether its padding opened.
	field *transform.Writer
	pad   *indexStreamPadWriter
	// The overlap that begins the next document.
	overlap []byte
	err     error
}

// Writes step 7's opening space before the first byte the normalizer gives, so a field that normalizes to nothing,
// which no non-empty value does, adds nothing.
type indexStreamPadWriter struct {
	sink   io.Writer
	opened bool
}

// Passes text on, the opening space first.
func (self *indexStreamPadWriter) Write(text []byte) (int, error) {
	if len(text) == 0 {
		return 0, nil
	}
	if !self.opened {
		self.opened = true
		if _, err := self.sink.Write(indexFieldPad); err != nil {
			return 0, err
		}
	}
	return self.sink.Write(text)
}

// The documents of one source, their fields 1 to 4 given as fields, which normalize once.
func indexNewStreamDocuments(args *indexStreamArgs, fields []indexTextField) (*indexStreamDocuments, error) {
	if args.normalizer.collector == nil {
		args.normalizer.collector = indexNewTrigramCollector()
	}
	prefix := &bytes.Buffer{}
	if err := args.normalizer.writeDocument(prefix, fields); err != nil {
		return nil, err
	}
	return &indexStreamDocuments{args: args, prefix: prefix.Bytes(), overlap: make([]byte, 0, args.settings.OverlapByteCount)}, nil
}

// Opens document chunk: its key bitmap cleared, its fields 1 to 4 replayed, its field 5 not yet opened.
func (self *indexStreamDocuments) open(chunk int) {
	collector := self.args.normalizer.collector
	collector.reset()
	collector.Write(self.prefix)
	self.pad = &indexStreamPadWriter{sink: collector}
	self.field = transform.NewWriter(self.pad, self.args.normalizer.chain)
	self.chunk = chunk
	self.live = true
}

// Feeds text to the live document's field 5.
func (self *indexStreamDocuments) feed(text []byte) {
	if self.err != nil || len(text) == 0 {
		return
	}
	if _, err := self.field.Write(text); err != nil {
		self.err = err
	}
}

// Finishes the live document: its field closed and padded, its key set and row built, and the document handed on.
func (self *indexStreamDocuments) finish() {
	if self.err != nil || !self.live {
		return
	}
	self.live = false
	if err := self.field.Close(); err != nil {
		self.err = err
		return
	}
	collector := self.args.normalizer.collector
	if self.pad.opened {
		collector.Write(indexFieldPad)
	}
	keys := collector.keys()
	document := &indexStreamDocument{chunk: uint32(self.chunk)}
	// the row first, as prepare builds it, since D6 reads its bytes
	template := *self.args.template
	template.Chunk = uint32(self.chunk)
	template.ByteCount = self.args.byteCount
	row := template.row(len(keys), self.args.companion, self.args.refId)
	if err := row.check(self.args.companion); err != nil {
		self.err = err
		return
	}
	if indexDocumentSkipped(keys, row, self.args.settings) {
		document.skipped = true
	} else {
		document.keys, document.row = keys, row
	}
	self.err = self.args.emit(document)
}

// Takes the body text's next bytes.
func (self *indexStreamDocuments) Write(text []byte) (int, error) {
	settings := self.args.settings
	written := len(text)
	for 0 < len(text) && self.err == nil {
		if !self.live {
			self.open(0)
		}
		chunkEnd := (self.chunk + 1) * settings.ChunkByteCount
		overlapEnd := chunkEnd + settings.OverlapByteCount
		switch {
		case self.position < chunkEnd:
			take := min(len(text), chunkEnd-self.position)
			self.feed(text[:take])
			self.position += take
			text = text[take:]
		case self.position < overlapEnd:
			take := min(len(text), overlapEnd-self.position)
			self.feed(text[:take])
			self.overlap = append(self.overlap, text[:take]...)
			self.position += take
			text = text[take:]
		default:
			// past this chunk's overlap: it is finished, and the next begins with the overlap
			self.finish()
			next := self.chunk + 1
			self.open(next)
			self.feed(self.overlap)
			self.overlap = self.overlap[:0]
		}
	}
	return written, self.err
}

// Finishes the text: the live document, the one its overlap begins when the text reaches past its chunk, and the one
// empty document of an empty text.
func (self *indexStreamDocuments) Close() error {
	if !self.live {
		self.open(0)
	}
	self.finish()
	if self.err == nil && 0 < len(self.overlap) {
		self.open(self.chunk + 1)
		self.feed(self.overlap)
		self.overlap = self.overlap[:0]
		self.finish()
	}
	return self.err
}

// The body text's pieces (D3): each piece that gives any byte, after the first such, opens with one SP.
type indexStreamPieces struct {
	text  *indexStreamDocuments
	given bool
	// The piece being written has given a byte.
	opened bool
}

// Opens a piece.
func (self *indexStreamPieces) begin() {
	self.opened = false
}

// The piece's next bytes.
func (self *indexStreamPieces) write(text []byte) {
	if len(text) == 0 {
		return
	}
	if !self.opened {
		self.opened = true
		if self.given {
			self.text.Write([]byte{' '})
		}
		self.given = true
	}
	self.text.Write(text)
}

// A whole piece at once.
func (self *indexStreamPieces) piece(text []byte) {
	self.begin()
	self.write(text)
}

// What an entity gives once its header block is read (M1 to M6).
type indexStreamKind int

const (
	// Nothing more: an attachment, a type that is not text, a message/rfc822 part, a multipart with no boundary
	// that can match, or one MimeMaxDepth deep.
	indexStreamNothing indexStreamKind = iota
	indexStreamMultipart
	indexStreamText
)

// The header fields an entity keeps, and the message's joined ones (H6).
var indexStreamHeaderNames = []string{"content-type", "content-disposition", "content-transfer-encoding"}
var indexStreamMessageNames = []string{"subject", "from", "to", "cc"}

// One entity of the walk: the message, or a part of a multipart.
type indexStreamEntity struct {
	stream   *indexMailStream
	depth    int
	inDigest bool

	// The header block: the logical line being read, whether one is open, whether the current physical line has
	// given content, and whether the line ended.
	inHeader    bool
	logical     []byte
	logicalOpen bool
	lineHasByte bool
	// The first value of each of indexStreamHeaderNames, and whether one was found.
	firsts     [3]string
	firstFound [3]bool

	kind indexStreamKind
	// A multipart's delimiter and close delimiter lines, whether its close delimiter has passed, whether it is a
	// digest, and its part being read.
	delimiter      []byte
	closeDelimiter []byte
	closed         bool
	digest         bool
	child          *indexStreamEntity
	// A text part's stages, the first of which takes its body.
	stages indexStreamStage
	done   bool
}

// One stage of a text part's body: it takes bytes as they come and, at the part's end, gives what it holds.
type indexStreamStage interface {
	write(text []byte)
	finish()
}

// A one-pass extraction of one message (D1, D3; 11.2.5 and 11.2.8).
type indexMailStream struct {
	args     *indexStreamArgs
	settings *IndexFormatSettings
	root     *indexStreamEntity
	pieces   *indexStreamPieces
	text     *indexStreamDocuments
	// The message's joined Subject, From, To and Cc so far, in indexStreamMessageNames' order, each at most
	// HeaderMaxByteCount, and whether a field of each was found.
	joined      [4][]byte
	joinedFound [4]bool

	// The line being read while it may be a delimiter, at most LineWindowByteCount bytes; once decided it is not,
	// its bytes go straight to the current entity, a CR at their end held until the next byte.
	line        []byte
	lineDecided bool
	heldCr      bool
	// The previous line's break, CR LF or LF, held until this line is known not to be a delimiter.
	heldBreak []byte

	written uint64
	closed  bool
}

// A one-pass extraction of a message of args.byteCount bytes at template's path.
func indexNewMailStream(args *indexStreamArgs) *indexMailStream {
	stream := &indexMailStream{args: args, settings: args.settings, line: make([]byte, 0, args.settings.LineWindowByteCount)}
	stream.root = &indexStreamEntity{stream: stream, depth: 0, inHeader: true}
	return stream
}

// The deepest entity of the walk, which takes every line that is no delimiter.
func (self *indexMailStream) current() *indexStreamEntity {
	entity := self.root
	for entity.child != nil {
		entity = entity.child
	}
	return entity
}

// Takes the message's next bytes.
func (self *indexMailStream) Write(p []byte) (int, error) {
	if self.closed {
		return 0, errIndexStreamClosed
	}
	total := len(p)
	self.written += uint64(total)
	for 0 < len(p) {
		end := bytes.IndexByte(p, '\n')
		if self.lineDecided {
			// a line past LineWindowByteCount: straight to the entity until its LF
			if end < 0 {
				self.deliverDecided(p, false)
				break
			}
			self.deliverDecided(p[:end], true)
			p = p[end+1:]
			continue
		}
		room := self.settings.LineWindowByteCount - len(self.line)
		if 0 <= end && end <= room {
			self.line = append(self.line, p[:end]...)
			self.endLine(true)
			p = p[end+1:]
			continue
		}
		if len(p) <= room {
			self.line = append(self.line, p...)
			break
		}
		// the line passes LineWindowByteCount: no delimiter
		self.line = append(self.line, p[:room]...)
		p = p[room:]
		self.decideLine()
	}
	return total, self.err()
}

// The first error the documents met.
func (self *indexMailStream) err() error {
	if self.text != nil {
		return self.text.err
	}
	return nil
}

// The line held so far is no delimiter: the held break goes to the entity, then the line's bytes, a CR at their end
// held, and the rest of the line follows them straight.
func (self *indexMailStream) decideLine() {
	self.releaseBreak()
	self.lineDecided = true
	content := self.line
	self.line = self.line[:0]
	self.deliverDecided(content, false)
}

// Delivers a decided line's bytes to the current entity, holding a CR at their end until the next byte says whether
// it opens the line break; ended says the line's LF came right after them.
func (self *indexMailStream) deliverDecided(content []byte, ended bool) {
	entity := self.current()
	if self.heldCr && 0 < len(content) {
		entity.content([]byte{'\r'})
		self.heldCr = false
	}
	if 0 < len(content) && content[len(content)-1] == '\r' {
		entity.content(content[:len(content)-1])
		self.heldCr = true
	} else {
		entity.content(content)
	}
	if ended {
		self.holdBreak(entity, self.breakOf(self.heldCr))
		self.heldCr = false
		self.lineDecided = false
	}
}

// Holds a line's break until the next line is known not to be a delimiter, for a body, whose content it is. A header
// line's break is no content: it ends the line at once, so an empty line ends the header block before the next line
// is tested against the boundary that block may open.
func (self *indexMailStream) holdBreak(entity *indexStreamEntity, brk []byte) {
	if entity.inHeader {
		entity.lineBreak(brk)
		return
	}
	self.heldBreak = brk
}

// A line break: LF, after a CR when the line's content ended in one.
func (self *indexMailStream) breakOf(cr bool) []byte {
	if cr {
		return []byte("\r\n")
	}
	return []byte("\n")
}

// Gives the held break to the current entity, as content of its line, now that the next line is no delimiter.
func (self *indexMailStream) releaseBreak() {
	if self.heldBreak == nil {
		return
	}
	brk := self.heldBreak
	self.heldBreak = nil
	self.current().lineBreak(brk)
}

// A line held whole ends: at its LF when lf, else at the end of the message. It is tested as a delimiter against every
// open boundary, outermost first; if it is none, the held break and the line go to the current entity.
func (self *indexMailStream) endLine(lf bool) {
	line := self.line
	self.line = self.line[:0]
	if self.delimiter(line) {
		self.heldBreak = nil
		return
	}
	self.releaseBreak()
	entity := self.current()
	content := line
	cr := 0 < len(content) && content[len(content)-1] == '\r'
	if cr {
		content = content[:len(content)-1]
	}
	entity.content(content)
	if lf {
		self.holdBreak(entity, self.breakOf(cr))
	} else if cr {
		// the last line, with no LF: its CR is the body's, and the header's to drop (H1)
		entity.lineBreak([]byte{'\r'})
	}
}

// B1's delimiter test of a line held whole, against each open boundary from the outermost: the first that matches
// takes it, ending the part that boundary's multipart was reading, and opening the next unless it is the close
// delimiter.
func (self *indexMailStream) delimiter(line []byte) bool {
	trimmed := bytes.TrimRight(line, " \t\r")
	for entity := self.root; entity != nil; entity = entity.child {
		if entity.kind != indexStreamMultipart || entity.inHeader || entity.closed {
			continue
		}
		isClose := bytes.Equal(trimmed, entity.closeDelimiter)
		if !isClose && !bytes.Equal(trimmed, entity.delimiter) {
			continue
		}
		if entity.child != nil {
			entity.child.end()
			entity.child = nil
		}
		if isClose {
			entity.closed = true
		} else {
			entity.child = &indexStreamEntity{stream: self, depth: entity.depth + 1, inDigest: entity.digest, inHeader: true}
		}
		return true
	}
	return false
}

// Ends the message: its last line, held break and every entity, and then its documents. Refuses a message of another
// length than declared.
func (self *indexMailStream) Close() error {
	if self.closed {
		return errIndexStreamClosed
	}
	self.closed = true
	if self.lineDecided {
		if self.heldCr {
			self.current().lineBreak([]byte{'\r'})
			self.heldCr = false
		}
		self.lineDecided = false
	} else if 0 < len(self.line) {
		self.endLine(false)
	}
	self.releaseBreak()
	// a header block that never ended ends here, opening the text
	self.root.end()
	if err := self.text.Close(); err != nil {
		return err
	}
	if self.written != self.args.byteCount {
		return errIndexStreamLength
	}
	return nil
}

// Opens the body text once the message's header block is read: the documents' fields 1 to 3 are its decoded Subject,
// From, and To with Cc (D3).
func (self *indexMailStream) beginText() {
	if self.text != nil {
		return
	}
	words := func(index int) []byte {
		return []byte(indexDecodeEncodedWords(string(self.joined[index])))
	}
	subject, from := words(0), words(1)
	to := indexJoinNonEmpty(words(2), words(3))
	self.args.template.Fields[indexFieldSubject] = subject
	self.args.template.Fields[indexFieldFrom] = from
	self.args.template.Fields[indexFieldTo] = to
	fields := []indexTextField{}
	for _, number := range []int{indexFieldSubject, indexFieldFrom, indexFieldTo} {
		if value := self.args.template.Fields[number]; 0 < len(value) {
			fields = append(fields, indexTextField{number: number, text: bytes.NewReader(value)})
		}
	}
	text, err := indexNewStreamDocuments(self.args, fields)
	if err != nil {
		text = &indexStreamDocuments{args: self.args, err: err}
	}
	self.text = text
	self.pieces = &indexStreamPieces{text: text}
}

// A line's content, or a part of it.
func (self *indexStreamEntity) content(text []byte) {
	if self.done {
		return
	}
	if self.inHeader {
		self.headerContent(text)
		return
	}
	if self.kind == indexStreamText && 0 < len(text) {
		self.stages.write(text)
	}
}

// A line's break, given once the next line is known not to be a delimiter, or a last line's CR.
func (self *indexStreamEntity) lineBreak(brk []byte) {
	if self.done {
		return
	}
	if self.inHeader {
		self.headerLineEnd()
		return
	}
	if self.kind == indexStreamText {
		self.stages.write(brk)
	}
}

// H3 to H5 on a physical line's content as it comes: its first byte decides whether it continues the logical line or
// begins one, and a logical line keeps its first HeaderMaxByteCount bytes.
func (self *indexStreamEntity) headerContent(text []byte) {
	if len(text) == 0 {
		return
	}
	if !self.lineHasByte {
		self.lineHasByte = true
		if !(self.logicalOpen && indexBlank(text[0])) {
			self.finishLogical()
			self.logical = self.logical[:0]
			self.logicalOpen = true
		}
	}
	room := self.stream.settings.HeaderMaxByteCount - len(self.logical)
	self.logical = append(self.logical, text[:max(0, min(len(text), room))]...)
}

// A physical header line ends. One that gave no content is the empty line that ends the block (H2).
func (self *indexStreamEntity) headerLineEnd() {
	if self.lineHasByte {
		self.lineHasByte = false
		return
	}
	self.finishLogical()
	self.headerDone()
}

// H5 and H6 on the logical line read: a field of interest keeps its value, first or joined.
func (self *indexStreamEntity) finishLogical() {
	if !self.logicalOpen {
		return
	}
	self.logicalOpen = false
	name, value, ok := strings.Cut(string(self.logical), ":")
	if !ok {
		return
	}
	name, value = indexLower(indexTrim(name)), indexTrim(value)
	for index, wanted := range indexStreamHeaderNames {
		if name == wanted && !self.firstFound[index] {
			self.firsts[index], self.firstFound[index] = value, true
		}
	}
	if self.depth != 0 {
		return
	}
	stream := self.stream
	for index, wanted := range indexStreamMessageNames {
		if name != wanted {
			continue
		}
		joined := stream.joined[index]
		if stream.joinedFound[index] && len(joined) < stream.settings.HeaderMaxByteCount {
			joined = append(joined, ' ')
		}
		stream.joinedFound[index] = true
		joined = append(joined, value...)
		stream.joined[index] = joined[:min(len(joined), stream.settings.HeaderMaxByteCount)]
	}
}

// The header block is read: the entity's media type decides what its body gives (M1 to M6), a leaf's name is its
// first piece, and the message's documents open.
func (self *indexStreamEntity) headerDone() {
	self.inHeader = false
	self.logical = nil
	stream := self.stream
	if self.depth == 0 {
		stream.beginText()
	}
	contentType := indexParseMediaValue(self.firsts[0])
	disposition := indexParseMediaValue(self.firsts[1])
	mediaType := contentType.value
	if mediaType == "" {
		mediaType = "text/plain"
		if self.inDigest {
			mediaType = "message/rfc822"
		}
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := contentType.param("boundary")
		delimiter := "--" + boundary
		// a boundary that ends in a byte B1 trims, or whose delimiter passes the line window, matches no line
		if boundary == "" || stream.settings.MimeMaxDepth <= self.depth || stream.settings.LineWindowByteCount < len(delimiter) ||
			strings.TrimRight(delimiter, " \t\r") != delimiter {
			self.kind = indexStreamNothing
			return
		}
		self.kind = indexStreamMultipart
		self.delimiter = []byte(delimiter)
		self.closeDelimiter = []byte(delimiter + "--")
		self.digest = mediaType == "multipart/digest"
		return
	}
	name := disposition.param("filename")
	if name == "" {
		name = contentType.param("name")
	}
	if name != "" {
		stream.pieces.piece([]byte(indexDecodeEncodedWords(name)))
	}
	if disposition.value == "attachment" || (mediaType != "text/plain" && mediaType != "text/html") {
		self.kind = indexStreamNothing
		return
	}
	self.kind = indexStreamText
	stream.pieces.begin()
	var sink indexStreamStage = &indexStreamPieceStage{pieces: stream.pieces}
	if mediaType == "text/html" {
		sink = indexNewStreamTags(indexNewStreamReferences(sink))
	}
	sink = indexNewStreamCharset(contentType.param("charset"), sink)
	self.stages = indexNewStreamTransfer(self.firsts[2], sink, stream.settings)
}

// Ends the entity: a header block that never ended ends here with an empty body, the part it is reading ends first,
// and a text part gives what its stages hold.
func (self *indexStreamEntity) end() {
	if self.done {
		return
	}
	if self.inHeader {
		self.finishLogical()
		self.headerDone()
	}
	if self.child != nil {
		self.child.end()
		self.child = nil
	}
	if self.kind == indexStreamText {
		self.stages.finish()
	}
	self.done = true
}

// The last stage of a text part: its bytes are the piece's.
type indexStreamPieceStage struct {
	pieces *indexStreamPieces
}

// Gives text to the piece.
func (self *indexStreamPieceStage) write(text []byte) {
	self.pieces.write(text)
}

// Holds nothing to give.
func (self *indexStreamPieceStage) finish() {}

// Extracts one message in one pass: content written in pieces of any size to the stream, each finished document
// handed to emit (D3). What indexExtractMail gives over the whole message, document for document, as key sets and
// rows.
func indexExtractMailStream(args *indexStreamArgs) *indexMailStream {
	template := *args.template
	template.Kind = IndexDocMail
	args.template = &template
	return indexNewMailStream(args)
}

// One pass over a file (D2, S1 to S4; 11.2.8's point 4): its first SniffByteCount bytes decide text or binary, a first
// read finds its title, stopping at the first line with a letter or a number, which for nearly every file is its first,
// and a second builds its documents, each handed to args.emit; false for a binary, which gives none. content is read
// in blocks of ExtractReadByteCount and never held. What indexExtractFile gives over the whole file, document for
// document, as key sets and rows.
func indexExtractFileStream(args *indexStreamArgs, content io.ReaderAt) (bool, error) {
	settings := args.settings
	size := int64(args.byteCount)
	window := make([]byte, min(int64(settings.SniffByteCount), size))
	if byteCount, err := content.ReadAt(window, 0); byteCount < len(window) {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return false, err
	}
	var text func() io.Reader
	switch {
	case bytes.HasPrefix(window, indexUtf16BigEndianMark), bytes.HasPrefix(window, indexUtf16LittleEndianMark):
		bigEndian := bytes.HasPrefix(window, indexUtf16BigEndianMark)
		text = func() io.Reader {
			mark := int64(len(indexUtf16BigEndianMark))
			return &indexStreamUtf16{source: io.NewSectionReader(content, mark, size-mark), bigEndian: bigEndian, block: make([]byte, settings.ExtractReadByteCount)}
		}
	default:
		// the window alone decides, as S2 reads it
		if _, ok := indexSniff(window, settings); !ok {
			return false, nil
		}
		start := int64(0)
		if bytes.HasPrefix(window, indexUtf8Mark) {
			start = int64(len(indexUtf8Mark))
		}
		text = func() io.Reader {
			return io.NewSectionReader(content, start, size-start)
		}
	}
	block := make([]byte, settings.ExtractReadByteCount)
	title, err := indexStreamTitle(text(), block, settings)
	if err != nil {
		return false, err
	}
	template := *args.template
	template.Kind = IndexDocFile
	template.Fields[indexFieldTitle] = []byte(title)
	fileArgs := *args
	fileArgs.template = &template
	field := append(append([]byte(title), ' '), template.Name...)
	documents, err := indexNewStreamDocuments(&fileArgs, []indexTextField{{number: indexFieldTitle, text: bytes.NewReader(field)}})
	if err != nil {
		return false, err
	}
	if _, err := io.CopyBuffer(documents, text(), block); err != nil {
		return false, err
	}
	return true, documents.Close()
}

// S4 over a text read once from its start: the first line, split at LF, holding a code point of category L or N, read
// as UTF-8 with N1's rule; without its leading run of '#' and SP and its trailing run of SP, HT and CR; N1 applied; cut
// to TitleMaxByteCount on a code point. Of that line it keeps only the bytes the cut can reach, TitleMaxByteCount and
// the longest sequence less one, and where its trailing run starts; empty when no line has a letter or number.
func indexStreamTitle(text io.Reader, block []byte, settings *IndexFormatSettings) (string, error) {
	keepByteCount := settings.TitleMaxByteCount + utf8.UTFMax - 1
	kept := make([]byte, 0, keepByteCount)
	// The line's bytes past its leading run, how many, and how many up to the last byte not in its trailing run.
	leading := true
	lineByteCount := 0
	untrimmedByteCount := 0
	hasLetter := false
	// A UTF-8 sequence the read cut.
	carry := make([]byte, 0, utf8.UTFMax)
	scan := func(atLineEnd bool) {
		for 0 < len(carry) {
			if !atLineEnd && !utf8.FullRune(carry) {
				return
			}
			r, size := utf8.DecodeRune(carry)
			if unicode.IsLetter(r) || unicode.IsNumber(r) {
				hasLetter = true
			}
			carry = carry[:copy(carry, carry[size:])]
		}
	}
	title := func() string {
		trimmed := kept[:min(len(kept), untrimmedByteCount)]
		return indexCutUtf8(indexRowText(string(trimmed)), settings.TitleMaxByteCount)
	}
	reset := func() {
		kept = kept[:0]
		leading, lineByteCount, untrimmedByteCount, hasLetter = true, 0, 0, false
		carry = carry[:0]
	}
	for {
		byteCount, err := text.Read(block)
		for _, b := range block[:byteCount] {
			if b == '\n' {
				scan(true)
				if hasLetter {
					return title(), nil
				}
				reset()
				continue
			}
			if !hasLetter {
				carry = append(carry, b)
				scan(false)
			}
			if leading && (b == '#' || b == ' ') {
				continue
			}
			leading = false
			if len(kept) < keepByteCount {
				kept = append(kept, b)
			}
			lineByteCount += 1
			if b != ' ' && b != '\t' && b != '\r' {
				untrimmedByteCount = lineByteCount
			}
		}
		if err == io.EOF {
			scan(true)
			if hasLetter {
				return title(), nil
			}
			return "", nil
		}
		if err != nil {
			return "", err
		}
	}
}

// S1's UTF-16 as a reader of UTF-8: code units in the byte order given, a surrogate pair its code point, a surrogate
// with no partner U+FFFD and an odd last byte U+FFFD, as indexDecodeUtf16 decodes a whole file. It holds a block, a
// unit pair the read cut, and what it decoded and has not given yet.
type indexStreamUtf16 struct {
	source    io.Reader
	bigEndian bool
	block     []byte
	// Bytes read and not yet decoded, at most a surrogate pair's three.
	pending []byte
	decoded []byte
	eof     bool
}

// Gives the next decoded bytes.
func (self *indexStreamUtf16) Read(p []byte) (int, error) {
	for len(self.decoded) == 0 {
		if self.eof {
			return 0, io.EOF
		}
		byteCount, err := self.source.Read(self.block)
		self.pending = append(self.pending, self.block[:byteCount]...)
		if err == io.EOF {
			self.eof = true
		} else if err != nil {
			return 0, err
		}
		self.decode()
	}
	byteCount := copy(p, self.decoded)
	self.decoded = self.decoded[:copy(self.decoded, self.decoded[byteCount:])]
	return byteCount, nil
}

// Decodes the units pending that can be: a high surrogate waits for the unit after it unless the source has ended.
func (self *indexStreamUtf16) decode() {
	unitAt := func(index int) rune {
		if self.bigEndian {
			return rune(self.pending[index])<<8 | rune(self.pending[index+1])
		}
		return rune(self.pending[index+1])<<8 | rune(self.pending[index])
	}
	index := 0
	for ; index+1 < len(self.pending); index += 2 {
		unit := unitAt(index)
		switch {
		case 0xD800 <= unit && unit <= 0xDBFF && index+3 < len(self.pending):
			if next := unitAt(index + 2); 0xDC00 <= next && next <= 0xDFFF {
				self.decoded = utf8.AppendRune(self.decoded, 0x10000+(unit-0xD800)<<10+(next-0xDC00))
				index += 2
				continue
			}
			self.decoded = utf8.AppendRune(self.decoded, utf8.RuneError)
		case 0xD800 <= unit && unit <= 0xDBFF && !self.eof:
			// the unit after it is not read yet
			self.pending = self.pending[:copy(self.pending, self.pending[index:])]
			return
		case 0xD800 <= unit && unit <= 0xDFFF:
			self.decoded = utf8.AppendRune(self.decoded, utf8.RuneError)
		default:
			self.decoded = utf8.AppendRune(self.decoded, unit)
		}
	}
	if self.eof && index < len(self.pending) {
		self.decoded = utf8.AppendRune(self.decoded, utf8.RuneError)
		index = len(self.pending)
	}
	self.pending = self.pending[:copy(self.pending, self.pending[index:])]
}
