// Normalizer 1 (§11.14; protocol/INDEX-FORMAT.md): the one definition of index text, shared by writers, queries and
// reproduction, so that builds on one set of tables turn a document into one key set (FI-22). It is a chain of
// transforms, so a document of any size passes through a few buffers, which lets a phone normalize a 1 MiB chunk
// without holding its expansion: U+FDFA alone grows 11 times. Nothing here reads a clock, a locale or a map's order.
//
// Root evs_index_ files link on every leg but ios_extension, sidecar_http included, so they name no connect type.

package sidecar

import (
	"errors"
	"io"
	"runtime/debug"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Headers carry it as IndexFileHeader.normalizer.
const indexNormalizerId = 1

// Normalizer 1's Unicode version, which every table a build links must report.
const indexNormalizerUnicodeVersion = "17.0.0"

// Normalizer 1's x/text module. One norm.Version does not fix NFC: v0.40.0 and v0.41.0 report 17.0.0 too, and compose
// U+05D2 U+0307 to U+105C9 (§11.14's tables row).
const indexNormalizerTextModuleVersion = "v0.43.0"

const indexTextModulePath = "golang.org/x/text"

// §11.14's field numbers. Fields 6-15 are registered per document class, and field n's cut bit in a row is bit n + 2.
const (
	indexFieldSubject = 1
	indexFieldFrom    = 2
	indexFieldTo      = 3
	indexFieldTitle   = 4
	indexFieldBody    = 5
	indexFieldLast    = 15
)

// Longest normalized subject, from, to or title in a document's text, where a row's display copy is shorter.
const indexHeaderFieldByteCount = 1024

// Buffer between the chain and a sink. It must hold a field cut at indexHeaderFieldByteCount, and one past that shows
// where the cut's code point ends.
const indexNormalizerBufferByteCount = 4 * 1024

// The padding of step 7, one space a side.
var indexFieldPad = []byte{' '}

// A build on other tables is another normalizer: it writes nothing, and a search of an index on normalizer 1 reads
// status update (§11.14's tables row).
var errIndexOtherNormalizer = errors.New("this build links another normalizer's tables")

// plan-SEARCH-cherokee-fold is open, so normalizer 1 has no answer for this text, and an index byte built from one
// reading could not be rebuilt under another. Such a document stays out of the index and reads not yet searchable.
var errIndexCherokeeUnsettled = errors.New("normalizer 1 does not yet define case folding for cherokee")

// A field out of order, or a number §11.14 does not give.
var errIndexFieldOrder = errors.New("index fields must ascend from 1 to 15")

// The tables a build links, which decide what normalizing means. Read at run time, never written as constants, since
// a header must say what built it.
type indexTables struct {
	normVersion       string
	casesVersion      string
	unicodeVersion    string
	textModuleVersion string
}

// What this build links, read once. An absent or replaced x/text module reads as no version, which matches nothing.
var indexLinkedTables = sync.OnceValue(func() indexTables {
	tables := indexTables{
		normVersion:    norm.Version,
		casesVersion:   cases.UnicodeVersion,
		unicodeVersion: unicode.Version,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return tables
	}
	for _, module := range info.Deps {
		if module.Path == indexTextModulePath && module.Replace == nil {
			tables.textModuleVersion = module.Version
		}
	}
	return tables
})

// Whether these tables are normalizer 1's.
func (self indexTables) isNormalizerOne() bool {
	return self.normVersion == indexNormalizerUnicodeVersion &&
		self.casesVersion == indexNormalizerUnicodeVersion &&
		self.unicodeVersion == indexNormalizerUnicodeVersion &&
		self.textModuleVersion == indexNormalizerTextModuleVersion
}

// A step of this package's own: one code point in, at most one out, which is all steps 1, 3, 4 and 5 need of
// transform's contract. The chain may end a buffer inside a code point, so an incomplete one waits for more, and only
// at the end of the input does it read as ill-formed.
type indexRuneStep struct {
	// What a code point becomes, negative for nothing. It runs once for each code point, since Transform checks for
	// room first, so it may keep state.
	mapRune func(r rune) (rune, error)
	// Forgets that state.
	reset func()
}

// Reads src a code point at a time. DecodeRune reads each ill-formed byte as U+FFFD, so writing back what it returns
// is step 1's whole rule.
func (self *indexRuneStep) Transform(dst []byte, src []byte, atEof bool) (dstByteCount int, srcByteCount int, err error) {
	for srcByteCount < len(src) {
		if len(dst)-dstByteCount < utf8.UTFMax {
			return dstByteCount, srcByteCount, transform.ErrShortDst
		}
		if !atEof && !utf8.FullRune(src[srcByteCount:]) {
			return dstByteCount, srcByteCount, transform.ErrShortSrc
		}
		r, size := utf8.DecodeRune(src[srcByteCount:])
		mapped, err := self.mapRune(r)
		if err != nil {
			return dstByteCount, srcByteCount, err
		}
		if 0 <= mapped {
			dstByteCount += utf8.EncodeRune(dst[dstByteCount:], mapped)
		}
		srcByteCount += size
	}
	return dstByteCount, srcByteCount, nil
}

// Clears the step's state for the next text.
func (self *indexRuneStep) Reset() {
	self.reset()
}

// Whether x/text's fold swaps this code point's case. Each of the 172 folds to its other case, so folding twice
// returns the input, and that is the case plan-SEARCH-cherokee-fold asks about.
func indexIsCherokeeCased(r rune) bool {
	return (0x13A0 <= r && r <= 0x13F5) || (0x13F8 <= r && r <= 0x13FD) || (0xAB70 <= r && r <= 0xABBF)
}

// Whether a nonspacing mark after this code point goes: a letter of step 4's five scripts. Hangul and kana are not,
// so a syllable stays one syllable, and が and กิน keep their marks.
func indexDropsMarks(r rune) bool {
	return unicode.IsLetter(r) &&
		unicode.In(r, unicode.Latin, unicode.Greek, unicode.Cyrillic, unicode.Arabic, unicode.Hebrew)
}

// Steps 1-5, in order, as one transform.
func indexNormalizerChain() transform.Transformer {
	validStep := &indexRuneStep{
		mapRune: func(r rune) (rune, error) {
			return r, nil
		},
		reset: func() {},
	}
	cherokeeStep := &indexRuneStep{
		mapRune: func(r rune) (rune, error) {
			if indexIsCherokeeCased(r) {
				return -1, errIndexCherokeeUnsettled
			}
			return r, nil
		},
		reset: func() {},
	}
	// The nearest code point that is not Mn decides, so stacked marks after one base all go.
	dropsMarks := false
	markStep := &indexRuneStep{
		mapRune: func(r rune) (rune, error) {
			if !unicode.Is(unicode.Mn, r) {
				dropsMarks = indexDropsMarks(r)
			} else if dropsMarks {
				return -1, nil
			}
			return r, nil
		},
		reset: func() {
			dropsMarks = false
		},
	}
	inRun := false
	runStep := &indexRuneStep{
		mapRune: func(r rune) (rune, error) {
			if unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) {
				inRun = false
				return r, nil
			}
			if inRun {
				return -1, nil
			}
			inRun = true
			return ' ', nil
		},
		reset: func() {
			inRun = false
		},
	}
	return transform.Chain(validStep, norm.NFKC, cases.Fold(), cherokeeStep, norm.NFD, markStep, norm.NFC, runStep)
}

// One field of a document's text, by §11.14's number. A nil text, or one that reads empty, is a field with no text.
type indexTextField struct {
	number int
	text   io.Reader
}

// Normalizes text and builds key sets. Its buffers are a few KiB, plus 2 MiB once a document's keys are collected, so
// a caller keeps one for as long as it has documents, a refused one among them. Not safe for concurrent use.
type indexNormalizer struct {
	chain     transform.Transformer
	buffer    []byte
	collector *indexTrigramCollector
}

// Refuses tables that are not normalizer 1's, so nothing downstream of here can write under them.
func indexNewNormalizer(tables indexTables) (*indexNormalizer, error) {
	if !tables.isNormalizerOne() {
		return nil, errIndexOtherNormalizer
	}
	return &indexNormalizer{
		chain:  indexNormalizerChain(),
		buffer: make([]byte, indexNormalizerBufferByteCount),
	}, nil
}

// Steps 1-5 on one text, held whole: a query's term or a field already in memory.
func indexNormalize(text []byte) ([]byte, error) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	return normalizer.normalize(text)
}

// As indexNormalize, on this normalizer's chain.
func (self *indexNormalizer) normalize(text []byte) ([]byte, error) {
	normalized, _, err := transform.Bytes(self.chain, text)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

// Steps 1-5 as a stream: what comes out of the returned reader is src normalized, a buffer at a time.
func (self *indexNormalizer) stream(src io.Reader) io.Reader {
	return transform.NewReader(src, self.chain)
}

// Writes one field as step 7 has it: nothing for no text, else the text between two spaces. Fields 1-4 stop at their
// cut, on a code point (step 6), and what the cut left is never read.
func (self *indexNormalizer) writeField(sink io.Writer, field indexTextField) error {
	if field.text == nil {
		return nil
	}
	normalized := self.stream(field.text)
	wroteText := false
	write := func(text []byte) error {
		if !wroteText {
			wroteText = true
			if _, err := sink.Write(indexFieldPad); err != nil {
				return err
			}
		}
		_, err := sink.Write(text)
		return err
	}
	if field.number <= indexFieldTitle {
		byteCount, err := io.ReadFull(normalized, self.buffer[:indexHeaderFieldByteCount+utf8.UTFMax])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if byteCount != 0 {
			if err := write(indexCutUtf8(self.buffer[:byteCount], indexHeaderFieldByteCount)); err != nil {
				return err
			}
		}
	} else {
		for {
			byteCount, err := normalized.Read(self.buffer)
			if byteCount != 0 {
				if err := write(self.buffer[:byteCount]); err != nil {
					return err
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	if wroteText {
		if _, err := sink.Write(indexFieldPad); err != nil {
			return err
		}
	}
	return nil
}

// Writes a document's whole text to sink, fields in number order, holding only a buffer of it.
func (self *indexNormalizer) writeDocument(sink io.Writer, fields []indexTextField) error {
	lastNumber := 0
	for _, field := range fields {
		if field.number <= lastNumber || indexFieldLast < field.number {
			return errIndexFieldOrder
		}
		lastNumber = field.number
		if err := self.writeField(sink, field); err != nil {
			return err
		}
	}
	return nil
}

// A document's key set, ascending, in bounded memory whatever its fields expand to.
func (self *indexNormalizer) documentKeys(fields []indexTextField) (indexKeySet, error) {
	if self.collector == nil {
		self.collector = indexNewTrigramCollector()
	}
	self.collector.reset()
	if err := self.writeDocument(self.collector, fields); err != nil {
		return nil, err
	}
	return self.collector.keys(), nil
}

// The longest prefix of at most byteCount bytes that ends on a code point. text is valid UTF-8.
func indexCutUtf8[T ~string | ~[]byte](text T, byteCount int) T {
	if len(text) <= byteCount {
		return text
	}
	for 0 < byteCount && !utf8.RuneStart(text[byteCount]) {
		byteCount -= 1
	}
	return text[:byteCount]
}
