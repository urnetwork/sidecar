//go:build !ios_extension

// The local vocabulary (§11.14's typos row; §5.9's holds and delete rows; SEARCH-M10-25): the words of the text this
// host holds, each with the number of documents holding it, which a desktop's near hits expand a term against. A word
// is a run between spaces of a document's text as normalizer 1 writes it, so the vocabulary speaks the index's own
// normalization and a correction is a term the index can match. Counts, not a bare set: erasing a document
// decrements each of its words, read from its text before the text is deleted (CORE-M10-04's ApplyErase calls
// RemoveDocument), and a word no document holds any more leaves, so an erasure leaves no word of its own behind
// (FS-78). Words past VocabularyWordMaxByteCount, and words holding a CJK character, which near hits never correct,
// are kept out.
//
// A phone's display vocabulary is one too, built from the subjects, senders and i/ snippets it holds (AddText), so
// its one-edit variants can prefer the words it shows.
//
// It is sealed as derived data (SearchCachePartVocabulary), its words in byte order with their counts, written whole,
// replacing the copy before it, and read back a frame at a time (searchScanVocabulary), so an expansion streams it
// from storage rather than holding it (QD-641). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The sealed vocabulary's format.
const searchVocabularyFormat = 1

// A vocabulary's words and counts.
type SearchVocabulary struct {
	settings *SearchResultSettings

	stateLock sync.Mutex
	counts    map[string]uint32
}

// An empty vocabulary. settings nil takes the defaults.
func NewSearchVocabulary(settings *SearchResultSettings) *SearchVocabulary {
	if settings == nil {
		settings = DefaultSearchResultSettings()
	}
	return &SearchVocabulary{settings: settings, counts: map[string]uint32{}}
}

// Whether a rune is of a script near hits never correct: Han, kana, Hangul and Bopomofo.
func searchIsCjk(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Bopomofo)
}

// Whether a normalized word may be kept: not empty, within the cap, valid UTF-8 and with no CJK character.
func (self *SearchVocabulary) keeps(word []byte) bool {
	if len(word) == 0 || self.settings.VocabularyWordMaxByteCount < len(word) || !utf8.Valid(word) {
		return false
	}
	for _, r := range string(word) {
		if searchIsCjk(r) {
			return false
		}
	}
	return true
}

// A sink that splits normalized text at spaces into distinct words, holding a word no longer than the cap.
type searchWordSplitter struct {
	vocabulary *SearchVocabulary
	words      map[string]bool
	word       []byte
	// The current word passed the cap: it is dropped at its end.
	long bool
}

// Splits text, carrying a word across writes.
func (self *searchWordSplitter) Write(text []byte) (int, error) {
	for _, b := range text {
		if b == ' ' {
			self.end()
			continue
		}
		if self.long {
			continue
		}
		if self.vocabulary.settings.VocabularyWordMaxByteCount <= len(self.word) {
			self.long = true
			self.word = self.word[:0]
			continue
		}
		self.word = append(self.word, b)
	}
	return len(text), nil
}

// Ends the current word.
func (self *searchWordSplitter) end() {
	if !self.long && self.vocabulary.keeps(self.word) {
		self.words[string(self.word)] = true
	}
	self.word = self.word[:0]
	self.long = false
}

// A document's distinct words: its text as the index's writer normalizes it, fields padded and joined, split at
// spaces.
func (self *SearchVocabulary) documentWords(normalizer *indexNormalizer, document *IndexDocument) (map[string]bool, error) {
	splitter := &searchWordSplitter{vocabulary: self, words: map[string]bool{}}
	if err := normalizer.writeDocument(splitter, document.textFields()); err != nil {
		return nil, err
	}
	splitter.end()
	return splitter.words, nil
}

// A display text's distinct words, normalized as a field is.
func (self *SearchVocabulary) textWords(normalizer *indexNormalizer, text []byte) (map[string]bool, error) {
	normalized, err := normalizer.normalize(text)
	if err != nil {
		return nil, err
	}
	splitter := &searchWordSplitter{vocabulary: self, words: map[string]bool{}}
	splitter.Write(normalized)
	splitter.end()
	return splitter.words, nil
}

// Counts each word once more, or once less, dropping a word whose count reaches 0.
func (self *SearchVocabulary) apply(words map[string]bool, add bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for word := range words {
		switch {
		case add:
			self.counts[word] += 1
		case self.counts[word] <= 1:
			delete(self.counts, word)
		default:
			self.counts[word] -= 1
		}
	}
}

// Counts a document's words: one document more for each.
func (self *SearchVocabulary) AddDocument(normalizer *indexNormalizer, document *IndexDocument) error {
	words, err := self.documentWords(normalizer, document)
	if err != nil {
		return err
	}
	self.apply(words, true)
	return nil
}

// Uncounts a document's words, from the text the document held, which the caller reads before deleting it.
func (self *SearchVocabulary) RemoveDocument(normalizer *indexNormalizer, document *IndexDocument) error {
	words, err := self.documentWords(normalizer, document)
	if err != nil {
		return err
	}
	self.apply(words, false)
	return nil
}

// Counts a display text's words as one document's: a phone's subjects, senders and i/ snippets.
func (self *SearchVocabulary) AddText(normalizer *indexNormalizer, text []byte) error {
	words, err := self.textWords(normalizer, text)
	if err != nil {
		return err
	}
	self.apply(words, true)
	return nil
}

// Uncounts a display text's words.
func (self *SearchVocabulary) RemoveText(normalizer *indexNormalizer, text []byte) error {
	words, err := self.textWords(normalizer, text)
	if err != nil {
		return err
	}
	self.apply(words, false)
	return nil
}

// The documents holding word, normalized; 0 for a word none holds.
func (self *SearchVocabulary) Count(word string) uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts[word]
}

// The words held.
func (self *SearchVocabulary) Len() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.counts)
}

// Calls visit with each word and its count in byte order until it answers false, on a copy taken under the lock.
func (self *SearchVocabulary) each(visit func(word []byte, count uint32) bool) {
	type wordCount struct {
		word  string
		count uint32
	}
	words := []wordCount{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for word, count := range self.counts {
			words = append(words, wordCount{word: word, count: count})
		}
	}()
	slices.SortFunc(words, func(a wordCount, b wordCount) int {
		return strings.Compare(a.word, b.word)
	})
	for _, entry := range words {
		if !visit([]byte(entry.word), entry.count) {
			return
		}
	}
}

// The vocabulary's bytes: its format, its word count, then each word, its length and bytes, with its count, in byte
// order, every integer VByte. A function of its words and counts alone.
func (self *SearchVocabulary) encode() []byte {
	encoded := []byte{searchVocabularyFormat}
	encoded = indexAppendVByte(encoded, uint64(self.Len()))
	self.each(func(word []byte, count uint32) bool {
		encoded = indexAppendVByte(encoded, uint64(len(word)))
		encoded = append(encoded, word...)
		encoded = indexAppendVByte(encoded, uint64(count))
		return true
	})
	return encoded
}

// Reads a sealed vocabulary's records from r a byte at a time, refusing a format it does not know, words out of
// order or past the cap, and a count of 0.
func searchReadVocabulary(r io.ByteReader, settings *SearchResultSettings, visit func(word []byte, count uint32) bool) error {
	format, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("%w: a vocabulary with no format", ErrSearchCacheArgs)
	}
	if format != searchVocabularyFormat {
		return fmt.Errorf("%w: a vocabulary of format %d", ErrSearchCacheArgs, format)
	}
	wordCount, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("%w: a vocabulary's word count", ErrSearchCacheArgs)
	}
	previous := []byte{}
	word := make([]byte, 0, settings.VocabularyWordMaxByteCount)
	for index := uint64(0); index < wordCount; index += 1 {
		length, err := binary.ReadUvarint(r)
		if err != nil || length == 0 || uint64(settings.VocabularyWordMaxByteCount) < length {
			return fmt.Errorf("%w: a vocabulary word's length", ErrSearchCacheArgs)
		}
		word = word[:0]
		for range length {
			b, err := r.ReadByte()
			if err != nil {
				return fmt.Errorf("%w: a vocabulary word cut short", ErrSearchCacheArgs)
			}
			word = append(word, b)
		}
		count, err := binary.ReadUvarint(r)
		if err != nil || count == 0 || uint64(^uint32(0)) < count {
			return fmt.Errorf("%w: a vocabulary word's count", ErrSearchCacheArgs)
		}
		if 0 < index && bytes.Compare(previous, word) >= 0 {
			return fmt.Errorf("%w: vocabulary words out of order", ErrSearchCacheArgs)
		}
		previous = append(previous[:0], word...)
		if !visit(word, uint32(count)) {
			return nil
		}
	}
	return nil
}

// A vocabulary from its bytes.
func searchDecodeVocabulary(encoded []byte, settings *SearchResultSettings) (*SearchVocabulary, error) {
	vocabulary := NewSearchVocabulary(settings)
	reader := bytes.NewReader(encoded)
	if err := searchReadVocabulary(reader, vocabulary.settings, func(word []byte, count uint32) bool {
		vocabulary.counts[string(word)] = count
		return true
	}); err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("%w: bytes after a vocabulary", ErrSearchCacheArgs)
	}
	return vocabulary, nil
}

// Reads a kept part's frames in order as one stream, one frame decrypted at a time.
type searchFrameReader struct {
	source     indexFrameSource
	frame      []byte
	frameIndex int
	frameCount int
}

// A reader over every frame of source.
func searchNewFrameReader(source indexFrameSource) *searchFrameReader {
	return &searchFrameReader{source: source, frameCount: (source.indexLength() + EvsRecordFrameByteCount - 1) / EvsRecordFrameByteCount}
}

// The next byte, reading the next frame when one ends.
func (self *searchFrameReader) ReadByte() (byte, error) {
	for len(self.frame) == 0 {
		if self.frameCount <= self.frameIndex {
			return 0, io.EOF
		}
		frame, err := self.source.indexReadFrame(self.frameIndex, nil)
		if err != nil {
			return 0, err
		}
		self.frame = frame
		self.frameIndex += 1
	}
	b := self.frame[0]
	self.frame = self.frame[1:]
	return b, nil
}

// Streams a kept vocabulary's words and counts in byte order from its frames, holding one frame and one word.
func searchScanVocabulary(source indexFrameSource, settings *SearchResultSettings, visit func(word []byte, count uint32) bool) error {
	return searchReadVocabulary(searchNewFrameReader(source), settings, visit)
}

// Seals the vocabulary as the derived part at key, replacing the copy kept there, so a word an erasure removed is in
// no kept copy. The key names the ref and the root the vocabulary is of; version 0 keeps one copy a root, which each
// save replaces.
func (self *SearchVocabulary) Save(ctx context.Context, cache *SearchCache, key SearchCacheKey) error {
	return cache.PutDerived(ctx, &SearchCacheDerived{Key: key, Part: SearchCachePartVocabulary, Plaintext: self.encode()})
}

// The vocabulary kept at key, or an empty one where none is.
func LoadSearchVocabulary(cache *SearchCache, key SearchCacheKey, settings *SearchResultSettings) (*SearchVocabulary, error) {
	frames, err := cache.OpenDerived(key, SearchCachePartVocabulary)
	if err == ErrSidecarStoreAbsent {
		return NewSearchVocabulary(settings), nil
	}
	if err != nil {
		return nil, err
	}
	encoded, err := frames.ReadAll()
	if err != nil {
		return nil, err
	}
	return searchDecodeVocabulary(encoded, settings)
}
