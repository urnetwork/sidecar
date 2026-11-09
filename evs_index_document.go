// Documents (§11.14's Documents block and never row; protocol/INDEX-FORMAT.md's Documents): what the index holds one
// row and one key set of. A document is a text file's chunk, a mail message's, a record entry, or a document §16.8 or
// §16.11 derives, such as a run card. Its key is
//
//	doc_key = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16]
//
// with K_ref from RK_1 (D-KEYS-22), so keys survive rotations and path epochs, and a rename is a removal and a
// creation. Text past 1 MiB is one document per 1 MiB, each with the next 256 B, so a query of up to 256 B across a
// boundary is found. A chunk whose key set would encode past 512 KiB, which nearly every query would match, is
// skipped.
//
// An index covers only documents every reader of its ref can open, and config, mailcfg and secret repos hold none
// (D-EVS-43), which indexExcluded decides before a version is read.

package sidecar

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// What a document is: a row's first byte and SearchHit.doc_kind.
type IndexDocKind = indexDocKind

const (
	IndexDocFile    IndexDocKind = indexDocFile
	IndexDocMail    IndexDocKind = indexDocMail
	IndexDocRecord  IndexDocKind = indexDocRecord
	IndexDocDerived IndexDocKind = indexDocDerived
)

// A document's chunks: 1 MiB each, and the next 256 B.
const (
	indexChunkByteCount   = 1024 * 1024
	indexOverlapByteCount = 256
)

// doc_key's label, its ASCII bytes.
const indexDocKeyLabel = "UR evs 1.0 doc"

// The longest name doc_key's u16be length can hold.
const indexNameMaxByteCount = 0xFFFF

// One document as its extractor or registered source gives it, before normalization: its fields' values and its
// row's attributes. A file's or message's comes from indexExtractFile or indexExtractMail, a record entry's or
// derived document's from its IndexDocumentSource.
type IndexDocument struct {
	Kind IndexDocKind
	// The path's bytes, or a derived document's registered name (run/ || run_id, a/ || announcement_id).
	Name []byte
	// The chunk of its source, 0 for the first or only.
	Chunk uint32
	// The path's entry version, or a derived document's writer's sequence. The newest version of a key wins.
	Version uint64
	// The source's length in bytes, a whole file's on each of its chunks.
	ByteCount uint64
	// Values by §11.14's number: 1 subject, 2 from, 3 to, 4 title, 5 body, and 6-15 as the class registers them.
	// Index 0 stays empty. A file's title is indexed with its path, and its row shows the title alone.
	Fields [indexFieldLast + 1][]byte
	// From the push's provenance (§16.6).
	Tainted bool
	// Mail from outside the network, or an EvsImport's content.
	Outside bool
	// A directory document's private marker (§16.11).
	Private bool
	// A derived document's times, in seconds; zero on every other kind.
	StartedSeconds uint64
	ExpiresSeconds uint64
}

// One document a chunk of text: every 1 MiB, each with the next 256 B, and one for an empty text.
func indexChunks(text []byte) [][]byte {
	chunks := [][]byte{}
	for start := 0; start == 0 || start < len(text); start += indexChunkByteCount {
		chunks = append(chunks, text[start:min(len(text), start+indexChunkByteCount+indexOverlapByteCount)])
	}
	return chunks
}

// K_ref, from RK_1 at any generation, which doc keys and ref ids derive from. DeriveKey hooks it, and refuses a key
// whose ladder walk has not reached generation 1.
func indexRefKey(repoKey *EvsRepoKey) ([]byte, error) {
	return repoKey.DeriveKey(EvsKeyPurposeRef, nil)
}

// A document's key under K_ref: HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name ||
// u32be(chunk))[:16]. A name past 65,535 B has no key.
func indexDocKey(refKey []byte, refId Id, name []byte, chunk uint32) ([indexIdByteCount]byte, error) {
	if indexNameMaxByteCount < len(name) {
		return [indexIdByteCount]byte{}, indexMalformed("a name past 65,535 B")
	}
	mac := hmac.New(sha256.New, refKey)
	mac.Write([]byte(indexDocKeyLabel))
	mac.Write(refId.Bytes())
	mac.Write(binary.BigEndian.AppendUint16(nil, uint16(len(name))))
	mac.Write(name)
	mac.Write(binary.BigEndian.AppendUint32(nil, chunk))
	return [indexIdByteCount]byte(mac.Sum(nil)[:indexIdByteCount]), nil
}

// The document's fields as normalizer 1 reads them, in number order. A file's title is followed by one space and its
// path, which indexes the path's words with the title's, the reading question
// search-m10-07-extractor-field-placement recommends and SearchOracle takes, pending its answer.
func (self *IndexDocument) textFields() []indexTextField {
	fields := []indexTextField{}
	for number := 1; number <= indexFieldLast; number += 1 {
		value := self.Fields[number]
		if number == indexFieldTitle && self.Kind == IndexDocFile {
			value = append(append(append([]byte{}, value...), ' '), self.Name...)
		}
		if len(value) != 0 {
			fields = append(fields, indexTextField{number: number, text: bytes.NewReader(value)})
		}
	}
	return fields
}

// The document's row, its values cut to the row's caps by fit: the locator is the name, fields 1-4 and the
// registered ones the values shown, and the trigram count n_d. companion puts the ref's id in the row, as ur/index's
// rows carry it.
func (self *IndexDocument) row(trigramCount int, companion bool, refId Id) *indexRow {
	row := &indexRow{
		docKind:      self.Kind,
		byteCount:    self.ByteCount,
		chunk:        uint64(self.Chunk),
		trigramCount: uint64(trigramCount),
		locator:      string(self.Name),
	}
	if self.Tainted {
		row.flags |= indexRowTainted
	}
	if self.Outside {
		row.flags |= indexRowOutside
	}
	if self.Private {
		row.flags |= indexRowPrivate
	}
	if self.Kind == IndexDocDerived {
		row.startedSeconds = self.StartedSeconds
		row.expiresSeconds = self.ExpiresSeconds
	}
	if companion {
		row.refId = refId.Bytes()
	}
	for _, field := range self.Kind.rowFields() {
		row.fields[field] = string(self.Fields[field])
	}
	row.fit()
	return row
}

// What one document indexes as: its key set and row, or skipped, when its key set would encode past 512 KiB.
type indexPreparedDocument struct {
	keys    indexKeySet
	row     *indexRow
	skipped bool
}

// Normalizes the document and builds its key set and row. A skipped chunk holds no key set and no row: its version
// is a tombstone where its key was indexed before, which only the writer knows.
func (self *IndexDocument) prepare(normalizer *indexNormalizer, companion bool, refId Id) (*indexPreparedDocument, error) {
	if err := self.check(); err != nil {
		return nil, err
	}
	keys, err := normalizer.documentKeys(self.textFields())
	if err != nil {
		return nil, err
	}
	if indexKeySetSkipped(keys) {
		return &indexPreparedDocument{skipped: true}, nil
	}
	row := self.row(len(keys), companion, refId)
	if err := row.check(companion); err != nil {
		return nil, err
	}
	return &indexPreparedDocument{keys: keys, row: row}, nil
}

// Whether a chunk with these keys is skipped: its key set would encode past 512 KiB, which nearly every query would
// match (§11.14's sniff row).
func indexKeySetSkipped(keys indexKeySet) bool {
	return indexKeySetMaxByteCount < keys.encodedByteCount()
}

// Refuses what no extractor or source gives: an unknown kind, a name too long for its key, fields its kind does not
// hold, or a derived document's times or private marker on another kind. A registered class's own rules are its
// registry's (IndexFieldRegistry.check).
func (self *IndexDocument) check() error {
	if self.Kind < IndexDocFile || IndexDocDerived < self.Kind {
		return indexMalformed("a document of no kind")
	}
	if indexNameMaxByteCount < len(self.Name) {
		return indexMalformed("a name past 65,535 B")
	}
	if len(self.Fields[0]) != 0 {
		return indexMalformed("a field numbered 0")
	}
	for number := indexFieldBody + 1; number <= indexFieldLast; number += 1 {
		if len(self.Fields[number]) != 0 && !self.Kind.hasRegisteredFields() {
			return indexMalformed("a registered field on a file or message")
		}
	}
	if self.Kind != IndexDocDerived && (self.StartedSeconds != 0 || self.ExpiresSeconds != 0) {
		return indexMalformed("times on a document that is not derived")
	}
	if self.Private && !self.Kind.hasRegisteredFields() {
		return indexMalformed("a private file or message")
	}
	return nil
}

// Where a version sits, as a writer knows it before reading the version (§11.14's never row).
type indexPlace struct {
	repoKind protocol.RepoKind
	// A group inbox: a general repo laid out as a mailbox, whose mail is m/ (§15.7).
	groupInbox bool
	// ur/index, which holds index files and nothing else.
	indexRef bool
	// The path within its ref.
	path string
	// A deposit not yet ingested.
	deposit bool
}

// The mailbox families §15.7 lays out, of which only m/ messages are documents.
const indexMailMessagePrefix = "m/"

// Whether §11.14's never row keeps the version out of the index: config, mailcfg and secret repos, and any repo of no
// kind; .ur-index/ paths and every file on ur/index; a mailbox's or group inbox's every path but m/ (its i/, r/,
// vault/, o/, or/, p/, forward, ra/, f/ and s/model); and deposits before their ingest. Binaries are the sniff's to
// find, once the version is read.
func indexExcluded(place indexPlace) bool {
	switch place.repoKind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET,
		protocol.RepoKind_REPO_KIND_UNSPECIFIED:
		return true
	}
	if place.deposit || place.indexRef {
		return true
	}
	if strings.HasPrefix(place.path, indexFileModePrefix) || place.path == strings.TrimSuffix(indexFileModePrefix, "/") {
		return true
	}
	if place.repoKind == protocol.RepoKind_REPO_KIND_MAILBOX || place.groupInbox {
		return !strings.HasPrefix(place.path, indexMailMessagePrefix)
	}
	return false
}

// Which extractor a version takes: mail for a mailbox's or group inbox's m/ messages, files for the rest.
func indexExtractorKind(place indexPlace) IndexDocKind {
	if (place.repoKind == protocol.RepoKind_REPO_KIND_MAILBOX || place.groupInbox) &&
		strings.HasPrefix(place.path, indexMailMessagePrefix) {
		return IndexDocMail
	}
	return IndexDocFile
}
