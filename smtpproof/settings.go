package smtpproof

import (
	"errors"
	"fmt"
	"strings"
)

// The proofs' own settings (DESIGN-DETAILS 3.2.8; QD-702): the shape catalog and every limit the relation,
// the circuits and the gate share. Each is a protocol value, so its default is the one place it is set,
// and a deployment never changes one on one side alone: a prover and a verifier each carry a value of
// DefaultProofSettings.
//
// This is SMTP-M9-37's first step. The catalog, headerSplit and recordRoleAt read these settings; the
// landed shapes (partShapes) and the constants circuit_message.go, circuit_replies.go and relation.go still
// hold are replaced by them when the unit shapes' circuits land, and until then nothing proves under this
// catalog.

// A shape's kind, as its KeySet name spells it (DESIGN-DETAILS 3.2.6).
type ShapeKind string

const (
	// Part 1: Z1 and the EHLO record.
	ShapeKindKey ShapeKind = "key"
	// A group of envelope commands, with the replies to the group before.
	ShapeKindEnvelope ShapeKind = "env"
	// BDAT's command or DATA's 354, and the header block's first record.
	ShapeKindMessage ShapeKind = "msg"
	// One later header record.
	ShapeKindHeader ShapeKind = "hdr"
	// One DATA body record.
	ShapeKindBody ShapeKind = "body"
)

// A family of circuits: one keystream, whatever the TLS version, but the key part's (3.2.3).
type ShapeFamily string

const (
	// TLS 1.3's AES-128-GCM and both TLS 1.2 AES-128-GCM suites.
	ShapeFamilyAes128Gcm ShapeFamily = "aes128gcm"
	// TLS 1.3's ChaCha20-Poly1305.
	ShapeFamilyChacha20 ShapeFamily = "chacha20"
)

// One shape of the catalog: its kind, family, version for a key shape, and pools in keystream blocks of
// 16 octets (AES-128-GCM) or 64 (ChaCha20).
type ShapeSettings struct {
	Kind   ShapeKind
	Family ShapeFamily
	// A key shape's TLS version, 0x0304 or 0x0303; 0 for every other kind, which serves both.
	Version uint16
	// Blocks of server records, which hold the replies the part covers.
	ServerBlocks int
	// Blocks of command records, BDAT's command and QUIT.
	ClientBlocks int
	// Blocks of the header block's first record (msg) and of a later one (hdr).
	HeadBlocks int
	RestBlocks int
	// Blocks of one DATA body record.
	BodyBlocks int
	// Whether the client blocks carry the local-part table (env).
	Locals bool
}

// The KeySet name, which spells the kind, the version for a key shape, the family and every pool, so a
// changed pool is another name and another key.
func (self *ShapeSettings) Name() string {
	name := []string{string(self.Kind)}
	if self.Version != 0 {
		name = append(name, fmt.Sprintf("v%04x", self.Version))
	}
	name = append(name, string(self.Family))
	for _, pool := range []struct {
		letter string
		blocks int
	}{
		{letter: "s", blocks: self.ServerBlocks},
		{letter: "c", blocks: self.ClientBlocks},
		{letter: "h", blocks: self.HeadBlocks},
		{letter: "r", blocks: self.RestBlocks},
		{letter: "b", blocks: self.BodyBlocks},
	} {
		if 0 < pool.blocks {
			name = append(name, fmt.Sprintf("%s%d", pool.letter, pool.blocks))
		}
	}
	return strings.Join(name, "-")
}

// The octets one keystream block covers.
func (self *ShapeSettings) blockBytes() int {
	if self.Family == ShapeFamilyChacha20 {
		return 64
	}
	return 16
}

// The content octets a pool of blocks holds as one record of the given TLS version: TLS 1.3's inner
// type octet takes one of them.
func (self *ShapeSettings) recordContentBytes(blocks int, version uint16) int {
	contentBytes := blocks * self.blockBytes()
	if version == tlsVersion13 {
		contentBytes -= tlsInnerTypeBytes
	}
	return contentBytes
}

type ProofSettings struct {
	// The catalog of DESIGN-DETAILS 3.2.6, in the order a part takes the first of its kind and family
	// that holds it. Set only here; every shape fills one domain.
	Shapes []*ShapeSettings
	// The points of the domain every shape proves over: 2^20.
	DomainSize int
	// Constraints and public inputs a shape leaves free of the domain: 10,486, 1%.
	DomainHeadroomCount int
	// TLS's record bounds: 16,384 octets of content, 16,640 of ciphertext.
	RecordContentMaxByteCount    int
	RecordCiphertextMaxByteCount int
	// RFC 5321's: a local part of 64 octets, a domain of 255, a label of 63.
	LocalMaxByteCount  int
	DomainMaxByteCount int
	LabelMaxByteCount  int
	// The header block: at most 16,384 octets in at most 16 records, each but the last at least 128
	// octets, longer than any literal Z5 reads, so a literal straddles at most one boundary, and the last
	// at least 4, its final CRLF CRLF.
	HeaderBlockMaxByteCount      int
	HeaderRecordMaxCount         int
	HeaderRecordMinByteCount     int
	HeaderLastRecordMinByteCount int
	// The longest line Z5 reads as a literal, an address in it, and the signature's tags: 124, 93, 93.
	LiteralLineMaxByteCount    int
	LiteralAddressMaxByteCount int
	LiteralTagMaxByteCount     int
	// Octets between a scan's pinned states: 32.
	ScanPinInterval int
	// Recipients a connection holds: §20.4's largest, 100.
	RecipientMaxCount int
	// Parts a connection takes, and client records a part opens: 8,192 and 64.
	PartMaxCount       int
	PartRecordMaxCount int
}

// A fresh value each call.
func DefaultProofSettings() *ProofSettings {
	return &ProofSettings{
		Shapes: []*ShapeSettings{
			{Kind: ShapeKindKey, Family: ShapeFamilyAes128Gcm, Version: tlsVersion13, ClientBlocks: 8},
			{Kind: ShapeKindKey, Family: ShapeFamilyChacha20, Version: tlsVersion13, ClientBlocks: 2},
			{Kind: ShapeKindKey, Family: ShapeFamilyAes128Gcm, Version: tlsVersion12, ClientBlocks: 8},
			{Kind: ShapeKindEnvelope, Family: ShapeFamilyAes128Gcm, ServerBlocks: 40, ClientBlocks: 40, Locals: true},
			{Kind: ShapeKindMessage, Family: ShapeFamilyAes128Gcm, ServerBlocks: 16, ClientBlocks: 4, HeadBlocks: 52},
			{Kind: ShapeKindHeader, Family: ShapeFamilyAes128Gcm, ClientBlocks: 2, RestBlocks: 75},
			{Kind: ShapeKindBody, Family: ShapeFamilyAes128Gcm, ClientBlocks: 2, BodyBlocks: 81},
			{Kind: ShapeKindEnvelope, Family: ShapeFamilyChacha20, ServerBlocks: 19, ClientBlocks: 20, Locals: true},
			{Kind: ShapeKindMessage, Family: ShapeFamilyChacha20, ServerBlocks: 12, ClientBlocks: 2, HeadBlocks: 19},
			{Kind: ShapeKindHeader, Family: ShapeFamilyChacha20, ClientBlocks: 1, RestBlocks: 35},
			{Kind: ShapeKindBody, Family: ShapeFamilyChacha20, ClientBlocks: 2, BodyBlocks: 40},
		},
		DomainSize:                   1024 * 1024,
		DomainHeadroomCount:          10486,
		RecordContentMaxByteCount:    16 * 1024,
		RecordCiphertextMaxByteCount: 16*1024 + 256,
		LocalMaxByteCount:            64,
		DomainMaxByteCount:           255,
		LabelMaxByteCount:            63,
		HeaderBlockMaxByteCount:      16 * 1024,
		HeaderRecordMaxCount:         16,
		HeaderRecordMinByteCount:     128,
		HeaderLastRecordMinByteCount: 4,
		LiteralLineMaxByteCount:      124,
		LiteralAddressMaxByteCount:   93,
		LiteralTagMaxByteCount:       93,
		ScanPinInterval:              32,
		RecipientMaxCount:            100,
		PartMaxCount:                 8192,
		PartRecordMaxCount:           64,
	}
}

// A TLS suite's family: ChaCha20 for 1.3's ChaCha20-Poly1305, AES-128-GCM for every other suite E1 lets
// through.
func suiteFamily(suite uint16) ShapeFamily {
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		return ShapeFamilyChacha20
	}
	return ShapeFamilyAes128Gcm
}

// The first catalog shape of a kind and family, and for a key shape of the version.
func (self *ProofSettings) shape(kind ShapeKind, family ShapeFamily, version uint16) *ShapeSettings {
	for _, shape := range self.Shapes {
		if shape.Kind != kind || shape.Family != family {
			continue
		}
		if kind == ShapeKindKey && shape.Version != version {
			continue
		}
		return shape
	}
	return nil
}

// How the sender cuts a header block of length octets into records, by length alone (DESIGN-DETAILS
// 3.2.4's split): the family's msg shape's head first, then hdr records of its rest, the last moved up
// to HeaderLastRecordMinByteCount from the record before it. The cut tells the edge nothing past the
// length it sees. A block past HeaderBlockMaxByteCount, or one that needs more than HeaderRecordMaxCount
// records, has no cut.
func (self *ProofSettings) headerSplit(length int, family ShapeFamily, version uint16) ([]int, error) {
	message := self.shape(ShapeKindMessage, family, 0)
	header := self.shape(ShapeKindHeader, family, 0)
	if message == nil || header == nil {
		return nil, fmt.Errorf("no msg or hdr shape of family %s", family)
	}
	if length < self.HeaderLastRecordMinByteCount || self.HeaderBlockMaxByteCount < length {
		return nil, fmt.Errorf("a header block of %d octets", length)
	}
	headBytes := message.recordContentBytes(message.HeadBlocks, version)
	restBytes := header.recordContentBytes(header.RestBlocks, version)
	if headBytes < self.HeaderRecordMinByteCount || restBytes < self.HeaderRecordMinByteCount {
		return nil, errors.New("the shapes' header records are shorter than a record must be")
	}
	if length <= headBytes {
		return []int{length}, nil
	}
	sizes := []int{headBytes}
	left := length - headBytes
	for restBytes < left {
		sizes = append(sizes, restBytes)
		left -= restBytes
	}
	sizes = append(sizes, left)
	if short := self.HeaderLastRecordMinByteCount - left; 0 < short {
		sizes[len(sizes)-2] -= short
		sizes[len(sizes)-1] += short
	}
	if self.HeaderRecordMaxCount < len(sizes) {
		return nil, fmt.Errorf("a header block of %d octets takes %d records", length, len(sizes))
	}
	return sizes, nil
}

// Whether a cut is one the edge accepts (DESIGN-DETAILS 3.2.4): 1 to HeaderRecordMaxCount records, every
// one but the last at least HeaderRecordMinByteCount octets, the last at least
// HeaderLastRecordMinByteCount.
func (self *ProofSettings) headerCutAccepted(sizes []int) bool {
	if len(sizes) == 0 || self.HeaderRecordMaxCount < len(sizes) {
		return false
	}
	for i, size := range sizes {
		minimum := self.HeaderRecordMinByteCount
		if i == len(sizes)-1 {
			minimum = self.HeaderLastRecordMinByteCount
		}
		if size < minimum {
			return false
		}
	}
	return true
}

// A client record's role from its position alone (DESIGN-DETAILS 3.2.5's table), offset counting from
// the first application record f: EHLO, MAIL, recipientCount RCPTs, then BDAT's command or DATA, then
// headerRecordCount header records, then body. Body is BDAT's unopened chunk or DATA's records; the end
// mark and QUIT are the last part's to name, at the end of what it opens. headerRecordCount is 0 until
// the part that opens the header block's first record has named it.
func recordRoleAt(offset uint64, recipientCount uint32, mode uint32, headerRecordCount uint32) (recordRole, error) {
	envelopeEnd := 2 + uint64(recipientCount)
	switch {
	case recipientCount == 0:
		return 0, errors.New("a transaction names at least one recipient")
	case offset == 0:
		return recordRoleEhlo, nil
	case offset == 1:
		return recordRoleMail, nil
	case offset < envelopeEnd:
		return recordRoleRcpt, nil
	case offset == envelopeEnd && mode == partModeBdat:
		return recordRoleBdat, nil
	case offset == envelopeEnd && mode == partModeData:
		return recordRoleData, nil
	case offset == envelopeEnd:
		return 0, fmt.Errorf("mode %d has no record at the envelope's end", mode)
	case headerRecordCount == 0:
		return 0, errors.New("no header record count is named yet")
	case offset <= envelopeEnd+uint64(headerRecordCount):
		return recordRoleHeaderBlock, nil
	default:
		return recordRoleBody, nil
	}
}
