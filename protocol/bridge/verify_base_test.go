// The keyless device role's base check: one base that passes, and each of §7.9's keyless checks failing alone.

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
)

// The config writer's key in these tests.
var testBaseKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

// A base's parts, each a test may change before building its entry.
type testBase struct {
	header *ProjectionHeader
	rows   []byte
	kind   uint32
	n      uint64
	prev   []byte
	key    ed25519.PrivateKey
	// the type the Signed claims
	signedType SignedType
}

// A base at position 9 over 64 bytes of rows, after a previous base at config version 3 folded through 5.
func newTestBase() *testBase {
	rows := bytes.Repeat([]byte{0x07}, 64)
	rowsSha256 := sha256.Sum256(rows)
	prev := bytes.Repeat([]byte{0x11}, sha256.Size)
	return &testBase{
		header: &ProjectionHeader{
			NetworkId: bytes.Repeat([]byte{0x01}, 16), Version: 9, PrevChain: prev, FoldedThrough: 6,
			ConfigVersion: 4, ConfigHeadSha256: bytes.Repeat([]byte{0x22}, sha256.Size),
			RowsSha256: rowsSha256[:], RowsByteCount: uint32(len(rows)), Threshold: 2,
		},
		rows: rows, kind: AuthEntryKindBase, n: 9, prev: prev, key: testBaseKey, signedType: SignedType_SIGNED_PROJECTION_HEADER,
	}
}

// The previous base the checks compare against.
func testPreviousBase() *ProjectionHeader {
	return &ProjectionHeader{ConfigVersion: 3, FoldedThrough: 5}
}

// The entry, its header signed by key under its claimed type.
func (self *testBase) entry(t *testing.T) *AuthEntry {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(self.header)
	if err != nil {
		t.Fatal(err)
	}
	signed := &Signed{
		Body:      body,
		Signature: ed25519.Sign(self.key, SignedBytes(SignedPurposeAuthority, self.signedType, body)),
		Type:      uint32(self.signedType),
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return &AuthEntry{NetworkId: bytes.Repeat([]byte{0x01}, 16), N: self.n, PrevChain: self.prev, Kind: self.kind, TimeMs: 1, Body: signedBytes}
}

func TestVerifyBaseKeylessPassesABase(t *testing.T) {
	base := newTestBase()
	header, err := VerifyBaseKeyless(base.entry(t), testBaseKey.Public().(ed25519.PublicKey), base.rows, testPreviousBase())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(header, base.header) {
		t.Errorf("got %v", header)
	}
	if _, err := VerifyBaseKeyless(base.entry(t), testBaseKey.Public().(ed25519.PublicKey), base.rows, nil); err != nil {
		t.Errorf("base 1 has no previous: %v", err)
	}
}

// Each keyless check, failing alone.
func TestVerifyBaseKeylessRefusesEachCheck(t *testing.T) {
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	cases := []struct {
		name   string
		mutate func(base *testBase)
	}{
		{name: "a statement's kind", mutate: func(base *testBase) { base.kind = AuthEntryKindStatement }},
		{name: "another signer", mutate: func(base *testBase) { base.key = otherKey }},
		{name: "another type", mutate: func(base *testBase) { base.signedType = SignedType_SIGNED_ADMIN_SET }},
		{name: "another network", mutate: func(base *testBase) { base.header.NetworkId = bytes.Repeat([]byte{0x02}, 16) }},
		{name: "another version", mutate: func(base *testBase) { base.header.Version = 10 }},
		{name: "another prev_chain", mutate: func(base *testBase) { base.header.PrevChain = bytes.Repeat([]byte{0x12}, sha256.Size) }},
		{name: "a fold at its own position", mutate: func(base *testBase) { base.header.FoldedThrough = 9 }},
		{name: "rows that miss their hash", mutate: func(base *testBase) { base.rows = append(bytes.Clone(base.rows[:63]), 0x08) }},
		{name: "another byte count", mutate: func(base *testBase) { base.header.RowsByteCount = 63 }},
		{name: "an older config head", mutate: func(base *testBase) { base.header.ConfigVersion = 2 }},
		{name: "a lower fold", mutate: func(base *testBase) { base.header.FoldedThrough = 4 }},
	}
	for _, c := range cases {
		base := newTestBase()
		c.mutate(base)
		if _, err := VerifyBaseKeyless(base.entry(t), testBaseKey.Public().(ed25519.PublicKey), base.rows, testPreviousBase()); !errors.Is(err, ErrBaseRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Rows over 4 MiB are refused whatever their hash says.
func TestVerifyBaseKeylessRefusesRowsOver4MiB(t *testing.T) {
	base := newTestBase()
	base.rows = make([]byte, baseRowsMaxByteCount+1)
	rowsSha256 := sha256.Sum256(base.rows)
	base.header.RowsSha256, base.header.RowsByteCount = rowsSha256[:], uint32(len(base.rows))
	if _, err := VerifyBaseKeyless(base.entry(t), testBaseKey.Public().(ed25519.PublicKey), base.rows, testPreviousBase()); !errors.Is(err, ErrBaseRefused) {
		t.Errorf("got %v", err)
	}
}

// The digest form passes what the rows form passes and refuses a digest or byte count off by one, so a streaming
// caller is held to the same checks.
func TestVerifyBaseKeylessDigestHoldsTheRowsForm(t *testing.T) {
	base := newTestBase()
	rowsSha256 := sha256.Sum256(base.rows)
	key := testBaseKey.Public().(ed25519.PublicKey)
	header, err := VerifyBaseKeylessDigest(base.entry(t), key, rowsSha256[:], int64(len(base.rows)), testPreviousBase())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(header, base.header) {
		t.Errorf("got %v", header)
	}
	otherSha256 := bytes.Clone(rowsSha256[:])
	otherSha256[0] ^= 0x01
	if _, err := VerifyBaseKeylessDigest(base.entry(t), key, otherSha256, int64(len(base.rows)), testPreviousBase()); !errors.Is(err, ErrBaseRefused) {
		t.Errorf("another digest: %v", err)
	}
	if _, err := VerifyBaseKeylessDigest(base.entry(t), key, rowsSha256[:], int64(len(base.rows))-1, testPreviousBase()); !errors.Is(err, ErrBaseRefused) {
		t.Errorf("another byte count: %v", err)
	}
	if _, err := VerifyBaseKeylessDigest(base.entry(t), key, rowsSha256[:], -1, testPreviousBase()); !errors.Is(err, ErrBaseRefused) {
		t.Errorf("a negative byte count: %v", err)
	}
}
