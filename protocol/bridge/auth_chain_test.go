// §7.9's chain. The vectors in testdata/config/chain.json were built from the formula by hand, not by this code, and read
// again by a second implementation in another language, so a digest that drifted from §7.9 fails them.

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const testChainVectorsPath = "../../testdata/config/chain.json"

type testChainEntry struct {
	N          uint64 `json:"n"`
	Kind       uint32 `json:"kind"`
	TimeMs     int64  `json:"time_ms"`
	PrevChain  string `json:"prev_chain"`
	Body       string `json:"body"`
	BodySha256 string `json:"body_sha256"`
	Preimage   string `json:"preimage"`
	Chain      string `json:"chain"`
	Entry      string `json:"entry"`
}

type testChainVectors struct {
	Genesis struct {
		Signed string `json:"signed"`
		Chain  string `json:"chain"`
	} `json:"genesis"`
	Entries []testChainEntry `json:"entries"`
	Edges   []testChainEntry `json:"edges"`
}

func testReadChainVectors(t *testing.T) *testChainVectors {
	encoded, err := os.ReadFile(testChainVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testChainVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	// A file that lost its rows would pass every loop below.
	if len(vectors.Entries) == 0 || len(vectors.Edges) == 0 {
		t.Fatalf("%d entries, %d edges", len(vectors.Entries), len(vectors.Edges))
	}
	return vectors
}

// One row's digest, checked against the row.
func testCheckChainRow(t *testing.T, row testChainEntry) {
	got, err := AuthChainDigest(row.N, testFromHex(t, row.PrevChain), row.Kind, row.TimeMs, testFromHex(t, row.Body))
	if err != nil {
		t.Fatalf("n %d: %v", row.N, err)
	}
	if hex.EncodeToString(got[:]) != row.Chain {
		t.Errorf("n %d: got %x, want %s", row.N, got, row.Chain)
	}
}

func TestAuthChainDigestLayout(t *testing.T) {
	prevChain := bytes.Repeat([]byte{0x41}, sha256.Size)
	body := []byte("body")
	bodySha256 := sha256.Sum256(body)

	want := []byte("urnetwork-sidecar-v1/auth-log")
	want = append(want, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
	want = append(want, prevChain...)
	want = append(want, 0x00, 0x00, 0x00, 0x02)
	want = append(want, 0x00, 0x00, 0x01, 0x8B, 0xCF, 0xE5, 0x68, 0x00)
	want = append(want, bodySha256[:]...)
	wantDigest := sha256.Sum256(want)

	got, err := AuthChainDigest(0x0102030405060708, prevChain, AuthEntryKindStatement, 1700000000000, body)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantDigest {
		t.Errorf("got %x, want %x", got, wantDigest)
	}
}

// One small log, each entry on the digest before it, starting from the genesis it names.
func TestAuthChainDigestFollowsTheVectors(t *testing.T) {
	vectors := testReadChainVectors(t)
	chain := GenesisChain(testFromHex(t, vectors.Genesis.Signed))
	if hex.EncodeToString(chain[:]) != vectors.Genesis.Chain {
		t.Fatalf("A_0 is %x, want %s", chain, vectors.Genesis.Chain)
	}
	for _, row := range vectors.Entries {
		if hex.EncodeToString(chain[:]) != row.PrevChain {
			t.Fatalf("n %d does not follow %x", row.N, chain)
		}
		testCheckChainRow(t, row)
		copy(chain[:], testFromHex(t, row.Chain))
	}
}

// Each field's width and byte order at its extremes, negative times included.
func TestAuthChainDigestFollowsTheEdges(t *testing.T) {
	for _, row := range testReadChainVectors(t).Edges {
		testCheckChainRow(t, row)
	}
}

// The width is all that keeps prev_chain from its neighbors, and a received prev_chain can be any length.
func TestAuthChainDigestRefusesOtherPrevChainSizes(t *testing.T) {
	for _, size := range []int{0, 1, sha256.Size - 1, sha256.Size + 1, 2 * sha256.Size} {
		_, err := AuthChainDigest(1, make([]byte, size), AuthEntryKindBase, 1, nil)
		if !errors.Is(err, ErrAuthChainSize) {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
	if _, err := AuthChainDigest(1, nil, AuthEntryKindBase, 1, nil); !errors.Is(err, ErrAuthChainSize) {
		t.Errorf("nil: %v", err)
	}
}

func TestAuthChainDigestCoversEveryField(t *testing.T) {
	prevChain := bytes.Repeat([]byte{0x41}, sha256.Size)
	otherPrevChain := bytes.Repeat([]byte{0x42}, sha256.Size)
	digest := func(n uint64, prev []byte, kind uint32, timeMs int64, body []byte) [sha256.Size]byte {
		got, err := AuthChainDigest(n, prev, kind, timeMs, body)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	base := digest(7, prevChain, AuthEntryKindStatement, 9, []byte("body"))
	cases := []struct {
		name   string
		digest [sha256.Size]byte
	}{
		{name: "n", digest: digest(8, prevChain, AuthEntryKindStatement, 9, []byte("body"))},
		{name: "prev_chain", digest: digest(7, otherPrevChain, AuthEntryKindStatement, 9, []byte("body"))},
		{name: "kind", digest: digest(7, prevChain, AuthEntryKindTick, 9, []byte("body"))},
		{name: "time_ms", digest: digest(7, prevChain, AuthEntryKindStatement, 10, []byte("body"))},
		{name: "body", digest: digest(7, prevChain, AuthEntryKindStatement, 9, []byte("bodz"))},
	}
	for _, c := range cases {
		if c.digest == base {
			t.Errorf("%s is not covered", c.name)
		}
	}
}

// A received entry's fields are what it hashes: its encoding, kept verbatim, decodes to the row, and encodes the same
// way again on any leg.
func TestAuthEntryVectorsAreByteEqual(t *testing.T) {
	for _, row := range testReadChainVectors(t).Entries {
		encoded := testFromHex(t, row.Entry)
		entry := &AuthEntry{}
		if err := proto.Unmarshal(encoded, entry); err != nil {
			t.Fatalf("n %d: %v", row.N, err)
		}
		if entry.GetN() != row.N || entry.GetKind() != row.Kind || entry.GetTimeMs() != row.TimeMs ||
			!bytes.Equal(entry.GetPrevChain(), testFromHex(t, row.PrevChain)) ||
			!bytes.Equal(entry.GetBody(), testFromHex(t, row.Body)) {
			t.Errorf("n %d decoded to %v", row.N, entry)
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, encoded) {
			t.Errorf("n %d encoded differently", row.N)
		}
	}
}

// Another wrapper around a genesis is another A_0, so it misses the anchor: unlike a statement's id, nothing here keys
// a repeat, and the stricter reading is the closed one.
func TestGenesisChainHashesTheBytesAsReceived(t *testing.T) {
	body := []byte("a genesis body")
	seed := bytes.Repeat([]byte{0x5A}, ed25519.SeedSize)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), SignedBytes(SignedPurposeAuthority, SignedType_SIGNED_GENESIS, body))
	encoded, err := proto.Marshal(&Signed{Body: body, Signature: signature, Type: uint32(SignedType_SIGNED_GENESIS)})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(encoded)
	if got := GenesisChain(encoded); got != want {
		t.Fatalf("got %x, want %x", got, want)
	}
	rewrapped := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(encoded), 100, protowire.BytesType), []byte("x"))
	if GenesisChain(rewrapped) == want {
		t.Error("another wrapper kept its anchor")
	}
}

// These are §7.9's numbers and §6.11's purposes, and both reach signed bytes, so a change here is a change to the wire.
func TestAuthEntryKindsAndPurposesStable(t *testing.T) {
	if AuthEntryKindBase != 1 || AuthEntryKindStatement != 2 || AuthEntryKindTick != 3 {
		t.Errorf("kinds %d, %d, %d", AuthEntryKindBase, AuthEntryKindStatement, AuthEntryKindTick)
	}
	if SignedPurposeAuthority != "authority" || SignedPurposeAcl != "acl" || SignedPurposeBridge != "bridge" {
		t.Errorf("purposes %q, %q, %q", SignedPurposeAuthority, SignedPurposeAcl, SignedPurposeBridge)
	}
	preimage := binary.BigEndian.AppendUint32([]byte("urnetwork-sidecar-v1/authority\x00"), uint32(SignedType_SIGNED_GENESIS))
	if !bytes.Equal(SignedBytes(SignedPurposeAuthority, SignedType_SIGNED_GENESIS, nil), preimage) {
		t.Error("the purpose does not reach the signed bytes as written")
	}
}
