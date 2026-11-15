package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A share's code and its two networks, fixed for the tests.
func testBridgeShareSeal(t testing.TB) (*BridgeShareSeal, Id, Id) {
	t.Helper()
	x, y := testConfigId("sharing network"), testConfigId("accepting network")
	seal, err := NewBridgeShareSeal(bytes.Repeat([]byte{0x5c}, bridgeShareCodeByteCount), x, nil)
	if err != nil {
		t.Fatal(err)
	}
	return seal, x, y
}

// A target table of count targets, each a /24 of 192.168.<i>.0 at its own host.
func testBridgeShareTargets(lengths ...uint32) *bridge.BridgeShareTargets {
	targets := &bridge.BridgeShareTargets{}
	for i, length := range lengths {
		address := testBridgeIpv4(192, 168, byte(i), 0)
		if length == 32 {
			address = testBridgeIpv4(100, 80, 3, byte(7+i))
		}
		if length < 24 {
			address = testBridgeIpv4(10, byte(i), 0, 0) & bridgePrefixMask(length)
		}
		targets.Targets = append(targets.Targets, &bridge.BridgeShareTarget{
			Index: uint32(i), HostSidecarId: testConfigId("share host").Bytes(),
			HostIdentityPublicKey: bytes.Repeat([]byte{byte(0x40 + i)}, ed25519.PublicKeySize),
			Prefix:                &bridge.BridgeIpv4Prefix{Address: address, Length: length},
		})
	}
	return targets
}

// Each label's body seals and opens whole under K, at its networks and version, padded to the multiple, and the pad
// never reaches the opened body.
func TestBridgeShareSealRoundTripsEachLabel(t *testing.T) {
	seal, _, y := testBridgeShareSeal(t)
	for label, body := range map[BridgeShareLabel]proto.Message{
		BridgeShareLabelTargets:   testBridgeShareTargets(24, 32),
		BridgeShareLabelAliases:   &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: 0x8000, Length: 24}}},
		BridgeShareLabelShareKey:  &bridge.BridgeShareKeyBody{SharePublicKey: bytes.Repeat([]byte{7}, ed25519.PublicKeySize)},
		BridgeShareLabelShortfall: &bridge.BridgeShareShortfall{Index: 2, Length: 18, FreeAddressCount: 900, LargestFreeLength: 23},
	} {
		accepting := y
		if label == BridgeShareLabelTargets {
			accepting = Id{}
		}
		sealed, err := seal.Seal(label, accepting, 1, body, nil)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if plainByteCount := len(sealed) - 24 - 16; plainByteCount == 0 || plainByteCount%256 != 0 {
			t.Errorf("%s: a body of %d bytes is not padded to 256", label, plainByteCount)
		}
		opened := bridgeShareBodyOf(label)
		if err := seal.Open(label, accepting, 1, sealed, opened); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !proto.Equal(opened, body) {
			t.Errorf("%s: opened %v", label, opened)
		}
	}
}

// A seal opens only as what it was sealed as: another share's key or network, another label, another version, the
// accepting network changed, and a flipped bit are each refused, with no fallback (§17.9's open row).
func TestBridgeShareSealRefusesWhatItDidNotSeal(t *testing.T) {
	seal, x, y := testBridgeShareSeal(t)
	aliases := &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: 0x8000, Length: 24}}}
	sealed, err := seal.Seal(BridgeShareLabelAliases, y, 1, aliases, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherCode, _ := NewBridgeShareSeal(bytes.Repeat([]byte{0x5d}, bridgeShareCodeByteCount), x, nil)
	otherNetwork, _ := NewBridgeShareSeal(bytes.Repeat([]byte{0x5c}, bridgeShareCodeByteCount), testConfigId("another sharing network"), nil)
	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-20] ^= 0x01
	nonce := bytes.Clone(sealed)
	nonce[3] ^= 0x80
	for name, open := range map[string]func() error{
		"another share's code": func() error {
			return otherCode.Open(BridgeShareLabelAliases, y, 1, sealed, &bridge.BridgeShareAliases{})
		},
		"another sharing network": func() error {
			return otherNetwork.Open(BridgeShareLabelAliases, y, 1, sealed, &bridge.BridgeShareAliases{})
		},
		"another accepting network": func() error {
			return seal.Open(BridgeShareLabelAliases, testConfigId("a third network"), 1, sealed, &bridge.BridgeShareAliases{})
		},
		"another version": func() error { return seal.Open(BridgeShareLabelAliases, y, 2, sealed, &bridge.BridgeShareAliases{}) },
		"another label":   func() error { return seal.Open(BridgeShareLabelShareKey, y, 1, sealed, &bridge.BridgeShareKeyBody{}) },
		"a flipped bit":   func() error { return seal.Open(BridgeShareLabelAliases, y, 1, flipped, &bridge.BridgeShareAliases{}) },
		"a changed nonce": func() error { return seal.Open(BridgeShareLabelAliases, y, 1, nonce, &bridge.BridgeShareAliases{}) },
		"a short value": func() error {
			return seal.Open(BridgeShareLabelAliases, y, 1, sealed[:30], &bridge.BridgeShareAliases{})
		},
	} {
		if err := open(); !errors.Is(err, ErrBridgeShareSeal) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := seal.Open(BridgeShareLabelAliases, y, 1, sealed, &bridge.BridgeShareAliases{}); err != nil {
		t.Fatalf("as sealed: %v", err)
	}
}

// The seal refuses what is not its own to seal: a label it does not know, a body of another label, targets naming an
// accepting network or any other body naming none, a version of 0, a short code, and no sharing network.
func TestBridgeShareSealRefusesWhatIsNotItsToSeal(t *testing.T) {
	seal, x, y := testBridgeShareSeal(t)
	targets := testBridgeShareTargets(24)
	for name, err := range map[string]error{
		"an unknown label":          bridgeShareSealError(seal.Seal("routes", y, 1, targets, nil)),
		"a body of another label":   bridgeShareSealError(seal.Seal(BridgeShareLabelAliases, y, 1, targets, nil)),
		"targets for an accepter":   bridgeShareSealError(seal.Seal(BridgeShareLabelTargets, y, 1, targets, nil)),
		"aliases for no accepter":   bridgeShareSealError(seal.Seal(BridgeShareLabelAliases, Id{}, 1, &bridge.BridgeShareAliases{}, nil)),
		"a version of 0":            bridgeShareSealError(seal.Seal(BridgeShareLabelTargets, Id{}, 0, targets, nil)),
		"a short code":              bridgeShareSealError(NewBridgeShareSeal(make([]byte, 16), x, nil)),
		"no sharing network":        bridgeShareSealError(NewBridgeShareSeal(make([]byte, 32), Id{}, nil)),
		"a short table key":         bridgeShareSealError(NewBridgeShareSealOfKey(make([]byte, 16), x, nil)),
		"a table key of no network": bridgeShareSealError(NewBridgeShareSealOfKey(make([]byte, 32), Id{}, nil)),
	} {
		if !errors.Is(err, ErrBridgeShareSealInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func bridgeShareSealError(_ any, err error) error {
	return err
}

// K is what the code derives and nothing else: the seal over K itself, as X's config holds it, opens what the code's
// seal sealed, and every body's size lands on the multiple whatever its length.
func TestBridgeShareSealOfItsKeyOpensTheCodes(t *testing.T) {
	seal, x, y := testBridgeShareSeal(t)
	ofKey, err := NewBridgeShareSealOfKey(seal.TableKey(), x, nil)
	if err != nil {
		t.Fatal(err)
	}
	for count := 1; count <= 40; count += 1 {
		aliases := &bridge.BridgeShareAliases{}
		for i := range count {
			aliases.Aliases = append(aliases.Aliases, &bridge.BridgeShareAlias{Index: uint32(i), AliasHostBits: 0x8000 + uint32(i)*256, Length: 24})
		}
		sealed, err := seal.Seal(BridgeShareLabelAliases, y, uint64(count), aliases, nil)
		if err != nil {
			t.Fatal(err)
		}
		if (len(sealed)-40)%256 != 0 {
			t.Fatalf("%d aliases: a body of %d bytes", count, len(sealed)-40)
		}
		opened := &bridge.BridgeShareAliases{}
		if err := ofKey.Open(BridgeShareLabelAliases, y, uint64(count), sealed, opened); err != nil || !proto.Equal(opened, aliases) {
			t.Fatalf("%d aliases: %v", count, err)
		}
	}
}

// One vector a label, in testdata/bridge/share/vectors.json: the code, both networks, the version, the nonce and the
// body give the sealed bytes, and the sealed bytes open to the body.
type testBridgeShareVector struct {
	Label               string `json:"label"`
	CodeHex             string `json:"code_hex"`
	SharingNetworkHex   string `json:"sharing_network_id_hex"`
	AcceptingNetworkHex string `json:"accepting_network_id_hex"`
	Version             uint64 `json:"version"`
	NonceHex            string `json:"nonce_hex"`
	BodyHex             string `json:"body_hex"`
	TableKeyHex         string `json:"table_key_hex"`
	SealedHex           string `json:"sealed_hex"`
}

const testBridgeShareVectorsPath = "testdata/bridge/share/vectors.json"

// The vectors' inputs, as the test writes them when SIDECAR_WRITE_BRIDGE_SHARE_VECTORS is set.
func testBridgeShareVectorInputs() []struct {
	label BridgeShareLabel
	body  proto.Message
} {
	return []struct {
		label BridgeShareLabel
		body  proto.Message
	}{
		{label: BridgeShareLabelTargets, body: testBridgeShareTargets(24, 32)},
		{label: BridgeShareLabelAliases, body: &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: 0x8000, Length: 24}, {Index: 1, AliasHostBits: 0x8101, Length: 32}}}},
		{label: BridgeShareLabelShareKey, body: &bridge.BridgeShareKeyBody{SharePublicKey: bytes.Repeat([]byte{7}, ed25519.PublicKeySize)}},
		{label: BridgeShareLabelShortfall, body: &bridge.BridgeShareShortfall{Index: 2, Length: 18, FreeAddressCount: 900, LargestFreeLength: 23}},
	}
}

func TestBridgeShareSealMatchesItsVectors(t *testing.T) {
	code := bytes.Repeat([]byte{0x5c}, bridgeShareCodeByteCount)
	x, y := testConfigId("sharing network"), testConfigId("accepting network")
	if os.Getenv("SIDECAR_WRITE_BRIDGE_SHARE_VECTORS") != "" {
		seal, err := NewBridgeShareSeal(code, x, nil)
		if err != nil {
			t.Fatal(err)
		}
		vectors := []testBridgeShareVector{}
		for i, input := range testBridgeShareVectorInputs() {
			accepting := y
			if input.label == BridgeShareLabelTargets {
				accepting = Id{}
			}
			nonce := bytes.Repeat([]byte{byte(0xa0 + i)}, 24)
			sealed, err := seal.Seal(input.label, accepting, uint64(i+1), input.body, bytes.NewReader(nonce))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(input.body)
			vectors = append(vectors, testBridgeShareVector{
				Label: string(input.label), CodeHex: hex.EncodeToString(code), SharingNetworkHex: hex.EncodeToString(x.Bytes()),
				AcceptingNetworkHex: hex.EncodeToString(accepting.Bytes()), Version: uint64(i + 1), NonceHex: hex.EncodeToString(nonce),
				BodyHex: hex.EncodeToString(body), TableKeyHex: hex.EncodeToString(seal.TableKey()), SealedHex: hex.EncodeToString(sealed),
			})
		}
		encoded, _ := json.MarshalIndent(vectors, "", "  ")
		if err := os.WriteFile(testBridgeShareVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "js" {
		t.Skip("a Worker has no files: the native legs read the vectors")
	}
	encoded, err := os.ReadFile(testBridgeShareVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := []testBridgeShareVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatalf("%d vectors, not one a label", len(vectors))
	}
	unhex := func(encoded string) []byte {
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for _, vector := range vectors {
		label := BridgeShareLabel(vector.Label)
		sharing, _ := IdFromBytes(unhex(vector.SharingNetworkHex))
		accepting, _ := IdFromBytes(unhex(vector.AcceptingNetworkHex))
		seal, err := NewBridgeShareSeal(unhex(vector.CodeHex), sharing, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(seal.TableKey(), unhex(vector.TableKeyHex)) {
			t.Errorf("%s: the code derives another key", label)
		}
		body := bridgeShareBodyOf(label)
		if err := proto.Unmarshal(unhex(vector.BodyHex), body); err != nil {
			t.Fatal(err)
		}
		sealed, err := seal.Seal(label, accepting, vector.Version, body, bytes.NewReader(unhex(vector.NonceHex)))
		if err != nil || !bytes.Equal(sealed, unhex(vector.SealedHex)) {
			t.Errorf("%s: sealed otherwise: %v", label, err)
		}
		opened := bridgeShareBodyOf(label)
		if err := seal.Open(label, accepting, vector.Version, unhex(vector.SealedHex), opened); err != nil || !proto.Equal(opened, body) {
			t.Errorf("%s: the vector does not open to its body: %v", label, err)
		}
		// each vector refuses the next one's label and version
		if err := seal.Open(label, accepting, vector.Version+1, unhex(vector.SealedHex), bridgeShareBodyOf(label)); !errors.Is(err, ErrBridgeShareSeal) {
			t.Errorf("%s: opened at another version: %v", label, err)
		}
	}
}
