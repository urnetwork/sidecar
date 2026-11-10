package sidecar

// CORE-M2-05's recovery code: the embedded list is BIP-39's, the 12-word codec meets BIP-39's own vectors, and
// testdata/recovery/ pins a code to both public keys and a genesis_sig, byte-equal on every leg (QD-010).
//
//	SIDECAR_REGENERATE_RECOVERY_VECTORS=1 go test -run '^TestRecoveryVectors$' .
//
// writes the vectors while the file holds none, and never changes one already there: a printed code outlives any
// software. The file is embedded, since the Worker leg has no files.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The list is bitcoin/bips' bip-0039/english.txt, word for word, in its order.
func TestRecoveryWordListIsBip39(t *testing.T) {
	words := recoveryWordList()
	if len(words) != recoveryWordCount {
		t.Fatalf("%d words", len(words))
	}
	digest := sha256.Sum256([]byte(strings.Join(words, "\n") + "\n"))
	if hex.EncodeToString(digest[:]) != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Errorf("the list's hash is %x", digest)
	}
	for index, word := range words {
		if len(word) < 3 || 8 < len(word) || (0 < index && word <= words[index-1]) {
			t.Fatalf("word %d %q", index, word)
		}
	}
}

// BIP-39's own test vectors for 128 bits (trezor/python-mnemonic's vectors.json): entropy to words and back.
func TestRecoveryCodeBip39Vectors(t *testing.T) {
	vectors := [][2]string{
		{"00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
		{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"},
		{"80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
		{"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
		{"9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"},
		{"77c2b00716cec7213839159e404db50d", "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge"},
		{"0460ef47585604c5660618db2e6a7e7f", "afford alter spike radar gate glance object seek swamp infant panel yellow"},
		{"18ab19a9f54a9274f03e5209a2ac8a91", "board flee heavy tunnel powder denial science ski answer betray cargo cat"},
	}
	for _, vector := range vectors {
		entropy, _ := hex.DecodeString(vector[0])
		code, err := NewRecoveryCode(bytes.NewReader(entropy))
		if err != nil {
			t.Fatal(err)
		}
		words, err := code.Words()
		if err != nil || strings.Join(words, " ") != vector[1] {
			t.Errorf("%s encodes to %q, %v", vector[0], strings.Join(words, " "), err)
		}
		parsed, err := ParseRecoveryCode("  " + strings.ToUpper(vector[1]) + "\n")
		if err != nil || !bytes.Equal(parsed.entropy[:], entropy) {
			t.Errorf("%q does not parse to its entropy: %v", vector[1], err)
		}
	}
}

// A count that is not 12, a word no list holds and a failed checksum each refuse at entry, and no error repeats what
// was typed.
func TestRecoveryCodeRefusesBadEntry(t *testing.T) {
	good := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	cases := []struct {
		text string
		want error
	}{
		{text: "", want: ErrRecoveryCodeWords},
		{text: strings.TrimSuffix(good, " yellow"), want: ErrRecoveryCodeWords},
		{text: good + " yellow", want: ErrRecoveryCodeWords},
		{text: strings.Replace(good, "sausage", "sausagez", 1), want: ErrRecoveryCodeWords},
		{text: strings.Replace(good, "yellow", "year", 1), want: ErrRecoveryCodeChecksum},
		// two words changed places
		{text: "winner legal thank year wave sausage worth useful legal winner thank yellow", want: ErrRecoveryCodeChecksum},
	}
	for _, testCase := range cases {
		_, err := ParseRecoveryCode(testCase.text)
		if !errors.Is(err, testCase.want) {
			t.Errorf("%q: %v", testCase.text, err)
		}
		if err != nil && testCase.text != "" && strings.Contains(err.Error(), "sausage") {
			t.Errorf("the error repeats the entry: %v", err)
		}
	}
}

// One vector of testdata/recovery/vectors.json.
type recoveryVector struct {
	Entropy          string `json:"entropy"`
	Words            string `json:"words"`
	Ed25519PublicKey string `json:"ed25519_public_key"`
	KeySha256        string `json:"key_sha256"`
	XwingPublicKey   string `json:"xwing_public_key"`
	NetworkId        string `json:"network_id"`
	GenesisSha256    string `json:"genesis_sha256"`
	GenesisSig       string `json:"genesis_sig"`
}

const recoveryVectorsPath = "testdata/recovery/vectors.json"

//go:embed testdata/recovery/vectors.json
var recoveryVectorsJson []byte

// What the derivation gives for one entropy, as a vector.
func deriveRecoveryVector(t *testing.T, entropy []byte, networkId Id, genesisSha256 []byte) recoveryVector {
	t.Helper()
	code, err := NewRecoveryCode(bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	words, err := code.Words()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	genesisSig, err := keys.SignGenesis(networkId, genesisSha256)
	if err != nil {
		t.Fatal(err)
	}
	return recoveryVector{
		Entropy:          hex.EncodeToString(entropy),
		Words:            strings.Join(words, " "),
		Ed25519PublicKey: hex.EncodeToString(keys.Ed25519PublicKey()),
		KeySha256:        hex.EncodeToString(keys.KeySha256()),
		XwingPublicKey:   hex.EncodeToString(keys.XwingPublicKey()),
		NetworkId:        hex.EncodeToString(networkId.Bytes()),
		GenesisSha256:    hex.EncodeToString(genesisSha256),
		GenesisSig:       hex.EncodeToString(genesisSig),
	}
}

// QD-010's derivation, pinned: each code derives exactly the public keys and the genesis_sig the vectors hold, on
// every leg. Ed25519 signatures are deterministic, so the signature is a vector too.
func TestRecoveryVectors(t *testing.T) {
	networkId, _ := IdFromBytes(countingBytes(0x01, 16))
	genesisSha256 := sha256.Sum256([]byte("a synthetic Signed Genesis"))
	entropies := [][]byte{
		make([]byte, 16),
		bytes.Repeat([]byte{0xff}, 16),
		countingBytes(0x10, 16),
		countingBytes(0xa5, 16),
	}
	encoded := recoveryVectorsJson
	if len(bytes.TrimSpace(encoded)) <= len("[]") && os.Getenv("SIDECAR_REGENERATE_RECOVERY_VECTORS") == "1" {
		vectors := []recoveryVector{}
		for _, entropy := range entropies {
			vectors = append(vectors, deriveRecoveryVector(t, entropy, networkId, genesisSha256[:]))
		}
		generated, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(generated, '\n')
		if err := os.WriteFile(recoveryVectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vectors := []recoveryVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != len(entropies) {
		t.Fatalf("%d vectors", len(vectors))
	}
	for index, vector := range vectors {
		entropy, _ := hex.DecodeString(vector.Entropy)
		if !bytes.Equal(entropy, entropies[index]) {
			t.Fatalf("vector %d is of another code", index)
		}
		derived := deriveRecoveryVector(t, entropy, networkId, genesisSha256[:])
		if derived != vector {
			t.Errorf("vector %d: derived %+v", index, derived)
		}
		publicKey, _ := hex.DecodeString(vector.Ed25519PublicKey)
		genesisSig, _ := hex.DecodeString(vector.GenesisSig)
		if err := VerifyRecoveryGenesisSig(publicKey, networkId, genesisSha256[:], genesisSig); err != nil {
			t.Errorf("vector %d: %v", index, err)
		}
	}
}

// A genesis_sig holds for its own network and genesis and no other, and the keys erase.
func TestRecoveryGenesisSigBindsItsNetwork(t *testing.T) {
	code, err := NewRecoveryCode(bytes.NewReader(countingBytes(0x33, 16)))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	// the code erased itself once its keys were derived
	if _, err := code.Keys(); !errors.Is(err, ErrRecoveryCodeErased) {
		t.Errorf("a second derivation: %v", err)
	}
	if _, err := code.Words(); !errors.Is(err, ErrRecoveryCodeErased) || code.entropy != [recoveryCodeByteCount]byte{} {
		t.Errorf("the code was not erased: %v", err)
	}
	networkId, otherNetworkId := NewId(), NewId()
	genesisSha256 := sha256.Sum256([]byte("genesis"))
	otherGenesisSha256 := sha256.Sum256([]byte("another genesis"))
	genesisSig, err := keys.SignGenesis(networkId, genesisSha256[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey := keys.Ed25519PublicKey()
	if err := VerifyRecoveryGenesisSig(publicKey, networkId, genesisSha256[:], genesisSig); err != nil {
		t.Error(err)
	}
	requireError(t, VerifyRecoveryGenesisSig(publicKey, otherNetworkId, genesisSha256[:], genesisSig), ErrRecoveryGenesisSig)
	requireError(t, VerifyRecoveryGenesisSig(publicKey, networkId, otherGenesisSha256[:], genesisSig), ErrRecoveryGenesisSig)

	// the key signs what §7.9's Recovery lets it, as its member, and verifies as the carrier rule says
	memberId := NewId()
	signed, err := keys.Sign(memberId, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, []byte("a synthetic cosign body"))
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.VerifyRecoverySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, keys.KeySha256()); err != nil {
		t.Error(err)
	}
	if _, err := keys.Sign(memberId, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, []byte("body")); !errors.Is(err, ErrSidecarSignRefused) {
		t.Errorf("a recovery key signed a revocation: %v", err)
	}
	keys.Erase()
	if _, err := keys.SignGenesis(networkId, genesisSha256[:]); !errors.Is(err, ErrRecoveryKeys) {
		t.Errorf("erased keys signed: %v", err)
	}
}
