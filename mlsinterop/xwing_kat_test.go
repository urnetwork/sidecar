// §22.10's kem row (D-KEYS-10): draft-ietf-hpke-pq's X-Wing vectors, as GOROOT's crypto/hpke/testdata/hpke-pq.json
// carries them, through Go's crypto/hpke MLKEM768X25519(), which suite 0x0010 runs on; DeriveKeyPair among them,
// since every MLS node key comes through it and an encapsulation KAT alone misses it. Then tmc/mls's X-Wing against
// crypto/hpke on fixed seeds: its DeriveKeyPair, and its EncryptWithLabel's kem_output and ciphertext under one
// fixed random stream, both ways.
//
// tmc/mls builds X-Wing on crypto/hpke (its suite.go), the code mls_* runs, so its half passes by construction: it
// shows tmc/mls wires the KEM to RFC 9420's EncryptWithLabel as mls_* does, not that X-Wing is right. The draft's
// vectors are the one independent X-Wing evidence here (plan-KEYS-interop-independence #2), and the root's
// mls_xwing_test.go runs the X-Wing draft's own Appendix C besides. None of this needs tmc/mls's suite number, so it
// runs unpatched, under its 0x004F.

package mlsinterop

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/tmc/mls"
)

// X-Wing's KEM id in HPKE (draft-ietf-hpke-pq).
const xWingKemId = 0x647a

// The Go tree this test runs on, whose crypto/hpke the vectors check. -trimpath, which the build cache here
// uses, leaves runtime.GOROOT empty, so the go command answers then.
func xWingGoRoot(t *testing.T) string {
	t.Helper()
	if goRoot := os.Getenv("GOROOT"); goRoot != "" {
		return goRoot
	}
	if goRoot := runtime.GOROOT(); goRoot != "" {
		return goRoot
	}
	output, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("no GOROOT to read crypto/hpke's vectors from: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// One entry of hpke-pq.json, in RFC 9180's test vector form.
type xWingHpkeVector struct {
	Mode        int           `json:"mode"`
	KemId       uint16        `json:"kem_id"`
	KdfId       uint16        `json:"kdf_id"`
	AeadId      uint16        `json:"aead_id"`
	Info        xWingHex      `json:"info"`
	IkmR        xWingHex      `json:"ikmR"`
	SkRm        xWingHex      `json:"skRm"`
	PkRm        xWingHex      `json:"pkRm"`
	Enc         xWingHex      `json:"enc"`
	Encryptions []xWingSeal   `json:"encryptions"`
	Exports     []xWingExport `json:"exports"`
}

type xWingSeal struct {
	Aad xWingHex `json:"aad"`
	Ct  xWingHex `json:"ct"`
	Pt  xWingHex `json:"pt"`
}

type xWingExport struct {
	Context xWingHex `json:"exporter_context"`
	Length  int      `json:"L"`
	Value   xWingHex `json:"exported_value"`
}

// Hex text as bytes.
type xWingHex []byte

func (self *xWingHex) UnmarshalJSON(encoded []byte) error {
	var text string
	if err := json.Unmarshal(encoded, &text); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return err
	}
	*self = decoded
	return nil
}

// The X-Wing entries of GOROOT's hpke-pq.json, each in base mode; the test stops when there are none.
func xWingHpkeVectors(t *testing.T) []*xWingHpkeVector {
	t.Helper()
	path := filepath.Join(xWingGoRoot(t), "src", "crypto", "hpke", "testdata", "hpke-pq.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the draft's vectors: %v", err)
	}
	all := []*xWingHpkeVector{}
	if err := json.Unmarshal(encoded, &all); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	vectors := []*xWingHpkeVector{}
	for _, vector := range all {
		if vector.KemId == xWingKemId && vector.Mode == 0 {
			vectors = append(vectors, vector)
		}
	}
	if len(vectors) == 0 {
		t.Fatalf("%s holds no X-Wing vector", path)
	}
	t.Logf("%d X-Wing vectors from %s, sha256 %x", len(vectors), path, sha256.Sum256(encoded))
	return vectors
}

// Each vector's recipient key pair comes out of DeriveKeyPair(ikmR) byte for byte, NewPrivateKey(skRm) gives the same
// public key, and the vector's enc opens every one of its ciphertexts, in order, and gives every export.
func TestXWingHpkePqVectorsThroughCryptoHpke(t *testing.T) {
	kem := hpke.MLKEM768X25519()
	if kem.ID() != xWingKemId {
		t.Fatalf("MLKEM768X25519's id %#x", kem.ID())
	}
	for index, vector := range xWingHpkeVectors(t) {
		kdf, err := hpke.NewKDF(vector.KdfId)
		if err != nil {
			t.Fatalf("vector %d: kdf %#x: %v", index, vector.KdfId, err)
		}
		aead, err := hpke.NewAEAD(vector.AeadId)
		if err != nil {
			t.Fatalf("vector %d: aead %#x: %v", index, vector.AeadId, err)
		}
		derived, err := kem.DeriveKeyPair(vector.IkmR)
		if err != nil {
			t.Fatalf("vector %d: DeriveKeyPair: %v", index, err)
		}
		derivedPrivate, err := derived.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derivedPrivate, vector.SkRm) || !bytes.Equal(derived.PublicKey().Bytes(), vector.PkRm) {
			t.Errorf("vector %d: DeriveKeyPair(ikmR) is not (skRm, pkRm)", index)
		}
		loaded, err := kem.NewPrivateKey(vector.SkRm)
		if err != nil || !bytes.Equal(loaded.PublicKey().Bytes(), vector.PkRm) {
			t.Errorf("vector %d: NewPrivateKey(skRm): %v", index, err)
		}
		recipient, err := hpke.NewRecipient(vector.Enc, derived, kdf, aead, vector.Info)
		if err != nil {
			t.Fatalf("vector %d: decapsulating enc: %v", index, err)
		}
		for sequence, seal := range vector.Encryptions {
			plaintext, err := recipient.Open(seal.Aad, seal.Ct)
			if err != nil || !bytes.Equal(plaintext, seal.Pt) {
				t.Errorf("vector %d: encryption %d: %v", index, sequence, err)
			}
		}
		for exportIndex, export := range vector.Exports {
			value, err := recipient.Export(string(export.Context), export.Length)
			if err != nil || !bytes.Equal(value, export.Value) {
				t.Errorf("vector %d: export %d: %v", index, exportIndex, err)
			}
		}
	}
}

// tmc/mls's DeriveKeyPair gives crypto/hpke's pair, on the vectors' ikmR and on fixed seeds of every length the tree
// derives from: a node secret is the suite's hash length.
func TestXWingTmcDeriveKeyPairMatchesCryptoHpke(t *testing.T) {
	suite := mls.MLKEM768X25519AES128GCMSHA256Ed25519
	kem := hpke.MLKEM768X25519()
	ikms := [][]byte{}
	for _, vector := range xWingHpkeVectors(t) {
		ikms = append(ikms, vector.IkmR)
	}
	for seed := range 8 {
		ikm := sha256.Sum256([]byte{byte(seed)})
		ikms = append(ikms, ikm[:])
	}
	for index, ikm := range ikms {
		tmcPrivate, tmcPublic, err := suite.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatalf("ikm %d: tmc/mls: %v", index, err)
		}
		derived, err := kem.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatalf("ikm %d: crypto/hpke: %v", index, err)
		}
		derivedPrivate, _ := derived.Bytes()
		if !bytes.Equal(tmcPrivate, derivedPrivate) || !bytes.Equal(tmcPublic, derived.PublicKey().Bytes()) {
			t.Errorf("ikm %d: the pairs differ", index)
		}
	}
}

// RFC 9420's EncryptContext{label, context}, label "MLS 1.0 " || label, each an opaque<V>: written here, apart from
// both stacks.
func xWingEncryptContext(label string, context []byte) []byte {
	opaque := func(out []byte, data []byte) []byte {
		length := len(data)
		switch {
		case length < 1<<6:
			out = append(out, byte(length))
		case length < 1<<14:
			out = append(out, byte(0x40|length>>8), byte(length))
		default:
			out = append(out, byte(0x80|length>>24), byte(length>>16), byte(length>>8), byte(length))
		}
		return append(out, data...)
	}
	return opaque(opaque(nil, []byte("MLS 1.0 "+label)), context)
}

// On one fixed random stream, tmc/mls's EncryptWithLabel and crypto/hpke under the suite's KDF and AEAD encapsulate
// to the same kem_output and seal the same ciphertext, and each opens the other's.
func TestXWingTmcEncryptWithLabelMatchesCryptoHpke(t *testing.T) {
	suite := mls.MLKEM768X25519AES128GCMSHA256Ed25519
	kem := hpke.MLKEM768X25519()
	for seed := uint64(1); seed <= 4; seed += 1 {
		ikm := sha256.Sum256([]byte{byte(seed), 'r'})
		recipient, err := kem.DeriveKeyPair(ikm[:])
		if err != nil {
			t.Fatal(err)
		}
		recipientPrivate, _ := recipient.Bytes()
		publicKey := recipient.PublicKey().Bytes()
		label, context := "UpdatePathNode", []byte{byte(seed), 2, 3}
		plaintext := bytes.Repeat([]byte{byte(seed)}, 32)

		cryptotest.SetGlobalRandom(t, seed)
		tmcSealed, err := suite.EncryptWithLabel(publicKey, label, context, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		cryptotest.SetGlobalRandom(t, seed)
		encapsulation, sender, err := hpke.NewSender(recipient.PublicKey(), hpke.HKDFSHA256(), hpke.AES128GCM(), xWingEncryptContext(label, context))
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := sender.Seal(nil, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(tmcSealed.KEMOutput, encapsulation) || !bytes.Equal(tmcSealed.Ciphertext, ciphertext) {
			t.Errorf("seed %d: tmc/mls and crypto/hpke encapsulate differently on one random stream", seed)
		}

		opened, err := suite.DecryptWithLabel(recipientPrivate, label, context, &mls.HPKECiphertext{KEMOutput: encapsulation, Ciphertext: ciphertext})
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Errorf("seed %d: tmc/mls does not open crypto/hpke's: %v", seed, err)
		}
		opened, err = hpke.Open(recipient, hpke.HKDFSHA256(), hpke.AES128GCM(), xWingEncryptContext(label, context),
			append(bytes.Clone(tmcSealed.KEMOutput), tmcSealed.Ciphertext...))
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Errorf("seed %d: crypto/hpke does not open tmc/mls's: %v", seed, err)
		}
		if _, err := suite.DecryptWithLabel(recipientPrivate, label+" other", context, tmcSealed); err == nil {
			t.Errorf("seed %d: another label opens", seed)
		}
	}
}
