// The X-Wing KAT (§10.4; D-KEYS-10's kem row): the X-Wing draft's vectors against Go's crypto/hpke
// MLKEM768X25519(), which suite 0x0010 runs on, and draft-ietf-hpke-pq's vector for what MLS leans
// on most, DeriveKeyPair.
//
// crypto/hpke exposes neither its KEM's encapsulation nor its decapsulation, only the HPKE contexts
// built on them. So each vector is checked three ways: EncapsulateDerand recomputed here from
// crypto/mlkem and crypto/ecdh, which proves the vector's ciphertext and shared secret; a Recipient
// on the vector's ciphertext, whose exporter must equal RFC 9180's schedule run here on the vector's
// shared secret, which proves decapsulation; and a Sender on a fixed random stream, which proves
// encapsulation.

package sidecar

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"testing/cryptotest"
)

// The vectors of the X-Wing draft's Appendix C.
type mlsXWingVector struct {
	Seed  mlsHexBytes `json:"seed"`
	Sk    mlsHexBytes `json:"sk"`
	Pk    mlsHexBytes `json:"pk"`
	Eseed mlsHexBytes `json:"eseed"`
	Ct    mlsHexBytes `json:"ct"`
	Ss    mlsHexBytes `json:"ss"`
}

// All three, or the test stops.
func mlsLoadXWingVectors(t *testing.T) []mlsXWingVector {
	t.Helper()
	var vectors []mlsXWingVector
	mlsLoadVectorFile(t, filepath.Join("testdata", "mls", "xwing", "draft-connolly-cfrg-xwing-kem-11.json"), &vectors)
	if len(vectors) != 3 {
		t.Fatalf("%d vectors, want the draft's three", len(vectors))
	}
	return vectors
}

// draft-ietf-hpke-pq's Appendix A.5.
type mlsHpkePqVector struct {
	KemId          uint16      `json:"kem_id"`
	KdfId          uint16      `json:"kdf_id"`
	AeadId         uint16      `json:"aead_id"`
	Info           mlsHexBytes `json:"info"`
	IkmE           mlsHexBytes `json:"ikmE"`
	IkmR           mlsHexBytes `json:"ikmR"`
	SkRm           mlsHexBytes `json:"skRm"`
	PkRm           mlsHexBytes `json:"pkRm"`
	Enc            mlsHexBytes `json:"enc"`
	SharedSecret   mlsHexBytes `json:"shared_secret"`
	Key            mlsHexBytes `json:"key"`
	BaseNonce      mlsHexBytes `json:"base_nonce"`
	ExporterSecret mlsHexBytes `json:"exporter_secret"`
	Encryptions    []struct {
		Pt    mlsHexBytes `json:"pt"`
		Aad   mlsHexBytes `json:"aad"`
		Nonce mlsHexBytes `json:"nonce"`
		Ct    mlsHexBytes `json:"ct"`
	} `json:"encryptions"`
	Exports []struct {
		ExporterContext mlsHexBytes `json:"exporter_context"`
		L               int         `json:"L"`
		ExportedValue   mlsHexBytes `json:"exported_value"`
	} `json:"exports"`
}

// The one vector, or the test stops.
func mlsLoadHpkePqVector(t *testing.T) *mlsHpkePqVector {
	t.Helper()
	var vectors []*mlsHpkePqVector
	mlsLoadVectorFile(t, filepath.Join("testdata", "mls", "xwing", "draft-ietf-hpke-pq-05-a5.json"), &vectors)
	if len(vectors) != 1 {
		t.Fatalf("%d vectors, want one", len(vectors))
	}
	return vectors[0]
}

// X-Wing's EncapsulateDerand (the draft's §5.4.1), from the primitives crypto/hpke combines, so that
// an error there cannot cancel out here.
func mlsXWingEncapsulateDerand(t *testing.T, publicKey []byte, encapsulationSeed []byte) (sharedSecret []byte, ciphertext []byte) {
	t.Helper()
	if len(publicKey) != 1216 || len(encapsulationSeed) != 64 {
		t.Fatalf("public key of %d bytes, seed of %d", len(publicKey), len(encapsulationSeed))
	}
	encapsulationKey, err := mlkem.NewEncapsulationKey768(publicKey[:1184])
	if err != nil {
		t.Fatal(err)
	}
	sharedSecretM, ciphertextM, err := mlkemtest.Encapsulate768(encapsulationKey, encapsulationSeed[:32])
	if err != nil {
		t.Fatal(err)
	}

	publicKeyX := publicKey[1184:]
	remoteKey, err := ecdh.X25519().NewPublicKey(publicKeyX)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralKey, err := ecdh.X25519().NewPrivateKey(encapsulationSeed[32:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertextX := ephemeralKey.PublicKey().Bytes()
	sharedSecretX, err := ephemeralKey.ECDH(remoteKey)
	if err != nil {
		t.Fatal(err)
	}

	// the draft's §5.3 combiner, with XWingLabel in the hex it gives
	combined := sha3.New256()
	combined.Write(sharedSecretM)
	combined.Write(sharedSecretX)
	combined.Write(ciphertextX)
	combined.Write(publicKeyX)
	combined.Write([]byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c})
	return combined.Sum(nil), append(bytes.Clone(ciphertextM), ciphertextX...)
}

// RFC 9180's KeySchedule for mode_base over HKDF-SHA256, from a shared secret alone.
type mlsHpkeScheduleForTest struct {
	suiteId        []byte
	key            []byte
	baseNonce      []byte
	exporterSecret []byte
}

// RFC 9180's LabeledExtract.
func (self *mlsHpkeScheduleForTest) labeledExtract(t *testing.T, salt []byte, label string, inputKey []byte) []byte {
	t.Helper()
	labeled := append([]byte("HPKE-v1"), self.suiteId...)
	labeled = append(labeled, label...)
	labeled = append(labeled, inputKey...)
	extracted, err := hkdf.Extract(sha256.New, labeled, salt)
	if err != nil {
		t.Fatal(err)
	}
	return extracted
}

// RFC 9180's LabeledExpand.
func (self *mlsHpkeScheduleForTest) labeledExpand(t *testing.T, secret []byte, label string, info []byte, length int) []byte {
	t.Helper()
	labeled := binary.BigEndian.AppendUint16(nil, uint16(length))
	labeled = append(labeled, "HPKE-v1"...)
	labeled = append(labeled, self.suiteId...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	expanded, err := hkdf.Expand(sha256.New, secret, string(labeled), length)
	if err != nil {
		t.Fatal(err)
	}
	return expanded
}

// Runs the schedule for a suite and a shared secret.
func newMlsHpkeScheduleForTest(t *testing.T, kemId uint16, kdfId uint16, aeadId uint16, aeadKeyLength int, sharedSecret []byte, info []byte) *mlsHpkeScheduleForTest {
	t.Helper()
	suiteId := []byte("HPKE")
	suiteId = binary.BigEndian.AppendUint16(suiteId, kemId)
	suiteId = binary.BigEndian.AppendUint16(suiteId, kdfId)
	suiteId = binary.BigEndian.AppendUint16(suiteId, aeadId)
	schedule := &mlsHpkeScheduleForTest{suiteId: suiteId}

	context := []byte{0} // mode_base
	context = append(context, schedule.labeledExtract(t, nil, "psk_id_hash", nil)...)
	context = append(context, schedule.labeledExtract(t, nil, "info_hash", info)...)
	secret := schedule.labeledExtract(t, sharedSecret, "secret", nil)
	schedule.key = schedule.labeledExpand(t, secret, "key", context, aeadKeyLength)
	schedule.baseNonce = schedule.labeledExpand(t, secret, "base_nonce", context, 12)
	schedule.exporterSecret = schedule.labeledExpand(t, secret, "exp", context, sha256.Size)
	return schedule
}

// The exporter's output for this context, as a Sender or Recipient must report it.
func (self *mlsHpkeScheduleForTest) export(t *testing.T, exporterContext string, length int) []byte {
	t.Helper()
	return self.labeledExpand(t, self.exporterSecret, "sec", []byte(exporterContext), length)
}

// The schedule above reproduces the draft's own intermediate values, so it can stand as the oracle
// for the X-Wing vectors, whose drafts give only a shared secret.
func TestXWingHpkeScheduleOracleMatchesTheDraft(t *testing.T) {
	vector := mlsLoadHpkePqVector(t)
	schedule := newMlsHpkeScheduleForTest(t, vector.KemId, vector.KdfId, vector.AeadId, 32, vector.SharedSecret, vector.Info)
	if !bytes.Equal(schedule.key, vector.Key) {
		t.Errorf("key %x, want %x", schedule.key, vector.Key)
	}
	if !bytes.Equal(schedule.baseNonce, vector.BaseNonce) {
		t.Errorf("base nonce %x, want %x", schedule.baseNonce, vector.BaseNonce)
	}
	if !bytes.Equal(schedule.exporterSecret, vector.ExporterSecret) {
		t.Errorf("exporter secret %x, want %x", schedule.exporterSecret, vector.ExporterSecret)
	}
	for _, export := range vector.Exports {
		value := schedule.export(t, string(export.ExporterContext), export.L)
		if !bytes.Equal(value, export.ExportedValue) {
			t.Errorf("export %x: %x, want %x", export.ExporterContext, value, export.ExportedValue)
		}
	}
}

func TestXWingKatKeyGeneration(t *testing.T) {
	for _, vector := range mlsLoadXWingVectors(t) {
		if !bytes.Equal(vector.Seed, vector.Sk) {
			t.Errorf("seed %x, sk %x: X-Wing's decapsulation key is its seed", vector.Seed, vector.Sk)
		}
		privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(vector.Sk)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := privateKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, vector.Sk) {
			t.Errorf("private key %x, want %x", encoded, vector.Sk)
		}
		if publicKey := privateKey.PublicKey().Bytes(); !bytes.Equal(publicKey, vector.Pk) {
			t.Errorf("public key %x, want %x", publicKey, vector.Pk)
		}
		parsed, err := hpke.MLKEM768X25519().NewPublicKey(vector.Pk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.Bytes(), vector.Pk) {
			t.Error("the public key does not round-trip")
		}
	}
}

func TestXWingKatDerandomizedEncapsulation(t *testing.T) {
	for _, vector := range mlsLoadXWingVectors(t) {
		sharedSecret, ciphertext := mlsXWingEncapsulateDerand(t, vector.Pk, vector.Eseed)
		if !bytes.Equal(ciphertext, vector.Ct) {
			t.Errorf("ciphertext %x, want %x", ciphertext, vector.Ct)
		}
		if !bytes.Equal(sharedSecret, vector.Ss) {
			t.Errorf("shared secret %x, want %x", sharedSecret, vector.Ss)
		}
	}
}

func TestXWingKatDecapsulationThroughHpke(t *testing.T) {
	suite := mlsSuite
	info := []byte("mls-base xwing kat")
	for _, vector := range mlsLoadXWingVectors(t) {
		privateKey, err := suite.kem.NewPrivateKey(vector.Sk)
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := hpke.NewRecipient(vector.Ct, privateKey, suite.kdf, suite.aead, info)
		if err != nil {
			t.Fatal(err)
		}
		exported, err := recipient.Export("kat", 32)
		if err != nil {
			t.Fatal(err)
		}
		schedule := newMlsHpkeScheduleForTest(
			t, suite.kem.ID(), suite.kdf.ID(), suite.aead.ID(), suite.aeadKeyLength, vector.Ss, info,
		)
		if want := schedule.export(t, "kat", 32); !bytes.Equal(exported, want) {
			t.Errorf("recipient exported %x, want %x from the vector's shared secret", exported, want)
		}
	}
}

// crypto/hpke takes no encapsulation seed, so this draws one from a fixed random stream and replays
// the stream into a Sender. It reads X25519's ephemeral key first and ML-KEM's message second, the
// reverse of eseed's layout. Go keeps the right to change those reads: this test failing on a new
// toolchain with the others passing means that, not a broken KEM.
func TestXWingKatEncapsulationThroughHpke(t *testing.T) {
	suite := mlsSuite
	info := []byte("mls-base xwing kat")
	for index, vector := range mlsLoadXWingVectors(t) {
		publicKey, err := suite.kem.NewPublicKey(vector.Pk)
		if err != nil {
			t.Fatal(err)
		}

		stream := make([]byte, 64)
		cryptotest.SetGlobalRandom(t, uint64(index+1))
		rand.Read(stream)
		encapsulationSeed := append(bytes.Clone(stream[32:]), stream[:32]...)
		wantSharedSecret, wantCiphertext := mlsXWingEncapsulateDerand(t, vector.Pk, encapsulationSeed)

		cryptotest.SetGlobalRandom(t, uint64(index+1))
		ciphertext, sender, err := hpke.NewSender(publicKey, suite.kdf, suite.aead, info)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ciphertext, wantCiphertext) {
			t.Errorf("ciphertext %x, want %x", ciphertext, wantCiphertext)
		}
		exported, err := sender.Export("kat", 32)
		if err != nil {
			t.Fatal(err)
		}
		schedule := newMlsHpkeScheduleForTest(
			t, suite.kem.ID(), suite.kdf.ID(), suite.aead.ID(), suite.aeadKeyLength, wantSharedSecret, info,
		)
		if want := schedule.export(t, "kat", 32); !bytes.Equal(exported, want) {
			t.Errorf("sender exported %x, want %x", exported, want)
		}
	}
}

// Every MLS node key comes through DeriveKeyPair, so this runs the suite layer's own call.
func TestXWingDeriveKeyPairMatchesHpkePq(t *testing.T) {
	vector := mlsLoadHpkePqVector(t)
	privateKey, err := mlsSuite.deriveKemKey("test", vector.IkmR)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := privateKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, vector.SkRm) {
		t.Errorf("private key %x, want %x", encoded, vector.SkRm)
	}
	if publicKey := privateKey.PublicKey().Bytes(); !bytes.Equal(publicKey, vector.PkRm) {
		t.Errorf("public key %x, want %x", publicKey, vector.PkRm)
	}
}

// The X-Wing draft's §5.6 derives with unlabeled SHAKE256, the HPKE draft with LabeledDerive. Suite
// 0x0010 cites the second. An implementation on the first, which a peer such as OpenMLS's 0x004D may
// be, computes different node keys from equal path secrets, so this difference is worth pinning.
func TestXWingDeriveKeyPairIsNotTheUnlabeledForm(t *testing.T) {
	vector := mlsLoadHpkePqVector(t)
	unlabeled := sha3.NewSHAKE256()
	unlabeled.Write(vector.IkmR)
	seed := make([]byte, 32)
	unlabeled.Read(seed)
	if bytes.Equal(seed, vector.SkRm) {
		t.Fatal("the drafts agree after all: drop this test and the note in mls_ciphersuite.go")
	}
}

// The HPKE draft's whole base-mode vector: its derandomized encapsulation, then every encryption and
// export through crypto/hpke.
func TestXWingHpkePqVectorBaseMode(t *testing.T) {
	vector := mlsLoadHpkePqVector(t)
	if vector.KemId != 0x647a {
		t.Fatalf("kem %#x", vector.KemId)
	}

	sharedSecret, ciphertext := mlsXWingEncapsulateDerand(t, vector.PkRm, vector.IkmE)
	if !bytes.Equal(ciphertext, vector.Enc) {
		t.Errorf("enc %x, want %x", ciphertext, vector.Enc)
	}
	if !bytes.Equal(sharedSecret, vector.SharedSecret) {
		t.Errorf("shared secret %x, want %x", sharedSecret, vector.SharedSecret)
	}

	kem := hpke.MLKEM768X25519()
	privateKey, err := kem.NewPrivateKey(vector.SkRm)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(vector.Enc, privateKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), vector.Info)
	if err != nil {
		t.Fatal(err)
	}
	for sequence, encryption := range vector.Encryptions {
		plaintext, err := recipient.Open(encryption.Aad, encryption.Ct)
		if err != nil {
			t.Fatalf("encryption %d: %v", sequence, err)
		}
		if !bytes.Equal(plaintext, encryption.Pt) {
			t.Errorf("encryption %d: plaintext %x, want %x", sequence, plaintext, encryption.Pt)
		}
	}
	for _, export := range vector.Exports {
		value, err := recipient.Export(string(export.ExporterContext), export.L)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(value, export.ExportedValue) {
			t.Errorf("export %x: %x, want %x", export.ExporterContext, value, export.ExportedValue)
		}
	}
}

// A ciphertext of the wrong size refuses at setup, and a tampered one of the right size decapsulates
// implicitly to a different secret, which the AEAD then refuses: both as one refusal to the caller.
func TestXWingRefusesBadCiphertexts(t *testing.T) {
	suite := mlsSuite
	privateKey, err := suite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("path secret")
	kemOutput, ciphertext, err := suite.encryptWithLabel(privateKey.PublicKey().Bytes(), "Welcome", nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	tamperedM := bytes.Clone(kemOutput)
	tamperedM[0] ^= 1
	tamperedX := bytes.Clone(kemOutput)
	tamperedX[1100] ^= 1
	for _, badOutput := range [][]byte{kemOutput[:1119], append(bytes.Clone(kemOutput), 0), tamperedM, tamperedX, nil} {
		_, err := suite.decryptWithLabel("test", privateKey, "Welcome", nil, badOutput, ciphertext)
		if !errors.Is(err, errMlsAuthentication) {
			t.Errorf("kem output of %d bytes: %v", len(badOutput), err)
		}
	}
}

func TestXWingRefusesBadKeys(t *testing.T) {
	kem := mlsSuite.kem
	if _, err := kem.NewPrivateKey(make([]byte, 31)); err == nil {
		t.Error("took a 31-byte private key")
	}
	if _, err := kem.NewPublicKey(make([]byte, 1215)); err == nil {
		t.Error("took a 1215-byte public key")
	}
	// ML-KEM's modulus check: every coefficient here is 4095, past q
	if _, err := kem.NewPublicKey(bytes.Repeat([]byte{0xff}, 1216)); err == nil {
		t.Error("took an encapsulation key past the modulus")
	}
}
