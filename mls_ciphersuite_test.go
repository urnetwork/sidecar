// The cipher suite layer against the mlswg's crypto-basics vectors under 0x0001, and each labeled
// function's behavior under both suites.

package sidecar

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The value of the classical suite the mlswg's vectors run under.
const mlsCipherSuiteX25519 uint16 = 0x0001

// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. Tests alone build it (§10.4).
var mlsTestSuiteX25519 = newMlsCipherSuite(mlsCipherSuiteX25519, hpke.DHKEM(ecdh.X25519()))

// Both suites, for behavior that must hold under each.
var mlsTestSuites = []*mlsCipherSuite{mlsSuite, mlsTestSuiteX25519}

func TestMlsCryptoBasicsVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite uint16 `json:"cipher_suite"`
		RefHash     struct {
			Label string      `json:"label"`
			Value mlsHexBytes `json:"value"`
			Out   mlsHexBytes `json:"out"`
		} `json:"ref_hash"`
		ExpandWithLabel struct {
			Secret  mlsHexBytes `json:"secret"`
			Label   string      `json:"label"`
			Context mlsHexBytes `json:"context"`
			Length  int         `json:"length"`
			Out     mlsHexBytes `json:"out"`
		} `json:"expand_with_label"`
		DeriveSecret struct {
			Secret mlsHexBytes `json:"secret"`
			Label  string      `json:"label"`
			Out    mlsHexBytes `json:"out"`
		} `json:"derive_secret"`
		DeriveTreeSecret struct {
			Secret     mlsHexBytes `json:"secret"`
			Label      string      `json:"label"`
			Generation uint32      `json:"generation"`
			Length     int         `json:"length"`
			Out        mlsHexBytes `json:"out"`
		} `json:"derive_tree_secret"`
		SignWithLabel struct {
			Priv      mlsHexBytes `json:"priv"`
			Pub       mlsHexBytes `json:"pub"`
			Content   mlsHexBytes `json:"content"`
			Label     string      `json:"label"`
			Signature mlsHexBytes `json:"signature"`
		} `json:"sign_with_label"`
		EncryptWithLabel struct {
			Priv       mlsHexBytes `json:"priv"`
			Pub        mlsHexBytes `json:"pub"`
			Label      string      `json:"label"`
			Context    mlsHexBytes `json:"context"`
			Plaintext  mlsHexBytes `json:"plaintext"`
			KemOutput  mlsHexBytes `json:"kem_output"`
			Ciphertext mlsHexBytes `json:"ciphertext"`
		} `json:"encrypt_with_label"`
	}
	mlsLoadVectors(t, "crypto-basics", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for _, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++

		refHash, err := suite.refHash(vector.RefHash.Label, vector.RefHash.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(refHash, vector.RefHash.Out) {
			t.Errorf("ref_hash %x, want %x", refHash, vector.RefHash.Out)
		}

		expanded, err := suite.expandWithLabel(
			"test",
			vector.ExpandWithLabel.Secret,
			vector.ExpandWithLabel.Label,
			vector.ExpandWithLabel.Context,
			vector.ExpandWithLabel.Length,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expanded, vector.ExpandWithLabel.Out) {
			t.Errorf("expand_with_label %x, want %x", expanded, vector.ExpandWithLabel.Out)
		}

		derived, err := suite.deriveSecret("test", vector.DeriveSecret.Secret, vector.DeriveSecret.Label)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derived, vector.DeriveSecret.Out) {
			t.Errorf("derive_secret %x, want %x", derived, vector.DeriveSecret.Out)
		}

		treeSecret, err := suite.deriveTreeSecret(
			"test",
			vector.DeriveTreeSecret.Secret,
			vector.DeriveTreeSecret.Label,
			vector.DeriveTreeSecret.Generation,
			vector.DeriveTreeSecret.Length,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(treeSecret, vector.DeriveTreeSecret.Out) {
			t.Errorf("derive_tree_secret %x, want %x", treeSecret, vector.DeriveTreeSecret.Out)
		}

		sign := vector.SignWithLabel
		if !suite.verifyWithLabel(sign.Pub, sign.Label, sign.Content, sign.Signature) {
			t.Error("sign_with_label: the vector's signature does not verify")
		}
		signatureKey, err := suite.loadSignatureKey("test", sign.Priv)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := suite.signWithLabel(signatureKey, sign.Label, sign.Content)
		if err != nil {
			t.Fatal(err)
		}
		if !suite.verifyWithLabel(sign.Pub, sign.Label, sign.Content, signature) {
			t.Error("sign_with_label: a fresh signature does not verify")
		}

		encrypt := vector.EncryptWithLabel
		privateKey, err := suite.loadKemKey("test", encrypt.Priv)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := suite.decryptWithLabel(
			"test", privateKey, encrypt.Label, encrypt.Context, encrypt.KemOutput, encrypt.Ciphertext,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, encrypt.Plaintext) {
			t.Errorf("encrypt_with_label: plaintext %x, want %x", plaintext, encrypt.Plaintext)
		}
		kemOutput, ciphertext, err := suite.encryptWithLabel(encrypt.Pub, encrypt.Label, encrypt.Context, encrypt.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err = suite.decryptWithLabel("test", privateKey, encrypt.Label, encrypt.Context, kemOutput, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, encrypt.Plaintext) {
			t.Errorf("encrypt_with_label: fresh plaintext %x, want %x", plaintext, encrypt.Plaintext)
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

// The registry rows the suite's constants copy (draft-ietf-mls-pq-ciphersuites-07 table 2).
func TestMlsSuiteMatchesTheRegistry(t *testing.T) {
	if mlsSuite.value != 0x0010 {
		t.Errorf("suite value %#x", mlsSuite.value)
	}
	if id := mlsSuite.kem.ID(); id != 0x647a {
		t.Errorf("kem %#x", id)
	}
	if mlsTestSuiteX25519.kem.ID() != 0x0020 {
		t.Errorf("0x0001's kem %#x", mlsTestSuiteX25519.kem.ID())
	}
	for _, suite := range mlsTestSuites {
		if id := suite.kdf.ID(); id != 0x0001 {
			t.Errorf("kdf %#x", id)
		}
		if id := suite.aead.ID(); id != 0x0001 {
			t.Errorf("aead %#x", id)
		}
		if suite.hashLength != sha256.Size {
			t.Errorf("hash length %d", suite.hashLength)
		}
		if suite.aeadKeyLength != 16 || suite.aeadNonceLength != 12 {
			t.Errorf("aead key %d, nonce %d", suite.aeadKeyLength, suite.aeadNonceLength)
		}
	}
}

// Nothing outside tests may name the classical suite, so production has exactly one.
func TestMlsProductionCodeBuildsOneSuite(t *testing.T) {
	paths, err := filepath.Glob("mls_*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	suiteBuilds := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "newMlsCipherSuite" {
				suiteBuilds++
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "DHKEM" {
				t.Errorf("%s: names a classical KEM", fileSet.Position(call.Pos()))
			}
			return true
		})
	}
	if suiteBuilds != 1 {
		t.Fatalf("%d suites built outside tests, want mlsSuite alone", suiteBuilds)
	}
}

func TestMlsLabelsSeparateDerivations(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, mlsSuite.hashLength)
	for _, suite := range mlsTestSuites {
		first, err := suite.expandWithLabel("test", secret, "one", []byte("context"), 32)
		if err != nil {
			t.Fatal(err)
		}
		second, err := suite.expandWithLabel("test", secret, "two", []byte("context"), 32)
		if err != nil {
			t.Fatal(err)
		}
		third, err := suite.expandWithLabel("test", secret, "one", []byte("other"), 32)
		if err != nil {
			t.Fatal(err)
		}
		fourth, err := suite.expandWithLabel("test", secret, "one", []byte("context"), 16)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, second) || bytes.Equal(first, third) {
			t.Error("label or context not bound")
		}
		// KDFLabel carries the length, so a shorter output is not a prefix of a longer one
		if bytes.Equal(first[:16], fourth) {
			t.Error("length not bound")
		}
	}
}

func TestMlsExpandRefusesLengthsPastItsField(t *testing.T) {
	secret := make([]byte, mlsSuite.hashLength)
	for _, length := range []int{-1, 0x10000} {
		if _, err := mlsSuite.expandWithLabel("test", secret, "label", nil, length); err == nil {
			t.Errorf("length %d expanded", length)
		}
	}
	// past HKDF's own limit of 255 hash outputs
	if _, err := mlsSuite.expandWithLabel("test", secret, "label", nil, 255*sha256.Size+1); err == nil {
		t.Error("expanded past hkdf's limit")
	}
}

func TestMlsSignatureBindsLabelAndContent(t *testing.T) {
	for _, suite := range mlsTestSuites {
		signatureKey, err := suite.generateSignatureKey("test")
		if err != nil {
			t.Fatal(err)
		}
		publicKey := []byte(signatureKey.Public().(ed25519.PublicKey))
		content := []byte("content")
		signature, err := suite.signWithLabel(signatureKey, "LeafNodeTBS", content)
		if err != nil {
			t.Fatal(err)
		}
		if !suite.verifyWithLabel(publicKey, "LeafNodeTBS", content, signature) {
			t.Fatal("does not verify")
		}
		if suite.verifyWithLabel(publicKey, "KeyPackageTBS", content, signature) {
			t.Error("verified under another label")
		}
		if suite.verifyWithLabel(publicKey, "LeafNodeTBS", []byte("other"), signature) {
			t.Error("verified over other content")
		}
		tampered := bytes.Clone(signature)
		tampered[0] ^= 1
		if suite.verifyWithLabel(publicKey, "LeafNodeTBS", content, tampered) {
			t.Error("verified a tampered signature")
		}
	}
}

// ed25519.Verify and ed25519.Sign panic on a key of the wrong size, and these bytes come off the wire.
func TestMlsSignatureRefusesKeysOfTheWrongSize(t *testing.T) {
	for _, size := range []int{0, 31, 33, 64} {
		if mlsSuite.verifyWithLabel(make([]byte, size), "label", nil, make([]byte, 64)) {
			t.Errorf("verified under a %d-byte key", size)
		}
	}
	for _, size := range []int{0, 32, 63, 65} {
		if _, err := mlsSuite.signWithLabel(make([]byte, size), "label", nil); err == nil {
			t.Errorf("signed under a %d-byte key", size)
		}
	}
	for _, size := range []int{0, 31, 33, 64} {
		if _, err := mlsSuite.loadSignatureKey("test", make([]byte, size)); err == nil {
			t.Errorf("loaded a seed of %d bytes", size)
		}
	}
}

func TestMlsEncryptionBindsLabelContextAndKey(t *testing.T) {
	for _, suite := range mlsTestSuites {
		privateKey, err := suite.generateKemKey("test")
		if err != nil {
			t.Fatal(err)
		}
		otherKey, err := suite.generateKemKey("test")
		if err != nil {
			t.Fatal(err)
		}
		publicKey := privateKey.PublicKey().Bytes()
		context := []byte("group context")
		plaintext := []byte("path secret")
		kemOutput, ciphertext, err := suite.encryptWithLabel(publicKey, "UpdatePathNode", context, plaintext)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := suite.decryptWithLabel("test", privateKey, "UpdatePathNode", context, kemOutput, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted %x", decrypted)
		}

		cases := []struct {
			name       string
			key        hpke.PrivateKey
			label      string
			context    []byte
			kemOutput  []byte
			ciphertext []byte
		}{
			{name: "label", key: privateKey, label: "Welcome", context: context, kemOutput: kemOutput, ciphertext: ciphertext},
			{name: "context", key: privateKey, label: "UpdatePathNode", context: []byte("other"), kemOutput: kemOutput, ciphertext: ciphertext},
			{name: "key", key: otherKey, label: "UpdatePathNode", context: context, kemOutput: kemOutput, ciphertext: ciphertext},
			{name: "ciphertext", key: privateKey, label: "UpdatePathNode", context: context, kemOutput: kemOutput, ciphertext: ciphertext[1:]},
			{name: "kem output", key: privateKey, label: "UpdatePathNode", context: context, kemOutput: kemOutput[1:], ciphertext: ciphertext},
		}
		for _, c := range cases {
			_, err := suite.decryptWithLabel("test", c.key, c.label, c.context, c.kemOutput, c.ciphertext)
			if !errors.Is(err, errMlsAuthentication) {
				t.Errorf("suite %#x, wrong %s: %v", suite.value, c.name, err)
			}
		}
	}
}

func TestMlsEncryptRefusesAPublicKeyTheKemCannotParse(t *testing.T) {
	for _, suite := range mlsTestSuites {
		if _, _, err := suite.encryptWithLabel([]byte{1, 2, 3}, "Welcome", nil, []byte("x")); err == nil {
			t.Errorf("suite %#x encrypted to three bytes", suite.value)
		}
	}
}

func TestMlsKemKeysDeriveDeterministically(t *testing.T) {
	for _, suite := range mlsTestSuites {
		secret := bytes.Repeat([]byte{0x42}, suite.hashLength)
		first, err := suite.deriveKemKey("test", secret)
		if err != nil {
			t.Fatal(err)
		}
		second, err := suite.deriveKemKey("test", secret)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.PublicKey().Bytes(), second.PublicKey().Bytes()) {
			t.Error("two derivations differ")
		}

		encoded, err := first.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := suite.loadKemKey("test", encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.PublicKey().Bytes(), loaded.PublicKey().Bytes()) {
			t.Error("a loaded key differs")
		}
	}
}

// The sizes §10.6's inputs rest on.
func TestMlsXWingKeySizes(t *testing.T) {
	privateKey, err := mlsSuite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := privateKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 32 {
		t.Errorf("private key of %d bytes", len(encoded))
	}
	publicKey := privateKey.PublicKey().Bytes()
	if len(publicKey) != 1216 {
		t.Errorf("public key of %d bytes", len(publicKey))
	}
	kemOutput, _, err := mlsSuite.encryptWithLabel(publicKey, "Welcome", nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(kemOutput) != 1120 {
		t.Errorf("kem output of %d bytes", len(kemOutput))
	}
}

func TestMlsMacVerification(t *testing.T) {
	key := bytes.Repeat([]byte{7}, mlsSuite.hashLength)
	tag := mlsSuite.mac(key, []byte("data"))
	if len(tag) != mlsSuite.hashLength {
		t.Fatalf("tag of %d bytes", len(tag))
	}
	if !mlsSuite.verifyMac(key, []byte("data"), tag) {
		t.Error("does not verify")
	}
	if mlsSuite.verifyMac(key, []byte("other"), tag) {
		t.Error("verified other data")
	}
	if mlsSuite.verifyMac(key, []byte("data"), tag[1:]) {
		t.Error("verified a short tag")
	}
}

func TestMlsAeadRoundTripAndRefusal(t *testing.T) {
	key := make([]byte, mlsSuite.aeadKeyLength)
	nonce := make([]byte, mlsSuite.aeadNonceLength)
	rand.Read(key)
	rand.Read(nonce)
	sealed, err := mlsSuite.aeadSeal(key, nonce, []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := mlsSuite.aeadOpen(key, nonce, []byte("aad"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, []byte("plaintext")) {
		t.Fatalf("opened %q", opened)
	}
	if _, err := mlsSuite.aeadOpen(key, nonce, []byte("other"), sealed); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("other aad: %v", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[0] ^= 1
	if _, err := mlsSuite.aeadOpen(key, nonce, []byte("aad"), tampered); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("tampered: %v", err)
	}
}

// cipher.AEAD panics on a nonce of the wrong size, so these must come back as errors.
func TestMlsAeadRefusesWrongSizes(t *testing.T) {
	key := make([]byte, mlsSuite.aeadKeyLength)
	nonce := make([]byte, mlsSuite.aeadNonceLength)
	if _, err := mlsSuite.aeadSeal(key[1:], nonce, nil, nil); err == nil {
		t.Error("sealed under a short key")
	}
	if _, err := mlsSuite.aeadSeal(key, nonce[1:], nil, nil); err == nil {
		t.Error("sealed under a short nonce")
	}
	if _, err := mlsSuite.aeadOpen(key, nonce[1:], nil, make([]byte, 16)); err == nil {
		t.Error("opened under a short nonce")
	}
}

func TestMlsGeneratedSecretsHaveHashLengthAndDiffer(t *testing.T) {
	first := mlsSuite.generateSecret("test")
	second := mlsSuite.generateSecret("test")
	if len(first) != mlsSuite.hashLength {
		t.Errorf("secret of %d bytes", len(first))
	}
	if bytes.Equal(first, second) {
		t.Error("two secrets are equal")
	}
}
