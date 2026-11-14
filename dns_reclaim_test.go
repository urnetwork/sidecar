//go:build !ios_extension

// §12.8's label reclaim proof (DNS-M5-16), T1 on every leg: testdata/dns/reclaim/vectors.json's tuples give their
// signed bytes exactly, its fixed leaf and signature verify for the first tuple and for no other name, network or
// incident, and a fresh key's proof verifies only under its own leaf. A format change regenerates the vectors.

package sidecar_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

//go:embed testdata/dns/reclaim/vectors.json
var testDnsReclaimFiles embed.FS

type testDnsReclaimVector struct {
	Name        string `json:"name"`
	NetworkId   string `json:"network_id"`
	IncidentId  string `json:"incident_id"`
	SignedBytes string `json:"signed_bytes"`
}

type testDnsReclaimFile struct {
	Vectors   []testDnsReclaimVector `json:"vectors"`
	Leaf      string                 `json:"leaf"`
	Signature string                 `json:"signature"`
}

func readTestDnsReclaimFile(t testing.TB) *testDnsReclaimFile {
	t.Helper()
	data, err := testDnsReclaimFiles.ReadFile("testdata/dns/reclaim/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	file := &testDnsReclaimFile{}
	if err := json.Unmarshal(data, file); err != nil {
		t.Fatal(err)
	}
	return file
}

func testDnsReclaimId(t testing.TB, text string) sidecar.Id {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 16 {
		t.Fatalf("id %q", text)
	}
	return sidecar.Id(raw)
}

func (self *testDnsReclaimVector) proof(t testing.TB) *sidecar.DnsReclaimProof {
	return &sidecar.DnsReclaimProof{Name: self.Name, NetworkId: testDnsReclaimId(t, self.NetworkId), IncidentId: testDnsReclaimId(t, self.IncidentId)}
}

// Each tuple's signed bytes are the vector's, byte for byte; a name in another case or with its final dot reads the
// same, and an empty name or a zero id has no bytes.
func TestDnsReclaimProofSignedBytesMatchTheVectors(t *testing.T) {
	file := readTestDnsReclaimFile(t)
	for _, vector := range file.Vectors {
		signedBytes, err := vector.proof(t).SignedBytes()
		if err != nil || hex.EncodeToString(signedBytes) != vector.SignedBytes {
			t.Errorf("%s: %x %v", vector.Name, signedBytes, err)
		}
	}
	upper := file.Vectors[0].proof(t)
	upper.Name = "LBL0000001.Root.Example."
	if signedBytes, _ := upper.SignedBytes(); hex.EncodeToString(signedBytes) != file.Vectors[0].SignedBytes {
		t.Errorf("a name in another case")
	}
	for _, invalid := range []*sidecar.DnsReclaimProof{
		{Name: "", NetworkId: sidecar.NewId(), IncidentId: sidecar.NewId()},
		{Name: "lbl0000001.root.example", IncidentId: sidecar.NewId()},
		{Name: "lbl0000001.root.example", NetworkId: sidecar.NewId()},
	} {
		if _, err := invalid.SignedBytes(); !errors.Is(err, sidecar.ErrDnsReclaimProofInvalid) {
			t.Errorf("%+v: %v", invalid, err)
		}
	}
}

// The fixed leaf and signature prove the first tuple, and a signature that fits it fits no other name, network or
// incident.
func TestDnsReclaimProofVerifiesOnlyItsOwnTuple(t *testing.T) {
	file := readTestDnsReclaimFile(t)
	leaf, err := base64.StdEncoding.DecodeString(file.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(file.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := sidecar.VerifyDnsReclaimProof(file.Vectors[0].proof(t), leaf, signature); err != nil {
		t.Fatalf("the vector: %v", err)
	}
	// another incident, the same name and network
	if err := sidecar.VerifyDnsReclaimProof(file.Vectors[1].proof(t), leaf, signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("another incident: %v", err)
	}
	otherNetwork := file.Vectors[0].proof(t)
	otherNetwork.NetworkId = sidecar.NewId()
	if err := sidecar.VerifyDnsReclaimProof(otherNetwork, leaf, signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("another network: %v", err)
	}
	// another name the leaf does not name
	if err := sidecar.VerifyDnsReclaimProof(file.Vectors[2].proof(t), leaf, signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("another name: %v", err)
	}
}

// A leaf on a fresh key naming tuple's name.
func testDnsReclaimLeaf(t testing.TB, key *ecdsa.PrivateKey, names ...string) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Sign's signature verifies under the signer's own leaf, through a wildcard naming too; another key's leaf, a leaf
// naming another name and a P-384 key are refused.
func TestDnsReclaimProofSignsWithTheLeafsKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := &sidecar.DnsReclaimProof{Name: "lbl0000002.root.example", NetworkId: sidecar.NewId(), IncidentId: sidecar.NewId()}
	signature, err := proof.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := sidecar.VerifyDnsReclaimProof(proof, testDnsReclaimLeaf(t, key, "lbl0000002.root.example"), signature); err != nil {
		t.Errorf("its own leaf: %v", err)
	}
	if err := sidecar.VerifyDnsReclaimProof(proof, testDnsReclaimLeaf(t, key, "*.lbl0000002.root.example"), signature); err != nil {
		t.Errorf("a wildcard leaf: %v", err)
	}
	if err := sidecar.VerifyDnsReclaimProof(proof, testDnsReclaimLeaf(t, other, "lbl0000002.root.example"), signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("another key's leaf: %v", err)
	}
	if err := sidecar.VerifyDnsReclaimProof(proof, testDnsReclaimLeaf(t, key, "lbl0000003.root.example"), signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("a leaf naming another name: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proof.Sign(p384); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("a P-384 key: %v", err)
	}
	if err := sidecar.VerifyDnsReclaimProof(proof, []byte("not a certificate"), signature); !errors.Is(err, sidecar.ErrDnsReclaimRefused) {
		t.Errorf("a leaf that does not parse: %v", err)
	}
}
