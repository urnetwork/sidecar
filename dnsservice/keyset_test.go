package dnsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar/dnsservice"
)

// A visibly synthetic P-256 scalar. No key here signs anything outside tests.
const keysetTestScalarHex = "4444444444444444444444444444444444444444444444444444444444444444"

func keysetTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(keysetTestScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The file BIND's tools and miekg write for key.
func keysetTestFile(key *ecdsa.PrivateKey) string {
	return (&dns.DNSKEY{Algorithm: dns.ECDSAP256SHA256}).PrivateKeyString(key)
}

func TestLoadZskReadsBindsPrivateKeyFormat(t *testing.T) {
	key := keysetTestKey(t)
	for _, text := range []string{
		keysetTestFile(key),
		strings.Replace(keysetTestFile(key), "v1.3", "v1.2", 1),
		keysetTestFile(key) + "Created: 20261101000000\nPublish: 20261101000000\nActivate: 20261101000000\n",
		"\n" + strings.ReplaceAll(keysetTestFile(key), "\n", "\r\n"),
	} {
		zsk, err := dnsservice.LoadZsk([]byte(text))
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if !key.PublicKey.Equal(zsk.Public()) {
			t.Errorf("%q: another public key", text)
		}
	}
}

func TestLoadZskRefusals(t *testing.T) {
	key := keysetTestKey(t)
	good := keysetTestFile(key)
	encoded := base64.StdEncoding.EncodeToString(key.D.FillBytes(make([]byte, 32)))
	order, _ := hex.DecodeString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
	cases := []struct {
		name string
		text string
	}{
		{name: "an unknown format", text: strings.Replace(good, "v1.3", "v1.4", 1)},
		{name: "no format", text: strings.Replace(good, "Private-key-format: v1.3\n", "", 1)},
		{name: "another algorithm", text: strings.Replace(good, "Algorithm: 13", "Algorithm: 14", 1)},
		{name: "no private key", text: strings.Replace(good, "PrivateKey: "+encoded+"\n", "", 1)},
		{name: "not base64", text: strings.Replace(good, encoded, "!!!!", 1)},
		{name: "a short scalar", text: strings.Replace(good, encoded, base64.StdEncoding.EncodeToString(make([]byte, 31)), 1)},
		{name: "a zero scalar", text: strings.Replace(good, encoded, base64.StdEncoding.EncodeToString(make([]byte, 32)), 1)},
		{name: "a scalar past the order", text: strings.Replace(good, encoded, base64.StdEncoding.EncodeToString(order), 1)},
		{name: "a field twice", text: good + "PrivateKey: " + encoded + "\n"},
		{name: "a line with no field", text: good + "garbage\n"},
		{name: "nothing", text: ""},
	}
	for _, c := range cases {
		zsk, err := dnsservice.LoadZsk([]byte(c.text))
		if !errors.Is(err, dnsservice.ErrDnsKeyRefused) {
			t.Errorf("%s: %v %v", c.name, zsk, err)
			continue
		}
		// a refusal names the part, never the key
		if strings.Contains(err.Error(), encoded) {
			t.Errorf("%s: the refusal holds the key", c.name)
		}
	}
}

func TestParseDnsTrustAnchorsTakesOnlyKeySigningKeys(t *testing.T) {
	key := keysetTestKey(t)
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(point[1:])
	anchors, err := dnsservice.ParseDnsTrustAnchors("Zone.Example", []string{"257 3 13 " + public})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 || anchors[0].Hdr.Name != "zone.example." || anchors[0].Flags != 257 {
		t.Errorf("anchors %v", anchors)
	}
	for _, rdata := range []string{"256 3 13 " + public, "257 3 8 " + public, "385 3 13 " + public, "257 3 13 !!!", "257 3 13 " + public + "\n257"} {
		if _, err := dnsservice.ParseDnsTrustAnchors("zone.example.", []string{rdata}); !errors.Is(err, dnsservice.ErrDnsKeyRefused) {
			t.Errorf("%q: %v", rdata, err)
		}
	}
	if _, err := dnsservice.ParseDnsTrustAnchors("zone.example.", nil); !errors.Is(err, dnsservice.ErrDnsKeyRefused) {
		t.Errorf("none: %v", err)
	}
	if _, err := dnsservice.ParseDnsTrustAnchors("example", []string{"257 3 13 " + public}); !errors.Is(err, dnsservice.ErrDnsKeyRefused) {
		t.Errorf("a top-level root: %v", err)
	}
}
