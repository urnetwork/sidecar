// The key schedule against published traces, independently of the tests that compare the client to
// crypto/tls: a shared misreading of RFC 8446 would pass those and fail these.

package smtpproof

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"strings"
	"testing"
)

// Octets written as RFC 8448 prints them, in space-separated hex.
func testSpacedHex(t *testing.T, spaced string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(spaced), ""))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// RFC 8448 section 3, the simple 1-RTT handshake: TLS_AES_128_GCM_SHA256 over x25519, through the
// handshake secrets and MS. Every function Z1 mirrors runs here: tls13HandshakeSecret,
// tls13MasterSecret, tls13TrafficSecret and tls13TrafficKeys. The trace's application traffic
// secrets are not reproduced: this machine holds no copy of the RFC to check their transcript hash
// against, and a value recalled wrong would only be replaced by this code's own output.
type testRfc8448Trace struct {
	clientPrivate string
	serverPublic  string
	sharedSecret  string
	// Transcript-Hash(ClientHello .. ServerHello), which is Z1's H_sh.
	helloHash     string
	earlySecret   string
	derived       string
	hs            string
	chts          string
	shts          string
	masterDerived string
	ms            string
	serverHsKey   string
	serverHsIv    string
	clientHsKey   string
	clientHsIv    string
	serverFinKey  string
}

func testRfc8448() *testRfc8448Trace {
	return &testRfc8448Trace{
		clientPrivate: "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05",
		serverPublic:  "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f",
		sharedSecret:  "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
		helloHash:     "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8",
		earlySecret:   "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a",
		derived:       "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba",
		hs:            "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac",
		chts:          "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21",
		shts:          "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38",
		masterDerived: "43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4",
		ms:            "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19",
		serverHsKey:   "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc",
		serverHsIv:    "5d 31 3e b2 67 12 76 ee 13 00 0b 30",
		clientHsKey:   "db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01",
		clientHsIv:    "5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f",
		serverFinKey:  "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8",
	}
}

func testExpectOctets(t *testing.T, name string, got []byte, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s: %x, want %x", name, got, want)
	}
}

func TestKeyScheduleReproducesRfc8448(t *testing.T) {
	trace := testRfc8448()
	octets := func(spaced string) []byte {
		return testSpacedHex(t, spaced)
	}

	// the ECDHE secret itself, so the trace's IKM is not taken on trust either
	private, err := ecdh.X25519().NewPrivateKey(octets(trace.clientPrivate))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.X25519().NewPublicKey(octets(trace.serverPublic))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	testExpectOctets(t, "ECDHE secret", shared, octets(trace.sharedSecret))

	// each step of RFC 8446 §7.1 that tls13HandshakeSecret and tls13MasterSecret fold together
	earlySecret := tlsExtract(nil, make([]byte, tlsSecretBytes))
	testExpectOctets(t, "early secret", earlySecret, octets(trace.earlySecret))
	testExpectOctets(t, "derived", tlsExpandLabel(earlySecret, "derived", tlsEmptyHash(), tlsSecretBytes), octets(trace.derived))
	hs := tls13HandshakeSecret(shared)
	testExpectOctets(t, "HS", hs, octets(trace.hs))
	testExpectOctets(t, "derived for MS", tlsExpandLabel(hs, "derived", tlsEmptyHash(), tlsSecretBytes), octets(trace.masterDerived))
	testExpectOctets(t, "MS", tls13MasterSecret(hs), octets(trace.ms))

	// the handshake traffic secrets under H_sh: SHTS is what E2 opens the flight with and Z1 hashes
	helloHash := octets(trace.helloHash)
	shts := tls13TrafficSecret(hs, "s hs traffic", helloHash)
	testExpectOctets(t, "SHTS", shts, octets(trace.shts))
	chts := tls13TrafficSecret(hs, "c hs traffic", helloHash)
	testExpectOctets(t, "CHTS", chts, octets(trace.chts))
	key, iv := tls13TrafficKeys(tlsSuiteAes128GcmSha256, shts)
	testExpectOctets(t, "server handshake key", key, octets(trace.serverHsKey))
	testExpectOctets(t, "server handshake iv", iv, octets(trace.serverHsIv))
	key, iv = tls13TrafficKeys(tlsSuiteAes128GcmSha256, chts)
	testExpectOctets(t, "client handshake key", key, octets(trace.clientHsKey))
	testExpectOctets(t, "client handshake iv", iv, octets(trace.clientHsIv))
	testExpectOctets(t, "server finished key", tlsExpandLabel(shts, "finished", nil, tlsSecretBytes), octets(trace.serverFinKey))

	// Z1's binding: the hash of the trace's SHTS is what the edge would hold as H_shts, and HS with
	// H_sh reproduces it while a neighbouring HS does not
	other := bytes.Clone(hs)
	other[31] ^= 1
	if bytes.Equal(tls13TrafficSecret(other, "s hs traffic", helloHash), shts) {
		t.Error("another HS gave the trace's SHTS")
	}
}

func TestExpandLabelInfoIsRfc8448s(t *testing.T) {
	// HkdfLabel, the octets the circuit hashes as HMAC input, as RFC 8448 prints them
	trace := testRfc8448()
	cases := []struct {
		label   string
		context []byte
		size    int
		want    string
	}{
		{label: "key", size: 16, want: "00 10 09 74 6c 73 31 33 20 6b 65 79 00"},
		{label: "iv", size: 12, want: "00 0c 08 74 6c 73 31 33 20 69 76 00"},
		{label: "finished", size: 32, want: "00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65 64 00"},
		{
			label: "c hs traffic", context: testSpacedHex(t, trace.helloHash), size: 32,
			want: "00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20 " + trace.helloHash,
		},
	}
	for _, c := range cases {
		testExpectOctets(t, c.label, tlsExpandLabelInfo(c.label, c.context, c.size), testSpacedHex(t, c.want))
	}
}

func TestTls12PrfReproducesThePublishedVector(t *testing.T) {
	// the P_SHA256 vector that implementations of RFC 5246 §5 share, 100 octets so that the output
	// spans four HMAC iterations and ends inside the fourth
	secret := testSpacedHex(t, "9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35")
	seed := testSpacedHex(t, "a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c")
	want := testSpacedHex(t, "e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a"+
		" 6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab"+
		" 4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01"+
		" 87 34 7b 66")
	testExpectOctets(t, "PRF", tls12Prf(secret, "test label", seed, len(want)), want)
	// a shorter output is the same stream's prefix, which the circuit's PRF relies on
	testExpectOctets(t, "PRF prefix", tls12Prf(secret, "test label", seed, 12), want[:12])
}
