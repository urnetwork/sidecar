// The key schedule against published traces, independently of the tests that compare the client to
// crypto/tls: a shared misreading of RFC 8446 would pass those and fail these.

package smtpproof

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
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
// tls13MasterSecret, tls13TrafficSecret and tls13TrafficKeys.
//
// Of the trace's application values, two are checked: its server application traffic secret gives
// its key and IV, and MS over the hash of the handshake through the client's Finished gives its
// resumption master secret, which is Derive-Secret at MS over a whole handshake, as the application
// secrets are. The application secrets are not derived from MS here: that needs the hash through the
// server's Finished, which no copy of the RFC on this machine holds, and a value recalled wrong would
// only be replaced by this code's own output. The ACVP vector below derives them from a published MS
// and transcript instead.
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
	// Transcript-Hash(ClientHello .. client Finished), and resumption_master_secret under it.
	clientFinishedHash string
	resumption         string
	serverApTraffic    string
	serverApKey        string
	serverApIv         string
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

		clientFinishedHash: "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d",
		resumption:         "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c",
		serverApTraffic:    "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43",
		serverApKey:        "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56",
		serverApIv:         "cf 78 2b 88 dd 83 54 9a ad f1 e9 84",
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

	// past the handshake keys: Derive-Secret at the MS this code derived, over a whole handshake's
	// hash, and an application traffic secret's key and IV
	ms := tls13MasterSecret(hs)
	testExpectOctets(t, "resumption master secret", tls13TrafficSecret(ms, "res master", octets(trace.clientFinishedHash)), octets(trace.resumption))
	key, iv = tls13TrafficKeys(tlsSuiteAes128GcmSha256, octets(trace.serverApTraffic))
	testExpectOctets(t, "server application key", key, octets(trace.serverApKey))
	testExpectOctets(t, "server application iv", iv, octets(trace.serverApIv))

	// Z1's binding: the hash of the trace's SHTS is what the edge would hold as H_shts, and HS with
	// H_sh reproduces it while a neighbouring HS does not
	other := bytes.Clone(hs)
	other[31] ^= 1
	if bytes.Equal(tls13TrafficSecret(other, "s hs traffic", helloHash), shts) {
		t.Error("another HS gave the trace's SHTS")
	}
}

func TestKeyScheduleReproducesTheAcvpVector(t *testing.T) {
	// NIST ACVP's TLS 1.3 KDF test (ACVP-Server commit 3a7333f63, gen-val/json-files/
	// TLS-v1.3-KDF-RFC8446, prompt.json lines 428-436 and expectedResults.json lines 571-581), as Go's
	// crypto/tls key_schedule_test.go carries it. Its transcript is the hash of the four randoms
	// written in turn, and its early secret has a PSK, so HS is built here from the steps
	// tls13HandshakeSecret folds for the zero PSK. What it adds to RFC 8448's trace is the step Z1 takes
	// after MS: both application traffic secrets from MS under a whole handshake's hash.
	octets := func(text string) []byte {
		return testHex(t, strings.ToLower(text))
	}
	psk := octets("56288B726C73829F7A3E47B103837C8139ACF552E7530C7A710B35ED41191698")
	dhe := octets("EFFE9EC26AA29FD750DFA6A10B944D74071595B27EE88887D5E11C84590B5CC3")
	helloClientRandom := octets("E9137679E582BA7C1DB41CF725F86C6D09C8C05F297BAD9A65B552EAF524FDE4")
	helloServerRandom := octets("23ECCFD030790748C8F8D8A656FD98D717F1B62AF3712F97211D2070B499F98A")
	finishedClientRandom := octets("62A62FA75563ED4FDCAA0BC16567B314871C304ACF06B0FFC3F08C1797594D43")
	finishedServerRandom := octets("C750EDA6696CD101B142BD79E00E6AC8C5F2C0ABC78DD64F4D991326659E9299")
	transcriptHash := func(parts ...[]byte) []byte {
		sum := sha256.Sum256(bytes.Join(parts, nil))
		return sum[:]
	}

	earlySecret := tlsExtract(nil, psk)
	testExpectOctets(t, "client early traffic secret", tls13TrafficSecret(earlySecret, "c e traffic", transcriptHash(helloClientRandom)),
		octets("3272189698C3594D18F58EFA3F12B638A249515099BE7A2FA9836BABE74F0111"))
	hs := tlsExtract(tlsExpandLabel(earlySecret, "derived", tlsEmptyHash(), tlsSecretBytes), dhe)

	helloHash := transcriptHash(helloClientRandom, helloServerRandom)
	testExpectOctets(t, "CHTS", tls13TrafficSecret(hs, "c hs traffic", helloHash), octets("B32306C3CE9932C460A1FE6C0F060593974842036B96FA45049B7352E71C2AD2"))
	testExpectOctets(t, "SHTS", tls13TrafficSecret(hs, "s hs traffic", helloHash), octets("22787F8CA269D34BC549AC8BA19F2040938A3AA370D7CC9D60F720882B88D01B"))

	ms := tls13MasterSecret(hs)
	finishedHash := transcriptHash(helloClientRandom, helloServerRandom, finishedServerRandom)
	testExpectOctets(t, "CATS", tls13TrafficSecret(ms, "c ap traffic", finishedHash), octets("47D7EA08397B5871154B0FE85584BCC30A87C69E84D69B56007C5B21F76493BA"))
	testExpectOctets(t, "SATS", tls13TrafficSecret(ms, "s ap traffic", finishedHash), octets("EFBDB0C873C0480DA57307083839A8984BE25B9A8545E4FCA029940FE2800565"))
	testExpectOctets(t, "exporter master secret", tls13TrafficSecret(ms, "exp master", finishedHash), octets("8A43D787EE3804EAD4A2A5B32972F9896B696295645D7222E1FD081DDD939834"))
	testExpectOctets(t, "resumption master secret", tls13TrafficSecret(ms, "res master", transcriptHash(helloClientRandom, helloServerRandom, finishedServerRandom, finishedClientRandom)),
		octets("5F4C961329C91044011ACBECB0B289282E0E3FED045CB3EA924DFFE5FE654B3D"))
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
