// Fixed DPoP proofs (§7.4) and the exact bytes they give, on every leg, so a build whose encoding
// moves fails here, wasm's included, and server's verifier (TEAM-M1-02) checks the same file. A
// format change regenerates it:
//
//	go test -run TestDpopVectors . -args -update-dpop-vectors
//
// which is a format change, and is read as one in review. The Worker has no file system, so the
// vectors are embedded.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/dpop/vectors.json
var dpopVectorsJson []byte

var updateDpopVectors = flag.Bool("update-dpop-vectors", false, "rewrite testdata/dpop/vectors.json")

// One proof: its inputs, then what they give.
type dpopVector struct {
	Name string `json:"name"`
	// The ClientKey seed.
	Seed     hexBytes `json:"seed"`
	Method   string   `json:"method"`
	Url      string   `json:"url"`
	Token    string   `json:"token"`
	JtiBytes hexBytes `json:"jti_bytes"`
	Iat      int64    `json:"iat"`

	PublicKey hexBytes `json:"public_key"`
	Ath       string   `json:"ath"`
	Htu       string   `json:"htu"`
	Jti       string   `json:"jti"`
	Header    string   `json:"header"`
	Claims    string   `json:"claims"`
	Proof     string   `json:"proof"`
}

// The file's shape.
type dpopVectors struct {
	Proofs []dpopVector `json:"proofs"`
}

// The seed 00 01 .. 1f, visibly synthetic.
func dpopVectorSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// A clock stopped at unix second iat.
func fixedDpopClock(iat int64) func() time.Time {
	return func() time.Time {
		return time.Unix(iat, 0)
	}
}

// Each vector's inputs, and its outputs from this leg's signer.
func computeDpopVectors(t *testing.T) *dpopVectors {
	t.Helper()
	inputs := []dpopVector{
		{
			Name:     "refresh",
			Seed:     dpopVectorSeed(),
			Method:   "GET",
			Url:      "https://api.example/auth/refresh",
			Token:    "synthetic-client-jwt-1",
			JtiBytes: bytes.Repeat([]byte{0xa1}, dpopJtiByteCount),
			Iat:      1767225600,
		},
		{
			Name:     "exchange",
			Seed:     dpopVectorSeed(),
			Method:   "POST",
			Url:      "https://auth.example/oauth/token",
			Token:    "synthetic-client-jwt-1",
			JtiBytes: bytes.Repeat([]byte{0xb2}, dpopJtiByteCount),
			Iat:      1767225660,
		},
		{
			Name:     "auth-client, query and fragment dropped",
			Seed:     dpopVectorSeed(),
			Method:   "POST",
			Url:      "https://api.example/network/auth-client?synthetic=1&b=2#fragment",
			Token:    "synthetic-client-jwt-2",
			JtiBytes: bytes.Repeat([]byte{0xc3}, dpopJtiByteCount),
			Iat:      1767225720,
		},
		{
			Name:     "another key, a port and an & in the path",
			Seed:     bytes.Repeat([]byte{0x5a}, ed25519.SeedSize),
			Method:   "GET",
			Url:      "https://api.example:8443/auth/refresh&synthetic",
			Token:    "synthetic-client-jwt-3",
			JtiBytes: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			Iat:      1767225780,
		},
	}

	vectors := &dpopVectors{}
	for _, vector := range inputs {
		signer, err := newDpopSigner(vector.Seed, fixedDpopClock(vector.Iat), bytes.NewReader(vector.JtiBytes))
		if err != nil {
			t.Fatal(err)
		}
		vector.Ath = dpopAth(vector.Token)
		proof, err := signer(vector.Method, vector.Url, vector.Ath)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		parts := strings.Split(proof, ".")
		if len(parts) != 3 {
			t.Fatalf("%s: %d parts", vector.Name, len(parts))
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		claims, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		vector.PublicKey = hexBytes(ed25519.NewKeyFromSeed(vector.Seed).Public().(ed25519.PublicKey))
		vector.Htu, err = dpopHtu(vector.Url)
		if err != nil {
			t.Fatal(err)
		}
		vector.Jti = base64.RawURLEncoding.EncodeToString(vector.JtiBytes)
		vector.Header = string(header)
		vector.Claims = string(claims)
		vector.Proof = proof
		vectors.Proofs = append(vectors.Proofs, vector)
	}
	return vectors
}

// The file as checked in, with what this leg computes from the same inputs beside it.
func TestDpopVectorsAreByteEqual(t *testing.T) {
	encoded, err := json.MarshalIndent(computeDpopVectors(t), "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updateDpopVectors {
		if err := os.WriteFile("testdata/dpop/vectors.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(encoded, dpopVectorsJson) {
		t.Error("a vector moved: this leg computes other bytes than testdata/dpop/vectors.json holds")
	}
}

// A proof's header and claims as a verifier decodes them.
type testDpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		D   string `json:"d"`
	} `json:"jwk"`
}

// The claims a verifier reads.
type testDpopClaims struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Ath string `json:"ath"`
}

// Verifies proof as §7.4's verifier does, short of the clock and the replay store: the compact form,
// the header, and the signature by publicKey, which the jwk must name. Answers the claims.
func verifyTestDpopProof(t *testing.T, proof string, publicKey ed25519.PublicKey) *testDpopClaims {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("a proof of %d parts", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	header := &testDpopHeader{}
	if err := json.Unmarshal(headerBytes, header); err != nil {
		t.Fatal(err)
	}
	if header.Typ != "dpop+jwt" || header.Alg != "EdDSA" || header.Jwk.Kty != "OKP" || header.Jwk.Crv != "Ed25519" {
		t.Errorf("header %s", headerBytes)
	}
	if header.Jwk.D != "" {
		t.Error("the jwk holds a private key")
	}
	if header.Jwk.X != base64.RawURLEncoding.EncodeToString(publicKey) {
		t.Errorf("the jwk names another key than the signer's")
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Error("the signature does not verify")
	}
	claims := &testDpopClaims{}
	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// Each vector also verifies, so the file cannot pin bytes no verifier takes.
func TestDpopVectorsVerify(t *testing.T) {
	vectors := &dpopVectors{}
	if err := json.Unmarshal(dpopVectorsJson, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Proofs) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range vectors.Proofs {
		publicKey := ed25519.NewKeyFromSeed(vector.Seed).Public().(ed25519.PublicKey)
		if !bytes.Equal(publicKey, vector.PublicKey) {
			t.Errorf("%s: the public key is not the seed's", vector.Name)
		}
		claims := verifyTestDpopProof(t, vector.Proof, publicKey)
		if claims.Htm != vector.Method || claims.Htu != vector.Htu || claims.Iat != vector.Iat {
			t.Errorf("%s: claims %+v", vector.Name, claims)
		}
		if claims.Ath != dpopAth(vector.Token) || claims.Ath != vector.Ath {
			t.Errorf("%s: ath is not the token's hash", vector.Name)
		}
		if claims.Jti != base64.RawURLEncoding.EncodeToString(vector.JtiBytes) || claims.Jti != vector.Jti {
			t.Errorf("%s: jti %q", vector.Name, claims.Jti)
		}
		if strings.ContainsAny(claims.Htu, "?#") {
			t.Errorf("%s: htu %q keeps a query or fragment", vector.Name, claims.Htu)
		}
	}
}

// RFC 9449's htu: no query, no fragment, and the rest as the request had it.
func TestDpopHtuDropsQuery(t *testing.T) {
	signer, err := newDpopSigner(dpopVectorSeed(), fixedDpopClock(1767225600), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(dpopVectorSeed()).Public().(ed25519.PublicKey)
	for _, c := range []struct {
		url string
		htu string
	}{
		{url: "https://api.example/auth/refresh?a=1&b=2", htu: "https://api.example/auth/refresh"},
		{url: "https://api.example/auth/refresh#fragment", htu: "https://api.example/auth/refresh"},
		{url: "https://api.example/auth/refresh?a=1#fragment", htu: "https://api.example/auth/refresh"},
		{url: "https://api.example/auth/refresh?", htu: "https://api.example/auth/refresh"},
		{url: "https://api.example", htu: "https://api.example/"},
		{url: "https://api.example?a=1", htu: "https://api.example/"},
		{url: "https://api.example:8443/sidecar/identity/x%2Fy?q", htu: "https://api.example:8443/sidecar/identity/x%2Fy"},
	} {
		proof, err := signer("GET", c.url, dpopAth("synthetic-token"))
		if err != nil {
			t.Fatalf("%q: %v", c.url, err)
		}
		if claims := verifyTestDpopProof(t, proof, publicKey); claims.Htu != c.htu {
			t.Errorf("%q: htu %q, want %q", c.url, claims.Htu, c.htu)
		}
	}
}

// What the signer refuses signs nothing, and its error repeats no argument.
func TestDpopSignerRefusesWhatIsNotARequest(t *testing.T) {
	signer, err := newDpopSigner(dpopVectorSeed(), fixedDpopClock(1767225600), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ath := dpopAth("synthetic-token")
	for _, c := range []struct {
		method string
		url    string
		ath    string
	}{
		{method: "get", url: "https://api.example/auth/refresh", ath: ath},
		{method: "", url: "https://api.example/auth/refresh", ath: ath},
		{method: "GET\n", url: "https://api.example/auth/refresh", ath: ath},
		{method: "GET", url: "/auth/refresh", ath: ath},
		{method: "GET", url: "", ath: ath},
		{method: "GET", url: "ftp://api.example/auth/refresh", ath: ath},
		{method: "GET", url: "https://synthetic-user:synthetic-pass@api.example/auth/refresh", ath: ath},
		{method: "GET", url: "https://api.example/auth/refresh", ath: ""},
		{method: "GET", url: "https://api.example/auth/refresh", ath: "synthetic-token"},
		{method: "GET", url: "https://api.example/auth/refresh", ath: ath + "="},
	} {
		proof, err := signer(c.method, c.url, c.ath)
		if !errors.Is(err, errDpopProof) || proof != "" {
			t.Errorf("%q %q %q: %q, %v", c.method, c.url, c.ath, proof, err)
			continue
		}
		if strings.Contains(err.Error(), "synthetic") {
			t.Errorf("the error repeats an argument: %v", err)
		}
	}
}

// A ClientKey seed is 32 bytes, connect.ClientSettings.ClientKeySeed's.
func TestDpopSignerRefusesAShortSeed(t *testing.T) {
	for _, seed := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 64)} {
		if _, err := newDpopSigner(seed, time.Now, cryptorand.Reader); !errors.Is(err, errDpopProof) {
			t.Errorf("%d bytes: %v", len(seed), err)
		}
	}
}

// Each proof draws its own jti, which a verifier spends once, and iat follows the clock.
func TestDpopSignerDrawsEachJtiAndReadsTheClock(t *testing.T) {
	now := time.Unix(1767225600, 0)
	signer, err := newDpopSigner(dpopVectorSeed(), func() time.Time { return now }, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(dpopVectorSeed()).Public().(ed25519.PublicKey)
	ath := dpopAth("synthetic-token")

	first, err := signer("GET", "https://api.example/auth/refresh", ath)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	second, err := signer("GET", "https://api.example/auth/refresh", ath)
	if err != nil {
		t.Fatal(err)
	}
	firstClaims := verifyTestDpopProof(t, first, publicKey)
	secondClaims := verifyTestDpopProof(t, second, publicKey)
	if firstClaims.Jti == secondClaims.Jti {
		t.Error("two proofs share a jti")
	}
	jti, err := base64.RawURLEncoding.DecodeString(firstClaims.Jti)
	if err != nil || len(jti) != 16 {
		t.Errorf("jti %q is not 128 bits", firstClaims.Jti)
	}
	if firstClaims.Iat != 1767225600 || secondClaims.Iat != 1767225661 {
		t.Errorf("iat %d, %d", firstClaims.Iat, secondClaims.Iat)
	}
}

// Failing reads, as an exhausted or broken source gives.
type failingDpopReader struct{}

func (self failingDpopReader) Read(buffer []byte) (int, error) {
	return 0, errors.New("synthetic draw failure")
}

// A jti that could not be drawn is not replaced by a weaker one: nothing is signed.
func TestDpopSignerSignsNothingWithoutAJti(t *testing.T) {
	for _, random := range []interface{ Read([]byte) (int, error) }{
		failingDpopReader{},
		bytes.NewReader(make([]byte, dpopJtiByteCount-1)),
	} {
		signer, err := newDpopSigner(dpopVectorSeed(), fixedDpopClock(1767225600), random)
		if err != nil {
			t.Fatal(err)
		}
		if proof, err := signer("GET", "https://api.example/auth/refresh", dpopAth("synthetic-token")); !errors.Is(err, errDpopProof) || proof != "" {
			t.Errorf("%q, %v", proof, err)
		}
	}
}

// ath is the unpadded base64url of SHA-256 over the token (RFC 9449 §4.2), here for an empty token,
// whose hash every implementation knows.
func TestDpopAthIsTheTokensHash(t *testing.T) {
	if ath := dpopAth(""); ath != "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Errorf("ath %q", ath)
	}
}
