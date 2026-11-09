package sidecar

// RFC 8785's canonical JSON and the admin token's cmd digest (TEAM-M1-08). testdata/admin_command/vectors.json
// holds RFC 8785's own cases and numbers and digests computed outside this repository; every leg runs these, the
// Worker's included, so the bytes are equal wherever ur-cli or api computes them.

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// The Worker leg has no file system, so the vectors are embedded.
//
//go:embed testdata/admin_command/vectors.json
var adminCommandVectorsJson []byte

type adminCommandVectors struct {
	Canonical []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	} `json:"canonical"`
	Numbers []struct {
		Bits string `json:"bits"`
		Text string `json:"text"`
	} `json:"numbers"`
	Digests []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
		Cmd    string `json:"cmd"`
	} `json:"digests"`
}

func loadAdminCommandVectors(t *testing.T) *adminCommandVectors {
	t.Helper()
	vectors := &adminCommandVectors{}
	if err := json.Unmarshal(adminCommandVectorsJson, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Canonical) == 0 || len(vectors.Numbers) == 0 || len(vectors.Digests) == 0 {
		t.Fatal("the vectors are empty")
	}
	return vectors
}

func TestCanonicalJsonRfc8785Vectors(t *testing.T) {
	for _, vector := range loadAdminCommandVectors(t).Canonical {
		canonical, err := CanonicalJson([]byte(vector.Input))
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if string(canonical) != vector.Canonical {
			t.Errorf("%s:\n%s\nnot\n%s", vector.Name, canonical, vector.Canonical)
		}
		// canonical form is a fixed point
		again, err := CanonicalJson(canonical)
		if err != nil || !bytes.Equal(again, canonical) {
			t.Errorf("%s: not a fixed point: %s %v", vector.Name, again, err)
		}
	}
}

func TestCanonicalJsonRfc8785Numbers(t *testing.T) {
	for _, vector := range loadAdminCommandVectors(t).Numbers {
		bits, err := hex.DecodeString(vector.Bits)
		if err != nil || len(bits) != 8 {
			t.Fatalf("bits %s", vector.Bits)
		}
		value := math.Float64frombits(binary.BigEndian.Uint64(bits))
		if text := EcmaScriptNumber(value); text != vector.Text {
			t.Errorf("%s: %s not %s", vector.Bits, text, vector.Text)
		}
		// and through the parser, as a number in a body arrives
		canonical, err := CanonicalJson([]byte("[" + vector.Text + "]"))
		if err != nil || string(canonical) != "["+vector.Text+"]" {
			t.Errorf("%s through the parser: %s %v", vector.Bits, canonical, err)
		}
	}
}

// What RFC 8785 cannot canonicalize is refused, never written some other way.
func TestCanonicalJsonRefusals(t *testing.T) {
	for _, bad := range []string{
		`{"a":1,"a":2}`,
		`{"a":1} {}`,
		`[1e400]`,
		`[-1e400]`,
		"\"\xff\"",
		`{"a":`,
		``,
		strings.Repeat("[", 70) + strings.Repeat("]", 70),
	} {
		if canonical, err := CanonicalJson([]byte(bad)); !errors.Is(err, ErrCanonicalJsonInvalid) {
			t.Errorf("%q canonicalized to %q: %v", bad, canonical, err)
		}
	}
}

// Every control below 0x20 escapes, the five short ones by their short forms, and nothing else does.
func TestCanonicalJsonStringEscapes(t *testing.T) {
	input, _ := json.Marshal("\x00\x01\b\t\n\f\r\x1f \"\\/\u007f\u2028<>&")
	canonical, err := CanonicalJson(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := "\"\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f \\\"\\\\/\u007f\u2028<>&\""
	if string(canonical) != expected {
		t.Fatalf("%s\nnot\n%s", canonical, expected)
	}
}

func TestAdminCommandDigestVectors(t *testing.T) {
	for _, vector := range loadAdminCommandVectors(t).Digests {
		cmd, err := AdminCommandDigest(vector.Method, vector.Path, []byte(vector.Body))
		if err != nil {
			t.Fatal(err)
		}
		if cmd != vector.Cmd {
			t.Errorf("%s %s %s: %s not %s", vector.Method, vector.Path, vector.Body, cmd, vector.Cmd)
		}
	}
}

// A body that changes in anything but whitespace and member order, another method or another path changes cmd.
func TestAdminCommandDigestBindsMethodPathAndBody(t *testing.T) {
	base, err := AdminCommandDigest("POST", "/network/auth-keys", []byte(`{"duration_seconds":300,"max_uses":1}`))
	if err != nil {
		t.Fatal(err)
	}
	same, err := AdminCommandDigest("POST", "/network/auth-keys", []byte("{ \"max_uses\" : 1 ,\n\"duration_seconds\":300.0 }"))
	if err != nil || same != base {
		t.Fatalf("whitespace, order and a number's spelling moved cmd: %s %v", same, err)
	}
	for _, command := range []*AdminCommand{
		{Method: "PUT", Path: "/network/auth-keys", Body: []byte(`{"duration_seconds":300,"max_uses":1}`)},
		{Method: "POST", Path: "/network/auth-key-revoke", Body: []byte(`{"duration_seconds":300,"max_uses":1}`)},
		{Method: "POST", Path: "/network/auth-keys", Body: []byte(`{"duration_seconds":301,"max_uses":1}`)},
		{Method: "POST", Path: "/network/auth-keys", Body: []byte(`{"duration_seconds":300,"max_uses":1,"tags":[]}`)},
		{Method: "POST", Path: "/network/auth-keys", Body: []byte(`{"duration_seconds":"300","max_uses":1}`)},
		{Method: "POST", Path: "/network/auth-keys"},
	} {
		cmd, err := command.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if cmd == base {
			t.Errorf("%s %s %s has the same cmd", command.Method, command.Path, command.Body)
		}
	}
	// the separator keeps method and path apart from each other and from the body
	a, _ := AdminCommandDigest("POST", "/ab", nil)
	b, _ := AdminCommandDigest("POS", "/ab", nil)
	if a == b {
		t.Fatal("method and path run together")
	}
}

func TestAdminCommandRefusals(t *testing.T) {
	for _, command := range []*AdminCommand{
		{Method: "post", Path: "/network/auth-keys"},
		{Method: "", Path: "/network/auth-keys"},
		{Method: "POST", Path: "network/auth-keys"},
		{Method: "POST", Path: "/network/auth-keys?x=1"},
		{Method: "POST", Path: "/network/auth-keys#x"},
		{Method: "POST", Path: "/network/auth keys"},
		{Method: "POST", Path: "/network/auth-keys", Body: []byte(`{"a":1,"a":1}`)},
		{Method: "POST", Path: "/network/auth-keys", Body: bytes.Repeat([]byte(" "), AdminCommandMaxBodyByteCount+1)},
	} {
		if _, err := command.Digest(); !errors.Is(err, ErrAdminCommandInvalid) {
			t.Errorf("%q %q %q: %v", command.Method, command.Path, command.Body, err)
		}
	}
}

// authorization_details round trips one command and its code, and refuses anything but one entry of the type.
func TestAdminCommandDetailsRoundTrip(t *testing.T) {
	command := &AdminCommand{Method: "POST", Path: "/network/auth-keys", Body: []byte(`{"max_uses":1,"duration_seconds":300}`)}
	code, err := NewAdminConsentCode(bytes.NewReader(bytes.Repeat([]byte{7, 200, 255, 31}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatAdminCommandDetails(command, code)
	if err != nil {
		t.Fatal(err)
	}
	expected := `[{"type":"urn:ur:params:oauth:admin-command","method":"POST","path":"/network/auth-keys",` +
		`"body":{"duration_seconds":300,"max_uses":1},"consent_code":"` + code + `"}]`
	if formatted != expected {
		t.Fatalf("%s\nnot\n%s", formatted, expected)
	}
	details, err := ParseAdminCommandDetails(formatted)
	if err != nil {
		t.Fatal(err)
	}
	parsedCmd, _ := details.Command().Digest()
	commandCmd, _ := command.Digest()
	if parsedCmd != commandCmd || details.ConsentCode != code {
		t.Fatalf("parsed %+v", details)
	}

	for _, bad := range []string{
		`[]`,
		`{}`,
		expected[:len(expected)-1] + `,{"type":"urn:ur:params:oauth:admin-command","method":"GET","path":"/a","consent_code":"` + code + `"}]`,
		strings.Replace(expected, "urn:ur:params:oauth:admin-command", "payment_initiation", 1),
		strings.Replace(expected, `"consent_code"`, `"extra":1,"consent_code"`, 1),
		strings.Replace(expected, code, "ABCD-EFG0", 1),
		strings.Replace(expected, `"POST"`, `"post"`, 1),
		expected + ` []`,
	} {
		if _, err := ParseAdminCommandDetails(bad); !errors.Is(err, ErrAdminCommandInvalid) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// A consent code is two groups of four of the alphabet, every symbol equally likely: a draw past the alphabet's
// largest multiple is drawn again.
func TestAdminConsentCode(t *testing.T) {
	code, err := NewAdminConsentCode(bytes.NewReader([]byte{0, 1, 2, 3, 240, 4, 5, 6, 7}))
	if err != nil {
		t.Fatal(err)
	}
	if code != "2345-6789" {
		t.Fatalf("code %s", code)
	}
	if err := ValidateAdminConsentCode(code); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"23456789", "2345_6789", "2345-678", "2345-678I", "abcd-efgh", "2345-67890"} {
		if err := ValidateAdminConsentCode(bad); !errors.Is(err, ErrAdminCommandInvalid) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := NewAdminConsentCode(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("a short draw made a code")
	}
}

// RFC 8037 Appendix A's key: its thumbprint is A.3's.
func TestDpopKeyThumbprintRfc8037(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key, err := NewAdminDpopKey(bytes.NewReader(seed), func() time.Time { return time.Unix(1767225600, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if key.Thumbprint != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", key.Thumbprint)
	}
}

// A proof by an admin DPoP key names its key, the request and the token, and an erased key signs nothing.
func TestAdminDpopKeySignsAndErases(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{9}, 32+16))
	key, err := NewAdminDpopKey(random, func() time.Time { return time.Unix(1767225600, 0) })
	if err != nil {
		t.Fatal(err)
	}
	proof, err := key.Sign("POST", "https://api.example/network/auth-keys?x=1", "synthetic-token")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof %s", proof)
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	jwk := &struct {
		Jwk struct {
			X string `json:"x"`
		} `json:"jwk"`
	}{}
	if err := json.Unmarshal(header, jwk); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(jwk.Jwk.X)
	if DpopKeyThumbprint(publicKey) != key.Thumbprint || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("the proof is not by the key")
	}
	expectedClaims := `{"ath":"` + dpopAth("synthetic-token") + `","htm":"POST","htu":"https://api.example/network/auth-keys","iat":1767225600,"jti":"`
	if !strings.HasPrefix(string(claims), expectedClaims) {
		t.Fatalf("claims %s", claims)
	}
	key.Erase()
	if _, err := key.Sign("POST", "https://api.example/network/auth-keys", "synthetic-token"); err == nil {
		t.Fatal("an erased key signed")
	}
}
