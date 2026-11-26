//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A cache salt's line: [ur:<32 lowercase hex>].
var testInferCacheSaltLine = regexp.MustCompile(`^\[ur:[0-9a-f]{32}\]$`)

// testdata/infer/salt/vectors.json.
type testInferCacheSaltVectors struct {
	Tee []struct {
		Secret   string `json:"secret"`
		Provider string `json:"provider"`
		Line     string `json:"line"`
	} `json:"tee"`
	Direct []struct {
		Secret string `json:"secret"`
		RunId  string `json:"run_id"`
		Line   string `json:"line"`
	} `json:"direct"`
}

// A secret of 32 bytes from hex.
func testInferCacheSecretBytes(t *testing.T, text string) []byte {
	t.Helper()
	secret, err := hex.DecodeString(text)
	if err != nil || len(secret) != inferCacheSecretByteCount {
		t.Fatalf("secret %q: %v", text, err)
	}
	return secret
}

// The vectors, computed apart from crypto/hkdf, hold for both paths.
func TestCacheSaltVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "infer", "salt", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testInferCacheSaltVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Tee) == 0 || len(vectors.Direct) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range vectors.Tee {
		line, err := inferCacheSaltTee(testInferCacheSecretBytes(t, vector.Secret), vector.Provider)
		if err != nil || line != vector.Line {
			t.Errorf("tee %s: %q, %v; want %q", vector.Provider, line, err, vector.Line)
		}
	}
	for _, vector := range vectors.Direct {
		runBytes, err := hex.DecodeString(vector.RunId)
		if err != nil {
			t.Fatal(err)
		}
		runId, err := IdFromBytes(runBytes)
		if err != nil {
			t.Fatal(err)
		}
		line, err := inferCacheSaltDirect(testInferCacheSecretBytes(t, vector.Secret), &runId, rand.Reader)
		if err != nil || line != vector.Line {
			t.Errorf("direct %s: %q, %v; want %q", vector.RunId, line, err, vector.Line)
		}
	}
}

// One member's secret gives each provider its own salt, so no two providers' caches hold one prefix of the member's
// alike, and each salt is the line §6.6 writes.
func TestSaltDiffersAcrossProviders(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, inferCacheSecretByteCount)
	lines := map[string]string{}
	for _, provider := range []string{"chutes", "engy", "saygm", "reference"} {
		line, err := inferCacheSaltTee(secret, provider)
		if err != nil {
			t.Fatal(err)
		}
		if !testInferCacheSaltLine.MatchString(line) {
			t.Errorf("%s: %q is not [ur:<32 hex>]", provider, line)
		}
		for other, otherLine := range lines {
			if otherLine == line {
				t.Errorf("%s and %s share a salt", provider, other)
			}
		}
		lines[provider] = line
		again, err := inferCacheSaltTee(secret, provider)
		if err != nil || again != line {
			t.Errorf("%s: a second derivation gave %q", provider, again)
		}
	}
}

// The direct path's salt is per run: one run's calls share it, two runs differ, a call bound to no run or session takes
// a fresh one each time, and a party holding the run id the directory announces but not the secret derives none of
// them: neither from another secret, such as K_sock, nor by the TEE path's derivation over the same bytes.
func TestDirectSaltPerRunNotFromDirectory(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, inferCacheSecretByteCount)
	runA := NewId()
	runB := NewId()
	first, err := inferCacheSaltDirect(secret, &runA, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !testInferCacheSaltLine.MatchString(first) {
		t.Fatalf("%q is not [ur:<32 hex>]", first)
	}
	again, err := inferCacheSaltDirect(secret, &runA, rand.Reader)
	if err != nil || again != first {
		t.Errorf("one run's second call: %q", again)
	}
	other, err := inferCacheSaltDirect(secret, &runB, rand.Reader)
	if err != nil || other == first {
		t.Errorf("a second run shares the first's salt: %q", other)
	}
	fresh, err := inferCacheSaltDirect(secret, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	freshAgain, err := inferCacheSaltDirect(secret, nil, rand.Reader)
	if err != nil || fresh == freshAgain || fresh == first {
		t.Errorf("calls bound to no run: %q and %q", fresh, freshAgain)
	}
	// K_sock or any other secret every admitted sidecar holds gives another salt for the same run
	socketKey := bytes.Repeat([]byte{0x34}, inferCacheSecretByteCount)
	guess, err := inferCacheSaltDirect(socketKey, &runA, rand.Reader)
	if err != nil || guess == first {
		t.Errorf("another secret derived the run's salt: %q", guess)
	}
	// the run id alone, read as a provider's slug or as the TEE path's input, gives no salt of the run's
	runText := hex.EncodeToString(runA.Bytes())
	tee, err := inferCacheSaltTee(secret, runText)
	if err != nil || tee == first {
		t.Errorf("the TEE path over the run's id gave the run's salt: %q, %v", tee, err)
	}
}

// A salt is refused for a secret of another size and for a provider that is no slug, before anything is derived.
func TestCacheSaltRefusesWhatIsNoSecretOrSlug(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, inferCacheSecretByteCount)
	if _, err := inferCacheSaltTee(secret[:16], "chutes"); err == nil {
		t.Error("a 16-byte secret salted")
	}
	if _, err := inferCacheSaltTee(secret, "Chutes-AI"); err == nil {
		t.Error("a provider that is no slug salted")
	}
	run := NewId()
	if _, err := inferCacheSaltDirect(nil, &run, rand.Reader); err == nil {
		t.Error("no secret salted")
	}
	if _, err := inferCacheSaltDirect(secret, nil, bytes.NewReader(nil)); err == nil {
		t.Error("a fresh salt with no randomness")
	}
}
