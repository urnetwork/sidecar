//go:build !ios_extension && !sidecar_http

package sidecar

// The policy's search line, decoded strictly, and the catalog's search section read into search endpoints (SRCH-M13-01,
// SRCH-M13-02).

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A synthetic search line: a .example host, a test chain, addresses and a key drawn from labels.
func testWebSearchLine(t *testing.T) *WebSearchPolicyLine {
	t.Helper()
	seed := sha256.Sum256([]byte("test signer key"))
	key, err := hpke.MLKEM768X25519().DeriveKeyPair(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	asset := sha256.Sum256([]byte("test usdc contract"))
	payer := sha256.Sum256([]byte("test payer"))
	line := &WebSearchPolicyLine{
		Host:          "parallelmpp.example",
		Network:       "eip155:84532",
		ChainId:       84532,
		AssetName:     "USD Coin",
		AssetVersion:  "2",
		CeilingAmount: 15000,
		SignerKey:     key.PublicKey(),
	}
	copy(line.Asset[:], asset[:])
	copy(line.Payer[:], payer[:])
	return line
}

// A line written as the signers would reads back to itself, payee_fresh absent as false and present as written.
func TestWebSearchPolicyLineRoundTrips(t *testing.T) {
	settings := DefaultWebSearchSettings()
	for _, fresh := range []bool{false, true} {
		line := testWebSearchLine(t)
		line.PayeeFresh = fresh
		encoded, err := WebSearchPolicyLineJson(line)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseWebSearchPolicyLine(encoded, settings)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Host != line.Host || parsed.Network != line.Network || parsed.ChainId != line.ChainId ||
			parsed.Asset != line.Asset || parsed.AssetName != line.AssetName || parsed.AssetVersion != line.AssetVersion ||
			parsed.CeilingAmount != line.CeilingAmount || parsed.Payer != line.Payer || parsed.PayeeFresh != fresh ||
			hex.EncodeToString(parsed.SignerKey.Bytes()) != hex.EncodeToString(line.SignerKey.Bytes()) {
			t.Fatalf("parsed %+v, want %+v", parsed, line)
		}
		if domain := parsed.Domain(); domain.Name != "USD Coin" || domain.Version != "2" || domain.ChainId != 84532 || domain.VerifyingContract != line.Asset {
			t.Fatalf("the domain %+v", domain)
		}
	}
}

// Every way a line is not of its format is refused whole: an unknown member, one twice, a null, one missing, a value of
// another type, trailing data, an uppercase address, a host or network not of their forms, a key not X-Wing, a ceiling
// of nothing, and a line past its size.
func TestWebSearchPolicyLineStrict(t *testing.T) {
	settings := DefaultWebSearchSettings()
	encoded, err := WebSearchPolicyLineJson(testWebSearchLine(t))
	if err != nil {
		t.Fatal(err)
	}
	good := string(encoded)
	replace := func(old string, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("the line holds no %q", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	planted := map[string]string{
		"unknown member":     replace(`"host":`, `"extra":1,"host":`),
		"unknown nested":     replace(`"name":`, `"decimals":6,"name":`),
		"member twice":       replace(`"host":"parallelmpp.example"`, `"host":"parallelmpp.example","host":"other.example"`),
		"nested twice":       replace(`"name":"USD Coin"`, `"name":"USD Coin","name":"Other"`),
		"null":               replace(`"host":"parallelmpp.example"`, `"host":null`),
		"fresh null":         replace(`"host":`, `"payee_fresh":null,"host":`),
		"missing ceiling":    replace(`"ceiling_amount":15000,`, ``),
		"ceiling as string":  replace(`"ceiling_amount":15000`, `"ceiling_amount":"15000"`),
		"ceiling of nothing": replace(`"ceiling_amount":15000`, `"ceiling_amount":0`),
		"negative ceiling":   replace(`"ceiling_amount":15000`, `"ceiling_amount":-1`),
		"trailing":           good + ` {}`,
		"two values":         good + good,
		"uppercase payer":    strings.Replace(good, `"payer":"0x`, `"payer":"0X`, 1),
		"uppercase host":     replace(`"parallelmpp.example"`, `"Parallelmpp.example"`),
		"host with port":     replace(`"parallelmpp.example"`, `"parallelmpp.example:443"`),
		"another network":    replace(`"eip155:84532"`, `"solana:84532"`),
		"empty asset name":   replace(`"name":"USD Coin"`, `"name":""`),
		"short key":          replace(`"signer_key":"`, `"signer_key":"00`),
		"array":              `[` + good + `]`,
		"empty":              ``,
		"past its size":      replace(`"host":`, `"host_pad":"`+strings.Repeat("a", settings.PolicyLineMaxByteCount)+`","host":`),
	}
	// an address in uppercase hex
	line := testWebSearchLine(t)
	planted["uppercase address"] = strings.Replace(good, line.Payer.Hex(), "0x"+strings.ToUpper(line.Payer.Hex()[2:]), 1)
	for name, raw := range planted {
		if _, err := ParseWebSearchPolicyLine([]byte(raw), settings); !errors.Is(err, ErrWebSearchPolicyLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The catalog's search section reads into search endpoints, search/<engine>/<mode> at their prices, an entry with no
// price or outside the id grammar left out; a body that does not read lists none.
func TestWebSearchCatalogSectionReads(t *testing.T) {
	settings := DefaultInferSettings()
	body, err := proto.Marshal(&protocol.WebSearchCatalogSection{Entries: []*protocol.WebSearchCatalogEntry{
		{Engine: WebSearchEngineParallel, Mode: WebSearchModeFast, NanoUsdPerSearch: 12_000_000},
		{Engine: WebSearchEngineParallel, Mode: WebSearchModeAdvanced, NanoUsdPerSearch: 12_000_000},
		{Engine: WebSearchEngineParallel, Mode: WebSearchModeTurbo, NanoUsdPerSearch: 0},
		{Engine: "Not An Engine", Mode: WebSearchModeFast, NanoUsdPerSearch: 12_000_000},
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := webSearchReadCatalogSection(body, settings)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, entry := range entries {
		if entry.Kind != InferCatalogKindSearch || entry.Label != ComputeLabelNone || entry.Search.NanoUsdPerSearch != 12_000_000 {
			t.Errorf("entry %+v", entry)
		}
		ids = append(ids, entry.SearchId())
	}
	if strings.Join(ids, " ") != "search/parallel/fast search/parallel/advanced" {
		t.Errorf("the endpoints read %v", ids)
	}
	if _, err := webSearchReadCatalogSection([]byte{0xff, 0xff}, settings); err == nil {
		t.Error("a body that does not read listed endpoints")
	}
	if _, registered := inferCatalogSectionReaders[webSearchCatalogSection]; !registered {
		t.Error("the search section's reader is not registered")
	}
}
