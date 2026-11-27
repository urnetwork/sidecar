//go:build !ios_extension && !sidecar_http

package sidecar

// x402 v2 as the device speaks it (SRCH-M13-02): the challenge read from its header or its body, each offer field held
// to the policy and the catalog, the retail price's rounding, the payment payload and the receipt.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A challenge's JSON for offer, mutated by mutate.
func testWebSearchChallenge(t *testing.T, line *WebSearchPolicyLine, mutate func(offer map[string]any, whole map[string]any)) []byte {
	t.Helper()
	offer := map[string]any{
		"scheme": "exact", "network": line.Network, "amount": "10000", "asset": line.Asset.ChecksumHex(),
		"payTo": "0x" + strings.Repeat("ab", 20), "maxTimeoutSeconds": 300,
		"extra": map[string]any{"name": line.AssetName, "version": line.AssetVersion},
	}
	whole := map[string]any{"x402Version": 2, "error": "Payment required", "accepts": []any{offer},
		"resource": map[string]any{"url": "https://" + line.Host + "/api/search", "mimeType": "application/json"}}
	if mutate != nil {
		mutate(offer, whole)
	}
	encoded, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A challenge reads from PAYMENT-REQUIRED's base64, else from the body; one past its cap, of another version or not
// JSON does not.
func TestWebSearchChallengeReads(t *testing.T) {
	settings := DefaultWebSearchSettings()
	line := testWebSearchLine(t)
	raw := testWebSearchChallenge(t, line, nil)
	fromHeader, err := webSearchReadChallenge(base64.StdEncoding.EncodeToString(raw), []byte("not json"), settings)
	if err != nil || len(fromHeader.Accepts) != 1 {
		t.Fatalf("from the header: %v", err)
	}
	fromBody, err := webSearchReadChallenge("", raw, settings)
	if err != nil || len(fromBody.Accepts) != 1 || string(fromBody.Accepts[0]) != string(fromHeader.Accepts[0]) {
		t.Fatalf("from the body: %v", err)
	}
	planted := map[string]func() error{
		"not base64": func() error { _, err := webSearchReadChallenge("%%%", nil, settings); return err },
		"not json":   func() error { _, err := webSearchReadChallenge("", []byte("<html>"), settings); return err },
		"version 1": func() error {
			_, err := webSearchReadChallenge("", testWebSearchChallenge(t, line, func(_ map[string]any, whole map[string]any) { whole["x402Version"] = 1 }), settings)
			return err
		},
		"past its cap": func() error {
			_, err := webSearchReadChallenge("", []byte(`{"x402Version":2,"error":"`+strings.Repeat("x", settings.ChallengeMaxByteCount)+`"}`), settings)
			return err
		},
	}
	for name, read := range planted {
		if err := read(); !errors.Is(err, ErrWebSearchChallenge) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each offer field off the policy or the catalog is no offer, bad_offer; the good one is taken, its bytes kept as the
// gateway wrote them; an offer among others is found.
func TestWebSearchOfferFields(t *testing.T) {
	settings := DefaultWebSearchSettings()
	line := testWebSearchLine(t)
	price := &WebSearchPrice{CatalogVersion: 1, NanoUsdPerSearch: 12_000_000}
	take := func(raw []byte) (*webSearchOffer, error) {
		challenge, err := webSearchReadChallenge("", raw, settings)
		if err != nil {
			t.Fatal(err)
		}
		return webSearchTakeOffer(challenge, line, price, settings)
	}
	good, err := take(testWebSearchChallenge(t, line, nil))
	if err != nil || good.amount != 10000 || good.payTo[0] != 0xab {
		t.Fatalf("the good offer: %+v, %v", good, err)
	}
	if !strings.Contains(string(good.raw), `"maxTimeoutSeconds":300`) {
		t.Fatalf("the offer's bytes: %s", good.raw)
	}
	planted := map[string]func(offer map[string]any, whole map[string]any){
		"scheme":  func(offer map[string]any, _ map[string]any) { offer["scheme"] = "upto" },
		"network": func(offer map[string]any, _ map[string]any) { offer["network"] = "eip155:1" },
		"asset":   func(offer map[string]any, _ map[string]any) { offer["asset"] = "0x" + strings.Repeat("cd", 20) },
		"name": func(offer map[string]any, _ map[string]any) {
			offer["extra"] = map[string]any{"name": "Other", "version": "2"}
		},
		"version": func(offer map[string]any, _ map[string]any) {
			offer["extra"] = map[string]any{"name": "USD Coin", "version": "1"}
		},
		"no extra":     func(offer map[string]any, _ map[string]any) { delete(offer, "extra") },
		"timeout":      func(offer map[string]any, _ map[string]any) { offer["maxTimeoutSeconds"] = 119 },
		"payee":        func(offer map[string]any, _ map[string]any) { offer["payTo"] = "0x1234" },
		"zero":         func(offer map[string]any, _ map[string]any) { offer["amount"] = "0" },
		"not decimal":  func(offer map[string]any, _ map[string]any) { offer["amount"] = "1e4" },
		"leading zero": func(offer map[string]any, _ map[string]any) { offer["amount"] = "010000" },
		"past ceiling": func(offer map[string]any, _ map[string]any) { offer["amount"] = "15001" },
		"past catalog": func(offer map[string]any, _ map[string]any) { offer["amount"] = "10001" },
		"another host": func(_ map[string]any, whole map[string]any) {
			whole["resource"] = map[string]any{"url": "https://other.example/api/search"}
		},
		"another path": func(_ map[string]any, whole map[string]any) {
			whole["resource"] = map[string]any{"url": "https://" + line.Host + "/api/task"}
		},
		"another scheme": func(_ map[string]any, whole map[string]any) {
			whole["resource"] = map[string]any{"url": "http://" + line.Host + "/api/search"}
		},
		"no offers":        func(_ map[string]any, whole map[string]any) { whole["accepts"] = []any{} },
		"offer not object": func(_ map[string]any, whole map[string]any) { whole["accepts"] = []any{"exact"} },
	}
	for name, mutate := range planted {
		if _, err := take(testWebSearchChallenge(t, line, mutate)); WebSearchErrorCode(err) != WebSearchCodeBadOffer {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a good offer after one that is not
	mixed := testWebSearchChallenge(t, line, func(offer map[string]any, whole map[string]any) {
		bad := map[string]any{}
		for key, value := range offer {
			bad[key] = value
		}
		bad["network"] = "eip155:1"
		whole["accepts"] = []any{bad, offer}
	})
	if offer, err := take(mixed); err != nil || offer.amount != 10000 {
		t.Fatalf("the good offer among others: %v", err)
	}
}

// What a search of an amount costs: its value times 6/5, rounded up to $0.0001; $0.012 at the gateway's $0.01.
func TestWebSearchRetailPrice(t *testing.T) {
	settings := DefaultWebSearchSettings()
	for _, c := range []struct {
		amount uint64
		retail int64
	}{
		{amount: 10000, retail: 12_000_000},
		{amount: 10001, retail: 12_100_000},
		{amount: 15000, retail: 18_000_000},
		{amount: 1, retail: 100_000},
		{amount: 0, retail: 0},
	} {
		if retail, ok := webSearchRetailNanoUsd(c.amount, settings); !ok || retail != c.retail {
			t.Errorf("%d: %d, %v; want %d", c.amount, retail, ok, c.retail)
		}
	}
	if _, ok := webSearchRetailNanoUsd(^uint64(0), settings); ok {
		t.Error("a price past 64 bits read")
	}
}

// The payment payload: x402Version 2, accepted the offer's bytes as the gateway wrote them, the signature and the
// authorization in x402's forms, base64.
func TestWebSearchPaymentPayload(t *testing.T) {
	line := testWebSearchLine(t)
	settings := DefaultWebSearchSettings()
	challenge, err := webSearchReadChallenge("", testWebSearchChallenge(t, line, nil), settings)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := webSearchTakeOffer(challenge, line, &WebSearchPrice{NanoUsdPerSearch: 12_000_000}, settings)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &protocol.ComputeSearchAuthorization{
		From: line.Payer[:], To: offer.payTo[:], Value: 10000, ValidAfterS: 1767225540, ValidBeforeS: 1767225720,
		Nonce: make([]byte, 32), Signature: append(make([]byte, 64), 27),
	}
	value, err := webSearchPaymentHeaderValue(offer, authorization)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 || string(payload["x402Version"]) != "2" || string(payload["accepted"]) != string(offer.raw) {
		t.Fatalf("the payload %s", decoded)
	}
	var exact X402ExactPayload
	if err := json.Unmarshal(payload["payload"], &exact); err != nil {
		t.Fatal(err)
	}
	if exact.Signature != "0x"+hex.EncodeToString(authorization.Signature) || exact.Authorization.Value != "10000" ||
		exact.Authorization.ValidAfter != "1767225540" || exact.Authorization.ValidBefore != "1767225720" ||
		exact.Authorization.Nonce != "0x"+strings.Repeat("00", 32) || exact.Authorization.From != line.Payer.ChecksumHex() {
		t.Fatalf("the exact payload %+v", exact.Authorization)
	}
}

// PAYMENT-RESPONSE's transaction, where the gateway names one in x402's form; nothing otherwise.
func TestWebSearchPaymentResponse(t *testing.T) {
	settings := DefaultWebSearchSettings()
	encode := func(value string) string {
		return base64.StdEncoding.EncodeToString([]byte(value))
	}
	transaction := strings.Repeat("ef", 32)
	if got, ok := webSearchReadPaymentResponse(encode(`{"success":true,"transaction":"0x`+transaction+`","network":"eip155:84532"}`), settings); !ok || hex.EncodeToString(got) != transaction {
		t.Fatalf("the receipt: %x, %v", got, ok)
	}
	for _, planted := range []string{"", "%%%", encode(`{"success":false,"transaction":"0x` + transaction + `"}`),
		encode(`{"success":true,"transaction":"0x1234"}`), encode(`{"success":true}`), encode(`[]`)} {
		if _, ok := webSearchReadPaymentResponse(planted, settings); ok {
			t.Errorf("%q read", planted)
		}
	}
}

// The answer's whitelist: results with an http or https url, each warning's text; search_id, usage and session_id
// kept nowhere; an answer with no results list does not read.
func TestWebSearchAnswerWhitelist(t *testing.T) {
	answer, err := webSearchReadAnswer([]byte(`{"search_id":"search_secret_id","results":[
		{"url":"https://one.example/a","title":"One","publish_date":"2026-01-02","excerpts":["first"],"extra":"dropped"},
		{"url":"javascript:alert(1)","title":"Bad","excerpts":[]},
		{"url":"http://two.example/b","title":"Two","excerpts":["second","third"]}],
		"warnings":["a warning",{"type":"input","message":"an object warning"},3],
		"usage":[{"name":"sku_search","count":1}],"session_id":"session_secret_id"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Results) != 2 || answer.Results[0].PublishDate != "2026-01-02" || answer.Results[1].PublishDate != "" ||
		len(answer.Results[1].Excerpts) != 2 {
		t.Fatalf("results %+v", answer.Results)
	}
	if len(answer.Warnings) != 2 || answer.Warnings[1] != "an object warning" {
		t.Fatalf("warnings %v", answer.Warnings)
	}
	encoded, _ := json.Marshal(answer)
	if strings.Contains(string(encoded), "secret_id") || strings.Contains(string(encoded), "sku_search") {
		t.Fatal("the answer kept search_id, session_id or usage")
	}
	for _, planted := range []string{`{}`, `{"results":null}`, `[]`, `not json`} {
		if _, err := webSearchReadAnswer([]byte(planted)); err == nil {
			t.Errorf("%s read", planted)
		}
	}
}
