//go:build !ios_extension && !sidecar_http

// The policy's format (ATTEST-M11-01): the strict parse, each line's rules, the disclosures line and the raw lines
// kept verbatim. The refusals a signed document can carry are signed by the test compute-policy key and refused by the
// verifier, so a correct signature carries no malformed policy through.

package sidecar

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// document, signed by the certified test key, through a production build's verifier at testAttestNow.
func testAttestVerifyDocument(t *testing.T, document []byte) (*ComputePolicy, error) {
	t.Helper()
	keys := newTestAttestKeys(t)
	signature := testAttestSign(t, keys.policy, ComputePolicyNamespace, document)
	return keys.verifier(false).Verify(document, signature, testAttestNow)
}

// A format refusal for document, signed: wrapped in ErrComputePolicyRefused and errComputePolicyFormat.
func testAttestWantFormatRefusal(t *testing.T, name string, document []byte) {
	t.Helper()
	policy, err := testAttestVerifyDocument(t, document)
	if policy != nil || !errors.Is(err, ErrComputePolicyRefused) || !errors.Is(err, errComputePolicyFormat) {
		t.Errorf("%s: got %v, %v; want a format refusal", name, policy, err)
	}
}

// A member this format does not know, at the top and inside a line, is refused whole, signed or not.
func TestComputePolicyRefusesUnknownMembers(t *testing.T) {
	testAttestWantFormatRefusal(t, "at the top", testAttestPolicyEdit(t, `"version": 3,`, `"version": 3, "extra": 1,`))
	testAttestWantFormatRefusal(t, "in a provider", testAttestPolicyEdit(t, `"id": "teetest",`, `"id": "teetest", "tls": true,`))
	testAttestWantFormatRefusal(t, "in a disclosure", testAttestPolicyEdit(t, `"grace_days": 0,`, `"grace_days": 0, "since": 1,`))
	// encoding/json would match these case-insensitively; this format matches names by their bytes
	testAttestWantFormatRefusal(t, "another case", testAttestPolicyEdit(t, `"version": 3,`, `"Version": 3,`))
	testAttestWantFormatRefusal(t, "a folded letter", testAttestPolicyEdit(t, `"cpus": ["tdx"],`, `"cpuſ": ["tdx"],`))
}

// A member written twice is refused, in a declared object and inside a raw line alike.
func TestComputePolicyRefusesDuplicateMembers(t *testing.T) {
	testAttestWantFormatRefusal(t, "at the top", testAttestPolicyEdit(t, `"version": 3,`, `"version": 3, "version": 3,`))
	testAttestWantFormatRefusal(t, "in roots", testAttestPolicyEdit(t, `"nvidia_nras": [`, `"nvidia_device": [], "nvidia_nras": [`))
	testAttestWantFormatRefusal(t, "in the search line", testAttestPolicyEdit(t, `"payee_fresh": false}`, `"payee_fresh": false, "payee_fresh": true}`))
	testAttestWantFormatRefusal(t, "in the services line", testAttestPolicyEdit(t, `{ "service" : "test" ,`, `{ "service" : "test" , "service" : "other" ,`))
}

// Every disclosure carries English, first.
func TestComputePolicyRefusesMissingEnglishLocale(t *testing.T) {
	english := `"locale": "en",
          "summary": "A test provider's line, in a TEE that keeps its miners out.",`
	testAttestWantFormatRefusal(t, "no English", testAttestPolicyEdit(t, english, strings.Replace(english, `"en"`, `"fr"`, 1)))
	testAttestWantFormatRefusal(t, "English second", testAttestPolicyEdit(t, english, `"locale": "de", "summary": "Ein Test.", "exposed": [], "private": []
        },
        {
          `+english))
}

// Anything after the object, a null where a value is declared, and numbers that are not integers in range.
func TestComputePolicyRefusesMalformedValues(t *testing.T) {
	document := testAttestPolicyDocument(t)
	testAttestWantFormatRefusal(t, "a second value", append(bytes.Clone(document), []byte("{}")...))
	testAttestWantFormatRefusal(t, "a stray byte", append(bytes.Clone(document), 'x'))
	testAttestWantFormatRefusal(t, "a null line", testAttestPolicyEdit(t, `"custody": [`, `"custody": null, "x": [`))
	testAttestWantFormatRefusal(t, "a null search line", testAttestPolicyEdit(t, `"search": {"host"`, `"search": null, "x": {"host"`))
	testAttestWantFormatRefusal(t, "a fraction", testAttestPolicyEdit(t, `"version": 3,`, `"version": 3.0,`))
	testAttestWantFormatRefusal(t, "an exponent", testAttestPolicyEdit(t, `"version": 3,`, `"version": 3e0,`))
	testAttestWantFormatRefusal(t, "a negative count", testAttestPolicyEdit(t, `"version": 3,`, `"version": -3,`))
	testAttestWantFormatRefusal(t, "past its type", testAttestPolicyEdit(t, `"gpu_count": 8,`, `"gpu_count": 4294967296,`))
	testAttestWantFormatRefusal(t, "a string for a number", testAttestPolicyEdit(t, `"version": 3,`, `"version": "3",`))
	testAttestWantFormatRefusal(t, "an array, not an object", []byte("[]"))
	testAttestWantFormatRefusal(t, "not utf-8", testAttestPolicyEdit(t, `"summary": "Not in a TEE`, "\"summary\": \"\xff Not in a TEE"))
	testAttestWantFormatRefusal(t, "version 0", testAttestPolicyEdit(t, `"version": 3,`, `"version": 0,`))
}

// The disclosures line as §2.8 and QD-1242 give it: an integer version and revision, a grace of 14 or 0, the instant
// the version took effect, English first and any translation after.
func TestComputePolicyDisclosuresLine(t *testing.T) {
	policy, err := testAttestVerifyDocument(t, testAttestPolicyDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	local := policy.Disclosure("inference:local")
	if local == nil || local.Version != 1 || local.Revision != 0 || local.GraceDays != 14 || local.SinceMs != 1793491200000 {
		t.Fatalf("inference:local %+v", local)
	}
	english := local.English()
	if english == nil || english.Summary != "On this device: the model runs here, and no server takes part in a call." ||
		len(english.Exposed) != 4 || len(english.Private) != 1 {
		t.Errorf("inference:local's English %+v", english)
	}
	if german := local.Text("de"); german == nil || german.Summary == english.Summary || local.Text("fr") != nil {
		t.Errorf("inference:local's translations: de %+v", german)
	}
	direct := policy.Disclosure("inference:directtest")
	if direct == nil || direct.Version != 2 || direct.Revision != 1 || direct.GraceDays != 0 || direct.SinceMs != 1792022400000 {
		t.Errorf("inference:directtest %+v", direct)
	}
	if policy.Disclosure("search:parallel") != nil {
		t.Error("a disclosure the policy does not carry")
	}

	testAttestWantFormatRefusal(t, "a grace past 14", testAttestPolicyEdit(t, `"grace_days": 0,`, `"grace_days": 15,`))
	testAttestWantFormatRefusal(t, "no instant", testAttestPolicyEdit(t, `"since_ms": 1792022400000,`, `"since_ms": 0,`))
	testAttestWantFormatRefusal(t, "version 0", testAttestPolicyEdit(t, `"version": 2,`, `"version": 0,`))
	testAttestWantFormatRefusal(t, "an id twice", testAttestPolicyEdit(t, `"id": "inference:teetest",`, `"id": "inference:local",`))
	testAttestWantFormatRefusal(t, "an id that is not family:slug", testAttestPolicyEdit(t, `"id": "inference:teetest",`, `"id": "Inference:teetest",`))
	testAttestWantFormatRefusal(t, "a locale twice", testAttestPolicyEdit(t, `"locale": "de",`, `"locale": "en",`))
	testAttestWantFormatRefusal(t, "a summary of two lines", testAttestPolicyEdit(t, `"summary": "A test provider's line,`, `"summary": "A test provider's\nline,`))
	testAttestWantFormatRefusal(t, "an empty item", testAttestPolicyEdit(t, `"exposed": ["Ein Testeintrag."],`, `"exposed": [" "],`))
}

// The search and services lines are kept byte for byte as the document holds them, spacing and order included,
// inside the verified bytes, for their owners to decode; a policy without them carries neither.
func TestComputePolicyRawLinesSurviveVerbatim(t *testing.T) {
	policy, err := testAttestVerifyDocument(t, testAttestPolicyDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	search := `{"host":   "search.test.example", "asset": {"network": "test-chain", "contract": "0x0000000000000000000000000000000000000000"},
             "ceiling_nano_usd": 15000000, "payee_fresh": false}`
	services := `[ { "service" : "test" , "hosts" : [ "issuer.test.example" ] } ]`
	if string(policy.Search) != search || string(policy.Services) != services {
		t.Errorf("search %q\nservices %q", policy.Search, policy.Services)
	}
	if !bytes.Contains(policy.Document(), []byte(search)) || !bytes.Contains(policy.Document(), []byte(services)) {
		t.Error("the raw lines are not the verified bytes")
	}

	without := testAttestPolicyEdit(t, `"search": {"host":   "search.test.example", "asset": {"network": "test-chain", "contract": "0x0000000000000000000000000000000000000000"},
             "ceiling_nano_usd": 15000000, "payee_fresh": false},
`, ``)
	without = bytes.Replace(without, []byte(`  "services": [ { "service" : "test" , "hosts" : [ "issuer.test.example" ] } ],
`), []byte{}, 1)
	policy, err = testAttestVerifyDocument(t, without)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Search != nil || policy.Services != nil {
		t.Errorf("lines the policy does not carry: %q, %q", policy.Search, policy.Services)
	}
}

// Each parse limit is a setting: at its bound the vector parses, one under it the parse is refused.
func TestComputePolicyParseLimits(t *testing.T) {
	document := testAttestPolicyDocument(t)
	cases := []struct {
		name  string
		limit func(settings *AttestSettings)
	}{
		{name: "size", limit: func(settings *AttestSettings) { settings.PolicyMaxByteCount = len(document) - 1 }},
		// an event of providers[].profiles[].replayed[].events[] is the deepest value: 9, the document 1
		{name: "depth", limit: func(settings *AttestSettings) { settings.PolicyMaxDepth = 8 }},
		// inference:local's English exposed list holds 4
		{name: "count", limit: func(settings *AttestSettings) { settings.PolicyMaxListCount = 3 }},
		{name: "string", limit: func(settings *AttestSettings) { settings.PolicyMaxStringByteCount = 200 }},
		{name: "id", limit: func(settings *AttestSettings) { settings.PolicyMaxIdByteCount = 16 }},
		{name: "grace", limit: func(settings *AttestSettings) { settings.DisclosureGraceMaxDays = 13 }},
	}
	if _, err := parseComputePolicy(document, DefaultAttestSettings()); err != nil {
		t.Fatalf("the vector under the defaults: %v", err)
	}
	for _, c := range cases {
		settings := DefaultAttestSettings()
		c.limit(settings)
		if policy, err := parseComputePolicy(document, settings); policy != nil || !errors.Is(err, errComputePolicyFormat) {
			t.Errorf("%s: %v, %v", c.name, policy, err)
		}
	}
	settings := DefaultAttestSettings()
	settings.PolicyMaxDepth = 9
	settings.PolicyMaxListCount = 4
	settings.DisclosureGraceMaxDays = 14
	if _, err := parseComputePolicy(document, settings); err != nil {
		t.Errorf("at the depth and count bounds: %v", err)
	}
}

// What §5.3 never allows, and the lines that must name what they refer to.
func TestComputePolicyRefusesWhatTheLinesForbid(t *testing.T) {
	cases := map[string][2]string{
		"a TDX status never allowed":           {`"statuses": ["UpToDate", "SWHardeningNeeded"],`, `"statuses": ["UpToDate", "OutOfDate"],`},
		"advisories without SWHardeningNeeded": {`"statuses": ["UpToDate", "SWHardeningNeeded"],`, `"statuses": ["UpToDate"],`},
		"an unknown family":                    {`{"family": "milan", "build": 31},`, `{"family": "naples", "build": 31},`},
		"a firmware build past a byte":         {`{"family": "milan", "build": 31},`, `{"family": "milan", "build": 256},`},
		"a bit both set and clear":             {`"policy_bits_clear": 524288`, `"policy_bits_clear": 65536`},
		"a hash in capitals":                   {`"intel_sgx": ["f2cba7`, `"intel_sgx": ["F2CBA7`},
		"an unknown scheme":                    {`"schemes": ["chutes-e2e-v1"],`, `"schemes": ["ra-tls"],`},
		"a label not a TEE's":                  {`"label": "AP",`, `"label": "none",`},
		"a profile without review":             {`"review": "reproduced",`, `"review": "",`},
		"listed without its list":              {`"review_list_sha256": "4d2e755c1e721cc46ef5ac07afa42edc9880995fe1aae95679700434f801aa77"`, `"review_list_sha256": ""`},
		"tdx carrying SNP's measurement": {`"xfam": "e702060000000000",
          "measurement": "",`, `"xfam": "e702060000000000",
          "measurement": "332ce86683cd076e9e700743d36a8cc4125c3269dc76282ac2ac290fdabaffb3844cb83f2a17b733e36bb7cdd574afe4",`},
		"a profile id twice":                  {`"id": "ur-enclave-2026.11.1-enclavetest",`, `"id": "teetest-2026.11.1",`},
		"limited_use of an unlisted model":    {`"limited_use": ["teetest-test-model-27b",`, `"limited_use": ["teetest-other-model",`},
		"a direct provider that is a TEE's":   {`"slug": "directtest",`, `"slug": "teetest",`},
		"custody of an unlisted provider":     {`{"provider": "teetest", "registry"`, `{"provider": "nobody", "registry"`},
		"a chip of an unknown kind":           {`{"kind": "intel_ppid",`, `{"kind": "serial",`},
		"a GPU model without a count":         {`"gpu_count": 8,`, `"gpu_count": 0,`},
		"a host with a port":                  {`"api_host": "api.direct-test.example",`, `"api_host": "api.direct-test.example:443",`},
		"a target with a query":               {`"path": "/v1/chat/completions"`, `"path": "/v1/chat/completions?x=1"`},
		"a replayed register that is no RTMR": {`"register": "pcr12",`, `"register": "pcr24",`},
	}
	for name, edit := range cases {
		document := testAttestPolicyDocument(t)
		if !bytes.Contains(document, []byte(edit[0])) {
			t.Fatalf("%s: policy.json does not hold %q", name, edit[0])
		}
		edited := bytes.Replace(document, []byte(edit[0]), []byte(edit[1]), 1)
		if policy, err := parseComputePolicy(edited, DefaultAttestSettings()); policy != nil || !errors.Is(err, errComputePolicyFormat) {
			t.Errorf("%s: %v, %v", name, policy, err)
		}
	}
}

// A refusal's message names what was wrong and never repeats the document's values.
func TestComputePolicyRefusalsNeverRepeatValues(t *testing.T) {
	canary := "canary-value-7f3a"
	edits := [][2]string{
		{`"label": "AP",`, `"label": "` + canary + `",`},
		{`"version": 3,`, `"` + canary + `": 3,`},
		{`"api_host": "api.direct-test.example",`, `"api_host": "` + canary + `.example:1",`},
	}
	for _, edit := range edits {
		_, err := parseComputePolicy(testAttestPolicyEdit(t, edit[0], edit[1]), DefaultAttestSettings())
		if err == nil || strings.Contains(err.Error(), canary) {
			t.Errorf("%q: %v", edit[1], err)
		}
	}
}
