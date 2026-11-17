// Holds the quota types every leg decodes to operator-core's on every leg (QD-856): its own on every leg
// but sidecar_http, aliased, and api_quota_http.go's structs on that one, which the page Worker's run
// reads (TestHttpLegPassesInAWorker names the test). The JSON and the fields below were read off
// operator-core's.

package sidecar

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// A struct's fields as declared: name, type and tag, in order.
func quotaTwinFields(structType reflect.Type) []string {
	fields := []string{}
	for index := 0; index < structType.NumField(); index += 1 {
		field := structType.Field(index)
		fields = append(fields, field.Name+" "+field.Type.String()+" "+string(field.Tag))
	}
	return fields
}

func TestQuotaTwinEncodesAsOperatorCoresDoes(t *testing.T) {
	refusalFields := []string{
		`LimitKey string json:"limit_key"`,
		`Limit int64 json:"limit"`,
		`Used int64 json:"used"`,
		`RetryAfterMs uint32 json:"retry_after_ms"`,
		`Upgrade bool json:"upgrade"`,
		`CaseId string json:"case_id,omitempty"`,
	}
	if fields := quotaTwinFields(reflect.TypeFor[QuotaRefusal]()); !slices.Equal(fields, refusalFields) {
		t.Errorf("QuotaRefusal's fields are %q, want %q", fields, refusalFields)
	}
	limitsFields := []string{
		`Tier string json:"tier"`,
		`Limits map[string]int64 json:"limits"`,
		`Enforced bool json:"enforced"`,
	}
	if fields := quotaTwinFields(reflect.TypeFor[QuotaLimits]()); !slices.Equal(fields, limitsFields) {
		t.Errorf("QuotaLimits's fields are %q, want %q", fields, limitsFields)
	}

	refusal := QuotaRefusal{LimitKey: "evs_stored_bytes", Limit: 1 << 40, Used: 1<<40 + 1, RetryAfterMs: 60000, Upgrade: true}
	refusalJson := `{"limit_key":"evs_stored_bytes","limit":1099511627776,"used":1099511627777,"retry_after_ms":60000,"upgrade":true}`
	encoded, err := json.Marshal(refusal)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != refusalJson {
		t.Errorf("refusal %s, want %s", encoded, refusalJson)
	}
	var decodedRefusal QuotaRefusal
	if err := json.Unmarshal([]byte(refusalJson), &decodedRefusal); err != nil {
		t.Fatal(err)
	}
	if decodedRefusal != refusal {
		t.Errorf("refusal decoded to %+v", decodedRefusal)
	}

	// a screen review's refusal carries its case (QD-1014), and every other leaves the field out, as above
	review := QuotaRefusal{LimitKey: "screen_review", CaseId: "0195a6b8-1c2d-7e3f-8a9b-0c1d2e3f4a5b"}
	reviewJson := `{"limit_key":"screen_review","limit":0,"used":0,"retry_after_ms":0,"upgrade":false,"case_id":"0195a6b8-1c2d-7e3f-8a9b-0c1d2e3f4a5b"}`
	encoded, err = json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != reviewJson {
		t.Errorf("review refusal %s, want %s", encoded, reviewJson)
	}
	var decodedReview QuotaRefusal
	if err := json.Unmarshal([]byte(reviewJson), &decodedReview); err != nil || decodedReview != review {
		t.Errorf("review refusal decoded to %+v, %v", decodedReview, err)
	}

	limits := QuotaLimits{Tier: "team", Limits: map[string]int64{"directory_cards": 16, "evs_stored_bytes": -1, "public_names": 0}, Enforced: true}
	limitsJson := `{"tier":"team","limits":{"directory_cards":16,"evs_stored_bytes":-1,"public_names":0},"enforced":true}`
	encoded, err = json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != limitsJson {
		t.Errorf("limits %s, want %s", encoded, limitsJson)
	}
	var decodedLimits QuotaLimits
	if err := json.Unmarshal([]byte(limitsJson), &decodedLimits); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodedLimits, limits) {
		t.Errorf("limits decoded to %+v", decodedLimits)
	}
	// a key this build does not know reads 0, which fails closed (§20.5)
	if decodedLimits.Limits["a_limit_from_later"] != 0 {
		t.Errorf("an absent key reads %d", decodedLimits.Limits["a_limit_from_later"])
	}

	// enforce_sidecar_limits off encodes as false, and an older api's body, which has no enforced, decodes as
	// false, so it refuses nothing locally (owner decision 520)
	dark := QuotaLimits{Tier: "free", Limits: map[string]int64{"directory_requests_pending": 20}}
	encoded, err = json.Marshal(dark)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tier":"free","limits":{"directory_requests_pending":20},"enforced":false}`; string(encoded) != want {
		t.Errorf("dark limits %s, want %s", encoded, want)
	}
	var older QuotaLimits
	if err := json.Unmarshal([]byte(`{"tier":"free","limits":{"directory_requests_pending":20}}`), &older); err != nil {
		t.Fatal(err)
	}
	if older.Enforced || older.Limits["directory_requests_pending"] != 20 {
		t.Errorf("an older body decoded to %+v", older)
	}
}
