package sidecar

import (
	"encoding/json"
	"reflect"
	"testing"
)

// GET /sidecar/limits and every refusal cross the wire as these names (§20.7).
func TestQuotaRefusalJsonNames(t *testing.T) {
	refusal := QuotaRefusal{LimitKey: "storage", Limit: 10, Used: 11, RetryAfterMs: 500, Upgrade: true}
	encoded, err := json.Marshal(refusal)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"limit_key":"storage","limit":10,"used":11,"retry_after_ms":500,"upgrade":true}`
	if string(encoded) != want {
		t.Errorf("%s, want %s", encoded, want)
	}
}

func TestQuotaLimitsRoundTrip(t *testing.T) {
	src := `{"tier":"team","limits":{"directory_requests_pending":20,"mail_burners_active":-1,"storage":214748364800}}`
	var limits QuotaLimits
	if err := json.Unmarshal([]byte(src), &limits); err != nil {
		t.Fatal(err)
	}
	want := QuotaLimits{
		Tier: "team",
		Limits: map[string]int64{
			"directory_requests_pending": 20,
			"mail_burners_active":        -1,
			"storage":                    200 * 1024 * 1024 * 1024,
		},
	}
	if !reflect.DeepEqual(limits, want) {
		t.Errorf("%+v, want %+v", limits, want)
	}
	encoded, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != src {
		t.Errorf("%s, want %s", encoded, src)
	}
}
