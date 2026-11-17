package sidecar

// GET /sidecar/limits and the QuotaRefusal a refusal carries (§20.7), on every leg, the sidecar_http leg's
// page Worker included: go test -tags sidecar_http runs these too, since they open nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestSidecarApiLimitsReadsItsBody(t *testing.T) {
	transport := answerWith(http.StatusOK, `{"tier":"pro","limits":{"storage":21474836480,"sidecar_clients":200,"directory_requests_per_day":50,"tls_endpoints":-1,"acl_groups":1}}`)
	api := newTestSidecarApi(t, transport)
	limits, err := api.Limits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := &QuotaLimits{
		Tier: "pro",
		Limits: map[string]int64{
			"storage":                    20 * 1024 * 1024 * 1024,
			"sidecar_clients":            200,
			"directory_requests_per_day": 50,
			"tls_endpoints":              -1,
			"acl_groups":                 1,
		},
	}
	if !reflect.DeepEqual(limits, want) {
		t.Errorf("limits %+v, want %+v", limits, want)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "GET" || request.URL.String() != validSidecarSettings().ApiUrl+"/sidecar/limits" || len(body) != 0 {
		t.Errorf("request %s %s with %d bytes", request.Method, request.URL, len(body))
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Errorf("authorization %q", request.Header.Get("Authorization"))
	}
}

// The body's enforced, enforce_sidecar_limits's state, is read beside the plan's limits, which the body reports
// whatever it says; a body that leaves it out, an older api's, reads off (owner decision 520).
func TestSidecarApiLimitsReadsEnforced(t *testing.T) {
	for _, c := range []struct {
		body     string
		enforced bool
	}{
		{body: `{"tier":"free","limits":{"directory_requests_pending":20},"enforced":true}`, enforced: true},
		{body: `{"tier":"free","limits":{"directory_requests_pending":20},"enforced":false}`, enforced: false},
		{body: `{"tier":"free","limits":{"directory_requests_pending":20}}`, enforced: false},
	} {
		limits, err := newTestSidecarApi(t, answerWith(http.StatusOK, c.body)).Limits(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		if limits.Enforced != c.enforced || limits.Tier != "free" || limits.Limits["directory_requests_pending"] != 20 {
			t.Errorf("%s: %+v", c.body, limits)
		}
	}
}

// What a local pre-check holds a count to: the answer's limit while it is enforced, a key it lacks reading 0, not
// included; none for every key while it is not, whatever the plan says; and 0 for no answer at all, which refuses.
func TestQuotaLocalLimitFollowsEnforced(t *testing.T) {
	enforced := &QuotaLimits{Tier: "free", Limits: map[string]int64{"directory_requests_pending": 20, "mail_burners_active": -1}, Enforced: true}
	dark := &QuotaLimits{Tier: "free", Limits: map[string]int64{"directory_requests_pending": 20, "mail_burners_active": -1}}
	for _, c := range []struct {
		limits   *QuotaLimits
		limitKey string
		want     int64
	}{
		{limits: enforced, limitKey: "directory_requests_pending", want: 20},
		{limits: enforced, limitKey: "mail_burners_active", want: -1},
		{limits: enforced, limitKey: "a_limit_from_later", want: 0},
		{limits: dark, limitKey: "directory_requests_pending", want: -1},
		{limits: dark, limitKey: "mail_burners_active", want: -1},
		{limits: dark, limitKey: "a_limit_from_later", want: -1},
		{limits: nil, limitKey: "directory_requests_pending", want: 0},
	} {
		if limit := quotaLocalLimit(c.limits, c.limitKey); limit != c.want {
			t.Errorf("%+v %s: %d, want %d", c.limits, c.limitKey, limit, c.want)
		}
	}
}

// An answer that is not the route's is refused whole, never taken in part.
func TestSidecarApiLimitsRefusesAnAnswerThatIsNotItsShape(t *testing.T) {
	for _, body := range []string{
		`{"tier":"enterprise","limits":{"storage":1}}`,
		`{"tier":"","limits":{"storage":1}}`,
		`{"tier":"free"}`,
		`{"tier":"free","limits":{"Storage":1}}`,
		`{"tier":"free","limits":{"storage":-2}}`,
		`{"tier":"free","limits":{"storage":"1gib"}}`,
		`{"tier":"free","limits":{"storage":1},"enforced":"yes"}`,
		`{"tier":"free","limits":{"storage":1},"enforced":1}`,
		`[]`,
	} {
		api := newTestSidecarApi(t, answerWith(http.StatusOK, body))
		if _, err := api.Limits(context.Background()); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v, want a malformed reply", body, err)
		}
	}
}

// A refusal of the route itself is a SidecarApiError, as every route's is.
func TestSidecarApiLimitsRefusal(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(http.StatusForbidden, `{"error":"Not authorized.","code":"strict_exp_refused"}`))
	_, err := api.Limits(context.Background())
	apiErr := asSidecarApiError(t, err)
	if apiErr.Route != sidecarLimitsRoute || apiErr.Status != http.StatusForbidden || apiErr.QuotaRefusal != nil {
		t.Errorf("%+v", apiErr)
	}
}

// A sidecar limit's refusal reaches the caller as its QuotaRefusal, in each of api's shapes: 429 with a window
// and Retry-After, 429 with none (RESOURCE_EXHAUSTED), 402 with the body alone, and 402 with x402's terms beside
// the refusal's fields. A body that is no refusal, or one with a field of the wrong type, carries none.
func TestSidecarApiErrorCarriesItsQuotaRefusal(t *testing.T) {
	for _, c := range []struct {
		status     int
		body       string
		retryAfter string
		want       *QuotaRefusal
	}{
		{
			status:     http.StatusTooManyRequests,
			body:       `{"limit_key":"evs_drops_per_day","limit":20,"used":20,"retry_after_ms":3600000,"upgrade":true}`,
			retryAfter: "3600",
			want:       &QuotaRefusal{LimitKey: "evs_drops_per_day", Limit: 20, Used: 20, RetryAfterMs: 3600000, Upgrade: true},
		},
		{
			status: http.StatusTooManyRequests,
			body:   `{"limit_key":"directory_target_pending","limit":100,"used":100,"retry_after_ms":0,"upgrade":false}`,
			want:   &QuotaRefusal{LimitKey: "directory_target_pending", Limit: 100, Used: 100},
		},
		{
			status: http.StatusPaymentRequired,
			body:   `{"limit_key":"sidecar_clients","limit":20,"used":20,"retry_after_ms":0,"upgrade":true}`,
			want:   &QuotaRefusal{LimitKey: "sidecar_clients", Limit: 20, Used: 20, Upgrade: true},
		},
		{
			status: http.StatusPaymentRequired,
			body:   `{"x402Version":1,"error":"quota limit dns_entries reached","accepts":[{"scheme":"exact","network":"base"}],"limit_key":"dns_entries","limit":5,"used":5,"retry_after_ms":0,"upgrade":true}`,
			want:   &QuotaRefusal{LimitKey: "dns_entries", Limit: 5, Used: 5, Upgrade: true},
		},
		{
			status: http.StatusTooManyRequests,
			body:   `{"error":"Too many requests.","code":"rate_limited"}`,
		},
		{
			status: http.StatusTooManyRequests,
			body:   `{"limit_key":"dns entries","limit":5,"used":5,"retry_after_ms":0,"upgrade":true}`,
		},
		{
			status: http.StatusTooManyRequests,
			body:   `{"limit_key":"dns_entries","limit":"5","used":5,"retry_after_ms":0,"upgrade":true}`,
		},
		{
			status: http.StatusTooManyRequests,
			body:   `{"limit_key":"dns_entries","used":5}`,
		},
	} {
		transport := &scriptedApiTransport{
			answer: func(request *http.Request, requestBody []byte) (*http.Response, error) {
				header := http.Header{}
				if c.retryAfter != "" {
					header.Set("Retry-After", c.retryAfter)
				}
				return syntheticResponse(request, c.status, c.body, header), nil
			},
		}
		api := newTestSidecarApi(t, transport)
		_, err := api.Limits(context.Background())
		apiErr := asSidecarApiError(t, err)
		if apiErr.Status != c.status || !reflect.DeepEqual(apiErr.QuotaRefusal, c.want) {
			t.Errorf("%s: status %d, refusal %+v, want %+v", c.body, apiErr.Status, apiErr.QuotaRefusal, c.want)
		}
		if c.want != nil && apiErr.RetryAfterMs != c.want.RetryAfterMs {
			t.Errorf("%s: retry after %d ms, want %d", c.body, apiErr.RetryAfterMs, c.want.RetryAfterMs)
		}
	}
}

// QuotaLimits crosses JSON unchanged, as the page Worker decodes it.
func TestQuotaLimitsJsonRoundTrip(t *testing.T) {
	limits := &QuotaLimits{
		Tier:   "team",
		Limits: map[string]int64{"storage": 200 * 1024 * 1024 * 1024, "tls_endpoints": 200, "mail_burners_active": -1},
	}
	encoded, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &QuotaLimits{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, limits) {
		t.Errorf("%+v, want %+v", decoded, limits)
	}
}
