//go:build !ios_extension

package sidecar

// POST /mail/enable and GET /mail/status on SidecarApi (MAIL-M7-22): each sends its request with the client JWT and
// no body, reads its answer, refuses one that is not its shape, and gives a refusal as a SidecarApiError.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestSidecarApiMailEnableSendsNoBodyAndReadsItsTime(t *testing.T) {
	transport := answerWith(http.StatusOK, `{"enabled_time":1793923200000}`)
	api := newTestSidecarApi(t, transport)
	enabled, err := api.MailEnable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.EnabledTime.Equal(time.UnixMilli(1793923200000)) {
		t.Errorf("enabled at %s", enabled.EnabledTime)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != validSidecarSettings().ApiUrl+"/mail/enable" || len(body) != 0 {
		t.Errorf("request %s %s with %d bytes", request.Method, request.URL, len(body))
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Errorf("authorization %q", request.Header.Get("Authorization"))
	}
}

func TestSidecarApiMailStatusReadsItsBody(t *testing.T) {
	transport := answerWith(http.StatusOK, `{"enabled":true,"storage_full":false,"spent":true,"direct_mx":false}`)
	api := newTestSidecarApi(t, transport)
	status, err := api.MailStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *status != (MailNetworkStatus{Enabled: true, Spent: true}) {
		t.Errorf("status %+v", status)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "GET" || request.URL.String() != validSidecarSettings().ApiUrl+"/mail/status" || len(body) != 0 {
		t.Errorf("request %s %s with %d bytes", request.Method, request.URL, len(body))
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Errorf("authorization %q", request.Header.Get("Authorization"))
	}
}

// An answer that is not the route's is refused whole, never taken in part.
func TestSidecarApiMailRoutesRefuseAnAnswerThatIsNotTheirShape(t *testing.T) {
	for _, body := range []string{`{}`, `{"enabled_time":0}`, `{"enabled_time":-5}`, `{"enabled_time":"now"}`, `[]`} {
		api := newTestSidecarApi(t, answerWith(http.StatusOK, body))
		if _, err := api.MailEnable(context.Background()); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("enable %s: %v, want a malformed reply", body, err)
		}
	}
	for _, body := range []string{
		`{}`,
		`{"enabled":true,"storage_full":false,"spent":false}`,
		`{"enabled":true,"storage_full":false,"direct_mx":false}`,
		`{"enabled":"yes","storage_full":false,"spent":false,"direct_mx":false}`,
		`[]`,
	} {
		api := newTestSidecarApi(t, answerWith(http.StatusOK, body))
		if _, err := api.MailStatus(context.Background()); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("status %s: %v, want a malformed reply", body, err)
		}
	}
}

// A refusal of either route is a SidecarApiError, as every route's is: a dark route's 503 and a suspended zone's 403.
func TestSidecarApiMailRoutesRefusal(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(http.StatusForbidden, `{"error":"Not authorized.","code":"zone_suspended"}`))
	_, err := api.MailEnable(context.Background())
	if apiErr := asSidecarApiError(t, err); apiErr.Route != sidecarMailEnableRoute || apiErr.Status != http.StatusForbidden {
		t.Errorf("%+v", apiErr)
	}
	api = newTestSidecarApi(t, answerWith(http.StatusServiceUnavailable, `{"error":"Unavailable.","code":"gate_closed"}`))
	_, err = api.MailStatus(context.Background())
	if apiErr := asSidecarApiError(t, err); apiErr.Route != sidecarMailStatusRoute || apiErr.Status != http.StatusServiceUnavailable {
		t.Errorf("%+v", apiErr)
	}
}
