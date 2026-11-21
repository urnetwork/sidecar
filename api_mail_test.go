//go:build !ios_extension

package sidecar

// POST /mail/enable and GET /mail/status on SidecarApi (MAIL-M7-22): each sends its request with the client JWT and
// no body, reads its answer, refuses one that is not its shape, and gives a refusal as a SidecarApiError. GET
// /mail/status names the network's custom domains in strict mode (QD-1129), each a domain name a sender may put in
// MAIL FROM, or the answer is refused whole.

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
	transport := answerWith(http.StatusOK, `{"enabled":true,"storage_full":false,"spent":true,"direct_mx":false,"strict_domains":[]}`)
	api := newTestSidecarApi(t, transport)
	status, err := api.MailStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.StorageFull || !status.Spent || status.DirectMx || status.StrictDomains == nil || len(status.StrictDomains) != 0 {
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
		`{"enabled":true,"storage_full":false,"spent":false,"strict_domains":[]}`,
		`{"enabled":true,"storage_full":false,"direct_mx":false,"strict_domains":[]}`,
		`{"enabled":"yes","storage_full":false,"spent":false,"direct_mx":false,"strict_domains":[]}`,
		// an answer of a server before QD-1129, which names no strict domains: whether a custom domain's envelope moved
		// is unknown, so it is no answer to send by
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,"strict_domains":null}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,"strict_domains":"brand.example"}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":true,"strict_domains":[],"direct_mx_addresses":["0.0.0.0"]}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":true,"strict_domains":[],"direct_mx_addresses":["10.2.3.4"]}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,"strict_domains":[],"direct_mx_addresses":["192.0.2.25"]}`,
		`{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,"strict_domains":[],"verified_domains":["Customer.Example"]}`,
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

// The strict domains come as the server names them, each a name a sender may put in MAIL FROM under b.: two or more
// lowercase LDH labels, with room for b. above it. Any other entry refuses the whole answer, since a sender would
// otherwise send at an envelope the edge never derives.
func TestSidecarApiMailStatusNamesTheStrictDomains(t *testing.T) {
	transport := answerWith(http.StatusOK, `{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,`+
		`"strict_domains":["brand.example","mail.shop.example"]}`)
	status, err := newTestSidecarApi(t, transport).MailStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(status.StrictDomains, []string{"brand.example", "mail.shop.example"}) {
		t.Fatalf("strict %v", status.StrictDomains)
	}
	// the longest name that leaves room for b. is taken, one octet more is not
	long := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 59)
	if len("b."+long) != 253 {
		t.Fatalf("a bad fixture: %d", len(long))
	}
	for _, c := range []struct {
		domain string
		taken  bool
	}{
		{domain: long, taken: true},
		{domain: long + "a", taken: false},
		{domain: "example", taken: false},
		{domain: "Brand.example", taken: false},
		{domain: "brand.example.", taken: false},
		{domain: "-brand.example", taken: false},
		{domain: "brand..example", taken: false},
		{domain: "brand.example>", taken: false},
		{domain: "", taken: false},
	} {
		body := `{"enabled":true,"storage_full":false,"spent":false,"direct_mx":false,"strict_domains":["brand.example",` +
			strconv.Quote(c.domain) + `]}`
		status, err := newTestSidecarApi(t, answerWith(http.StatusOK, body)).MailStatus(context.Background())
		switch {
		case c.taken && (err != nil || !slices.Equal(status.StrictDomains, []string{"brand.example", c.domain})):
			t.Errorf("%q: %v %v", c.domain, status, err)
		case !c.taken && !errors.Is(err, ErrSidecarApiReply):
			t.Errorf("%q: %v, want a malformed reply", c.domain, err)
		}
	}
}

// A pending assignment is visible only through the per-receiver field. Older replies carry no addresses.
func TestSidecarApiMailStatusReadsReceiverAssignments(t *testing.T) {
	const body = `{"enabled":true,"storage_full":false,"spent":false,"direct_mx":true,"strict_domains":[],
		"verified_domains":["customer.example"],"may_send_from_custom_domains":true,"direct_mx_addresses":["192.0.2.25","2001:db8::25"]}`
	transport := answerWith(http.StatusOK, body)
	api := newTestSidecarApi(t, transport)
	status, err := api.MailStatus(context.Background())
	if err != nil || !status.MaySendFromCustomDomains || !slices.Equal(status.VerifiedDomains, []string{"customer.example"}) ||
		!slices.Equal(status.DirectMxAddresses, []netip.Addr{netip.MustParseAddr("192.0.2.25"), netip.MustParseAddr("2001:db8::25")}) {
		t.Fatalf("receiver status %+v: %v", status, err)
	}
}
