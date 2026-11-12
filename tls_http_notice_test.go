//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A fixture on tier, a Community network when tier is "free" and an unknown one when it is "".
func newTlsNoticeFixture(t *testing.T, tier string, configure func(fixture *tlsFrontFixture)) *tlsFrontFixture {
	t.Helper()
	return newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.limits = func(ctx context.Context) (*QuotaLimits, error) {
			if tier == "" {
				return nil, errors.New("synthetic: limits unreadable")
			}
			return &QuotaLimits{Tier: tier}, nil
		}
		if configure != nil {
			configure(fixture)
		}
	})
}

// Whether an answer is the notice's page.
func tlsNoticeTestShown(response *http.Response, body string) bool {
	return response.StatusCode == http.StatusOK && strings.Contains(body, `action="/.well-known/ur/notice"`)
}

// §13.7's interstitial: a Community public endpoint's first navigation meets the notice and reaches nothing; its
// same-origin post keeps the acceptance and returns the visitor where it was going, and from then on the site.
func TestTlsHttpNoticeOnceOnCommunityPublic(t *testing.T) {
	fixture := newTlsNoticeFixture(t, "free", nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	response, body := tlsFrontTestDo(t, client, tlsFrontTestNavigation(t, http.MethodGet, "/page?x=1"))
	if !tlsNoticeTestShown(response, body) || !strings.Contains(body, `value="/page?x=1"`) {
		t.Fatalf("no notice: %d %q", response.StatusCode, body)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials behind the notice", dials)
	}
	accept, err := http.NewRequest(http.MethodPost, "https://"+tlsFrontTestServerName+tlsNoticePath,
		strings.NewReader(url.Values{tlsNoticeReturnField: {"/page?x=1"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	accept.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accept.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
	accept.Header.Set(tlsHttpHeaderFetchMode, tlsFetchModeNavigate)
	accept.Header.Set(tlsHttpHeaderFetchDest, tlsFetchDestDocument)
	response, _ = tlsFrontTestDo(t, client, accept)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/page?x=1" {
		t.Fatalf("accept: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != tlsNoticeCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" {
		t.Fatalf("cookies %v", cookies)
	}
	again := tlsFrontTestNavigation(t, http.MethodGet, "/page?x=1")
	again.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: cookies[0].Value})
	response, body = tlsFrontTestDo(t, client, again)
	if response.StatusCode != http.StatusOK || body != "backend" {
		t.Errorf("after the notice: %d %q", response.StatusCode, body)
	}
}

// The notice never shows on Pro, on the system publish, under another audience, or on a request that is no
// navigation; and shows when the tier cannot be read.
func TestTlsHttpNoticeNeverElsewhere(t *testing.T) {
	cases := []struct {
		name      string
		tier      string
		configure func(fixture *tlsFrontFixture)
		request   func(t *testing.T) *http.Request
		shown     bool
	}{
		{name: "pro", tier: "pro", shown: false},
		{name: "unknown", tier: "", shown: true},
		{name: "system publish", tier: "free", shown: false, configure: func(fixture *tlsFrontFixture) {
			fixture.target.SystemPublish = true
		}},
		{name: "an API call", tier: "free", shown: false, request: func(t *testing.T) *http.Request {
			request, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+"/hook", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", "application/json")
			return request
		}},
		{name: "a webhook post", tier: "free", shown: false, request: func(t *testing.T) *http.Request {
			request, err := http.NewRequest(http.MethodPost, "https://"+tlsFrontTestServerName+"/hook", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			return request
		}},
	}
	for _, c := range cases {
		fixture := newTlsNoticeFixture(t, c.tier, c.configure)
		request := tlsFrontTestNavigation(t, http.MethodGet, "/")
		if c.request != nil {
			request = c.request(t)
		}
		response, body := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request)
		if shown := tlsNoticeTestShown(response, body); shown != c.shown {
			t.Errorf("%s: shown %t (%d)", c.name, shown, response.StatusCode)
		}
	}

	// a members visitor reaches the site signed in, with no notice
	memberId := NewId()
	fixture := newTlsNoticeFixture(t, "free", func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	request := tlsFrontTestNavigation(t, http.MethodGet, "/")
	request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: fixture.sealSession(t, memberId)})
	response, body := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request)
	if tlsNoticeTestShown(response, body) || response.StatusCode != http.StatusOK {
		t.Errorf("members: %d", response.StatusCode)
	}
}

// Only a same-origin post accepts the notice, so another page cannot accept it for a visitor; a return path that is
// no plain path returns to /.
func TestTlsHttpNoticeAcceptOnlySameOrigin(t *testing.T) {
	fixture := newTlsNoticeFixture(t, "free", nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	post := func(site string, origin string, to string) *http.Response {
		request, err := http.NewRequest(http.MethodPost, "https://"+tlsFrontTestServerName+tlsNoticePath,
			strings.NewReader(url.Values{tlsNoticeReturnField: {to}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if site != "" {
			request.Header.Set(tlsHttpHeaderFetchSite, site)
		}
		if origin != "" {
			request.Header.Set(tlsHttpHeaderOrigin, origin)
		}
		response, _ := tlsFrontTestDo(t, client, request)
		return response
	}
	for _, response := range []*http.Response{
		post("cross-site", "", "/"),
		post("same-site", "", "/"),
		post("", "https://"+tlsFrontTestOtherName, "/"),
	} {
		if response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 {
			t.Errorf("a post from elsewhere: %d, %v", response.StatusCode, response.Cookies())
		}
	}
	for _, to := range []string{"//evil.example/", "https://evil.example/", "/\\evil.example", "/.well-known/ur/callback"} {
		if response := post(tlsFetchSiteSameOrigin, "", to); response.Header.Get("Location") != "/" {
			t.Errorf("%q returned to %q", to, response.Header.Get("Location"))
		}
	}
	if response := post("", "https://"+tlsFrontTestServerName, "/ok"); response.StatusCode != http.StatusSeeOther {
		t.Errorf("its own Origin without metadata: %d", response.StatusCode)
	}
}
