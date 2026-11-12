//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Host, :authority and an absolute target each held to the SNI, port and case aside.
func TestTlsHttpHostMatches(t *testing.T) {
	for _, c := range []struct {
		host      string
		urlHost   string
		hostField string
		want      bool
	}{
		{host: tlsFrontTestServerName, want: true},
		{host: tlsFrontTestServerName + ":443", want: true},
		{host: "APP.abcdefghij.UR.example", want: true},
		{host: tlsFrontTestServerName + ".", want: true},
		{host: tlsFrontTestOtherName, want: false},
		{host: "", want: false},
		{host: "[2001:db8::1]", want: false},
		{host: tlsFrontTestServerName, urlHost: tlsFrontTestOtherName, want: false},
		{host: tlsFrontTestServerName, urlHost: tlsFrontTestServerName + ":443", want: true},
		{host: tlsFrontTestServerName, hostField: tlsFrontTestOtherName, want: false},
	} {
		request := &http.Request{Host: c.host, URL: &url.URL{Host: c.urlHost}, Header: http.Header{}}
		if c.hostField != "" {
			request.Header.Set("Host", c.hostField)
		}
		if got := tlsHttpHostMatches(request, tlsFrontTestServerName); got != c.want {
			t.Errorf("%q %q %q: %t", c.host, c.urlHost, c.hostField, got)
		}
	}
}

// §13.7's other-origins row, each Fetch Metadata row and each row without it: which requests count the front's
// session cookies, which are navigations, and which are same-origin.
func TestTlsHttpSessionViewRows(t *testing.T) {
	origin := "https://" + tlsFrontTestServerName
	for _, c := range []struct {
		name           string
		method         string
		header         map[string]string
		wantCounts     bool
		wantNavigation bool
		wantSameOrigin bool
	}{
		{name: "same-origin fetch", method: "POST", header: map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
			wantCounts: true, wantSameOrigin: true},
		{name: "typed into the bar", method: "GET", header: map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
			wantCounts: true, wantNavigation: true},
		{name: "a link from another site", method: "GET", header: map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
			wantCounts: true, wantNavigation: true},
		{name: "a HEAD navigation", method: "HEAD", header: map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
			wantCounts: true, wantNavigation: true},
		{name: "another network's host's fetch", method: "GET", header: map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}},
		{name: "a cross-site POST navigation", method: "POST", header: map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}},
		{name: "a framed navigation", method: "GET", header: map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}},
		{name: "a subresource", method: "GET", header: map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}},
		{name: "a WebSocket", method: "GET", header: map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "websocket", "Sec-Fetch-Dest": "websocket"}},
		{name: "no metadata, no Origin", method: "GET", header: map[string]string{"Accept": "text/html"}, wantCounts: true, wantNavigation: true},
		{name: "no metadata, its own Origin", method: "POST", header: map[string]string{"Origin": origin}, wantCounts: true, wantSameOrigin: true},
		{name: "no metadata, another Origin", method: "POST", header: map[string]string{"Origin": "https://" + tlsFrontTestOtherName}},
		{name: "no metadata, an API call", method: "GET", header: map[string]string{"Accept": "application/json"}, wantCounts: true},
	} {
		request := &http.Request{Method: c.method, Header: http.Header{}}
		for name, value := range c.header {
			request.Header.Set(name, value)
		}
		request.Header.Add("Cookie", tlsSessionCookieName+"=s; "+tlsLinkCookieName+"=l; "+tlsPreLoginCookieName+"=p; "+tlsNoticeCookieName+"=1")
		view := newTlsHttpSessionView(request, tlsFrontTestServerName)
		if view.counts != c.wantCounts || view.navigation != c.wantNavigation || view.sameOrigin != c.wantSameOrigin {
			t.Errorf("%s: counts %t, navigation %t, same-origin %t", c.name, view.counts, view.navigation, view.sameOrigin)
		}
		if (view.session == "s") != c.wantCounts || (view.link == "l") != c.wantCounts || (view.preLogin == "p") != c.wantCounts {
			t.Errorf("%s: cookies %q %q %q", c.name, view.session, view.link, view.preLogin)
		}
		if !view.noticeAccepted {
			t.Errorf("%s: the notice's acceptance was not read", c.name)
		}
	}
}

// Under members, with a session the front sealed: a cross-origin POST, a subresource GET and a WebSocket arrive
// anonymous and reach nothing, while a same-origin request and a top-level navigation from elsewhere pass.
func TestTlsHttpOtherOriginsArriveAnonymous(t *testing.T) {
	memberId := NewId()
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	cookie := fixture.sealSession(t, memberId)
	client := fixture.httpClient(tlsAlpnHttp11)
	request := func(method string, metadata map[string]string) *http.Request {
		request, err := http.NewRequest(method, "https://"+tlsFrontTestServerName+"/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range metadata {
			request.Header.Set(name, value)
		}
		request.Header.Set("Cookie", tlsSessionCookieName+"="+cookie)
		return request
	}
	anonymous := []map[string]string{
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "websocket", "Sec-Fetch-Dest": "websocket", "Upgrade": "websocket", "Connection": "Upgrade"},
		{"Origin": "https://" + tlsFrontTestOtherName},
	}
	for _, metadata := range anonymous {
		method := http.MethodGet
		if metadata["Sec-Fetch-Mode"] == "cors" || metadata["Origin"] != "" {
			method = http.MethodPost
		}
		response, _ := tlsFrontTestDo(t, client, request(method, metadata))
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%v: %d", metadata, response.StatusCode)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials for anonymous requests", dials)
	}
	passing := []map[string]string{
		{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
		{},
	}
	for _, metadata := range passing {
		response, _ := tlsFrontTestDo(t, client, request(http.MethodGet, metadata))
		if response.StatusCode != http.StatusOK {
			t.Errorf("%v: %d", metadata, response.StatusCode)
		}
		fixture.backend.nextRequest(t)
	}
}
