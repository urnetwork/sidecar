//go:build !sidecar_http && !ios_extension

// §13.7's origin rows for one HTTP request (D-TLS-5, D-TEAM-15, §12.4): browsers coalesce a network's hosts on one
// wildcard certificate and one address set, and until <root> is on the PSL every network is one site, so neither the
// connection nor SameSite says which origin a request is for or from.
//
//	421     Host, or h2's :authority, and an absolute-form target's authority must equal the SNI, port aside (RFC 9113
//	        §9.1.1), or the request is answered 421 and goes nowhere
//	cookies the front's session cookies, __Host-ur-session and a link's __Host-ur-link, and the pending login's
//	        __Host-ur-pre, count only on Sec-Fetch-Site same-origin or none, or on a top-level GET or HEAD navigation
//	        (Sec-Fetch-Mode navigate, Sec-Fetch-Dest document); without Fetch Metadata, only with no Origin or the
//	        host's own. Any other request, from the network's other hosts too, arrives anonymous
//
// Browsers without Fetch Metadata (before March 2023) still send the cookies on other origins' GETs, which §2.10
// discloses. tlsHttpSessionView is what one request may count, and it holds no cookie it may not.

package sidecar

import (
	"net"
	"net/http"
	"strings"
)

// Fetch Metadata's values the rules read (https://www.w3.org/TR/fetch-metadata/).
const (
	tlsFetchSiteSameOrigin   = "same-origin"
	tlsFetchSiteNone         = "none"
	tlsFetchModeNavigate     = "navigate"
	tlsFetchDestDocument     = "document"
	tlsHttpHeaderFetchSite   = "Sec-Fetch-Site"
	tlsHttpHeaderFetchMode   = "Sec-Fetch-Mode"
	tlsHttpHeaderFetchDest   = "Sec-Fetch-Dest"
	tlsHttpHeaderOrigin      = "Origin"
	tlsHttpContentTypeHtml   = "text/html"
	tlsHttpHeaderAccept      = "Accept"
	tlsHttpOriginSchemeHttps = "https://"
)

// Whether r is for serverName: its Host, :authority on h2 and any Host header beside it, and an absolute-form target's
// authority, each port aside and with no trailing dot, case aside.
func tlsHttpHostMatches(r *http.Request, serverName string) bool {
	hostMatches := func(host string) bool {
		if host == "" {
			return false
		}
		hostname := host
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			hostname = splitHost
		}
		return strings.EqualFold(strings.TrimSuffix(hostname, "."), serverName)
	}
	if !hostMatches(r.Host) {
		return false
	}
	// on h2 a Host header beside :authority must agree with it (RFC 9113 §8.3.1)
	if host := r.Header.Get("Host"); host != "" && !hostMatches(host) {
		return false
	}
	return r.URL.Host == "" || hostMatches(r.URL.Host)
}

// What one request may count of the front's own cookies, and how it came.
type tlsHttpSessionView struct {
	// The front's session cookies count: the other-origins rule holds.
	counts bool
	// Same-origin by Fetch Metadata, or without it by Origin: what a front form's post needs.
	sameOrigin bool
	// A top-level GET or HEAD navigation for a document: what edge login and the notice start on.
	navigation bool
	// The cookies, each "" when absent or when the request may not count it.
	session  string
	link     string
	preLogin string
	// The notice was accepted on this host. It holds no standing, so it is read whatever the rule says.
	noticeAccepted bool
}

// r's view on serverName's host.
func newTlsHttpSessionView(r *http.Request, serverName string) *tlsHttpSessionView {
	view := &tlsHttpSessionView{}
	getOrHead := r.Method == http.MethodGet || r.Method == http.MethodHead
	if site := r.Header.Get(tlsHttpHeaderFetchSite); site != "" {
		view.navigation = getOrHead && r.Header.Get(tlsHttpHeaderFetchMode) == tlsFetchModeNavigate &&
			r.Header.Get(tlsHttpHeaderFetchDest) == tlsFetchDestDocument
		view.sameOrigin = site == tlsFetchSiteSameOrigin
		view.counts = view.sameOrigin || site == tlsFetchSiteNone || view.navigation
	} else {
		origin := r.Header.Get(tlsHttpHeaderOrigin)
		view.sameOrigin = strings.EqualFold(origin, tlsHttpOriginSchemeHttps+serverName)
		view.counts = origin == "" || view.sameOrigin
		view.navigation = getOrHead && view.counts && strings.Contains(r.Header.Get(tlsHttpHeaderAccept), tlsHttpContentTypeHtml)
	}
	cookieValue := func(name string) string {
		cookie, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
	view.noticeAccepted = cookieValue(tlsNoticeCookieName) != ""
	if view.counts {
		view.session = cookieValue(tlsSessionCookieName)
		view.link = cookieValue(tlsLinkCookieName)
		view.preLogin = cookieValue(tlsPreLoginCookieName)
	}
	return view
}

// Whether a cookie's name is one of the front's, its __Host-ur- prefix in any case, since browsers read the
// __Host- prefix without regard to case.
func tlsHttpFrontCookieName(name string) bool {
	name = strings.TrimSpace(name)
	return len(tlsFrontCookiePrefix) <= len(name) && strings.EqualFold(name[:len(tlsFrontCookiePrefix)], tlsFrontCookiePrefix)
}

// Takes the front's cookies out of a request's Cookie headers, leaving every other pair as it was sent, so the local
// service never sees a session, a link or a pending login.
func tlsHttpStripFrontCookies(header http.Header) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return
	}
	keptPairs := []string{}
	for _, value := range values {
		for _, pair := range strings.Split(value, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, _, _ := strings.Cut(pair, "=")
			if tlsHttpFrontCookieName(name) {
				continue
			}
			keptPairs = append(keptPairs, pair)
		}
	}
	header.Del("Cookie")
	if 0 < len(keptPairs) {
		header.Set("Cookie", strings.Join(keptPairs, "; "))
	}
}

// Takes a response's Set-Cookie headers for the front's cookies out, so the local service can neither set nor clear
// one.
func tlsHttpStripFrontSetCookies(header http.Header) {
	values := header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	keptValues := []string{}
	for _, value := range values {
		name, _, _ := strings.Cut(value, "=")
		if tlsHttpFrontCookieName(name) {
			continue
		}
		keptValues = append(keptValues, value)
	}
	header.Del("Set-Cookie")
	for _, value := range keptValues {
		header.Add("Set-Cookie", value)
	}
}
