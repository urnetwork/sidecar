//go:build !ios_extension && !js

// The CT client on fixtures (§22.9: staging CT is unreliable): each source's own listing form, Cert Spotter's paging
// and crt.sh's fetch a certificate, the cursors, and every way a source fails. The fixtures' certificates are
// synthetic, under .example.

package sidecar

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The zone and custom host the fixtures' certificates name.
const (
	tlsCtTestZone   = "abcdefghij.sidecar.example"
	tlsCtTestCustom = "app.customer.example"
)

// Both sources over the fixtures, as their APIs answer: Cert Spotter a page at a time past after, crt.sh a listing a
// pattern and a certificate an id.
type tlsCtFixtureTransport struct {
	t           *testing.T
	certSpotter []map[string]any
	crtSh       struct {
		Listing      []map[string]any  `json:"listing"`
		Certificates map[string]string `json:"certificates"`
	}
	pageCount int

	stateLock sync.Mutex
	requests  []*http.Request
	// a source's name to the answer it gives in place of its own: a status, or a body
	failStatus map[string]int
	failBody   map[string]string
}

func newTlsCtFixtureTransport(t *testing.T) *tlsCtFixtureTransport {
	t.Helper()
	transport := &tlsCtFixtureTransport{t: t, pageCount: 2, failStatus: map[string]int{}, failBody: map[string]string{}}
	read := func(name string, into any) {
		encoded, err := os.ReadFile("testdata/tls/ct/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, into); err != nil {
			t.Fatal(err)
		}
	}
	read("certspotter.json", &transport.certSpotter)
	read("crtsh.json", &transport.crtSh)
	return transport
}

func (self *tlsCtFixtureTransport) fail(source string, status int, body string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.failStatus, source)
	delete(self.failBody, source)
	if status != 0 {
		self.failStatus[source] = status
	}
	if body != "" {
		self.failBody[source] = body
	}
}

func (self *tlsCtFixtureTransport) requestCount(host string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, request := range self.requests {
		if request.URL.Host == host {
			count += 1
		}
	}
	return count
}

// Whether a logged name is domain, under it, or a wildcard over it.
func tlsCtFixtureMatches(names []string, domain string) bool {
	for _, name := range names {
		name = strings.TrimPrefix(name, "*.")
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func (self *tlsCtFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	source := map[string]string{"api.certspotter.com": TlsCtSourceCertSpotter, "crt.sh": TlsCtSourceCrtSh}[request.URL.Host]
	status, body := func() (int, string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		return self.failStatus[source], self.failBody[source]
	}()
	if status != 0 {
		return syntheticResponse(request, status, "{}", nil), nil
	}
	if body != "" {
		return syntheticResponse(request, 200, body, nil), nil
	}
	query := request.URL.Query()
	answer := func(value any) (*http.Response, error) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return syntheticResponse(request, 200, string(encoded), nil), nil
	}
	switch source {
	case TlsCtSourceCertSpotter:
		if request.URL.Path != "/v1/issuances" || query.Get("include_subdomains") != "true" || query.Get("match_wildcards") != "true" {
			return syntheticResponse(request, 400, "{}", nil), nil
		}
		after, _ := strconv.Atoi(query.Get("after"))
		page := []map[string]any{}
		for _, issuance := range self.certSpotter {
			id, _ := strconv.Atoi(issuance["id"].(string))
			names := []string{}
			for _, name := range issuance["dns_names"].([]any) {
				names = append(names, name.(string))
			}
			if after < id && tlsCtFixtureMatches(names, query.Get("domain")) && len(page) < self.pageCount {
				page = append(page, issuance)
			}
		}
		return answer(page)
	case TlsCtSourceCrtSh:
		if id := query.Get("d"); id != "" {
			certificate, ok := self.crtSh.Certificates[id]
			if !ok {
				return syntheticResponse(request, 404, "", nil), nil
			}
			return syntheticResponse(request, 200, certificate, nil), nil
		}
		pattern := query.Get("q")
		listing := []map[string]any{}
		for _, entry := range self.crtSh.Listing {
			for _, name := range strings.Split(entry["name_value"].(string), "\n") {
				name = strings.TrimPrefix(name, "*.")
				matches := name == pattern
				if under, ok := strings.CutPrefix(pattern, "%."); ok {
					matches = strings.HasSuffix(name, "."+under)
				}
				if matches {
					listing = append(listing, entry)
					break
				}
			}
		}
		return answer(listing)
	}
	return syntheticResponse(request, 404, "{}", nil), nil
}

func newTlsCtFixtureClient(t *testing.T, transport *tlsCtFixtureTransport, key string) *TlsCtClient {
	t.Helper()
	client, err := NewTlsCtClient(&TlsCtClientArgs{Transport: transport, CertSpotterKey: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestTlsCtClientReadsCertSpotterAPageAtATime(t *testing.T) {
	transport := newTlsCtFixtureTransport(t)
	client := newTlsCtFixtureClient(t, transport, "synthetic-team-key")
	source := client.Sources()[0]
	if source.Name() != TlsCtSourceCertSpotter {
		t.Fatalf("the first source is %s", source.Name())
	}
	certificates, cursor, err := source.Issuances(t.Context(), tlsCtTestZone, "")
	if err != nil {
		t.Fatal(err)
	}
	// two under the zone and the expired one beneath it, over two pages and the empty one that ends them
	if len(certificates) != 3 || cursor != "900004" {
		t.Fatalf("%d certificates to cursor %q", len(certificates), cursor)
	}
	if count := transport.requestCount("api.certspotter.com"); count != 3 {
		t.Errorf("%d requests", count)
	}
	first := certificates[0]
	if first.Source != TlsCtSourceCertSpotter || first.SourceId != "900001" || first.Precertificate {
		t.Errorf("the first issuance %+v", first)
	}
	if len(first.DnsNames) != 2 || first.DnsNames[0] != "*."+tlsCtTestZone || first.DnsNames[1] != tlsCtTestZone {
		t.Errorf("names %v", first.DnsNames)
	}
	if first.SpkiSha256 == ([32]byte{}) || first.CertSha256 == ([32]byte{}) || first.NotBefore.IsZero() || !first.NotBefore.Before(first.NotAfter) {
		t.Errorf("the first issuance's key or validity %+v", first)
	}
	if _, err := first.IdentifierSetSha256(); err != nil {
		t.Errorf("the names form no identifier set: %v", err)
	}
	transport.stateLock.Lock()
	for _, request := range transport.requests {
		if request.Header.Get("Authorization") != "Bearer synthetic-team-key" {
			t.Errorf("a request without the Team's key")
		}
		if request.URL.Query().Get("domain") != tlsCtTestZone {
			t.Errorf("a request for another domain")
		}
	}
	transport.stateLock.Unlock()

	// past the cursor there is nothing, and the cursor stays
	again, next, err := source.Issuances(t.Context(), tlsCtTestZone, cursor)
	if err != nil || len(again) != 0 || next != cursor {
		t.Errorf("past the cursor: %d certificates to %q, %v", len(again), next, err)
	}
	// a custom host is its own query
	custom, _, err := source.Issuances(t.Context(), tlsCtTestCustom, "")
	if err != nil || len(custom) != 1 || custom[0].DnsNames[0] != tlsCtTestCustom {
		t.Errorf("the custom host's issuances %v, %v", custom, err)
	}
}

func TestTlsCtClientQueriesKeylessWithNoKey(t *testing.T) {
	transport := newTlsCtFixtureTransport(t)
	client := newTlsCtFixtureClient(t, transport, "")
	if _, _, err := client.Sources()[0].Issuances(t.Context(), tlsCtTestZone, ""); err != nil {
		t.Fatal(err)
	}
	transport.stateLock.Lock()
	defer transport.stateLock.Unlock()
	for _, request := range transport.requests {
		if _, ok := request.Header["Authorization"]; ok {
			t.Errorf("a keyless query carries a credential")
		}
	}
}

func TestTlsCtClientStopsAtItsBoundsAndContinuesFromTheCursor(t *testing.T) {
	transport := newTlsCtFixtureTransport(t)
	settings := DefaultTlsCtClientSettings()
	settings.CertificateMaxCount = 2
	client, err := NewTlsCtClient(&TlsCtClientArgs{Transport: transport, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range client.Sources() {
		first, cursor, err := source.Issuances(t.Context(), tlsCtTestZone, "")
		if err != nil || len(first) != 2 || cursor == "" {
			t.Fatalf("%s: %d certificates to %q, %v", source.Name(), len(first), cursor, err)
		}
		rest, next, err := source.Issuances(t.Context(), tlsCtTestZone, cursor)
		if err != nil || len(rest) != 1 || next == cursor {
			t.Errorf("%s: the rest is %d certificates to %q, %v", source.Name(), len(rest), next, err)
		}
		if rest[0].SourceId == first[0].SourceId || rest[0].SourceId == first[1].SourceId {
			t.Errorf("%s: a certificate answered twice", source.Name())
		}
	}
}

func TestTlsCtClientReadsCrtShACertificateAtATime(t *testing.T) {
	transport := newTlsCtFixtureTransport(t)
	client := newTlsCtFixtureClient(t, transport, "synthetic-team-key")
	source := client.Sources()[1]
	if source.Name() != TlsCtSourceCrtSh {
		t.Fatalf("the second source is %s", source.Name())
	}
	certificates, cursor, err := source.Issuances(t.Context(), tlsCtTestZone, "")
	if err != nil {
		t.Fatal(err)
	}
	// a precertificate, its certificate and a second certificate; the expired one is left out by the query
	if len(certificates) != 3 || cursor != "7000003" {
		t.Fatalf("%d certificates to cursor %q", len(certificates), cursor)
	}
	precertificate, certificate, second := certificates[0], certificates[1], certificates[2]
	if !precertificate.Precertificate || certificate.Precertificate || second.Precertificate {
		t.Errorf("precertificates %t %t %t", precertificate.Precertificate, certificate.Precertificate, second.Precertificate)
	}
	// the pair is one key and one set of names, and two logged entries
	if precertificate.SpkiSha256 != certificate.SpkiSha256 || strings.Join(precertificate.DnsNames, " ") != strings.Join(certificate.DnsNames, " ") {
		t.Errorf("a precertificate and its certificate differ in key or names")
	}
	if precertificate.CertSha256 == certificate.CertSha256 || second.SpkiSha256 == certificate.SpkiSha256 {
		t.Errorf("two entries read as one")
	}
	// crt.sh gets no credential of another source
	transport.stateLock.Lock()
	for _, request := range transport.requests {
		if request.URL.Host == "crt.sh" && request.Header.Get("Authorization") != "" {
			t.Errorf("crt.sh was sent Cert Spotter's key")
		}
	}
	transport.stateLock.Unlock()

	// both sources name the same keys
	spotted, _, err := client.Sources()[0].Issuances(t.Context(), tlsCtTestZone, "")
	if err != nil {
		t.Fatal(err)
	}
	if spotted[0].SpkiSha256 != certificate.SpkiSha256 || spotted[1].SpkiSha256 != second.SpkiSha256 {
		t.Errorf("the sources disagree on a certificate's key")
	}
	if spotted[0].CertSha256 != certificate.CertSha256 {
		t.Errorf("the sources disagree on a certificate's hash")
	}

	fetched := transport.requestCount("crt.sh")
	again, next, err := source.Issuances(t.Context(), tlsCtTestZone, cursor)
	if err != nil || len(again) != 0 || next != cursor {
		t.Errorf("past the cursor: %d certificates to %q, %v", len(again), next, err)
	}
	// only the two listings, and no certificate fetched twice
	if transport.requestCount("crt.sh")-fetched != 2 {
		t.Errorf("%d requests past the cursor", transport.requestCount("crt.sh")-fetched)
	}
	if _, _, err := source.Issuances(t.Context(), tlsCtTestZone, "not a cursor"); !errors.Is(err, ErrTlsCtSource) {
		t.Errorf("a cursor that is not crt.sh's: %v", err)
	}
}

func TestTlsCtClientASourceThatFailsIsAnErrorAndNeverACertificate(t *testing.T) {
	transport := newTlsCtFixtureTransport(t)
	settings := DefaultTlsCtClientSettings()
	settings.ResponseMaxByteCount = 64 * 1024
	client, err := NewTlsCtClient(&TlsCtClientArgs{Transport: transport, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "rate limited", status: 429},
		{name: "unavailable", status: 503},
		{name: "a redirect", status: 302},
		{name: "not a listing", body: "<html>busy</html>"},
		{name: "an object", body: `{"error":"busy"}`},
		{name: "an entry with no id or key", body: `[{"dns_names":["abcdefghij.sidecar.example"]}]`},
		{name: "past the bound", body: `["` + strings.Repeat("a", 70*1024) + `"]`},
	}
	for _, source := range client.Sources() {
		for _, c := range cases {
			transport.fail(source.Name(), c.status, c.body)
			certificates, cursor, err := source.Issuances(t.Context(), tlsCtTestZone, "")
			if !errors.Is(err, ErrTlsCtSource) || len(certificates) != 0 || cursor != "" {
				t.Errorf("%s, %s: %d certificates to %q, %v", source.Name(), c.name, len(certificates), cursor, err)
			}
			// the error names no domain (I-13)
			if err != nil && strings.Contains(err.Error(), "sidecar.example") {
				t.Errorf("%s, %s: the error carries the domain", source.Name(), c.name)
			}
		}
		transport.fail(source.Name(), 0, "")
	}
	// a Cert Spotter issuance with a key that is no hash, and a crt.sh certificate that does not parse
	transport.fail(TlsCtSourceCertSpotter, 0, `[{"id":"1","pubkey_sha256":"zz","not_before":"2026-03-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z"}]`)
	if _, _, err := client.Sources()[0].Issuances(t.Context(), tlsCtTestZone, ""); !errors.Is(err, ErrTlsCtSource) {
		t.Errorf("an issuance with no key: %v", err)
	}
	if _, err := parseTlsCtCertificate([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); !errors.Is(err, ErrTlsCtSource) {
		t.Errorf("a certificate that does not parse: %v", err)
	}
	if _, err := parseTlsCtCertificate([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); !errors.Is(err, ErrTlsCtSource) {
		t.Errorf("a block that is no certificate: %v", err)
	}
}

func TestNewTlsCtClientDialsDirectlyAndRefusesBadSettings(t *testing.T) {
	client, err := NewTlsCtClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// no proxy of any kind, the environment's included (§2.8 ext-1)
	if client.ownTransport == nil || client.ownTransport.Proxy != nil {
		t.Errorf("the client's own transport may use a proxy")
	}
	if len(client.Sources()) != 2 {
		t.Errorf("%d sources", len(client.Sources()))
	}
	plain := DefaultTlsCtClientSettings()
	plain.CrtShUrl = "http://crt.sh/"
	if _, err := NewTlsCtClient(&TlsCtClientArgs{Settings: plain}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a plain http source: %v", err)
	}
	unbounded := DefaultTlsCtClientSettings()
	unbounded.ResponseMaxByteCount = 0
	if _, err := NewTlsCtClient(&TlsCtClientArgs{Settings: unbounded}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("no response bound: %v", err)
	}
}

// §12.5's restore replay and §21.6's screen import the client from server, so it links no connect.
func TestTlsCtClientImportsNoConnect(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "tls_ct_client.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		if strings.Contains(spec.Path.Value, "urnetwork/connect") {
			t.Errorf("tls_ct_client.go imports %s", spec.Path.Value)
		}
	}
}
