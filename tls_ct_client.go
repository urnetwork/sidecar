//go:build !ios_extension

// The two Certificate Transparency sources D-TLS-8's watch reads (TLS-M5-24; R-TLS-8, D-TRUST-6, §2.8 ext-1): Cert
// Spotter's issuances API and crt.sh. Exported and free of connect, since §12.5's restore replay and §21.6's screen
// read the same sources from server.
//
// Each source answers the certificates logged for a domain and its subdomains past a cursor of its own, in one form:
// the key's SPKI hash, the names, the validity, and whether the entry is a precertificate. Cert Spotter gives those
// in its listing. crt.sh's listing names no key, so each entry not yet seen is fetched and parsed.
//
// A source's answer is an outside party's word, read under bounds: a response past ResponseMaxByteCount, a page or
// certificate count past its bound, or an entry that does not parse is the source failing, never a certificate. A
// keyless query is best effort, so a failure here is what the watch shows as degraded, and never an alarm.
//
// A query never rides a URnetwork proxy (§2.8 ext-1): with no Transport given the client dials directly, with no
// proxy of any kind, the environment's included. A query's url carries the domain asked about, which is what ext-1
// says the source sees; nothing here logs it (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The sources' names, as a cursor and an alarm name them.
const (
	TlsCtSourceCertSpotter = "certspotter"
	TlsCtSourceCrtSh       = "crtsh"
)

// A source gave no usable answer: unreachable, refused, rate limited, past a bound, or not in its own form.
var ErrTlsCtSource = errors.New("tls ct: the source gave no usable answer")

// RFC 6962's poison extension, which marks a precertificate.
var tlsCtPoisonExtensionId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// Tunables of the client.
type TlsCtClientSettings struct {
	// Cert Spotter's issuances endpoint (https://sslmate.com/help/reference/ct_search_api_v1).
	CertSpotterUrl string
	// crt.sh's search endpoint.
	CrtShUrl string
	// One request's deadline.
	RequestTimeout time.Duration
	// The most bytes one response is read to.
	ResponseMaxByteCount int64
	// The most pages one call reads from Cert Spotter. A domain with more is continued from the cursor.
	PageMaxCount int
	// The most certificates one call answers, and so the most crt.sh certificates one call fetches. A domain with
	// more is continued from the cursor.
	CertificateMaxCount int
}

// The public endpoints, under bounds a network's own zone stays far inside.
func DefaultTlsCtClientSettings() *TlsCtClientSettings {
	return &TlsCtClientSettings{
		CertSpotterUrl:       "https://api.certspotter.com/v1/issuances",
		CrtShUrl:             "https://crt.sh/",
		RequestTimeout:       30 * time.Second,
		ResponseMaxByteCount: 8 * 1024 * 1024,
		PageMaxCount:         32,
		CertificateMaxCount:  1024,
	}
}

// One certificate a source logged.
type TlsCtCertificate struct {
	// The source's name and its own id for the entry.
	Source   string
	SourceId string
	// Of the key's DER SubjectPublicKeyInfo.
	SpkiSha256 [sha256.Size]byte
	// Of the logged certificate's DER. Zero where the source gives none.
	CertSha256 [sha256.Size]byte
	// The DNS names, lowercase, sorted, each once.
	DnsNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	// The entry is a precertificate. Cert Spotter folds a precertificate and its certificate into one issuance.
	Precertificate bool
}

// TlsIdentifierSetHash of the certificate's names, which an attestation of it covers. An error for names that form
// no identifier set, which no attestation covers.
func (self *TlsCtCertificate) IdentifierSetSha256() ([sha256.Size]byte, error) {
	return TlsIdentifierSetHash(self.DnsNames)
}

// One source of logged certificates. Safe for concurrent use.
type TlsCtSource interface {
	// TlsCtSourceCertSpotter or TlsCtSourceCrtSh.
	Name() string
	// The certificates logged for domain, its subdomains and the wildcards over them, past cursor, and the cursor
	// past them. cursor is the source's own, "" from the start. An error wraps ErrTlsCtSource and moves no cursor.
	Issuances(ctx context.Context, domain string, cursor string) (certificates []*TlsCtCertificate, next string, err error)
}

// What NewTlsCtClient takes.
type TlsCtClientArgs struct {
	// How the client reaches the sources. nil dials directly, with no proxy. A caller's own must reach them without a
	// URnetwork proxy.
	Transport http.RoundTripper
	// Cert Spotter's API key, a Team's own (D-TLS-8). Empty queries keyless.
	CertSpotterKey string
	// nil takes the defaults.
	Settings *TlsCtClientSettings
}

// The client of both sources.
type TlsCtClient struct {
	settings       *TlsCtClientSettings
	httpClient     *http.Client
	ownTransport   *http.Transport
	certSpotterKey string
}

// A client of both sources. Close releases its connections.
func NewTlsCtClient(args *TlsCtClientArgs) (*TlsCtClient, error) {
	if args == nil {
		args = &TlsCtClientArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultTlsCtClientSettings()
	}
	for _, endpoint := range []string{settings.CertSpotterUrl, settings.CrtShUrl} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, fmt.Errorf("%w: a ct source's url is https", errInvalidSettings)
		}
	}
	if settings.RequestTimeout <= 0 || settings.ResponseMaxByteCount <= 0 || settings.PageMaxCount <= 0 || settings.CertificateMaxCount <= 0 {
		return nil, fmt.Errorf("%w: a ct client's bounds are positive", errInvalidSettings)
	}
	self := &TlsCtClient{settings: settings, certSpotterKey: args.CertSpotterKey}
	transport := args.Transport
	if transport == nil {
		// no proxy, the environment's included
		self.ownTransport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}
		transport = self.ownTransport
	}
	self.httpClient = &http.Client{
		Transport: transport,
		// a source that redirects is not answering
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return self, nil
}

// Releases the client's own connections.
func (self *TlsCtClient) Close() {
	if self.ownTransport != nil {
		self.ownTransport.CloseIdleConnections()
	}
}

// Both sources, Cert Spotter first.
func (self *TlsCtClient) Sources() []TlsCtSource {
	return []TlsCtSource{&tlsCtCertSpotter{client: self}, &tlsCtCrtSh{client: self}}
}

// One GET's body, read to the response bound. Anything but a 200 inside the bound is the source failing.
func (self *TlsCtClient) get(ctx context.Context, requestUrl string, bearer string) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, self.settings.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, "GET", requestUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: a request that cannot be one", ErrTlsCtSource)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := self.httpClient.Do(request)
	if err != nil {
		// a transport's error carries the url, and so the domain: not wrapped
		return nil, fmt.Errorf("%w: unreachable", ErrTlsCtSource)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrTlsCtSource, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount+1))
	if err != nil {
		return nil, fmt.Errorf("%w: a body cut short", ErrTlsCtSource)
	}
	if self.settings.ResponseMaxByteCount < int64(len(body)) {
		return nil, fmt.Errorf("%w: a body past the bound", ErrTlsCtSource)
	}
	return body, nil
}

// The names of a logged certificate in one form: lowercase, sorted, each once.
func tlsCtCanonicalNames(names []string) []string {
	canonical := []string{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			canonical = append(canonical, name)
		}
	}
	slices.Sort(canonical)
	return slices.Compact(canonical)
}

// A hex SHA-256 as a source writes one.
func tlsCtParseSha256(value string) ([sha256.Size]byte, bool) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return [sha256.Size]byte{}, false
	}
	return [sha256.Size]byte(decoded), true
}

// Cert Spotter's issuances.
type tlsCtCertSpotter struct {
	client *TlsCtClient
}

// One issuance of Cert Spotter's listing: a certificate and its precertificate as one entry.
type tlsCtCertSpotterIssuance struct {
	Id           string   `json:"id"`
	CertSha256   string   `json:"cert_sha256"`
	PubkeySha256 string   `json:"pubkey_sha256"`
	DnsNames     []string `json:"dns_names"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
}

// See TlsCtSource.
func (self *tlsCtCertSpotter) Name() string {
	return TlsCtSourceCertSpotter
}

// See TlsCtSource. The cursor is the last issuance's id, which the API takes as after.
func (self *tlsCtCertSpotter) Issuances(ctx context.Context, domain string, cursor string) ([]*TlsCtCertificate, string, error) {
	settings := self.client.settings
	certificates := []*TlsCtCertificate{}
	for range settings.PageMaxCount {
		query := url.Values{}
		query.Set("domain", domain)
		query.Set("include_subdomains", "true")
		query.Set("match_wildcards", "true")
		query.Add("expand", "dns_names")
		if cursor != "" {
			query.Set("after", cursor)
		}
		body, err := self.client.get(ctx, settings.CertSpotterUrl+"?"+query.Encode(), self.client.certSpotterKey)
		if err != nil {
			return nil, "", err
		}
		issuances := []*tlsCtCertSpotterIssuance{}
		if err := json.Unmarshal(body, &issuances); err != nil {
			return nil, "", fmt.Errorf("%w: not a listing", ErrTlsCtSource)
		}
		if len(issuances) == 0 {
			return certificates, cursor, nil
		}
		for _, issuance := range issuances {
			certificate, err := issuance.certificate()
			if err != nil {
				return nil, "", err
			}
			certificates = append(certificates, certificate)
			cursor = issuance.Id
			if settings.CertificateMaxCount <= len(certificates) {
				return certificates, cursor, nil
			}
		}
	}
	return certificates, cursor, nil
}

// The issuance in the client's form. One with no id, key or validity is not the API's.
func (self *tlsCtCertSpotterIssuance) certificate() (*TlsCtCertificate, error) {
	if self == nil || self.Id == "" {
		return nil, fmt.Errorf("%w: an issuance with no id", ErrTlsCtSource)
	}
	spkiSha256, ok := tlsCtParseSha256(self.PubkeySha256)
	if !ok {
		return nil, fmt.Errorf("%w: an issuance with no key", ErrTlsCtSource)
	}
	notBefore, err := time.Parse(time.RFC3339, self.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("%w: an issuance with no validity", ErrTlsCtSource)
	}
	notAfter, err := time.Parse(time.RFC3339, self.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("%w: an issuance with no validity", ErrTlsCtSource)
	}
	// absent for an issuance known only by its precertificate
	certSha256, _ := tlsCtParseSha256(self.CertSha256)
	return &TlsCtCertificate{
		Source:     TlsCtSourceCertSpotter,
		SourceId:   self.Id,
		SpkiSha256: spkiSha256,
		CertSha256: certSha256,
		DnsNames:   tlsCtCanonicalNames(self.DnsNames),
		NotBefore:  notBefore.UTC(),
		NotAfter:   notAfter.UTC(),
	}, nil
}

// crt.sh's search.
type tlsCtCrtSh struct {
	client *TlsCtClient
}

// One entry of crt.sh's listing. It names no key, so the entry's certificate is fetched by its id.
type tlsCtCrtShEntry struct {
	Id int64 `json:"id"`
}

// See TlsCtSource.
func (self *tlsCtCrtSh) Name() string {
	return TlsCtSourceCrtSh
}

// See TlsCtSource. The cursor is the greatest entry id read, in decimal: crt.sh's ids rise as it logs.
func (self *tlsCtCrtSh) Issuances(ctx context.Context, domain string, cursor string) ([]*TlsCtCertificate, string, error) {
	settings := self.client.settings
	after := int64(0)
	if cursor != "" {
		parsed, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || parsed < 0 {
			return nil, "", fmt.Errorf("%w: a cursor that is not crt.sh's", ErrTlsCtSource)
		}
		after = parsed
	}
	// the name itself, then every name under it, which the wildcards over them match too
	ids := []int64{}
	for _, pattern := range []string{domain, "%." + domain} {
		query := url.Values{}
		query.Set("q", pattern)
		query.Set("output", "json")
		query.Set("exclude", "expired")
		body, err := self.client.get(ctx, settings.CrtShUrl+"?"+query.Encode(), "")
		if err != nil {
			return nil, "", err
		}
		entries := []*tlsCtCrtShEntry{}
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, "", fmt.Errorf("%w: not a listing", ErrTlsCtSource)
		}
		for _, entry := range entries {
			if entry == nil || entry.Id <= 0 {
				return nil, "", fmt.Errorf("%w: an entry with no id", ErrTlsCtSource)
			}
			if after < entry.Id {
				ids = append(ids, entry.Id)
			}
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	// oldest first, so a domain with more than the bound is continued from the cursor
	ids = ids[:min(len(ids), settings.CertificateMaxCount)]
	certificates := []*TlsCtCertificate{}
	for _, id := range ids {
		sourceId := strconv.FormatInt(id, 10)
		query := url.Values{}
		query.Set("d", sourceId)
		body, err := self.client.get(ctx, settings.CrtShUrl+"?"+query.Encode(), "")
		if err != nil {
			return nil, "", err
		}
		certificate, err := parseTlsCtCertificate(body)
		if err != nil {
			return nil, "", err
		}
		certificate.Source = TlsCtSourceCrtSh
		certificate.SourceId = sourceId
		certificates = append(certificates, certificate)
		after = id
	}
	if after == 0 {
		return certificates, "", nil
	}
	return certificates, strconv.FormatInt(after, 10), nil
}

// A logged certificate or precertificate, PEM or DER, in the client's form.
func parseTlsCtCertificate(data []byte) (*TlsCtCertificate, error) {
	der := data
	if block, _ := pem.Decode(bytes.TrimSpace(data)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: not a certificate", ErrTlsCtSource)
		}
		der = block.Bytes
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: a certificate that does not parse", ErrTlsCtSource)
	}
	certificate := &TlsCtCertificate{
		SpkiSha256: sha256.Sum256(parsed.RawSubjectPublicKeyInfo),
		CertSha256: sha256.Sum256(der),
		DnsNames:   tlsCtCanonicalNames(parsed.DNSNames),
		NotBefore:  parsed.NotBefore.UTC(),
		NotAfter:   parsed.NotAfter.UTC(),
	}
	for _, extension := range parsed.Extensions {
		if extension.Id.Equal(tlsCtPoisonExtensionId) {
			certificate.Precertificate = true
		}
	}
	return certificate, nil
}
