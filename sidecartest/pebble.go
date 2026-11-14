// Pebble, Let's Encrypt's ACME test server, run in the test's own process for T2's ACME rows (§22.9:
// "Pebble with 5% bad nonces in T2 and T3"), beside a DNS server its validation authority asks. certs
// writes its DNS-01 challenges through FakeCertsDns, which serves them there, so an order runs the whole
// of RFC 8555 against a real ACME server: accounts with or without EAB, orders, authorizations, ARI,
// replaces, key rollover and revocation. Pebble never checks CAA or a customer's accounturi (§22.9), so
// those rows are LE staging's.
//
// Pebble reads its knobs from the environment when it starts, so StartPebble sets them with t.Setenv,
// and a test that starts one cannot run in parallel. It answers on loopback TLS under a certificate of
// its own, which HttpClient trusts. Everything stops when the test ends.

package sidecartest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

// A profile like Let's Encrypt's tlsserver: 45 days (§13.8).
const PebbleProfileTlsServer = "tlsserver"

type PebbleSettings struct {
	// The share of good nonces Pebble refuses as bad, in percent: §22.9's 5.
	NonceRejectPercent int
	// The share of orders whose authorizations Pebble reuses from an earlier valid one, in percent, as
	// LE's 7 h reuse does. 0 asks for every authorization again.
	AuthzReusePercent int
	// Whether newAccount needs an external account binding, as GTS and ZeroSSL do.
	RequireEab bool
	// EAB key ids to their base64url MAC keys.
	EabKeys map[string]string
}

func DefaultPebbleSettings() *PebbleSettings {
	return &PebbleSettings{
		NonceRejectPercent: 5,
		AuthzReusePercent:  0,
		EabKeys:            map[string]string{},
	}
}

// One Pebble and its DNS server.
type Pebble struct {
	// The ACME directory.
	DirectoryUrl string
	// Trusts Pebble's TLS.
	HttpClient *http.Client
	// Pebble's issuing roots, which its chains verify under.
	Roots *x509.CertPool
	// Where certs writes the challenges Pebble checks.
	Dns *FakeCertsDns

	newOrderPath string
	// Pebble's rows, for what it recorded of a revocation
	memoryStore *db.MemoryStore

	stateLock sync.Mutex
	// newOrder requests still to refuse with 429, and the Retry-After each says
	refuseOrderCount int
	refuseRetryAfter time.Duration
}

// A Pebble on loopback, stopped at the test's end.
func StartPebble(t testing.TB, settings *PebbleSettings) *Pebble {
	t.Helper()
	if settings == nil {
		settings = DefaultPebbleSettings()
	}
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", strconv.Itoa(settings.NonceRejectPercent))
	t.Setenv("PEBBLE_AUTHZREUSE", strconv.Itoa(settings.AuthzReusePercent))

	dnsServer := startPebbleDns(t)
	logger := log.New(io.Discard, "", 0)
	memoryStore := db.NewMemoryStore()
	authority := ca.New(logger, memoryStore, "", "ecdsa", 0, 1, map[string]ca.Profile{
		PebbleProfileTlsServer: {Description: "45 days, as LE's tlsserver", ValidityPeriod: uint64((45 * 24 * time.Hour).Seconds())},
		"default":              {Description: "Pebble's default"},
	})
	validator := va.New(logger, 0, 0, false, dnsServer.address, memoryStore)
	for keyId, macKey := range settings.EabKeys {
		if err := memoryStore.AddExternalAccountKeyByID(keyId, macKey); err != nil {
			t.Fatal(err)
		}
	}
	frontEnd := wfe.New(logger, memoryStore, validator, authority, []string{"pebble.example"}, false, settings.RequireEab, 0, 0)

	pebble := &Pebble{
		Dns:          newFakeCertsDns(dnsServer),
		newOrderPath: "/order-plz",
		memoryStore:  memoryStore,
	}
	handler := frontEnd.Handler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == pebble.newOrderPath && pebble.refuseOrder(writer) {
			return
		}
		handler.ServeHTTP(writer, request)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	pebble.DirectoryUrl = server.URL + wfe.DirectoryPath
	pebble.HttpClient = server.Client()
	pebble.Roots = x509.NewCertPool()
	pebble.Roots.AddCert(authority.GetRootCert(0).Cert)

	// the directory names newOrder's path; Pebble's own is checked rather than assumed
	response, err := pebble.HttpClient.Get(pebble.DirectoryUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	directory := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&directory); err != nil {
		t.Fatal(err)
	}
	newOrderUrl, _ := directory["newOrder"].(string)
	parsed, err := url.Parse(newOrderUrl)
	if err != nil || parsed.Path == "" {
		t.Fatalf("Pebble's directory names no newOrder: %v", directory)
	}
	pebble.newOrderPath = parsed.Path
	return pebble
}

// What Pebble recorded of leaf's revocation: the RFC 5280 reason code it was told, 0 when it was told
// none, and whether it holds the certificate as revoked at all.
func (self *Pebble) RevocationReason(leaf []byte) (reason int, revoked bool) {
	record := self.memoryStore.GetRevokedCertificateByDER(leaf)
	if record == nil {
		return 0, false
	}
	if record.Reason != nil {
		reason = int(*record.Reason)
	}
	return reason, true
}

// Refuses the next count newOrder requests with 429 rateLimited and Retry-After, as LE's limits do.
func (self *Pebble) RefuseNewOrders(count int, retryAfter time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuseOrderCount = count
	self.refuseRetryAfter = retryAfter
}

// Answers a refused newOrder, and false when none is to be refused.
func (self *Pebble) refuseOrder(writer http.ResponseWriter) bool {
	retryAfter, refuse := func() (time.Duration, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.refuseOrderCount <= 0 {
			return 0, false
		}
		self.refuseOrderCount -= 1
		return self.refuseRetryAfter, true
	}()
	if !refuse {
		return false
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	writer.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(writer, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many new orders","status":429}`)
	return true
}

// The DNS server Pebble's validation authority asks, over TCP, as Pebble's VA does: TXT records by name,
// NOERROR with no answer for anything else.
type pebbleDns struct {
	address string

	stateLock sync.Mutex
	nameTxts  map[string][]string
}

func startPebbleDns(t testing.TB) *pebbleDns {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	self := &pebbleDns{address: listener.Addr().String(), nameTxts: map[string][]string{}}
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: dns.HandlerFunc(self.serve)}
	go server.ActivateAndServe()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.ShutdownContext(ctx)
	})
	return self
}

func (self *pebbleDns) serve(writer dns.ResponseWriter, request *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.Authoritative = true
	for _, question := range request.Question {
		if question.Qtype != dns.TypeTXT {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		for _, txt := range self.txts(name) {
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			})
		}
	}
	writer.WriteMsg(reply)
}

func (self *pebbleDns) txts(name string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.nameTxts[name]...)
}

func (self *pebbleDns) set(name string, values []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name = strings.ToLower(name)
	if len(values) == 0 {
		delete(self.nameTxts, name)
		return
	}
	self.nameTxts[name] = append([]string{}, values...)
}
