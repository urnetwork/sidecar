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
//
// A test whose challenges a real dns edge serves gives the resolver Pebble's validation authority asks
// (PebbleSettings.DnsAddress), as server's e2e world does with its own, which reaches the edge; Pebble
// then starts no DNS server of its own and Dns is nil. SetRenewalWindow answers a certificate's ARI
// with the window a test chooses, as a CA asking for an early renewal does (RFC 9773 §4.2).
//
// Pebble v2.10.3 leaks a read lock on each challenge it leaves out when it shows an authorization that
// is no longer pending (wfe's prepAuthorizationForDisplay continues past the challenge's RUnlock). A
// challenge no one starts costs nothing by it, but a deactivation that lands while the authorization's
// challenge is under validation leaves that challenge's lock read-held for good: the validation
// authority then waits forever for the challenge's write lock while it holds the authorization's, and a
// later newOrder, whose look for a valid authorization to reuse reads each authorization's lock in
// turn, waits forever behind it with Pebble's store lock read-held, so no order goes again. acmez
// deactivates an order's authorizations when a later one's solver fails, after it has had Pebble start
// validating an earlier one, as certs' does when dns refuses a challenge write mid-order. So a request
// on an authorization reaches Pebble here only once the validation authority has finished every
// challenge of it under way, which only the authority's log tells: the harness reads it for each
// challenge set valid or invalid. A request still held at ValidationWaitTimeout is answered 503 and
// fails the test. A client starting a challenge while it sends a request on the same authorization is
// not held apart from it; acmez never sends the two at once.
//
// Every wait here is bounded: the start's by StartTimeout, a held request's by ValidationWaitTimeout,
// and the test's end, which lets held requests go, closes Pebble's connections and waits for its
// requests and its DNS server to end, by CloseTimeout, past which it fails the test naming Pebble's
// goroutines rather than wait on a Pebble that will never answer. HoldLookups and AuthorizationHeld let
// a test put a request on an authorization while its challenge is under validation, deterministically.

package sidecartest

import (
	"bytes"
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
	"path"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

// A profile like Let's Encrypt's tlsserver: 45 days (§13.8).
const PebbleProfileTlsServer = "tlsserver"

// Where Pebble serves authorizations, wfe's authzPath, which it does not export.
const pebbleAuthzPath = "/authZ/"

// What Pebble's validation authority logs once it has set a challenge and its authorization valid or
// invalid, after "authz <id> set VALID" or "set INVALID" and before the challenge's id.
const pebbleValidationDoneMarker = " by completed challenge "

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
	// The DNS server Pebble's validation authority asks over TCP for each DNS-01 challenge, host:port, as
	// a recursive resolver is asked: a test's own. Empty starts Pebble's own beside it, which certs
	// writes to through Dns.
	DnsAddress string
	// Whether newOrder lists the order's authorizations in its names' sorted order, the order Pebble makes
	// them in, rather than shuffled as Pebble lists them (RFC 8555 §7.4 lets a server list them in any
	// order), so a test knows which one acmez takes first.
	SortedAuthorizations bool
	// How long a certificate of the tlsserver profile lasts: LE's 45 days (§13.8).
	TlsServerValidity time.Duration
	// The roots Pebble issues under beside its first, its PEBBLE_ALTERNATE_ROOTS: none.
	AlternateRootCount int
	// The length of the chain under each root, its PEBBLE_CHAIN_LENGTH: 1, Pebble's own.
	ChainLength int
	// The Retry-After, in whole seconds, Pebble gives a pending authorization with a challenge under
	// validation. Zero gives none, so a client polls at its own interval.
	AuthzRetryAfter time.Duration
	// The Retry-After, in whole seconds, Pebble gives an order it is still processing. Zero gives none.
	OrderRetryAfter time.Duration
	// The TTL of each TXT record Pebble's own DNS serves.
	DnsTxtTtl time.Duration
	// How long StartPebble waits for its DNS server to listen and for Pebble's directory.
	StartTimeout time.Duration
	// How long a request on an authorization waits for the validation authority to finish a challenge
	// of it under way (see the file header): past the 15 s Pebble gives each lookup, so a loaded machine
	// still waits one out. A request held this long is answered 503 and fails the test.
	ValidationWaitTimeout time.Duration
	// How long the test's end waits for Pebble's requests, and then its DNS server, to end before it
	// fails the test.
	CloseTimeout time.Duration
}

func DefaultPebbleSettings() *PebbleSettings {
	return &PebbleSettings{
		NonceRejectPercent:    5,
		AuthzReusePercent:     0,
		EabKeys:               map[string]string{},
		TlsServerValidity:     45 * 24 * time.Hour,
		AlternateRootCount:    0,
		ChainLength:           1,
		AuthzRetryAfter:       0,
		OrderRetryAfter:       0,
		DnsTxtTtl:             60 * time.Second,
		StartTimeout:          30 * time.Second,
		ValidationWaitTimeout: 30 * time.Second,
		CloseTimeout:          10 * time.Second,
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
	// Where certs writes the challenges Pebble checks; nil when PebbleSettings.DnsAddress named the
	// resolver Pebble asks.
	Dns *FakeCertsDns

	settings     *PebbleSettings
	newOrderPath string
	// Pebble's rows, for what it recorded of a revocation and an authorization's challenges
	memoryStore *db.MemoryStore
	// Pebble's own DNS; nil when PebbleSettings.DnsAddress named the resolver
	dnsServer *pebbleDns
	// what the validation authority has finished, read from its log
	validations *pebbleValidations
	// closed at the test's end, which lets every held request go
	closing chan struct{}
	// closed at the first request on an authorization held for a challenge under validation
	authorizationHeld     chan struct{}
	authorizationHeldOnce sync.Once

	stateLock sync.Mutex
	// newOrder requests still to refuse with 429, and the Retry-After each says
	refuseOrderCount int
	refuseRetryAfter time.Duration
	// what the harness did in Pebble's place, failed at the test's end
	faults []string
}

// A Pebble on loopback, stopped at the test's end. Settings are DefaultPebbleSettings' with a test's
// changes; settings that leave a bound unset fail the test.
func StartPebble(t testing.TB, settings *PebbleSettings) *Pebble {
	t.Helper()
	if settings == nil {
		settings = DefaultPebbleSettings()
	}
	unset := []string{}
	for field, ok := range map[string]bool{
		"TlsServerValidity":     0 < settings.TlsServerValidity,
		"AlternateRootCount":    0 <= settings.AlternateRootCount,
		"ChainLength":           1 <= settings.ChainLength,
		"AuthzRetryAfter":       0 <= settings.AuthzRetryAfter,
		"OrderRetryAfter":       0 <= settings.OrderRetryAfter,
		"DnsTxtTtl":             0 <= settings.DnsTxtTtl,
		"StartTimeout":          0 < settings.StartTimeout,
		"ValidationWaitTimeout": 0 < settings.ValidationWaitTimeout,
		"CloseTimeout":          0 < settings.CloseTimeout,
	} {
		if !ok {
			unset = append(unset, field)
		}
	}
	if 0 < len(unset) {
		slices.Sort(unset)
		t.Fatalf("PebbleSettings leave %v unset or out of range; start from DefaultPebbleSettings", unset)
	}
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", strconv.Itoa(settings.NonceRejectPercent))
	t.Setenv("PEBBLE_AUTHZREUSE", strconv.Itoa(settings.AuthzReusePercent))

	pebble := &Pebble{
		settings:          settings,
		newOrderPath:      "/order-plz",
		memoryStore:       db.NewMemoryStore(),
		validations:       newPebbleValidations(),
		closing:           make(chan struct{}),
		authorizationHeld: make(chan struct{}),
	}
	dnsAddress := settings.DnsAddress
	if dnsAddress == "" {
		pebble.dnsServer = startPebbleDns(t, settings)
		dnsAddress = pebble.dnsServer.address
		pebble.Dns = newFakeCertsDns(pebble.dnsServer)
	}
	logger := log.New(io.Discard, "", 0)
	authority := ca.New(logger, pebble.memoryStore, "", "ecdsa", settings.AlternateRootCount, settings.ChainLength, map[string]ca.Profile{
		PebbleProfileTlsServer: {Description: "45 days, as LE's tlsserver", ValidityPeriod: uint64(settings.TlsServerValidity.Seconds())},
		"default":              {Description: "Pebble's default"},
	})
	// the validation authority's log is read for each challenge it finishes
	validator := va.New(log.New(pebble.validations, "", 0), 0, 0, false, dnsAddress, pebble.memoryStore)
	for keyId, macKey := range settings.EabKeys {
		if err := pebble.memoryStore.AddExternalAccountKeyByID(keyId, macKey); err != nil {
			t.Fatal(err)
		}
	}
	frontEnd := wfe.New(
		logger,
		pebble.memoryStore,
		validator,
		authority,
		[]string{"pebble.example"},
		false,
		settings.RequireEab,
		int(settings.AuthzRetryAfter.Seconds()),
		int(settings.OrderRetryAfter.Seconds()),
	)

	handler := frontEnd.Handler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			if request.URL.Path == pebble.newOrderPath {
				if pebble.refuseOrder(writer) {
					return
				}
				if settings.SortedAuthorizations {
					pebble.serveSortedOrder(handler, writer, request)
					return
				}
			}
			if strings.HasPrefix(request.URL.Path, pebbleAuthzPath) && !pebble.awaitValidations(writer, request) {
				return
			}
		}
		handler.ServeHTTP(writer, request)
	}))
	server.StartTLS()
	t.Cleanup(func() {
		pebble.close(t, server)
	})
	pebble.DirectoryUrl = server.URL + wfe.DirectoryPath
	pebble.HttpClient = server.Client()
	pebble.Roots = x509.NewCertPool()
	pebble.Roots.AddCert(authority.GetRootCert(0).Cert)

	// the directory names newOrder's path; Pebble's own is checked rather than assumed
	ctx, cancel := context.WithTimeout(context.Background(), settings.StartTimeout)
	defer cancel()
	directoryRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, pebble.DirectoryUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := pebble.HttpClient.Do(directoryRequest)
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

// Answers ARI for leaf's certificate (RFC 9773) with the window from start to end from now on, in
// place of the one Pebble computes, as a CA asking for an early renewal does: a window that has begun
// asks its client to renew now.
func (self *Pebble) SetRenewalWindow(leaf []byte, start time.Time, end time.Time) error {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return err
	}
	answer, err := json.Marshal(&core.RenewalInfo{SuggestedWindow: core.SuggestedWindow{Start: start.UTC(), End: end.UTC()}})
	if err != nil {
		return err
	}
	return self.memoryStore.SetARIResponse(certificate.SerialNumber, string(answer))
}

// Refuses the next count newOrder requests with 429 rateLimited and Retry-After, as LE's limits do.
func (self *Pebble) RefuseNewOrders(count int, retryAfter time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuseOrderCount = count
	self.refuseRetryAfter = retryAfter
}

// Holds each lookup the validation authority makes at Pebble's own DNS until release, which the test's
// end calls too; arrived closes at the first lookup held. With AuthorizationHeld, a test has a request
// on an authorization reach the harness while its challenge is under validation. Fails the test for a
// Pebble that asks a resolver of the test's own.
func (self *Pebble) HoldLookups(t testing.TB) (arrived <-chan struct{}, release func()) {
	t.Helper()
	if self.dnsServer == nil {
		t.Fatal("Pebble asks the test's own resolver, whose lookups the test holds itself")
	}
	arrived, release = self.dnsServer.holdLookups()
	t.Cleanup(release)
	return arrived, release
}

// Closes at the first request on an authorization the harness holds for a challenge of it under
// validation (see the file header).
func (self *Pebble) AuthorizationHeld() <-chan struct{} {
	return self.authorizationHeld
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

// Answers newOrder as Pebble does, with the authorizations Pebble lists listed in their names' sorted
// order (PebbleSettings.SortedAuthorizations). Any other answer of Pebble's goes on as it is, and a
// created order whose list cannot be sorted goes on as it is and fails the test.
func (self *Pebble) serveSortedOrder(handler http.Handler, writer http.ResponseWriter, request *http.Request) {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.Bytes()
	if recorder.Code == http.StatusCreated {
		sortedBody, err := func() ([]byte, error) {
			order := map[string]json.RawMessage{}
			if err := json.Unmarshal(body, &order); err != nil {
				return nil, err
			}
			authzUrls := []string{}
			if err := json.Unmarshal(order["authorizations"], &authzUrls); err != nil {
				return nil, err
			}
			authzUrlNames := map[string]string{}
			for _, authzUrl := range authzUrls {
				authz := self.memoryStore.GetAuthorizationByID(path.Base(authzUrl))
				if authz == nil {
					return nil, fmt.Errorf("Pebble holds no authorization at %s", authzUrl)
				}
				authz.RLock()
				authzUrlNames[authzUrl] = authz.Identifier.Value
				authz.RUnlock()
			}
			slices.SortStableFunc(authzUrls, func(a string, b string) int {
				return strings.Compare(authzUrlNames[a], authzUrlNames[b])
			})
			sorted, err := json.Marshal(authzUrls)
			if err != nil {
				return nil, err
			}
			order["authorizations"] = sorted
			return json.Marshal(order)
		}()
		if err == nil {
			body = sortedBody
		} else {
			self.fault(fmt.Sprintf("the harness could not sort newOrder's authorizations: %v", err))
		}
	}
	for key, values := range recorder.Header() {
		writer.Header()[key] = values
	}
	writer.Header().Del("Content-Length")
	writer.WriteHeader(recorder.Code)
	writer.Write(body)
}

// Records what the harness did in Pebble's place, which fails the test at its end.
func (self *Pebble) fault(fault string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.faults = append(self.faults, fault)
}

// Holds a request on an authorization until the validation authority has finished each challenge of it
// under way (see the file header). False when the request was answered here, or its client has gone.
func (self *Pebble) awaitValidations(writer http.ResponseWriter, request *http.Request) bool {
	authz := self.memoryStore.GetAuthorizationByID(strings.TrimPrefix(request.URL.Path, pebbleAuthzPath))
	if authz == nil {
		// Pebble answers it 404
		return true
	}
	// an authorization's challenges are set before it is stored, and its lock orders before theirs
	authz.RLock()
	challenges := slices.Clone(authz.Challenges)
	authz.RUnlock()
	var timeout <-chan time.Time
	for _, challenge := range challenges {
		challenge.RLock()
		challengeId := challenge.ID
		validating := challenge.Status == acme.StatusProcessing
		challenge.RUnlock()
		if !validating {
			continue
		}
		if timeout == nil {
			timeout = time.After(self.settings.ValidationWaitTimeout)
		}
		self.authorizationHeldOnce.Do(func() {
			close(self.authorizationHeld)
		})
		select {
		case <-self.validations.done(challengeId):
		case <-request.Context().Done():
			return false
		case <-self.closing:
			http.Error(writer, "the test has ended", http.StatusServiceUnavailable)
			return false
		case <-timeout:
			fault := fmt.Sprintf(
				"Pebble's validation authority had not finished challenge %s %v after a request on its authorization arrived, which the harness answered 503 rather than let Pebble wedge",
				challengeId,
				self.settings.ValidationWaitTimeout,
			)
			self.fault(fault)
			problem, _ := json.Marshal(map[string]any{
				"type":   "urn:ietf:params:acme:error:serverInternal",
				"detail": fault,
				"status": http.StatusServiceUnavailable,
			})
			writer.Header().Set("Content-Type", "application/problem+json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			writer.Write(problem)
			return false
		}
	}
	return true
}

// Ends Pebble at the test's end: lets every held request go, closes Pebble's connections, and waits
// for its requests to end, failing the test past CloseTimeout with Pebble's goroutines, which will
// never end; then fails it with what the harness did in Pebble's place.
func (self *Pebble) close(t testing.TB, server *httptest.Server) {
	close(self.closing)
	server.CloseClientConnections()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		server.Close()
	}()
	select {
	case <-closed:
	case <-time.After(self.settings.CloseTimeout):
		t.Errorf("Pebble's requests had not ended %v after the test, so Pebble is wedged:\n%s", self.settings.CloseTimeout, pebbleGoroutines())
	}
	faults := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.faults)
	}()
	for _, fault := range faults {
		t.Error(fault)
	}
}

// The stacks of Pebble's goroutines but its validation authorities' idle task loops, one of which every
// Pebble the process started keeps, as Pebble has no way to stop one.
func pebbleGoroutines() string {
	dump := &bytes.Buffer{}
	if err := pprof.Lookup("goroutine").WriteTo(dump, 2); err != nil {
		return err.Error()
	}
	stacks := []string{}
	for _, stack := range strings.Split(dump.String(), "\n\n") {
		if !strings.Contains(stack, "github.com/letsencrypt/pebble/") {
			continue
		}
		lines := strings.SplitN(stack, "\n", 3)
		if 2 <= len(lines) && strings.HasPrefix(lines[1], "github.com/letsencrypt/pebble/v2/va.VAImpl.processTasks(") {
			continue
		}
		stacks = append(stacks, stack)
	}
	return strings.Join(stacks, "\n\n")
}

// The challenges Pebble's validation authority has finished, read from its log, which is the only
// thing of Pebble's that tells when. Safe for concurrent use.
type pebbleValidations struct {
	stateLock sync.Mutex
	// closed once the validation authority has set the challenge valid or invalid, by challenge id
	challengeIdDones map[string]chan struct{}
}

func newPebbleValidations() *pebbleValidations {
	return &pebbleValidations{challengeIdDones: map[string]chan struct{}{}}
}

// One line of the validation authority's log; log.Logger writes each line whole.
func (self *pebbleValidations) Write(line []byte) (int, error) {
	before, challengeId, found := strings.Cut(strings.TrimSpace(string(line)), pebbleValidationDoneMarker)
	if found && strings.HasPrefix(before, "authz ") && challengeId != "" {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		done := self.doneWithLock(challengeId)
		select {
		case <-done:
		default:
			close(done)
		}
	}
	return len(line), nil
}

// Closes once the validation authority has finished challengeId.
func (self *pebbleValidations) done(challengeId string) <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.doneWithLock(challengeId)
}

func (self *pebbleValidations) doneWithLock(challengeId string) chan struct{} {
	done, ok := self.challengeIdDones[challengeId]
	if !ok {
		done = make(chan struct{})
		self.challengeIdDones[challengeId] = done
	}
	return done
}

// The DNS server Pebble's validation authority asks, over TCP, as Pebble's VA does: TXT records by name,
// NOERROR with no answer for anything else. A test may hold its lookups (Pebble.HoldLookups).
type pebbleDns struct {
	address string
	// each record's TTL, in seconds
	txtTtl uint32

	stateLock sync.Mutex
	nameTxts  map[string][]string
	// while a test holds lookups, closed to let them go; nil while none does
	lookupRelease chan struct{}
	// closed at the first lookup held
	lookupArrived chan struct{}
}

func startPebbleDns(t testing.TB, settings *PebbleSettings) *pebbleDns {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	self := &pebbleDns{
		address:  listener.Addr().String(),
		txtTtl:   uint32(settings.DnsTxtTtl.Seconds()),
		nameTxts: map[string][]string{},
	}
	started := make(chan struct{})
	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler:  dns.HandlerFunc(self.serve),
		NotifyStartedFunc: func() {
			close(started)
		},
	}
	served := make(chan error, 1)
	go func() {
		served <- server.ActivateAndServe()
	}()
	// a server that has not started takes no shutdown, and would serve on past the test
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("Pebble's DNS server: %v", err)
	case <-time.After(settings.StartTimeout):
		t.Fatalf("Pebble's DNS server had not started after %v", settings.StartTimeout)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), settings.CloseTimeout)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Errorf("Pebble's DNS server had not stopped %v after the test: %v", settings.CloseTimeout, err)
		}
	})
	return self
}

func (self *pebbleDns) serve(writer dns.ResponseWriter, request *dns.Msg) {
	if release := self.arrive(); release != nil {
		<-release
	}
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
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: self.txtTtl},
				Txt: []string{txt},
			})
		}
	}
	writer.WriteMsg(reply)
}

// Holds lookups from now on: see Pebble.HoldLookups. release may be called more than once.
func (self *pebbleDns) holdLookups() (arrived <-chan struct{}, release func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lookupRelease := make(chan struct{})
	lookupArrived := make(chan struct{})
	self.lookupRelease = lookupRelease
	self.lookupArrived = lookupArrived
	return lookupArrived, sync.OnceFunc(func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		close(lookupRelease)
		if self.lookupRelease == lookupRelease {
			self.lookupRelease = nil
			self.lookupArrived = nil
		}
	})
}

// What a lookup waits on before it is answered, nil when none is held.
func (self *pebbleDns) arrive() chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lookupRelease == nil {
		return nil
	}
	select {
	case <-self.lookupArrived:
	default:
		close(self.lookupArrived)
	}
	return self.lookupRelease
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
