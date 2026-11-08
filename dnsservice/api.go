// The dns API block (§12.8, §19.4): server/cli/dns's api role, serving the routes the dns edges, the
// monitors, certs and lbmap call. This draft serves the feed (api_feed.go) and GET ready
// (api_ready.go); the record, challenge, canary, custom-host and key routes join the same table from
// their own tasks.
//
// Every route here is internal, under /dns/internal/ (plan-DNS-internal-route-credential, decided by
// the owner, over §12.8's /dns/journal and the rest), where the lb answers 403 unless the source is on
// the service's allow list (W8). Each route takes one caller class, by a bearer DnsInternalAuth
// verifies, and a host with no verifier configured refuses every internal route with 403, so nothing is
// exposed while the vault entries wait. Then §19.11's dns gate: disabled, every route answers 503 with
// Retry-After and the block stays ready; writes: false, the incident switch, refuses the routes that
// change zone data.
//
// The block reaches §12.14's tables only through DnsStore, and holds no lock across its I/O. Safe for
// concurrent use.

package dnsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"gopkg.in/yaml.v3"
)

var _ sidecar.HttpEngine = (*DnsApi)(nil)

// The internal routes (§12.8 under plan-DNS-internal-route-credential's prefix).
const (
	DnsInternalPathPrefix = "/dns/internal/"
	DnsJournalPath        = DnsInternalPathPrefix + "journal"
	DnsSnapshotPath       = DnsInternalPathPrefix + "snapshot"
	DnsReloadDiffPath     = DnsInternalPathPrefix + "reload-diff"
	DnsReadyPath          = DnsInternalPathPrefix + "ready"
)

// The lb's proxy_read_timeout on the block (warp's config), which every long-poll stays under.
const dnsLbProxyReadTimeoutSeconds = 30

// RFC 4648 §5 with no padding: how a 256-bit bearer is written.
var dnsCredentialEncoding = base64.RawURLEncoding

// A bearer's raw length: 256 random bits (plan-DNS-internal-route-credential).
const dnsCredentialByteCount = 32

// Who may call an internal route, by the bearer it carries (plan-DNS-internal-route-credential,
// plan-TLS-internal-credentials). Each route takes exactly one.
type DnsCallerClass string

const (
	// ns1 and ns2: journal, snapshot, reload-diff and route-probes.
	DnsCallerEdge DnsCallerClass = "dnsedge"
	// the site's monitor: canary and canary-report.
	DnsCallerMonitor DnsCallerClass = "monitor"
	// the off-site monitor: canary-report alone.
	DnsCallerMonitorOutside DnsCallerClass = "monitor_outside"
	// certs in taskworker: acme-challenge, caa-canary and ready.
	DnsCallerCerts DnsCallerClass = "certs"
	// each lb interface's lbmap: custom-host-map and its applied route.
	DnsCallerLbmap DnsCallerClass = "lbmap"
)

// Whether a class is one this release knows.
func (self DnsCallerClass) known() bool {
	switch self {
	case DnsCallerEdge, DnsCallerMonitor, DnsCallerMonitorOutside, DnsCallerCerts, DnsCallerLbmap:
		return true
	}
	return false
}

// Checks an internal route's credential. Safe for concurrent use; no I/O.
type DnsInternalAuth interface {
	// The class whose bearer request carries, or false for none or one it does not know.
	Authenticate(request *http.Request) (class DnsCallerClass, ok bool)
}

// A credential file or verify file that cannot be used. The text names the part, never a bearer.
var ErrDnsCredentialRefused = errors.New("dns internal credential refused")

// One caller's entry in internal-verify.yml.
type dnsVerifyEntryYaml struct {
	Class  string   `yaml:"class"`
	Sha256 []string `yaml:"sha256"`
}

// One digest a bearer may hash to, and its class.
type dnsVerifyDigest struct {
	class  DnsCallerClass
	digest [sha256.Size]byte
}

// The block's view of internal-verify.yml: SHA-256 digests only, never a bearer.
type dnsInternalVerifier struct {
	digests []dnsVerifyDigest
}

// Reads internal-verify.yml from the block's secret_files: a map of caller name to its class and the
// SHA-256, in hex, of each bearer it may send, its current and its previous during a rotation:
//
//	dnsedge-1: {class: dnsedge, sha256: [<hex>, <hex>]}
//
// The form is this draft's reading of plan-DNS-internal-route-credential, which names the file and
// what it holds but not its layout.
func NewDnsInternalVerifier(data []byte) (DnsInternalAuth, error) {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: internal-verify.yml: %s", ErrDnsCredentialRefused, fmt.Sprintf(format, arguments...))
	}
	entries := map[string]dnsVerifyEntryYaml{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&entries); err != nil {
		return nil, refuse("%v", err)
	}
	self := &dnsInternalVerifier{}
	for caller, entry := range entries {
		class := DnsCallerClass(entry.Class)
		if !class.known() {
			return nil, refuse("%s names no class", caller)
		}
		if len(entry.Sha256) == 0 {
			return nil, refuse("%s holds no digest", caller)
		}
		for _, text := range entry.Sha256 {
			digest, err := hex.DecodeString(text)
			if err != nil || len(digest) != sha256.Size {
				return nil, refuse("%s holds a digest that is not SHA-256 in hex", caller)
			}
			self.digests = append(self.digests, dnsVerifyDigest{class: class, digest: [sha256.Size]byte(digest)})
		}
	}
	if len(self.digests) == 0 {
		return nil, refuse("no caller")
	}
	return self, nil
}

// Hashes the bearer and compares it with every digest in constant time, with no early exit, so the
// time taken says nothing of which caller, if any, it matched.
func (self *dnsInternalVerifier) Authenticate(request *http.Request) (DnsCallerClass, bool) {
	bearer, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte(bearer))
	var class DnsCallerClass
	matched := 0
	for index := range self.digests {
		if subtle.ConstantTimeCompare(digest[:], self.digests[index].digest[:]) == 1 {
			class = self.digests[index].class
			matched = 1
		}
	}
	return class, matched == 1
}

// One caller's credential file (internal-dnsedge-1.yml and the rest): its current bearer and, during a
// rotation, the previous one, each 256 bits in unpadded base64url.
type dnsCredentialYaml struct {
	Current  string `yaml:"current"`
	Previous string `yaml:"previous"`
}

// Reads a caller's credential file from its secret_files and returns the bearer it sends: current. The
// bearer goes to the privacy harness the moment it is read (§22.7).
func LoadDnsInternalCredential(data []byte) (string, error) {
	credential := &dnsCredentialYaml{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(credential); err != nil {
		return "", fmt.Errorf("%w: credential file: %v", ErrDnsCredentialRefused, err)
	}
	for _, bearer := range []string{credential.Current, credential.Previous} {
		if bearer == "" {
			continue
		}
		raw, err := dnsCredentialEncoding.DecodeString(bearer)
		testHookSecret("dns_internal_credential", []byte(bearer))
		if err != nil || len(raw) != dnsCredentialByteCount {
			return "", fmt.Errorf("%w: a bearer that is not 256 bits in base64url", ErrDnsCredentialRefused)
		}
	}
	if credential.Current == "" {
		return "", fmt.Errorf("%w: no current bearer", ErrDnsCredentialRefused)
	}
	return credential.Current, nil
}

// What the block takes beyond its host, settings and store. Each seam that is nil fails closed.
type DnsApiDeps struct {
	// The internal routes' bearer check. nil refuses every internal route with 403.
	Auth DnsInternalAuth
	// The lb inventory every feed answer names (reading 6: server.ParseServicesLbInventory over the
	// mounted services.yml). nil names none, and an edge then answers edge rows from no address.
	Interfaces func() []DnsLbInterface
	// The DNSKEY window released for root at now (DNS-M5-19's KeyWindowRelease). nil names none, so an
	// edge with no window of its own serves nothing.
	KeyWindow func(root string, now time.Time) *DnsKeyWindow
	// dns_ns's stopped NS and dns_canary_verdict's rows for GET ready. nil reads every NS dns.yml lists
	// as running and every verdict as missing, so ready answers canary_failing: both the closed
	// direction (plan-DNS-running-ns, plan-DNS-canary-route-state).
	ReadyStore DnsReadyStore
	// Reads an NS's SOA over TCP for GET ready. nil reads every NS as not answering, so ready holds and
	// answers waiting.
	SoaReader DnsSoaReader
	// Lifecycle only. nil discards.
	Log sidecar.Logger
}

// One internal route: its method, path, the one class it takes, whether it changes zone data, and its
// handler.
type dnsApiRoute struct {
	method string
	path   string
	class  DnsCallerClass
	write  bool
	serve  func(writer http.ResponseWriter, request *http.Request)
}

// The block. Safe for concurrent use.
type DnsApi struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	settings *DnsSettings
	store    DnsStore
	deps     *DnsApiDeps
	clock    sidecar.Clock
	log      sidecar.Logger
	metrics  *dnsApiMetrics
	handler  http.Handler
	soa      *dnsSoaPoller
	// Whether every root's dns_root row was read at the last probe.
	storesReachable *sidecar.MonitorValue[bool]
	// Probes finished, each counted once the wait for the next is armed.
	probeCount *sidecar.MonitorValue[int]
	// Long-polls in flight, for Drain.
	holdCount *sidecar.MonitorValue[int]
	// Long-polls parked in their wait, with nothing in hand: what a test reads before it moves a fake
	// clock, so time moves only while every hold waits on it.
	parkedCount *sidecar.MonitorValue[int]
	// Closed at Drain: every hold answers with what is there.
	draining     chan struct{}
	drainingOnce sync.Once
}

// Starts the block, not ready until a probe has read every root's dns_root row, adding one at serial
// zero where none is. host needs Metrics; its Gates are §19.11's and its Clock every wait's. It runs
// until ctx ends or Close.
func NewDnsApi(ctx context.Context, host *sidecar.ServiceHost, settings *DnsSettings, store DnsStore, deps *DnsApiDeps) (*DnsApi, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("dns api needs a host with Metrics")
	}
	if store == nil {
		return nil, errors.New("dns api needs a store")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &DnsApiDeps{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	self := &DnsApi{
		ctx:             cancelCtx,
		cancel:          cancel,
		host:            host,
		settings:        settings,
		store:           store,
		deps:            deps,
		clock:           clock,
		log:             log,
		metrics:         newDnsApiMetrics(host.Metrics),
		storesReachable: sidecar.NewMonitorValue(false),
		probeCount:      sidecar.NewMonitorValue(0),
		holdCount:       sidecar.NewMonitorValue(0),
		parkedCount:     sidecar.NewMonitorValue(0),
		draining:        make(chan struct{}),
	}
	self.soa = newDnsSoaPoller(cancelCtx, clock, deps.SoaReader, settings, self.metrics)
	mux := http.NewServeMux()
	for _, route := range self.routes() {
		mux.HandleFunc(route.method+" "+route.path, self.guard(route))
	}
	self.handler = mux
	go self.run()
	return self, nil
}

// Every route the block serves. A later task adds its own list here.
func (self *DnsApi) routes() []*dnsApiRoute {
	return append(self.feedRoutes(), self.readyRoutes()...)
}

// The handler every route runs behind: the bearer's class, then the gate.
func (self *DnsApi) guard(route *dnsApiRoute) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if self.deps.Auth == nil {
			self.metrics.refused.Add(1, dnsApiRefusedNoVerifier)
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		class, ok := self.deps.Auth.Authenticate(request)
		if !ok || class != route.class {
			self.metrics.refused.Add(1, dnsApiRefusedCredential)
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		gates := self.host.GatesOrClosed()
		gate := gates.Service(sidecar.ServiceGateDns)
		if !gate.Enabled() || (route.write && !gate.Writes()) {
			self.metrics.refused.Add(1, dnsApiRefusedGate)
			retryAfter := int(math.Ceil(gates.RetryAfter().Seconds()))
			writer.Header().Set("Retry-After", strconv.Itoa(max(retryAfter, 1)))
			http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		route.serve(writer, request)
	}
}

// One handler for every route.
func (self *DnsApi) Handler() http.Handler {
	return self.handler
}

// Whether every root's dns_root row read at the last probe. The gate does not touch this: a closed
// gate answers 503 and the block stays ready (§19.11).
func (self *DnsApi) Ready() bool {
	return self.storesReachable.Value()
}

// Probes the store until the block ends.
func (self *DnsApi) run() {
	for {
		reachable := true
		for _, root := range self.settings.Roots {
			err := func() error {
				ctx, cancel := context.WithCancel(self.ctx)
				defer cancel()
				stop := self.clock.AfterFunc(dnsSeconds(self.settings.Api.StoreTimeoutSeconds), cancel)
				defer stop()
				if err := self.store.EnsureRoot(ctx, root); err != nil {
					return err
				}
				_, err := self.store.RootState(ctx, root)
				return err
			}()
			if err != nil {
				reachable = false
			}
		}
		self.storesReachable.Set(reachable)
		next := self.clock.After(dnsSeconds(self.settings.Api.StoreProbeSeconds))
		self.probeCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-next:
		}
	}
}

// Probes finished, and a channel that closes at the next.
func (self *DnsApi) Probes() (count int, changed chan struct{}) {
	return self.probeCount.Get()
}

// Marks one long-poll in flight until done is called.
func (self *DnsApi) holdStarted() (done func()) {
	self.holdCount.Update(func(count int) int { return count + 1 })
	return func() {
		self.holdCount.Update(func(count int) int { return count - 1 })
	}
}

// Runs wait, counted as parked while it runs.
func (self *DnsApi) park(wait func() bool) bool {
	self.parkedCount.Update(func(count int) int { return count + 1 })
	defer self.parkedCount.Update(func(count int) int { return count - 1 })
	return wait()
}

// Ends every hold with what is there now, so edges and certs reconnect to another block, then returns
// once none is in flight or api.drain_s has passed.
func (self *DnsApi) Drain() {
	self.drainingOnce.Do(func() { close(self.draining) })
	deadline := self.clock.After(dnsSeconds(self.settings.Api.DrainSeconds))
	for {
		count, changed := self.holdCount.Get()
		if count == 0 {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// Ends the probe loop and every hold at once. Safe more than once.
func (self *DnsApi) Close() {
	self.cancel()
}

// The root a request names in root=, or false. With one root configured, root= may be left out.
func (self *DnsApi) requestRoot(request *http.Request) (string, bool) {
	text := request.URL.Query().Get("root")
	if text == "" {
		if len(self.settings.Roots) == 1 {
			return self.settings.Roots[0], true
		}
		return "", false
	}
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	text = strings.ToLower(text)
	for _, root := range self.settings.Roots {
		if root == text {
			return root, true
		}
	}
	return "", false
}

// The labels of the block's refusal counter.
const (
	dnsApiRefusedNoVerifier = "no_verifier"
	dnsApiRefusedCredential = "credential"
	dnsApiRefusedGate       = "gate"
)

// urnetwork_dns_*: what the block counts beside the host's route metrics. Labels from closed sets only.
type dnsApiMetrics struct {
	// Requests refused before their route ran, by reason.
	refused sidecar.MetricsCounter
	// Long-polls answered, by route and how each ended: rows or a reload, an empty hold, or waiting.
	holds sidecar.MetricsCounter
	// SOA reads of an NS, by result.
	soaReads sidecar.MetricsCounter
}

func newDnsApiMetrics(metrics sidecar.Metrics) *dnsApiMetrics {
	return &dnsApiMetrics{
		refused:  metrics.Counter("urnetwork_dns_internal_refused_total", "Internal requests refused before their route, by reason.", "reason"),
		holds:    metrics.Counter("urnetwork_dns_holds_total", "Long-polls answered, by route and end.", "route", "result"),
		soaReads: metrics.Counter("urnetwork_dns_soa_reads_total", "SOA reads of an NS, by result.", "result"),
	}
}
