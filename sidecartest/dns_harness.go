// §12's serving path in one process (§12.6, §22.4, R-DNS-1, D-DNS-3), for T2 and, given dnshost.Store,
// T3: an API block and one edge for each NS dns.yml lists, each a process of a Net, added through
// Net.AddEngine on the host AddEngines gave it, so a test or a schedule kills and restarts them as it
// does any engine.
//
//   - The block serves its internal routes over a DnsStore: a FakeDnsStore on the Net's clock and fault
//     queue unless the settings give another.
//   - Each edge follows the block through DnsFeed's own HTTP client, with the bearer its credential
//     file holds, over a transport that runs each request on a goroutine of the block's, so a store
//     call is the block's own and a dead block's goroutines park as a dead process's do. It signs with
//     keys made here, keeps its local snapshot in a directory of its own, and probes fake lb
//     interfaces that answer tlsedge's alert until a test fails or drains one.
//   - A query reaches an edge over in-memory TCP or UDP, through the edge's own Serve and ServePacket,
//     so it meets the edge's admission, RRL and signing as a resolver's would. Resolver gives TLS's and
//     MAIL's T2 tests a net.Resolver that resolves <net>.<root> names the same way.
//
// Nothing listens on a socket, and the keys, bearers, store, gates and metrics are each harness's own,
// so two harnesses on one Net share only what the Net is: its clock, fault queue and privacy capture.
// Every process runs on the Net's clock whatever host AddEngines gave, since probe rounds move with it.
//
// The record API, §12.7's system records and certs' routes are other tasks' (DNS-M5-11 to DNS-M5-13).
// Until they land, Write is model code's one write path, DnsStore.Write, and ApexRows and NetworkRows
// are fixtures for a test's names to resolve, not §12.7's set.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

var (
	// The process a call needs is not running: killed, or never started.
	ErrDnsHarnessDown = errors.New("dns harness process not running")
	// An edge took a query and gave no answer: a root not ready, or RRL dropping it.
	ErrDnsHarnessNoAnswer = errors.New("dns harness edge gave no answer")
	// Settings the harness cannot run.
	ErrDnsHarnessSettings = errors.New("dns harness settings refused")
)

// tlsedge's answer to a probe: a plaintext TLS alert record, fatal, unrecognized_name (RFC 8446 §6),
// which is what every hello to a fake interface that answers gets.
var dnsHarnessTlsedgeAlert = []byte{21, 3, 3, 0, 2, 2, 112}

// A TLS record's header: type, version, then a two-byte length (RFC 8446 §5.1).
const dnsHarnessTlsRecordHeaderByteCount = 5

// A harness's name, which prefixes its processes and names its block's host: a DNS label's shape.
var dnsHarnessNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// A bearer's raw length: 256 random bits (plan-DNS-internal-route-credential).
const dnsHarnessBearerByteCount = 32

// The apex SOA's RDATA for a root: its first NS as MNAME, hostmaster as RNAME, then serial, refresh,
// retry, expire and minimum. The edge answers the root's serial in place of the 1, and a fixture's
// timers mean nothing to a zone signed online with no secondaries.
const dnsHarnessSoaFormat = "%s.%s hostmaster.%s 1 7200 3600 1209600 %d"

type DnsHarnessSettings struct {
	// Each process is <Name>-api or <Name>-<ns>, so two harnesses on one Net need two names.
	Name string
	// dns.yml as the block and every edge read it. Its ns list names the edges, one process each.
	// edge.udp_readers must be 1, so a UDP query's drop is known when the edge's reader reads again.
	Dns *dnsservice.DnsSettings
	// The lb inventory every feed answer names: one fake interface each, answering tlsedge's alert
	// on every port until failed.
	Interfaces []dnsservice.DnsLbInterface
	// Each edge's local snapshot sits in a directory of its own below this one. Required. An edge
	// writes there until it stops, so the directory goes only after Close: a test passes t.TempDir()
	// and then registers t.Cleanup(harness.Close), which runs first.
	Directory string
	// The block's store. nil makes a FakeDnsStore on the Net's clock and fault queue; T3 passes
	// dnshost.Store.
	Store dnsservice.DnsStore
	// Writes ApexRows to each root still at serial zero at the start, so every edge has an apex to
	// serve and self-check.
	SeedApex bool
	// How the stand-in for DNS-M5-19's released windows makes them.
	Keys DnsHarnessKeySettings
}

// The DNSKEY windows the block's feed names, standing in for DNS-M5-19's release: each signed by this
// harness's KSK over the KSK and ZSK, released one after another so a fake clock may run for weeks.
type DnsHarnessKeySettings struct {
	// How long a window's KSK signatures last: §12.6's 14 days.
	WindowDuration time.Duration
	// How far apart windows start, less than WindowDuration so a newer one is current before the
	// last expires.
	WindowStep time.Duration
	// How far before its step a window starts, so one released at its step is already valid.
	WindowLead time.Duration
	// The DNSKEY RRset's TTL in seconds, which the KSK's signature covers.
	DnskeyTtl uint32
}

// One root, harness.example., two NS, three interfaces of documentation addresses, lb-2 and lb-3 on
// the router list, and limits raised past anything a test reaches, since a test's fake clock may
// stand still for a thousand queries.
func DefaultDnsHarnessSettings() *DnsHarnessSettings {
	dnsSettings := dnsservice.DefaultDnsSettings()
	dnsSettings.Roots = []string{"harness.example."}
	dnsSettings.SignaturesPerSecond = 1000 * 1000
	dnsSettings.Tcp.ConnectionsPerSource = 1024
	dnsSettings.Rrl.ResponsesPerSecond = 1000 * 1000
	dnsSettings.Edge.UdpReaderCount = 1
	return &DnsHarnessSettings{
		Name: "dns",
		Dns:  dnsSettings,
		Interfaces: []dnsservice.DnsLbInterface{
			{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1"), Ipv6: netip.MustParseAddr("2001:db8::1")},
			{Name: "lb-2", Ipv4: netip.MustParseAddr("192.0.2.2"), Ipv6: netip.MustParseAddr("2001:db8::2"), Router: true},
			{Name: "lb-3", Ipv4: netip.MustParseAddr("192.0.2.3"), Ipv6: netip.MustParseAddr("2001:db8::3"), Router: true},
		},
		SeedApex: true,
		Keys: DnsHarnessKeySettings{
			WindowDuration: 14 * 24 * time.Hour,
			WindowStep:     7 * 24 * time.Hour,
			WindowLead:     24 * time.Hour,
			DnskeyTtl:      3600,
		},
	}
}

// One running block.
type dnsHarnessApi struct {
	ctx     context.Context
	api     *dnsservice.DnsApi
	metrics *FakeMetrics
}

// One running edge: the dnsedge role's three parts, as server/cli/dns runs them on one host, with its
// TCP 53 in memory. As an Engine it is the role's whole lifecycle.
type dnsHarnessEdge struct {
	ns       string
	ctx      context.Context
	edge     *dnsservice.DnsEdge
	loop     *dnsservice.FeedLoop
	prober   *dnsservice.Prober
	listener *dnsHarnessListener
	metrics  *FakeMetrics
	serving  sync.WaitGroup
}

func (self *dnsHarnessEdge) Ready() bool {
	return self.edge.Ready()
}

func (self *dnsHarnessEdge) Drain() {
	self.edge.Drain()
}

// Stops the feed first, which writes the local snapshot, then the prober and the edge.
func (self *dnsHarnessEdge) Close() {
	self.loop.Close()
	self.prober.Close()
	self.edge.Close()
	self.listener.Close()
	self.serving.Wait()
}

// The harness. See the file header.
type DnsHarness struct {
	net         *Net
	clock       *FakeClock
	settings    *DnsHarnessSettings
	dnsSettings *dnsservice.DnsSettings
	store       dnsservice.DnsStore
	fakeStore   *FakeDnsStore
	gates       *FakeServiceGates
	readyStore  *dnsHarnessReadyStore
	transport   *dnsHarnessTransport
	keys        *dnsHarnessKeys
	// What the block and the edges hold of plan-DNS-internal-route-credential's files.
	verifier     dnsservice.DnsInternalAuth
	classBearers map[dnsservice.DnsCallerClass]string
	// Where the edges' feed client sends requests; the transport ignores the host.
	apiUrl string
	// Each query's source port, so in-memory connections are told apart in a trace.
	sourcePort atomic.Uint32
	// Bumped at each start and end of a process, so a wait reads again.
	instances *sidecar.MonitorValue[uint64]

	stateLock      sync.Mutex
	api            *dnsHarnessApi
	nsEdges        map[string]*dnsHarnessEdge
	interfaces     []dnsservice.DnsLbInterface
	failedNames    map[string]bool
	requireReloads map[string]bool
	// Set by Close: nothing here runs any more.
	closed bool

	// Held across rendering sidecar.yml and setting it, so two changes land in the order made.
	gatesLock    sync.Mutex
	gateEnabled  bool
	gateWrites   bool
	drainedNames []string
}

// Starts the block and every edge on net, and returns once each edge serves every root at the
// serial its store holds. ctx bounds only that wait; the processes live as long as net does, or until
// killed.
func NewDnsHarness(ctx context.Context, net *Net, settings *DnsHarnessSettings) (*DnsHarness, error) {
	if net == nil || settings == nil || settings.Dns == nil {
		return nil, fmt.Errorf("%w: a harness needs a net and settings", ErrDnsHarnessSettings)
	}
	if err := validateDnsHarnessSettings(net, settings); err != nil {
		return nil, err
	}
	keys, err := newDnsHarnessKeys(net, settings)
	if err != nil {
		return nil, err
	}
	self := &DnsHarness{
		net:            net,
		clock:          net.Clock(),
		settings:       settings,
		dnsSettings:    settings.Dns,
		store:          settings.Store,
		gates:          NewFakeServiceGates(nil),
		readyStore:     newDnsHarnessReadyStore(),
		keys:           keys,
		classBearers:   map[dnsservice.DnsCallerClass]string{},
		apiUrl:         "http://" + settings.Name + "-api.invalid",
		instances:      sidecar.NewMonitorValue[uint64](0),
		nsEdges:        map[string]*dnsHarnessEdge{},
		interfaces:     slices.Clone(settings.Interfaces),
		failedNames:    map[string]bool{},
		requireReloads: map[string]bool{},
		gateEnabled:    true,
		gateWrites:     true,
	}
	self.transport = &dnsHarnessTransport{harness: self}
	if self.store == nil {
		self.fakeStore = NewFakeDnsStore(net.Clock(), net.Faults())
		self.store = self.fakeStore
	}
	if err := self.makeCredentials(); err != nil {
		return nil, err
	}
	if err := self.applyGates(); err != nil {
		return nil, err
	}
	rootSerials := map[string]uint64{}
	for _, root := range self.dnsSettings.Roots {
		serial, err := self.seed(ctx, root)
		if err != nil {
			return nil, err
		}
		rootSerials[root] = serial
	}
	if err := self.start(ctx, rootSerials); err != nil {
		// what started stops, so a caller's directory can go
		self.Close()
		return nil, err
	}
	return self, nil
}

// Adds the block, waits for it to read its store, adds the edges, and waits for each to serve every
// root at the serial its store held.
func (self *DnsHarness) start(ctx context.Context, rootSerials map[string]uint64) error {
	if _, err := self.net.AddEngine(self.ApiProcess(), self.buildApi); err != nil {
		return err
	}
	if err := self.awaitApiReady(ctx); err != nil {
		return err
	}
	for _, ns := range self.dnsSettings.Ns {
		if _, err := self.net.AddEngine(self.EdgeProcess(ns), func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
			return self.buildEdge(ctx, ns, host)
		}); err != nil {
			return err
		}
	}
	for root, serial := range rootSerials {
		if err := self.AwaitServed(ctx, root, serial); err != nil {
			return err
		}
	}
	return nil
}

// What NewDnsHarness refuses before it starts anything.
func validateDnsHarnessSettings(net *Net, settings *DnsHarnessSettings) error {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsHarnessSettings, fmt.Sprintf(format, arguments...))
	}
	if !dnsHarnessNamePattern.MatchString(settings.Name) {
		return refuse("name %q is not lowercase letters, digits and inner hyphens", settings.Name)
	}
	if settings.Directory == "" {
		return refuse("no directory for the edges' snapshots")
	}
	if err := settings.Dns.Validate(); err != nil {
		return err
	}
	if settings.Dns.Edge.UdpReaderCount != 1 {
		return refuse("edge.udp_readers is %d, not 1", settings.Dns.Edge.UdpReaderCount)
	}
	keys := &settings.Keys
	if keys.WindowStep <= 0 || keys.WindowLead < 0 || keys.WindowDuration <= keys.WindowStep+keys.WindowLead || keys.DnskeyTtl == 0 {
		return refuse("key windows that leave a gap: %+v", *keys)
	}
	if err := validateDnsHarnessInterfaces(settings.Interfaces); err != nil {
		return err
	}
	processNames := []string{settings.Name + "-api"}
	for _, ns := range settings.Dns.Ns {
		processNames = append(processNames, settings.Name+"-"+ns)
	}
	for _, processName := range processNames {
		if net.Actors().Lookup(processName) != nil {
			return refuse("process %s is already on this net", processName)
		}
	}
	return nil
}

// Every interface named, and each name once.
func validateDnsHarnessInterfaces(interfaces []dnsservice.DnsLbInterface) error {
	names := map[string]bool{}
	for index := range interfaces {
		name := interfaces[index].Name
		if name == "" || names[name] {
			return fmt.Errorf("%w: interface %q is unnamed or named twice", ErrDnsHarnessSettings, name)
		}
		names[name] = true
	}
	return nil
}

// Makes a bearer for each class the harness calls as, through LoadDnsInternalCredential, so each goes
// to the privacy capture as a real credential file's does, and the block's verifier of their digests.
func (self *DnsHarness) makeCredentials() error {
	type verifyEntry struct {
		Class  string   `yaml:"class"`
		Sha256 []string `yaml:"sha256"`
	}
	entries := map[string]verifyEntry{}
	for _, class := range []dnsservice.DnsCallerClass{dnsservice.DnsCallerEdge, dnsservice.DnsCallerCerts} {
		raw := make([]byte, dnsHarnessBearerByteCount)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		credentialFile, err := yaml.Marshal(map[string]string{"current": base64.RawURLEncoding.EncodeToString(raw)})
		if err != nil {
			return err
		}
		bearer, err := dnsservice.LoadDnsInternalCredential(credentialFile)
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(bearer))
		entries[string(class)+"-1"] = verifyEntry{Class: string(class), Sha256: []string{hex.EncodeToString(digest[:])}}
		self.classBearers[class] = bearer
	}
	verifyFile, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	verifier, err := dnsservice.NewDnsInternalVerifier(verifyFile)
	if err != nil {
		return err
	}
	self.verifier = verifier
	return nil
}

// Ensures root's row, and writes the apex to a root at serial zero when the settings ask. Returns the
// serial the edges must reach.
func (self *DnsHarness) seed(ctx context.Context, root string) (uint64, error) {
	if err := self.store.EnsureRoot(ctx, root); err != nil {
		return 0, err
	}
	state, err := self.store.RootState(ctx, root)
	if err != nil {
		return 0, err
	}
	if state.Serial != 0 || !self.settings.SeedApex {
		return state.Serial, nil
	}
	return self.store.Write(ctx, &dnsservice.DnsZoneWrite{Root: root, Upserts: self.ApexRows(root)})
}

// The process name of the block on the Net.
func (self *DnsHarness) ApiProcess() string {
	return self.settings.Name + "-api"
}

// The process name of the edge for ns, one of dns.yml's ns labels.
func (self *DnsHarness) EdgeProcess(ns string) string {
	return self.settings.Name + "-" + ns
}

// dns.yml as every process reads it. Read only.
func (self *DnsHarness) Settings() *dnsservice.DnsSettings {
	return self.dnsSettings
}

// The first root dns.yml lists.
func (self *DnsHarness) Root() string {
	return self.dnsSettings.Roots[0]
}

// The block's store.
func (self *DnsHarness) Store() dnsservice.DnsStore {
	return self.store
}

// The block's store as the fake the harness made, or nil when the settings gave one, as T3 does.
func (self *DnsHarness) FakeStore() *FakeDnsStore {
	return self.fakeStore
}

// sidecar.yml as every process here reads it: the dns gate and the drained list. A test changes them
// through SetDnsGate and DrainInterface, which own the file's text.
func (self *DnsHarness) Gates() *FakeServiceGates {
	return self.gates
}

// The bearer this harness sends as class: dnsedge or certs. A test calling the block as certs sends it
// over ApiTransport.
func (self *DnsHarness) Bearer(class dnsservice.DnsCallerClass) string {
	return self.classBearers[class]
}

// A transport to the running block's handler, whatever host a request names.
func (self *DnsHarness) ApiTransport() http.RoundTripper {
	return self.transport
}

// The running block, or nil.
func (self *DnsHarness) Api() *dnsservice.DnsApi {
	if block := self.runningApi(); block != nil {
		return block.api
	}
	return nil
}

// The running block's metrics, or nil.
func (self *DnsHarness) ApiMetrics() *FakeMetrics {
	if block := self.runningApi(); block != nil {
		return block.metrics
	}
	return nil
}

// The running edge for ns, or nil.
func (self *DnsHarness) Edge(ns string) *dnsservice.DnsEdge {
	if edge := self.runningEdge(ns); edge != nil {
		return edge.edge
	}
	return nil
}

// The running edge's metrics for ns, or nil.
func (self *DnsHarness) EdgeMetrics(ns string) *FakeMetrics {
	if edge := self.runningEdge(ns); edge != nil {
		return edge.metrics
	}
	return nil
}

func (self *DnsHarness) runningApi() *dnsHarnessApi {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.api == nil || self.api.ctx.Err() != nil {
		return nil
	}
	return self.api
}

func (self *DnsHarness) runningEdge(ns string) *dnsHarnessEdge {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	edge := self.nsEdges[ns]
	if self.closed || edge == nil || edge.ctx.Err() != nil {
		return nil
	}
	return edge
}

// Closes every running process here, the edges first, so each writes its local snapshot and stops
// writing, then the block, and returns once each has stopped: what a test runs before Directory goes.
// A killed edge's goroutines end with its context, and Close does not wait for them, since a schedule
// may hold one at a barrier until its end. The Net's Close closes these again, which does nothing
// more. Safe more than once.
func (self *DnsHarness) Close() {
	edges := []*dnsHarnessEdge{}
	var block *dnsHarnessApi
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for _, ns := range self.dnsSettings.Ns {
			if edge := self.nsEdges[ns]; edge != nil && edge.ctx.Err() == nil {
				edges = append(edges, edge)
			}
		}
		if self.api != nil && self.api.ctx.Err() == nil {
			block = self.api
		}
	}()
	for _, edge := range edges {
		edge.Close()
	}
	if block != nil {
		block.api.Close()
	}
	self.bumpInstances()
}

// The host one process runs on: the Net's, with the Net's clock, this harness's gates and metrics of
// the process's own, which go to the privacy capture as the host's fakes do.
func (self *DnsHarness) processHost(host *sidecar.ServiceHost, process string) (*sidecar.ServiceHost, *FakeMetrics) {
	metrics := NewFakeMetrics(nil)
	self.net.Capture().AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for _, line := range metrics.Dump() {
			items = append(items, &PrivacyItem{Class: "CC4", Name: "metric of " + process, Body: []byte(line)})
		}
		return items
	})
	hostCopy := *host
	hostCopy.Metrics = metrics
	hostCopy.Gates = self.gates
	hostCopy.Clock = self.clock
	return &hostCopy, metrics
}

// Builds the block from durable state alone: the store, the settings and the credentials.
func (self *DnsHarness) buildApi(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
	processHost, metrics := self.processHost(host, self.ApiProcess())
	api, err := dnsservice.NewDnsApi(ctx, processHost, self.dnsSettings, self.store, &dnsservice.DnsApiDeps{
		Auth:       self.verifier,
		Interfaces: self.currentInterfaces,
		KeyWindow:  self.keys.releasedWindow,
		ReadyStore: self.readyStore,
		SoaReader:  &dnsHarnessSoaReader{harness: self},
	})
	if err != nil {
		return nil, err
	}
	block := &dnsHarnessApi{ctx: ctx, api: api, metrics: metrics}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.api = block
	}()
	self.bumpInstances()
	context.AfterFunc(ctx, self.bumpInstances)
	return api, nil
}

// Waits until the running block has read every root's row.
func (self *DnsHarness) awaitApiReady(ctx context.Context) error {
	for {
		_, instancesChanged := self.instances.Get()
		var probesChanged chan struct{}
		if api := self.Api(); api != nil {
			count, changed := api.Probes()
			if 0 < count && api.Ready() {
				return nil
			}
			probesChanged = changed
		}
		select {
		case <-probesChanged:
		case <-instancesChanged:
		case <-ctx.Done():
			return fmt.Errorf("the dns api never read its store: %w", ctx.Err())
		}
	}
}

// Builds an edge from durable state alone: its local snapshot, the ZSK, the anchors and its bearer,
// with --require-reload when SetRequireReload set it.
func (self *DnsHarness) buildEdge(ctx context.Context, ns string, host *sidecar.ServiceHost) (sidecar.Engine, error) {
	processHost, metrics := self.processHost(host, self.EdgeProcess(ns))
	requireReload := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.requireReloads[ns]
	}()
	edge, err := dnsservice.NewDnsEdge(ctx, processHost, self.dnsSettings, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: self.transport}
	bearer := self.classBearers[dnsservice.DnsCallerEdge]
	// the block answers route-probes only once DNS-M6-03 adds the route, so a report fails until then
	routeProbes, err := dnsservice.NewDnsRouteProbeSinkHttp(self.apiUrl, bearer, client, self.dnsSettings)
	if err != nil {
		edge.Close()
		return nil, err
	}
	prober, err := dnsservice.NewProber(ctx, processHost, self.dnsSettings, &dnsservice.ProberDeps{
		Dialer:      &dnsHarnessProbeDialer{harness: self},
		RouteProbes: routeProbes,
	}, edge.SetHealthySet)
	if err != nil {
		edge.Close()
		return nil, err
	}
	feed, err := dnsservice.NewDnsFeedHttp(self.apiUrl, bearer, client, self.dnsSettings)
	if err != nil {
		prober.Close()
		edge.Close()
		return nil, err
	}
	loop, err := dnsservice.NewFeedLoop(ctx, processHost, self.dnsSettings, &dnsservice.FeedLoopDeps{
		Feed:              feed,
		Edge:              edge,
		Zsk:               self.keys.zsk,
		Anchors:           self.keys.rootAnchors,
		SnapshotDirectory: filepath.Join(self.settings.Directory, self.EdgeProcess(ns)),
		RequireReload:     requireReload,
		OnInterfaces:      prober.SetInterfaces,
	})
	if err != nil {
		prober.Close()
		edge.Close()
		return nil, err
	}
	instance := &dnsHarnessEdge{
		ns:       ns,
		ctx:      ctx,
		edge:     edge,
		loop:     loop,
		prober:   prober,
		listener: newDnsHarnessListener(self.edgeAddr(ns)),
		metrics:  metrics,
	}
	instance.serving.Add(1)
	go func() {
		defer instance.serving.Done()
		edge.Serve(instance.listener)
		// an edge closed before Serve took the listener leaves it to this
		instance.listener.Close()
	}()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.nsEdges[ns] = instance
	}()
	self.bumpInstances()
	context.AfterFunc(ctx, self.bumpInstances)
	return instance, nil
}

func (self *DnsHarness) bumpInstances() {
	self.instances.Update(func(count uint64) uint64 { return count + 1 })
}

// Where an edge listens, for what its connections report: one TEST-NET-3 address an NS.
func (self *DnsHarness) edgeAddr(ns string) *net.TCPAddr {
	index := max(slices.Index(self.dnsSettings.Ns, ns), 0)
	return &net.TCPAddr{IP: net.IPv4(203, 0, 113, byte(53+index)), Port: 53}
}

// Restarts of ns's edge, from the next on, start with --require-reload: serve nothing until a reload,
// the local snapshot being the one it replaces (§19.10's rule for a stopped NS).
func (self *DnsHarness) SetRequireReload(ns string, requireReload bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requireReloads[ns] = requireReload
}

// One write through the store: §12.6's one transaction, one serial and one journal row. Root empty
// takes Root(). Returns the serial taken.
func (self *DnsHarness) Write(ctx context.Context, write *dnsservice.DnsZoneWrite) (uint64, error) {
	zoneWrite := *write
	if zoneWrite.Root == "" {
		zoneWrite.Root = self.Root()
	}
	return self.store.Write(ctx, &zoneWrite)
}

// Write, then AwaitServed on every edge.
func (self *DnsHarness) WriteServed(ctx context.Context, write *dnsservice.DnsZoneWrite) (uint64, error) {
	serial, err := self.Write(ctx, write)
	if err != nil {
		return 0, err
	}
	root := write.Root
	if root == "" {
		root = self.Root()
	}
	return serial, self.AwaitServed(ctx, root, serial)
}

// Waits until the edges named, every edge when none is, each serve root at serial or above. An edge
// that is not running is waited for until it runs again, so a test that killed one names the others.
func (self *DnsHarness) AwaitServed(ctx context.Context, root string, serial uint64, nsLabels ...string) error {
	if !slices.Contains(self.dnsSettings.Roots, root) {
		return fmt.Errorf("%w: %s is not a root here", ErrDnsHarnessSettings, root)
	}
	if len(nsLabels) == 0 {
		nsLabels = self.dnsSettings.Ns
	}
	for _, ns := range nsLabels {
		if !slices.Contains(self.dnsSettings.Ns, ns) {
			return fmt.Errorf("%w: %s is not an ns here", ErrDnsHarnessSettings, ns)
		}
		for {
			_, instancesChanged := self.instances.Get()
			var servedChanged chan struct{}
			served := uint64(0)
			if edge := self.Edge(ns); edge != nil {
				served, servedChanged = edge.ServedSerial(root)
				if serial <= served {
					break
				}
			}
			select {
			case <-servedChanged:
			case <-instancesChanged:
			case <-ctx.Done():
				return fmt.Errorf("%s serves %s at %d, not %d: %w", ns, root, served, serial, ctx.Err())
			}
		}
	}
	return nil
}

// The lb inventory the block names now.
func (self *DnsHarness) Interfaces() []dnsservice.DnsLbInterface {
	return self.currentInterfaces()
}

func (self *DnsHarness) currentInterfaces() []dnsservice.DnsLbInterface {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.interfaces)
}

// Replaces the inventory the block names, map fields included. Edges take it with their next answer:
// after the next write, or once a hold ends on the clock.
func (self *DnsHarness) SetInterfaces(interfaces []dnsservice.DnsLbInterface) error {
	if err := validateDnsHarnessInterfaces(interfaces); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.interfaces = slices.Clone(interfaces)
	return nil
}

// Whether a probe of address reaches a fake interface that answers.
func (self *DnsHarness) interfaceAnswers(address netip.Addr) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	address = address.Unmap()
	for index := range self.interfaces {
		lbInterface := &self.interfaces[index]
		if lbInterface.Ipv4.Unmap() == address || lbInterface.Ipv6 == address {
			return !self.failedNames[lbInterface.Name]
		}
	}
	return false
}

// Sets whether an interface refuses every probe, as a host that is down does.
func (self *DnsHarness) setFailed(name string, failed bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !slices.ContainsFunc(self.interfaces, func(lbInterface dnsservice.DnsLbInterface) bool { return lbInterface.Name == name }) {
		return fmt.Errorf("%w: no interface %s", ErrDnsHarnessSettings, name)
	}
	self.failedNames[name] = failed
	return nil
}

// Fails an interface, then runs enough probe rounds on every edge for each to judge it: dropped from
// every edge row's answers, or kept by never-all when it is the last (§12.6).
func (self *DnsHarness) FailInterface(ctx context.Context, name string) error {
	if err := self.setFailed(name, true); err != nil {
		return err
	}
	return self.ProbeRounds(ctx, self.dnsSettings.Probe.FailureCount+1)
}

// Lets a failed interface answer again, then runs the round that brings it back.
func (self *DnsHarness) RestoreInterface(ctx context.Context, name string) error {
	if err := self.setFailed(name, false); err != nil {
		return err
	}
	return self.ProbeRounds(ctx, 2)
}

// Lists an interface in sidecar.yml's drained, as §19.5's W1 does, then runs the round that drops it
// from edge and router answers alike.
func (self *DnsHarness) DrainInterface(ctx context.Context, name string) error {
	if err := self.setDrained(name, true); err != nil {
		return err
	}
	return self.ProbeRounds(ctx, 2)
}

// Takes an interface off drained, then runs the round that brings it back.
func (self *DnsHarness) UndrainInterface(ctx context.Context, name string) error {
	if err := self.setDrained(name, false); err != nil {
		return err
	}
	return self.ProbeRounds(ctx, 2)
}

func (self *DnsHarness) setDrained(name string, drained bool) error {
	if !slices.ContainsFunc(self.currentInterfaces(), func(lbInterface dnsservice.DnsLbInterface) bool { return lbInterface.Name == name }) {
		return fmt.Errorf("%w: no interface %s", ErrDnsHarnessSettings, name)
	}
	self.gatesLock.Lock()
	defer self.gatesLock.Unlock()
	self.drainedNames = slices.DeleteFunc(self.drainedNames, func(drainedName string) bool { return drainedName == name })
	if drained {
		self.drainedNames = append(self.drainedNames, name)
	}
	return self.applyGatesWithLock()
}

// Sets §19.11's dns gate: closed, every route answers 503; writes off, the routes that change zone data
// do.
func (self *DnsHarness) SetDnsGate(enabled bool, writes bool) error {
	self.gatesLock.Lock()
	defer self.gatesLock.Unlock()
	self.gateEnabled = enabled
	self.gateWrites = writes
	return self.applyGatesWithLock()
}

func (self *DnsHarness) applyGates() error {
	self.gatesLock.Lock()
	defer self.gatesLock.Unlock()
	return self.applyGatesWithLock()
}

// Renders sidecar.yml from the gate and the drained list, and hands it to the gates.
func (self *DnsHarness) applyGatesWithLock() error {
	file := map[string]any{"sidecar": map[string]any{
		"dns":     map[string]any{"enabled": self.gateEnabled, "writes": self.gateWrites},
		"drained": self.drainedNames,
	}}
	text, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	return self.gates.Set(string(text))
}

// Moves the Net's clock one probe interval count times, each time waiting for every running edge to
// finish a round, so what the fake interfaces answer reaches every edge's healthy set. A round already
// running when a state changed may not see it, so a caller wanting n rounds of a new state asks for
// n+1. Every other timer on the clock fires as it passes.
func (self *DnsHarness) ProbeRounds(ctx context.Context, count int) error {
	for range count {
		edgeRounds := map[*dnsHarnessEdge]int{}
		for _, ns := range self.dnsSettings.Ns {
			if edge := self.runningEdge(ns); edge != nil {
				rounds, _ := edge.prober.Rounds()
				edgeRounds[edge] = rounds
			}
		}
		self.clock.Advance(time.Duration(self.dnsSettings.Probe.IntervalSeconds) * time.Second)
		for edge, rounds := range edgeRounds {
			for {
				_, instancesChanged := self.instances.Get()
				current, changed := edge.prober.Rounds()
				if rounds < current || edge.ctx.Err() != nil {
					break
				}
				select {
				case <-changed:
				case <-instancesChanged:
				case <-ctx.Done():
					return fmt.Errorf("%s never finished a probe round: %w", edge.ns, ctx.Err())
				}
			}
		}
	}
	return nil
}

// A query source for an in-memory connection: one TEST-NET-2 address, a port of its own.
func (self *DnsHarness) querySource() *net.TCPAddr {
	port := 1024 + self.sourcePort.Add(1)%(65535-1024)
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: int(port)}
}

// A connection to ns's edge over its TCP 53 in memory.
func (self *DnsHarness) dialEdge(ctx context.Context, ns string) (net.Conn, error) {
	edge := self.runningEdge(ns)
	if edge == nil {
		return nil, fmt.Errorf("%w: %s", ErrDnsHarnessDown, ns)
	}
	return edge.listener.dial(ctx, self.querySource())
}

// message to ns's edge over TCP, as a resolver retrying after TC does, and its answer. An edge that
// closes the connection with no answer, as one not ready does, answers ErrDnsHarnessNoAnswer.
func (self *DnsHarness) Query(ctx context.Context, ns string, message *dns.Msg) (*dns.Msg, error) {
	conn, err := self.dialEdge(ctx, ns)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(message); err != nil {
		return nil, err
	}
	reply, err := dnsConn.ReadMsg()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("%w: %s over tcp", ErrDnsHarnessNoAnswer, ns)
	}
	if err != nil {
		return nil, err
	}
	if reply.Id != message.Id {
		return nil, fmt.Errorf("%w: %s answered another id", ErrDnsHarnessNoAnswer, ns)
	}
	return reply, nil
}

// message to ns's edge over UDP from source, which keys RRL, and its answer: ErrDnsHarnessNoAnswer when
// the edge reads it and sends nothing back, as RRL's drop and a root not ready do.
func (self *DnsHarness) QueryUdp(ctx context.Context, ns string, message *dns.Msg, source netip.Addr) (*dns.Msg, error) {
	edge := self.runningEdge(ns)
	if edge == nil {
		return nil, fmt.Errorf("%w: %s", ErrDnsHarnessDown, ns)
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, err
	}
	conn := &dnsHarnessPacketConn{
		localAddr: &net.UDPAddr{IP: edge.listener.addr.IP, Port: 53},
		source:    net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, uint16(self.querySource().Port))),
		query:     packed,
		replies:   make(chan []byte, 1),
		readAgain: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		edge.edge.ServePacket(conn)
	}()
	defer func() {
		conn.Close()
		<-served
	}()
	var data []byte
	select {
	case data = <-conn.replies:
	case <-conn.readAgain:
	case <-served:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if data == nil {
		// the reader writes before it reads again, so a reply it sent is in the channel by now
		select {
		case data = <-conn.replies:
		default:
			return nil, fmt.Errorf("%w: %s over udp", ErrDnsHarnessNoAnswer, ns)
		}
	}
	reply := &dns.Msg{}
	if err := reply.Unpack(data); err != nil {
		return nil, err
	}
	if reply.Id != message.Id {
		return nil, fmt.Errorf("%w: %s answered another id", ErrDnsHarnessNoAnswer, ns)
	}
	return reply, nil
}

// A net.Resolver whose every lookup goes to ns's edge over TCP in memory, for code that takes one.
// Lookups name fully qualified names, so no search domain of the host's resolv.conf is tried.
func (self *DnsHarness) Resolver(ns string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return self.dialEdge(ctx, ns)
		},
	}
}

// GET ready for root at serial, as certs asks it (§12.8): the answer, after the route's hold on the
// Net's clock. A second ask at one fake time sees the same SOA reads.
func (self *DnsHarness) Ready(ctx context.Context, root string, serial uint64) (*dnsservice.DnsReadyAnswer, error) {
	query := url.Values{"root": {root}, "serial": {fmt.Sprint(serial)}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.apiUrl+dnsservice.DnsReadyPath+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+self.classBearers[dnsservice.DnsCallerCerts])
	response, err := (&http.Client{Transport: self.transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ready answered %d", response.StatusCode)
	}
	answer := &dnsservice.DnsReadyAnswer{}
	if err := json.NewDecoder(response.Body).Decode(answer); err != nil {
		return nil, err
	}
	return answer, nil
}

// Stops or starts ns for root in dns_ns's stand-in, as `dns ns stop` writes it (plan-DNS-running-ns).
func (self *DnsHarness) SetNsStopped(root string, ns string, stopped bool) {
	self.readyStore.setStopped(root, ns, stopped)
}

// Records a monitor's canary verdict for root now, as POST /dns/canary-report does
// (plan-DNS-canary-route-state). With none, GET ready answers canary_failing.
func (self *DnsHarness) ReportCanary(root string, source string, serial uint64, ok bool) {
	self.readyStore.report(root, dnsservice.DnsCanaryVerdict{Source: source, Serial: serial, Ok: ok, ReportTime: self.clock.Now()})
}

// A fixture apex for root: an SOA and an NS for each dns.yml ns label, which is what an edge needs to
// serve and self-check. Not §12.7's set, which DNS-M5-11 reconciles from dns.yml.
func (self *DnsHarness) ApexRows(root string) []dnsservice.DnsRecordSet {
	ttl := &self.dnsSettings.Ttl
	nsTargets := []string{}
	for _, ns := range self.dnsSettings.Ns {
		nsTargets = append(nsTargets, ns+"."+root)
	}
	return []dnsservice.DnsRecordSet{
		{
			Owner: root,
			Type:  dns.TypeSOA,
			Ttl:   ttl.SoaMinimum,
			Kind:  dnsservice.DnsRecordKindSystem,
			Rdata: []string{fmt.Sprintf(dnsHarnessSoaFormat, self.dnsSettings.Ns[0], root, root, ttl.SoaMinimum)},
		},
		{Owner: root, Type: dns.TypeNS, Ttl: ttl.Ns, Kind: dnsservice.DnsRecordKindSystem, Rdata: nsTargets},
	}
}

// A fixture for one network's names to resolve: <label>.<root> and * answering the healthy lb
// interfaces and MX 10 mx.<label>.<root>, which answers the healthy router interfaces. §12.7's set
// holds more and is DNS-M5-11's; a test needing more writes its own rows. root empty takes Root().
func (self *DnsHarness) NetworkRows(root string, label string) []dnsservice.DnsRecordSet {
	if root == "" {
		root = self.Root()
	}
	ttl := &self.dnsSettings.Ttl
	zone := label + "." + root
	mxHost := "mx." + zone
	rows := []dnsservice.DnsRecordSet{}
	for _, owner := range []string{zone, "*." + zone} {
		rows = append(rows,
			dnsservice.DnsRecordSet{Owner: owner, Type: dns.TypeA, Ttl: ttl.Edge, Kind: dnsservice.DnsRecordKindEdge},
			dnsservice.DnsRecordSet{Owner: owner, Type: dns.TypeAAAA, Ttl: ttl.Edge, Kind: dnsservice.DnsRecordKindEdge},
			dnsservice.DnsRecordSet{Owner: owner, Type: dns.TypeMX, Ttl: ttl.Mx, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{"10 " + mxHost}},
		)
	}
	return append(rows,
		dnsservice.DnsRecordSet{Owner: mxHost, Type: dns.TypeA, Ttl: ttl.MxHost, Kind: dnsservice.DnsRecordKindRouter},
		dnsservice.DnsRecordSet{Owner: mxHost, Type: dns.TypeAAAA, Ttl: ttl.MxHost, Kind: dnsservice.DnsRecordKindRouter},
	)
}

// This harness's KSK and ZSK, and the windows its feed releases. Safe for concurrent use.
type dnsHarnessKeys struct {
	settings *DnsHarnessKeySettings
	// The first window's step: when the harness started.
	epoch      time.Time
	kskPrivate *ecdsa.PrivateKey
	// The ZSK as LoadZsk read it from a key file, as an edge's secret_files hold it.
	zsk crypto.Signer
	// By root: the KSK and ZSK records, the KSK first, and the anchors an edge holds a window to.
	rootDnskeys map[string][]*dns.DNSKEY
	rootAnchors map[string][]*dns.DNSKEY

	stateLock   sync.Mutex
	rootWindows map[string]map[int64]*dnsservice.DnsKeyWindow
}

// Makes the keys for every root. The ZSK goes through LoadZsk, and the KSK to the Net's capture, so
// the privacy harness scans for both.
func newDnsHarnessKeys(net *Net, settings *DnsHarnessSettings) (*dnsHarnessKeys, error) {
	self := &dnsHarnessKeys{
		settings:    &settings.Keys,
		epoch:       net.Clock().Now(),
		rootDnskeys: map[string][]*dns.DNSKEY{},
		rootAnchors: map[string][]*dns.DNSKEY{},
		rootWindows: map[string]map[int64]*dnsservice.DnsKeyWindow{},
	}
	// miekg/dns will not sign under a key whose tag is 0, and about one random key in 65536 has
	// that tag, so such a key is drawn again.
	newKey := func(flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey, error) {
		for {
			record := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: settings.Keys.DnskeyTtl},
				Flags:     flags,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
			}
			private, err := record.Generate(256)
			if err != nil {
				return nil, nil, err
			}
			key, ok := private.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("miekg made no ecdsa key")
			}
			if record.KeyTag() != 0 {
				return record, key, nil
			}
		}
	}
	kskRecord, kskPrivate, err := newKey(dns.ZONE | dns.SEP)
	if err != nil {
		return nil, err
	}
	zskRecord, zskPrivate, err := newKey(dns.ZONE)
	if err != nil {
		return nil, err
	}
	kskScalar, err := kskPrivate.Bytes()
	if err != nil {
		return nil, err
	}
	net.Capture().AddSecret("dns_ksk", kskScalar)
	self.kskPrivate = kskPrivate
	self.zsk, err = dnsservice.LoadZsk([]byte(zskRecord.PrivateKeyString(zskPrivate)))
	if err != nil {
		return nil, err
	}
	for _, root := range settings.Dns.Roots {
		ksk := dns.Copy(kskRecord).(*dns.DNSKEY)
		ksk.Hdr.Name = root
		zsk := dns.Copy(zskRecord).(*dns.DNSKEY)
		zsk.Hdr.Name = root
		self.rootDnskeys[root] = []*dns.DNSKEY{ksk, zsk}
		self.rootAnchors[root] = []*dns.DNSKEY{ksk}
	}
	return self, nil
}

// The DnsApiDeps.KeyWindow the block names in each feed answer: the newest window released at now,
// made once each and kept.
func (self *dnsHarnessKeys) releasedWindow(root string, now time.Time) *dnsservice.DnsKeyWindow {
	dnskeys, ok := self.rootDnskeys[root]
	if !ok {
		return nil
	}
	index := int64(0)
	if self.epoch.Before(now) {
		index = int64(now.Sub(self.epoch) / self.settings.WindowStep)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	indexWindows, ok := self.rootWindows[root]
	if !ok {
		indexWindows = map[int64]*dnsservice.DnsKeyWindow{}
		self.rootWindows[root] = indexWindows
	}
	if window, ok := indexWindows[index]; ok {
		return window
	}
	notBefore := self.epoch.Add(time.Duration(index)*self.settings.WindowStep - self.settings.WindowLead)
	notAfter := notBefore.Add(self.settings.WindowDuration)
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: root, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: self.settings.DnskeyTtl},
		Algorithm:  dns.ECDSAP256SHA256,
		KeyTag:     dnskeys[0].KeyTag(),
		SignerName: root,
		Inception:  uint32(notBefore.Unix()),
		Expiration: uint32(notAfter.Unix()),
	}
	rrset := []dns.RR{}
	rdatas := []string{}
	for _, dnskey := range dnskeys {
		rrset = append(rrset, dnskey)
		rdatas = append(rdatas, dnsHarnessRdata(dnskey))
	}
	if err := rrsig.Sign(self.kskPrivate, rrset); err != nil {
		// an edge keeps the window it has, and its self-check says why
		return nil
	}
	window := &dnsservice.DnsKeyWindow{
		Root:      root,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Dnskeys:   rdatas,
		Rrsigs:    []string{dnsHarnessRdata(rrsig)},
	}
	indexWindows[index] = window
	return window
}

// A record's presentation-form RDATA, without owner, TTL, class or type.
func dnsHarnessRdata(record dns.RR) string {
	return strings.TrimPrefix(record.String(), record.Header().String())
}

// dns_ns and dns_canary_verdict for the harness's block: an NS stops and a monitor reports only when a
// test says so, so with no verdict ready answers canary_failing, as a site whose monitor has not run
// does. Safe for concurrent use.
type dnsHarnessReadyStore struct {
	stateLock     sync.Mutex
	rootStoppedNs map[string][]string
	rootVerdicts  map[string]map[string]dnsservice.DnsCanaryVerdict
}

func newDnsHarnessReadyStore() *dnsHarnessReadyStore {
	return &dnsHarnessReadyStore{
		rootStoppedNs: map[string][]string{},
		rootVerdicts:  map[string]map[string]dnsservice.DnsCanaryVerdict{},
	}
}

func (self *dnsHarnessReadyStore) StoppedNs(ctx context.Context, root string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.rootStoppedNs[root]), nil
}

func (self *dnsHarnessReadyStore) CanaryVerdicts(ctx context.Context, root string) ([]dnsservice.DnsCanaryVerdict, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	verdicts := []dnsservice.DnsCanaryVerdict{}
	for _, verdict := range self.rootVerdicts[root] {
		verdicts = append(verdicts, verdict)
	}
	return verdicts, nil
}

func (self *dnsHarnessReadyStore) setStopped(root string, ns string, stopped bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stoppedNs := slices.DeleteFunc(self.rootStoppedNs[root], func(stoppedLabel string) bool { return stoppedLabel == ns })
	if stopped {
		stoppedNs = append(stoppedNs, ns)
	}
	self.rootStoppedNs[root] = stoppedNs
}

// Overwrites the source's row in place, as the table's (root, source) key does.
func (self *dnsHarnessReadyStore) report(root string, verdict dnsservice.DnsCanaryVerdict) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sourceVerdicts, ok := self.rootVerdicts[root]
	if !ok {
		sourceVerdicts = map[string]dnsservice.DnsCanaryVerdict{}
		self.rootVerdicts[root] = sourceVerdicts
	}
	sourceVerdicts[verdict.Source] = verdict
}

// The block's SOA reads, over each edge's TCP 53 in memory, as NewDnsTcpSoaReader reads a host's.
type dnsHarnessSoaReader struct {
	harness *DnsHarness
}

var errDnsHarnessSoaUnreadable = errors.New("no SOA answer")

func (self *dnsHarnessSoaReader) ReadSoa(ctx context.Context, root string, ns string) (uint32, error) {
	query := &dns.Msg{}
	query.SetQuestion(root, dns.TypeSOA)
	query.RecursionDesired = false
	reply, err := self.harness.Query(ctx, ns, query)
	if err != nil {
		return 0, err
	}
	if !reply.Authoritative || reply.Rcode != dns.RcodeSuccess {
		return 0, errDnsHarnessSoaUnreadable
	}
	for _, record := range reply.Answer {
		if soa, ok := record.(*dns.SOA); ok && dns.CanonicalName(soa.Hdr.Name) == root {
			return soa.Serial, nil
		}
	}
	return 0, errDnsHarnessSoaUnreadable
}

// The fake lb: a probe of an interface that answers gets tlsedge's alert, whatever its hello names,
// and one of a failed or unknown address is refused, as a dial to a host that is down is.
type dnsHarnessProbeDialer struct {
	harness *DnsHarness
}

var errDnsHarnessProbeRefused = errors.New("probe refused")

func (self *dnsHarnessProbeDialer) DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	if !self.harness.interfaceAnswers(address.Addr()) {
		return nil, errDnsHarnessProbeRefused
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		header := make([]byte, dnsHarnessTlsRecordHeaderByteCount)
		if _, err := io.ReadFull(server, header); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[3:5]))); err != nil {
			return
		}
		server.Write(dnsHarnessTlsedgeAlert)
	}()
	return client, nil
}

// The block's end of DnsFeed's HTTP client and of certs' calls: each request runs the running block's
// handler on a goroutine of its own, under the block's process context, as a server's goroutine would.
// A block that is not running, or that dies before it answers, fails the request as a reset would.
type dnsHarnessTransport struct {
	harness *DnsHarness
}

func (self *dnsHarnessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	block := self.harness.runningApi()
	if block == nil {
		return nil, fmt.Errorf("%w: the dns api", ErrDnsHarnessDown)
	}
	serverCtx, cancel := context.WithCancel(block.ctx)
	defer cancel()
	stop := context.AfterFunc(request.Context(), cancel)
	defer stop()
	serverRequest := request.Clone(serverCtx)
	serverRequest.Body = io.NopCloser(bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		block.api.Handler().ServeHTTP(recorder, serverRequest)
	}()
	select {
	case <-answered:
		response := recorder.Result()
		response.Request = request
		return response, nil
	case <-request.Context().Done():
		return nil, request.Context().Err()
	case <-block.ctx.Done():
		return nil, fmt.Errorf("%w: the dns api died", ErrDnsHarnessDown)
	}
}

// An edge's TCP 53 in memory: each dial makes a pipe, and Accept hands over its far end. Safe for
// concurrent use.
type dnsHarnessListener struct {
	addr      *net.TCPAddr
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newDnsHarnessListener(addr *net.TCPAddr) *dnsHarnessListener {
	return &dnsHarnessListener{addr: addr, conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (self *dnsHarnessListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *dnsHarnessListener) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *dnsHarnessListener) Addr() net.Addr {
	return self.addr
}

// A connection from source, once the edge has accepted it.
func (self *dnsHarnessListener) dial(ctx context.Context, source *net.TCPAddr) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case self.conns <- &dnsHarnessConn{Conn: server, localAddr: self.addr, remoteAddr: source}:
		return &dnsHarnessConn{Conn: client, localAddr: source, remoteAddr: self.addr}, nil
	case <-self.closed:
		client.Close()
		server.Close()
		return nil, fmt.Errorf("%w: the edge closed", ErrDnsHarnessDown)
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	}
}

// One end of a pipe with the addresses a TCP connection would report, so the edge keys its
// per-source cap as it would a resolver's.
type dnsHarnessConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (self *dnsHarnessConn) LocalAddr() net.Addr {
	return self.localAddr
}

func (self *dnsHarnessConn) RemoteAddr() net.Addr {
	return self.remoteAddr
}

// One UDP exchange in memory, served by one ServePacket of its own. The edge's one reader takes the
// query on its first read and, having answered or dropped it, reads again, which is how a drop is
// known with no wait. Safe for concurrent use.
type dnsHarnessPacketConn struct {
	localAddr net.Addr
	source    net.Addr
	query     []byte
	// Takes the one reply. Buffered, so the reader never waits on it.
	replies chan []byte
	// Closed at the second read.
	readAgain chan struct{}
	closed    chan struct{}
	closeOnce sync.Once

	stateLock sync.Mutex
	readCount int
}

func (self *dnsHarnessPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	readCount := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.readCount += 1
		return self.readCount
	}()
	if readCount == 1 {
		select {
		case <-self.closed:
			return 0, nil, net.ErrClosed
		default:
		}
		return copy(buffer, self.query), self.source, nil
	}
	if readCount == 2 {
		close(self.readAgain)
	}
	<-self.closed
	return 0, nil, net.ErrClosed
}

func (self *dnsHarnessPacketConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	select {
	case self.replies <- bytes.Clone(buffer):
	default:
	}
	return len(buffer), nil
}

func (self *dnsHarnessPacketConn) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *dnsHarnessPacketConn) LocalAddr() net.Addr {
	return self.localAddr
}

func (self *dnsHarnessPacketConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (self *dnsHarnessPacketConn) SetReadDeadline(deadline time.Time) error {
	return nil
}

func (self *dnsHarnessPacketConn) SetWriteDeadline(deadline time.Time) error {
	return nil
}
