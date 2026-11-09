// Route probes (§12.6, §13.4, D-TLS-12, FS-122): each round an edge sends each lb interface, on
// probe.route_port (443) as a visitor would, a ClientHello offering ALPN ur-route-probe then http/1.1
// for the probe name of the custom-host map version the feed says that interface reported, and, once
// per reported version, one for each of up to probe.route_hosts hosts that version added. tlsedge
// answers a hello offering ur-route-probe with a plaintext unrecognized_name before any lookup or
// Find (§13.5), so a probe passes on that and on nothing else; the http branch, where an interface's
// map does not send the name, would select http/1.1 and show a platform certificate, so its
// ServerHello fails. A probe sends its hello and nothing after it, and reaches no listener.
//
// Results feed nothing here: each round's go to the block in one POST /dns/internal/route-probes
// (plan-DNS-internal-route-credential's prefix over §12.8's /dns/route-probes), whose handler is
// DNS-M6-03's, and map-stale comes back through the feed, so both edges act on one decision. A host's
// pass counts once the block has taken it: a host is probed again each round until a report carrying
// its pass is posted, so a failing host repeats every round until it passes, and a report the block
// did not take loses nothing.
//
// An interface is probed at its IPv4 address, or its IPv6 one when it has none: one nginx serves both
// on an interface, with one map, so one hello tests the map. Drained, failed and map-stale interfaces
// are probed too, since an interface must be current before it rejoins (§19.5's W1).
//
// A prober with no DnsRouteProbeSink sends no route probe, and the block then never counts an
// interface current, which keeps every custom host pending: the closed direction.

package dnsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// POST /dns/internal/route-probes: an edge's route-probe results, which DNS-M6-03's handler keeps in
// dns_custom_host_map_applied and answers 204.
const DnsRouteProbesPath = DnsInternalPathPrefix + "route-probes"

// The ALPN id a route probe offers first (§13.4), which tlsedge answers unrecognized_name with no
// lookup.
const DnsRouteProbeAlpn = "ur-route-probe"

// The ALPN id a route probe offers second, which the http branch selects.
const dnsRouteProbeAlpnHttp11 = "http/1.1"

// The values of the route_probes metric's result label.
const (
	dnsRouteProbePass = "pass"
	dnsRouteProbeFail = "fail"
)

// The values of the route_reports metric's result label.
const (
	dnsRouteReportPosted = "posted"
	dnsRouteReportFailed = "failed"
)

// The longest name a probe asks for, by RFC 1035 §2.3.4 in presentation form without the final dot.
const dnsRouteProbeNameMaxByteCount = 253

// A report the block cannot keep. Nothing of it is taken.
var ErrDnsRouteProbeReportMalformed = errors.New("dns route probe report malformed")

// One round's route probes from one edge. The block stamps its own time on what it takes, since the
// 2-minute window it judges is its own: an edge sends no time, and does not say which NS it is.
type DnsRouteProbeReport struct {
	// Read before anything else, as wire.go's rows are.
	Format     int                   `json:"format"`
	Interfaces []DnsRouteProbeResult `json:"interfaces"`
}

// One interface's probes in one round, every one for the version the feed said it reported.
type DnsRouteProbeResult struct {
	// The inventory name, as the feed named it.
	Name    string `json:"name"`
	Version uint64 `json:"version"`
	// That version's probe name, and whether tlsedge answered a hello for it.
	ProbeName   string `json:"probe_name"`
	ProbePassed bool   `json:"probe_passed"`
	// The added hosts probed this round, each once. A host whose pass the block took in an earlier
	// round is not probed again for this version.
	Hosts []DnsRouteProbeHost `json:"hosts,omitempty"`
}

// One added host's probe.
type DnsRouteProbeHost struct {
	Host   string `json:"host"`
	Passed bool   `json:"passed"`
}

// Whether the block can keep this report: a format it reads, each interface once with a version and a
// probe name, each host once, no name longer than a DNS name. Names are as the feed gave them, and
// one no hello could ask for is reported failed, so whether a name is well formed, and whether a host
// belongs to the version, is the block's to judge against its own rows; a malformed name refusing the
// whole report would lose every other result with it, round after round.
func (self *DnsRouteProbeReport) Validate() error {
	if err := checkDnsFormat(self.Format); err != nil {
		return err
	}
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsRouteProbeReportMalformed, fmt.Sprintf(format, arguments...))
	}
	names := map[string]bool{}
	for index := range self.Interfaces {
		result := &self.Interfaces[index]
		if result.Name == "" || names[result.Name] {
			return refuse("an interface unnamed or named twice")
		}
		names[result.Name] = true
		if result.Version == 0 {
			return refuse("%s's version is zero", result.Name)
		}
		if !isDnsRouteReportName(result.ProbeName) {
			return refuse("%s's probe name is empty or too long", result.Name)
		}
		hosts := map[string]bool{}
		for _, host := range result.Hosts {
			if !isDnsRouteReportName(host.Host) || hosts[host.Host] {
				return refuse("%s names a host that is empty, too long or there twice", result.Name)
			}
			hosts[host.Host] = true
		}
	}
	return nil
}

// Reads one report, stopping at a format this release does not read before reading the rest.
func DecodeDnsRouteProbeReport(data []byte) (*DnsRouteProbeReport, error) {
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRouteProbeReportMalformed, err)
	}
	if err := checkDnsFormat(header.Format); err != nil {
		return nil, err
	}
	report := &DnsRouteProbeReport{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRouteProbeReportMalformed, err)
	}
	if err := report.Validate(); err != nil {
		return nil, err
	}
	return report, nil
}

// Whether name is one a hello can ask for: a DNS name, with or without its final dot, which SNI leaves
// off (dnsRouteProbeSni).
func isDnsRouteProbeName(name string) bool {
	sni := dnsRouteProbeSni(name)
	if sni == "" || dnsRouteProbeNameMaxByteCount < len(sni) {
		return false
	}
	_, ok := dns.IsDomainName(name)
	return ok
}

// Whether name can stand in a report: present, and no longer than a DNS name with its final dot.
func isDnsRouteReportName(name string) bool {
	return name != "" && len(name) <= dnsRouteProbeNameMaxByteCount+1
}

// name as a hello's SNI carries it: with no final dot (RFC 6066 §3).
func dnsRouteProbeSni(name string) string {
	return strings.TrimSuffix(name, ".")
}

// Where a round's report goes: the block over HTTP (NewDnsRouteProbeSinkHttp), or a fake. Safe for
// concurrent use.
type DnsRouteProbeSink interface {
	// Posts one round's report. An error means the block did not take it, and the round's passes are
	// probed again.
	RouteProbes(ctx context.Context, report *DnsRouteProbeReport) error
}

// An edge's client for POST route-probes: the feed's client, with the same bearer, since route-probes
// takes the dnsedge class as the feed's routes do.
func NewDnsRouteProbeSinkHttp(baseUrl string, credential string, client *http.Client, settings *DnsSettings) (DnsRouteProbeSink, error) {
	feed, err := NewDnsFeedHttp(baseUrl, credential, client, settings)
	if err != nil {
		return nil, err
	}
	return feed.(*dnsFeedHttp), nil
}

func (self *dnsFeedHttp) RouteProbes(ctx context.Context, report *DnsRouteProbeReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.baseUrl+DnsRouteProbesPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := self.do(request, http.StatusNoContent)
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}

// One route probe of a round: a name at one interface's address, for the version the feed said it
// reported.
type dnsRouteProbe struct {
	interfaceName string
	version       uint64
	probeName     string
	// The added host this probes, or empty for the version's probe name.
	host    string
	address netip.AddrPort
	// nil when no hello could be made for the name, which then fails without a dial.
	hello  []byte
	passed bool
}

// The name this probe asks for, as the feed named it.
func (self *dnsRouteProbe) serverName() string {
	if self.host != "" {
		return self.host
	}
	return self.probeName
}

// The added hosts one interface's reported version still owes a pass the block took.
type dnsRouteVersion struct {
	version      uint64
	pendingHosts []string
}

// A prober's route probes: which hosts each interface's version still owes, and each name's hello.
// Safe for concurrent use.
type dnsRouteProbes struct {
	settings *DnsSettings
	clock    sidecar.Clock
	metrics  *dnsMetrics
	sink     DnsRouteProbeSink

	stateLock         sync.Mutex
	interfaceVersions map[string]*dnsRouteVersion
	// Each name's ClientHello, made once and kept while a version names it.
	nameHellos map[string][]byte
}

func newDnsRouteProbes(settings *DnsSettings, clock sidecar.Clock, metrics *dnsMetrics, sink DnsRouteProbeSink) *dnsRouteProbes {
	return &dnsRouteProbes{
		settings:          settings,
		clock:             clock,
		metrics:           metrics,
		sink:              sink,
		interfaceVersions: map[string]*dnsRouteVersion{},
		nameHellos:        map[string][]byte{},
	}
}

// This round's probes over interfaces, as the feed last named them: the probe name of each reported
// version, and each added host it still owes. None without a sink.
func (self *dnsRouteProbes) probes(interfaces []DnsLbInterface) []*dnsRouteProbe {
	if self.sink == nil {
		return nil
	}
	probes := []*dnsRouteProbe{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listed := map[string]bool{}
		for index := range interfaces {
			lbInterface := &interfaces[index]
			listed[lbInterface.Name] = true
			if lbInterface.ReportedVersion == 0 || lbInterface.ProbeName == "" {
				delete(self.interfaceVersions, lbInterface.Name)
				continue
			}
			address := dnsInterfaceAddress(lbInterface, dnsFamilyIpv4)
			if !address.IsValid() {
				address = dnsInterfaceAddress(lbInterface, dnsFamilyIpv6)
			}
			if !address.IsValid() {
				continue
			}
			version, ok := self.interfaceVersions[lbInterface.Name]
			if !ok || version.version != lbInterface.ReportedVersion {
				version = &dnsRouteVersion{version: lbInterface.ReportedVersion}
				for _, host := range lbInterface.AddedHosts {
					if len(version.pendingHosts) < self.settings.Probe.RouteHostCount && !slices.Contains(version.pendingHosts, host) {
						version.pendingHosts = append(version.pendingHosts, host)
					}
				}
				self.interfaceVersions[lbInterface.Name] = version
			}
			probe := dnsRouteProbe{
				interfaceName: lbInterface.Name,
				version:       version.version,
				probeName:     lbInterface.ProbeName,
				address:       netip.AddrPortFrom(address, uint16(self.settings.Probe.RoutePort)),
			}
			probes = append(probes, &probe)
			for _, host := range version.pendingHosts {
				hostProbe := probe
				hostProbe.host = host
				probes = append(probes, &hostProbe)
			}
		}
		for name := range self.interfaceVersions {
			if !listed[name] {
				delete(self.interfaceVersions, name)
			}
		}
	}()
	names := map[string]bool{}
	for _, probe := range probes {
		names[probe.serverName()] = true
		probe.hello = self.hello(probe.serverName())
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for name := range self.nameHellos {
			if !names[name] {
				delete(self.nameHellos, name)
			}
		}
	}()
	return probes
}

// The hello a route probe of name sends: crypto/tls's, for name without its final dot, offering
// ur-route-probe then http/1.1.
func dnsRouteProbeClientHello(name string) ([]byte, error) {
	return dnsProbeClientHello(dnsRouteProbeSni(name), []string{DnsRouteProbeAlpn, dnsRouteProbeAlpnHttp11})
}

// name's hello, made once and kept. nil for a name no hello can ask for, whose probe then fails.
func (self *dnsRouteProbes) hello(name string) []byte {
	if !isDnsRouteProbeName(name) {
		return nil
	}
	hello, ok := func() ([]byte, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hello, ok := self.nameHellos[name]
		return hello, ok
	}()
	if ok {
		return hello
	}
	hello, err := dnsRouteProbeClientHello(name)
	if err != nil {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameHellos[name] = hello
	return hello
}

// Posts a round's results, bounded by probe.report_timeout_s on the clock, and once the block has
// taken them forgets each host whose pass they carry. Nothing to post without a probe.
func (self *dnsRouteProbes) report(ctx context.Context, probes []*dnsRouteProbe) {
	if len(probes) == 0 {
		return
	}
	report := &DnsRouteProbeReport{Format: DnsFormat}
	interfaceResults := map[string]*DnsRouteProbeResult{}
	for _, probe := range probes {
		if probe.passed {
			self.metrics.routeProbes.Add(1, dnsRouteProbePass)
		} else {
			self.metrics.routeProbes.Add(1, dnsRouteProbeFail)
		}
		result, ok := interfaceResults[probe.interfaceName]
		if !ok {
			report.Interfaces = append(report.Interfaces, DnsRouteProbeResult{
				Name:      probe.interfaceName,
				Version:   probe.version,
				ProbeName: probe.probeName,
			})
			result = &report.Interfaces[len(report.Interfaces)-1]
			interfaceResults[probe.interfaceName] = result
		}
		if probe.host == "" {
			result.ProbePassed = probe.passed
		} else {
			result.Hosts = append(result.Hosts, DnsRouteProbeHost{Host: probe.host, Passed: probe.passed})
		}
	}
	err := func() error {
		reportCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := self.clock.AfterFunc(dnsSeconds(self.settings.Probe.ReportTimeoutSeconds), cancel)
		defer stop()
		testHookBarrier("dnsservice.route_report.before", "")
		err := self.sink.RouteProbes(reportCtx, report)
		testHookBarrier("dnsservice.route_report.after", "")
		return err
	}()
	if err != nil {
		self.metrics.routeReports.Add(1, dnsRouteReportFailed)
		return
	}
	self.metrics.routeReports.Add(1, dnsRouteReportPosted)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, probe := range probes {
		if probe.host == "" || !probe.passed {
			continue
		}
		if version, ok := self.interfaceVersions[probe.interfaceName]; ok && version.version == probe.version {
			version.pendingHosts = slices.DeleteFunc(version.pendingHosts, func(host string) bool { return host == probe.host })
		}
	}
}
