// GET ready?serial=s (§12.6, §12.8, D-DNS-8; plan-TLS-canary-signal): what certs asks before it lets a
// CA validate a challenge written at serial s. Checked in this order:
//
//   - stale while restoring or for s at or below restore_serial, whose writes a restore may have lost,
//     so certs writes again at a new serial (§13.8);
//   - while any running NS serves an SOA below s by RFC 1982, the answer holds, up to api.ready_hold_s;
//   - then canary_failing unless plan-DNS-canary-route-state's clean rule holds, a missing verdict
//     reading as failing, and an order waits on it with no new write;
//   - else ready.
//
// A hold that ends with an NS still behind answers waiting, and certs asks again. Running is
// plan-DNS-running-ns's: every NS dns.yml lists that dns_ns does not mark stopped, whether or not it
// answers now, so a running NS that does not answer keeps ready waiting. SOA reads are coalesced per
// root across every waiting request, at most one round each api.soa_read_interval_s, so a hundred
// orders cost one read a second.

package dnsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// GET ready's answers.
const (
	DnsReadyStale         = "stale"
	DnsReadyReady         = "ready"
	DnsReadyCanaryFailing = "canary_failing"
	// The hold ended with a running NS still below the serial: ask again.
	DnsReadyWaiting = "waiting"
)

// What GET ready answers.
type DnsReadyAnswer struct {
	// DnsReadyStale, DnsReadyReady, DnsReadyCanaryFailing or DnsReadyWaiting.
	Answer string `json:"answer"`
	// The root's serial and restore_serial as the answer was made.
	Serial        uint64 `json:"serial"`
	RestoreSerial uint64 `json:"restore_serial"`
}

// The monitor sources a canary verdict comes from (plan-DNS-canary-route-state).
const (
	DnsCanarySourceSite    = "site"
	DnsCanarySourceOutside = "outside"
)

// One row of dns_canary_verdict: a monitor's last word on the canary TXT it validated through every
// running NS against the KSK anchor.
type DnsCanaryVerdict struct {
	Source     string
	Serial     uint64
	Ok         bool
	ReportTime time.Time
}

// What GET ready reads beyond dns_root: the resolutions' dns_ns and dns_canary_verdict. dnshost.Store
// implements it once MG5 holds those tables. Safe for concurrent use.
type DnsReadyStore interface {
	// The NS dns.yml lists that dns_ns marks stopped for root.
	StoppedNs(ctx context.Context, root string) ([]string, error)
	// dns_canary_verdict's rows for root, one each source.
	CanaryVerdicts(ctx context.Context, root string) ([]DnsCanaryVerdict, error)
}

// plan-DNS-canary-route-state's clean rule at now: the site's verdict ok and younger than fresh, and no
// outside verdict younger than fresh failing. No site verdict reads as failing; a stale outside one
// alone holds nothing.
func DnsCanaryClean(verdicts []DnsCanaryVerdict, now time.Time, fresh time.Duration) bool {
	siteClean := false
	for _, verdict := range verdicts {
		age := now.Sub(verdict.ReportTime)
		young := 0 <= age && age < fresh
		switch verdict.Source {
		case DnsCanarySourceSite:
			siteClean = siteClean || (verdict.Ok && young)
		case DnsCanarySourceOutside:
			if !verdict.Ok && young {
				return false
			}
		}
	}
	return siteClean
}

// Whether an SOA's 32-bit serial is at or above serial by RFC 1982, against serial's low 32 bits (plan
// reading 4). Half the space away is undefined there, and reads as below, which holds.
func dnsSoaAtOrAbove(soaSerial uint32, serial uint64) bool {
	return 0 <= int32(soaSerial-uint32(serial))
}

// Reads an NS's SOA serial for a root over TCP. Safe for concurrent use.
type DnsSoaReader interface {
	// The serial ns, a label dns.yml lists, serves in root's SOA. ctx bounds the read.
	ReadSoa(ctx context.Context, root string, ns string) (uint32, error)
}

// Reads over TCP from each NS's configured addresses, the first that answers.
type dnsTcpSoaReader struct {
	addresses map[string][]netip.AddrPort
	dialer    net.Dialer
}

// The SOA reader a host gives the block: addresses by NS label, from its configuration, since the NS
// hosts' addresses arrive with the hosts (DNS-M5-18).
func NewDnsTcpSoaReader(addresses map[string][]netip.AddrPort) DnsSoaReader {
	return &dnsTcpSoaReader{addresses: addresses}
}

var errDnsSoaUnreadable = errors.New("no SOA answer")

func (self *dnsTcpSoaReader) ReadSoa(ctx context.Context, root string, ns string) (uint32, error) {
	addresses := self.addresses[ns]
	if len(addresses) == 0 {
		return 0, errDnsSoaUnreadable
	}
	for _, address := range addresses {
		if serial, err := self.readOne(ctx, root, address); err == nil {
			return serial, nil
		}
	}
	return 0, errDnsSoaUnreadable
}

// One SOA query to one address, cut short when ctx ends.
func (self *dnsTcpSoaReader) readOne(ctx context.Context, root string, address netip.AddrPort) (uint32, error) {
	conn, err := self.dialer.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(dnsPastDeadline) })
	defer stop()
	query := &dns.Msg{}
	query.SetQuestion(root, dns.TypeSOA)
	query.RecursionDesired = false
	packed, err := query.Pack()
	if err != nil {
		return 0, err
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(packed)))
	if _, err := conn.Write(append(framed, packed...)); err != nil {
		return 0, err
	}
	lengthBytes := make([]byte, dnsTcpLengthByteCount)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return 0, err
	}
	data := make([]byte, binary.BigEndian.Uint16(lengthBytes))
	if _, err := io.ReadFull(conn, data); err != nil {
		return 0, err
	}
	reply := &dns.Msg{}
	if err := reply.Unpack(data); err != nil {
		return 0, err
	}
	if reply.Id != query.Id || !reply.Response || !reply.Authoritative || reply.Rcode != dns.RcodeSuccess {
		return 0, errDnsSoaUnreadable
	}
	for _, record := range reply.Answer {
		if soa, ok := record.(*dns.SOA); ok && dns.CanonicalName(soa.Hdr.Name) == root {
			return soa.Serial, nil
		}
	}
	return 0, errDnsSoaUnreadable
}

// One NS's last read.
type dnsSoaResult struct {
	serial uint32
	ok     bool
}

// One root's coalesced reads.
type dnsSoaRoot struct {
	results  map[string]dnsSoaResult
	readTime time.Time
	reading  bool
	// a round waiting for its interval
	scheduled bool
	// rounds finished, whose channel waiters hold
	rounds *sidecar.MonitorValue[uint64]
}

// Reads every NS of a root at most once an interval, however many requests wait. Safe for concurrent
// use.
type dnsSoaPoller struct {
	ctx      context.Context
	clock    sidecar.Clock
	reader   DnsSoaReader
	settings *DnsSettings
	metrics  *dnsApiMetrics

	stateLock sync.Mutex
	roots     map[string]*dnsSoaRoot
}

func newDnsSoaPoller(ctx context.Context, clock sidecar.Clock, reader DnsSoaReader, settings *DnsSettings, metrics *dnsApiMetrics) *dnsSoaPoller {
	return &dnsSoaPoller{ctx: ctx, clock: clock, reader: reader, settings: settings, metrics: metrics, roots: map[string]*dnsSoaRoot{}}
}

// root's state, made on first use.
func (self *dnsSoaPoller) rootWithLock(root string) *dnsSoaRoot {
	state, ok := self.roots[root]
	if !ok {
		state = &dnsSoaRoot{results: map[string]dnsSoaResult{}, rounds: sidecar.NewMonitorValue[uint64](0)}
		self.roots[root] = state
	}
	return state
}

// What root's NS answered in the last round, whether that round is fresh enough to decide on, no older
// than api.soa_read_interval_s, and a channel that closes when the next round lands.
func (self *dnsSoaPoller) results(root string) (map[string]dnsSoaResult, bool, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.rootWithLock(root)
	_, changed := state.rounds.Get()
	results := make(map[string]dnsSoaResult, len(state.results))
	for ns, result := range state.results {
		results[ns] = result
	}
	interval := dnsSeconds(self.settings.Api.SoaReadIntervalSeconds)
	fresh := !state.readTime.IsZero() && self.clock.Now().Sub(state.readTime) < interval
	return results, fresh, changed
}

// Asks for the next round: on this goroutine now when the last is an interval old, else when it will
// be, unless one is in flight or waiting already. Either way every caller's channel from results closes
// when it lands.
func (self *dnsSoaPoller) request(root string) {
	var state *dnsSoaRoot
	startNow := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state = self.rootWithLock(root)
		if state.reading || state.scheduled {
			return
		}
		due := state.readTime.Add(dnsSeconds(self.settings.Api.SoaReadIntervalSeconds)).Sub(self.clock.Now())
		if state.readTime.IsZero() || due <= 0 {
			state.reading = true
			startNow = true
			return
		}
		state.scheduled = true
		self.clock.AfterFunc(due, func() {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				state.scheduled = false
				state.reading = true
			}()
			self.read(root, state)
		})
	}()
	if startNow {
		self.read(root, state)
	}
}

// One round: every NS dns.yml lists, at once, each bounded by api.soa_read_timeout_s on the clock.
func (self *dnsSoaPoller) read(root string, state *dnsSoaRoot) {
	results := map[string]dnsSoaResult{}
	var resultsLock sync.Mutex
	var group sync.WaitGroup
	for _, ns := range self.settings.Ns {
		group.Add(1)
		go func() {
			defer group.Done()
			result := dnsSoaResult{}
			if self.reader != nil {
				ctx, cancel := context.WithCancel(self.ctx)
				stop := self.clock.AfterFunc(dnsSeconds(self.settings.Api.SoaReadTimeoutSeconds), cancel)
				serial, err := self.reader.ReadSoa(ctx, root, ns)
				stop()
				cancel()
				result = dnsSoaResult{serial: serial, ok: err == nil}
			}
			if result.ok {
				self.metrics.soaReads.Add(1, "ok")
			} else {
				self.metrics.soaReads.Add(1, "failed")
			}
			resultsLock.Lock()
			defer resultsLock.Unlock()
			results[ns] = result
		}()
	}
	group.Wait()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state.results = results
	state.readTime = self.clock.Now()
	state.reading = false
	state.rounds.Update(func(count uint64) uint64 { return count + 1 })
}

func (self *DnsApi) readyRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodGet, path: DnsReadyPath, class: DnsCallerCerts, serve: self.serveReady},
	}
}

func (self *DnsApi) serveReady(writer http.ResponseWriter, request *http.Request) {
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	serial, err := strconv.ParseUint(request.URL.Query().Get("serial"), 10, 64)
	if err != nil {
		http.Error(writer, "serial is not a serial", http.StatusBadRequest)
		return
	}
	answer, err := self.readyAnswer(request.Context(), root, serial)
	if err != nil {
		dnsStoreUnavailable(writer)
		return
	}
	dnsWriteJson(writer, answer)
}

// The running NS of root: dns.yml's, less those dns_ns marks stopped.
func (self *DnsApi) runningNs(ctx context.Context, root string) ([]string, error) {
	running := slices.Clone(self.settings.Ns)
	if self.deps.ReadyStore == nil {
		return running, nil
	}
	stopped, err := self.deps.ReadyStore.StoppedNs(ctx, root)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(running, func(ns string) bool { return slices.Contains(stopped, ns) }), nil
}

// GET ready's answer for serial: see the file header.
func (self *DnsApi) readyAnswer(ctx context.Context, root string, serial uint64) (*DnsReadyAnswer, error) {
	done := self.holdStarted()
	defer done()
	holdEnded := self.clock.After(dnsSeconds(self.settings.Api.ReadyHoldSeconds))
	for {
		state, err := self.store.RootState(ctx, root)
		if err != nil {
			return nil, err
		}
		answer := &DnsReadyAnswer{Serial: state.Serial, RestoreSerial: state.RestoreSerial}
		if state.Restoring || serial <= state.RestoreSerial {
			answer.Answer = DnsReadyStale
			return answer, nil
		}
		running, err := self.runningNs(ctx, root)
		if err != nil {
			return nil, err
		}
		results, fresh, changed := self.soa.results(root)
		behind := !fresh || slices.ContainsFunc(running, func(ns string) bool {
			result, ok := results[ns]
			return !ok || !result.ok || !dnsSoaAtOrAbove(result.serial, serial)
		})
		if !behind {
			verdicts := []DnsCanaryVerdict{}
			if self.deps.ReadyStore != nil {
				verdicts, err = self.deps.ReadyStore.CanaryVerdicts(ctx, root)
				if err != nil {
					return nil, err
				}
			}
			answer.Answer = DnsReadyReady
			if !DnsCanaryClean(verdicts, self.clock.Now(), dnsSeconds(self.settings.Api.CanaryFreshSeconds)) {
				answer.Answer = DnsReadyCanaryFailing
			}
			self.metrics.holds.Add(1, dnsHoldRouteReady, dnsHoldAnswered)
			return answer, nil
		}
		self.soa.request(root)
		ended := self.park(func() bool {
			select {
			case <-changed:
				return false
			case <-holdEnded:
			case <-self.draining:
			case <-ctx.Done():
			}
			return true
		})
		if !ended {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		self.metrics.holds.Add(1, dnsHoldRouteReady, dnsHoldEmpty)
		answer.Answer = DnsReadyWaiting
		return answer, nil
	}
}
