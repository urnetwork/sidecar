// The canary's two routes (§12.6's monitor, D-DNS-5, FS-50; DNS-M5-17; plan-DNS-canary-route-state,
// decided by the owner):
//
//   - POST /dns/internal/canary {root, value}, the site monitor's alone. value is at most 64 printable
//     ASCII bytes and starts with the writer's unix milliseconds, then a space and what the writer
//     likes, or nothing; no quote or backslash, this draft's reading, so a TXT string carries it with no
//     escape. It writes canary.<root> TXT at ttl.canary through §12.6's one write path (DnsCanaryWriter:
//     one serial, one journal row, the row expiring after its hour as a challenge's does), answers
//     {serial}, and 503 while restoring. A write, so the gate's writes: false refuses it.
//   - POST /dns/internal/canary-report {root, source, serial, ok}: the site monitor reports source site
//     and the outside monitor source outside, each by its own bearer and no other source. ok is true
//     only if the TXT validated through every running NS against the configured KSK anchor. The block
//     keeps the verdict with the time it came (DnsCanaryVerdictStore), which GET ready reads by
//     DnsCanaryClean. Not zone data, so writes: false leaves it be.
//
// dns_canary_verdict waits for its §2.8 row (plan-DNS-metadata-rows #7, v9), and a block with no verdict
// store answers each report 503, keeping nothing, so ready answers canary_failing: the resolution's
// interim, the closed direction.

package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// The routes (plan-DNS-internal-route-credential's prefix over plan-DNS-canary-route-state's paths).
const (
	DnsCanaryPath       = DnsInternalPathPrefix + "canary"
	DnsCanaryReportPath = DnsInternalPathPrefix + "canary-report"
)

// The label the canary sits at under each root (§12.7).
const DnsCanaryLabel = "canary"

// The longest canary value (plan-DNS-canary-route-state).
const dnsCanaryValueMaxByteCount = 64

// The most bytes either route's body may hold.
const dnsCanaryRequestMaxByteCount = 4 * 1024

var (
	// A value no canary may hold, or one the write path refuses: 400.
	ErrDnsCanaryRefused = errors.New("dns canary refused")
)

// The model's half of POST canary: one write through §12.6's path that takes a serial. Returns
// ErrDnsRestoring while restoring and ErrDnsCanaryRefused for what the path refuses. Safe for concurrent
// use.
type DnsCanaryWriter interface {
	PutCanary(ctx context.Context, root string, value string, ttl uint32) (serial uint64, err error)
}

// dns_canary_verdict, one row a root and source, each report over the last. Safe for concurrent use.
type DnsCanaryVerdictStore interface {
	PutCanaryVerdict(ctx context.Context, root string, verdict DnsCanaryVerdict) error
}

// The body of POST canary.
type DnsCanaryRequest struct {
	// May be left out with one root.
	Root  string `json:"root,omitempty"`
	Value string `json:"value"`
}

// The answer of POST canary: the serial the write took.
type DnsCanaryAnswer struct {
	Serial uint64 `json:"serial"`
}

// The body of POST canary-report.
type DnsCanaryReport struct {
	// May be left out with one root.
	Root string `json:"root,omitempty"`
	// DnsCanarySourceSite or DnsCanarySourceOutside, as the bearer's class says.
	Source string `json:"source"`
	// The serial the verdict was reached at: the lowest SOA serial the NS served.
	Serial uint64 `json:"serial"`
	Ok     bool   `json:"ok"`
}

// canary.<root>.
func DnsCanaryOwner(root string) string {
	return DnsCanaryLabel + "." + dns.CanonicalName(root)
}

// The TXT RDATA a value is written as: one string, which needs no escape.
func DnsCanaryRdata(value string) string {
	return `"` + value + `"`
}

// The writer's unix milliseconds a canary value starts with, or ErrDnsCanaryRefused for a value no
// canary may hold (see the file header).
func ParseDnsCanaryValue(value string) (int64, error) {
	if value == "" || dnsCanaryValueMaxByteCount < len(value) {
		return 0, fmt.Errorf("%w: a value of %d bytes", ErrDnsCanaryRefused, len(value))
	}
	for index := range len(value) {
		if value[index] < 0x20 || 0x7e < value[index] || value[index] == '"' || value[index] == '\\' {
			return 0, fmt.Errorf("%w: a value that is not printable ASCII", ErrDnsCanaryRefused)
		}
	}
	digits, _, _ := strings.Cut(value, " ")
	unixMilliseconds, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || unixMilliseconds <= 0 {
		return 0, fmt.Errorf("%w: a value that does not start with unix milliseconds", ErrDnsCanaryRefused)
	}
	return unixMilliseconds, nil
}

func (self *DnsApi) canaryRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: DnsCanaryPath, class: DnsCallerMonitor, write: true, serve: self.serveCanary},
		{method: http.MethodPost, path: DnsCanaryReportPath, class: DnsCallerMonitor, alsoClass: DnsCallerMonitorOutside, serve: self.serveCanaryReport},
	}
}

// The labels of the canary counter.
const (
	dnsCanaryResultWritten   = "written"
	dnsCanaryResultReported  = "reported"
	dnsCanaryResultRefused   = "refused"
	dnsCanaryResultRestoring = "restoring"
	dnsCanaryResultFailed    = "failed"
)

// 503 with the gate's Retry-After, for the monitor to try again.
func (self *DnsApi) canaryUnavailable(writer http.ResponseWriter) {
	retryAfter := int(math.Ceil(self.host.GatesOrClosed().RetryAfter().Seconds()))
	writer.Header().Set("Retry-After", strconv.Itoa(max(retryAfter, 1)))
	http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
}

// Reads a canary route's JSON body into value, or answers 400 and false.
func dnsReadCanaryBody(writer http.ResponseWriter, request *http.Request, value any) bool {
	body, err := io.ReadAll(io.LimitReader(request.Body, dnsCanaryRequestMaxByteCount+1))
	if err != nil || dnsCanaryRequestMaxByteCount < len(body) || json.Unmarshal(body, value) != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (self *DnsApi) serveCanary(writer http.ResponseWriter, request *http.Request) {
	if self.deps.Canaries == nil {
		self.metrics.canaries.Add(1, dnsCanaryResultFailed)
		self.canaryUnavailable(writer)
		return
	}
	canary := &DnsCanaryRequest{}
	if !dnsReadCanaryBody(writer, request, canary) {
		return
	}
	root, ok := self.challengeRoot(canary.Root)
	if !ok {
		self.metrics.canaries.Add(1, dnsCanaryResultRefused)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := ParseDnsCanaryValue(canary.Value); err != nil {
		self.metrics.canaries.Add(1, dnsCanaryResultRefused)
		http.Error(writer, "canary refused", http.StatusBadRequest)
		return
	}
	serial, err := self.deps.Canaries.PutCanary(request.Context(), root, canary.Value, self.settings.Ttl.Canary)
	switch {
	case err == nil:
		self.metrics.canaries.Add(1, dnsCanaryResultWritten)
	case errors.Is(err, ErrDnsRestoring):
		self.metrics.canaries.Add(1, dnsCanaryResultRestoring)
		self.canaryUnavailable(writer)
		return
	case errors.Is(err, ErrDnsCanaryRefused):
		self.metrics.canaries.Add(1, dnsCanaryResultRefused)
		http.Error(writer, "canary refused", http.StatusBadRequest)
		return
	default:
		self.metrics.canaries.Add(1, dnsCanaryResultFailed)
		self.log.Errorf("[dns]canary write failed: %v", err)
		self.canaryUnavailable(writer)
		return
	}
	dnsWriteJson(writer, &DnsCanaryAnswer{Serial: serial})
}

func (self *DnsApi) serveCanaryReport(writer http.ResponseWriter, request *http.Request) {
	// the guard took either class; the source must be the one this bearer's class reports
	class, _ := self.deps.Auth.Authenticate(request)
	report := &DnsCanaryReport{}
	if !dnsReadCanaryBody(writer, request, report) {
		return
	}
	root, ok := self.challengeRoot(report.Root)
	wantSource := DnsCanarySourceSite
	if class == DnsCallerMonitorOutside {
		wantSource = DnsCanarySourceOutside
	}
	if !ok || report.Source != wantSource {
		self.metrics.canaries.Add(1, dnsCanaryResultRefused)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	if self.deps.CanaryVerdicts == nil {
		self.metrics.canaries.Add(1, dnsCanaryResultFailed)
		self.canaryUnavailable(writer)
		return
	}
	verdict := DnsCanaryVerdict{Source: report.Source, Serial: report.Serial, Ok: report.Ok, ReportTime: self.clock.Now()}
	if err := self.deps.CanaryVerdicts.PutCanaryVerdict(request.Context(), root, verdict); err != nil {
		self.metrics.canaries.Add(1, dnsCanaryResultFailed)
		dnsStoreUnavailable(writer)
		return
	}
	self.metrics.canaries.Add(1, dnsCanaryResultReported)
	writer.WriteHeader(http.StatusNoContent)
}
