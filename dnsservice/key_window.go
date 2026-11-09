// The DNSKEY window file and its release (§12.6's Keys, D-DNS-5; DNS-M5-19). A ceremony's assemble makes
// the file; vault holds it and the API block's secret_files mount it, one a root, named
// DnsKeyWindowFileName. KeyWindowRelease holds every window of it and serves only the one released now,
// which the feed hands each edge (DnsApiDeps.KeyWindow), so a window not yet released is known to no
// edge and a leaked ZSK's forgeries end with the last window released while it was listed.
//
// One rule serves a window everywhere: of the windows whose release, inception plus
// keys.release_delay_s, is at or before now and which have not ended, the latest to start. A window's
// time to serve ends before keys.min_left_s is all it has left, which the monitor checks from outside
// (DNS-M5-17); a time with no such window is a gap, which release reports and verify and assemble find
// ahead of time.
//
// The file is JSON with a format integer, its windows ascending by inception. Each window is the feed's
// DnsKeyWindow, so what the file holds is what an edge receives.

package dnsservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// The format a window file is written in, and the highest this release reads.
const DnsKeyWindowFileFormat = 1

// A window file that cannot be served from. The wrapping error names the part, and never a key.
var ErrDnsKeyWindowRefused = errors.New("dns key window refused")

// One root's windows, as vault holds them.
type DnsKeyWindowFile struct {
	// Read before anything else, so a file this release does not know stops the reader.
	Format int    `json:"format"`
	Root   string `json:"root"`
	// Ascending by inception, each of Root.
	Windows []DnsKeyWindow `json:"windows"`
}

// A root's window file in secret_files: dns-key-windows-<root>.json, the root without its final dot.
func DnsKeyWindowFileName(root string) string {
	return "dns-key-windows-" + strings.TrimSuffix(dns.CanonicalName(root), ".") + ".json"
}

// Refuses with ErrDnsKeyWindowRefused and what failed.
func dnsKeyWindowRefuse(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrDnsKeyWindowRefused, fmt.Sprintf(format, arguments...))
}

// Reads a window file, stopping at a format this release does not know before reading the rest, and
// holding its shape: a canonical root, at least one window, each of the root, in whole seconds,
// strictly ascending by inception. Signatures are VerifyDnsKeyWindowFile's to check.
func ParseDnsKeyWindowFile(data []byte) (*DnsKeyWindowFile, error) {
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, dnsKeyWindowRefuse("a file that does not read: %v", err)
	}
	if header.Format <= 0 || DnsKeyWindowFileFormat < header.Format {
		return nil, dnsKeyWindowRefuse("format %d", header.Format)
	}
	file := &DnsKeyWindowFile{}
	if err := json.Unmarshal(data, file); err != nil {
		return nil, dnsKeyWindowRefuse("a file that does not read: %v", err)
	}
	if err := file.checkShape(); err != nil {
		return nil, err
	}
	return file, nil
}

// The shape ParseDnsKeyWindowFile holds a file to.
func (self *DnsKeyWindowFile) checkShape() error {
	if err := validateDnsRoot(self.Root); err != nil {
		return dnsKeyWindowRefuse("root: %v", err)
	}
	if len(self.Windows) == 0 {
		return dnsKeyWindowRefuse("no window")
	}
	for index := range self.Windows {
		window := &self.Windows[index]
		if window.Root != self.Root {
			return dnsKeyWindowRefuse("window %d is %s's", index, window.Root)
		}
		if !window.NotBefore.Equal(window.NotBefore.Truncate(time.Second)) || !window.NotAfter.Equal(window.NotAfter.Truncate(time.Second)) {
			return dnsKeyWindowRefuse("window %d's times are not whole seconds", index)
		}
		if !window.NotBefore.Before(window.NotAfter) {
			return dnsKeyWindowRefuse("window %d ends before it starts", index)
		}
		if 0 < index && !self.Windows[index-1].NotBefore.Before(window.NotBefore) {
			return dnsKeyWindowRefuse("window %d starts no later than the one before", index)
		}
	}
	return nil
}

// The file as vault holds it: indented JSON and a final newline, for a person to read.
func (self *DnsKeyWindowFile) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(self, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// When release first serves a window: its inception plus keys.release_delay_s.
func dnsKeyWindowRelease(window *DnsKeyWindow, settings *DnsKeySettings) time.Time {
	return window.NotBefore.Add(dnsSeconds(settings.ReleaseDelaySeconds))
}

// The window served at now (see the file header), or nil. windows ascend by inception.
func dnsServedKeyWindow(windows []*DnsKeyWindow, settings *DnsKeySettings, now time.Time) *DnsKeyWindow {
	for index := len(windows) - 1; 0 <= index; index -= 1 {
		window := windows[index]
		if !now.Before(dnsKeyWindowRelease(window, settings)) && now.Before(window.NotAfter) {
			return window
		}
	}
	return nil
}

// A time when no window is served, or the one served has keys.min_left_s or less.
type DnsKeyWindowGap struct {
	From  time.Time
	Until time.Time
}

// What a window file serves, as verify and assemble report it.
type DnsKeyWindowCoverage struct {
	// The first window's release.
	From time.Time
	// When the last window comes to keys.min_left_s: the next ceremony's windows must be released by
	// then.
	Until time.Time
	// The gaps between From and Until, in order.
	Gaps []DnsKeyWindowGap
}

// Where the windows serve, by a sweep over the times at which the served window or its standing can
// change: each release, each end, and each end less keys.min_left_s. Between two such times the served
// window is one and its standing does not change, so reading it at the first decides the stretch.
func dnsKeyWindowCoverage(windows []*DnsKeyWindow, settings *DnsKeySettings) *DnsKeyWindowCoverage {
	minLeft := dnsSeconds(settings.MinLeftSeconds)
	times := []time.Time{}
	for _, window := range windows {
		times = append(times, dnsKeyWindowRelease(window, settings), window.NotAfter.Add(-minLeft), window.NotAfter)
	}
	slices.SortFunc(times, func(a time.Time, b time.Time) int { return a.Compare(b) })
	times = slices.CompactFunc(times, func(a time.Time, b time.Time) bool { return a.Equal(b) })
	coverage := &DnsKeyWindowCoverage{}
	if len(windows) == 0 {
		return coverage
	}
	coverage.From = dnsKeyWindowRelease(windows[0], settings)
	// each stretch from one time to the next, and whether it is short of a window with over min_left
	type stretch struct {
		from  time.Time
		until time.Time
		short bool
	}
	stretches := []stretch{}
	for index, from := range times {
		if from.Before(coverage.From) {
			continue
		}
		served := dnsServedKeyWindow(windows, settings, from)
		short := served == nil || served.NotAfter.Sub(from) <= minLeft
		until := from
		if index+1 < len(times) {
			until = times[index+1]
		}
		if 0 < len(stretches) && stretches[len(stretches)-1].short == short {
			stretches[len(stretches)-1].until = until
			continue
		}
		stretches = append(stretches, stretch{from: from, until: until, short: short})
	}
	// the last stretch runs past the last time, so it is short: it starts at Until
	coverage.Until = coverage.From
	if 0 < len(stretches) {
		coverage.Until = stretches[len(stretches)-1].from
		for _, stretch := range stretches[:len(stretches)-1] {
			if stretch.short {
				coverage.Gaps = append(coverage.Gaps, DnsKeyWindowGap{From: stretch.from, Until: stretch.until})
			}
		}
	}
	return coverage
}

// Whether one window of root can serve: no longer than keys.window_s, at least one ZSK beside a key a
// configured anchor verifies, and every RRSIG over the DNSKEY RRset at the window's times, one of them
// verifying by an anchor the window publishes with the anchor's flags, as an edge's SelfCheck requires.
func verifyDnsKeyWindow(root string, window *DnsKeyWindow, anchors []*dns.DNSKEY, settings *DnsKeySettings) error {
	if dnsSeconds(settings.WindowSeconds) < window.NotAfter.Sub(window.NotBefore) {
		return errors.New("longer than keys.window_s")
	}
	keySet := DnsRecordSet{Owner: root, Type: dns.TypeDNSKEY, Kind: DnsRecordKindKey, Rdata: window.Dnskeys}
	keyRecords, err := keySet.Records()
	if err != nil || len(keyRecords) == 0 {
		return errors.New("its DNSKEYs do not parse")
	}
	zskCount := 0
	dnskeys := make([]*dns.DNSKEY, 0, len(keyRecords))
	for _, record := range keyRecords {
		key := record.(*dns.DNSKEY)
		dnskeys = append(dnskeys, key)
		if dnsUsableZoneKey(key) && key.Flags&dns.SEP == 0 {
			zskCount += 1
		}
	}
	if zskCount == 0 {
		return errors.New("it lists no ZSK")
	}
	rrsigSet := DnsRecordSet{Owner: root, Type: dns.TypeRRSIG, Kind: DnsRecordKindKey, Rdata: window.Rrsigs}
	rrsigRecords, err := rrsigSet.Records()
	if err != nil || len(rrsigRecords) == 0 {
		return errors.New("its signatures do not parse")
	}
	verified := false
	for _, record := range rrsigRecords {
		rrsig := record.(*dns.RRSIG)
		switch {
		case rrsig.TypeCovered != dns.TypeDNSKEY || dns.CanonicalName(rrsig.SignerName) != root:
			return errors.New("a signature over something else")
		case rrsig.Algorithm != dnsSigningAlgorithm || int(rrsig.Labels) != dns.CountLabel(root):
			return errors.New("a signature of another algorithm or label count")
		case rrsig.Inception != uint32(window.NotBefore.Unix()) || rrsig.Expiration != uint32(window.NotAfter.Unix()):
			return errors.New("a signature whose times are not the window's")
		case rrsig.OrigTtl != rrsigRecords[0].(*dns.RRSIG).OrigTtl:
			return errors.New("signatures that disagree on the TTL")
		}
		rrset := make([]dns.RR, 0, len(dnskeys))
		for _, key := range dnskeys {
			copied := dns.Copy(key)
			copied.Header().Ttl = rrsig.OrigTtl
			rrset = append(rrset, copied)
		}
		for _, anchor := range anchors {
			published := slices.ContainsFunc(dnskeys, func(key *dns.DNSKEY) bool {
				return dnsSameKey(key, anchor) && key.Flags == anchor.Flags
			})
			if published && rrsig.Verify(anchor, rrset) == nil {
				verified = true
			}
		}
	}
	if !verified {
		return errors.New("no signature verifies by a configured KSK it publishes")
	}
	return nil
}

// Rereads a window file offline: its shape, each window by dns.yml's anchors for its root, and where it
// serves. Gaps are reported in the coverage, not refused, since a file read after its quarter has them
// behind it; assemble refuses one ahead.
func VerifyDnsKeyWindowFile(settings *DnsSettings, file *DnsKeyWindowFile) (*DnsKeyWindowCoverage, error) {
	if err := file.checkShape(); err != nil {
		return nil, err
	}
	if !slices.Contains(settings.Roots, file.Root) {
		return nil, dnsKeyWindowRefuse("%s is not a root dns.yml serves", file.Root)
	}
	anchors, err := ParseDnsTrustAnchors(file.Root, settings.TrustAnchors[file.Root])
	if err != nil {
		return nil, dnsKeyWindowRefuse("dns.yml's anchors for %s: %v", file.Root, err)
	}
	windows := make([]*DnsKeyWindow, 0, len(file.Windows))
	for index := range file.Windows {
		window := &file.Windows[index]
		if err := verifyDnsKeyWindow(file.Root, window, anchors, &settings.Keys); err != nil {
			return nil, dnsKeyWindowRefuse("window %d: %v", index, err)
		}
		windows = append(windows, window)
	}
	return dnsKeyWindowCoverage(windows, &settings.Keys), nil
}

// What release serves for a root at one time.
type DnsKeyWindowStatus struct {
	// nil when no window is served.
	Window *DnsKeyWindow
	// How long the served window has left, zero with none.
	Left time.Duration
	// No window is served, or the one served has keys.min_left_s or less.
	Gap bool
}

// The API block's release of the windows (see the file header). Immutable once made but for what it last
// reported, so safe for concurrent use.
type KeyWindowRelease struct {
	settings    *DnsKeySettings
	rootWindows map[string][]*DnsKeyWindow
	log         sidecar.Logger
	// urnetwork_dns_key_window_left_seconds, by root.
	left sidecar.MetricsGauge
	// urnetwork_dns_key_window_gaps_total, by root: each gap counted as it starts.
	gaps sidecar.MetricsCounter

	stateLock sync.Mutex
	// Whether each root was in a gap at its last release, so a gap is counted and logged once.
	rootGaps map[string]bool
}

// Holds files, one a root dns.yml serves, each verified by its anchors first: a file that does not
// verify refuses the whole release, since a block serving a window no edge accepts serves nothing. A
// root with no file has no window, so its edges do not become ready, the closed direction. metrics is
// the block's; log may be nil, to discard.
func NewKeyWindowRelease(settings *DnsSettings, files []*DnsKeyWindowFile, metrics sidecar.Metrics, log sidecar.Logger) (*KeyWindowRelease, error) {
	if metrics == nil {
		return nil, errors.New("key window release needs metrics")
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	self := &KeyWindowRelease{
		settings:    &settings.Keys,
		rootWindows: map[string][]*DnsKeyWindow{},
		log:         log,
		left:        metrics.Gauge("urnetwork_dns_key_window_left_seconds", "Seconds the DNSKEY window released now has left, by root.", "root"),
		gaps:        metrics.Counter("urnetwork_dns_key_window_gaps_total", "Times release found no window with over keys.min_left_s left, by root.", "root"),
		rootGaps:    map[string]bool{},
	}
	for _, file := range files {
		if _, ok := self.rootWindows[file.Root]; ok {
			return nil, dnsKeyWindowRefuse("two files for %s", file.Root)
		}
		if _, err := VerifyDnsKeyWindowFile(settings, file); err != nil {
			return nil, err
		}
		windows := make([]*DnsKeyWindow, 0, len(file.Windows))
		for index := range file.Windows {
			window := file.Windows[index]
			window.Dnskeys = slices.Clone(window.Dnskeys)
			window.Rrsigs = slices.Clone(window.Rrsigs)
			windows = append(windows, &window)
		}
		self.rootWindows[file.Root] = windows
	}
	return self, nil
}

// What is served for root at now. The window is shared and must not be changed.
func (self *KeyWindowRelease) Status(root string, now time.Time) *DnsKeyWindowStatus {
	status := &DnsKeyWindowStatus{Gap: true}
	served := dnsServedKeyWindow(self.rootWindows[dns.CanonicalName(root)], self.settings, now)
	if served != nil {
		status.Window = served
		status.Left = served.NotAfter.Sub(now)
		status.Gap = status.Left <= dnsSeconds(self.settings.MinLeftSeconds)
	}
	return status
}

// The window released for root at now, or nil, as DnsApiDeps.KeyWindow takes it. A window with
// keys.min_left_s or less left is still served, since it is all there is and an edge with none serves
// nothing, and the gap is counted and logged as it starts, beside the monitor's page.
func (self *KeyWindowRelease) Window(root string, now time.Time) *DnsKeyWindow {
	root = dns.CanonicalName(root)
	status := self.Status(root, now)
	self.left.Set(status.Left.Seconds(), root)
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		wasGap := self.rootGaps[root]
		self.rootGaps[root] = status.Gap
		return status.Gap && !wasGap
	}()
	if started {
		self.gaps.Add(1, root)
		self.log.Errorf("[dns]no DNSKEY window with over %d s left for %s: a ceremony's windows are due", self.settings.MinLeftSeconds, root)
	}
	return status.Window
}
