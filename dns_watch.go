//go:build !ios_extension

// D-TRUST-9's zone watch (DNS-M5-22; owner decision 98, §2.8 EX2 and ext-3): a sidecar with a published name, and from
// M7 a mail host, watches its own zone's records through two public resolvers and alarms on changes it did not
// request. It is the only outside view of EX2, so it trusts no server: what it expects is what this device asked for
// and what its local state says, kept in its own store (<state>/net/<id>/dns/), never the API's word.
//
// Each pass, about every Interval with Jitter, asks both resolvers for every watched name and type: the published
// hosts and the apex @, A, AAAA and CAA at each (from M7 also mx, _25._tcp.mx and the DKIM selectors, which the mail
// components add through Watch). For each:
//
//   - the two resolvers' answers must agree; a split is asked once more, and a split that stays alarms (split);
//   - the agreed answer must hold exactly what the device expects where it expects anything, CAA none unless it asked
//     for one (unrequested);
//   - and it must hold what GET /dns/zone shows the device where the zone holds values, and at an owner the edge
//     answers, addresses and no CNAME (zone_mismatch).
//
// A resolver that fails marks the watch degraded, "zone watch degraded" in SidecarStatus, as the CT watch does, and
// that pass judges the other resolver's answer alone, with no split to see; both failing judge nothing. A sidecar
// with no published name and no watched name watches nothing. Lookups go only through DoH (§2.8 ext-3), never a
// URnetwork proxy: the resolver is DnsWatchResolver, whose connect-leg implementation is dns_watch_doh.go.
//
// Values compare in one canonical form a type (canonicalDnsWatchValue), which the resolver's parser and the zone's
// presentation text both reach. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The types the watch asks for (RFC 1035, 3596, 8659, 6698).
const (
	DnsWatchTypeA     uint16 = 1
	DnsWatchTypeCname uint16 = 5
	DnsWatchTypeMx    uint16 = 15
	DnsWatchTypeTxt   uint16 = 16
	DnsWatchTypeAaaa  uint16 = 28
	DnsWatchTypeTlsa  uint16 = 52
	DnsWatchTypeCaa   uint16 = 257
)

// Tunables of the watch.
type DnsWatchSettings struct {
	// About how often a pass runs: D-TRUST-9's 6 hours, like the CT watch.
	Interval time.Duration
	// The most a pass is moved from Interval either way, so devices do not ask in step.
	Jitter time.Duration
	// One lookup's deadline.
	LookupTimeout time.Duration
	// The most names one pass watches, a bound on its work.
	NameMaxCount int
}

func DefaultDnsWatchSettings() *DnsWatchSettings {
	return &DnsWatchSettings{
		Interval:      6 * time.Hour,
		Jitter:        30 * time.Minute,
		LookupTimeout: 10 * time.Second,
		NameMaxCount:  256,
	}
}

// What one resolver answered for one name and type.
type DnsWatchAnswer struct {
	// The name does not exist (NXDOMAIN).
	NameError bool
	// A CNAME the name answered with, canonical, "" for none.
	Cname string
	// The type's records at the name, each in canonicalDnsWatchValue's form, sorted. Empty for NODATA.
	Values []string
}

// Whether two answers say the same.
func (self *DnsWatchAnswer) equal(other *DnsWatchAnswer) bool {
	return self.NameError == other.NameError && self.Cname == other.Cname && slices.Equal(self.Values, other.Values)
}

// The two public resolvers the watch asks (§2.8 ext-3). Safe for concurrent use.
type DnsWatchResolver interface {
	// How many resolvers there are: two.
	ResolverCount() int
	// resolver's answer for name, canonical with its final dot, and qType. An error is the resolver failing, never
	// an answer.
	Lookup(ctx context.Context, resolver int, name string, qType uint16) (*DnsWatchAnswer, error)
}

// One RRset the device expects: the values it asked for, none for a delete.
type DnsWatchExpected struct {
	Name   string   `json:"name"`
	Type   uint16   `json:"type"`
	Values []string `json:"values,omitempty"`
}

// The watch's file in its store.
const dnsWatchFileName = "watch.json"

// The format of the watch's file.
const dnsWatchFileFormat = 1

type dnsWatchFile struct {
	Format   int                 `json:"format"`
	Expected []*DnsWatchExpected `json:"expected"`
	// Names a component asked the watch to watch beyond the published hosts and @.
	Names []string `json:"names,omitempty"`
}

// What the watch says of itself, for SidecarStatus.
type DnsWatchStatus struct {
	// A resolver failed at the last pass: "zone watch degraded".
	Degraded bool
	// When the last pass ended. Zero before any.
	PassTime time.Time
	// The names the last pass watched.
	NameCount int
}

// What NewDnsWatch takes.
type DnsWatchArgs struct {
	Resolver DnsWatchResolver
	// The network's dns/ directory in the sidecar's store.
	Store SidecarStore
	// GET /dns/zone: DnsClient.Zone.
	Zone func(ctx context.Context) (*DnsZone, error)
	// The hosts this sidecar publishes, canonical names (TLS's published-host list).
	PublishedHosts func() []string
	// dns_alarm's events. nil drops them.
	Event SidecarEventFunction
	// nil takes the defaults.
	Settings *DnsWatchSettings
	// nil is real time.
	Clock Clock
}

// The watch. See the file header.
type DnsWatch struct {
	resolver       DnsWatchResolver
	store          SidecarStore
	zone           func(ctx context.Context) (*DnsZone, error)
	publishedHosts func() []string
	event          SidecarEventFunction
	settings       *DnsWatchSettings
	clock          Clock

	cancel context.CancelFunc
	done   chan struct{}

	// one pass at a time
	passLock sync.Mutex

	stateLock sync.Mutex
	file      *dnsWatchFile
	status    DnsWatchStatus
}

// A watch over args, its expectations read from its store, its passes running under ctx until Close.
func NewDnsWatch(ctx context.Context, args *DnsWatchArgs) (*DnsWatch, error) {
	if args == nil || args.Resolver == nil || args.Store == nil || args.Zone == nil || args.PublishedHosts == nil {
		return nil, fmt.Errorf("%w: a dns watch needs its resolver, store, zone and published hosts", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDnsWatchSettings()
	}
	file, err := readDnsWatchFile(args.Store)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	self := &DnsWatch{
		resolver:       args.Resolver,
		store:          args.Store,
		zone:           args.Zone,
		publishedHosts: args.PublishedHosts,
		event:          args.Event,
		settings:       settings,
		clock:          clockOrReal(args.Clock),
		cancel:         cancel,
		done:           make(chan struct{}),
		file:           file,
	}
	go self.run(runCtx)
	return self, nil
}

func readDnsWatchFile(store SidecarStore) (*dnsWatchFile, error) {
	file := &dnsWatchFile{Format: dnsWatchFileFormat}
	reader, err := store.Open(dnsWatchFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return file, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dns watch: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("dns watch: %w", err)
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(file); err != nil || file.Format != dnsWatchFileFormat {
		return nil, fmt.Errorf("dns watch: %s is not this release's", dnsWatchFileName)
	}
	return file, nil
}

// Writes the file changed by change, before anything reads the change.
func (self *DnsWatch) updateFile(change func(file *dnsWatchFile)) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := &dnsWatchFile{Format: dnsWatchFileFormat, Names: slices.Clone(self.file.Names)}
	for _, expected := range self.file.Expected {
		entry := *expected
		entry.Values = slices.Clone(expected.Values)
		copied.Expected = append(copied.Expected, &entry)
	}
	change(copied)
	data, err := json.Marshal(copied)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(dnsWatchFileName)
	if err != nil {
		return fmt.Errorf("dns watch: %w", err)
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("dns watch: %w", err)
	}
	if err := writer.Commit(); err != nil {
		return fmt.Errorf("dns watch: %w", err)
	}
	self.file = copied
	return nil
}

// Records that this device asked for name's qType RRset to hold values, each one record's presentation RDATA, or for
// none: what DnsClient's writes call once the zone took them, so the watch alarms on no change this device made.
func (self *DnsWatch) Expect(name string, qType uint16, values []string) error {
	name = CanonicalDnsRecordName(name)
	canonical := []string{}
	for _, value := range values {
		canonical = append(canonical, canonicalDnsWatchValue(qType, value))
	}
	slices.Sort(canonical)
	return self.updateFile(func(file *dnsWatchFile) {
		file.Expected = slices.DeleteFunc(file.Expected, func(expected *DnsWatchExpected) bool {
			return expected.Name == name && expected.Type == qType
		})
		file.Expected = append(file.Expected, &DnsWatchExpected{Name: name, Type: qType, Values: canonical})
	})
}

// Adds name to every pass, beside the published hosts and @: a mail host, its TLSA owner or a DKIM selector (M7).
func (self *DnsWatch) Watch(name string) error {
	name = CanonicalDnsRecordName(name)
	return self.updateFile(func(file *dnsWatchFile) {
		if !slices.Contains(file.Names, name) {
			file.Names = append(file.Names, name)
		}
	})
}

// The watch's own view, for SidecarStatus.
func (self *DnsWatch) Status() DnsWatchStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.status
}

// Whether a resolver failed at the last pass: SidecarStatus's "zone watch degraded".
func (self *DnsWatch) Degraded() bool {
	return self.Status().Degraded
}

// Ends the passes and waits for the one running.
func (self *DnsWatch) Close() {
	self.cancel()
	<-self.done
}

// Runs a pass about every Interval, jittered, until ctx ends.
func (self *DnsWatch) run(ctx context.Context) {
	defer close(self.done)
	for {
		wait := self.settings.Interval
		if 0 < self.settings.Jitter {
			wait += time.Duration(rand.Int64N(int64(2*self.settings.Jitter))) - self.settings.Jitter
		}
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(max(wait, time.Second)):
		}
		self.Pass(ctx)
	}
}

// One name and type a pass asks about, and what it expects there.
type dnsWatchItem struct {
	name  string
	qType uint16
	// the device's own expectation, nil for none
	expected *DnsWatchExpected
	// the zone's RRset there, nil for none
	zone *DnsZoneRecordSet
	// A or AAAA at a host this sidecar publishes and the zone holds no row at, which the edge answers through *
	// (§12.7)
	edge bool
}

// Runs one pass now and answers whether it alarmed. A pass with nothing to watch asks nothing.
func (self *DnsWatch) Pass(ctx context.Context) bool {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	items, err := self.items(ctx)
	if err != nil {
		// no zone, so no expectation the pass could hold the resolvers to: the next pass tries again
		return false
	}
	degraded := false
	alarmed := false
	for _, item := range items {
		answers := self.lookup(ctx, item)
		if len(answers) < self.resolver.ResolverCount() {
			degraded = true
		}
		if len(answers) == 0 {
			continue
		}
		if 1 < len(answers) && !answers[0].equal(answers[1]) {
			// a split is asked once more before it alarms, so a health drop between the two answers does not
			again := self.lookup(ctx, item)
			if len(again) == 2 && !again[0].equal(again[1]) {
				self.alarm(SidecarDnsAlarmSplit)
				alarmed = true
				continue
			}
			if 0 < len(again) {
				answers = again
			}
		}
		if alarm, ok := judgeDnsWatchAnswer(item, answers[0]); !ok {
			self.alarm(alarm)
			alarmed = true
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.status = DnsWatchStatus{Degraded: degraded, PassTime: self.clock.Now(), NameCount: len(items)}
	}()
	return alarmed
}

// Every resolver's answer for item that came, in resolver order.
func (self *DnsWatch) lookup(ctx context.Context, item *dnsWatchItem) []*DnsWatchAnswer {
	answers := []*DnsWatchAnswer{}
	for resolver := range self.resolver.ResolverCount() {
		answer, err := func() (*DnsWatchAnswer, error) {
			lookupCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stop := self.clock.AfterFunc(self.settings.LookupTimeout, cancel)
			defer stop()
			return self.resolver.Lookup(lookupCtx, resolver, item.name, item.qType)
		}()
		if err == nil && answer != nil {
			slices.Sort(answer.Values)
			answers = append(answers, answer)
		}
	}
	return answers
}

// Raises one dns_alarm.
func (self *DnsWatch) alarm(alarm SidecarDnsAlarm) {
	if self.event != nil {
		self.event(SidecarEvent{Kind: SidecarEventDnsAlarm, DnsAlarm: alarm})
	}
}

// The names and types a pass asks about: A, AAAA and CAA at each published host and at @, and each type the device
// expects at a name. Nothing when no host is published and no name watched.
func (self *DnsWatch) items(ctx context.Context) ([]*dnsWatchItem, error) {
	file := func() *dnsWatchFile {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.file
	}()
	hosts := []string{}
	for _, host := range self.publishedHosts() {
		hosts = append(hosts, CanonicalDnsRecordName(host))
	}
	if len(hosts) == 0 && len(file.Names) == 0 && len(file.Expected) == 0 {
		return nil, nil
	}
	zone, err := self.zone(ctx)
	if err != nil {
		return nil, err
	}
	names := slices.Clone(hosts)
	if apex := zone.Apex(); apex != "" && 0 < len(hosts) && !slices.Contains(names, apex) {
		names = append(names, apex)
	}
	for _, name := range file.Names {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	// owners the zone holds rows at, which * does not cover (RFC 4592)
	ownersWithRows := map[string]bool{}
	for _, recordSet := range zone.RecordSets {
		ownersWithRows[CanonicalDnsRecordName(recordSet.Name)] = true
	}
	keys := map[string]bool{}
	items := []*dnsWatchItem{}
	add := func(name string, qType uint16) {
		key := name + " " + strconv.Itoa(int(qType))
		if keys[key] || self.settings.NameMaxCount <= len(items) {
			return
		}
		keys[key] = true
		item := &dnsWatchItem{name: name, qType: qType}
		item.edge = slices.Contains(hosts, name) && !ownersWithRows[name] && (qType == DnsWatchTypeA || qType == DnsWatchTypeAaaa)
		for _, expected := range file.Expected {
			if expected.Name == name && expected.Type == qType {
				item.expected = expected
			}
		}
		for index := range zone.RecordSets {
			recordSet := &zone.RecordSets[index]
			if CanonicalDnsRecordName(recordSet.Name) == name && dnsWatchTypeOf(recordSet.Type) == qType {
				item.zone = recordSet
			}
		}
		items = append(items, item)
	}
	for _, name := range names {
		for _, qType := range []uint16{DnsWatchTypeA, DnsWatchTypeAaaa, DnsWatchTypeCaa} {
			add(name, qType)
		}
	}
	for _, expected := range file.Expected {
		add(expected.Name, expected.Type)
	}
	return items, nil
}

// The type a mnemonic names, zero for one the watch does not ask about.
func dnsWatchTypeOf(mnemonic string) uint16 {
	switch mnemonic {
	case "A":
		return DnsWatchTypeA
	case "AAAA":
		return DnsWatchTypeAaaa
	case "CNAME":
		return DnsWatchTypeCname
	case "MX":
		return DnsWatchTypeMx
	case "TXT":
		return DnsWatchTypeTxt
	case "TLSA":
		return DnsWatchTypeTlsa
	case "CAA":
		return DnsWatchTypeCaa
	}
	return 0
}

// Whether answer is what item expects, and the alarm when it is not: the device's own expectation first, then the
// zone's values, then the edge's shape, and a CAA the device did not ask for is unrequested.
func judgeDnsWatchAnswer(item *dnsWatchItem, answer *DnsWatchAnswer) (SidecarDnsAlarm, bool) {
	if item.expected != nil {
		if answer.Cname != "" || !slices.Equal(answer.Values, item.expected.Values) {
			return SidecarDnsAlarmUnrequested, false
		}
		return "", true
	}
	if item.zone != nil && 0 < len(item.zone.Values) {
		zoneValues := []string{}
		for _, value := range item.zone.Values {
			zoneValues = append(zoneValues, canonicalDnsWatchValue(item.qType, value))
		}
		slices.Sort(zoneValues)
		if answer.Cname != "" || !slices.Equal(answer.Values, zoneValues) {
			return SidecarDnsAlarmZoneMismatch, false
		}
		return "", true
	}
	if item.qType == DnsWatchTypeCaa {
		if answer.Cname != "" || 0 < len(answer.Values) {
			return SidecarDnsAlarmUnrequested, false
		}
		return "", true
	}
	if item.zone != nil || item.edge {
		// an edge or router row, or a published host the edge answers through * or @: the healthy interfaces'
		// addresses, never a CNAME, and which of them the device cannot know apart
		if answer.Cname != "" || answer.NameError || len(answer.Values) == 0 {
			return SidecarDnsAlarmZoneMismatch, false
		}
		return "", true
	}
	// nothing expected and nothing in the zone: records here are no one's the device knows
	if answer.Cname != "" || 0 < len(answer.Values) {
		return SidecarDnsAlarmUnrequested, false
	}
	return "", true
}

// value, one record's RDATA in presentation form, in the one form the watch compares: an address as netip writes it;
// a TXT's strings unquoted and joined; names lowercase with their final dot; a TLSA's hex uppercase; a CAA's value
// unquoted; anything else its fields joined by one space.
func canonicalDnsWatchValue(qType uint16, value string) string {
	fields := strings.Fields(value)
	switch qType {
	case DnsWatchTypeA, DnsWatchTypeAaaa:
		if address, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
			return address.Unmap().String()
		}
	case DnsWatchTypeTxt:
		return dnsWatchTxtText(value)
	case DnsWatchTypeMx:
		if len(fields) == 2 {
			return fields[0] + " " + CanonicalDnsRecordName(fields[1])
		}
	case DnsWatchTypeCname:
		return CanonicalDnsRecordName(value)
	case DnsWatchTypeTlsa:
		if len(fields) == 4 {
			return fields[0] + " " + fields[1] + " " + fields[2] + " " + strings.ToUpper(fields[3])
		}
	case DnsWatchTypeCaa:
		if len(fields) >= 3 {
			return fields[0] + " " + strings.ToLower(fields[1]) + " " + strings.Trim(strings.Join(fields[2:], " "), `"`)
		}
	}
	return strings.Join(fields, " ")
}

// A TXT record's presentation text as its strings joined, each unquoted with its \X escapes undone.
func dnsWatchTxtText(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, `"`) {
		return value
	}
	var text strings.Builder
	inQuote := false
	for index := 0; index < len(value); index += 1 {
		character := value[index]
		switch {
		case character == '"':
			inQuote = !inQuote
		case character == '\\' && index+1 < len(value):
			index += 1
			text.WriteByte(value[index])
		case inQuote:
			text.WriteByte(character)
		}
	}
	return text.String()
}
