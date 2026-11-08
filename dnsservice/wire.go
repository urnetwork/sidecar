// What the journal, snapshots and the feed carry (§12.6). The encoding is JSON with a format integer,
// and a snapshot is newline-delimited JSON, so nothing buffers a zone (plan reading 5).
//
// Readers and writers on releases N and N+1 share these, so two rules hold them (§12.6, §19.11). N
// ignores a field N+1 adds, which encoding/json does. A row N cannot read carries a higher format,
// and a reader stops at it rather than half-applying it, keeping its last good view, while N+1 waits
// to write such rows until it serves 100%.
//
// A serial is the root's bigint (plan reading 4), which an edge compares whole. The SOA carries its
// low 32 bits, and everything on the wire or against an SOA compares by RFC 1982.

package dnsservice

import (
	"bufio"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The format this release writes and the highest it reads. N+1 raises it only for what N cannot read.
const DnsFormat = 1

// RFC 2181 §8: a TTL's top bit is clear.
const dnsTtlMaxSeconds = math.MaxInt32

// The most one line of a snapshot may hold: an RRset is at most a 64 KiB message, which presentation
// form at most quadruples, with room for the JSON around it. A format value, so a malformed stream
// costs a bounded buffer.
const dnsSnapshotLineMaxByteCount = 1024 * 1024

var (
	// A reader met a format above DnsFormat. It stops there and keeps its last good view.
	ErrDnsFormatTooNew = errors.New("dns format too new")
	// A row or answer that breaks this file's rules. Nothing of it is applied.
	ErrDnsRowMalformed = errors.New("dns row malformed")
	// A row above the next serial: the reader missed something, so it refuses this and asks again.
	ErrDnsSerialGap = errors.New("dns serial gap")
	// A row at or below the reader's serial with no reload. A view never lowers (DNS-M5-06).
	ErrDnsSerialLower = errors.New("dns serial lower")
)

// What a row is for, and so how it answers. Every kind but edge, router and copy answers its own
// rdata.
type DnsRecordKind string

const (
	// A network's own record, one dns_entries unit an RRset (§12.7).
	DnsRecordKindUser DnsRecordKind = "user"
	// A record §12.7's system table fixes.
	DnsRecordKindSystem DnsRecordKind = "system"
	// A copy of the wildcard's records at an owner that would otherwise block it (D-DNS-11): one row
	// an owner, of type DnsCopyType with no rdata, answered from the wildcard at answer time.
	DnsRecordKindCopy DnsRecordKind = "copy"
	// A or AAAA with no rdata, answered from the healthy lb interfaces at answer time.
	DnsRecordKindEdge DnsRecordKind = "edge"
	// A or AAAA with no rdata, answered from the healthy router interfaces at answer time.
	DnsRecordKindRouter DnsRecordKind = "router"
	// A DNS-01 TXT, which only certs writes (D-DNS-8) and which expires after 1 h.
	DnsRecordKindChallenge DnsRecordKind = "challenge"
	// A monitor's canary or a strong-mode probe's CAA (§12.6, §12.8).
	DnsRecordKindCanary DnsRecordKind = "canary"
	// A record naming a device's key: TLSA or DKIM TXT (§12.8).
	DnsRecordKindKey DnsRecordKind = "key"
)

// The type a copy row holds, since one row stands for every type at the wildcard. RFC 1035 reserves
// type zero, so it can name no real RRset.
const DnsCopyType uint16 = dns.TypeNone

// Whether this is a kind this release answers.
func (self DnsRecordKind) known() bool {
	switch self {
	case DnsRecordKindUser, DnsRecordKindSystem, DnsRecordKindCopy, DnsRecordKindEdge, DnsRecordKindRouter,
		DnsRecordKindChallenge, DnsRecordKindCanary, DnsRecordKindKey:
		return true
	}
	return false
}

// One RRset's name. Owner is canonical: lowercase and fully qualified, in the root's one namespace,
// with no escape, so a name has one spelling. Type is its IANA number, so a type with no mnemonic in
// this release still reads, and DnsCopyType names a copy row. Comparable, so it keys maps.
type DnsRecordKey struct {
	Owner string `json:"owner"`
	Type  uint16 `json:"type"`
}

// One RRset at one serial.
type DnsRecordSet struct {
	Owner string `json:"owner"`
	Type  uint16 `json:"type"`
	// Seconds. An edge or router row's is the answer's. A copy row's means nothing, since a copy
	// answers with the wildcard's.
	Ttl  uint32        `json:"ttl"`
	Kind DnsRecordKind `json:"kind"`
	// One presentation-form RDATA a record, without owner, TTL, class or type. Empty on edge, router
	// and copy rows, which hold no addresses.
	Rdata []string `json:"rdata,omitempty"`
}

// Where this RRset sits.
func (self *DnsRecordSet) Key() DnsRecordKey {
	return DnsRecordKey{Owner: self.Owner, Type: self.Type}
}

// A copy that shares nothing with this one.
func (self *DnsRecordSet) Clone() DnsRecordSet {
	clone := *self
	clone.Rdata = slices.Clone(self.Rdata)
	return clone
}

// The mnemonic NewRR reads, or RFC 3597's TYPE<n>.
func dnsTypeText(rrType uint16) string {
	if text, ok := dns.TypeToString[rrType]; ok {
		return text
	}
	return "TYPE" + strconv.Itoa(int(rrType))
}

// Each rdata as a record of this owner, type and TTL. Parsing starts from a fixed owner, so nothing in
// Owner can reach the zone-file parser as syntax, and refuses what could: a line break would end the
// record early and pass what follows unread.
func (self *DnsRecordSet) Records() ([]dns.RR, error) {
	records := make([]dns.RR, 0, len(self.Rdata))
	typeText := dnsTypeText(self.Type)
	for _, rdata := range self.Rdata {
		if strings.ContainsAny(rdata, "\n\r\x00") {
			return nil, fmt.Errorf("%w: %s rdata holds a line break", ErrDnsRowMalformed, typeText)
		}
		record, err := dns.NewRR(". IN " + typeText + " " + rdata)
		if err != nil {
			return nil, fmt.Errorf("%w: %s rdata: %w", ErrDnsRowMalformed, typeText, err)
		}
		if record == nil || record.Header().Rrtype != self.Type {
			return nil, fmt.Errorf("%w: %s rdata is not of that type", ErrDnsRowMalformed, typeText)
		}
		record.Header().Name = self.Owner
		record.Header().Ttl = self.Ttl
		records = append(records, record)
	}
	return records, nil
}

// Whether a row may hold this type. Meta-types are no data, and the signer alone makes what DNSSEC
// adds: a DNSKEY answers only from the released window (DNS-M5-04).
func dnsTypeStorable(rrType uint16) bool {
	switch rrType {
	case dns.TypeNone, dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB,
		dns.TypeANY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDNSKEY, dns.TypeNXNAME:
		return false
	}
	return true
}

// Whether owner is a canonical name at or below root.
func validateDnsOwner(root string, owner string) error {
	if _, ok := dns.IsDomainName(owner); !ok || !dns.IsFqdn(owner) {
		return fmt.Errorf("%w: owner %q is not a name", ErrDnsRowMalformed, owner)
	}
	if owner != strings.ToLower(owner) || strings.IndexByte(owner, '\\') != -1 {
		return fmt.Errorf("%w: owner %q is not canonical", ErrDnsRowMalformed, owner)
	}
	if !dns.IsSubDomain(root, owner) {
		return fmt.Errorf("%w: owner %q is outside %s", ErrDnsRowMalformed, owner, root)
	}
	return nil
}

// Whether this key can name a row under root.
func (self *DnsRecordKey) Validate(root string) error {
	if err := validateDnsOwner(root, self.Owner); err != nil {
		return err
	}
	if self.Type != DnsCopyType && !dnsTypeStorable(self.Type) {
		return fmt.Errorf("%w: type %s", ErrDnsRowMalformed, dnsTypeText(self.Type))
	}
	return nil
}

// Whether this RRset is well formed for root, by the rules that do not change between releases: the
// write path holds every row to this, and a reader refuses what fails it. What §12.7 refuses of a
// user is a later and a moving rule, which DNS-M5-02 holds at the write and a ZoneView at the answer.
func (self *DnsRecordSet) Validate(root string) error {
	_, err := self.parse(root)
	return err
}

// Validate's work, keeping the records for a caller that goes on to serve them. None on edge, router
// and copy rows.
func (self *DnsRecordSet) parse(root string) ([]dns.RR, error) {
	if err := validateDnsOwner(root, self.Owner); err != nil {
		return nil, err
	}
	if !self.Kind.known() {
		return nil, fmt.Errorf("%w: kind %q", ErrDnsRowMalformed, self.Kind)
	}
	if dnsTtlMaxSeconds < self.Ttl {
		return nil, fmt.Errorf("%w: ttl %d", ErrDnsRowMalformed, self.Ttl)
	}
	switch self.Kind {
	case DnsRecordKindCopy:
		if self.Type != DnsCopyType || len(self.Rdata) != 0 {
			return nil, fmt.Errorf("%w: a copy row holds no type or rdata", ErrDnsRowMalformed)
		}
		return nil, nil
	case DnsRecordKindEdge, DnsRecordKindRouter:
		if (self.Type != dns.TypeA && self.Type != dns.TypeAAAA) || len(self.Rdata) != 0 {
			return nil, fmt.Errorf("%w: an %s row is A or AAAA with no rdata", ErrDnsRowMalformed, self.Kind)
		}
		return nil, nil
	}
	if !dnsTypeStorable(self.Type) {
		return nil, fmt.Errorf("%w: type %s", ErrDnsRowMalformed, dnsTypeText(self.Type))
	}
	if len(self.Rdata) == 0 {
		return nil, fmt.Errorf("%w: %s holds no rdata", ErrDnsRowMalformed, dnsTypeText(self.Type))
	}
	// RFC 2181 §10.1 and RFC 1035 §5.2: a name has one canonical name, and a zone one SOA
	if (self.Type == dns.TypeCNAME || self.Type == dns.TypeSOA) && 1 < len(self.Rdata) {
		return nil, fmt.Errorf("%w: more than one %s", ErrDnsRowMalformed, dnsTypeText(self.Type))
	}
	records, err := self.Records()
	if err != nil {
		return nil, err
	}
	for index, record := range records {
		for _, earlier := range records[:index] {
			if dns.IsDuplicate(record, earlier) {
				return nil, fmt.Errorf("%w: %s repeats a record", ErrDnsRowMalformed, dnsTypeText(self.Type))
			}
		}
	}
	return records, nil
}

// One write's diff: serial n's upserts and deletes, which take the root from n-1 to n whole. An upsert
// replaces the RRset at its key, and a key appears at most once in a row.
type DnsJournalRow struct {
	// Read before anything else in the row, so a shape this release does not know stops the reader
	// rather than failing as something else.
	Format int `json:"format"`
	// Canonical, as settings give it.
	Root    string         `json:"root"`
	Serial  uint64         `json:"serial"`
	Upserts []DnsRecordSet `json:"upserts,omitempty"`
	Deletes []DnsRecordKey `json:"deletes,omitempty"`
}

// Whether a reader can apply this row. A row of a higher format fails with ErrDnsFormatTooNew, and any
// other fault with ErrDnsRowMalformed.
func (self *DnsJournalRow) Validate() error {
	if err := self.validateHead(); err != nil {
		return err
	}
	for index := range self.Upserts {
		if err := self.Upserts[index].Validate(self.Root); err != nil {
			return err
		}
	}
	return nil
}

// Validate's work on everything but each upsert's own rules, for a reader that parses those anyway.
func (self *DnsJournalRow) validateHead() error {
	if err := checkDnsFormat(self.Format); err != nil {
		return err
	}
	if err := validateDnsRoot(self.Root); err != nil {
		return fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if self.Serial == 0 {
		return fmt.Errorf("%w: serial zero", ErrDnsRowMalformed)
	}
	if len(self.Upserts) == 0 && len(self.Deletes) == 0 {
		return fmt.Errorf("%w: an empty row", ErrDnsRowMalformed)
	}
	keys := make(map[DnsRecordKey]bool, len(self.Upserts)+len(self.Deletes))
	note := func(key DnsRecordKey) error {
		if keys[key] {
			return fmt.Errorf("%w: %s %s twice in one row", ErrDnsRowMalformed, key.Owner, dnsTypeText(key.Type))
		}
		keys[key] = true
		return nil
	}
	for index := range self.Upserts {
		if err := note(self.Upserts[index].Key()); err != nil {
			return err
		}
	}
	for index := range self.Deletes {
		key := &self.Deletes[index]
		if err := key.Validate(self.Root); err != nil {
			return err
		}
		if err := note(*key); err != nil {
			return err
		}
	}
	return nil
}

// Whether this release reads format. Zero means the field was missing.
func checkDnsFormat(format int) error {
	if format <= 0 {
		return fmt.Errorf("%w: format %d", ErrDnsRowMalformed, format)
	}
	if DnsFormat < format {
		return fmt.Errorf("%w: %d above %d", ErrDnsFormatTooNew, format, DnsFormat)
	}
	return nil
}

// Reads one row, stopping at a format this release does not know before reading the rest.
func DecodeDnsJournalRow(data []byte) (*DnsJournalRow, error) {
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := checkDnsFormat(header.Format); err != nil {
		return nil, err
	}
	row := &DnsJournalRow{}
	if err := json.Unmarshal(data, row); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := row.Validate(); err != nil {
		return nil, err
	}
	return row, nil
}

// One lb interface as a feed answer names it (§12.6): where an edge probes and what it may answer,
// which is how an edge knows the inventory with no vault of its own (plan reading 6). The four map
// fields are M6's (§13.4), declared now so DNS-M6-04 needs no server work, and zero until then.
type DnsLbInterface struct {
	// An inventory id, stable across answers, which reports and the drained list use.
	Name string `json:"name"`
	// The zero value where the interface has no address of the family.
	Ipv4 netip.Addr `json:"ipv4"`
	Ipv6 netip.Addr `json:"ipv6"`
	// On §19.5's router list, so it serves mx hosts and takes the 25 banner probe.
	Router bool `json:"router,omitempty"`
	// The custom-host map version this interface last reported loading.
	ReportedVersion uint64 `json:"reported_version,omitempty"`
	// That version's probe name, <digest[0:12]>.map.probe.invalid.
	ProbeName string `json:"probe_name,omitempty"`
	// The hosts that version added, which the route probes take once each (§13.4).
	AddedHosts []string `json:"added_hosts,omitempty"`
	// Not current for a version over 20 min old, so edges drop it, never all (§13.4).
	MapStale bool `json:"map_stale,omitempty"`
}

// One released DNSKEY window (§12.6): the RRset and the KSK's signatures over it for 14 days, which is
// all an edge holds of the KSK. DNS-M5-19 makes these, and the file format is its own.
type DnsKeyWindow struct {
	Root string `json:"root"`
	// The RRSIGs' inception.
	NotBefore time.Time `json:"not_before"`
	// The RRSIGs' expiration, which the monitor holds over 7 d away.
	NotAfter time.Time `json:"not_after"`
	// The RRset, one presentation-form RDATA a record: the KSK and the current, next and standby ZSKs.
	Dnskeys []string `json:"dnskeys"`
	// The KSK's RRSIGs over it, one presentation-form RDATA a record.
	Rrsigs []string `json:"rrsigs"`
}

// What an edge signs with: a released window, and the current ZSK from secret_files, which never
// leaves the edge. Not a wire type, unlike the window: the json tag keeps a marshalled set from
// holding a key.
type DnsKeySet struct {
	Window *DnsKeyWindow `json:"window"`
	Zsk    crypto.Signer `json:"-"`
}

// One answer of GET /dns/journal: rows, or reload, or neither when a hold ended with nothing new.
type DnsFeedAnswer struct {
	Format int    `json:"format"`
	Root   string `json:"root"`
	// The root's serial as this answer was made.
	Serial uint64 `json:"serial"`
	// The last restore's serial, zero before any. A replaced snapshot older than this waits for its
	// diff (§12.6).
	RestoreSerial uint64 `json:"restore_serial"`
	// The journal cannot continue from the caller's serial: fetch a snapshot. Rows is then empty.
	Reload bool `json:"reload,omitempty"`
	// In serial order from the caller's serial plus one, with no hole.
	Rows []DnsJournalRow `json:"rows,omitempty"`
	// Every lb interface, on every answer, so an edge keeps the list through a core outage.
	Interfaces []DnsLbInterface `json:"interfaces,omitempty"`
	// The window now released, absent until one is (DNS-M5-19).
	KeyWindow *DnsKeyWindow `json:"key_window,omitempty"`
}

// Whether a reader can act on this answer, under the rules a row is held to.
func (self *DnsFeedAnswer) Validate() error {
	if err := checkDnsFormat(self.Format); err != nil {
		return err
	}
	if err := validateDnsRoot(self.Root); err != nil {
		return fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if self.Reload && len(self.Rows) != 0 {
		return fmt.Errorf("%w: reload with rows", ErrDnsRowMalformed)
	}
	for index := range self.Rows {
		row := &self.Rows[index]
		if err := row.Validate(); err != nil {
			return err
		}
		if row.Root != self.Root {
			return fmt.Errorf("%w: a row of %s in %s's answer", ErrDnsRowMalformed, row.Root, self.Root)
		}
		if 0 < index && row.Serial != self.Rows[index-1].Serial+1 {
			return fmt.Errorf("%w: rows are not consecutive", ErrDnsRowMalformed)
		}
	}
	return nil
}

// Reads one answer. A format this release does not know, on the answer or on any row, refuses the
// whole answer before the rest is read, so the reader keeps its last good view and asks again.
func DecodeDnsFeedAnswer(data []byte) (*DnsFeedAnswer, error) {
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := checkDnsFormat(header.Format); err != nil {
		return nil, err
	}
	var headers struct {
		Rows []struct {
			Format int `json:"format"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(data, &headers); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	for _, row := range headers.Rows {
		if err := checkDnsFormat(row.Format); err != nil {
			return nil, err
		}
	}
	answer := &DnsFeedAnswer{}
	if err := json.Unmarshal(data, answer); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := answer.Validate(); err != nil {
		return nil, err
	}
	return answer, nil
}

// What POST /dns/reload-diff carries after a reload across a restore: the RRsets that differ between
// the snapshot an edge replaced and the new one, which §12.6's restore step maps to networks.
type DnsReloadDiff struct {
	Root           string         `json:"root"`
	ReplacedSerial uint64         `json:"replaced_serial"`
	Serial         uint64         `json:"serial"`
	Rrsets         []DnsRecordKey `json:"rrsets"`
}

// The first line of a snapshot: one root at one serial, every row of which follows.
type DnsSnapshot struct {
	Format        int    `json:"format"`
	Root          string `json:"root"`
	Serial        uint64 `json:"serial"`
	RestoreSerial uint64 `json:"restore_serial"`
}

// The last line of a snapshot, which tells a whole stream from one cut short.
type dnsSnapshotEnd struct {
	End      bool   `json:"end"`
	RowCount uint64 `json:"row_count"`
}

// One root's rows at one serial, pulled a row at a time so neither end buffers a zone. Not safe for
// concurrent use.
type DnsSnapshotRows interface {
	// The serial every row is at.
	Snapshot() DnsSnapshot
	// The next row, or io.EOF after the last. Any other error means the snapshot is not whole, and
	// nothing read so far may be served.
	Next() (*DnsRecordSet, error)
	// Ends the read and releases what it holds: a store's transaction, a stream. Safe after an error,
	// and more than once.
	Close() error
}

// Rows already in memory, for a fake or a test.
type dnsSnapshotSlice struct {
	snapshot DnsSnapshot
	rows     []DnsRecordSet
}

// Serves rows as a DnsSnapshotRows. Takes the slice, which the caller no longer changes.
func NewDnsSnapshotRows(snapshot DnsSnapshot, rows []DnsRecordSet) DnsSnapshotRows {
	return &dnsSnapshotSlice{snapshot: snapshot, rows: rows}
}

// The first line's values.
func (self *dnsSnapshotSlice) Snapshot() DnsSnapshot {
	return self.snapshot
}

// The next row of the slice.
func (self *dnsSnapshotSlice) Next() (*DnsRecordSet, error) {
	if len(self.rows) == 0 {
		return nil, io.EOF
	}
	row := &self.rows[0]
	self.rows = self.rows[1:]
	return row, nil
}

// Holds nothing to release.
func (self *dnsSnapshotSlice) Close() error {
	return nil
}

// Writes a snapshot's lines as its rows arrive. Not safe for concurrent use.
type DnsSnapshotWriter struct {
	writer   io.Writer
	rowCount uint64
}

// Writes the first line.
func NewDnsSnapshotWriter(writer io.Writer, snapshot DnsSnapshot) (*DnsSnapshotWriter, error) {
	self := &DnsSnapshotWriter{writer: writer}
	if err := self.writeLine(snapshot); err != nil {
		return nil, err
	}
	return self, nil
}

// Writes one value and its newline.
func (self *DnsSnapshotWriter) writeLine(value any) error {
	line, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = self.writer.Write(append(line, '\n'))
	return err
}

// Writes one row.
func (self *DnsSnapshotWriter) Write(row *DnsRecordSet) error {
	self.rowCount += 1
	return self.writeLine(row)
}

// Writes the last line. A stream without it reads as cut short.
func (self *DnsSnapshotWriter) Close() error {
	return self.writeLine(dnsSnapshotEnd{End: true, RowCount: self.rowCount})
}

// Reads a snapshot's lines.
type dnsSnapshotStream struct {
	snapshot DnsSnapshot
	scanner  *bufio.Scanner
	closer   io.Closer
	rowCount uint64
	ended    bool
}

// Reads the first line and leaves the rest for Next, holding each row to the root's rules, so a
// reader sees only rows it could apply. A stream of a format this release does not know stops here.
// When reader is also an io.Closer, Close closes it.
func NewDnsSnapshotReader(reader io.Reader) (DnsSnapshotRows, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(nil, dnsSnapshotLineMaxByteCount)
	self := &dnsSnapshotStream{scanner: scanner}
	if closer, ok := reader.(io.Closer); ok {
		self.closer = closer
	}
	line, err := self.nextLine()
	if err != nil {
		return nil, err
	}
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(line, &header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := checkDnsFormat(header.Format); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(line, &self.snapshot); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := validateDnsRoot(self.snapshot.Root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	return self, nil
}

// One line, which a stream that ends early turns into an error.
func (self *dnsSnapshotStream) nextLine() ([]byte, error) {
	if self.scanner.Scan() {
		return self.scanner.Bytes(), nil
	}
	if err := self.scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, io.ErrUnexpectedEOF)
}

// The first line's values.
func (self *dnsSnapshotStream) Snapshot() DnsSnapshot {
	return self.snapshot
}

// The next row, or io.EOF once the last line has counted the rows.
func (self *dnsSnapshotStream) Next() (*DnsRecordSet, error) {
	if self.ended {
		return nil, io.EOF
	}
	line, err := self.nextLine()
	if err != nil {
		return nil, err
	}
	var end dnsSnapshotEnd
	if err := json.Unmarshal(line, &end); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if end.End {
		if end.RowCount != self.rowCount {
			return nil, fmt.Errorf("%w: %d rows where the end counts %d", ErrDnsRowMalformed, self.rowCount, end.RowCount)
		}
		if self.scanner.Scan() {
			return nil, fmt.Errorf("%w: a line past the end", ErrDnsRowMalformed)
		}
		self.ended = true
		return nil, io.EOF
	}
	row := &DnsRecordSet{}
	if err := json.Unmarshal(line, row); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := row.Validate(self.snapshot.Root); err != nil {
		return nil, err
	}
	self.rowCount += 1
	return row, nil
}

// Closes the reader, when it can be.
func (self *dnsSnapshotStream) Close() error {
	if self.closer == nil {
		return nil
	}
	closer := self.closer
	self.closer = nil
	return closer.Close()
}
