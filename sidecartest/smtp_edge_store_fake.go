// T2's SmtpEdgeStore and SmtpReportLookups: Postgres in memory, until SMTP-M5-06's report tables and
// SMTP-M9-18's MG9. Calls go through hostCall, so a plan under FaultOpHost with the key
// "smtpedge.<Method>" reaches them, and each is counted, so a test can show a path never called one.
// Held to the same promises as the real store by RunSmtpEdgeStoreSuite. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

var _ smtpedgeservice.SmtpEdgeStore = (*FakeSmtpEdgeStore)(nil)
var _ smtpedgeservice.SmtpReportLookups = (*FakeSmtpEdgeStore)(nil)

// What smtp_send's primary key is.
type fakeSmtpSendKey struct {
	sendDay int64
	sendId  string
}

// What InsertAggregate's uniqueness is.
type fakeSmtpAggregateKey struct {
	reporter string
	reportId string
}

// What smtp_dkim_key's lookup is.
type fakeSmtpDkimKeyKey struct {
	selector string
	domain   string
}

// Rows and call counts, in memory.
type FakeSmtpEdgeStore struct {
	clock  Clock
	faults *FaultQueue

	stateLock  sync.Mutex
	sends      []*smtpedgeservice.SmtpSendRecord
	sendKeys   map[fakeSmtpSendKey]bool
	complaints []*smtpedgeservice.SmtpComplaint
	aggregates map[fakeSmtpAggregateKey]*smtpedgeservice.SmtpAggregateReport
	// In insertion order, for Aggregates.
	aggregateKeys []fakeSmtpAggregateKey
	halts         map[sidecar.Id]*smtpedgeservice.SmtpHalt
	dkimKeys      map[fakeSmtpDkimKeyKey]*smtpedgeservice.SmtpDkimKey
	opCounts      map[string]int
}

// ActiveHalts reads clock, nil being real time. A nil faults takes a fresh queue.
func NewFakeSmtpEdgeStore(clock Clock, faults *FaultQueue) *FakeSmtpEdgeStore {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeSmtpEdgeStore{
		clock:      clock,
		faults:     faults,
		sendKeys:   map[fakeSmtpSendKey]bool{},
		aggregates: map[fakeSmtpAggregateKey]*smtpedgeservice.SmtpAggregateReport{},
		halts:      map[sidecar.Id]*smtpedgeservice.SmtpHalt{},
		dkimKeys:   map[fakeSmtpDkimKeyKey]*smtpedgeservice.SmtpDkimKey{},
		opCounts:   map[string]int{},
	}
}

// One call through the fake's fault and count, serve running under the lock.
func (self *FakeSmtpEdgeStore) call(ctx context.Context, method string, serve func() error) error {
	return hostCall(ctx, self.faults, "smtpedge."+method, func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts["smtpedge."+method] += 1
		return serve()
	})
}

// A deep copy, so neither side's later changes reach the other.
func copySmtpSendRecord(send *smtpedgeservice.SmtpSendRecord) *smtpedgeservice.SmtpSendRecord {
	kept := *send
	kept.SendId = bytes.Clone(send.SendId)
	kept.MessageIdHash = bytes.Clone(send.MessageIdHash)
	kept.RetryOfSendId = bytes.Clone(send.RetryOfSendId)
	return &kept
}

// A deep copy.
func copySmtpComplaint(complaint *smtpedgeservice.SmtpComplaint) *smtpedgeservice.SmtpComplaint {
	kept := *complaint
	kept.MessageIdHash = bytes.Clone(complaint.MessageIdHash)
	kept.SealedReport = bytes.Clone(complaint.SealedReport)
	return &kept
}

// A deep copy.
func copySmtpAggregateReport(report *smtpedgeservice.SmtpAggregateReport) *smtpedgeservice.SmtpAggregateReport {
	kept := *report
	kept.Counts = make([]*smtpedgeservice.SmtpAggregateCount, 0, len(report.Counts))
	for _, count := range report.Counts {
		keptCount := *count
		kept.Counts = append(kept.Counts, &keptCount)
	}
	return &kept
}

// See SmtpEdgeStore. A record already stored under its key stays as first written.
func (self *FakeSmtpEdgeStore) InsertSends(ctx context.Context, sends []*smtpedgeservice.SmtpSendRecord) error {
	return self.call(ctx, "InsertSends", func() error {
		for _, send := range sends {
			key := fakeSmtpSendKey{sendDay: smtpedgeservice.SmtpSendDay(send.StartTime), sendId: string(send.SendId)}
			if self.sendKeys[key] {
				continue
			}
			self.sendKeys[key] = true
			self.sends = append(self.sends, copySmtpSendRecord(send))
		}
		return nil
	})
}

// See SmtpEdgeStore.
func (self *FakeSmtpEdgeStore) FindSends(ctx context.Context, key *smtpedgeservice.SmtpJoinKey) ([]*smtpedgeservice.SmtpSendRecord, error) {
	var found []*smtpedgeservice.SmtpSendRecord
	err := self.call(ctx, "FindSends", func() error {
		if key == nil || (len(key.SendId) == 0 && len(key.MessageIdHash) == 0 && key.NetworkId == (sidecar.Id{}) && !key.SendingAddress.IsValid()) {
			return smtpedgeservice.ErrSmtpJoinKeyEmpty
		}
		for _, send := range self.sends {
			if len(key.SendId) != 0 && !bytes.Equal(key.SendId, send.SendId) {
				continue
			}
			if len(key.MessageIdHash) != 0 && !bytes.Equal(key.MessageIdHash, send.MessageIdHash) {
				continue
			}
			if key.NetworkId != (sidecar.Id{}) && key.NetworkId != send.NetworkId {
				continue
			}
			if key.SendingAddress.IsValid() && key.SendingAddress.Unmap() != send.SendingAddress.Unmap() {
				continue
			}
			if !key.Since.IsZero() && send.StartTime.Before(key.Since) {
				continue
			}
			if !key.Until.IsZero() && send.StartTime.After(key.Until) {
				continue
			}
			found = append(found, copySmtpSendRecord(send))
		}
		slices.SortStableFunc(found, func(a *smtpedgeservice.SmtpSendRecord, b *smtpedgeservice.SmtpSendRecord) int {
			if c := a.StartTime.Compare(b.StartTime); c != 0 {
				return c
			}
			return bytes.Compare(a.SendId, b.SendId)
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// See SmtpEdgeStore.
func (self *FakeSmtpEdgeStore) InsertComplaint(ctx context.Context, complaint *smtpedgeservice.SmtpComplaint) error {
	return self.call(ctx, "InsertComplaint", func() error {
		self.complaints = append(self.complaints, copySmtpComplaint(complaint))
		return nil
	})
}

// See SmtpEdgeStore.
func (self *FakeSmtpEdgeStore) InsertAggregate(ctx context.Context, report *smtpedgeservice.SmtpAggregateReport) (bool, error) {
	inserted := false
	err := self.call(ctx, "InsertAggregate", func() error {
		key := fakeSmtpAggregateKey{reporter: report.Reporter, reportId: report.ReportId}
		if _, ok := self.aggregates[key]; ok {
			return nil
		}
		self.aggregates[key] = copySmtpAggregateReport(report)
		self.aggregateKeys = append(self.aggregateKeys, key)
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// See SmtpEdgeStore.
func (self *FakeSmtpEdgeStore) SetHalt(ctx context.Context, halt *smtpedgeservice.SmtpHalt) error {
	return self.call(ctx, "SetHalt", func() error {
		kept := *halt
		self.halts[halt.HaltId] = &kept
		return nil
	})
}

// See SmtpEdgeStore. Holding is read on the fake's clock.
func (self *FakeSmtpEdgeStore) ActiveHalts(ctx context.Context) ([]*smtpedgeservice.SmtpHalt, error) {
	var active []*smtpedgeservice.SmtpHalt
	err := self.call(ctx, "ActiveHalts", func() error {
		now := self.clock.Now()
		for _, halt := range self.halts {
			if halt.ActiveAt(now) {
				kept := *halt
				active = append(active, &kept)
			}
		}
		slices.SortFunc(active, func(a *smtpedgeservice.SmtpHalt, b *smtpedgeservice.SmtpHalt) int {
			if c := a.StartTime.Compare(b.StartTime); c != 0 {
				return c
			}
			return a.HaltId.Cmp(b.HaltId)
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return active, nil
}

// See SmtpReportLookups.
func (self *FakeSmtpEdgeStore) FindDkimKey(ctx context.Context, selector string, domain string) (*smtpedgeservice.SmtpDkimKey, error) {
	var found *smtpedgeservice.SmtpDkimKey
	err := self.call(ctx, "FindDkimKey", func() error {
		key, ok := self.dkimKeys[fakeSmtpDkimKeyKey{selector: strings.ToLower(selector), domain: strings.ToLower(domain)}]
		if ok {
			kept := *key
			kept.PublicKey = bytes.Clone(key.PublicKey)
			found = &kept
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// See SmtpReportLookups.
func (self *FakeSmtpEdgeStore) RecipientCount(ctx context.Context, networkId sidecar.Id, since time.Time) (uint64, error) {
	var count uint64
	err := self.call(ctx, "RecipientCount", func() error {
		for _, send := range self.sends {
			if send.NetworkId == networkId && !send.StartTime.Before(since) {
				count += uint64(send.RecipientCount)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Publishes a key, as POST /smtp/dkim-keys will (SMTP-M9-19). Not part of either interface.
func (self *FakeSmtpEdgeStore) PutDkimKey(key *smtpedgeservice.SmtpDkimKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := *key
	kept.PublicKey = bytes.Clone(key.PublicKey)
	self.dkimKeys[fakeSmtpDkimKeyKey{selector: strings.ToLower(key.Selector), domain: strings.ToLower(key.Domain)}] = &kept
}

// Every send stored, in insertion order, as copies.
func (self *FakeSmtpEdgeStore) Sends() []*smtpedgeservice.SmtpSendRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sends := make([]*smtpedgeservice.SmtpSendRecord, 0, len(self.sends))
	for _, send := range self.sends {
		sends = append(sends, copySmtpSendRecord(send))
	}
	return sends
}

// Every complaint stored, in insertion order, as copies.
func (self *FakeSmtpEdgeStore) Complaints() []*smtpedgeservice.SmtpComplaint {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	complaints := make([]*smtpedgeservice.SmtpComplaint, 0, len(self.complaints))
	for _, complaint := range self.complaints {
		complaints = append(complaints, copySmtpComplaint(complaint))
	}
	return complaints
}

// Every aggregate stored, in insertion order, as copies.
func (self *FakeSmtpEdgeStore) Aggregates() []*smtpedgeservice.SmtpAggregateReport {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reports := make([]*smtpedgeservice.SmtpAggregateReport, 0, len(self.aggregateKeys))
	for _, key := range self.aggregateKeys {
		reports = append(reports, copySmtpAggregateReport(self.aggregates[key]))
	}
	return reports
}

// Every halt stored, expired ones included, as copies in no fixed order.
func (self *FakeSmtpEdgeStore) Halts() []*smtpedgeservice.SmtpHalt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	halts := make([]*smtpedgeservice.SmtpHalt, 0, len(self.halts))
	for _, halt := range self.halts {
		kept := *halt
		halts = append(halts, &kept)
	}
	return halts
}

// How often each method ran, by its fault key.
func (self *FakeSmtpEdgeStore) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// Starts counting from zero, so a test can measure one path.
func (self *FakeSmtpEdgeStore) ResetOpCounts() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.opCounts)
}

// What a privacy scan reads of the store: every stored row, sealed copies included, as CC3 items.
func (self *FakeSmtpEdgeStore) PrivacyItems() []*PrivacyItem {
	items := []*PrivacyItem{}
	for _, complaint := range self.Complaints() {
		items = append(items, &PrivacyItem{Class: "CC3", Name: "smtp_complaint", Body: []byte(complaint.Reporter + "\x00" + complaint.Type + "\x00" + complaint.Domain + "\x00" + complaint.DkimDomain + "\x00" + complaint.DkimSelector + "\x00" + complaint.XUrRef + "\x00" + complaint.FeedbackId + "\x00" + string(complaint.MessageIdHash) + "\x00" + string(complaint.SealedReport))})
	}
	for _, report := range self.Aggregates() {
		body := report.Reporter + "\x00" + report.ReportId + "\x00" + report.Kind
		for _, count := range report.Counts {
			body += "\x00" + count.Domain + "\x00" + count.PolicyType
		}
		items = append(items, &PrivacyItem{Class: "CC3", Name: "smtp_dmarc_daily", Body: []byte(body)})
	}
	for _, send := range self.Sends() {
		items = append(items, &PrivacyItem{Class: "CC3", Name: "smtp_send", Body: []byte(send.RecipientDomain + "\x00" + send.MxHost + "\x00" + send.Result)})
	}
	return items
}
