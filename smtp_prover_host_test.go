//go:build !sidecar_http && !ios_extension

// The prover host's idle work (SMTP-M9-09): a host that has not enabled mail never calls PrepareKeys; no p/ before a
// family is ready; the prepare loop stops for a send and resumes after it; p/ is rewritten when the key set changes
// and at ProverMeasureInterval, and holds every field the record carries; and p/'s record refuses what no reader
// could take back.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A prover whose PrepareKeys a test steers: each call answers the readiness it holds, after a gate the test may close
// to hold a call inside it until its ctx ends.
type testSteeredProver struct {
	*sidecartest.FakeSmtpProver

	stateLock    sync.Mutex
	readiness    *sidecar.SmtpProverReadiness
	blocking     bool
	entered      chan struct{}
	prepareCount int
	measureCount int
}

func (self *testSteeredProver) PrepareKeys(ctx context.Context) (*sidecar.SmtpProverReadiness, error) {
	self.stateLock.Lock()
	self.prepareCount += 1
	blocking, entered, readiness := self.blocking, self.entered, self.readiness
	self.stateLock.Unlock()
	if blocking {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return readiness, nil
}

func (self *testSteeredProver) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	self.stateLock.Lock()
	self.measureCount += 1
	self.stateLock.Unlock()
	return self.FakeSmtpProver.Measure(ctx)
}

func (self *testSteeredProver) set(readiness *sidecar.SmtpProverReadiness, blocking bool) chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readiness, self.blocking = readiness, blocking
	self.entered = make(chan struct{})
	return self.entered
}

func (self *testSteeredProver) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.prepareCount, self.measureCount
}

// A host over a steered prover, its p/ in mailbox, mail enabled while enabled says so.
func newTestProverHost(t *testing.T, clock *sidecartest.FakeClock, mailbox sidecar.SmtpMailbox, enabled func() bool) (*sidecar.SmtpProverHost, *testSteeredProver, sidecar.Id) {
	t.Helper()
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.Measure = &sidecar.SmtpProverMeasure{
		DataProofBytes: 3 * 1024 * 1024, DataBytesPerSecond: 400, MeasureTime: clock.Now(), UnitTime: 4 * time.Second,
		HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
	}
	prover := &testSteeredProver{FakeSmtpProver: sidecartest.NewFakeSmtpProver(proverSettings)}
	prover.set(&sidecar.SmtpProverReadiness{}, false)
	sidecarId := sidecar.NewId()
	host, err := sidecar.NewSmtpProverHost(&sidecar.SmtpProverHostArgs{
		Prover: prover, Mailbox: mailbox, SidecarId: sidecarId, MailEnabled: enabled, Settings: sidecar.DefaultSmtpSenderSettings(), Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, prover, sidecarId
}

func testReadyKeySet(id byte) *sidecar.SmtpProverKeySet {
	return &sidecar.SmtpProverKeySet{Id: bytes.Repeat([]byte{id}, 32), ReadySuites: []uint16{0x1303, 0x1301}}
}

// A host whose member has not enabled mail never checks keys, so it fetches nothing (§2.8 smtp-7).
func TestSmtpProverHostWithoutMailCallsNoPrepare(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	mailbox := sidecartest.NewFakeSmtpMailbox(nil)
	host, prover, _ := newTestProverHost(t, clock, mailbox, func() bool { return false })
	for range 3 {
		if err := host.Idle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if prepareCount, measureCount := prover.counts(); prepareCount != 0 || measureCount != 0 || mailbox.OpCount("WriteProverRecord") != 0 {
		t.Errorf("%d prepares, %d measures", prepareCount, measureCount)
	}
	if host2, prover2, _ := newTestProverHost(t, clock, mailbox, nil); host2.Idle(context.Background()) != nil || prover2.prepareCount != 0 {
		t.Error("a host with no mail setting checked keys")
	}
}

// No family ready, and none to come: no measure and no p/. Then a ready family: a measure and p/ with every field.
func TestSmtpProverHostRecordsNoProverRecordBeforeAFamilyIsReady(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	mailbox := sidecartest.NewFakeSmtpMailbox(nil)
	host, prover, sidecarId := newTestProverHost(t, clock, mailbox, func() bool { return true })
	prover.set(&sidecar.SmtpProverReadiness{Done: true}, false)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, measureCount := prover.counts(); measureCount != 0 || mailbox.OpCount("WriteProverRecord") != 0 || host.Measure() != nil || len(host.ReadyKeySets()) != 0 {
		t.Fatalf("a host with no ready family measured %d times", measureCount)
	}

	host, prover, sidecarId = newTestProverHost(t, clock, mailbox, func() bool { return true })
	prover.set(&sidecar.SmtpProverReadiness{KeySets: []*sidecar.SmtpProverKeySet{testReadyKeySet(0x61)}, Done: true}, false)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := mailbox.ListProverRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record := records[sidecarId]
	if record == nil || record.Measure.DataProofBytes != 3*1024*1024 || record.Measure.UnitTime != 4*time.Second || record.Measure.EnvelopeGroupCount != 13 ||
		!bytes.Equal(record.KeySet, testReadyKeySet(0x61).Id) || !slices.Equal(record.ReadySuites, []uint16{0x1303, 0x1301}) {
		t.Errorf("p/ holds %+v", record)
	}
	if keySets := host.ReadyKeySets(); len(keySets) != 1 || host.Cap() != 3*1024*1024 {
		t.Errorf("ready %x, cap %d", keySets, host.Cap())
	}
}

// A send's hold stops a PrepareKeys in flight at once and keeps idle work off until the send ends; then it resumes.
func TestSmtpProverHostPrepareStopsForASendAndResumes(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	mailbox := sidecartest.NewFakeSmtpMailbox(nil)
	host, prover, _ := newTestProverHost(t, clock, mailbox, func() bool { return true })
	entered := prover.set(nil, true)
	idled := make(chan error, 1)
	go func() { idled <- host.Idle(context.Background()) }()
	<-entered
	release := host.HoldForSend()
	if err := <-idled; !errors.Is(err, context.Canceled) {
		t.Fatalf("the prepare a send stopped: %v", err)
	}
	// held: no idle work starts
	prover.set(&sidecar.SmtpProverReadiness{KeySets: []*sidecar.SmtpProverKeySet{testReadyKeySet(0x61)}, Done: true}, false)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prepareCount, _ := prover.counts(); prepareCount != 1 {
		t.Errorf("%d prepares while a send held the host", prepareCount)
	}
	release()
	release()
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prepareCount, measureCount := prover.counts(); prepareCount != 2 || measureCount != 1 || mailbox.OpCount("WriteProverRecord") != 1 {
		t.Errorf("after the send: %d prepares, %d measures", prepareCount, measureCount)
	}
}

// p/ is rewritten when the key set changes and at ProverMeasureInterval, and not between.
func TestSmtpProverHostRewritesProverRecordWhenTheKeySetChanges(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	mailbox := sidecartest.NewFakeSmtpMailbox(nil)
	host, prover, sidecarId := newTestProverHost(t, clock, mailbox, func() bool { return true })
	// the older pinned set is ready while the newer one is still being checked
	prover.set(&sidecar.SmtpProverReadiness{KeySets: []*sidecar.SmtpProverKeySet{testReadyKeySet(0x61)}}, false)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, measureCount := prover.counts(); measureCount != 1 {
		t.Fatalf("%d measures with nothing changed", measureCount)
	}
	// the newer set's family is ready: the key set the host proves under changes
	prover.set(&sidecar.SmtpProverReadiness{KeySets: []*sidecar.SmtpProverKeySet{testReadyKeySet(0x62), testReadyKeySet(0x61)}, Done: true}, false)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := mailbox.ListProverRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if record := records[sidecarId]; record == nil || !bytes.Equal(record.KeySet, testReadyKeySet(0x62).Id) {
		t.Errorf("p/ holds %+v after the key set changed", record)
	}
	if _, measureCount := prover.counts(); measureCount != 2 {
		t.Errorf("%d measures", measureCount)
	}
	clock.Advance(sidecar.DefaultSmtpSenderSettings().ProverMeasureInterval)
	if err := host.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, measureCount := prover.counts(); measureCount != 3 {
		t.Errorf("%d measures after the interval", measureCount)
	}
}

// p/'s record round-trips every field and refuses what no reader could take back.
func TestSmtpProverRecordRoundTrips(t *testing.T) {
	record := &sidecar.SmtpProverRecord{
		Measure: sidecar.SmtpProverMeasure{
			DataProofBytes: 1, DataBytesPerSecond: 2, MeasureTime: time.UnixMilli(1_800_000_000_000), UnitTime: 3 * time.Second,
			HeadByteCount: 4, HeaderRecordByteCount: 5, EnvelopeGroupCount: 6,
		},
		KeySet:      []byte{7, 8},
		ReadySuites: []uint16{0x1303},
	}
	mailRecord, err := record.MailProverRecord()
	if err != nil {
		t.Fatal(err)
	}
	back, err := sidecar.SmtpProverRecordFromMail(mailRecord)
	if err != nil || back.Measure != record.Measure || !bytes.Equal(back.KeySet, record.KeySet) || !slices.Equal(back.ReadySuites, record.ReadySuites) {
		t.Errorf("back %+v, %v", back, err)
	}
	if _, err := (&sidecar.SmtpProverRecord{}).MailProverRecord(); err == nil {
		t.Error("a record with no measure time")
	}
	if _, err := sidecar.SmtpProverRecordFromMail(&protocol.MailProverRecord{MeasureTimeMs: 1, ReadySuites: []uint32{0x10000}}); err == nil {
		t.Error("a suite past 16 bits")
	}
	if _, err := sidecar.SmtpProverRecordFromMail(&protocol.MailProverRecord{}); err == nil {
		t.Error("a record with no time")
	}
}
