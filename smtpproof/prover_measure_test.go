// Measure on a fake clock: the proving backend moves the clock by what each suite's part costs, so
// the limits it sets are exact and nothing waits on real time.

package smtpproof

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A clock that only moves when told.
type testClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func (self *testClock) read() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
}

// Proves nothing, and moves the clock by what a part of each suite costs. A suite with no cost has no
// keys.
type testClockedBackend struct {
	clock *testClock
	costs map[uint16]time.Duration
	// When set, the error a statement's proof ends in, as a host short of memory or keys would see.
	refuse func(statement *partStatement) error
	// The statements it was asked to prove.
	statements []*partStatement
}

func (self *testClockedBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	cost, ok := self.costs[statement.session.suite]
	if !ok {
		return nil, errNoKeys
	}
	self.statements = append(self.statements, statement)
	if self.refuse != nil {
		if err := self.refuse(statement); err != nil {
			return nil, err
		}
	}
	self.clock.advance(cost)
	return []byte("measured"), nil
}

func testMeasuringProver(costs map[uint16]time.Duration) (*Prover, *testClockedBackend) {
	clock := &testClock{now: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)}
	backend := &testClockedBackend{clock: clock, costs: costs}
	return &Prover{settings: DefaultProverSettings(), backend: backend, clock: clock.read}, backend
}

// What one body record of a family's body shape carries under 1.3, which Measure rates a part by.
func testMeasureCapacity(family ShapeFamily) int {
	shape := DefaultProofSettings().shape(ShapeKindBody, family, 0)
	return shape.recordContentBytes(shape.BodyBlocks, tlsVersion13)
}

func TestMeasurePartsFillTheirShapesAndSatisfyTheRelation(t *testing.T) {
	// a measuring part is a real body part of its shape, so its cost is that shape's unit
	proof := DefaultProofSettings()
	for _, shape := range partShapes(proof) {
		if shape.kind != partKindBody {
			continue
		}
		statement, witness, err := newMeasurePart(proof, shape)
		if err != nil {
			t.Fatal(err)
		}
		if failures := relationCheckPart(statement, witness); len(failures) != 0 {
			t.Errorf("%s: %v", partShapeName(shape), failures)
		}
		found, err := partShapeFor(proof, statement)
		if err != nil || *found != *shape {
			t.Errorf("%s: found %+v, %v", partShapeName(shape), found, err)
		}
	}
}

func TestMeasureProvesOneBodyUnitPerFamily(t *testing.T) {
	// every shape fills one domain, so a body unit of each family stands for the rest (DESIGN-DETAILS 3.2.6)
	prover, backend := testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        10 * time.Second,
		tlsSuiteChacha20Poly1305Sha256: 5 * time.Second,
	})
	if _, err := prover.Measure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(backend.statements) != 2 {
		t.Fatalf("proved %d parts, want one body unit a family", len(backend.statements))
	}
	families := map[ShapeFamily]bool{}
	for _, statement := range backend.statements {
		shape, err := partShapeFor(DefaultProofSettings(), statement)
		if err != nil || shape.kind != partKindBody || statement.mode != partModeData || statement.index != 4 {
			t.Errorf("part %d mode %d: %v", statement.index, statement.mode, err)
			continue
		}
		families[shape.family] = true
	}
	if !families[ShapeFamilyAes128Gcm] || !families[ShapeFamilyChacha20] {
		t.Errorf("families %v", families)
	}
}

func TestMeasureRecordsNothingWhereAUnitCannotProve(t *testing.T) {
	// a host that cannot prove a unit records no p/ and only queues (QD-483); a host out of memory dies in
	// the attempt, and any other failure ends Measure with no result
	prover, backend := testMeasuringProver(map[uint16]time.Duration{tlsSuiteAes128GcmSha256: time.Second})
	backend.refuse = func(statement *partStatement) error {
		return errors.New("out of memory")
	}
	if measure, err := prover.Measure(context.Background()); err == nil {
		t.Fatalf("measured %+v", measure)
	}
	if len(backend.statements) != 1 {
		t.Errorf("proved %d parts after the first failed", len(backend.statements))
	}
	if settings := prover.sendSettings(); settings != nil {
		t.Fatal("a failed measure admitted a send")
	}
}

func TestMeasureSetsTheLimitsAndThePriceByTheSlowestFamily(t *testing.T) {
	prover, backend := testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        20 * time.Second,
		tlsSuiteChacha20Poly1305Sha256: 5 * time.Second,
	})
	measure, err := prover.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// the smaller family's body record, AES-128-GCM's, and the slowest family's 20 s for one
	capacity := min(testMeasureCapacity(ShapeFamilyAes128Gcm), testMeasureCapacity(ShapeFamilyChacha20))
	if measure.DataBytesPerSecond != uint64(capacity/20) {
		t.Errorf("rate %d", measure.DataBytesPerSecond)
	}
	if measure.DataProofBytes != uint64(capacity/20*2*60*60) {
		t.Errorf("cap %d", measure.DataProofBytes)
	}
	if !measure.MeasureTime.Equal(backend.clock.read()) {
		t.Errorf("measured at %v", measure.MeasureTime)
	}
	// a send is priced in AES-128-GCM's units: 3.2.6's head and rest, and 13 commands a group after the first
	proof := DefaultProofSettings()
	message := proof.shape(ShapeKindMessage, ShapeFamilyAes128Gcm, 0)
	header := proof.shape(ShapeKindHeader, ShapeFamilyAes128Gcm, 0)
	if measure.UnitTime != 20*time.Second || measure.HeadByteCount != uint64(message.recordContentBytes(message.HeadBlocks, tlsVersion13)) ||
		measure.HeaderRecordByteCount != uint64(header.recordContentBytes(header.RestBlocks, tlsVersion13)) || measure.EnvelopeGroupCount != 13 {
		t.Errorf("unit %v, head %d, rest %d, group %d", measure.UnitTime, measure.HeadByteCount, measure.HeaderRecordByteCount, measure.EnvelopeGroupCount)
	}
	if measure.HeadByteCount != 831 {
		t.Errorf("head %d, want 3.2.6's 831", measure.HeadByteCount)
	}
	settings := prover.sendSettings()
	if uint64(settings.DataProofBytes) != measure.DataProofBytes {
		t.Errorf("a send would run with cap %d", settings.DataProofBytes)
	}
	// the Prover's own settings are untouched: only its sends see the measure
	if prover.settings.DataProofBytes != DefaultProverSettings().DataProofBytes {
		t.Error("Measure wrote into the settings it was given")
	}

	// where ChaCha20's unit is the slower, a send is priced in its: 19 commands a group
	prover, _ = testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        5 * time.Second,
		tlsSuiteChacha20Poly1305Sha256: 8 * time.Second,
	})
	if measure, err = prover.Measure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if measure.UnitTime != 8*time.Second || measure.HeadByteCount != 1215 || measure.HeaderRecordByteCount != 2239 || measure.EnvelopeGroupCount != 19 {
		t.Errorf("unit %v, head %d, rest %d, group %d", measure.UnitTime, measure.HeadByteCount, measure.HeaderRecordByteCount, measure.EnvelopeGroupCount)
	}
}

func TestMeasureClosesDataWhereAUnitCannotProveInTime(t *testing.T) {
	// a part past 2 minutes would outlast the MX's timeout, so this host sends no DATA at all, and a
	// message to an MX without CHUNKING is too_large before MAIL, naming the cap it passed
	prover, _ := testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        3 * time.Minute,
		tlsSuiteChacha20Poly1305Sha256: time.Second,
	})
	measure, err := prover.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if measure.DataProofBytes != 0 {
		t.Errorf("cap %d", measure.DataProofBytes)
	}
	settings := prover.sendSettings()
	if settings.DataProofBytes != 0 {
		t.Fatalf("cap %d", settings.DataProofBytes)
	}
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"PIPELINING"}
	job := testJob("a small body\r\n", "bob")
	backend := newTestWitnessBackend()
	send := testRunSendThrough(t, testTlsLegs()[0], mxSettings, settings, job, backend, backend, nil, measure)
	if send.err != nil || send.result == nil || !send.result.TooLarge || send.result.DataProofByteCount != 0 {
		t.Fatalf("result %+v, %v", send.result, send.err)
	}
	if commands := send.mx.seen(); len(commands) != 1 {
		t.Errorf("the MX saw %q, want EHLO alone", commands)
	}
	backend = newTestWitnessBackend()
	send = testRunSendThrough(t, testTlsLegs()[0], testMxDefaults(), settings, job, backend, backend, nil, measure)
	testExpectOneTransaction(t, testTlsLegs()[0], send, job)
}

func TestMeasuredPositiveDataLimitIsAppliedBeforeMail(t *testing.T) {
	prover, _ := testMeasuringProver(map[uint16]time.Duration{tlsSuiteAes128GcmSha256: 10 * time.Second})
	mx := testMxDefaults()
	mx.keywords = []string{"PIPELINING"}
	leg := testTlsLegs()[0]
	job := testJob("a small body\r\n", "bob")
	for _, window := range []time.Duration{time.Second, time.Hour} {
		prover.settings.DataConnectionTime = window
		measure, err := prover.Measure(context.Background())
		if err != nil || measure.DataProofBytes == 0 {
			t.Fatalf("measure for %v: %+v, %v", window, measure, err)
		}
		backend := newTestWitnessBackend()
		send := testRunSendThrough(t, leg, mx, prover.sendSettings(), job, backend, backend, nil, measure)
		if window == time.Hour {
			testExpectOneTransaction(t, leg, send, job)
			continue
		}
		if send.err != nil || send.result == nil || !send.result.TooLarge || send.result.DataProofByteCount != measure.DataProofBytes ||
			len(send.mx.seen()) != 1 {
			t.Fatalf("cap %d: %+v, %v; commands %v", measure.DataProofBytes, send.result, send.err, send.mx.seen())
		}
	}
}

func TestMeasureSkipsFamiliesWithoutKeysAndFailsWithNone(t *testing.T) {
	prover, backend := testMeasuringProver(map[uint16]time.Duration{tlsSuiteChacha20Poly1305Sha256: 4 * time.Second})
	measure, err := prover.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.statements) != 1 || measure.DataBytesPerSecond != uint64(testMeasureCapacity(ShapeFamilyChacha20)/4) {
		t.Errorf("%d parts, rate %d", len(backend.statements), measure.DataBytesPerSecond)
	}

	// Before keys load, a failed measure keeps this host queued.
	unloaded := NewProver(DefaultProverSettings(), DefaultKeySettings(), nil, t.TempDir())
	if _, err := unloaded.Measure(context.Background()); !errors.Is(err, errNoKeys) {
		t.Errorf("err %v", err)
	}
	if settings := unloaded.sendSettings(); settings != nil {
		t.Fatal("a prover without a measurement admitted a send")
	}
}

func TestMeasureTakesOnlyTheCurrentSetsReadyFamilies(t *testing.T) {
	// a host with keys measures the families ready in the set it would prove under, and no other
	circuits := testFamilyKeySetCircuits(t)
	made := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	prover := testProverOver(t, circuits, made)
	if proof, families := prover.measureFamilies(); len(families) != 0 || proof != prover.settings.Proof {
		t.Errorf("before any check: %v", families)
	}
	testPrepareAll(t, prover)
	proof, families := prover.measureFamilies()
	if len(families) != 1 || families[0] != ShapeFamilyChacha20 {
		t.Errorf("families %v", families)
	}
	if proof.shape(ShapeKindBody, ShapeFamilyChacha20, 0) == nil {
		t.Error("the set's catalog holds no body shape")
	}
}
