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
	// a measuring part is a real body part of its shape, so its cost is that shape's, and its msg part a
	// real one of the msg shape's
	proof := DefaultProofSettings()
	for _, shape := range partShapes(proof) {
		var statement *partStatement
		var witness *partWitness
		var err error
		switch shape.kind {
		case partKindBody:
			statement, witness, err = newMeasurePart(proof, shape)
		case partKindMessage:
			statement, witness, err = newMeasureMessagePart(proof, shape)
		default:
			continue
		}
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

func TestMeasureProvesEachFamilysMessagePartFirst(t *testing.T) {
	prover, backend := testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        10 * time.Second,
		tlsSuiteChacha20Poly1305Sha256: 5 * time.Second,
	})
	if _, err := prover.Measure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(backend.statements) != 4 {
		t.Fatalf("proved %d parts, want each family's msg part and then its body part", len(backend.statements))
	}
	for i, statement := range backend.statements {
		want := uint32(measurePartIndex)
		if i < 2 {
			want = 3
		}
		if statement.index != want || statement.mode != partModeData {
			t.Errorf("part %d: index %d mode %d", i, statement.index, statement.mode)
		}
	}
}

func TestMeasureRecordsNothingWhereAUnitCannotProve(t *testing.T) {
	// plan-SMTP-small-readings #19: a host that cannot prove a unit records no p/ and only queues. A host
	// out of memory dies in the attempt; any other failure ends Measure with no result
	prover, backend := testMeasuringProver(map[uint16]time.Duration{tlsSuiteAes128GcmSha256: time.Second})
	backend.refuse = func(statement *partStatement) error {
		if statement.index == 3 {
			return errors.New("out of memory")
		}
		return nil
	}
	if measure, err := prover.Measure(context.Background()); err == nil {
		t.Fatalf("measured %+v", measure)
	}
	if len(backend.statements) != 1 {
		t.Errorf("proved %d parts after the msg part failed", len(backend.statements))
	}
	if settings := prover.sendSettings(); settings.DataProofBytes != DefaultProverSettings().DataProofBytes || settings.DataPartBytes != DefaultProverSettings().DataPartBytes {
		t.Errorf("a failed measure set part %d and cap %d", settings.DataPartBytes, settings.DataProofBytes)
	}
}

func TestMeasureSetsTheDataLimitsByTheSlowestFamily(t *testing.T) {
	prover, backend := testMeasuringProver(map[uint16]time.Duration{
		tlsSuiteAes128GcmSha256:        20 * time.Second,
		tlsSuiteChacha20Poly1305Sha256: 5 * time.Second,
	})
	measure, err := prover.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.statements) != 4 {
		t.Errorf("proved %d parts, want each family's msg part and body part", len(backend.statements))
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
	settings := prover.sendSettings()
	if settings.DataPartBytes != capacity || uint64(settings.DataProofBytes) != measure.DataProofBytes {
		t.Errorf("a send would run with part %d and cap %d", settings.DataPartBytes, settings.DataProofBytes)
	}
	// the Prover's own settings are untouched: only its sends see the measure
	if prover.settings.DataProofBytes != DefaultProverSettings().DataProofBytes {
		t.Error("Measure wrote into the settings it was given")
	}
}

func TestMeasureClosesDataWhereAPartCannotProveInTime(t *testing.T) {
	// a part past 2 minutes would outlast the MX's timeout, so this host sends no DATA at all, and a
	// message to an MX without CHUNKING is too_large before MAIL
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
	if settings.DataPartBytes != 0 || settings.DataProofBytes != 0 {
		t.Fatalf("part %d, cap %d", settings.DataPartBytes, settings.DataProofBytes)
	}
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"PIPELINING"}
	job := testJob("a small body\r\n", "bob")
	send := testRunSend(t, testTlsLegs()[0], mxSettings, settings, job)
	if send.err != nil || send.result == nil || !send.result.TooLarge {
		t.Fatalf("result %+v, %v", send.result, send.err)
	}
	if commands := send.mx.seen(); len(commands) != 1 {
		t.Errorf("the MX saw %q, want EHLO alone", commands)
	}
}

func TestMeasureSkipsFamiliesWithoutKeysAndFailsWithNone(t *testing.T) {
	prover, backend := testMeasuringProver(map[uint16]time.Duration{tlsSuiteChacha20Poly1305Sha256: 4 * time.Second})
	measure, err := prover.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.statements) != 2 || measure.DataBytesPerSecond != uint64(testMeasureCapacity(ShapeFamilyChacha20)/4) {
		t.Errorf("%d parts, rate %d", len(backend.statements), measure.DataBytesPerSecond)
	}

	// what cli/ holds before keys load: the measure fails, and the settings' unmeasured limits stand
	unloaded := NewProver(DefaultProverSettings(), nil, "")
	if _, err := unloaded.Measure(context.Background()); !errors.Is(err, errNoKeys) {
		t.Errorf("err %v", err)
	}
	if settings := unloaded.sendSettings(); settings.DataProofBytes != DefaultProverSettings().DataProofBytes {
		t.Errorf("cap %d", settings.DataProofBytes)
	}
}
