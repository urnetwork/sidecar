//go:build !sidecar_http && !ios_extension

package sidecar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Its keys are ready. Each measurement finishes when the test releases its unit.
type testAdmissionProver struct {
	*sidecartest.FakeSmtpProver
	entered chan struct{}
	finish  chan error
	measure sidecar.SmtpProverMeasure
}

func (p *testAdmissionProver) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	p.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-p.finish:
		if err != nil {
			return nil, err
		}
		measure := p.measure
		return &measure, nil
	}
}

func TestSmtpSenderWaitsForACompletedHostMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	records := sidecartest.NewFakeSmtpMailbox(nil)
	prover := &testAdmissionProver{
		FakeSmtpProver: sidecartest.NewFakeSmtpProver(nil), entered: make(chan struct{}, 1), finish: make(chan error, 1),
		measure: sidecar.SmtpProverMeasure{MeasureTime: clock.Now(), UnitTime: time.Second, DataProofBytes: 1024 * 1024},
	}
	host, err := sidecar.NewSmtpProverHost(&sidecar.SmtpProverHostArgs{
		Prover: prover, Mailbox: records, SidecarId: sidecar.NewId(), MailEnabled: func() bool { return true },
		Settings: sidecar.DefaultSmtpSenderSettings(), Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := sidecar.NewId()
	world := newTestSenderWorld(t, &testSenderOptions{proverHost: host, memberDevice: func(id sidecar.Id) bool { return id == remote }})
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	if err := world.mailbox.WriteProverRecord(ctx, remote, &sidecar.SmtpProverRecord{
		Measure: sidecar.SmtpProverMeasure{MeasureTime: clock.Now(), DataProofBytes: 9000},
	}); err != nil {
		t.Fatal(err)
	}
	queued := func() {
		t.Helper()
		if got := testDomainOutcome(t, world.send(message), testTlsDomain); got.Outcome != sidecar.SmtpOutcomeQueued ||
			world.stub.DialCount() != 0 || len(world.mailbox.Dsns()) != 0 || host.Measure() != nil || len(host.ReadyKeySets()) != 0 {
			t.Fatalf("before a completed measurement: outcome %+v, dials %d, measure %+v", got, world.stub.DialCount(), host.Measure())
		}
		check, err := world.sender.Check(ctx, message)
		if err != nil || len(check.Domains) != 1 || check.Domains[0].CapByteCount != 9000 {
			t.Fatalf("queued host's remote cap: %+v, %v", check, err)
		}
	}
	idled := make(chan error, 1)
	go func() { idled <- host.Idle(ctx) }()
	<-prover.entered
	// A send that checked just as another key family became ready can reach the hold. It cannot cancel
	// the measurement the host now needs.
	release := host.HoldForSend()
	release()
	queued()
	unitFailure := errors.New("unit cannot complete")
	prover.finish <- unitFailure
	if err := <-idled; !errors.Is(err, unitFailure) {
		t.Fatalf("first measurement: %v", err)
	}
	queued()
	go func() { idled <- host.Idle(ctx) }()
	<-prover.entered
	queued()
	prover.finish <- nil
	if err := <-idled; err != nil {
		t.Fatal(err)
	}
	if len(host.ReadyKeySets()) != 1 || records.OpCount("WriteProverRecord") != 1 {
		t.Fatal("completed capacity was not published")
	}
	if got := testDomainOutcome(t, world.send(message), testTlsDomain); got.Outcome != sidecar.SmtpOutcomeSent || len(world.mx.Transactions()) != 1 {
		t.Fatalf("after measurement: %+v", got)
	}

	clock.Advance(sidecar.DefaultSmtpSenderSettings().ProverMeasureInterval)
	go func() { idled <- host.Idle(ctx) }()
	<-prover.entered
	prover.finish <- unitFailure
	if err := <-idled; !errors.Is(err, unitFailure) || host.Measure() != nil || len(host.ReadyKeySets()) != 0 {
		t.Fatalf("failed remeasurement: %+v, %v", host.Measure(), err)
	}
	if got := testDomainOutcome(t, world.send(message), testTlsDomain); got.Outcome != sidecar.SmtpOutcomeSent || len(world.mx.Transactions()) != 1 {
		t.Fatalf("existing delivery after measurement failed: %+v", got)
	}
}

func TestSmtpSenderMeasuredZeroCapClosesOnlyData(t *testing.T) {
	settings := sidecartest.DefaultFakeSmtpProverSettings()
	settings.DataProofByteCount = 0
	world := newTestSenderWorld(t, &testSenderOptions{prover: settings})
	world.addDomain(testDataDomain, testDataHost, testDataAddress, testDataOnlyScript())
	message := world.message([]string{"bob@" + testTlsDomain, "bob@" + testDataDomain}, nil, "body\r\n")
	result := world.send(message)
	if got := testDomainOutcome(t, result, testTlsDomain); got.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("BDAT: %+v", got)
	}
	if got := testDomainOutcome(t, result, testDataDomain); got.Outcome != sidecar.SmtpOutcomeTooLarge || got.CapByteCount != 0 {
		t.Fatalf("DATA: %+v", got)
	}
	check, err := world.sender.Check(context.Background(), message)
	if err != nil || len(check.Domains) != 2 || check.Domains[0].Prediction != sidecar.SmtpCheckOk ||
		check.Domains[1].Prediction != sidecar.SmtpCheckTooLarge || check.Domains[1].CapByteCount != 0 {
		t.Fatalf("measured zero: %+v, %v", check, err)
	}
}
