//go:build !ios_extension && !sidecar_http && !js

// The remote-work gate (ATTEST-M12-01) against the second review's R2-11 under a fixed clock: a sitting's batch
// issued in full, an immediate revocation whose new policy is withheld, and each of §5.4's device rules, for every
// remote operation.

package sidecar

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A test's world for the gate: the store's world, a store holding version 3, and a gate over it.
type testAttestGateWorld struct {
	*testAttestStoreWorld
	policyStore *ComputePolicyStore
	gate        *ComputePolicyGate
	alarms      []*ComputePolicyAlarm
	staging     bool
}

// A world whose device took policy 3 at the sitting; a staging world's verifier, policy and tickets are staging's.
func newTestAttestGateWorld(t *testing.T, staging bool) *testAttestGateWorld {
	t.Helper()
	world := &testAttestGateWorld{testAttestStoreWorld: newTestAttestStoreWorld(t), staging: staging}
	world.verifier = world.keys.verifier(staging)
	world.clock.Set(testAttestSitting)
	world.reopen(t)
	if _, err := world.policyStore.Offer(world.policy(t, 3)); err != nil {
		t.Fatal(err)
	}
	return world
}

// A fresh store and gate over the world's directory, as after a restart.
func (self *testAttestGateWorld) reopen(t *testing.T) {
	t.Helper()
	self.policyStore = self.open(t, 0)
	gate, err := NewComputePolicyGate(&ComputePolicyGateArgs{
		Store:    self.policyStore,
		Verifier: self.verifier,
		Settings: DefaultAttestSettings(),
		Alarm: func(alarm *ComputePolicyAlarm) {
			self.alarms = append(self.alarms, alarm)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	self.gate = gate
}

// The vector at version, signed by the world's policy key, or its staging key in a staging world.
func (self *testAttestGateWorld) policy(t *testing.T, version int) ([]byte, []byte) {
	t.Helper()
	document := testAttestPolicyVersion(t, version)
	signer, namespace := self.signer()
	return document, testAttestSign(t, signer, namespace, document)
}

// The key and namespace the world's policies and tickets are signed with.
func (self *testAttestGateWorld) signer() (ssh.Signer, string) {
	if self.staging {
		return self.keys.staging, ComputePolicyStagingNamespace
	}
	return self.keys.policy, ComputePolicyNamespace
}

// The batch of a sitting at signedAt naming version.
func (self *testAttestGateWorld) batch(t *testing.T, signedAt time.Time, version uint64, revocation bool) []*testAttestTicket {
	t.Helper()
	signer, namespace := self.signer()
	return testAttestBatch(t, signer, namespace, signedAt, version, revocation)
}

// Offers ticket at the clock's now, which must keep it.
func (self *testAttestGateWorld) keep(t *testing.T, ticket *testAttestTicket) {
	t.Helper()
	held, err := self.gate.OfferTicket(ticket.file)
	if err != nil || !held.NotBefore.Equal(ticket.ticket.NotBefore) {
		t.Fatalf("the ticket of %s: %v, %v", ticket.ticket.NotBefore, held, err)
	}
}

// Every remote operation runs at at.
func (self *testAttestGateWorld) wantRemoteWork(t *testing.T, at time.Time) {
	t.Helper()
	self.clock.Set(at)
	for _, operation := range ComputeRemoteOperations {
		if err := self.gate.RemoteWork(context.Background(), operation); err != nil {
			t.Fatalf("%s at %s: %v", operation, at, err)
		}
	}
}

// Every remote operation is refused at at, for reason.
func (self *testAttestGateWorld) wantLapsed(t *testing.T, at time.Time, reason ComputeRemoteLapseReason) {
	t.Helper()
	self.clock.Set(at)
	for _, operation := range ComputeRemoteOperations {
		err := self.gate.RemoteWork(context.Background(), operation)
		lapsed := &ComputeRemoteLapsedError{}
		if !errors.Is(err, ErrComputeRemoteLapsed) || !errors.As(err, &lapsed) || lapsed.Reason != reason || lapsed.Operation != operation {
			t.Fatalf("%s at %s: %v, want %s", operation, at, err, reason)
		}
	}
}

// R2-11: the batch issued in full, a revocation at once whose new policy and batch are withheld, the ticket host
// deleting the old batch's unreleased tickets. The last ticket released before the revocation is honored until 72
// hours after its start, and refused at that instant, for every remote operation.
func TestTicketReleasedHonoredFor72Hours(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	released := testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC))
	world.clock.Set(time.Date(2026, time.December, 3, 1, 0, 0, 0, time.UTC))
	world.keep(t, released)
	// the revocation at 15:00: policy 4 and its batch exist, and the device is given neither
	world.wantRemoteWork(t, time.Date(2026, time.December, 3, 15, 0, 0, 0, time.UTC))
	world.wantRemoteWork(t, released.ticket.NotBefore.Add(72*time.Hour-time.Second))
	world.wantLapsed(t, released.ticket.NotBefore.Add(72*time.Hour), ComputeRemoteLapseTicketExpired)
}

// A ticket whose start is ahead is refused, neither kept nor passed on, and raises the alarm more than an hour early;
// at its start it is taken.
func TestTicketUnreleasedRefusedBeforeStart(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	current := testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC))
	unreleased := testAttestTicketAt(t, batch, time.Date(2026, time.December, 4, 0, 0, 0, 0, time.UTC))
	world.wantLapsed(t, time.Date(2026, time.December, 3, 12, 0, 0, 0, time.UTC), ComputeRemoteLapseTicketUnavailable)
	if held, err := world.gate.OfferTicket(unreleased.file); held != nil || !errors.Is(err, ErrComputePolicyTicketEarly) {
		t.Fatalf("an unreleased ticket: %v, %v", held, err)
	}
	if world.policyStore.heldTicket() != nil || world.gate.Ticket() != nil {
		t.Error("an unreleased ticket was kept or passed on")
	}
	world.wantLapsed(t, time.Date(2026, time.December, 3, 12, 0, 0, 0, time.UTC), ComputeRemoteLapseTicketUnavailable)
	world.keep(t, current)
	if _, err := world.gate.OfferTicket(unreleased.file); !errors.Is(err, ErrComputePolicyTicketEarly) {
		t.Fatalf("an unreleased ticket beside a current one: %v", err)
	}
	if string(world.gate.Ticket()) != string(current.file) {
		t.Error("the gate passes on another ticket than the current one")
	}
	if len(world.alarms) != 2 || !world.alarms[0].NotBefore.Equal(unreleased.ticket.NotBefore) || world.alarms[0].BatchId != unreleased.ticket.Batch.Id {
		t.Errorf("alarms %+v", world.alarms)
	}
	world.clock.Set(unreleased.ticket.NotBefore)
	world.keep(t, unreleased)
	world.wantRemoteWork(t, unreleased.ticket.NotBefore)
}

// The batch's last ticket is honored a second before the batch's expiry, 14 days after its sitting, and refused at
// it, for every remote operation.
func TestTicketLastOfBatchUntilExpires(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	last := batch[len(batch)-1]
	expires := testAttestSitting.Add(14 * 24 * time.Hour)
	if !last.ticket.NotAfter.Equal(expires) {
		t.Fatalf("the last ticket ends at %s", last.ticket.NotAfter)
	}
	world.clock.Set(last.ticket.NotBefore)
	world.keep(t, last)
	world.wantRemoteWork(t, expires.Add(-time.Second))
	world.wantLapsed(t, expires, ComputeRemoteLapseTicketExpired)
}

// Once a verified ticket names version 4, no remote work runs under 3, and no ticket naming 3 is honored, until 4 is
// held, a restart between included; then it runs again.
func TestNewerVersionSeenStopsRemoteWork(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	world.clock.Set(time.Date(2026, time.December, 3, 1, 0, 0, 0, time.UTC))
	world.keep(t, testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)))
	revocationAt := time.Date(2026, time.December, 3, 15, 0, 0, 0, time.UTC)
	revocation := world.batch(t, revocationAt, 4, true)
	world.clock.Set(revocationAt.Add(time.Minute))
	world.keep(t, revocation[0])
	world.wantLapsed(t, revocationAt.Add(time.Minute), ComputeRemoteLapsePolicyNewerSeen)
	if _, err := world.gate.OfferTicket(testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)).file); err != nil {
		t.Fatal(err)
	}
	world.wantLapsed(t, revocationAt.Add(time.Minute), ComputeRemoteLapsePolicyNewerSeen)
	err := world.gate.RemoteWork(context.Background(), ComputeRemoteSearch)
	lapsed := &ComputeRemoteLapsedError{}
	if !errors.As(err, &lapsed) || lapsed.HighestSeen != 4 || lapsed.PolicyVersion != 3 {
		t.Errorf("the refusal says %v", err)
	}
	world.reopen(t)
	world.wantLapsed(t, revocationAt.Add(time.Minute), ComputeRemoteLapsePolicyNewerSeen)
	if _, err := world.policyStore.Offer(world.policy(t, 4)); err != nil {
		t.Fatal(err)
	}
	world.wantRemoteWork(t, revocationAt.Add(time.Minute))
}

// A ticket current past its policy's not_after carries nothing past it.
func TestTicketNeverCarriesPolicyPastNotAfter(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	notAfter := time.UnixMilli(1801440000000).UTC()
	sitting := notAfter.Add(-4 * 24 * time.Hour).Add(10 * time.Hour)
	batch := world.batch(t, sitting, 3, false)
	straddling := testAttestTicketAt(t, batch, testAttestDay(notAfter).AddDate(0, 0, -1))
	if !notAfter.Before(straddling.ticket.NotAfter) {
		t.Fatalf("the ticket ends at %s, before the policy's not_after", straddling.ticket.NotAfter)
	}
	world.clock.Set(straddling.ticket.NotBefore)
	world.keep(t, straddling)
	world.wantRemoteWork(t, notAfter.Add(-time.Second))
	world.wantLapsed(t, notAfter, ComputeRemoteLapsePolicyExpired)
	if _, err := world.gate.PolicyCurrent(); !errors.Is(err, ErrComputePolicyNotCurrent) {
		t.Errorf("the policy past its not_after: %v", err)
	}
}

// Now never goes back past the newest current ticket's start, nor, once the device saw its ticket lapse, past that
// ticket's end, across a restart; a clock set back revives no ticket, and an older ticket offered then is not taken.
func TestClockSetBackRevivesNoTicket(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	older := testAttestTicketAt(t, batch, time.Date(2026, time.December, 2, 0, 0, 0, 0, time.UTC))
	newest := testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC))
	world.clock.Set(newest.ticket.NotBefore.Add(time.Hour))
	world.keep(t, newest)
	world.clock.Set(time.Date(2026, time.December, 2, 6, 0, 0, 0, time.UTC))
	if now := world.gate.Now(); !now.Equal(newest.ticket.NotBefore) {
		t.Errorf("a clock set back reads %s, before the newest ticket's start", now)
	}
	if held, err := world.gate.OfferTicket(older.file); err != nil || !held.NotBefore.Equal(newest.ticket.NotBefore) {
		t.Errorf("an older ticket offered: %v, %v", held, err)
	}
	world.wantLapsed(t, newest.ticket.NotAfter, ComputeRemoteLapseTicketExpired)
	world.wantLapsed(t, time.Date(2026, time.December, 4, 0, 0, 0, 0, time.UTC), ComputeRemoteLapseTicketExpired)
	world.reopen(t)
	world.wantLapsed(t, time.Date(2026, time.December, 4, 0, 0, 0, 0, time.UTC), ComputeRemoteLapseTicketExpired)
	if now := world.gate.Now(); !now.Equal(newest.ticket.NotAfter) {
		t.Errorf("after a restart the clock reads %s", now)
	}
}

// A ticket more than an hour early alarms, once per offer; one less early is refused without one.
func TestEarlyTicketAlarms(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	ticket := testAttestTicketAt(t, batch, time.Date(2026, time.December, 4, 0, 0, 0, 0, time.UTC))
	world.clock.Set(ticket.ticket.NotBefore.Add(-30 * time.Minute))
	if _, err := world.gate.OfferTicket(ticket.file); !errors.Is(err, ErrComputePolicyTicketEarly) || len(world.alarms) != 0 {
		t.Errorf("half an hour early: %v, %d alarms", err, len(world.alarms))
	}
	world.clock.Set(ticket.ticket.NotBefore.Add(-time.Hour - time.Second))
	if _, err := world.gate.OfferTicket(ticket.file); !errors.Is(err, ErrComputePolicyTicketEarly) || len(world.alarms) != 1 {
		t.Errorf("past an hour early: %v, %d alarms", err, len(world.alarms))
	}
	if alarm := world.alarms[0]; !alarm.Now.Equal(ticket.ticket.NotBefore.Add(-time.Hour - time.Second)) {
		t.Errorf("the alarm %+v", alarm)
	}
}

// A lapse stops every remote operation, and no fetch, calendar link or connected service: they read PolicyCurrent,
// which only the policy's own not_after ends. Local inference calls neither: no operation names it.
func TestLapseStopsRemoteButNotLocal(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	ticket := testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC))
	world.clock.Set(ticket.ticket.NotBefore)
	world.keep(t, ticket)
	world.wantLapsed(t, ticket.ticket.NotAfter.Add(time.Hour), ComputeRemoteLapseTicketExpired)
	policy, err := world.gate.PolicyCurrent()
	if err != nil || policy.Version != 3 {
		t.Errorf("fetches, calendar links and connections after a lapse: %v, %v", policy, err)
	}
	for _, operation := range ComputeRemoteOperations {
		if operation == "local_inference" || operation == "fetch" || operation == "calendar" || operation == "connection" {
			t.Errorf("%s is gated as remote work", operation)
		}
	}
	err = world.gate.RemoteWork(context.Background(), "local_inference")
	lapsed := &ComputeRemoteLapsedError{}
	if !errors.As(err, &lapsed) || lapsed.Reason != ComputeRemoteLapseOperationUnknown {
		t.Errorf("an operation the gate does not know: %v", err)
	}
}

// The staging policy expires 7 days after the device took it whatever it says, and the banner shows only while it
// is in force; a production build never shows it.
func TestStagingPolicyExpiresAfterSevenDays(t *testing.T) {
	world := newTestAttestGateWorld(t, true)
	if policy := world.policyStore.Newest(); policy == nil || policy.Signer().Namespace != ComputePolicyStagingNamespace {
		t.Fatalf("the staging world's policy %v", policy)
	}
	batch := world.batch(t, testAttestSitting, 3, false)
	expires := testAttestSitting.Add(7 * 24 * time.Hour)
	ticket := testAttestTicketAt(t, batch, testAttestDay(expires))
	world.clock.Set(ticket.ticket.NotBefore)
	world.keep(t, ticket)
	world.wantRemoteWork(t, expires.Add(-time.Second))
	if _, err := world.gate.PolicyCurrent(); err != nil || !world.gate.Staging() {
		t.Errorf("a day before its 7 days: %v, staging %t", err, world.gate.Staging())
	}
	world.wantLapsed(t, expires, ComputeRemoteLapsePolicyExpired)
	if _, err := world.gate.PolicyCurrent(); !errors.Is(err, ErrComputePolicyNotCurrent) || world.gate.Staging() {
		t.Errorf("at its 7 days: %v, staging %t", err, world.gate.Staging())
	}
	production := newTestAttestGateWorld(t, false)
	if production.gate.Staging() {
		t.Error("a production build shows the staging banner")
	}
}

// A lapse a fetch could answer asks Refresh once, judges again, and asks no more often than FetchMinInterval; an
// operation the gate does not know asks nothing.
func TestRemoteWorkRefreshesAtMostOncePerInterval(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	ticket := testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC))
	refreshes := atomic.Int32{}
	gate, err := NewComputePolicyGate(&ComputePolicyGateArgs{
		Store:    world.policyStore,
		Verifier: world.verifier,
		Settings: DefaultAttestSettings(),
		Refresh: func(ctx context.Context) error {
			refreshes.Add(1)
			_, err := world.gate.OfferTicket(ticket.file)
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Set(ticket.ticket.NotBefore.Add(time.Hour))
	if err := gate.RemoteWork(context.Background(), ComputeRemoteSearch); err != nil || refreshes.Load() != 1 {
		t.Fatalf("a lapse the refresh answers: %v, %d refreshes", err, refreshes.Load())
	}
	world.clock.Set(ticket.ticket.NotAfter)
	if err := gate.RemoteWork(context.Background(), ComputeRemoteSearch); !errors.Is(err, ErrComputeRemoteLapsed) || refreshes.Load() != 2 {
		t.Fatalf("a lapse the refresh does not answer: %v, %d refreshes", err, refreshes.Load())
	}
	if err := gate.RemoteWork(context.Background(), ComputeRemoteSearch); !errors.Is(err, ErrComputeRemoteLapsed) || refreshes.Load() != 2 {
		t.Errorf("a second lapse within the interval: %v, %d refreshes", err, refreshes.Load())
	}
	world.clock.Set(ticket.ticket.NotAfter.Add(DefaultAttestSettings().FetchMinInterval))
	if err := gate.RemoteWork(context.Background(), ComputeRemoteSearch); !errors.Is(err, ErrComputeRemoteLapsed) || refreshes.Load() != 3 {
		t.Errorf("past the interval: %v, %d refreshes", err, refreshes.Load())
	}
	if err := gate.RemoteWork(context.Background(), "unknown"); !errors.Is(err, ErrComputeRemoteLapsed) || refreshes.Load() != 3 {
		t.Errorf("an unknown operation: %v, %d refreshes", err, refreshes.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	world.clock.Set(ticket.ticket.NotAfter.Add(2 * DefaultAttestSettings().FetchMinInterval))
	gate.refreshSlot <- struct{}{}
	if err := gate.RemoteWork(ctx, ComputeRemoteSearch); !errors.Is(err, ErrComputeRemoteLapsed) || refreshes.Load() != 3 {
		t.Errorf("a refresh already running and the caller's context done: %v, %d refreshes", err, refreshes.Load())
	}
	<-gate.refreshSlot
}

// On a Sidecar the gate is built with the store, and in a build from this tree, which pins no release key, every
// remote operation is refused for want of a policy, no policy is current and no staging banner shows; with no serving
// path set, the refresh it asks fetches nothing.
func TestSidecarComputePolicyGateRefusesWithNoRoot(t *testing.T) {
	if computePolicyReleaseKeys != "" {
		t.Skip("this build pins a release key")
	}
	instance, enrollment := newTestEnrolledInstance(t)
	settings := testSidecarSettings(newTestSidecarPlatform())
	settings.Attest = DefaultAttestSettings()
	settings.Attest.FetchBaseUrls = []string{}
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, settings)
	gate, err := sidecar.ComputePolicyGate()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range ComputeRemoteOperations {
		err := gate.RemoteWork(context.Background(), operation)
		lapsed := &ComputeRemoteLapsedError{}
		if !errors.As(err, &lapsed) || lapsed.Reason != ComputeRemoteLapsePolicyUnavailable {
			t.Errorf("%s: %v", operation, err)
		}
	}
	if _, err := gate.PolicyCurrent(); !errors.Is(err, ErrComputePolicyNotCurrent) || gate.Staging() || gate.Ticket() != nil {
		t.Errorf("a gate with no policy: %v, staging %t", err, gate.Staging())
	}
}
