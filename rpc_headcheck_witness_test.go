// witnessed_at and the revoker on a fake clock: the 24 h alarm once per lapse and again after the next
// witness, a refresh only for the pin compared, and a revocation this device signed asked about each
// HeadCheckUnwitnessedInterval, alarmed at an hour, and cleared by a standing peer at or past it.

package sidecar

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Reconciles message from peerId and ends the exchange, answering its witness.
func (self *testHeadStop) exchange(peerId Id, message headCheckMessage) *headCheckWitness {
	self.t.Helper()
	step, err := self.stop.reconcile(peerId, message)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.stop.witness(peerId, message, step.forked)
}

func TestHeadStopAlarmsUnwitnessedAt24Hours(t *testing.T) {
	fixture := newTestHeadStop(t)
	fixture.advance(24*time.Hour-time.Minute, false)
	fixture.noAlarm()
	fixture.advance(time.Minute, true)
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmUnwitnessed || alarm.SidecarId != nil ||
		!bytes.Equal(alarm.Evidence[0], headCheckEvidence(testMainChain.pin(10))) || len(alarm.Evidence[1]) != 0 {
		t.Fatalf("alarm %+v", alarm)
	}
	// once per lapse
	fixture.advance(48*time.Hour, false)
	fixture.noAlarm()
	// a witness re-arms it, 24 h from then, with the pin it witnessed as evidence
	if fixture.exchange(testHeadPeer, fixture.device.message(testMainChain.pin(10))) == nil {
		t.Fatal("no witness")
	}
	fixture.advance(24*time.Hour-time.Minute, false)
	fixture.noAlarm()
	fixture.advance(time.Minute, true)
	alarm = fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmUnwitnessed || !bytes.Equal(alarm.Evidence[1], headCheckEvidence(testMainChain.pin(10))) {
		t.Fatalf("alarm %+v", alarm)
	}
}

func TestHeadStopWitnessRefreshesOnlyWhatItCompared(t *testing.T) {
	fixture := newTestHeadStop(t)
	// a peer behind refreshes nothing
	if fixture.exchange(testHeadPeer, fixture.device.message(testMainChain.pin(8))) != nil || !fixture.stop.WitnessedAt().IsZero() {
		t.Fatal("a peer behind witnessed")
	}
	// a suspended peer at this device's pin refreshes nothing either
	fixture.device.peers[testHeadPeerB] = HeadCheckPeer{Admitted: true, Suspended: true}
	if fixture.exchange(testHeadPeerB, fixture.device.message(testMainChain.pin(10))) != nil || !fixture.stop.WitnessedAt().IsZero() {
		t.Fatal("a suspended peer witnessed")
	}
	fixture.advance(time.Hour, false)
	witness := fixture.exchange(testHeadPeer, fixture.device.message(testMainChain.pin(10)))
	if witness == nil || !headCheckPinEqual(witness.pin, testMainChain.pin(10)) {
		t.Fatalf("witness %+v", witness)
	}
	if want := testHeadStart.Add(time.Hour); !fixture.stop.WitnessedAt().Equal(want) {
		t.Fatalf("witnessed_at %v, want %v", fixture.stop.WitnessedAt(), want)
	}
}

func TestHeadStopRevokerRetriesAlarmsAndClears(t *testing.T) {
	fixture := newTestHeadStop(t)
	fixture.device.follow(testMainChain, 1, 15)
	fixture.stop.TrackRevocation(12)
	// asked for at once, then each HeadCheckUnwitnessedInterval
	<-fixture.rounds
	if positions := fixture.stop.UnwitnessedRevocations(); len(positions) != 1 || positions[0] != 12 {
		t.Fatalf("positions %v", positions)
	}
	for range 5 {
		fixture.advance(10*time.Minute, true)
		<-fixture.rounds
		fixture.noAlarm()
	}
	// an hour unwitnessed alarms, with the revocation's position and this device's pin
	fixture.advance(10*time.Minute, true)
	<-fixture.rounds
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmUnwitnessed ||
		!bytes.Equal(alarm.Evidence[0], headCheckEvidence(&bridge.AuthPin{Version: 12})) || !bytes.Equal(alarm.Evidence[1], headCheckEvidence(testMainChain.pin(15))) {
		t.Fatalf("alarm %+v", alarm)
	}
	// a peer short of it, and a revoked one past it, hold nothing that clears it
	fixture.exchange(testHeadPeer, fixture.device.message(testMainChain.pin(11)))
	fixture.device.peers[testHeadPeerC] = HeadCheckPeer{Admitted: true, Revoked: true}
	fixture.stop.witness(testHeadPeerC, fixture.device.message(testMainChain.pin(15)), false)
	if len(fixture.stop.UnwitnessedRevocations()) != 1 {
		t.Fatal("cleared by a peer that does not hold it")
	}
	// a standing peer at or past it clears it, and the rounds stop
	fixture.exchange(testHeadPeerB, fixture.device.message(testMainChain.pin(13)))
	if positions := fixture.stop.UnwitnessedRevocations(); len(positions) != 0 {
		t.Fatalf("positions %v", positions)
	}
	fixture.advance(10*time.Minute, false)
	select {
	case <-fixture.rounds:
		t.Fatal("a round asked for after the revocation was witnessed")
	default:
	}
}

func TestHeadStopTracksARevocationOnce(t *testing.T) {
	fixture := newTestHeadStop(t)
	fixture.stop.TrackRevocation(12)
	fixture.stop.TrackRevocation(12)
	<-fixture.rounds
	select {
	case <-fixture.rounds:
		t.Fatal("asked twice")
	default:
	}
	if positions := fixture.stop.UnwitnessedRevocations(); len(positions) != 1 {
		t.Fatalf("positions %v", positions)
	}
}
