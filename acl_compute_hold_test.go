// §16.6's hold (CACL-M11-02): a reader whose release lacks a feature its network turned on holds at that base, or at a
// later one it starts from, applying nothing from there, through the fork stop with no fork alarm and upgrade_required
// raised once, while what it holds stays readable; updated, it resumes where it stopped and agrees with the network.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The upgrade_required events a client world raised, and its head alarms of any kind.
func (self *testConfigClientWorld) upgradeEvents() ([]SidecarEvent, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	upgrades := []SidecarEvent{}
	headAlarms := 0
	for _, event := range self.events {
		switch event.Kind {
		case SidecarEventUpgradeRequired:
			upgrades = append(upgrades, event)
		case SidecarEventHeadAlarm:
			headAlarms += 1
		}
	}
	return upgrades, headAlarms
}

// Waits until the client stops, a fork or a hold, and answers what stopped it.
func testFeatureStopped(t *testing.T, client *ConfigClient) *ConfigForkError {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		stopped, changed := client.stopped.Get()
		if stopped != nil {
			return stopped
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("the client never stopped")
		}
	}
}

func TestAuthFeatureHoldStopsWrites(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	// the network's own reader implements agent_repos; the client's release does not
	net.log.authFeatures = AuthFeatureAgentRepos
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	world.publish()
	client := world.client(nil)
	held := world.caughtUp(client)
	callbacks := atomic.Int32{}
	client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		callbacks.Add(1)
	})

	// the network turns agent_repos on, and admits a device after it
	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	net.fold(net.owner, net.n, configVersion)
	baseAt := net.n
	net.admitDevice(first, net.device("m second", member), 0)
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})

	hold := testFeatureStopped(t, client)
	if !hold.Held() || hold.N != baseAt || hold.UpgradeRequired != AuthFeatureAgentRepos {
		t.Fatalf("the client stopped at %v", hold)
	}
	// every path the fork stop stops stops: the client answers the hold as its fork, and every wait returns it
	if fork := client.Fork(); fork != hold || !errors.Is(fork, ErrConfigUpgradeRequired) || errors.Is(fork, ErrConfigFork) {
		t.Fatalf("the client's stop %v", fork)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.WaitFor(ctx, net.n); !errors.Is(err, ErrConfigUpgradeRequired) {
		t.Fatalf("a wait past the base: %v", err)
	}
	// it publishes nothing past the base: no state, no entry callback, no AuthAdvanced
	if state := client.State(); state.Pin().GetVersion() != baseAt-1 || state.Pin().GetVersion() != held.Pin().GetVersion() {
		t.Fatalf("the client's state moved to %d", state.Pin().GetVersion())
	}
	world.gkm.stateLock.Lock()
	positions := slices.Clone(world.gkm.positions)
	world.gkm.stateLock.Unlock()
	if callbacks.Load() != 0 || slices.ContainsFunc(positions, func(position uint64) bool { return baseAt <= position }) {
		t.Fatalf("%d callbacks, and AuthAdvanced at %v, past the base", callbacks.Load(), positions)
	}
	// it judges nothing more: a statement's check is refused at the stop
	statement := net.sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m third", member), nil, false, 0, 0))
	if verdict := client.Log().Check(statement, net.timeMs); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRefused) {
		t.Fatalf("a held log judged a statement: %v", verdict.Refusal)
	}
	// raised once, upgrade_required naming what it lacks, and no head_alarm or fork report
	upgrades, headAlarms := world.upgradeEvents()
	if len(upgrades) != 1 || upgrades[0].AuthFeatures != AuthFeatureAgentRepos || headAlarms != 0 || len(world.forks) != 0 {
		t.Fatalf("%d upgrade_required, %d head alarms, %d forks reported", len(upgrades), headAlarms, len(world.forks))
	}
	// a later follow changes nothing and raises nothing more
	if err := client.CatchUp(ctx); !errors.Is(err, ErrConfigUpgradeRequired) {
		t.Fatalf("a later follow: %v", err)
	}
	if upgrades, _ := world.upgradeEvents(); len(upgrades) != 1 {
		t.Fatalf("%d upgrade_required after another follow", len(upgrades))
	}
	// what it holds stays readable
	if row := client.State().SidecarRow(first.sidecarId); row == nil {
		t.Fatal("the held state reads no row")
	}
}

func TestAuthFeatureHoldFromLaterBase(t *testing.T) {
	net := newTestConfigNet(t)
	net.log.authFeatures = AuthFeatureListeners
	_, first := net.consentedMember("m")
	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureListeners)}
	net.fold(net.owner, net.n, configVersion)
	baseAt := net.n
	net.admitDevice(first, net.device("m second", first.memberId), 0)

	// a reader that starts at that base, a new device's or a restart's, from the entries it kept or api serves
	retained := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries[baseAt-1:], Rows: map[[sha256.Size]byte][]byte{}}
	_, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	hold := &ConfigForkError{}
	if !errors.As(err, &hold) || !hold.Held() || hold.N != baseAt || hold.UpgradeRequired != AuthFeatureListeners {
		t.Fatalf("a start at the base: %v", err)
	}
	// a rows-only gate starting there holds alike
	_, err = RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, net.source, nil)
	if !errors.Is(err, ErrConfigUpgradeRequired) {
		t.Fatalf("a rows-only start at the base: %v", err)
	}
	// and the same release, implementing the feature, starts there
	WithAuthFeaturesImplementedForTest(t, AuthFeatureListeners, nil)
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(restored.Pin(), net.log.Pin()) || !bytes.Equal(testConfigRowsBytes(t, restored.State()), testConfigRowsBytes(t, net.log.State())) ||
		!restored.State().AuthFeatureOn(AuthFeatureListeners) {
		t.Fatal("a start at the base by a release implementing it does not reach the network's state")
	}

	// a client whose first page starts at that base, api's retention point past it, holds with no fork alarm
	WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := &testConfigClientWorld{t: t, net: net, projection: newTestConfigProjection(net), heads: newTestConfigHeadReader(net),
		store: newTestConfigClientStore(), clock: newTestConfigClock(), gkm: &testConfigGkm{}}
	registerTestConfigAclCompiler(t)
	world.projection.retainedFrom = baseAt
	client := world.client(nil)
	stopped := testFeatureStopped(t, client)
	if !stopped.Held() || stopped.N != baseAt || client.State() != nil {
		t.Fatalf("the client's start stopped at %v", stopped)
	}
	upgrades, headAlarms := world.upgradeEvents()
	if len(upgrades) != 1 || headAlarms != 0 {
		t.Fatalf("%d upgrade_required, %d head alarms", len(upgrades), headAlarms)
	}
}

func TestAuthFeatureResumeAgrees(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.log.authFeatures = AuthFeatureAgentRepos
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	world.publish()
	settings := DefaultConfigClientSettings()
	settings.RetainFullTail = true
	client := world.client(settings)
	world.caughtUp(client)

	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	net.fold(net.owner, net.n, configVersion)
	baseAt := net.n
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	// bits only accumulate: the next head keeps the feature on
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion+1))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	net.fold(net.owner, net.n, configVersion+1)
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	if hold := testFeatureStopped(t, client); !hold.Held() || hold.N != baseAt {
		t.Fatalf("the old release stopped at %v", hold)
	}
	client.Close()

	// updated: the new release restores what the old one kept, below the base, and resumes there, verifying the base
	// by its rows check before it judges on
	WithAuthFeaturesImplementedForTest(t, AuthFeatureAgentRepos, nil)
	updated := world.client(settings)
	resumed := world.caughtUp(updated)
	testConfigStatesEqual(t, resumed, net.log.State())
	if !resumed.AuthFeatureOn(AuthFeatureAgentRepos) || resumed.SidecarRow(second.sidecarId) == nil {
		t.Fatal("the updated release does not agree on the admission past the base")
	}
	if fork := updated.Fork(); fork != nil {
		t.Fatalf("the updated release stops at %v", fork)
	}
	if upgrades, headAlarms := world.upgradeEvents(); len(upgrades) != 1 || headAlarms != 0 {
		t.Fatalf("%d upgrade_required and %d head alarms in all", len(upgrades), headAlarms)
	}
}

func TestAuthFeatureFaultyReaderRederives(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.log.authFeatures = AuthFeatureAgentRepos
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	keepOn := func(version uint64) {
		net.source.settings[[sha256.Size]byte(testConfigHeadSha256(version))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	}
	keepOn(configVersion)
	net.fold(net.owner, net.n, configVersion)
	net.admitDevice(first, net.device("m second", member), 0)
	world.publish()

	// a faulty build: it applies the base and judges past it, but writes as a release that does not implement it
	WithAuthFeaturesImplementedForTest(t, AuthFeatureAgentRepos, nil)
	settings := DefaultConfigClientSettings()
	settings.RetainFullTail = true
	faulty := world.client(settings)
	world.caughtUp(faulty)
	faulty.Close()
	document := world.store.document(t)
	if AuthFeature(document.AuthFeatures) != AuthFeatureAgentRepos {
		t.Fatalf("the file names %d", document.AuthFeatures)
	}
	document.AuthFeatures = 0
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	world.store.stateLock.Lock()
	world.store.files[configClientFileName] = data
	world.store.stateLock.Unlock()

	// updated, it rebuilds the log under its own rules and acts on nothing until the network's next base
	updated := world.client(settings)
	rederive := updated.Fork()
	if rederive == nil || !rederive.Rederiving || !rederive.Held() || !errors.Is(rederive, ErrConfigRederiving) || errors.Is(rederive, ErrConfigFork) ||
		rederive.UpgradeRequired != AuthFeatureAgentRepos || updated.stop() != nil {
		t.Fatalf("the restart's stop %v", rederive)
	}
	// it follows on through the wait, every path that acts on the log stopped meanwhile
	third := net.device("m third", member)
	net.admitDevice(first, third, 0)
	world.publish()
	updated.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	world.caughtUp(updated)
	if updated.Fork() != rederive {
		t.Fatal("the wait ended before a base past it")
	}
	// the network's next base, whose rows and tail verdicts agree with what it re-derived, ends the wait
	keepOn(configVersion + 1)
	net.fold(net.owner, net.n, configVersion+1)
	world.publish()
	updated.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	confirmed := world.caughtUp(updated)
	testConfigStatesEqual(t, confirmed, net.log.State())
	if fork := updated.Fork(); fork != nil {
		t.Fatalf("after the network's next base: %v", fork)
	}
	if confirmed.SidecarRow(third.sidecarId) == nil {
		t.Fatal("the re-derived log misses the admission it judged on")
	}
	if upgrades, headAlarms := world.upgradeEvents(); len(upgrades) != 0 || headAlarms != 0 || len(world.forks) != 0 {
		t.Fatalf("%d upgrade_required, %d head alarms, %d forks reported", len(upgrades), headAlarms, len(world.forks))
	}
}
