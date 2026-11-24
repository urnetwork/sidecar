//go:build !sidecar_http

// A device's key client before its config follower stands, as the daemon composes it, over GkmApi itself: a
// KeyDelivery client with its hints attached, handed a state unconfirmed (AuthUnconfirmed), which starts its join of
// the config group on the config repo's flow (QD-817's sync). A network's first device is handed the genesis
// (sidecar_config_bootstrap.go's firstOwnerGenesis), then drafts the group (DraftGroup) and, once base 1 lands, forms
// it (CreateGroup), the three on the one flow; until base 1 lands api's gate holds no state of the network, so the
// exchange answers every ask 503 temporarily_unavailable, as server/oauth's does, and the genesis gives the device no
// scope, so the join reads the repo's forms under the config repo's r alone, a role its state does not give. A joining
// device is handed the newest state its follower reads rows-only, whose config repo scope the state applier hands
// GkmApi as unconfirmed (SetUnconfirmedRepoScopes), and its follower's own reads of the config heads take the same
// flow. GkmApi asks either join once whatever the exchange answers, since no verified state gives what it presents;
// QD-1230's ride-out keeps a grant a verified state gives (gkm_grant_lag_test.go).

package sidecar_test

import (
	"context"
	"crypto/hpke"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A KeyDelivery client of device, as the daemon's is, over GkmApi on exchange and a gkm guarding on the world's log, its
// hints attached and no state handed yet, with the grant-lag world that drives it.
func newGkmBootstrapRideOutClient(world *gkmFlowWorld, device *gkmFlowDevice, exchange *gkmGrantLagExchange) *gkmGrantLagWorld {
	world.t.Helper()
	gkm := &gkmGrantLagGkm{t: world.t, log: world.log, exchange: exchange}
	settings := sidecar.DefaultGkmSettings()
	api, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:              "https://gkm.example",
		Transport:           gkm,
		GrantedServiceToken: exchange.token(device.id),
		Settings:            settings,
		Clock:               world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	groupApi := &gkmGrantLagApi{api: api, fake: device.api, hooks: map[string]func(){}}
	client, err := sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: device.id,
		Api:       groupApi,
		Sign:      device.signer.Sign,
		Secrets:   device.secrets,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := device.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return device.readerKeySha256 },
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return world.recoveryKeys[memberId], nil
		},
		Alarm:      func(alarm *sidecar.GkmAlarm) { device.alarms = append(device.alarms, alarm) },
		HoldsState: func() bool { return true },
		Jitter:     func(max time.Duration) time.Duration { return 0 },
		Clock:      world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	device.client = client
	ctx, cancel := context.WithCancel(world.ctx)
	world.t.Cleanup(cancel)
	hints, err := sidecar.NewGkmHints(ctx, &sidecar.GkmHintsArgs{Clock: world.clock})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(hints.Close)
	client.AttachHints(ctx, hints)
	return &gkmGrantLagWorld{
		gkmFlowWorld: world,
		exchange:     exchange,
		gkm:          gkm,
		device:       device,
		api:          api,
		groupApi:     groupApi,
		apiSettings:  settings,
	}
}

// Hands the device's client view unconfirmed, the world's repo its config repo, as its follower does before it stands,
// and answers once the join's sync this starts holds the repo's flow, its read of the repo's forms on its way to GkmApi.
func (self *gkmGrantLagWorld) joinUnconfirmed(view sidecar.GkmAuthView) {
	self.t.Helper()
	joining := make(chan struct{})
	self.groupApi.hook("Forms", func() { close(joining) })
	self.device.client.AuthUnconfirmed(view, self.repoId)
	select {
	case <-joining:
	case <-time.After(time.Minute):
		// only a failure's bound: the join never reached its read
		self.t.Fatal("the join's sync never read the config repo's forms")
	}
}

// The first device's join before base 1 asks the exchange once, for the config repo's r alone, and ends at its 503,
// nothing sent to gkm, so its draft and, once base 1 lands, its creation take the config repo's flow at once and form
// the drafted group with the clock where it stood. The code before (sidecar cf4431a9) asked that 503 again
// ExchangeRetryCount times ReadRetryWait apart, holding the flow, so the draft waited 3 s of the clock behind the join;
// on a clock that stands still, as the daemon tests' Net's does, the first owner's anchoring waited for good.
func TestAFirstDevicesJoinBeforeBaseOneLeavesItsCreationNothingToWaitFor(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	owner := world.flows[world.a]
	exchange := &gkmGrantLagExchange{
		clock:   world.clock,
		repoId:  world.repoId,
		otherId: sidecar.NewId(),
		// the network's first device admins the config repo at base 1, at api's gate and at gkm's
		admins: map[sidecar.Id]bool{owner.id: true},
		tokens: map[string]*gkmGrantLagToken{},
	}
	// api's gate holds no state of the network before base 1
	unloaded := &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable"}
	exchange.refuse(unloaded)
	lag := newGkmBootstrapRideOutClient(world, owner, exchange)
	client := owner.client

	// the genesis, which gives the device no scope (the state applier's at it)
	lag.api.SetUnconfirmedRepoScopes(nil)
	lag.joinUnconfirmed(gkmGenesisView{FakeGkmAuthView: world.log.Tip()})
	var drafted, formed *sidecar.EvsRepoKey
	err, took := lag.drive(func() error {
		var err error
		drafted, err = client.DraftGroup(world.ctx, world.createArgs())
		if err != nil {
			return err
		}
		// base 1 lands: api's gate holds it, and the state applier gives the device the config repo's admin
		exchange.refuse(nil)
		exchange.apply(world.log.Tip())
		lag.api.SetRepoScopes([]sidecar.GkmRepoScope{{RepoId: world.repoId, Role: sidecar.GkmScopeRoleAdmin}})
		client.AuthAdvanced(world.log.Tip())
		formed, err = client.CreateGroup(world.ctx, world.createArgs())
		return err
	})
	if err != nil {
		t.Fatalf("the first device's draft and creation: %v", err)
	}
	if took != 0 {
		t.Errorf("the draft and the creation took %s of the clock behind the join", took)
	}
	joins := exchange.asked(owner.id, gkmGrantLagScope(world.repoId, sidecar.GkmScopeRoleRead))
	if len(joins) != 1 || !errors.Is(joins[0].err, unloaded) {
		t.Errorf("the join asked the exchange for the config repo's r %d times", len(joins))
	}
	if formed.GroupId() != drafted.GroupId() || world.store.groupOwnerRepoIds[drafted.GroupId()] != world.repoId {
		t.Error("the creation did not form the drafted group")
	}
	if taken := lag.gkm.taken("Forms"); len(taken) != 0 {
		t.Errorf("gkm took %d forms reads, the join having no token", len(taken))
	}
	if taken := lag.gkm.taken("CreateGroup"); len(taken) != 1 || taken[0].status != http.StatusOK {
		t.Errorf("gkm took %d creations", len(taken))
	}
}

// A joining device's join at its unconfirmed state, whose read grant api's gate has not taken yet though its
// admission is there: the join asks the exchange once for the config repo's r, the unconfirmed state's scope, and ends
// at its invalid_scope, nothing sent to gkm, so the follower's own read of the config heads, which takes the same flow,
// runs at once and ends the same way, with the clock where it stood. The code before (sidecar 7db6a152) read an
// unconfirmed state's scope as one the client's verified state gives and rode the join's invalid_scope out
// ExchangeScopeWaitTimeout, 5 s, holding the flow, and the read's after it; on the Net's still clock
// TestDaemonReadsBaseOneAtTheStartsState's follower waited for good.
func TestAJoiningDevicesJoinAtItsUnconfirmedStateLeavesItsHeadReadsNothingToWaitFor(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	// tagged, so KeyDelivery as the daemon's client is; its flows built by hand, so no client of it holds a verified
	// state
	joiner := world.admit("joiner", sidecar.NewId())
	admitted := world.state()
	world.grant(false, joiner)
	granted := world.state()
	device := &gkmFlowDevice{
		gkmWorldDevice:    joiner,
		world:             world,
		secrets:           newGkmFakeSecrets(),
		api:               world.store.api(joiner.label, joiner.id),
		readerPrivateKeys: map[string]hpke.PrivateKey{},
	}
	device.publishReaderKey()
	exchange := &gkmGrantLagExchange{
		clock:   world.clock,
		repoId:  world.repoId,
		otherId: sidecar.NewId(),
		admins:  map[sidecar.Id]bool{},
		tokens:  map[string]*gkmGrantLagToken{},
	}
	// api's gate holds the admission and not the grant
	exchange.apply(admitted)
	lag := newGkmBootstrapRideOutClient(world, device, exchange)

	// the state applier's scopes at the unconfirmed state: the config repo's alone
	lag.api.SetUnconfirmedRepoScopes([]sidecar.GkmRepoScope{{RepoId: world.repoId, Role: sidecar.GkmScopeRoleRead}})
	lag.joinUnconfirmed(granted)
	err, took := lag.drive(func() error {
		_, err := device.client.CurrentRepoKey(world.ctx, world.repoId)
		return err
	})
	var apiError *sidecar.SidecarApiError
	if !errors.As(err, &apiError) || apiError.Code != "invalid_scope" {
		t.Fatalf("the follower's read of the config heads ended with %v", err)
	}
	if took != 0 {
		t.Errorf("the read took %s of the clock behind the join", took)
	}
	if asks := exchange.asked(joiner.id, gkmGrantLagScope(world.repoId, sidecar.GkmScopeRoleRead)); len(asks) != 2 {
		t.Errorf("the join and the read asked the exchange %d times, want once each", len(asks))
	}
	if taken := lag.gkm.taken("Forms"); len(taken) != 0 {
		t.Errorf("gkm took %d forms reads with no token", len(taken))
	}
}
