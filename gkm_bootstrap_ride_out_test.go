//go:build !sidecar_http

// A network's first device's bootstrap on gkm's side, as the daemon composes it (sidecar_config_bootstrap.go's
// firstOwnerGenesis), over GkmApi itself: a KeyDelivery client with its hints attached is handed the genesis
// unconfirmed, which starts its join of the config group (AuthUnconfirmed's sync), drafts the group (DraftGroup), and
// once base 1 lands forms it (CreateGroup), the three on the config repo's one flow. Until base 1 lands api's gate holds
// no state of the network, so the exchange answers every ask 503 temporarily_unavailable, as server/oauth's does; and
// the genesis gives the device no scope, so the join reads the repo's forms under the config repo's r alone, a role its
// state does not give, which GkmApi asks once whatever the exchange answers. QD-1230's ride-out keeps a grant the
// state gives (gkm_grant_lag_test.go).

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
	gkm := &gkmGrantLagGkm{t: t, log: world.log, exchange: exchange}
	settings := sidecar.DefaultGkmSettings()
	api, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:              "https://gkm.example",
		Transport:           gkm,
		GrantedServiceToken: exchange.token(owner.id),
		Settings:            settings,
		Clock:               world.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupApi := &gkmGrantLagApi{api: api, fake: owner.api, hooks: map[string]func(){}}
	// the daemon's: KeyDelivery, no MLS engine
	client, err := sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: owner.id,
		Api:       groupApi,
		Sign:      owner.signer.Sign,
		Secrets:   owner.secrets,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := owner.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return owner.readerKeySha256 },
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return world.recoveryKeys[memberId], nil
		},
		Alarm:      func(alarm *sidecar.GkmAlarm) { owner.alarms = append(owner.alarms, alarm) },
		HoldsState: func() bool { return true },
		Jitter:     func(max time.Duration) time.Duration { return 0 },
		Clock:      world.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner.client = client
	ctx, cancel := context.WithCancel(world.ctx)
	defer cancel()
	hints, err := sidecar.NewGkmHints(ctx, &sidecar.GkmHintsArgs{Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	client.AttachHints(ctx, hints)
	lag := &gkmGrantLagWorld{
		gkmFlowWorld: world,
		exchange:     exchange,
		gkm:          gkm,
		device:       owner,
		api:          api,
		groupApi:     groupApi,
		apiSettings:  settings,
	}

	// the genesis, which gives the device no scope (the state applier's SetRepoScopes at it), handed unconfirmed: the
	// join's sync starts on the hints' goroutine and holds the config repo's flow as its forms' read goes to GkmApi
	joining := make(chan struct{})
	groupApi.hook("Forms", func() { close(joining) })
	api.SetRepoScopes(nil)
	client.AuthUnconfirmed(gkmGenesisView{FakeGkmAuthView: world.log.Tip()}, world.repoId)
	select {
	case <-joining:
	case <-time.After(time.Minute):
		// only a failure's bound: the join never reached its read
		t.Fatal("the join's sync never read the config repo's forms")
	}

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
		api.SetRepoScopes([]sidecar.GkmRepoScope{{RepoId: world.repoId, Role: sidecar.GkmScopeRoleAdmin}})
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
	if taken := gkm.taken("Forms"); len(taken) != 0 {
		t.Errorf("gkm took %d forms reads, the join having no token", len(taken))
	}
	if taken := gkm.taken("CreateGroup"); len(taken) != 1 || taken[0].status != http.StatusOK {
		t.Errorf("gkm took %d creations", len(taken))
	}
}
