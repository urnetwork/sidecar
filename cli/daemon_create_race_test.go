//go:build sidecar_testhooks

// A creation raced by its creator's own key client, on the daemon's composition over real engines with gkm's caches as
// production runs them (§11.8's resolve row), where enginenet's own gkm caches nothing so that a test sees each write
// at once. A state that brings a new repo starts the key client's sync of it (GkmGroupClient.syncNewReaderRepos), which
// asks gkm for the repo's forms before the creator's PUT places it, held here until it has, and gkm keeps that 404
// 5 s for reads. Before the fix it refused the creator's KF1, sent right after the placement: the first device's
// bootstrap failed "config bootstrap: the config repo: evs: the repo's group: gkm refused: 404" and its follower could
// stand only at its 10 s anchor retry, which on the Net's clock, unmoved here, never comes; and EvsClient.CreateRepo of
// a shared repo failed "evs: the repo's group: gkm refused: 404".

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The status a handler wrote.
type testUrStatusWriter struct {
	http.ResponseWriter
	status int
}

func (self *testUrStatusWriter) WriteHeader(status int) {
	self.status = status
	self.ResponseWriter.WriteHeader(status)
}

// gkm with its production settings on the Net's host, behind the engines' gate, in place of the world's gkm: every
// request the daemon makes of gkm reaches it. Each GET of a repo's forms it answers 404 sends that repo's id, as the
// path names it, on the channel, which keeps the newest 64.
func testUrProductionGkm(t *testing.T, net *sidecartest.Net, engines *enginenet.Engines) <-chan string {
	t.Helper()
	revocationSettings := sidecar.DefaultRevocationSettings()
	revocationSettings.Clock = net.Clock()
	revocations := sidecar.NewRevocationChecker(net.Host().Blobs, func(object []byte) ([]byte, error) {
		return nil, errors.New("this world signs no revocation object")
	}, revocationSettings)
	state := gkmservice.NewAclGkmAuthState(engines.Gate(), revocations, net.Clock())
	built, err := net.AddEngine("gkm-production", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return gkmservice.NewGkmEngine(ctx, host, gkmservice.DefaultGkmServiceSettings(), &gkmservice.GkmEngineDeps{AuthState: state})
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := built.(*gkmservice.GkmEngine)
	notFound := make(chan string, 64)
	engines.Api().ServeService(gkmservice.GkmAudience, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capture := &testUrStatusWriter{ResponseWriter: writer, status: http.StatusOK}
		engine.Handler().ServeHTTP(capture, request)
		repoHex, forms := strings.CutSuffix(strings.TrimPrefix(request.URL.Path, "/gkm/repos/"), "/forms")
		if request.Method == http.MethodGet && forms && capture.status == http.StatusNotFound {
			select {
			case notFound <- repoHex:
			default:
			}
		}
	}))
	return notFound
}

// Waits for a GET of a repo's forms gkm answered 404, of a repo that pick takes.
func testUrAwaitNotFound(t *testing.T, ctx context.Context, notFound <-chan string, pick func(repoHex string) bool) {
	t.Helper()
	for {
		select {
		case repoHex := <-notFound:
			if pick(repoHex) {
				return
			}
		case <-ctx.Done():
			t.Fatal("no read of the new repo's forms met it unplaced")
		}
	}
}

// The owner's follower bootstraps an empty network while its own key client's sync of the config repo meets gkm's
// 404 ahead of the placement: the follower stands at its first attempt, the Net's clock unmoved, on its own base 1
// with the config repo's first head on evs.
func TestDaemonFirstNetworkStandsThoughItsOwnSyncRacesTheConfigRepoPlacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, net, settings)
	notFound := testUrProductionGkm(t, net, engines)
	networkId, ownerId := sidecar.NewId(), sidecar.NewId()
	engines.OpenNetwork(networkId)
	engines.Api().SetPersonalOwner(networkId, ownerId)
	instance, err := net.StartInstance("owner", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := net.Clock().Now()
	// the bootstrap's PUT of the config repo, held until the key client's own sync has met the 404
	site := evsservice.BarrierPlacePutBefore
	if err := net.Barriers().Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	testUrAwaitNotFound(t, ctx, notFound, func(string) bool { return true })
	if err := net.Barriers().AwaitHeld(ctx, site, ""); err != nil {
		t.Fatal(err)
	}
	if err := net.Barriers().Release(site); err != nil {
		t.Fatal(err)
	}
	// real time bounds only the failure: a bootstrap refused waits for its anchor retry on a clock nothing moves
	standCtx, standCancel := context.WithTimeout(ctx, urTestTimeout)
	defer standCancel()
	client, err := follower.WaitStanding(standCtx)
	if err != nil {
		t.Fatalf("the first owner's bootstrap: %+v: %v", follower.Status(), err)
	}
	state := follower.VerifiedState()
	if client.Pin().GetVersion() != 1 || state.Genesis() == nil {
		t.Fatalf("the owner did not stand on its own base: %v", client.Pin())
	}
	repoId, err := sidecar.IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		t.Fatal(err)
	}
	heads, err := engines.RefHeads(ctx, repoId)
	if err != nil || len(heads) != 1 || heads[0].GetVersion() != 1 {
		t.Fatalf("the first config repo heads: %v %v", heads, err)
	}
	if now := net.Clock().Now(); !now.Equal(start) {
		t.Errorf("the clock moved %s", now.Sub(start))
	}
}

// A standing owner creates a general repo through evs while its key client's sync of the new repo, which the
// RepoCreate's state starts, meets gkm's 404 ahead of the PUT: EvsClient.CreateRepo's KF1 right after the placement
// is taken, and the owner holds the repo's generation 1. The network is bootstrapped on the world's gkm, which caches
// nothing, and the production one serves from the create on.
func TestDaemonCreateRepoRacedByItsOwnSyncOfTheNewRepoIsTaken(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	running, gkm, result := bootstrapTestDaemonOwner(t, ctx, net, engines)
	notFound := testUrProductionGkm(t, net, engines)
	if startUrConfigFollower(running, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started")
	}
	standCtx, standCancel := context.WithTimeout(ctx, urTestTimeout)
	defer standCancel()
	if _, err := running.ConfigFollower().WaitStanding(standCtx); err != nil {
		t.Fatalf("the follower: %v (%+v)", err, running.ConfigFollower().Status())
	}
	configRepoHex := sidecar.EvsKeyId(result.ConfigRepoId)
	site := evsservice.BarrierPlacePutBefore
	if err := net.Barriers().Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	type created struct {
		repoId sidecar.Id
		err    error
	}
	creates := make(chan created, 1)
	go func() {
		repoId, err := engines.CreateRepo(ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
		creates <- created{repoId: repoId, err: err}
	}()
	testUrAwaitNotFound(t, ctx, notFound, func(repoHex string) bool { return repoHex != configRepoHex })
	if err := net.Barriers().AwaitHeld(ctx, site, ""); err != nil {
		t.Fatal(err)
	}
	if err := net.Barriers().Release(site); err != nil {
		t.Fatal(err)
	}
	create := <-creates
	if create.err != nil {
		t.Fatalf("EvsClient.CreateRepo raced by its own sync: %v", create.err)
	}
	key, err := gkm.CurrentRepoKey(ctx, create.repoId)
	if err != nil || key.Generation() != 1 {
		t.Fatalf("the new repo's generation 1: %v", err)
	}
}
