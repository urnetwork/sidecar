//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The race that made TestS6ForwardAndRelayThroughMailsCode flaky ("a kind with no registered lookup is refused before
// its reserve", from M8Gate), as a fixed schedule on the laptop client's install barriers (mail_client.go's
// mailConfig): the component's first pass builds the client's mailcfg reader (RetireBurnedSelectors, through Burners)
// while the row's first CreateBurner builds another. Each build is held at mail.client.config.install.before, the
// component's first; the component's installs and is kept, held then at .after, and the burner's, built after it,
// finds it and closes. Before the fix each build registered its alias Lookups at construction, so the closed one,
// the last to register, took alias_create off the gate and the burner was refused before its Reserve. And M8Gate's
// own registry: a removal takes only the Lookup it added, as Sidecar.RegisterEffectLookup's does.
//
// The world is mail_m9_test.go's S6 world (mailworld's M9World with the component). Nothing sleeps: every step waits on
// a barrier or a run's end.

package sidecartest_test

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The client's install barriers around its mailcfg reader (mail_client.go).
const (
	mailM9ConfigInstallBefore = "mail.client.config.install.before"
	mailM9ConfigInstallAfter  = "mail.client.config.install.after"
)

// The burner the row's first CreateBurner makes while the component builds the laptop client's reader, both builds
// held at the install as the file header says: the burner is created, the gate holding the kept reader's alias
// Lookups, and once the component goes on a second burner is created too.
func TestS6BurnerCreatedAsTheComponentBuildsItsReaderPassesTheGate(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	barriers := net.Barriers()
	// the component's first pass is the world's first build of the reader: held at its install
	if err := barriers.Arm(mailM9ConfigInstallBefore, "", 0); err != nil {
		t.Fatal(err)
	}
	settings := mailworld.DefaultM9WorldSettings()
	settings.Component = true
	world := mailworld.NewM9World(t, net, settings)
	ctx := world.Context()
	if err := barriers.AwaitHeld(ctx, mailM9ConfigInstallBefore, ""); err != nil {
		t.Fatal(err)
	}

	// the row's CreateBurner, as an actor whose build is held at the install after the component's
	shopper := net.Actors().Actor(ctx, "shopper")
	if err := barriers.Arm(mailM9ConfigInstallBefore, shopper.Name(), 0); err != nil {
		t.Fatal(err)
	}
	createBurner := func(ctx context.Context, site string) (*sidecar.MailBurnerCreated, error) {
		return world.Owner.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: site})
	}
	var burner *sidecar.MailBurnerCreated
	run := barriers.Start(shopper, func() error {
		var err error
		burner, err = createBurner(ctx, "https://"+mailworld.M8SenderDomain+"/signup")
		return err
	})
	if err := barriers.AwaitHeldOrEnded(ctx, mailM9ConfigInstallBefore, shopper.Name(), run); err != nil {
		t.Fatal(err)
	}

	// the component's build, the oldest held, installs and is kept
	if err := barriers.Arm(mailM9ConfigInstallAfter, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := barriers.Release(mailM9ConfigInstallBefore); err != nil {
		t.Fatal(err)
	}
	if err := barriers.AwaitHeld(ctx, mailM9ConfigInstallAfter, ""); err != nil {
		t.Fatal(err)
	}
	// the burner's build finds it, closes, and the creation goes on through the kept reader
	if err := barriers.Release(sidecartest.ActorBarrierSite(shopper.Name(), mailM9ConfigInstallBefore)); err != nil {
		t.Fatal(err)
	}
	if err := barriers.AwaitChannel(ctx, "the burner's creation", run.Ended()); err != nil {
		t.Fatal(err)
	}
	if err := run.Err(); err != nil {
		t.Fatalf("the burner created as the component built its reader: %v", err)
	}
	if burner == nil || burner.Label == "" {
		t.Fatalf("the burner %+v", burner)
	}
	gate := world.M8.Gate
	if !gate.HoldsLookup(sidecar.SidecarActionAliasCreate) || !gate.HoldsLookup(sidecar.SidecarActionAliasDelete) {
		t.Fatal("the gate holds no alias Lookup while the client keeps a reader")
	}

	// the component goes on, and a second burner passes the gate as well
	if err := barriers.Release(mailM9ConfigInstallAfter); err != nil {
		t.Fatal(err)
	}
	second, err := createBurner(ctx, "https://other.example/signup")
	if err != nil {
		t.Fatalf("a second burner: %v", err)
	}
	if second.Label == burner.Label {
		t.Fatal("the second burner took the first's label")
	}
}

// M8Gate's registry keeps each kind's Lookup as the Sidecar's does: a later registration replaces an earlier one, an
// earlier one's removal then leaves it, and a removal takes the kind only while its own Lookup stands.
func TestM8GateRemovalTakesOnlyTheLookupItAdded(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	world := mailworld.NewM8World(t, net, nil)
	gate := world.Gate
	kind := sidecar.SidecarActionAliasCreate
	lookup := func(ctx context.Context, canonical []byte, effectKey []byte) (*sidecar.SidecarOutcome, error) {
		return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain}, nil
	}
	// the world's own client builds no reader, so the kind starts with no Lookup
	if gate.HoldsLookup(kind) {
		t.Fatal("a Lookup stands before any registration")
	}
	removeFirst := gate.RegisterEffectLookup(kind, lookup)
	removeSecond := gate.RegisterEffectLookup(kind, lookup)
	removeFirst()
	if !gate.HoldsLookup(kind) {
		t.Fatal("the first registration's removal took the second's Lookup")
	}
	removeSecond()
	if gate.HoldsLookup(kind) {
		t.Fatal("the standing registration's removal left its Lookup")
	}
	removeFirst()
	removeSecond()
	if gate.HoldsLookup(kind) {
		t.Fatal("a removal made again brought a Lookup back")
	}
}
