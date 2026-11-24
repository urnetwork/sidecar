//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The client's mailcfg reader against §16.6's gate (D-MCP-11; record_effect.go), on its install barriers: two first
// uses that each build a reader leave the one the client keeps with its alias Lookups registered, and a client closed
// while a build waits to install keeps and registers nothing. The gate here is the Sidecar's own Lookup registry,
// whose removal takes only the entry it added, and it refuses a kind with no registered Lookup before its Reserve as
// §16.6's gate does, so a reader the client closed can be seen taking the kept one's Lookups off it. Nothing sleeps:
// each build is held at its barrier until the test lets it go.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the registry gate answers for a kind with no registered Lookup.
var errTestMailRegistryNoLookup = errors.New("a kind with no registered lookup is refused before its reserve")

// §16.6's gate as far as a reader's Lookups go: the Sidecar's registry (Sidecar.RegisterEffectLookup), a kind with no
// Lookup there refused before its Reserve, and otherwise the effect run once under a key drawn from the action's
// bytes.
type testMailRegistryGate struct {
	registry *Sidecar
}

func newTestMailRegistryGate() *testMailRegistryGate {
	return &testMailRegistryGate{registry: &Sidecar{}}
}

func (self *testMailRegistryGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	if self.registry.effectLookup(action.Kind) == nil {
		return errTestMailRegistryNoLookup
	}
	effectRef, err := action.Effect.Run(ctx, mailConfigTestEffectKey(action.Canonical))
	switch {
	case err == nil:
		action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: effectRef}
	case errors.Is(err, ErrSidecarEffectNotDone):
		action.Outcome = &SidecarOutcome{State: ApprovalOutcomeNotDone, Err: err}
	default:
		action.Outcome = &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: err}
	}
	return nil
}

func (self *testMailRegistryGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	return self.registry.RegisterEffectLookup(kind, lookup)
}

// Whether both alias kinds have a Lookup registered.
func (self *testMailRegistryGate) holdsAliasLookups() bool {
	return self.registry.effectLookup(SidecarActionAliasCreate) != nil && self.registry.effectLookup(SidecarActionAliasDelete) != nil
}

// The client world with mail on, and a client of it that has built no mailcfg reader yet, bound to a registry gate.
func newTestMailConfigInstallWorld(t *testing.T) (*mailClientTestWorld, *MailClient, *testMailRegistryGate) {
	t.Helper()
	world := newMailClientTestWorld(t)
	world.enable()
	client := world.newClient()
	gate := newTestMailRegistryGate()
	binding, _, err := client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Gate = gate
	client.Bind(&copied)
	if gate.holdsAliasLookups() {
		t.Fatal("the gate holds alias Lookups before any reader is built")
	}
	return world, client, gate
}

// Holds the first count arrivals at name, each until its release is closed, sending each arrival's index to arrived
// as it is held. Every later arrival passes. Removed with the test.
func testHoldMailBarrier(t *testing.T, name string, count int) (arrived chan int, releases []chan struct{}) {
	t.Helper()
	arrived = make(chan int, count)
	releases = make([]chan struct{}, count)
	for index := range releases {
		releases[index] = make(chan struct{})
	}
	var stateLock sync.Mutex
	arrivals := 0
	SetTestHooks(&TestHooks{Barrier: func(barrierName string, key string) {
		if barrierName != name {
			return
		}
		index := func() int {
			stateLock.Lock()
			defer stateLock.Unlock()
			index := arrivals
			arrivals += 1
			return index
		}()
		if index < count {
			arrived <- index
			<-releases[index]
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	return arrived, releases
}

// One mailConfig call's answer.
type testMailConfigAnswer struct {
	config *MailConfig
	err    error
}

// Two first uses of the client's reader, each holding a build at the install, the second built, and so registered
// were it to register at construction, after the first: the first installs and the client keeps it, the second
// closes its own build and answers the kept one, and the gate still holds the kept one's alias Lookups, so an alias
// creation passes it. Before the fix the closed build took the kind off the gate (the S6 flake in mail_m9_test.go,
// whose component's first pass and first CreateBurner race this way), and the creation was refused before its
// Reserve.
func TestMailClientConfigRaceKeepsTheKeptReadersLookups(t *testing.T) {
	_, client, gate := newTestMailConfigInstallWorld(t)
	arrived, releases := testHoldMailBarrier(t, "mail.client.config.install.before", 2)
	answers := make(chan testMailConfigAnswer, 2)
	build := func() {
		config, err := client.mailConfig()
		answers <- testMailConfigAnswer{config: config, err: err}
	}

	go build()
	if index := testAwait(t, arrived, "the first build at its install"); index != 0 {
		t.Fatalf("arrival %d", index)
	}
	go build()
	if index := testAwait(t, arrived, "the second build at its install"); index != 1 {
		t.Fatalf("arrival %d", index)
	}
	close(releases[0])
	kept := testAwait(t, answers, "the first build's answer")
	close(releases[1])
	other := testAwait(t, answers, "the second build's answer")
	if kept.err != nil || other.err != nil {
		t.Fatalf("the builds answered %v and %v", kept.err, other.err)
	}
	if kept.config == nil || other.config != kept.config {
		t.Fatal("the two uses answered different readers")
	}
	if !gate.holdsAliasLookups() {
		t.Fatal("the gate holds no alias Lookup while the client keeps a reader: the closed build took them")
	}

	alias, err := client.CreateAlias(context.Background(), &MailAliasCreateArgs{LocalPart: "bo"})
	if err != nil {
		t.Fatalf("an alias creation after the race: %v", err)
	}
	if !alias.Known || alias.Address != testMailIngestRecipient {
		t.Fatalf("the alias %+v", alias)
	}
}

// A client closed while a build waits to install it keeps nothing: the build closes, the call answers ErrMailUnbound,
// no alias Lookup is left on the gate, and a later use builds nothing. Before the fix the closed client kept the
// build, its follower running and its Lookups on the gate for good.
func TestMailClientClosedWhileABuildWaitsKeepsAndRegistersNothing(t *testing.T) {
	_, client, gate := newTestMailConfigInstallWorld(t)
	arrived, releases := testHoldMailBarrier(t, "mail.client.config.install.before", 1)
	answers := make(chan testMailConfigAnswer, 1)
	go func() {
		config, err := client.mailConfig()
		answers <- testMailConfigAnswer{config: config, err: err}
	}()
	testAwait(t, arrived, "the build at its install")
	client.Close()
	close(releases[0])
	answer := testAwait(t, answers, "the build's answer")
	if !errors.Is(answer.err, ErrMailUnbound) || answer.config != nil {
		t.Fatalf("a closed client's build answered %v", answer.err)
	}
	if gate.registry.effectLookup(SidecarActionAliasCreate) != nil || gate.registry.effectLookup(SidecarActionAliasDelete) != nil {
		t.Fatal("a closed client left an alias Lookup on the gate")
	}
	if config, err := client.mailConfig(); !errors.Is(err, ErrMailUnbound) || config != nil {
		t.Fatalf("a later use of the closed client answered %v", err)
	}
}

// A reader registers once however many uses ask, and its Close takes back what it registered, so the gate holds the
// alias kinds while the client keeps it and not after; a second reader registered in its place keeps its own when the
// first closes, as the registry takes only the entry a removal added; and a reader closed before its owner registers
// it registers nothing.
func TestMailConfigRegistersItsLookupsOnceAndTakesThemBackAtClose(t *testing.T) {
	world, client, gate := newTestMailConfigInstallWorld(t)
	config, err := client.mailConfig()
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.mailConfig()
	if err != nil || again != config {
		t.Fatalf("a second use answered another reader: %v", err)
	}
	if !gate.holdsAliasLookups() || len(config.unregisters) != 2 {
		t.Fatalf("the reader registered %d removals", len(config.unregisters))
	}

	// another reader on the same gate, as a second MailConfig of the args' contract replaces the first's
	newReader := func(lookupsOnInstall bool) *MailConfig {
		reader := newMailConfig(&mailConfigTestStore{repo: world.configRepo, sidecarId: world.device}, &MailConfigArgs{
			Network: testMailIngestNetwork, SidecarId: world.device, Authority: world.configAuthority, Gate: gate,
			lookupsOnInstall: lookupsOnInstall,
		})
		t.Cleanup(reader.Close)
		return reader
	}
	replacing := newReader(false)
	config.Close()
	if !gate.holdsAliasLookups() {
		t.Fatal("the first reader's Close took the second's Lookups")
	}
	replacing.Close()
	if gate.registry.effectLookup(SidecarActionAliasCreate) != nil || gate.registry.effectLookup(SidecarActionAliasDelete) != nil {
		t.Fatal("a Lookup stands after every reader closed")
	}

	late := newReader(true)
	if gate.registry.effectLookup(SidecarActionAliasCreate) != nil {
		t.Fatal("a reader whose owner registers it registered at construction")
	}
	late.Close()
	late.registerLookups()
	if gate.registry.effectLookup(SidecarActionAliasCreate) != nil || gate.registry.effectLookup(SidecarActionAliasDelete) != nil {
		t.Fatal("a reader closed before its registration registered")
	}
}
