//go:build !sidecar_http && !js && !ios_extension

// The receiver composition's resolver and its test guard (mail_component_receive.go, mail_receiver_resolver.go), from
// inside: outside a test binary a receiver whose settings name no resolver builds a DohCache of its own over connect's
// defaults, as production always has; the composition over a Sidecar refuses that default in this test binary before
// it builds a part, builds on the resolver its settings name and releases it once with its parts, a later part's
// failure included; and a MailClient whose receiver is refused so reports it, which is how the e2e world's mail step
// fails until it names its own DNS. Nothing here dials: no DohCache built here is asked a question, and the Sidecar's
// api transport answers every request itself.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// A resolver a test names, which answers nothing.
type mailCompositionTestDoh struct{}

func (self *mailCompositionTestDoh) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	return nil, false
}

func (self *mailCompositionTestDoh) ForwardDnssec(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	return nil, false
}

// A ResolverFactory that counts its builds and their releases.
type mailCompositionTestResolvers struct {
	stateLock    sync.Mutex
	builtCount   int
	releaseCount int
}

func (self *mailCompositionTestResolvers) factory() (*MailReceiverResolver, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.builtCount += 1
	return &MailReceiverResolver{Doh: &mailCompositionTestDoh{}, Close: func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.releaseCount += 1
	}}, nil
}

func (self *mailCompositionTestResolvers) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.builtCount, self.releaseCount
}

// A Sidecar holding an identity and its network's DnsClient, and the args a receiver on receive is built over: what
// the composition reads before it builds its parts. Building a receiver starts nothing, and the api transport answers
// each request itself, so nothing dials.
func newMailCompositionTestSidecar(t *testing.T, receive *MailReceiveSettings) (*Sidecar, *mailReceiverFactoryArgs) {
	t.Helper()
	sidecar := newTestSidecar(t)
	networkId, sidecarId := NewId(), NewId()
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: sidecarId}
		sidecar.networkId = &networkId
	}()
	sidecar.sidecarApi = newTestSidecarApi(t, answerWith(503, `{}`))
	return sidecar, &mailReceiverFactoryArgs{
		Evs:      &EvsClient{},
		Config:   &MailConfig{},
		Api:      &mailClientTestApi{},
		Store:    newTestMemoryStore(),
		Settings: receive,
		Clock:    RealClock{},
		Log:      NewNoopLogger(),
	}
}

// A receive part naming factory, nil for none.
func mailCompositionTestSettings(factory func() (*MailReceiverResolver, error)) *MailReceiveSettings {
	settings := defaultMailReceiveSettings()
	settings.ResolverFactory = factory
	return settings
}

// Outside a test binary, a receiver whose settings name no resolver asks a DohCache of its own over connect's default
// resolvers, production's (§2.8 ext-3), under the DNS root's keys, released with the receiver; two receivers never
// share one (CODESTYLE's DoH rule). Neither cache is asked anything.
func TestMailReceiverResolverOutsideATestIsADohCacheOfItsOwn(t *testing.T) {
	settings := defaultMailReceiveSettings()
	first, err := newMailReceiverResolver(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := newMailReceiverResolver(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstCache, firstOk := first.Doh.(*connect.DohCache)
	secondCache, secondOk := second.Doh.(*connect.DohCache)
	if !firstOk || !secondOk || firstCache == secondCache {
		t.Fatalf("the default resolvers %T and %T, the same cache %t", first.Doh, second.Doh, firstCache == secondCache)
	}
	if first.Anchors != nil || first.Close == nil {
		t.Errorf("the default resolver's anchors %v, release set %t", first.Anchors, first.Close != nil)
	}
	// the same refusal a test binary's composition gets
	if _, err := newMailReceiverResolver(settings, true); !errors.Is(err, ErrMailReceiverPublicResolver) {
		t.Errorf("in a test: %v", err)
	}
}

// The composition over a Sidecar, as the mail component calls it here, refuses a receiver whose settings name no
// resolver, building no part and returning no release.
func TestMailSidecarReceiverFactoryInATestRefusesThePublicResolvers(t *testing.T) {
	sidecar, args := newMailCompositionTestSidecar(t, mailCompositionTestSettings(nil))
	receiver, release, err := newMailSidecarReceiverFactory(sidecar)(args)
	if !errors.Is(err, ErrMailReceiverPublicResolver) || receiver != nil || release != nil {
		t.Fatalf("the composition on the default resolvers in a test: %v", err)
	}
}

// The composition builds its receiver on the resolver its settings name, once, and its release releases it once.
func TestMailSidecarReceiverFactoryBuildsOnTheResolverItsSettingsName(t *testing.T) {
	resolvers := &mailCompositionTestResolvers{}
	sidecar, args := newMailCompositionTestSidecar(t, mailCompositionTestSettings(resolvers.factory))
	receiver, release, err := newMailSidecarReceiverFactory(sidecar)(args)
	if err != nil || receiver == nil || release == nil {
		t.Fatalf("the composition on a named resolver: %v", err)
	}
	if built, released := resolvers.counts(); built != 1 || released != 0 {
		t.Fatalf("%d built and %d released before the receiver ended", built, released)
	}
	release()
	if built, released := resolvers.counts(); built != 1 || released != 1 {
		t.Errorf("%d built and %d released once it ended", built, released)
	}
}

// A part built after the resolver that fails releases the resolver before the composition answers its error.
func TestMailSidecarReceiverFactoryReleasesItsResolverWhenALaterPartFails(t *testing.T) {
	resolvers := &mailCompositionTestResolvers{}
	sidecar, args := newMailCompositionTestSidecar(t, mailCompositionTestSettings(resolvers.factory))
	// the sessions refuse to build without their spool
	args.Store = nil
	receiver, release, err := newMailSidecarReceiverFactory(sidecar)(args)
	if !errors.Is(err, ErrMailReceiverInvalid) || receiver != nil || release != nil {
		t.Fatalf("a receiver with no spool: %v", err)
	}
	if built, released := resolvers.counts(); built != 1 || released != 1 {
		t.Errorf("%d built and %d released", built, released)
	}
}

// A MailClient in a test whose receive settings name no resolver runs no receiver and reports the guard as its
// receiver's problem, where a host's status, and the e2e world's wait for its receiver, read it.
func TestMailClientInATestReportsTheGuardAsItsReceiversProblem(t *testing.T) {
	world := newMailClientTestWorld(t)
	sidecar, _ := newMailCompositionTestSidecar(t, nil)
	world.client.sidecar = sidecar
	world.client.componentSeams = &mailComponentSeams{mayReceive: func() bool { return true }}
	world.enable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	bound, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	// the network's EvsClient, which a receiver deposits through; the world binds none
	binding := *bound
	binding.Evs = &EvsClient{}
	world.client.passReceive(run, &binding)
	status := func() MailClientReceiverStatus {
		world.client.stateLock.Lock()
		defer world.client.stateLock.Unlock()
		return world.client.receiverStatus
	}()
	if status.Running || !strings.Contains(status.Problem, ErrMailReceiverPublicResolver.Error()) || run.receiver != nil {
		t.Fatalf("the receiver's status %+v, a receiver running %t", status, run.receiver != nil)
	}
}
