//go:build !sidecar_http && !ios_extension && !js

// The desktop sender composition's resolver seam and its test guard (mail_component_smtp.go, mail_sender_resolver.go),
// from inside: outside a test binary a sender whose settings name no resolver asks a DohCache of its own over connect's
// defaults under the DNS root's keys, as production always has; in this test binary the composition refuses that
// default before it builds a part, so no prover host starts and nothing is dialed; a sender composed on the resolver its
// settings name asks it alone, TL2's _mta-sts lookup and TL3's MX lookup through its policy and the DKIM domain answers,
// validates TL1 to its anchors, and releases it once when the sender ends, a later part's failure included; and two
// senders each own their own. Every name is synthetic, and no DohCache built here is asked a question.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// One question a sender asked its resolver.
type testMailSenderQuestion struct {
	qType  dnsmessage.Type
	domain string
}

// A sender's resolver a test names: every question it is asked kept, each answered from a zone of its own that no
// public resolver knows, an MX at every domain naming mx.<domain> and no other name, and nothing once released, so a
// sender still asking after its release reads no answer.
type testMailSenderDoh struct {
	stateLock sync.Mutex
	questions []testMailSenderQuestion
	released  bool
}

var _ SmtpDohForwarder = (*testMailSenderDoh)(nil)

func (self *testMailSenderDoh) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	released := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.released {
			self.questions = append(self.questions, testMailSenderQuestion{qType: qType, domain: domain})
		}
		return self.released
	}()
	if released {
		return nil, false
	}
	// asked off the test's goroutine by the policy's lookups, so a reply that does not build is no answer
	reply := func() ([]byte, error) {
		name, err := dnsmessage.NewName(domain + ".")
		if err != nil {
			return nil, err
		}
		rcode := dnsmessage.RCodeNameError
		if qType == dnsmessage.TypeMX {
			rcode = dnsmessage.RCodeSuccess
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
		if err := builder.StartQuestions(); err != nil {
			return nil, err
		}
		if err := builder.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET}); err != nil {
			return nil, err
		}
		if qType == dnsmessage.TypeMX {
			mx, err := dnsmessage.NewName("mx." + domain + ".")
			if err != nil {
				return nil, err
			}
			if err := builder.StartAnswers(); err != nil {
				return nil, err
			}
			header := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET, TTL: 60}
			if err := builder.MXResource(header, dnsmessage.MXResource{Pref: 10, MX: mx}); err != nil {
				return nil, err
			}
		}
		return builder.Finish()
	}
	response, err := reply()
	if err != nil {
		return nil, false
	}
	return response, true
}

// The questions asked so far, in the order they came.
func (self *testMailSenderDoh) asked() []testMailSenderQuestion {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.questions)
}

// A ResolverFactory over resolvers of its own under anchors, nil taking the DNS root's keys: a testMailSenderDoh at
// each build, each build kept and each release counted.
type testMailSenderResolvers struct {
	anchors *SmtpDnssecAnchors

	stateLock     sync.Mutex
	built         []*testMailSenderDoh
	releaseCounts []int
}

func (self *testMailSenderResolvers) factory() (*MailSenderResolver, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	doh := &testMailSenderDoh{}
	index := len(self.built)
	self.built = append(self.built, doh)
	self.releaseCounts = append(self.releaseCounts, 0)
	return &MailSenderResolver{
		Doh:     doh,
		Anchors: self.anchors,
		Close: func() {
			func() {
				doh.stateLock.Lock()
				defer doh.stateLock.Unlock()
				doh.released = true
			}()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.releaseCounts[index] += 1
		},
	}, nil
}

// The resolvers built so far, and how many times each was released.
func (self *testMailSenderResolvers) snapshot() ([]*testMailSenderDoh, []int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.built), slices.Clone(self.releaseCounts)
}

// A generation of the mail component on a prover host, composing its sender as a daemon's does: the send-result world's
// client over an enrolled memory Sidecar whose prover is prover, its send settings naming factory (nil for none), mail
// on for the network but not yet enabled on this device, and a run whose push client has started. Whatever sender the
// run holds ends with the test.
type testMailSenderRun struct {
	world   *mailSendResultTestWorld
	client  *MailClient
	run     *mailComponentRun
	binding *MailBinding
}

func newTestMailSenderRun(t *testing.T, prover SmtpProver, factory func() (*MailSenderResolver, error)) *testMailSenderRun {
	t.Helper()
	world := newMailSendResultTestWorld(t)
	client := world.client
	client.settings.Send.ResolverFactory = factory
	instance, _, _ := enrolledInstance(t)
	settings := DefaultSidecarSettings()
	settings.Connect.SmtpProver = prover
	client.sidecar = &Sidecar{instance: instance, networkId: &testNetworkId, settings: settings}
	client.setNetworkRow(testMailIngestNetwork())
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	dispatcher := newTestSubprotocol(t, nil).subprotocol
	versions := newTestPushHeldVersions()
	push, err := newPushClient(ctx, &PushClientEnv{Subprotocol: dispatcher, Store: world.store}, versions.versions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(push.Close)
	versions.awaitStart(t, "the generation's first push resync")
	versions.answer(t)
	run := &mailComponentRun{ctx: ctx, cancel: cancel, env: &SidecarEnv{
		Ctx: ctx, SidecarApi: &SidecarApi{}, Subprotocol: dispatcher,
	}}
	client.componentRun = run
	t.Cleanup(func() { client.replaceSmtp(run, nil) })
	binding, _, err := client.bound()
	if err != nil {
		t.Fatal(err)
	}
	client.enabledLocally = false
	client.setNetworkEnabled(true)
	return &testMailSenderRun{world: world, client: client, run: run, binding: binding}
}

// Outside a test binary, a sender whose settings name no resolver asks a DohCache of its own over connect's default
// resolvers, production's (§2.8 ext-3), under the DNS root's keys, released with the sender; two senders never share
// one (CODESTYLE's DoH rule). Neither cache is asked anything. The defaults name no resolver.
func TestMailSenderResolverOutsideATestIsADohCacheOfItsOwn(t *testing.T) {
	settings := DefaultMailSendSettings()
	if settings.ResolverFactory != nil {
		t.Fatal("the send defaults name a resolver of their own")
	}
	first, err := newMailSenderResolver(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := newMailSenderResolver(settings, false)
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
	if _, err := newMailSenderResolver(settings, true); !errors.Is(err, ErrMailSenderPublicResolver) {
		t.Errorf("in a test: %v", err)
	}
}

// In a test binary, a prover host whose send settings name no resolver composes no sender: the composition answers
// the guard's refusal before it builds a part, so the pass binds no sender, the prover host never starts, and with no
// sender nothing is ever dialed.
func TestMailSidecarSenderInATestRefusesThePublicResolvers(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, nil)
	sender.client.enabledLocally = true
	sender.client.passSmtp(sender.run, sender.binding)
	if sender.run.smtp != nil {
		t.Fatal("a prover host on the default resolvers composed a sender in a test")
	}
	smtp, err := mailSidecarSenderFactory(sender.client, sender.run, sender.world.member, sender.world.mailboxId)
	if !errors.Is(err, ErrMailSenderPublicResolver) || smtp != nil {
		t.Fatalf("the composition on the default resolvers in a test: %v", err)
	}
	binding, _, err := sender.client.bound()
	if err != nil || binding.Sender != nil || binding.BurnerSelectors != nil {
		t.Fatalf("a refused sender is bound: %v", err)
	}
	// nothing started any goroutine that could enter the prover since the refusal came before every part
	select {
	case <-prover.entered:
		t.Fatal("a refused sender started its prover host")
	default:
	}
}

// A sender composed on the resolver its settings name asks that resolver alone: TL2's _mta-sts lookup and TL3's MX
// lookup, side by side in the policy's Authenticate, reach it, and TL3's view agrees with the MX only it answers; the
// DKIM domain answers ask it under the network's root; TL1 validates to its anchors. It was built once, and it is
// released once the sender ends, after which it answers nothing.
func TestMailSidecarSenderAsksTheResolverItsSettingsName(t *testing.T) {
	resolvers := &testMailSenderResolvers{anchors: &SmtpDnssecAnchors{}}
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	sender.client.enabledLocally = true
	sender.client.passSmtp(sender.run, sender.binding)
	smtp := sender.run.smtp
	if smtp == nil {
		t.Fatalf("no sender on a named resolver: %v", sender.world.log.snapshot())
	}
	built, releases := resolvers.snapshot()
	if len(built) != 1 || releases[0] != 0 {
		t.Fatalf("%d resolvers built, released %v, before the sender ended", len(built), releases)
	}
	doh := built[0]
	policy := smtp.sender.args.Policy
	authentication, err := policy.Authenticate(t.Context(), &SmtpTlsRequest{RecipientDomain: "recipient.example", MxHost: "mx.recipient.example"})
	if err != nil {
		t.Fatal(err)
	}
	if authentication.mtaStsPolicy != nil || !authentication.mxView.agrees("recipient.example", "mx.recipient.example") {
		t.Errorf("the policy's lookups: mta-sts %v, mx view %+v", authentication.mtaStsPolicy, authentication.mxView)
	}
	asked := doh.asked()
	slices.SortFunc(asked, func(a testMailSenderQuestion, b testMailSenderQuestion) int {
		return int(a.qType) - int(b.qType)
	})
	want := []testMailSenderQuestion{
		{qType: dnsmessage.TypeMX, domain: "recipient.example"},
		{qType: dnsmessage.TypeTXT, domain: "_mta-sts.recipient.example"},
	}
	if !slices.Equal(asked, want) {
		t.Errorf("the resolver was asked %v, not %v", asked, want)
	}
	if policy.mtaSts.doh != SmtpDohForwarder(doh) || policy.doh != SmtpDohForwarder(doh) {
		t.Error("TL2's or TL3's lookups ask another resolver")
	}
	answers := smtp.dkim.domainAnswers()
	if answers == nil || answers.Doh != SmtpDohForwarder(doh) || answers.Root != testMailIngestRoot {
		t.Errorf("the DKIM domain answers %+v", answers)
	}
	if policy.dane.anchors != resolvers.anchors {
		t.Error("TL1 validates to anchors other than the resolver's")
	}
	sender.client.replaceSmtp(sender.run, nil)
	if _, releases := resolvers.snapshot(); releases[0] != 1 {
		t.Errorf("the sender's end released its resolver %d times", releases[0])
	}
	if response, usable := doh.Forward(t.Context(), dnsmessage.TypeMX, "recipient.example"); usable || response != nil {
		t.Error("a released resolver still answers")
	}
}

// A part built after the resolver that fails releases the resolver before the composition answers its error.
func TestMailSidecarSenderReleasesItsResolverWhenALaterPartFails(t *testing.T) {
	resolvers := &testMailSenderResolvers{}
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	// the prover host refuses settings out of range
	sender.client.sidecar.settings.Connect.SmtpSender = &SmtpSenderSettings{}
	smtp, err := mailSidecarSenderFactory(sender.client, sender.run, sender.world.member, sender.world.mailboxId)
	if err == nil || smtp != nil {
		t.Fatal("a sender on settings out of range was composed")
	}
	if built, releases := resolvers.snapshot(); len(built) != 1 || releases[0] != 1 {
		t.Errorf("%d built, released %v", len(built), releases)
	}
}

// Two senders composed on the same settings each build a resolver of their own (CODESTYLE's DoH rule), and ending one
// releases its own alone: the other's lookups still ask its resolver, and only it.
func TestMailSidecarSendersEachOwnTheirResolver(t *testing.T) {
	resolvers := &testMailSenderResolvers{}
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	first, err := mailSidecarSenderFactory(sender.client, sender.run, sender.world.member, sender.world.mailboxId)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mailSidecarSenderFactory(sender.client, sender.run, sender.world.member, sender.world.mailboxId)
	if err != nil {
		first.close()
		t.Fatal(err)
	}
	defer second.close()
	built, _ := resolvers.snapshot()
	if len(built) != 2 || built[0] == built[1] {
		first.close()
		t.Fatalf("two senders built %d resolvers", len(built))
	}
	first.close()
	if _, err := second.sender.args.Policy.Authenticate(t.Context(), &SmtpTlsRequest{RecipientDomain: "second.example", MxHost: "mx.second.example"}); err != nil {
		t.Fatal(err)
	}
	if asked := built[0].asked(); len(asked) != 0 {
		t.Errorf("the first sender's resolver was asked %v", asked)
	}
	if asked := built[1].asked(); len(asked) != 2 {
		t.Errorf("the second sender's resolver was asked %v", asked)
	}
	if _, releases := resolvers.snapshot(); releases[0] != 1 || releases[1] != 0 {
		t.Errorf("after the first sender ended, releases %v", releases)
	}
}

// A factory's error comes back as it was given, and a factory answering no resolver, or one without its Doh, leaves
// the sender unbuilt, the latter released first. A factory is asked in a test binary as anywhere: the guard stands only
// before the default.
func TestMailSenderResolverFactoryRefusals(t *testing.T) {
	refused := errors.New("the test's DNS is not up")
	settings := DefaultMailSendSettings()
	settings.ResolverFactory = func() (*MailSenderResolver, error) {
		return nil, refused
	}
	if _, err := newMailSenderResolver(settings, true); !errors.Is(err, refused) {
		t.Errorf("a factory's error came back as %v", err)
	}
	settings.ResolverFactory = func() (*MailSenderResolver, error) {
		return nil, nil
	}
	if _, err := newMailSenderResolver(settings, true); !errors.Is(err, ErrMailClientInvalid) {
		t.Errorf("no resolver: %v", err)
	}
	releases := 0
	settings.ResolverFactory = func() (*MailSenderResolver, error) {
		return &MailSenderResolver{Close: func() { releases += 1 }}, nil
	}
	if _, err := newMailSenderResolver(settings, true); !errors.Is(err, ErrMailClientInvalid) || releases != 1 {
		t.Errorf("a resolver without its Doh: %v, released %d times", err, releases)
	}
}
