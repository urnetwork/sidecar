//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The support push topic on the device (support_push_topic.go; DESIGN-COMPUTE §28.9, D-SUP-6): the publisher's hint
// names an event and nothing of it; the push machine takes the topic as the clock it is; the client's part of a
// generation holds the topic; a hint or a resync notice wakes the client's loop, which reads the member's events from
// the fake feedback service and tells its listeners; a hint for recURd's thread, or with the release's switch off,
// asks nothing; Wake answers after a read, with the read's error; the notification hook keeps support's replies and
// moves alone; and a Sidecar holds the topic only with the skill on. A fake publisher writes each hint as the feedback
// service would.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// The fake publisher's hint for the event seq of entry on the apps' conversation, at version.
func testSupportHint(t testing.TB, product string, entry string, seq uint32, version uint64) *ClientHint {
	t.Helper()
	hint, err := NewSupportClientHint(product, entry, seq, version)
	if err != nil {
		t.Fatal(err)
	}
	return hint
}

// The notice the device's push makes of hint, as a raised version's is.
func testSupportNotice(hint *ClientHint) PushNotice {
	return PushNotice{Topic: hint.Topic, Version: hint.Version, Kind: hint.Kind, Hint: hint.Body}
}

// The resident's frame for hint at seq.
func testSupportHintFrame(t testing.TB, hint *ClientHint, seq uint64) *protocol.Envelope {
	t.Helper()
	return testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: seq, Topic: hint.Topic, Version: hint.Version, Kind: hint.Kind, Hint: hint.Body,
	})
}

// The hint names the event, {product, entry, seq}, under its kind, a few dozen bytes; anything a publisher could get
// wrong is refused before it reaches a client, and a notice the device cannot read as one names no event.
func TestSupportHintNamesTheEventAndNothingElse(t *testing.T) {
	hint := testSupportHint(t, SupportProductUrnetwork, "100171", 4, 1795000000000)
	if hint.Topic != PushTopicSupport || hint.Version != 1795000000000 || hint.Kind != uint32(protocol.MessageType_SUPPORT_HINT) || hint.Forced {
		t.Fatalf("hint %+v", hint)
	}
	decoded := &protocol.SupportHint{}
	if err := proto.Unmarshal(hint.Body, decoded); err != nil || decoded.Product != SupportProductUrnetwork || decoded.Entry != "100171" || decoded.Seq != 4 {
		t.Fatalf("body %v: %v", decoded, err)
	}
	if fields := decoded.ProtoReflect().Descriptor().Fields(); fields.Len() != 3 || 64 < len(hint.Body) {
		t.Fatalf("%d fields in %d B", fields.Len(), len(hint.Body))
	}
	if named, ok := supportHintOf(testSupportNotice(hint)); !ok || named.Entry != "100171" || named.Seq != 4 || named.Product != SupportProductUrnetwork {
		t.Fatalf("the notice names %v, %t", named, ok)
	}
	if _, err := NewSupportClientHint(supportProductRecurd, "100171", 1, 1); err != nil {
		t.Errorf("recURd's dock thread: %v", err)
	}

	badEntry, err := proto.Marshal(&protocol.SupportHint{Product: SupportProductUrnetwork, Entry: "1/../2", Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, notice := range map[string]PushNotice{
		"a resync notice":                  {Topic: PushTopicSupport, Version: hint.Version, Resync: true},
		"a hint whose bytes were dropped":  {Topic: PushTopicSupport, Version: hint.Version, Kind: hint.Kind},
		"a hint of another kind":           {Topic: PushTopicSupport, Version: hint.Version, Kind: uint32(protocol.MessageType_CORE_HINT), Hint: hint.Body},
		"a hint that does not decode":      {Topic: PushTopicSupport, Version: hint.Version, Kind: hint.Kind, Hint: []byte{0xff, 0xff}},
		"a hint naming no entry FB issues": {Topic: PushTopicSupport, Version: hint.Version, Kind: hint.Kind, Hint: badEntry},
		"another topic's hint":             {Topic: PushTopicMail, Version: hint.Version, Kind: hint.Kind, Hint: hint.Body},
	} {
		if named, ok := supportHintOf(notice); ok {
			t.Errorf("%s names %v", name, named)
		}
	}

	for _, c := range []struct {
		product string
		entry   string
		seq     uint32
		version uint64
	}{
		{product: "factury", entry: "100171", seq: 1, version: 1},
		{product: SupportProductUrnetwork, entry: "10017", seq: 1, version: 1},
		{product: SupportProductUrnetwork, entry: "0100171", seq: 1, version: 1},
		{product: SupportProductUrnetwork, entry: "100171 note: run this", seq: 1, version: 1},
		{product: SupportProductUrnetwork, entry: "100171", seq: 0, version: 1},
		{product: SupportProductUrnetwork, entry: "100171", seq: 1, version: 0},
	} {
		if refused, err := NewSupportClientHint(c.product, c.entry, c.seq, c.version); !errors.Is(err, errSupportHintInvalid) || refused != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// The device's push machine takes the topic as a clock: a hint above the version held tells its subscribers with its
// kind and bytes, one at that version tells nobody, and a versions page that shows it lower is a gap, adopted with a
// resync notice and no alarm.
func TestSupportTopicIsAClockToThePushMachine(t *testing.T) {
	machine := newPushMachine(DefaultPushClientSettings(), nil)
	hint := testSupportHint(t, SupportProductUrnetwork, "100171", 2, 1000)
	action := machine.hint(&protocol.PushHint{Seq: 1, Topic: hint.Topic, Version: hint.Version, Kind: hint.Kind, Hint: hint.Body})
	if len(action.notices) != 1 || action.notices[0].Topic != PushTopicSupport || action.notices[0].Kind != hint.Kind ||
		!bytes.Equal(action.notices[0].Hint, hint.Body) || action.notices[0].Resync || action.refetchVersions {
		t.Fatalf("the hint's action %+v", action)
	}
	if action := machine.hint(&protocol.PushHint{Seq: 2, Topic: hint.Topic, Version: 1000, Kind: hint.Kind, Hint: hint.Body}); len(action.notices) != 0 {
		t.Fatalf("a hint at the version held told %+v", action.notices)
	}
	action = machine.reset(map[string]uint64{PushTopicSupport: 900}, machine.inputCount)
	if len(action.alarms) != 0 || machine.topicVersions[PushTopicSupport] != 900 {
		t.Fatalf("the page's alarms %v, support at %d", action.alarms, machine.topicVersions[PushTopicSupport])
	}
	resynced := false
	for _, notice := range action.notices {
		resynced = resynced || (notice.Topic == PushTopicSupport && notice.Resync && notice.Version == 900)
	}
	if !resynced {
		t.Fatalf("the fall told %+v", action.notices)
	}
}

// Whether client's loop was woken since the last look, taking the wake.
func testSupportWoke(client *SupportClient) bool {
	select {
	case <-client.wake:
		return true
	default:
		return false
	}
}

// A hint or a resync notice of the topic wakes the client's loop, however the hint's bytes fared; a hint for recURd's
// thread asks nothing of this client, and nothing does with the release's switch off.
func TestSupportHintWakesTheLoopUnlessItIsAnotherProducts(t *testing.T) {
	world := newTestSupportWorld(t)
	hint := testSupportHint(t, SupportProductUrnetwork, "100171", 2, 1795000000000)
	for _, c := range []struct {
		name   string
		notice PushNotice
		wakes  bool
	}{
		{name: "a hint on the apps' conversation", notice: testSupportNotice(hint), wakes: true},
		{name: "a resync notice", notice: PushNotice{Topic: PushTopicSupport, Version: 7, Resync: true}, wakes: true},
		{name: "a hint whose bytes were dropped", notice: PushNotice{Topic: PushTopicSupport, Version: 8, Kind: hint.Kind}, wakes: true},
		{name: "a hint that does not decode", notice: PushNotice{Topic: PushTopicSupport, Version: 9, Kind: hint.Kind, Hint: []byte{0xff}}, wakes: true},
		{name: "a hint on recURd's thread", notice: testSupportNotice(testSupportHint(t, supportProductRecurd, "100172", 1, 10)), wakes: false},
	} {
		world.client.takeHint(c.notice)
		if woke := testSupportWoke(world.client); woke != c.wakes {
			t.Errorf("%s: woke %t", c.name, woke)
		}
	}
	world.client.settings.ServiceEnabled = false
	world.client.takeHint(testSupportNotice(hint))
	if testSupportWoke(world.client) {
		t.Error("a hint woke the loop with the switch off")
	}
}

// A push client on a test dispatcher, past its first resync.
func newTestSupportPush(t *testing.T) *testSubprotocol {
	t.Helper()
	fixture := newTestSubprotocol(t, nil)
	fetches := make(chan struct{}, 16)
	pushClient, err := newPushClient(t.Context(), &PushClientEnv{
		Subprotocol: fixture.subprotocol,
		Store:       newTestPushStore(),
		Clock:       newTestEnvelopeClock(),
		Log:         NewNoopLogger(),
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		fetches <- struct{}{}
		return &protocol.PollResponse{Reset_: &protocol.PushReset{Epoch: 1, Complete: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pushClient.Close)
	testAwait(t, fetches, "the first resync")
	return fixture
}

// The client's part of a generation holds the topic on the generation's push: the resident's hint reaches the client;
// a generation without push, or whose dispatcher no push client serves, holds nothing.
func TestSupportHintComponentHoldsTheTopic(t *testing.T) {
	world := newTestSupportWorld(t)
	fixture := newTestSupportPush(t)
	component := &supportHintComponent{client: world.client}
	if err := checkSidecarComponentName(component.Name()); err != nil {
		t.Errorf("name %q: %v", component.Name(), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := component.Attach(&SidecarEnv{Ctx: ctx, Subprotocol: fixture.subprotocol}); err != nil {
		t.Fatal(err)
	}
	fixture.receive(connect.ControlId, testSupportHintFrame(t, testSupportHint(t, SupportProductUrnetwork, "100171", 2, 1795000000000), 1),
		connect.Peer{TransportType: connect.TransportTypeH1})
	testAwait(t, world.client.wake, "the hint's wake")

	if err := component.Attach(&SidecarEnv{Ctx: ctx}); err != nil {
		t.Errorf("a generation without push: %v", err)
	}
	if err := component.Attach(&SidecarEnv{Ctx: ctx, Subprotocol: newTestSubprotocol(t, nil).subprotocol}); err != nil {
		t.Errorf("a dispatcher no push client serves: %v", err)
	}
}

// The fake service's transport: it counts the member's event reads and holds the next one, once asked, after the
// service has taken its view of the events and before the client reads the answer, until released.
type testSupportReadTransport struct {
	base     http.RoundTripper
	holdNext atomic.Bool
	held     chan struct{}
	release  chan struct{}
	reads    atomic.Int64
}

func (self *testSupportReadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.base.RoundTrip(request)
	if request.URL.Path == "/v1/events" {
		self.reads.Add(1)
		if self.holdNext.CompareAndSwap(true, false) {
			self.held <- struct{}{}
			<-self.release
		}
	}
	return response, err
}

// A support client with its run loop, on a clock whose interval never passes, so a pass runs at the start and then only
// on a wake, over the fake service through a read transport; holdFirst holds the first pass's read.
type testSupportLoopWorld struct {
	service   *testSupportService
	sources   *testSupportSources
	transport *testSupportReadTransport
	client    *SupportClient
	updates   chan *SupportUpdate
}

func newTestSupportLoopWorld(t *testing.T, holdFirst bool) *testSupportLoopWorld {
	t.Helper()
	settings := DefaultSupportSettings()
	settings.ServiceEnabled = true
	world := &testSupportLoopWorld{
		service: newTestSupportService(t),
		sources: &testSupportSources{host: testSupportServiceHost, current: 1, acknowledged: 1},
		updates: make(chan *SupportUpdate, 64),
	}
	httpClient := world.service.client()
	world.transport = &testSupportReadTransport{base: httpClient.Transport, held: make(chan struct{}, 1), release: make(chan struct{})}
	world.transport.holdNext.Store(holdFirst)
	httpClient.Transport = world.transport
	store := newTestMemoryStore()
	client, err := NewSupportClient(&SupportClientArgs{
		Host:       &testSupportHost{},
		Settings:   settings,
		Store:      func() (SidecarStore, error) { return store, nil },
		Clock:      newSupportLogTestClock(),
		HttpClient: httpClient,
		Sources:    world.sources.all(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	world.client = client
	remove := client.AddListener(func(update *SupportUpdate) { world.updates <- update })
	t.Cleanup(remove)
	return world
}

// Returns once count passes of the loop have ended.
func (self *testSupportLoopWorld) awaitPasses(t *testing.T, count uint64) {
	t.Helper()
	guard := time.After(30 * time.Second)
	for {
		passes, changed := self.client.passes.Get()
		if count <= passes.ended {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("%d of %d passes ended", passes.ended, count)
		}
	}
}

// The whole device path, from the fake publisher's hint at the resident to the client's listeners: support's reply
// lands in the member's events, the hint wakes the loop, whose read takes the reply and tells its enumerated fields;
// later a resident's reset that shows the topic moved reads again. The loop's interval never passes here, so nothing
// but the push reads.
func TestSupportTopicHintReachesTheClientsListeners(t *testing.T) {
	world := newTestSupportLoopWorld(t, false)
	world.awaitPasses(t, 1)
	fixture := newTestSupportPush(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := (&supportHintComponent{client: world.client}).Attach(&SidecarEnv{Ctx: ctx, Subprotocol: fixture.subprotocol}); err != nil {
		t.Fatal(err)
	}
	platform := connect.Peer{TransportType: connect.TransportTypeH1}
	at := time.Date(2026, time.November, 26, 9, 0, 0, 0, time.UTC)

	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: "Fixed in the next build.", By: "support", At: at})
	fixture.receive(connect.ControlId, testSupportHintFrame(t, testSupportHint(t, SupportProductUrnetwork, "100171", 2, 1795000000000), 1), platform)
	update := testAwait(t, world.updates, "the reply the hint's read took")
	if update.Entry != "100171" || update.Seq != 2 || update.Type != "note" || update.Product != SupportProductUrnetwork {
		t.Fatalf("update %+v", update)
	}
	if encoded, _ := json.Marshal(update); bytes.Contains(encoded, []byte("next build")) {
		t.Fatalf("the update carries the reply's text: %s", encoded)
	}

	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 3, Type: "status", Status: "fixed", FixedIn: "2026.11.30-100", Final: true, At: at})
	fixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_RESET, &protocol.PushReset{
		Epoch: 2, Complete: true, Versions: []*protocol.TopicVersion{{Topic: PushTopicSupport, Version: 1795000000100}},
	}), platform)
	update = testAwait(t, world.updates, "the status the reset's read took")
	if update.Seq != 3 || update.Status != "fixed" || update.FixedIn != "2026.11.30-100" || !update.Final {
		t.Fatalf("update %+v", update)
	}
	if reads := world.transport.reads.Load(); reads != 3 {
		t.Errorf("%d reads: one at the start, one a push", reads)
	}
}

// Wake reads the conversation now and answers once that read is done, the reply told first; a read that fails answers
// its error; a ctx that ends first answers its own; and Wake answers unavailable with the switch off or the client
// closed.
func TestSupportWakeReadsTheConversationNow(t *testing.T) {
	world := newTestSupportLoopWorld(t, false)
	world.awaitPasses(t, 1)
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: "We see it too.", By: "support"})
	if err := world.client.Wake(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-world.updates:
		if update.Seq != 2 {
			t.Fatalf("update %+v", update)
		}
	default:
		t.Fatal("Wake answered before its read told the reply")
	}

	// no host in the policy: the read fails, and Wake says why
	world.sources.stateLock.Lock()
	world.sources.host = ""
	world.sources.stateLock.Unlock()
	if err := world.client.Wake(t.Context()); SupportRefusalOf(err) != SupportRefusalNoHost {
		t.Fatalf("a read with no host: %v", err)
	}
	world.sources.stateLock.Lock()
	world.sources.host = testSupportServiceHost
	world.sources.stateLock.Unlock()

	// a ctx that ends while the read is held
	world.transport.holdNext.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	woke := make(chan error, 1)
	go func() { woke <- world.client.Wake(ctx) }()
	testAwait(t, world.transport.held, "the woken pass's read")
	cancel()
	if err := testAwait(t, woke, "Wake's answer"); !errors.Is(err, context.Canceled) {
		t.Fatalf("a ctx ended first: %v", err)
	}
	world.transport.release <- struct{}{}

	world.client.settings.ServiceEnabled = false
	if err := world.client.Wake(t.Context()); !errors.Is(err, ErrSupportUnavailable) {
		t.Fatalf("with the switch off: %v", err)
	}
	world.client.settings.ServiceEnabled = true
	world.client.Close()
	if err := world.client.Wake(t.Context()); !errors.Is(err, ErrSupportUnavailable) {
		t.Fatalf("once closed: %v", err)
	}
}

// A client closed while its woken pass reads answers the wake unavailable, never the cut read's outcome, which an app
// would take for a read that found nothing.
func TestSupportWakeAnswersUnavailableWhenTheClientClosesMidRead(t *testing.T) {
	world := newTestSupportLoopWorld(t, false)
	world.awaitPasses(t, 1)
	world.transport.holdNext.Store(true)
	woke := make(chan error, 1)
	go func() { woke <- world.client.Wake(t.Context()) }()
	testAwait(t, world.transport.held, "the woken pass's read")
	closed := make(chan struct{})
	go func() {
		world.client.Close()
		close(closed)
	}()
	<-world.client.ctx.Done()
	world.transport.release <- struct{}{}
	if err := testAwait(t, woke, "Wake's answer"); !errors.Is(err, ErrSupportUnavailable) {
		t.Fatalf("a wake the close cut: %v", err)
	}
	testAwait(t, closed, "the close")
}

// Support's replies and moves raise a notification of enumerated fields; the person's and their agents' messages, from
// any device, and everything else raise none.
func TestSupportNotificationKeepsSupportsRepliesAndMovesAlone(t *testing.T) {
	for _, c := range []struct {
		eventType string
		kind      string
	}{
		{eventType: "note", kind: SupportNotificationReply},
		{eventType: "status", kind: SupportNotificationStatus},
		{eventType: "fixed_in", kind: SupportNotificationStatus},
		{eventType: "linked", kind: SupportNotificationStatus},
		{eventType: "merged", kind: SupportNotificationStatus},
		{eventType: "submitted"},
		{eventType: "followup"},
		{eventType: "attachment"},
		{eventType: "deleted"},
		{eventType: "not_sent"},
		{eventType: ""},
	} {
		update := &SupportUpdate{
			Product: SupportProductUrnetwork, Entry: "100171", Seq: 5, Type: c.eventType, Status: "fixed", FixedIn: "2026.11.30-100",
			Final: true, Agents: []string{"release-bot"},
		}
		notification, raised := SupportNotificationOf(update)
		if raised != (c.kind != "") {
			t.Errorf("%q raised %t", c.eventType, raised)
			continue
		}
		if !raised {
			continue
		}
		want := SupportNotification{
			Product: SupportProductUrnetwork, Entry: "100171", Seq: 5, Kind: c.kind, Status: "fixed", FixedIn: "2026.11.30-100", Final: true,
		}
		if *notification != want {
			t.Errorf("%q: %+v", c.eventType, notification)
		}
	}
	if _, raised := SupportNotificationOf(&SupportUpdate{Product: SupportProductUrnetwork, Entry: "not an entry", Type: "note"}); raised {
		t.Error("an update naming no entry raised one")
	}
	if _, raised := SupportNotificationOf(nil); raised {
		t.Error("no update raised one")
	}
}

// The person's unread replies count each note of support's past what the person read, across the conversation; a
// status move is no reply, and the person's read of an item clears its count.
func TestSupportUnreadRepliesCountsThePersons(t *testing.T) {
	world := newTestSupportWorld(t)
	if _, err := world.send(&SupportSendArgs{Surface: SupportSurfacePerson, Text: "the VPN drops after sleep"}); err != nil {
		t.Fatal(err)
	}
	world.pass()
	at := world.clock.Now()
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: "Which version?", By: "support", At: at})
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 3, Type: "status", Status: "in_progress", At: at})
	world.pass()
	if unread, err := world.client.UnreadReplies(); err != nil || unread != 1 {
		t.Fatalf("unread %d, %v", unread, err)
	}
	if _, err := world.client.Read(context.Background(), &SupportReadArgs{Entry: "100171"}); err != nil {
		t.Fatal(err)
	}
	if unread, err := world.client.UnreadReplies(); err != nil || unread != 0 {
		t.Fatalf("unread after the person's read %d, %v", unread, err)
	}
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 4, Type: "note", Note: "Thanks: we see it.", By: "support", At: at})
	world.pass()
	if unread, err := world.client.UnreadReplies(); err != nil || unread != 1 {
		t.Fatalf("unread after a new reply %d, %v", unread, err)
	}
}

// A Sidecar holds the support topic on its generations only with the skill on: with the release's switch off, as it is
// until G-SUP-service passes, its client subscribes to nothing.
func TestSupportTopicIsHeldOnlyWithTheSkillOn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		instance, enrollment := newTestEnrolledInstance(t)
		settings := testSidecarSettings(newTestSidecarPlatform())
		settings.Support.ServiceEnabled = enabled
		sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, settings)
		leg, ok := sidecar.leg.(*sidecarConnectLeg)
		if !ok {
			t.Fatalf("a leg of %T", sidecar.leg)
		}
		if held := leg.listed(supportHintComponentName); held != enabled {
			t.Errorf("with the switch %t the topic's component is listed %t", enabled, held)
		}
		if _, err := sidecar.Support(); err != nil {
			t.Errorf("with the switch %t: %v", enabled, err)
		}
	}
}
