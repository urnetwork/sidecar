package sidecartest

// §6.8's M1 exit scenarios on T2 (PROTO-M1-11), through a real Sidecar's generation, its dispatcher and
// push client, with a resident on the Net's exchange (push_net.go) sending what server's resident sends:
// a ControlId push over a P2P carrier, what a peer forging ControlId delivers, is dropped, and the same
// frame over h1 is kept, while nothing but a push is taken from ControlId even over h1 (D-PROTO-8); push
// resyncs after a resident restart, a reset of the owners' versions and then hints whose seq only rises
// (D-PROTO-5); a reset left incomplete by a dropped tail applies nothing until versions are refetched
// (D-PROTO-20), also while the push waits out a refused versions refetch; and what the capture holds
// from ControlId is acks and hint fields alone (R-PROTO-8). Connect's own timers run in real time, as
// net_connect.go says; a publisher's window runs on a fake clock of its own, which the test steps.
//
// The sidecar's push runs on the Net's clock, which only a test moves, and fetches versions at its start
// on a goroutine of its own, so a test that took that refetch as done would race it: one still in flight
// lands its page wherever it lands, between a reset's part and the hint after it included, and one that
// fails waits out its retry until the clock moves. So the api refuses each test's start refetch, and the
// test moves the clock to the retry and hears it apply before anything else, once its subscribers are in
// place, or runs its rows during the retry wait. Past that a test moves the clock only to a refused
// refetch's retry, never to the hourly refetch, so a refetch comes only when an input asks for one.

import (
	"context"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
)

// How long a push test waits, in real time, for what it expects: only a broken run's bound.
const testPushTimeout = 45 * time.Second

// One admitted sidecar of the Net's default network, its client's resident, and every notice its push
// gives for the topics named, in order, with the push's first versions refetch refused at the Net's api:
// nothing the push fetches has applied, and it waits out its retry, RetryMinInterval on the Net's clock,
// which is set when this returns and ends only when the test moves the clock there.
func newTestPushSidecarRefetchRefused(t *testing.T, topics ...string) (*Net, *SubprotocolSidecar, *NetResident, chan sidecar.PushNotice) {
	t.Helper()
	net := newTestNet(t)
	// armed before the sidecar starts, so it is the start's refetch the api refuses
	refused, err := net.Faults().Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/sidecar/sync/versions", Result: FailBeforeApply})
	if err != nil {
		t.Fatal(err)
	}
	sidecars, _, err := net.AddSubprotocolSidecars("laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	notices := make(chan sidecar.PushNotice, 256)
	for _, topic := range topics {
		// a subscriber's callback must not block: a full channel is the test's failure, not a wait
		if _, err := laptop.Subprotocol().Subscribe(topic, func(notice sidecar.PushNotice) {
			select {
			case notices <- notice:
			default:
				t.Errorf("the test's notices are full")
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	resident, err := net.AddResident(laptop.ClientId())
	if err != nil {
		t.Fatal(err)
	}
	guard := time.After(testPushTimeout)
	select {
	case <-refused:
	case <-guard:
		t.Fatal("the push's start refetch never reached the api")
	}
	// the clock stands where it stood at the refusal, so the retry's timer is at a time known here
	clock := net.Clock()
	retryTime := clock.Now().Add(sidecar.DefaultPushClientSettings().RetryMinInterval)
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, retryTime.Equal) {
			return net, laptop, resident, notices
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("the push set no retry at %s: %v", retryTime, pending)
		}
	}
}

// newTestPushSidecarRefetchRefused's sidecar once the push's retry has applied: the test moves the Net's
// clock to the retry and hears its core notice, which every applied refetch gives (push_state.go), so the
// push applied a page fetched after the test's subscribers were in place, and has no refetch in flight.
// It refetches again only when an input asks, or at SyncRefetchInterval, which no test here reaches.
func newTestPushSidecar(t *testing.T, topics ...string) (*Net, *SubprotocolSidecar, *NetResident, chan sidecar.PushNotice) {
	t.Helper()
	net, laptop, resident, notices := newTestPushSidecarRefetchRefused(t, topics...)
	cores := make(chan sidecar.PushNotice, 16)
	removeCore, err := laptop.Subprotocol().Subscribe(sidecar.PushTopicCore, func(notice sidecar.PushNotice) {
		select {
		case cores <- notice:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer removeCore()
	if notice := awaitNoticeSteppingRetries(t, cores, "the retried refetch's core", net.Clock()); !notice.Resync {
		t.Fatalf("core's first notice is no refetch's: %+v", notice)
	}
	return net, laptop, resident, notices
}

// The next notice, moving clock, the Net's, to each of its timers due within RetryMaxInterval of the time
// the wait began: a refused versions refetch's retry, the nearest timer a push test's sidecar sets, the
// others, its hourly refetch among them, being an hour or more out. The hourly refetch is never reached,
// so a refetch comes only when an input asks for one or a refused one is retried.
func awaitNoticeSteppingRetries(t *testing.T, notices <-chan sidecar.PushNotice, what string, clock *FakeClock) sidecar.PushNotice {
	t.Helper()
	stepLimit := clock.Now().Add(sidecar.DefaultPushClientSettings().RetryMaxInterval)
	guard := time.After(testPushTimeout)
	for {
		pending, added := clock.WatchTimers()
		// nearest first
		if 0 < len(pending) && !pending[0].After(stepLimit) {
			clock.AdvanceTo(pending[0])
			continue
		}
		select {
		case notice := <-notices:
			return notice
		case <-added:
		case <-guard:
			t.Fatalf("no notice of %s", what)
			return sidecar.PushNotice{}
		}
	}
}

// The next notice, waiting at most testPushTimeout.
func awaitNotice(t *testing.T, notices <-chan sidecar.PushNotice, what string) sidecar.PushNotice {
	t.Helper()
	select {
	case notice := <-notices:
		return notice
	case <-time.After(testPushTimeout):
		t.Fatalf("no notice of %s", what)
		return sidecar.PushNotice{}
	}
}

// The next notice of topic, the others before it skipped: a core resync notice comes with every reset.
func awaitTopicNotice(t *testing.T, notices <-chan sidecar.PushNotice, topic string) sidecar.PushNotice {
	t.Helper()
	for {
		if notice := awaitNotice(t, notices, topic); notice.Topic == topic {
			return notice
		}
	}
}

// The next notice of topic, moving clock, a publisher's, past each timer it arms meanwhile, so its
// coalescing window and backoff end only when this steps them.
func awaitTopicNoticeStepping(t *testing.T, notices <-chan sidecar.PushNotice, topic string, clock *FakeClock) sidecar.PushNotice {
	t.Helper()
	guard := time.After(testPushTimeout)
	for {
		pending, added := clock.WatchTimers()
		if 0 < len(pending) {
			clock.AdvanceTo(slices.MinFunc(pending, func(a time.Time, b time.Time) int { return a.Compare(b) }))
			continue
		}
		select {
		case notice := <-notices:
			if notice.Topic == topic {
				return notice
			}
		case <-added:
		case <-guard:
			t.Fatalf("no notice of %s", topic)
			return sidecar.PushNotice{}
		}
	}
}

// Fails on any notice of topic still queued.
func expectNoTopicNotice(t *testing.T, notices chan sidecar.PushNotice, topic string) {
	t.Helper()
	for {
		select {
		case notice := <-notices:
			if notice.Topic == topic {
				t.Errorf("a notice of %s: %+v", topic, notice)
			}
		default:
			return
		}
	}
}

// A ControlId push over a P2P link, what a P2P peer forging ControlId delivers, is dropped before the
// sidecar's push sees it, and the same frame over h1, the platform's carrier, is kept; and nothing but a
// push type is taken from ControlId even over h1, which the sidecar's own guard drops.
func TestPushControlIdDroppedOverP2pKeptOverH1(t *testing.T) {
	net, laptop, resident, notices := newTestPushSidecar(t, sidecar.PushTopicTeam)
	ctx, cancel := context.WithTimeout(t.Context(), testPushTimeout)
	defer cancel()
	client := laptop.Client().Client
	hint := &protocol.PushHint{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 7}

	net.SetLink(connect.ControlId, laptop.ClientId(), &LinkConditions{TransportType: connect.TransportTypeP2p})
	droppedBefore := client.SubprotocolStats().DroppedControlSource
	// acked once the client's receive callbacks have run, so its dispatch is done with the frame
	if err := resident.SendPushAcked(ctx, protocol.MessageType_PUSH_HINT, hint); err != nil {
		t.Fatal(err)
	}
	if dropped := client.SubprotocolStats().DroppedControlSource; dropped != droppedBefore+1 {
		t.Errorf("connect dropped %d ControlId frames over P2P, want 1", dropped-droppedBefore)
	}
	expectNoTopicNotice(t, notices, sidecar.PushTopicTeam)

	// the same frame over h1
	net.SetLink(connect.ControlId, laptop.ClientId(), nil)
	if err := resident.SendPushAcked(ctx, protocol.MessageType_PUSH_HINT, hint); err != nil {
		t.Fatal(err)
	}
	notice := awaitTopicNotice(t, notices, sidecar.PushTopicTeam)
	if notice.Version != 7 || notice.Resync {
		t.Errorf("over h1 the push gave %+v", notice)
	}
	if dropped := client.SubprotocolStats().DroppedControlSource; dropped != droppedBefore+1 {
		t.Errorf("connect dropped the h1 frame too: %d", dropped-droppedBefore)
	}

	// over h1, a type that is not a push: connect hands it on to the opted-in dispatcher, whose guard
	// drops it, unanswered
	sourceDroppedBefore := laptop.Sidecar().Stats().Subprotocol.SourceDroppedCount
	envelopeBytes, err := proto.Marshal(&protocol.Envelope{Version: sidecar.WireVersionMajor, Type: uint32(protocol.MessageType_PING), RequestId: 1})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := connect.ToFrame(&connectprotocol.SubprotocolMessage{SubprotocolId: sidecar.SubprotocolId, MessageBytes: envelopeBytes}, connect.DefaultProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := resident.SendAcked(ctx, frame); err != nil {
		t.Fatal(err)
	}
	if dropped := laptop.Sidecar().Stats().Subprotocol.SourceDroppedCount; dropped != sourceDroppedBefore+1 {
		t.Errorf("the guard dropped %d non-push frames from ControlId, want 1", dropped-sourceDroppedBefore)
	}
	// the Ping was the capture's finding: a ControlId frame holding more than hint fields
	findings := net.Capture().Scan()
	if len(findings) != 1 || findings[0].NeedleKind != privacyNeedleUnsealed {
		t.Errorf("findings %v, want the Ping alone", findings)
	}
}

// Push resyncs after a resident restart: the client takes a reset and hints from its resident's
// publisher; the resident dies while the owners keep writing; the next resident's publisher sends a
// reset holding every version written meanwhile, then hints whose versions only rise; and what the
// client holds equals what the owners wrote. Nothing between ControlId and the client is more than
// acks and hint fields.
func TestPushResyncsAfterAResidentRestart(t *testing.T) {
	net, laptop, resident, notices := newTestPushSidecar(t, sidecar.PushTopicTeam, sidecar.PushTopicMail)
	ctx := t.Context()
	clientId := laptop.ClientId()
	writer, err := net.HintWriter()
	if err != nil {
		t.Fatal(err)
	}
	written := map[string]uint64{}
	write := func(topic string, version uint64) {
		t.Helper()
		if _, err := writer.HintClient(ctx, clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: 0x0201, Body: []byte{1, 2, 3}}); err != nil {
			t.Fatal(err)
		}
		written[topic] = version
	}
	held := map[string]uint64{}
	hold := func(notice sidecar.PushNotice) {
		t.Helper()
		if notice.Version < held[notice.Topic] {
			t.Errorf("%s fell from %d to %d", notice.Topic, held[notice.Topic], notice.Version)
		}
		held[notice.Topic] = notice.Version
	}

	clock := NewFakeClock(net.Clock().Now())
	if _, err := resident.StartPublisher(nil, clock); err != nil {
		t.Fatal(err)
	}
	// the publisher's reset, of an empty ver, reaches the client before any hint is written, so each
	// version below comes as a hint
	awaitCtx, awaitCancel := context.WithTimeout(ctx, testPushTimeout)
	defer awaitCancel()
	if err := resident.AwaitAcked(awaitCtx, 1); err != nil {
		t.Fatal(err)
	}
	for version := uint64(1); version <= 3; version += 1 {
		write(sidecar.PushTopicTeam, version)
		notice := awaitTopicNoticeStepping(t, notices, sidecar.PushTopicTeam, clock)
		if notice.Version != version || notice.Resync || len(notice.Hint) == 0 {
			t.Fatalf("hint %d gave %+v", version, notice)
		}
		hold(notice)
	}

	// the resident dies mid-stream, and the owners keep writing while none holds the client
	resident.Close()
	write(sidecar.PushTopicTeam, 4)
	write(sidecar.PushTopicTeam, 5)
	write(sidecar.PushTopicMail, 2)
	next, err := net.AddResident(clientId)
	if err != nil {
		t.Fatal(err)
	}
	nextClock := NewFakeClock(net.Clock().Now())
	if _, err := next.StartPublisher(nil, nextClock); err != nil {
		t.Fatal(err)
	}
	// a reset first, whose versions are the owners'
	for _, topic := range []string{sidecar.PushTopicMail, sidecar.PushTopicTeam} {
		notice := awaitTopicNoticeStepping(t, notices, topic, nextClock)
		if !notice.Resync || notice.Version != written[topic] {
			t.Errorf("after the restart %s gave %+v, the owners wrote %d", topic, notice, written[topic])
		}
		hold(notice)
	}
	// then hints, which only rise
	for version := uint64(6); version <= 7; version += 1 {
		write(sidecar.PushTopicTeam, version)
		notice := awaitTopicNoticeStepping(t, notices, sidecar.PushTopicTeam, nextClock)
		if notice.Version != version || notice.Resync {
			t.Fatalf("hint %d after the reset gave %+v", version, notice)
		}
		hold(notice)
	}
	owners, err := net.HintVersions(ctx, clientId)
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range []string{sidecar.PushTopicTeam, sidecar.PushTopicMail} {
		if held[topic] != owners[topic] || held[topic] != written[topic] {
			t.Errorf("%s: the client holds %d, ver %d, the owners wrote %d", topic, held[topic], owners[topic], written[topic])
		}
	}
	if len(net.Capture().FrameSizes(connect.ControlId, clientId)) == 0 {
		t.Fatal("the capture saw nothing from ControlId, so a clean scan proves nothing")
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("finding: %+v", finding)
	}
}

// A reset whose tail is dropped applies nothing: its first part, complete false, moves no topic, and the
// hint that comes next abandons the run and sends the client to GET /sidecar/sync/versions, whose page,
// the owners' versions, is what the client then holds. The part names a team version no owner wrote, so
// a part applied would show as that version, and team is durable, so the owners' lower one would then
// alarm rather than apply. The push has no refetch in flight when the part comes, so the only refetch
// after the run is the one the hint asks for.
func TestPushPartialResetAppliesNothingUntilVersionsRefetched(t *testing.T) {
	net, laptop, resident, notices := newTestPushSidecar(t, sidecar.PushTopicTeam, sidecar.PushTopicMail)
	testPushPartialReset(t, net, laptop, resident, notices)
}

// The same reset while the push waits out its retry of a refused versions refetch, on the Net's clock:
// the test moves the clock to the retry, so a refetch after the run comes whether or not the hint's ask
// for versions ends the wait, and its page is what the client then holds, still with nothing of the part.
func TestPushPartialResetAppliesNothingThroughARefetchRetry(t *testing.T) {
	net, laptop, resident, notices := newTestPushSidecarRefetchRefused(t, sidecar.PushTopicTeam, sidecar.PushTopicMail)
	testPushPartialReset(t, net, laptop, resident, notices)
}

// The partial reset tests' rows on a push set up for them: the owners write team 9 and mail 4, a
// reset's first part names team 50 and its tail never comes, a hint abandons the run, and the client
// ends on the owners' versions, fetched after the run, never having shown team 50.
func testPushPartialReset(t *testing.T, net *Net, laptop *SubprotocolSidecar, resident *NetResident, notices chan sidecar.PushNotice) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testPushTimeout)
	defer cancel()
	clientId := laptop.ClientId()
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := net.HintWriter()
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range []*sidecar.ClientHint{{Topic: sidecar.PushTopicTeam, Version: 9}, {Topic: sidecar.PushTopicMail, Version: 4}} {
		if _, err := writer.HintClient(ctx, clientId, hint); err != nil {
			t.Fatal(err)
		}
	}
	versionsBefore := api.RouteCount("GET /sidecar/sync/versions")

	// the first part of a reset, its tail never sent, as a resident that died between parts leaves it
	if err := resident.SendPushAcked(ctx, protocol.MessageType_PUSH_RESET, &protocol.PushReset{
		Epoch:    1,
		Versions: []*protocol.TopicVersion{{Topic: sidecar.PushTopicTeam, Version: 50}},
		Complete: false,
	}); err != nil {
		t.Fatal(err)
	}
	// a hint behind it on the same worker: it abandons the open run
	if err := resident.SendPushAcked(ctx, protocol.MessageType_PUSH_HINT, &protocol.PushHint{Seq: 2, Topic: sidecar.PushTopicMail, Version: 4}); err != nil {
		t.Fatal(err)
	}
	held := map[string]uint64{}
	for held[sidecar.PushTopicTeam] != 9 || held[sidecar.PushTopicMail] != 4 {
		notice := awaitNoticeSteppingRetries(t, notices, "team 9 and mail 4", net.Clock())
		if notice.Topic == sidecar.PushTopicTeam && notice.Version != 9 {
			t.Fatalf("team moved to %d, which only the incomplete reset named", notice.Version)
		}
		held[notice.Topic] = notice.Version
	}
	if api.RouteCount("GET /sidecar/sync/versions") <= versionsBefore {
		t.Errorf("no versions refetch after the abandoned run")
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("finding: %+v", finding)
	}
}

// The capture's rule for frames from ControlId: acks and push messages of hint fields pass, and
// anything else a resident might put in the clear is a finding, before any canary is looked for.
func TestCaptureHoldsControlIdToHintFields(t *testing.T) {
	transferFrame := func(t *testing.T, frames ...*connectprotocol.Frame) []byte {
		t.Helper()
		encoded, err := proto.Marshal(&connectprotocol.TransferFrame{Pack: &connectprotocol.Pack{Frames: frames}})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	pushFrame := func(t *testing.T, messageType protocol.MessageType, message proto.Message) *connectprotocol.Frame {
		t.Helper()
		frame, err := pushservice.PushFrame(messageType, message, 1)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	envelopeFrame := func(t *testing.T, envelope *protocol.Envelope) *connectprotocol.Frame {
		t.Helper()
		envelopeBytes, err := proto.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := connect.ToFrame(&connectprotocol.SubprotocolMessage{SubprotocolId: sidecar.SubprotocolId, MessageBytes: envelopeBytes}, connect.DefaultProtocolVersion)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	hintBody, err := proto.Marshal(&protocol.PushHint{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	// field 15 of a PushHint, which no hint has
	unknownHintBody := append(hintBody, 0x7a, 0x01, 0x58)
	simple, err := connect.ToFrame(&connectprotocol.SimpleMessage{Content: "content"}, connect.DefaultProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := proto.Marshal(&connectprotocol.TransferFrame{Ack: &connectprotocol.Ack{MessageId: connect.NewId().Bytes(), SequenceId: connect.NewId().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		frame []byte
		pass  bool
	}{
		{name: "hint", frame: transferFrame(t, pushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 2, Kind: 0x0201, Hint: make([]byte, pushservice.DefaultPushFormatSettings().MaxHintByteCount)})), pass: true},
		{name: "reset", frame: transferFrame(t, pushFrame(t, protocol.MessageType_PUSH_RESET, &protocol.PushReset{Epoch: 3, Versions: []*protocol.TopicVersion{{Topic: sidecar.PushTopicTeam, Version: 2}}, Complete: true})), pass: true},
		{name: "ack", frame: ack, pass: true},
		{name: "a connect message", frame: transferFrame(t, simple), pass: false},
		{name: "a peer's type", frame: transferFrame(t, envelopeFrame(t, &protocol.Envelope{Version: sidecar.WireVersionMajor, Type: uint32(protocol.MessageType_HELLO), Flags: sidecar.EnvelopeFlagNoReply})), pass: false},
		{name: "a push asking a reply", frame: transferFrame(t, envelopeFrame(t, &protocol.Envelope{Version: sidecar.WireVersionMajor, Type: uint32(protocol.MessageType_PUSH_HINT), Body: hintBody})), pass: false},
		{name: "a hint's unknown field", frame: transferFrame(t, envelopeFrame(t, &protocol.Envelope{Version: sidecar.WireVersionMajor, Type: uint32(protocol.MessageType_PUSH_HINT), Flags: sidecar.EnvelopeFlagNoReply, Body: unknownHintBody})), pass: false},
		{name: "a hint past 256 B", frame: transferFrame(t, pushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 2, Hint: make([]byte, pushservice.DefaultPushFormatSettings().MaxHintByteCount+1)})), pass: false},
	}
	for _, c := range cases {
		capture := NewPrivacyCapture()
		capture.AddFrame(connect.ControlId, connect.NewId(), c.frame)
		findings := capture.Scan()
		if c.pass && len(findings) != 0 {
			t.Errorf("%s: findings %v", c.name, findings)
		}
		if !c.pass && (len(findings) != 1 || findings[0].NeedleKind != privacyNeedleUnsealed) {
			t.Errorf("%s: findings %v, want the rule's one", c.name, findings)
		}
	}
}

// The api's sync routes answer as server's do: 503 with Retry-After from an api with no hint state, 401
// for a bearer it does not know, 400 for a cursor that is no base64url, and a versions page of the
// client's ver, core filled from the api's clock, as a 200 octet-stream PollResponse.
func TestFakeApiSyncRoutesAnswerAsServersDo(t *testing.T) {
	net := newTestNet(t)
	get := func(t *testing.T, api *FakeApi, path string, bearer string) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.Origin()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := api.Transport().RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		return response
	}
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	outside := NewFakeApi(t.Context(), net.Clock(), net.Faults(), nil, cluster, nil)
	networkId, clientId := sidecar.NewId(), sidecar.NewId()
	if response := get(t, outside, "/sidecar/sync/poll", outside.ClientToken(networkId, clientId, sidecar.Id{})); response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "" {
		t.Errorf("an api outside a Net: %d %v", response.StatusCode, response.Header)
	}

	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	bearer := api.ClientToken(networkId, clientId, sidecar.Id{})
	if response := get(t, api, "/sidecar/sync/versions", "an unknown token"); response.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unknown bearer: %d", response.StatusCode)
	}
	if response := get(t, api, "/sidecar/sync/poll?cursor=%21%21", bearer); response.StatusCode != http.StatusBadRequest {
		t.Errorf("a cursor that is no base64url: %d", response.StatusCode)
	}
	writer, err := net.HintWriter()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.HintClient(t.Context(), connect.Id(clientId), &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 12}); err != nil {
		t.Fatal(err)
	}
	response := get(t, api, "/sidecar/sync/versions", bearer)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("versions: %d %v", response.StatusCode, response.Header)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := &protocol.PollResponse{}
	if err := proto.Unmarshal(body, page); err != nil {
		t.Fatal(err)
	}
	versions := map[string]uint64{}
	for _, version := range page.GetReset_().GetVersions() {
		versions[version.Topic] = version.Version
	}
	if !page.GetReset_().GetComplete() || len(page.Hints) != 0 || versions[sidecar.PushTopicTeam] != 12 || versions[sidecar.PushTopicCore] != uint64(net.Clock().Now().UnixMicro()) {
		t.Errorf("versions page %v", page)
	}
}
