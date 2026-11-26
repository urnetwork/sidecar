package pushservice_test

// The support push topic's server half (DESIGN-COMPUTE §28.9; §6.8, §18.7; owner decision 783), with a fake publisher
// that hints as the feedback service, FB's and not built, would through Push.HintSidecars: the hint names the event
// and raises its clock past the stored value; a token holder with no live resident is woken as mail's are, the vendor
// told a topic class and a version and no id (WK4); and a resident's publisher tells the topic, bytes and all, to a
// sidecar's client, and to a forwarding device client its seq alone (owner decision 197).

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake feedback service: it hints the support topic for a member's sidecars as the service would when the member's
// conversation gains an event, its version its clock in ms.
type testSupportPublisher struct {
	t      *testing.T
	writer *pushservice.HintWriter
	clock  *sidecartest.FakeClock
}

// Hints the event seq of entry to each sidecar.
func (self *testSupportPublisher) event(sidecarIds []connect.Id, entry string, seq uint32) {
	self.t.Helper()
	hint, err := sidecar.NewSupportClientHint(sidecar.SupportProductUrnetwork, entry, seq, uint64(self.clock.Now().UnixMilli()))
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.writer.HintSidecars(self.t.Context(), sidecarIds, hint); err != nil {
		self.t.Fatal(err)
	}
}

// A member's phone, its resident gone, is woken for support's reply as for mail: the hint lands in its slot at the
// publisher's clock, a second event in the same millisecond is raised past it so the phone hears both, and the push
// sender submits a wake of class support carrying the version alone.
func TestSupportHintWakesAPhoneAsMailDoes(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	env.start("a")
	phoneSidecarId, phoneClientId := connect.NewId(), testWakeClient(7)
	resolver := &testPushResolver{sidecarClientIds: map[connect.Id]connect.Id{phoneSidecarId: phoneClientId}}
	enqueuer, err := pushservice.NewWakeEnqueuer(env.redis, env.settings.Queue, env.clock, func() bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pushservice.NewWakingHintWriter(env.redis, nil, resolver, nil, enqueuer)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &testSupportPublisher{t: t, writer: writer, clock: env.clock}
	env.token(phoneClientId, pushservice.WakePlatformApns, 21)

	publisher.event([]connect.Id{phoneSidecarId}, "100171", 2)
	settled := env.expect(phoneClientId, pushservice.WakeSettledSent)
	if settled.TopicClass != sidecar.PushTopicSupport {
		t.Fatalf("settled %+v", settled)
	}
	submissions := env.apns.Submissions()
	if len(submissions) != 1 {
		t.Fatalf("%d submissions", len(submissions))
	}
	version := uint64(env.clock.Now().UnixMilli())
	if payload := submissions[0].Payload; payload.TopicClass != sidecar.PushTopicSupport || payload.Version != version {
		t.Fatalf("payload %+v", payload)
	}
	for _, err := range sidecartest.WakeSubmissionErrors(submissions[0]) {
		t.Error(err)
	}
	if body := submissions[0].Body; !bytes.Contains(body, []byte(`"t":"support"`)) || bytes.Contains(body, []byte("100171")) {
		t.Fatalf("an apns body %s", body)
	}

	// the same millisecond's second event raises the clock past the stored value, so the phone's push takes it
	hint, err := sidecar.NewSupportClientHint(sidecar.SupportProductUrnetwork, "100171", 3, version)
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.HintClient(t.Context(), phoneClientId, hint)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != version+1 {
		t.Fatalf("a second hint in one ms carries %d, want %d", result.Version, version+1)
	}
	entries, err := env.redis.StreamRange(t.Context(), pushservice.HintStreamKey(phoneClientId), "", 16)
	if err != nil || len(entries) != 2 {
		t.Fatalf("%d hint entries: %v", len(entries), err)
	}
	for index, entry := range entries {
		pushHint, err := pushservice.ParseHintEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		named := &protocol.SupportHint{}
		if pushHint.Topic != sidecar.PushTopicSupport || pushHint.Kind != uint32(protocol.MessageType_SUPPORT_HINT) ||
			proto.Unmarshal(pushHint.Hint, named) != nil || named.Entry != "100171" || named.Seq != uint32(2+index) {
			t.Errorf("hint %d: %v, %v", index, pushHint, named)
		}
	}
}

// The support topic is a wake class, its entry read back as one; sock, tls, dns and compute stay none.
func TestSupportIsAWakeClass(t *testing.T) {
	if class, wakes := pushservice.WakeTopicClass(sidecar.PushTopicSupport); !wakes || class != sidecar.PushTopicSupport {
		t.Fatalf("support: %q, %t", class, wakes)
	}
	for _, topic := range []string{sidecar.PushTopicSock, sidecar.PushTopicTls, sidecar.PushTopicDns, sidecar.PushTopicCompute, "supports"} {
		if _, wakes := pushservice.WakeTopicClass(topic); wakes {
			t.Errorf("%s wakes", topic)
		}
	}
	env := newTestWakeEnv(t, nil)
	clientId := connect.NewId()
	env.token(clientId)
	hint, err := sidecar.NewSupportClientHint(sidecar.SupportProductUrnetwork, "100171", 2, 1795000000000)
	if err != nil {
		t.Fatal(err)
	}
	if result := env.hint(clientId, hint); result.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("wake %d", result.Wake)
	}
	if entries := env.queued(); len(entries) != 1 || entries[0].TopicClass != sidecar.PushTopicSupport || entries[0].Version != 1795000000000 {
		t.Fatalf("queued %+v", entries)
	}
}

// A sidecar's client is told the support topic, its hint whole; a forwarding device client, told team alone, gets the
// support hint as its seq, so nothing of support reaches the VPN component (owner decision 197).
func TestPublisherTellsTheSupportTopicToSidecarClientsAlone(t *testing.T) {
	for _, topics := range [][]string{nil, {sidecar.PushTopicTeam}} {
		func() {
			env := newTestPublisherEnv(t, nil)
			hint := func(seq uint32, version uint64) *sidecar.ClientHint {
				hint, err := sidecar.NewSupportClientHint(sidecar.SupportProductUrnetwork, "100171", seq, version)
				if err != nil {
					t.Fatal(err)
				}
				return hint
			}
			if _, err := env.writer.HintClient(t.Context(), env.clientId, hint(2, 1795000000000)); err != nil {
				t.Fatal(err)
			}
			told := testResetVersions(t, env.startIdle(topics))
			if _, held := told[sidecar.PushTopicSupport]; held != (topics == nil) {
				t.Errorf("%v: the reset holds %v", topics, told)
			}
			later := hint(3, 1795000000100)
			if _, err := env.writer.HintClient(t.Context(), env.clientId, later); err != nil {
				t.Fatal(err)
			}
			env.publisher.Kick()
			env.passWindow()
			env.awaitCall("xrange")
			sent := env.awaitHints(1)[0].hint
			if topics == nil {
				if sent.Topic != sidecar.PushTopicSupport || sent.Version != 1795000000100 || sent.Kind != later.Kind || !bytes.Equal(sent.Hint, later.Body) {
					t.Errorf("a sidecar's client was sent %v", sent)
				}
			} else if sent.Topic != "" || sent.Version != 0 || sent.Kind != 0 || len(sent.Hint) != 0 {
				t.Errorf("a device client was sent %v", sent)
			}
			env.publisher.Close()
		}()
	}
}
