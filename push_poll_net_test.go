//go:build !sidecar_http && !js

// §6.8's M1 exit row for HTTP-only hosts on T2 (PROTO-M1-11): a host with no connect client, an HTTP-only
// sandbox or the page Worker (§18.10), runs the long-poll client on SidecarApi against the Net's api,
// whose GET /sidecar/sync/poll holds on pushservice's own LongPoll over the Net's hint state; a real
// Sidecar beside it hears the same owners' writes from its resident over ControlId; and both reach the
// owners' state, topic by topic. The publisher's window runs on a fake clock the test steps, and the
// long-poll's holds on the Net's, which nothing moves, so only a hint ends one.

package sidecar_test

import (
	"context"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long the test waits, in real time, for what it expects: only a broken run's bound.
const testPushPollNetTimeout = 45 * time.Second

// One notice, with the client whose subscriber heard it.
type testPushNotice struct {
	clientName string
	notice     sidecar.PushNotice
}

// What each client has been told, topic by topic, as its subscribers heard it: one channel for all of
// them, so a wait reads one channel.
type testPushHeld struct {
	notices          chan testPushNotice
	clientTopicsHeld map[string]map[string]uint64
}

func newTestPushHeld() *testPushHeld {
	return &testPushHeld{notices: make(chan testPushNotice, 1024), clientTopicsHeld: map[string]map[string]uint64{}}
}

// Subscribes a client's topics, under clientName.
func (self *testPushHeld) subscribe(t *testing.T, clientName string, subscribe func(topic string, callback sidecar.PushNoticeFunction) (func(), error), topics ...string) {
	t.Helper()
	self.clientTopicsHeld[clientName] = map[string]uint64{}
	for _, topic := range topics {
		remove, err := subscribe(topic, func(notice sidecar.PushNotice) {
			select {
			case self.notices <- testPushNotice{clientName: clientName, notice: notice}:
			default:
				t.Errorf("the test's notices are full")
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(remove)
	}
}

// Takes one notice, failing on a version that falls.
func (self *testPushHeld) take(t *testing.T, notice testPushNotice) {
	t.Helper()
	held := self.clientTopicsHeld[notice.clientName]
	if notice.notice.Version < held[notice.notice.Topic] {
		t.Errorf("%s: %s fell from %d to %d", notice.clientName, notice.notice.Topic, held[notice.notice.Topic], notice.notice.Version)
	}
	held[notice.notice.Topic] = notice.notice.Version
}

// Waits until every client holds version for topic, moving clock, the publisher's, past each timer it
// arms meanwhile.
func (self *testPushHeld) await(t *testing.T, clock *sidecartest.FakeClock, topic string, version uint64) {
	t.Helper()
	guard := time.After(testPushPollNetTimeout)
	for {
		reached := true
		for _, held := range self.clientTopicsHeld {
			reached = reached && held[topic] == version
		}
		if reached {
			return
		}
		pending, added := clock.WatchTimers()
		if 0 < len(pending) {
			clock.AdvanceTo(slices.MinFunc(pending, func(a time.Time, b time.Time) int { return a.Compare(b) }))
			continue
		}
		select {
		case notice := <-self.notices:
			self.take(t, notice)
		case <-added:
		case <-guard:
			t.Fatalf("%s did not reach %d: %v", topic, version, self.clientTopicsHeld)
		}
	}
}

func TestPushPollReachesTheResidentsState(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithTimeout(t.Context(), testPushPollNetTimeout)
	defer cancel()
	sidecars, _, err := net.AddSubprotocolSidecars("laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	groupTopic := sidecar.PushTopicGkmGroup(sidecar.NewId())
	topics := []string{sidecar.PushTopicTeam, sidecar.PushTopicMail, groupTopic}

	// the sidecar on its resident's push
	held := newTestPushHeld()
	held.subscribe(t, "pushed", laptop.Subprotocol().Subscribe, topics...)
	resident, err := net.AddResident(laptop.ClientId())
	if err != nil {
		t.Fatal(err)
	}
	clock := sidecartest.NewFakeClock(net.Clock().Now())
	if _, err := resident.StartPublisher(nil, clock); err != nil {
		t.Fatal(err)
	}
	if err := resident.AwaitAcked(ctx, 1); err != nil {
		t.Fatal(err)
	}

	// the HTTP-only host: a client of the same network with no connect client, on the long-poll
	pollClientId := sidecar.NewId()
	bearer := api.ClientToken(laptop.NetworkId(), pollClientId, sidecar.NewId())
	settings := sidecar.DefaultSidecarSettings()
	settings.ApiUrl = api.Origin()
	settings.AuthUrl = api.AuthOrigin()
	settings.PlatformUrl = "wss://platform.sidecartest.example"
	settings.EvsUrl = api.ServiceOrigin("evs")
	settings.GkmUrl = api.ServiceOrigin("gkm")
	settings.SocketsUrl = api.ServiceOrigin("sockets")
	settings.DnsUrl = api.ServiceOrigin("dns")
	clientKeySeed := make([]byte, 32)
	if _, err := rand.Read(clientKeySeed); err != nil {
		t.Fatal(err)
	}
	sidecarApi, err := sidecar.NewSidecarApiWithClientKey(settings, api.Transport(), bearer, clientKeySeed, net.Clock().Now)
	if err != nil {
		t.Fatal(err)
	}
	pollClient, err := sidecar.NewPushPollClient(ctx, sidecarApi, sidecartest.NewFakeStore().Root(), nil, net.Clock(), sidecar.NewNoopLogger(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pollClient.Close()
	held.subscribe(t, "polled", pollClient.Subscribe, topics...)

	// the owners write to both clients alike
	writer, err := net.HintWriter()
	if err != nil {
		t.Fatal(err)
	}
	clientIds := []connect.Id{laptop.ClientId(), connect.Id(pollClientId)}
	for _, hint := range []*sidecar.ClientHint{
		{Topic: sidecar.PushTopicTeam, Version: 1, Kind: 0x0201, Body: []byte{1}},
		{Topic: sidecar.PushTopicMail, Version: 3},
		{Topic: sidecar.PushTopicTeam, Version: 2, Kind: 0x0201, Body: []byte{2}},
		{Topic: groupTopic, Version: 5 << 24},
		{Topic: sidecar.PushTopicTeam, Version: 3},
	} {
		if err := writer.Hint(ctx, clientIds, hint); err != nil {
			t.Fatal(err)
		}
		held.await(t, clock, hint.Topic, hint.Version)
	}
	for _, clientId := range clientIds {
		owners, err := net.HintVersions(ctx, clientId)
		if err != nil {
			t.Fatal(err)
		}
		for _, topic := range topics {
			pushed, polled := held.clientTopicsHeld["pushed"][topic], held.clientTopicsHeld["polled"][topic]
			if pushed != owners[topic] || polled != owners[topic] {
				t.Errorf("%s: pushed %d, polled %d, the owners wrote %d to %s", topic, pushed, polled, owners[topic], clientId)
			}
		}
	}
	if api.RouteCount("GET /sidecar/sync/poll") == 0 {
		t.Errorf("the HTTP-only host never polled")
	}
	if pollClient.Ended() != nil {
		t.Errorf("the poll ended: %v", pollClient.Ended())
	}
}
