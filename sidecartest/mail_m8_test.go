//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M8's mail rows of §22 on T2 (MAIL-M8-10; R-MAIL-6, R-MAIL-8, D-MAIL-15, FS-36, FS-82, R-PHASE-7; owner decisions 12,
// 88, 150, 197): the release-readiness paths BS1 ships on, composed from what MAIL-M8-01 to MAIL-M8-09 landed and adding
// no mechanism. Release readiness is never a per-user gate (owner decision 12): coverage shows copy and refuses nothing.
// No app is a mail indexer (owner decision 197), so the plan's Android path is the act row's refusal.
//
//	indexer paths  a desktop ur daemon, a NAS and a VPS: each is one mechanism, a ur daemon, so each path is the same
//	               run under its host's name. Before a designation an online receiver still takes mail, coverage reads
//	               foreground-only and Status, which ur status and mail.status print, carries §15.6's prompt (FS-82's
//	               M8 case); the device's IndexerSet for mail lands, coverage reads indexer and the prompt is gone; and
//	               the designated receiver takes the next message through the router, deposited under its own identity
//	act            SetReceiverEnabled on a real ur daemon's Sidecar, in a real Daemon of the admission suite's world
//	               (Fs98World), files its IndexerSet through the Sidecar's own act: once, a retry filing nothing, and
//	               false retires it; an MCP origin and an Android or iOS app host file nothing (owner decision 197)
//	copy           CreateBurner hands back §15.9's foreground-only copy before a first burner under none and
//	               foreground-only, and never under indexer or for a later burner, and refuses none of them
//	FS-36          the router's own miss, held (MAIL-M8-05's wake hold), wakes the lapsed receiver once and at once
//	               through SDK-M8-12's wake path, the waking hint writer, its enqueue and the push sender over the
//	               host's Redis, its payload a topic class and a version; the hold's next Find then takes the session.
//	               T2's one Redis node, not T3's 3-master cluster, which FS-36's row names
//
// The world is mailworld's M8World (m8_world.go), which S10's receive-only half stands on too (mailworld's s10.go,
// mail_s10_test.go): the admission suite's real log with ACL's own compile, MailWorld's router, receiver session and
// evs engine lined up on it, and the owner's laptop's MailClient bound as the component binds one, with the world's
// stand-ins for the gate, the api and a designation's services opener where no host has a part yet. One more is this
// file's:
//
//	resolver   FS-36's sidecar-to-client resolution, plan-KEYS-hint-addressing's, which no route serves yet
//	           (mailM8PushResolver)
//
// Every name and address is synthetic: .example names and RFC 5737 and 3849 addresses (connect/CODESTYLE.md's test
// data rule). Nothing sleeps: every wait is a monitor's, a pipe's or a timer the test saw armed.

package sidecartest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The indexer paths (the file header's indexer paths row): a desktop ur daemon, a NAS and a VPS each take mail as a
// designated indexer, and until one is designated an online receiver still takes it, coverage reads foreground-only
// and Status carries the prompt (FS-82's M8 case).
func TestMailM8IndexerPathsTakeMailAndEndThePrompt(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	for i, host := range []string{"desktop daemon", "nas", "vps"} {
		world := mailworld.NewM8World(t, net, &mailworld.M8WorldSettings{ReceiverName: host, Label: fmt.Sprintf("lbl%07d", i+1), Host: mailworld.NewM8FakeHost(t, net)})
		ctx := world.Context()

		status, err := world.OwnerMail.Status(ctx)
		if err != nil || !status.Enabled || !status.MailIndexerKnown || status.MailIndexer || status.Prompt != sidecar.MailIndexerPrompt {
			t.Fatalf("%s: before a designation, status %+v: %v", host, status, err)
		}
		if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageForegroundOnly {
			t.Fatalf("%s: before a designation, coverage %s: %v", host, coverage, err)
		}
		created, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "https://" + mailworld.M8SenderDomain + "/signup"})
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if created.CoverageCopy != sidecar.MailCoverageForegroundOnlyCopy {
			t.Fatalf("%s: the first burner's copy %q", host, created.CoverageCopy)
		}
		world.SyncReceiver()
		// FS-82's M8 case: with no mail indexer an online receiver still takes mail
		if reply := world.Send(created.Address, "before a designation", "Your verification code is 482913."); !reply.Is(250) {
			t.Fatalf("%s: mail before a designation: %s", host, reply)
		}

		world.Designate(world.Receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		if indexers := world.Admission.State().Indexers(); len(indexers) != 1 || indexers[0].SidecarId != world.Receiver.SidecarId {
			t.Fatalf("%s: the designations %+v", host, indexers)
		}
		if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageIndexer {
			t.Fatalf("%s: once designated, coverage %s: %v", host, coverage, err)
		}
		status, err = world.OwnerMail.Status(ctx)
		if err != nil || !status.MailIndexerKnown || !status.MailIndexer || status.Prompt != "" {
			t.Fatalf("%s: once designated, status %+v: %v", host, status, err)
		}
		if reply := world.Send(created.Address, "to the indexer", "Your verification code is 731004."); !reply.Is(250) {
			t.Fatalf("%s: mail to the designated indexer: %s", host, reply)
		}
		// both under the designated receiver's own identity, and ingested as the burner's mail
		for subject, depositorId := range world.Depositors() {
			if depositorId != world.Receiver.SidecarId {
				t.Fatalf("%s: %q was deposited by %s, not the %s", host, subject, depositorId, host)
			}
		}
		messages := world.Ingest()
		for _, subject := range []string{"before a designation", "to the indexer"} {
			message := messages[subject]
			if message == nil || message.DepositorId != world.Receiver.SidecarId {
				t.Fatalf("%s: %q was not ingested from the %s: %+v", host, subject, host, message)
			}
		}
	}
}

// CreateBurner's copy before a first burner (the file header's copy row): under none and foreground-only the
// foreground-only copy, the burner made all the same; under indexer none; and a later burner none.
func TestMailM8CreateBurnerShowsTheCopyBeforeAFirstBurner(t *testing.T) {
	cases := []struct {
		name      string
		policy    string
		designate bool
		coverage  sidecar.MailCoverage
		copy      string
	}{
		{name: "no receiver", policy: mailworld.M8PolicyNoReceiver, coverage: sidecar.MailCoverageNone, copy: sidecar.MailCoverageForegroundOnlyCopy},
		{name: "receivers and no indexer", policy: mailworld.M8PolicyReceive, coverage: sidecar.MailCoverageForegroundOnly, copy: sidecar.MailCoverageForegroundOnlyCopy},
		{name: "a mail indexer", policy: mailworld.M8PolicyReceive, designate: true, coverage: sidecar.MailCoverageIndexer},
	}
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	for i, c := range cases {
		world := mailworld.NewM8World(t, net, &mailworld.M8WorldSettings{Policy: c.policy, Label: fmt.Sprintf("lbl%07d", i+1), Host: mailworld.NewM8FakeHost(t, net)})
		ctx := world.Context()
		if c.designate {
			world.Designate(world.Receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		}
		if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != c.coverage {
			t.Fatalf("%s: coverage %s: %v", c.name, coverage, err)
		}
		first, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "first.example"})
		if err != nil {
			t.Fatalf("%s: a first burner refused: %v", c.name, err)
		}
		if first.CoverageCopy != c.copy {
			t.Fatalf("%s: the first burner's copy %q, want %q", c.name, first.CoverageCopy, c.copy)
		}
		second, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "second.example"})
		if err != nil || second.CoverageCopy != "" || second.Label == first.Label {
			t.Fatalf("%s: a second burner %+v: %v", c.name, second, err)
		}
		// the copy speaks of receiving alone: a send's limits are CheckSend's (FS-123's clause as reading 21 reads it)
		text := strings.ToLower(first.CoverageCopy)
		for _, word := range []string{"send", "sent", "outbound"} {
			if strings.Contains(text, word) {
				t.Fatalf("%s: the copy speaks of sending: %q", c.name, first.CoverageCopy)
			}
		}
	}
}

// One host of an Fs98World, a real ur daemon: its Sidecar, in a real Daemon, is admitted and consented in the network
// and is the designator of a MailClient bound to the world on an evs client its own keychain signs for.
type mailM8DaemonHost struct {
	host   *sidecartest.Fs98Host
	engine *sidecar.AclEngine
	mail   *sidecar.MailClient
}

// A daemon host of world named name, of the owner's member and confirmed by the owner's laptop, its MailClient on
// settings, nil for a daemon's.
func newMailM8DaemonHost(t *testing.T, world *mailworld.M8World, fs98 *sidecartest.Fs98World, name string, settings *sidecar.MailSettings) *mailM8DaemonHost {
	t.Helper()
	host := fs98.AddHost(name, world.Owner.MemberId, world.Owner, 0)
	fs98.OwnerConfirm(world.Owner, host.Device)
	if !world.Admission.Consented(host.Device, world.Owner.MemberId) {
		t.Fatalf("%s is not consented", name)
	}
	running := host.Sidecar.Sidecar()
	identity := running.Identity()
	evs := world.Mail.DeviceOf(identity.SidecarId, identity.IdentityPublicKey, running.Sign, false, sidecartest.NewFakeStore().Root(), nil)
	engine := world.Engine(identity.SidecarId)
	return &mailM8DaemonHost{host: host, engine: engine, mail: world.MailClient(identity.SidecarId, evs, engine, running, settings)}
}

// The act row (the file header's act row): SetReceiverEnabled on a real ur daemon files its designation through its
// Sidecar's act, a retry files none, the owner's coverage reads indexer and the prompt goes, and false retires it; an
// MCP origin files nothing, and an Android or iOS app host is never a mail indexer (owner decision 197).
func TestMailM8ReceiverEnabledOnARealDaemonFilesItsDesignation(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	fs98Settings := sidecartest.DefaultFs98Settings()
	fs98Settings.AclCompile = sidecartest.AclAdmissionCompile
	fs98 := sidecartest.NewFs98World(t, net, fs98Settings)
	t.Cleanup(fs98.Close)
	world := mailworld.NewM8World(t, net, &mailworld.M8WorldSettings{Admission: fs98.Admission()})
	ctx := world.Context()
	daemon := newMailM8DaemonHost(t, world, fs98, "desktop daemon host", nil)
	tip := func() uint64 {
		fs98.Settle()
		return world.Admission.Tip().GetVersion()
	}

	before := tip()
	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActMcp, nil); !errors.Is(err, sidecar.ErrMailHostNotConfirmed) {
		t.Fatalf("a designation through MCP: %v", err)
	}
	if after := tip(); after != before {
		t.Fatalf("an MCP origin moved the log from %d to %d", before, after)
	}
	for _, profile := range []sidecar.MailHostProfile{sidecar.MailHostProfileAndroid, sidecar.MailHostProfileIos} {
		settings := sidecar.DefaultMailSettings()
		sidecar.ApplyMobileMailSettings(settings, profile)
		phone := newMailM8DaemonHost(t, world, fs98, string(profile)+" app host", settings)
		before := tip()
		if err := phone.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); !errors.Is(err, sidecar.ErrMailHostNotIndexer) {
			t.Fatalf("the %s app host's designation: %v", profile, err)
		}
		if after := tip(); after != before {
			t.Fatalf("the %s app host moved the log from %d to %d", profile, before, after)
		}
	}

	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	filed := tip()
	world.Install()
	indexers := world.Admission.State().Indexers()
	daemonId := daemon.host.Device.SidecarId
	if len(indexers) != 1 || indexers[0].SidecarId != daemonId || indexers[0].Signer != daemonId || indexers[0].Scope != protocol.IndexerScope_INDEXER_SCOPE_MEMBER {
		t.Fatalf("the designations %+v", indexers)
	}
	if services, ok := world.OpenServices(indexers[0]); !ok || !slices.Equal(services, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}) {
		t.Fatalf("the designation's services %v, opened %t", services, ok)
	}
	// a retry finds mail filed already
	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); err != nil || tip() != filed {
		t.Fatalf("a retry: %v, the log at %d after %d", err, world.Admission.Tip().GetVersion(), filed)
	}
	if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageIndexer {
		t.Fatalf("the owner's coverage with the daemon designated: %s: %v", coverage, err)
	}
	if status, err := world.OwnerMail.Status(ctx); err != nil || status.Prompt != "" {
		t.Fatalf("the owner's status with the daemon designated: %+v: %v", status, err)
	}

	if err := daemon.mail.SetReceiverEnabled(ctx, false, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	tip()
	world.Install()
	if indexers := world.Admission.State().Indexers(); len(indexers) != 0 {
		t.Fatalf("after the retirement, designations %+v", indexers)
	}
	if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageForegroundOnly {
		t.Fatalf("the owner's coverage after the retirement: %s: %v", coverage, err)
	}
	if status, err := world.OwnerMail.Status(ctx); err != nil || status.Prompt != sidecar.MailIndexerPrompt {
		t.Fatalf("the owner's status after the retirement: %+v: %v", status, err)
	}
}

// plan-KEYS-hint-addressing's resolution, which no route serves yet (server's router block runs with none, so every
// hint by sidecar is lost there): each sidecar's current client, as the host's resolver is to answer it (§6.8).
type mailM8PushResolver struct {
	stateLock sync.Mutex
	clientIds map[connect.Id]connect.Id
}

func (self *mailM8PushResolver) PushClientIds(ctx context.Context, sidecarIds []connect.Id) (map[connect.Id]connect.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	resolved := map[connect.Id]connect.Id{}
	for _, sidecarId := range sidecarIds {
		if clientId, ok := self.clientIds[sidecarId]; ok {
			resolved[sidecarId] = clientId
		}
	}
	return resolved, nil
}

// FS-36's forced router miss with SDK-M8-12's wake path (the file header's FS-36 row): the router's own miss holds the
// session and its forced MailHint{RECEIVER_NEEDED} goes through the waking hint writer, its enqueue and the push
// sender, so the lapsed receiver's token is woken once and at once, though live was just refreshed, its payload a topic
// class and a version alone (WK4); then the receiver registers, the hold's next Find takes the session, and the
// message is deposited by that receiver, with no second wake.
func TestMailM8Fs36ForcedRouterMissWakesTheReceiverOnceAtOnce(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	host := mailworld.NewM8FakeHost(t, net)
	sidecartest.RegisterPushScripts(host.Redis)
	clock := net.Clock()
	ctx := t.Context()

	// the wake path as server's router block builds it: the waking hint writer over the host's Redis with its enqueue,
	// and the sender reading the queue into two vendor sinks, each wait long so the only timers are the schedule's
	senderSettings := pushservice.DefaultWakeSenderSettings()
	senderSettings.ReadBlock = 100 * time.Hour
	senderSettings.ClaimInterval = 1000 * time.Hour
	senderSettings.GateInterval = 10000 * time.Hour
	shardCount := pushservice.DefaultWakeQueueSettings().ShardCount
	if senderSettings.Queue != nil {
		shardCount = senderSettings.Queue.ShardCount
	}
	for shard := range shardCount {
		if err := host.Redis.StreamGroupCreate(ctx, pushservice.WakeQueueKey(shard), senderSettings.ConsumerGroup); err != nil {
			t.Fatal(err)
		}
	}
	metrics := sidecartest.NewFakeMetrics(nil)
	enqueuer, err := pushservice.NewWakeEnqueuer(host.Redis, senderSettings.Queue, clock, func() bool { return true }, metrics)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &mailM8PushResolver{clientIds: map[connect.Id]connect.Id{}}
	writer, err := pushservice.NewWakingHintWriter(host.Redis, nil, resolver, metrics, enqueuer)
	if err != nil {
		t.Fatal(err)
	}
	lapsed := &atomic.Bool{}
	lapsed.Store(true)
	world := mailworld.NewM8World(t, net, &mailworld.M8WorldSettings{Host: host, MailWorld: func(settings *mailworld.MailWorldSettings) {
		settings.Router = func(router *mxedgeservice.MxEdgeSettings) {
			router.WakeHold = true
		}
		settings.Push = writer
		// the receiver's registration lapsed: the Find answers no listener until it registers again
		settings.DialRefusal = func(request *mxedgeservice.MxEdgeDialRequest) error {
			if lapsed.Load() {
				return &sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener}
			}
			return nil
		}
	}})

	// the receiver's client, its keys in slots apart from its wake shard's (WK1), with a wake token and live just
	// refreshed, so an unforced hint would be put off
	var clientId connect.Id
	for range 64 {
		clientId = connect.NewId()
		shardKey := pushservice.WakeQueueKey(pushservice.WakeQueueShard(clientId, shardCount))
		if sidecartest.RedisClusterSlot(pushservice.HintTokenKey(clientId)) != sidecartest.RedisClusterSlot(shardKey) {
			break
		}
	}
	resolver.stateLock.Lock()
	resolver.clientIds[connect.Id(world.Receiver.SidecarId)] = clientId
	resolver.stateLock.Unlock()
	token := "synthetic-fcm-token-" + clientId.String()[:8]
	t0, err := pushservice.ReadWakeTokenTime(ctx, host.Redis, clientId)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := pushservice.ApplyWakeToken(ctx, host.Redis, &pushservice.WakeTokenRow{ClientId: clientId, Revision: 1, Platform: pushservice.WakePlatformFcm, Token: token}, t0, time.Minute); err != nil || applied != pushservice.WakeTokenApplied {
		t.Fatalf("the token's apply answered %q: %v", applied, err)
	}
	if err := host.Redis.Set(ctx, pushservice.HintLiveKey(clientId), []byte("1"), pushservice.DefaultSidecarPublisherSettings().LiveTimeout); err != nil {
		t.Fatal(err)
	}
	vendors := []*sidecartest.FakeWakeVendor{
		sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock), sidecartest.NewFakeWakeVendor(pushservice.WakePlatformFcm, clock),
	}
	settled := make(chan *pushservice.WakeSettled, 64)
	readsEnd := clock.Now().Add(senderSettings.ReadBlock)
	sender, err := pushservice.NewWakeSender(ctx, &pushservice.WakeSenderArgs{
		Redis:    host.Redis,
		Vendors:  []pushservice.WakeVendor{vendors[0], vendors[1]},
		Consumer: "mail-m8",
		Enabled:  func() bool { return true },
		Clock:    clock,
		Metrics:  metrics,
		Settings: senderSettings,
		Settled: func(result *pushservice.WakeSettled) {
			settled <- result
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	// each shard's reader in its read before a hint, as a sender long up is
	world.Mail.AwaitTimerCountAt(readsEnd, shardCount)
	submissions := func() []*sidecartest.FakeWakeSubmission {
		found := []*sidecartest.FakeWakeSubmission{}
		for _, vendor := range vendors {
			for _, submission := range vendor.Submissions() {
				if submission.Token == token {
					found = append(found, submission)
				}
			}
		}
		return found
	}

	created, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: mailworld.M8SenderDomain})
	if err != nil {
		t.Fatal(err)
	}
	world.SyncReceiver()
	mta := world.Mail.Connect(mailworld.M8Sender)
	defer mta.Close()
	world.Mail.Greet(mta, "relay."+mailworld.M8SenderDomain)
	handshake := make(chan error, 1)
	go func() {
		_, err := mta.StartTls(sidecartest.MailMtaTlsConfig(world.Mail.Settings().MxHost(), tls.VersionTLS13))
		handshake <- err
	}()
	routerSettings := mxedgeservice.DefaultMxEdgeSettings()
	quietAt := clock.Now().Add(routerSettings.StartTlsQuietTimeout)
	world.Mail.AwaitTimerAt(quietAt)
	clock.Advance(quietAt.Sub(clock.Now()))
	missAt := clock.Now()

	// the miss: held, and its forced hint woken at once
	select {
	case result := <-settled:
		if result.ClientId != clientId || result.Result != pushservice.WakeSettledSent || result.TopicClass != "mail" || result.Platform != pushservice.WakePlatformFcm {
			t.Fatalf("the wake %+v", result)
		}
	case <-time.After(world.Mail.Settings().StepTimeout):
		t.Fatal("the router's miss woke no one")
	}
	woken := submissions()
	if len(woken) != 1 || !woken[0].At.Equal(missAt) || woken[0].Payload.TopicClass != "mail" || woken[0].Payload.Version != uint64(missAt.UnixMilli()) {
		t.Fatalf("the submissions %+v at the miss %v", woken, missAt)
	}
	for _, body := range [][]byte{woken[0].Body, []byte(fmt.Sprint(woken[0].Payload))} {
		for _, id := range []string{clientId.String(), world.Receiver.SidecarId.String(), world.Admission.NetworkId().String()} {
			if bytes.Contains(body, []byte(id)) {
				t.Fatalf("the wake carries an id: %q", body)
			}
		}
	}
	select {
	case err := <-handshake:
		t.Fatalf("the held session's handshake ended before a receiver registered: %v", err)
	default:
	}

	// the receiver registers again, and the hold's next Find takes the session
	lapsed.Store(false)
	retryAt := missAt.Add(routerSettings.WakeHoldFindInterval)
	world.Mail.AwaitTimerAt(retryAt)
	clock.Advance(retryAt.Sub(clock.Now()))
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatalf("the held session's handshake: %v", err)
		}
	case <-time.After(world.Mail.Settings().StepTimeout):
		t.Fatal("the held session never spliced")
	}
	if reply, err := mta.Ehlo("relay." + mailworld.M8SenderDomain); err != nil || !reply.Is(250) {
		t.Fatalf("EHLO inside TLS: %s %v", reply, err)
	}
	if reply, err := mta.MailFrom("signup@" + mailworld.M8SenderDomain); err != nil || !reply.Is(250) {
		t.Fatalf("MAIL: %s %v", reply, err)
	}
	if reply, err := mta.RcptTo(created.Address); err != nil || !reply.Is(250) {
		t.Fatalf("RCPT: %s %v", reply, err)
	}
	if reply, err := mta.Data(mailworld.M8Message(created.Address, "held for the receiver", "Your verification code is 220917.")); err != nil || !reply.Is(250) {
		t.Fatalf("DATA: %s %v", reply, err)
	}
	world.Mail.Finish(mta)
	if message := world.Ingest()["held for the receiver"]; message == nil || message.DepositorId != world.Receiver.SidecarId {
		t.Fatalf("the held message was not ingested from the receiver: %+v", message)
	}
	if woken := submissions(); len(woken) != 1 {
		t.Fatalf("%d submissions for one hold", len(woken))
	}
}
