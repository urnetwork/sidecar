//go:build !sidecar_http && !js

// ConfigClient's withheld check judges a follow only by the hints noted before that follow read api
// (config-client-withheld-false-alarm, e2e-all-rerun's churn finding B). A device's own config writer posts its base and
// then waits for its position (WaitFor), which notes that position as a hint, the device's proof api holds it; a follow
// whose read of api came before the base landed, whose answer cannot hold it, was judged by that hint as its page ended,
// so the device raised head_alarm withheld when its own base landed, as TestE2eChurnLoad met once. The hint is now the
// next follow's to judge, the one it asked for, which reads api after it was noted; a position api really withholds
// still alarms once there.
//
// On T2's fake api with a real ConfigClient, ConfigWriter and ConfigLog, each case is held to the order that lost the
// race: the writer plans and signs its base (under the client's follow lock) and its post is held; a follow reads api
// and is held with its answer formed; only then does the base land and the writer's wait note its position and park
// (testWaitAppliedCtx); only then does the held follow go on to judge what it read.

package sidecar_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// api's projection as one follower reads it. While held, each read forms its answer first, reports it on answered, and
// answers only once the test lets it, so the test knows what api had answered before it moves on. Every entry from
// withheldFrom on is cut from the answers, as a server hiding it serves them.
type testWithheldProjection struct {
	reader sidecar.ConfigProjectionReader
	// each held read's after, once its answer is formed
	answered chan uint64

	stateLock sync.Mutex
	held      bool
	// a held read takes one value, or answers at its close
	release      chan struct{}
	withheldFrom uint64
}

func newTestWithheldProjection(reader sidecar.ConfigProjectionReader) *testWithheldProjection {
	return &testWithheldProjection{reader: reader, answered: make(chan uint64, 64), release: make(chan struct{})}
}

// Holds every read from now on until let.
func (self *testWithheldProjection) hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held = true
}

// Lets one held read answer, waiting for it to take the value.
func (self *testWithheldProjection) letOne(t *testing.T) {
	t.Helper()
	release := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.release
	}()
	select {
	case release <- struct{}{}:
	case <-time.After(30 * time.Second):
		t.Fatal("no held read took its release")
	}
}

// Lets every held read answer, and holds no more.
func (self *testWithheldProjection) letAll() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.held {
		self.held = false
		close(self.release)
		self.release = make(chan struct{})
	}
}

// Cuts every entry from n on from the answers; 0 cuts none.
func (self *testWithheldProjection) withhold(n uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.withheldFrom = n
}

// Fails unless a held read formed its answer within 30 s, and answers what it read after.
func (self *testWithheldProjection) waitAnswered(t *testing.T) uint64 {
	t.Helper()
	select {
	case after := <-self.answered:
		return after
	case <-time.After(30 * time.Second):
		t.Fatal("no follow read api")
		return 0
	}
}

// api's read, cut at withheldFrom, held while the test holds reads.
func (self *testWithheldProjection) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	projection, err := self.reader.ReadConfigProjection(ctx, after)
	if err != nil {
		return nil, err
	}
	held, release, withheldFrom := func() (bool, chan struct{}, uint64) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.held, self.release, self.withheldFrom
	}()
	if withheldFrom != 0 {
		served := &sidecar.ConfigProjection{SignedGenesis: projection.SignedGenesis, Rows: projection.Rows, More: projection.More}
		for _, entryBytes := range projection.Entries {
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				return nil, err
			}
			if withheldFrom <= entry.GetN() {
				served.More = false
				break
			}
			chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
			if err != nil {
				return nil, err
			}
			served.Entries = append(served.Entries, entryBytes)
			served.Tip = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
		}
		projection = served
	}
	if !held {
		return projection, nil
	}
	self.answered <- after
	select {
	case <-release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return projection, nil
}

// The head_alarms withheld a client raised, each one's evidence, and a channel closed at the first.
type testWithheldAlarms struct {
	first chan struct{}

	stateLock sync.Mutex
	evidence  [][2][]byte
}

func newTestWithheldAlarms() *testWithheldAlarms {
	return &testWithheldAlarms{first: make(chan struct{})}
}

// ConfigClientArgs.Emit's: keeps a head_alarm withheld.
func (self *testWithheldAlarms) emit(event sidecar.SidecarEvent) {
	if event.Kind != sidecar.SidecarEventHeadAlarm || event.HeadAlarm != sidecar.SidecarHeadAlarmWithheld {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.evidence = append(self.evidence, event.Evidence)
	if len(self.evidence) == 1 {
		close(self.first)
	}
}

// The withheld alarms raised so far, each by its evidence.
func (self *testWithheldAlarms) raised() [][2][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([][2][]byte(nil), self.evidence...)
}

// A full reader of the world's network over projection, its withheld alarms kept in alarms, on the world's clock and
// closed at the test's end.
func testWithheldClient(world *testWriterWorld, projection sidecar.ConfigProjectionReader, alarms *testWithheldAlarms) *sidecar.ConfigClient {
	world.t.Helper()
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = logSettings
	client, err := sidecar.NewConfigClient(world.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    world.networkId,
		GenesisChain: world.genesis.GenesisChain,
		Projection:   projection,
		Heads:        world.heads,
		Clock:        world.clock,
		Emit:         alarms.emit,
		Settings:     settings,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(client.Close)
	return client
}

// What a save answered.
type testWithheldSave struct {
	pin *bridge.AuthPin
	err error
}

// The owner device's save of a policy head through its writer, under way: the writer plans and signs its base, and its
// post is held until let, so the test reads api in between; once let, the base lands and the save's ctx is armed, so
// the save's wait, noting the base's position as it begins (WaitFor), closes the ctx's parked as it parks.
type testWithheldSaving struct {
	ctx   *testWaitAppliedCtx
	post  chan struct{}
	saved chan testWithheldSave
}

// Starts the owner's save over client, answering once the writer holds its post with the base signed: the writer's
// plan and signature each take the client's follow lock, which a held read holds, so they come first.
func testWithheldStartSave(t *testing.T, world *testWriterWorld, client *sidecar.ConfigClient) *testWithheldSaving {
	t.Helper()
	saving := &testWithheldSaving{ctx: newTestWaitAppliedCtx(t, world.ctx, false), post: make(chan struct{}), saved: make(chan testWithheldSave, 1)}
	posting := make(chan struct{}, 1)
	publisher := world.publisher()
	publisher.Before = func(ctx context.Context) {
		select {
		case posting <- struct{}{}:
		default:
		}
		select {
		case <-saving.post:
		case <-ctx.Done():
		}
	}
	// the writer's fold loop on a clock of its own, which nothing moves, so the save's is the one base
	writer := world.writer(world.owner, client, &testWaitAppliedPublisher{publisher: publisher, landed: saving.ctx.arm}, 0, sidecartest.NewFakeClock(world.clock.Now()))
	go func() {
		pin, err := writer.SaveHead(saving.ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
			return head.WithFile(sidecar.ConfigHeadPolicyPath, []byte("{\"grants\": []}"))
		})
		saving.saved <- testWithheldSave{pin: pin, err: err}
	}()
	select {
	case <-posting:
	case save := <-saving.saved:
		t.Fatalf("the save answered before it posted: %v %v", save.pin, save.err)
	}
	return saving
}

// Lets the held post land, and fails unless the save's wait then notes the base's position and parks.
func (self *testWithheldSaving) land(t *testing.T) {
	t.Helper()
	close(self.post)
	select {
	case <-self.ctx.parked:
	case save := <-self.saved:
		t.Fatalf("the save answered before its wait parked: %v %v", save.pin, save.err)
	}
}

// Fails unless the save answers within 30 s, and answers what it answered.
func (self *testWithheldSaving) answer(t *testing.T) testWithheldSave {
	t.Helper()
	select {
	case save := <-self.saved:
		return save
	case <-time.After(30 * time.Second):
		t.Fatal("the save never answered")
		return testWithheldSave{}
	}
}

// Starts a follow of client now on its own goroutine; the channel answers its error.
func testWithheldCatchUp(t *testing.T, world *testWriterWorld, client *sidecar.ConfigClient) chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	t.Cleanup(cancel)
	followed := make(chan error, 1)
	go func() {
		followed <- client.CatchUp(ctx)
	}()
	return followed
}

// A device whose own base lands during a follow raises no withheld alarm: the owner's writer has signed its base, a
// follow reads api before the post lands, whose answer ends at the device's pin, and the base lands and the writer's
// wait notes its position before that follow judges its page. The follow judges by the hints noted before its read, so
// it raises nothing, and the follow the hint asked for applies the base and answers the save. Before, the follow judged
// by the base's position, past what its read could hold, and raised head_alarm withheld.
func TestADevicesOwnBaseLandingDuringAFollowRaisesNoWithheldAlarm(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	projection := newTestWithheldProjection(world.reader())
	alarms := newTestWithheldAlarms()
	client := testWithheldClient(world, projection, alarms)
	before := world.caughtUp(client).Pin()

	saving := testWithheldStartSave(t, world, client)
	projection.hold()
	followed := testWithheldCatchUp(t, world, client)
	if after := projection.waitAnswered(t); after != before.GetVersion() {
		t.Fatalf("the follow read after %d, the device stands at %d", after, before.GetVersion())
	}
	saving.land(t)
	projection.letAll()

	save := saving.answer(t)
	if save.err != nil || save.pin.GetVersion() != before.GetVersion()+1 {
		t.Fatalf("the save landed %v and answered %v, want the base after %d", save.pin, save.err, before.GetVersion())
	}
	if err := <-followed; err != nil {
		t.Fatalf("the follow under way as the base landed answered %v", err)
	}
	// the save answered once a follow after the held one applied the base, so the held follow has judged its page
	if raised := alarms.raised(); len(raised) != 0 {
		t.Fatalf("the device raised head_alarm withheld %d times as its own base landed", len(raised))
	}
	if !client.WithheldSince().IsZero() || !proto.Equal(client.Pin(), save.pin) {
		t.Fatalf("the device stands at %v, withheld since %v, want %v and not withheld", client.Pin(), client.WithheldSince(), save.pin)
	}
}

// A position api really withholds still alarms, once: the owner's base lands at api during a follow as above, but api
// never serves it. The follow under way as it landed judges by the hints noted before its read and raises nothing; the
// follow the base's hint asked for reads api after it, finds it withheld, and raises head_alarm withheld with the
// device's pin as its evidence; follows after it while api still withholds raise no other. Once api serves the base the
// device applies it, is withheld no more, and the save answers.
func TestAPositionApiReallyWithholdsAlarmsOnce(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	projection := newTestWithheldProjection(world.reader())
	alarms := newTestWithheldAlarms()
	client := testWithheldClient(world, projection, alarms)
	before := world.caughtUp(client).Pin()

	projection.withhold(before.GetVersion() + 1)
	saving := testWithheldStartSave(t, world, client)
	projection.hold()
	followed := testWithheldCatchUp(t, world, client)
	projection.waitAnswered(t)
	saving.land(t)
	// the follow that read before the base landed goes on; the next to read api, the hint's follow among them, is held
	// with its answer formed, so the first has judged its page by then and the hint's has not
	projection.letOne(t)
	projection.waitAnswered(t)
	if raised := alarms.raised(); len(raised) != 0 {
		t.Fatalf("the follow that read api before the base landed raised head_alarm withheld %d times", len(raised))
	}
	if !client.WithheldSince().IsZero() {
		t.Fatalf("the follow that read api before the base landed counts the device withheld since %v", client.WithheldSince())
	}

	projection.letAll()
	select {
	case <-alarms.first:
	case <-time.After(30 * time.Second):
		t.Fatal("api withholding the base the device's own writer landed raised no head_alarm withheld")
	}
	if err := <-followed; err != nil {
		t.Fatalf("the follow under way as the base landed answered %v", err)
	}
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()
	for range 2 {
		if err := client.CatchUp(ctx); err != nil {
			t.Fatalf("a follow while api withholds: %v", err)
		}
	}
	raised := alarms.raised()
	if len(raised) != 1 || client.WithheldSince().IsZero() || !proto.Equal(client.Pin(), before) {
		t.Fatalf("the device raised head_alarm withheld %d times, stands at %v withheld since %v, want once at %v", len(raised), client.Pin(), client.WithheldSince(), before)
	}
	local := &bridge.AuthPin{}
	if err := proto.Unmarshal(raised[0][0], local); err != nil || !proto.Equal(local, before) {
		t.Fatalf("the alarm's evidence names %v, want the device's pin %v", local, before)
	}

	projection.withhold(0)
	if err := client.CatchUp(ctx); err != nil {
		t.Fatalf("a follow once api serves the base: %v", err)
	}
	save := saving.answer(t)
	if save.err != nil || save.pin.GetVersion() != before.GetVersion()+1 {
		t.Fatalf("the save landed %v and answered %v, want the base after %d", save.pin, save.err, before.GetVersion())
	}
	if !client.WithheldSince().IsZero() || !proto.Equal(client.Pin(), save.pin) || len(alarms.raised()) != 1 {
		t.Fatalf("the device stands at %v, withheld since %v, after %d alarms", client.Pin(), client.WithheldSince(), len(alarms.raised()))
	}
}
