// The fake api's log on T2: the shared store suite, the routes end to end through its transport with a rows-only
// reader following what they answer, the store results a schedule injects through the fault queue (a lost response, a
// 412, a timeout with the entry present), a lost route answer retried, a malicious sequencer's appends and a withheld
// entry.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fake api over a fake first cluster of its own, with its blobs, faults and clock, and a suite env on the same
// cluster for its signers.
type fakeApiTestWorld struct {
	t      *testing.T
	ctx    context.Context
	clock  *FakeClock
	faults *FaultQueue
	blobs  *FakeBlobs
	api    *FakeApi
	env    *configLogSuiteEnv
}

func newFakeApiTestWorld(t *testing.T) *fakeApiTestWorld {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	blobs := NewFakeBlobs(clock, faults, nil, DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	world := &fakeApiTestWorld{t: t, ctx: ctx, clock: clock, faults: faults, blobs: blobs}
	world.api = NewFakeApi(ctx, clock, faults, nil, cluster, nil)
	world.env = newConfigLogSuiteEnv(ctx, cluster, func(sidecar.Clock, sidecar.BlobCluster) ConfigLogSequencer { return world.api })
	world.env.clock = clock
	return world
}

// One request through the api's transport, its JSON reply decoded into result when 200.
func (self *fakeApiTestWorld) call(method string, path string, bearer string, args any, result any) (int, map[string]any, error) {
	var body io.Reader
	if args != nil {
		encoded, err := json.Marshal(args)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(self.ctx, method, self.api.Origin()+path, body)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := self.api.Transport().RoundTrip(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	replyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	if response.StatusCode == http.StatusOK && result != nil {
		return response.StatusCode, nil, json.Unmarshal(replyBytes, result)
	}
	refusal := map[string]any{}
	json.Unmarshal(replyBytes, &refusal)
	return response.StatusCode, refusal, nil
}

// The shared suite on the fake: every case, its sequencers fake apis over one fake cluster.
func TestFakeApiPassesTheConfigLogStoreSuite(t *testing.T) {
	blobs := NewFakeBlobs(NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	RunConfigLogStoreSuite(t, cluster, func(clock sidecar.Clock, cluster sidecar.BlobCluster) ConfigLogSequencer {
		return NewFakeApi(context.Background(), clock, NewFaultQueue(), nil, cluster, nil)
	})
}

// The routes end to end: base 1 with its genesis from the first device's client, statements, a refusal with its code
// and tip, a read from 0 with the genesis, entries and rows, which a rows-only reader follows to the tip; no bearer is
// 401, and an unadmitted client posts no plain statement.
func TestFakeApiRoutesServeTheLog(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	owner := world.api.ClientToken(env.networkId, configLogSuiteId(), env.owner.sidecarId)
	stranger := world.api.ClientToken(env.networkId, configLogSuiteId(), sidecar.Id{})

	genesisChain := bridge.GenesisChain(env.signedGenesis)
	env.tip = &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}
	rows := env.baseOneRows(env.owner)
	pin := &fakeApiConfigPin{}
	status, refusal, err := world.call(http.MethodPost, "/network/config/projection", owner, &fakeApiConfigProjectionPublishArgs{
		SignedHeader: env.base(env.owner, env.tip, rows, 0, 1), Rows: rows, Genesis: env.signedGenesis, ConfigPushes: env.configRepo.pushes(0, 1),
	}, pin)
	if err != nil || status != http.StatusOK || pin.N != 1 {
		t.Fatalf("base 1: %d %v %v", status, refusal, err)
	}
	env.tip = &bridge.AuthPin{Version: pin.N, Chain: pin.Chain}
	for range 3 {
		world.clock.Advance(time.Second)
		status, refusal, err := world.call(http.MethodPost, "/network/config/delta", owner, &fakeApiConfigDeltaArgs{Signed: env.memberAdmit()}, pin)
		if err != nil || status != http.StatusOK {
			t.Fatalf("a statement: %d %v %v", status, refusal, err)
		}
		env.tip = &bridge.AuthPin{Version: pin.N, Chain: pin.Chain}
	}
	if pin.N != 4 {
		t.Fatalf("the tip is %d", pin.N)
	}

	strangerDevice := env.device(env.ownerMemberId)
	refused := env.sign(strangerDevice, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: env.header(), MemberId: configLogSuiteId().Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})
	status, refusal, err = world.call(http.MethodPost, "/network/config/delta", owner, &fakeApiConfigDeltaArgs{Signed: refused}, nil)
	if err != nil || status != http.StatusForbidden || refusal["code"] != "config_refused" || refusal["tip"] == nil {
		t.Errorf("a refused statement: %d %v %v", status, refusal, err)
	}
	status, refusal, err = world.call(http.MethodPost, "/network/config/delta", stranger, &fakeApiConfigDeltaArgs{Signed: env.memberAdmit()}, nil)
	if err != nil || status != http.StatusForbidden || refusal["code"] != "config_unadmitted" {
		t.Errorf("an unadmitted client's plain statement: %d %v %v", status, refusal, err)
	}
	if status, _, err := world.call(http.MethodGet, "/network/config/projection?after=0", "", nil, nil); err != nil || status != http.StatusUnauthorized {
		t.Errorf("no bearer: %d %v", status, err)
	}

	read := &fakeApiConfigProjectionResult{}
	status, refusal, err = world.call(http.MethodGet, "/network/config/projection?after=0", stranger, nil, read)
	if err != nil || status != http.StatusOK {
		t.Fatalf("the read: %d %v %v", status, refusal, err)
	}
	if !bytes.Equal(read.Genesis, env.signedGenesis) || len(read.Entries) != 4 || len(read.Rows) != 1 || read.Tip.N != 4 || read.More {
		t.Fatalf("the read holds %d entries, %d rows, tip %v", len(read.Entries), len(read.Rows), read.Tip)
	}
	reader, err := sidecar.NewConfigLogRowsOnly(nil, read.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	rowsSource := sidecar.ConfigRowsOnlySource(func(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
		for _, rows := range read.Rows {
			if digest := sha256.Sum256(rows); bytes.Equal(digest[:], rowsSha256) {
				return rows, nil
			}
		}
		return nil, errors.New("no such rows")
	})
	if _, err := reader.ApplyRun(read.Entries, rowsSource); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reader.Pin().GetChain(), read.Tip.Chain) {
		t.Error("the reader's tip is not the read's")
	}
	later := &fakeApiConfigProjectionResult{}
	if status, _, err := world.call(http.MethodGet, "/network/config/projection?after=2", stranger, nil, later); err != nil || status != http.StatusOK || len(later.Entries) != 2 || later.Genesis != nil {
		t.Errorf("a read after 2: %d entries, %v", len(later.Entries), err)
	}
}

// FS-14 at the route: api's answer to a statement is lost, the client sends the same bytes again, and the log holds
// the statement once at the position the first send took.
func TestFakeApiLostAnswerRetriedLeavesOneEntry(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	if err := env.start(world.api); err != nil {
		t.Fatal(err)
	}
	owner := world.api.ClientToken(env.networkId, configLogSuiteId(), env.owner.sidecarId)
	signed := env.memberAdmit()
	fired, err := world.faults.Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/network/config/delta", Result: ApplyThenDrop})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := world.call(http.MethodPost, "/network/config/delta", owner, &fakeApiConfigDeltaArgs{Signed: signed}, nil); !errors.Is(err, errFakeApiTransport) {
		t.Fatalf("the lost answer: %v", err)
	}
	<-fired
	pin := &fakeApiConfigPin{}
	if status, refusal, err := world.call(http.MethodPost, "/network/config/delta", owner, &fakeApiConfigDeltaArgs{Signed: signed}, pin); err != nil || status != http.StatusOK {
		t.Fatalf("the retry: %d %v %v", status, refusal, err)
	}
	positions, err := env.positions()
	if err != nil {
		t.Fatal(err)
	}
	if pin.N != 2 || len(positions) != 3 {
		t.Errorf("the retry answered %d over %d entries", pin.N, len(positions))
	}
}

// The store results a schedule injects through the fault queue: a lost response, a 412 over nothing and a timeout
// whose write landed before the next request each end with the statement at the next position, once.
func TestFakeApiTakesInjectedStoreResults(t *testing.T) {
	plans := []struct {
		name string
		plan *FaultPlan
	}{
		{name: "a lost response", plan: &FaultPlan{Op: FaultOpPut, Result: ApplyThenDrop}},
		{name: "a 412", plan: &FaultPlan{Op: FaultOpPut, Result: Precondition}},
		{name: "a timeout with the entry present", plan: &FaultPlan{Op: FaultOpPut, Result: Delay, Delay: DelayLandsBeforeNext}},
	}
	for _, c := range plans {
		world := newFakeApiTestWorld(t)
		env := world.env
		if err := env.start(world.api); err != nil {
			t.Fatal(err)
		}
		c.plan.KeyPrefix = sidecar.ConfigEntryKey(env.networkId, 2)
		fired, err := world.faults.Add(c.plan)
		if err != nil {
			t.Fatal(err)
		}
		signed := env.memberAdmit()
		done := make(chan error, 1)
		var pin *bridge.AuthPin
		go func() {
			var err error
			pin, err = world.api.AppendStatement(world.ctx, env.networkId, signed)
			done <- err
		}()
		<-fired
		if c.plan.Result == Delay {
			// the client's request timeout passes on the clock with the write parked
			if err := world.clock.AwaitTimers(world.ctx, 1); err != nil {
				t.Fatal(err)
			}
			world.clock.Advance(11 * time.Second)
		}
		if err := <-done; err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		positions, err := env.positions()
		if err != nil {
			t.Fatal(err)
		}
		if pin.GetVersion() != 2 || len(positions) != 3 {
			t.Errorf("%s: at %d over %d entries", c.name, pin.GetVersion(), len(positions))
		}
		if err := env.checkEntry(pin, bridge.AuthEntryKindStatement, signed); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A malicious sequencer appends what api refuses (FS-102, FS-124): the statement takes its position, and every reader
// refuses it there and goes on.
func TestSequenceAnywayAppendsWhatApiRefuses(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	if err := env.start(world.api); err != nil {
		t.Fatal(err)
	}
	strangerDevice := env.device(env.ownerMemberId)
	refused := env.sign(strangerDevice, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: env.header(), MemberId: configLogSuiteId().Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})
	if _, err := world.api.AppendStatement(world.ctx, env.networkId, refused); err == nil {
		t.Fatal("api took a statement from no admitted signer")
	}
	pin, err := world.api.SequenceAnyway(world.ctx, env.networkId, bridge.AuthEntryKindStatement, refused)
	if err != nil {
		t.Fatal(err)
	}
	env.tip = pin
	after, err := world.api.AppendStatement(world.ctx, env.networkId, env.memberAdmit())
	if err != nil {
		t.Fatal(err)
	}
	read, err := world.api.ReadProjection(world.ctx, env.networkId, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sidecar.NewConfigLogRowsOnly(nil, read.SignedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	verdicts, err := reader.ApplyRun(read.Entries, world.api.rowsSource(world.ctx))
	if err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 3 || verdicts[1].Accepted() || !errors.Is(verdicts[1].Refusal, sidecar.ErrConfigSigner) || !verdicts[2].Accepted() {
		t.Errorf("the reader's verdicts: %v", verdicts)
	}
	if !proto.Equal(reader.Pin(), after) {
		t.Error("the reader stopped at the refused entry")
	}
}

// A withheld entry: reads stop before it and say more follows, so a reader holding proof of it treats itself as
// withheld, and the store still holds it.
func TestDropEntryWithholdsItFromReads(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	if err := env.start(world.api); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := env.post(world.api, env.memberAdmit()); err != nil {
			t.Fatal(err)
		}
	}
	world.api.DropEntry(env.networkId, 3)
	read, err := world.api.ReadProjection(world.ctx, env.networkId, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Entries) != 2 || !read.More || read.Tip.GetVersion() != 2 {
		t.Errorf("the read holds %d entries, more %t, tip %v", len(read.Entries), read.More, read.Tip)
	}
	if entry, err := env.entry(3); err != nil || entry == nil {
		t.Errorf("the store lost the withheld entry: %v", err)
	}
}

// A base's body is read up to server's 16 MiB JSON bound, past 4 MiB of rows and 4,096 pushes as base64, so a body
// over 8 MiB reaches the walk, here refused for its pushes, and only one past 16 MiB is unread.
func TestFakeApiReadsABaseUpToServersBodyBound(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	if err := env.start(world.api); err != nil {
		t.Fatal(err)
	}
	owner := world.api.ClientToken(env.networkId, configLogSuiteId(), env.owner.sidecarId)
	rows := env.baseOneRows(env.owner)
	oversized := func(pushCount int) *fakeApiConfigProjectionPublishArgs {
		args := &fakeApiConfigProjectionPublishArgs{SignedHeader: env.base(env.owner, env.tip, rows, 1, 1+uint64(pushCount)), Rows: rows}
		for range pushCount {
			args.ConfigPushes = append(args.ConfigPushes, make([]byte, 1024*1024))
		}
		return args
	}
	status, refusal, err := world.call(http.MethodPost, "/network/config/projection", owner, oversized(8), nil)
	if err != nil || status != http.StatusForbidden || refusal["code"] != "config_refused" {
		t.Errorf("a body of about 11 MiB: %d %v %v", status, refusal["code"], err)
	}
	status, refusal, err = world.call(http.MethodPost, "/network/config/projection", owner, oversized(13), nil)
	if err != nil || status != http.StatusBadRequest {
		t.Errorf("a body past 16 MiB: %d %v %v", status, refusal["code"], err)
	}
}

// The Net's api runs on its host's first cluster.
func TestNetAddsAnApiOnItsHost(t *testing.T) {
	net := NewNet(context.Background(), nil)
	defer net.Close()
	api, err := net.AddApi(nil)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	env := newConfigLogSuiteEnv(net.Context(), cluster, func(sidecar.Clock, sidecar.BlobCluster) ConfigLogSequencer { return api })
	if err := env.start(api); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(api.Origin(), "https://") || !strings.HasSuffix(api.Origin(), ".example") {
		t.Errorf("the origin %q", api.Origin())
	}
}

// A TB that records the suite's failures rather than failing the test.
type configLogSuiteRecorder struct {
	testing.TB
	failures []string
}

func (self *configLogSuiteRecorder) Helper() {}

func (self *configLogSuiteRecorder) Errorf(format string, args ...any) {
	self.failures = append(self.failures, format)
}

// The suite tells a sequencer that cannot resolve a race from one that can: a fake api that tries one position only
// fails the cases where another appender wins the first.
func TestTheConfigLogStoreSuiteFailsASequencerThatTriesOnePosition(t *testing.T) {
	blobs := NewFakeBlobs(NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &configLogSuiteRecorder{TB: t}
	RunConfigLogStoreSuite(recorder, cluster, func(clock sidecar.Clock, cluster sidecar.BlobCluster) ConfigLogSequencer {
		settings := DefaultFakeApiSettings()
		settings.AppendAttemptCount = 1
		return NewFakeApi(context.Background(), clock, NewFaultQueue(), nil, cluster, settings)
	})
	if len(recorder.failures) < 2 {
		t.Errorf("the suite failed %d cases", len(recorder.failures))
	}
}
