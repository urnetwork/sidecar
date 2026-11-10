// QUOTA-M2-10's read tests on T2's fakes: an unspent network unthrottled with no call, a spent one paced on its
// own repo to its rate on a fake clock within one bucket, another network's repo refused with upgrade, the split
// by blocks, the fallback rate while limits are unread, and through the engine FS-47's "reads work" and a large
// framed read that stays parseable while paced.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A Quota that counts what a gate asks of it, and can fail Limits.
type countingQuota struct {
	sidecar.Quota

	stateLock            sync.Mutex
	networkIdLimitCounts map[connect.Id]int
	limitNetworkIds      []connect.Id
	limitsErr            error
}

func (self *countingQuota) Limits(ctx context.Context, networkId connect.Id) (*sidecar.QuotaLimits, error) {
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkIdLimitCounts[networkId] += 1
		self.limitNetworkIds = append(self.limitNetworkIds, networkId)
		return self.limitsErr
	}()
	if err != nil {
		return nil, err
	}
	return self.Quota.Limits(ctx, networkId)
}

func (self *countingQuota) limitCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.limitNetworkIds)
}

func (self *countingQuota) setLimitsErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limitsErr = err
}

// A gate alone on a fake clock, so the only timers are its paces' waits.
type readGateFixture struct {
	t     *testing.T
	ctx   context.Context
	clock *sidecartest.FakeClock
	fake  *sidecartest.FakeQuota
	quota *countingQuota
	gate  *QuotaGate
}

func newReadGateFixture(t *testing.T, adjust func(settings *QuotaReadSettings)) *readGateFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	fake := sidecartest.NewFakeQuota(clock, nil, nil)
	quota := &countingQuota{Quota: fake, networkIdLimitCounts: map[connect.Id]int{}}
	settings := DefaultQuotaGateSettings()
	if adjust != nil {
		adjust(settings.Read)
	}
	gate, err := newQuotaGate(ctx, &sidecar.ServiceHost{Quota: quota, Clock: clock}, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	return &readGateFixture{t: t, ctx: ctx, clock: clock, fake: fake, quota: quota, gate: gate}
}

// The network spent with rate as its evs_unpaid_read_rate, both read by the gate once a pace exists.
func (self *readGateFixture) spend(networkId connect.Id, rate int64) {
	self.fake.SetSpentRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "transfer"})
	self.fake.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{quotaLimitKeyUnpaidReadRate: rate}})
	self.gate.refresh(self.ctx)
}

// The network's pace on its own repo, its limits read.
func (self *readGateFixture) ownPace(networkId connect.Id) *QuotaReadPace {
	self.t.Helper()
	pace, refusal := self.gate.CheckRead(networkId, networkId)
	if pace == nil || refusal != nil {
		self.t.Fatalf("a spent network's own read: pace %v, refusal %+v", pace, refusal)
	}
	self.gate.refresh(self.ctx)
	return pace
}

// Moves the clock from wait to wait until done closes: each step goes exactly to the next timer, so the time
// that passes is the time the waits asked for.
func (self *readGateFixture) runWaits(done <-chan struct{}) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		if 0 < len(pending) {
			self.clock.AdvanceTo(pending[0])
			continue
		}
		select {
		case <-done:
			return
		case <-added:
		case <-self.ctx.Done():
			self.t.Fatal(self.ctx.Err())
		}
	}
}

// What a paced writer wrote and when, on the fake clock.
type pacedRecorder struct {
	clock *sidecartest.FakeClock

	stateLock  sync.Mutex
	header     http.Header
	body       []byte
	writeTimes []time.Time
	writeEnds  []int
	flushCount int
}

func (self *pacedRecorder) Header() http.Header {
	return self.header
}

func (self *pacedRecorder) WriteHeader(status int) {}

func (self *pacedRecorder) Write(body []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.body = append(self.body, body...)
	self.writeTimes = append(self.writeTimes, self.clock.Now())
	self.writeEnds = append(self.writeEnds, len(self.body))
	return len(body), nil
}

func (self *pacedRecorder) Flush() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.flushCount += 1
}

// A network that is not spent reads with no pace, no bucket and no call, at its storage limit too, while
// another network is spent.
func TestCheckReadLeavesAnUnspentNetworkAloneWithNoCall(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.spend(connect.NewId(), 1000)
	fixture.fake.SetStorageRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 10, Used: 10, Upgrade: true})
	fixture.gate.refresh(fixture.ctx)
	for _, repoNetworkId := range []connect.Id{networkId, connect.NewId()} {
		pace, refusal := fixture.gate.CheckRead(networkId, repoNetworkId)
		if pace != nil || refusal != nil {
			t.Fatalf("an unspent network's read: pace %v, refusal %+v", pace, refusal)
		}
	}
	if fixture.gate.Spent(networkId) {
		t.Fatal("a network at its storage limit read as spent")
	}
	fixture.gate.refresh(fixture.ctx)
	if got := fixture.quota.limitCount(); got != 0 {
		t.Fatalf("%d Limits calls with no spent network reading, want none", got)
	}
	if got := len(fixture.gate.reads.networkIdBuckets); got != 0 {
		t.Fatalf("%d buckets with no spent network reading, want none", got)
	}
	if pending := fixture.clock.PendingTimers(); len(pending) != 0 {
		t.Fatalf("timers %v, want none", pending)
	}
}

// A spent network reads its own repos and no other network's: the refusal is the list's, with upgrade set.
func TestCheckReadRefusesASpentNetworkAnotherNetworksRepo(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.fake.SetSpentRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "transfer", Limit: 7, Used: 9})
	fixture.gate.refresh(fixture.ctx)
	if !fixture.gate.Spent(networkId) {
		t.Fatal("not spent")
	}
	for _, repoNetworkId := range []connect.Id{connect.NewId(), {}} {
		pace, refusal := fixture.gate.CheckRead(networkId, repoNetworkId)
		if pace != nil || refusal == nil {
			t.Fatalf("another network's repo: pace %v, refusal %+v", pace, refusal)
		}
		if refusal.LimitKey != "transfer" || refusal.Limit != 7 || refusal.Used != 9 || !refusal.Upgrade {
			t.Fatalf("refusal %+v", refusal)
		}
	}
	if got := len(fixture.gate.reads.networkIdBuckets); got != 0 {
		t.Fatalf("a refused read made %d buckets", got)
	}
	if pace, refusal := fixture.gate.CheckRead(networkId, networkId); pace == nil || refusal != nil {
		t.Fatalf("its own repo: pace %v, refusal %+v", pace, refusal)
	}
}

// A spent network's reply leaves at its rate within one bucket: the first second's worth at once, then never
// more than the rate allows, every byte in order, and in exactly the time the rate takes.
func TestSpentReadIsPacedToItsRateWithinOneBucket(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.spend(networkId, 1000)
	pace := fixture.ownPace(networkId)
	if pace.Rate() != 1000 || pace.ChunkByteCount() != 1000 {
		t.Fatalf("rate %d, chunk %d", pace.Rate(), pace.ChunkByteCount())
	}
	body := make([]byte, 5500)
	for i := range body {
		body[i] = byte(i * 7)
	}
	recorder := &pacedRecorder{clock: fixture.clock, header: http.Header{}}
	writer := newQuotaPacedWriter(fixture.ctx, recorder, pace)
	start := fixture.clock.Now()
	done := make(chan struct{})
	var written int
	var writeErr error
	go func() {
		defer close(done)
		written, writeErr = writer.Write(body)
	}()
	fixture.runWaits(done)
	if writeErr != nil || written != len(body) {
		t.Fatalf("wrote %d of %d: %v", written, len(body), writeErr)
	}
	if !bytes.Equal(recorder.body, body) {
		t.Fatal("the paced bytes are not the reply's, in order")
	}
	// 1,000 at once, then 4,500 at 1,000 a second
	if elapsed := fixture.clock.Now().Sub(start); elapsed != 4500*time.Millisecond {
		t.Fatalf("5,500 bytes took %s, want 4.5 s", elapsed)
	}
	for i, writeTime := range recorder.writeTimes {
		allowed := 1000 + 1000*writeTime.Sub(start).Milliseconds()/1000
		if int64(recorder.writeEnds[i]) > allowed {
			t.Fatalf("%d bytes sent by %s, past the bucket and the rate's %d", recorder.writeEnds[i], writeTime.Sub(start), allowed)
		}
	}
	if recorder.writeEnds[0] != 1000 || !recorder.writeTimes[0].Equal(start) {
		t.Fatalf("the first write: %d bytes at %s, want the bucket's 1,000 at once", recorder.writeEnds[0], recorder.writeTimes[0].Sub(start))
	}
	if recorder.flushCount != len(recorder.writeTimes)-1 {
		t.Fatalf("%d flushes for %d chunks", recorder.flushCount, len(recorder.writeTimes))
	}
	// an idle bucket fills to one second's worth, never more
	fixture.clock.Advance(time.Hour)
	again := fixture.clock.Now()
	done = make(chan struct{})
	go func() {
		defer close(done)
		written, writeErr = writer.Write(body[:2000])
	}()
	fixture.runWaits(done)
	if elapsed := fixture.clock.Now().Sub(again); writeErr != nil || elapsed != time.Second {
		t.Fatalf("2,000 bytes after an hour idle took %s (%v), want 1 s", elapsed, writeErr)
	}
}

// Two requests of one spent network share its bucket, so together they stay at the rate.
func TestSpentReadsOfOneNetworkShareItsBucket(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.spend(networkId, 1000)
	first := fixture.ownPace(networkId)
	second, _ := fixture.gate.CheckRead(networkId, networkId)
	start := fixture.clock.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, pace := range []*QuotaReadPace{first, second, first, second} {
			if err := pace.Wait(fixture.ctx, 1000); err != nil {
				t.Error(err)
			}
		}
	}()
	fixture.runWaits(done)
	if elapsed := fixture.clock.Now().Sub(start); elapsed != 3*time.Second {
		t.Fatalf("4,000 bytes over two requests took %s, want 3 s", elapsed)
	}
	// another spent network's bucket is its own
	otherId := connect.NewId()
	fixture.spend(otherId, 1000)
	other := fixture.ownPace(otherId)
	if err := other.Wait(fixture.ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if pending := fixture.clock.PendingTimers(); len(pending) != 0 {
		t.Fatalf("another network waited on this one's bucket: %v", pending)
	}
}

// Each of the evs processes paces at the rate ÷ blocks, rounded up, so the network stays at the published rate.
func TestSpentReadRateIsSplitByBlocks(t *testing.T) {
	fixture := newReadGateFixture(t, func(settings *QuotaReadSettings) { settings.Blocks = 4 })
	networkId := connect.NewId()
	fixture.fake.SetSpentRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "transfer"})
	fixture.gate.refresh(fixture.ctx)
	pace, _ := fixture.gate.CheckRead(networkId, networkId)
	// before its limits are read: the fallback, split
	if pace.Rate() != 256*1024 {
		t.Fatalf("fallback share %d, want 1 MiB over 4", pace.Rate())
	}
	fixture.spend(networkId, 1001)
	if pace.Rate() != 251 {
		t.Fatalf("share %d of 1,001 over 4 blocks, want 251", pace.Rate())
	}
	fixture.spend(networkId, 1)
	if pace.Rate() != 1 {
		t.Fatalf("share %d of 1 over 4 blocks, want 1, never 0", pace.Rate())
	}
}

// Limits are read off the read's path, at the gate's refresh. Until they answer a bucket paces at the fallback;
// a failed read keeps the rate; a limit that is not positive is unpaced and refuses nothing; and a network that
// leaves the spent set loses its bucket and waits no more.
func TestSpentReadRateFollowsLimitsAndFailsOpen(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.fake.SetSpentRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "transfer"})
	fixture.fake.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{quotaLimitKeyUnpaidReadRate: 2000}})
	fixture.gate.refresh(fixture.ctx)
	fixture.quota.setLimitsErr(errors.New("api away"))
	pace, _ := fixture.gate.CheckRead(networkId, networkId)
	if got := fixture.quota.limitCount(); got != 0 {
		t.Fatalf("CheckRead made %d Limits calls, want none on the read's path", got)
	}
	fixture.gate.refresh(fixture.ctx)
	if pace.Rate() != 1024*1024 {
		t.Fatalf("rate %d while Limits fails, want the fallback", pace.Rate())
	}
	fixture.quota.setLimitsErr(nil)
	fixture.gate.refresh(fixture.ctx)
	if pace.Rate() != 2000 {
		t.Fatalf("rate %d, want the network's 2,000", pace.Rate())
	}
	fixture.quota.setLimitsErr(errors.New("api away"))
	fixture.gate.refresh(fixture.ctx)
	if pace.Rate() != 2000 {
		t.Fatalf("rate %d after a failed read, want the last 2,000", pace.Rate())
	}
	fixture.quota.setLimitsErr(nil)
	for _, unusable := range []int64{0, -1} {
		fixture.spend(networkId, unusable)
		if pace.Rate() != 0 {
			t.Fatalf("rate %d for a limit of %d, want unpaced", pace.Rate(), unusable)
		}
		if err := pace.Wait(fixture.ctx, 64*1024*1024); err != nil {
			t.Fatal(err)
		}
		if again, refusal := fixture.gate.CheckRead(networkId, networkId); again == nil || refusal != nil {
			t.Fatalf("a limit of %d refused a spent network's own read: %+v", unusable, refusal)
		}
	}
	// a slow rate, drained, then the network has a balance again
	fixture.spend(networkId, 10)
	if err := pace.Wait(fixture.ctx, 10); err != nil {
		t.Fatal(err)
	}
	fixture.fake.SetSpentRefusal(networkId, nil)
	fixture.gate.refresh(fixture.ctx)
	if got := len(fixture.gate.reads.networkIdBuckets); got != 0 {
		t.Fatalf("%d buckets once no network is spent", got)
	}
	if err := pace.Wait(fixture.ctx, 64*1024*1024); err != nil {
		t.Fatal(err)
	}
	if pending := fixture.clock.PendingTimers(); len(pending) != 0 {
		t.Fatalf("a network no longer spent still waits: %v", pending)
	}
	if again, refusal := fixture.gate.CheckRead(networkId, connect.NewId()); again != nil || refusal != nil {
		t.Fatalf("a network no longer spent: pace %v, refusal %+v", again, refusal)
	}
}

// One refresh reads at most its bound of networks' limits, the least recently read first, so every reading
// network's rate is read in turn.
func TestSpentReadRefreshIsBounded(t *testing.T) {
	fixture := newReadGateFixture(t, func(settings *QuotaReadSettings) { settings.RefreshNetworkMaxCount = 2 })
	networkIds := []connect.Id{}
	for range 5 {
		networkId := connect.NewId()
		networkIds = append(networkIds, networkId)
		fixture.fake.SetSpentRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "transfer"})
		fixture.fake.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{quotaLimitKeyUnpaidReadRate: 500}})
	}
	fixture.gate.refresh(fixture.ctx)
	paces := []*QuotaReadPace{}
	for _, networkId := range networkIds {
		pace, _ := fixture.gate.CheckRead(networkId, networkId)
		paces = append(paces, pace)
	}
	for pass := 1; pass <= 3; pass += 1 {
		fixture.clock.Advance(5 * time.Second)
		fixture.gate.refresh(fixture.ctx)
		if got := fixture.quota.limitCount(); got != min(2*pass, 6) {
			t.Fatalf("pass %d: %d Limits calls, want 2 a pass", pass, got)
		}
	}
	for i, pace := range paces {
		if pace.Rate() != 500 {
			t.Fatalf("network %d: rate %d after three passes, want its 500", i, pace.Rate())
		}
	}
	for networkId, count := range fixture.quota.networkIdLimitCounts {
		if 2 < count {
			t.Fatalf("network %s read %d times in three passes of two", networkId, count)
		}
	}
}

// A client that leaves ends the wait and the write, with what was sent before it.
func TestSpentReadWaitEndsWithItsRequest(t *testing.T) {
	fixture := newReadGateFixture(t, nil)
	networkId := connect.NewId()
	fixture.spend(networkId, 1000)
	pace := fixture.ownPace(networkId)
	recorder := &pacedRecorder{clock: fixture.clock, header: http.Header{}}
	requestCtx, cancel := context.WithCancel(fixture.ctx)
	defer cancel()
	writer := newQuotaPacedWriter(requestCtx, recorder, pace)
	done := make(chan struct{})
	var written int
	var writeErr error
	go func() {
		defer close(done)
		written, writeErr = writer.Write(make([]byte, 3000))
	}()
	if err := fixture.clock.AwaitTimers(fixture.ctx, 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if written != 1000 || !errors.Is(writeErr, context.Canceled) {
		t.Fatalf("wrote %d (%v), want the first chunk and the context's end", written, writeErr)
	}
}

// The network spent, and at its storage limit too, as the upload fixture's gate reads it.
func (self *uploadFixture) spend(rate int64) {
	self.host.Quota.SetSpentRefusal(self.networkId, &sidecar.QuotaRefusal{LimitKey: "transfer", Upgrade: true})
	self.host.Quota.SetStorageRefusal(self.networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1, Used: 1, Upgrade: true})
	self.host.Quota.SetLimits(self.networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{quotaLimitKeyUnpaidReadRate: rate}})
	self.gate.refresh(self.ctx)
}

// The reader's token: r on the fixture's repo.
func (self *uploadFixture) readerToken() string {
	return self.token(self.reader, repoScope(self.repoId, "r"))
}

// One read route of the fixture's repo by its reader.
func (self *uploadFixture) readRoute(method string, suffix string, body proto.Message) *httptest.ResponseRecorder {
	self.t.Helper()
	var bodyBytes []byte
	if body != nil {
		var err error
		if bodyBytes, err = proto.Marshal(body); err != nil {
			self.t.Fatal(err)
		}
	}
	return self.serve(method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+suffix, self.readerToken(), bodyBytes)
}

// FS-47's "reads work": spent and at the exact storage limit, every read route of the network's own repo
// answers, while a plain upload is refused; another network's repo is refused with upgrade, and is read again
// once the network is no longer spent.
func TestReadsWorkWhileSpentAndAtTheStorageLimit(t *testing.T) {
	fixture := newUploadFixture(t)
	fixture.spend(1024 * 1024)
	// each reply is well within the bucket, so each answers at once, with no wait on the fake clock
	if recorder := fixture.readRoute(http.MethodGet, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("GET repo while spent: %d", recorder.Code)
	}
	if recorder := fixture.readRoute(http.MethodGet, "/refs", nil); recorder.Code != http.StatusOK {
		t.Fatalf("GET refs while spent: %d", recorder.Code)
	}
	refId := testId("spent ref")
	recorder := fixture.readRoute(http.MethodPost, "/read", &protocol.EvsReadRequest{RefId: refId.Bytes()})
	if recorder.Code != http.StatusOK {
		t.Fatalf("read while spent: %d", recorder.Code)
	}
	if reply := decodeReadFrames(t, recorder.Body.Bytes()); !reply.ended || reply.head == nil {
		t.Fatalf("read while spent: %+v", reply)
	}
	if got := len(fixture.gate.reads.networkIdBuckets); got != 1 {
		t.Fatalf("%d buckets for one spent network", got)
	}
	segment := testSegment(fixture.repoId, 4096, 3)
	paymentStatus, _ := sidecar.EvsRefusalStatus(protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", segment, sha256.Sum256(segment), false), paymentStatus, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)

	// the repo is another network's: not read at all
	fixture.auth.setRepo(fixture.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: testId("network-b")})
	for _, route := range []struct {
		method string
		suffix string
		body   proto.Message
	}{
		{method: http.MethodGet},
		{method: http.MethodGet, suffix: "/refs"},
		{method: http.MethodGet, suffix: "/log?ref=" + sidecar.EvsKeyId(refId) + "&since=1"},
		{method: http.MethodPost, suffix: "/read", body: &protocol.EvsReadRequest{RefId: refId.Bytes()}},
	} {
		recorder := fixture.readRoute(route.method, route.suffix, route.body)
		requireRefusal(t, recorder, paymentStatus, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
		if quota := refusalOf(t, recorder).GetQuota(); quota.GetLimitKey() != "transfer" || !quota.GetUpgrade() {
			t.Fatalf("%s %s: quota %v", route.method, route.suffix, quota)
		}
	}
	// a repo the caller's projection does not hold is not the caller's
	func() {
		fixture.auth.stateLock.Lock()
		defer fixture.auth.stateLock.Unlock()
		delete(fixture.auth.repoFacts, fixture.repoId)
	}()
	requireRefusal(t, fixture.readRoute(http.MethodGet, "", nil), paymentStatus, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	// a state that is not loaded answers 503, never a read
	fixture.auth.stateLock.Lock()
	fixture.auth.unloaded = true
	fixture.auth.stateLock.Unlock()
	requireRefusal(t, fixture.readRoute(http.MethodGet, "", nil), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.auth.stateLock.Lock()
	fixture.auth.unloaded = false
	fixture.auth.stateLock.Unlock()

	// with a balance again, the same read of another network's repo is the guard's alone to judge
	fixture.auth.setRepo(fixture.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: testId("network-b")})
	fixture.host.Quota.SetSpentRefusal(fixture.networkId, nil)
	fixture.gate.refresh(fixture.ctx)
	if recorder := fixture.readRoute(http.MethodGet, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("GET repo once unspent: %d", recorder.Code)
	}
	if got := len(fixture.gate.reads.networkIdBuckets); got != 0 {
		t.Fatalf("%d buckets once unspent", got)
	}
}

// A 3 MiB segment read by a spent network at 1 MiB a second: the reply is paced at its writer, takes the time
// the rate asks, never runs ahead of the bucket and the rate, and its frames still parse to the segment's bytes.
// The unpaid bytes are still counted to the caller.
func TestSpentReadStreamsALargeFramedReplyAtTheRate(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 3*1024*1024, 0x21)
	for i := 64; i < len(segment); i += 1 {
		segment[i] = byte(i * 31)
	}
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	if err := fixture.usage.Drain(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	uploadTransfer := fixture.host.Quota.TransferUsed(fixture.networkId, sidecar.QuotaMeterEvs)

	rate := int64(1024 * 1024)
	fixture.spend(rate)
	// the first read makes the bucket, and the refresh after it reads the network's rate
	if recorder := fixture.readRoute(http.MethodGet, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("GET repo: %d", recorder.Code)
	}
	fixture.gate.refresh(fixture.ctx)
	if err := fixture.usage.Drain(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	priorTransfer := fixture.host.Quota.TransferUsed(fixture.networkId, sidecar.QuotaMeterEvs)
	if priorTransfer <= uploadTransfer {
		t.Fatal("a spent network's read was not counted")
	}
	// idle for a while, so the bucket is full: one second's worth
	fixture.clock.Advance(10 * time.Second)

	bodyBytes, err := proto.Marshal(&protocol.EvsReadRequest{
		RefId:  testId("spent ref").Bytes(),
		Ranges: []*protocol.EvsReadRange{{SegmentId: segmentId[:], Offset: 0, Length: uint32(len(segment))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(fixture.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.repoId)+"/read", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+fixture.readerToken())
	recorder := httptest.NewRecorder()
	start := fixture.clock.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.engine.Handler().ServeHTTP(recorder, request)
	}()
	// each wait is one chunk's, 62.5 ms at this rate: move from one to the next, and to no other timer
	chunkTimeout := time.Duration(DefaultQuotaReadSettings().ChunkByteCount) * time.Second / time.Duration(rate)
	deadline := time.After(60 * time.Second)
	for streaming := true; streaming; {
		pending, added := fixture.clock.WatchTimers()
		if 0 < len(pending) && !pending[0].After(fixture.clock.Now().Add(chunkTimeout)) {
			fixture.clock.AdvanceTo(pending[0])
			continue
		}
		select {
		case <-done:
			streaming = false
		case <-added:
		case <-deadline:
			t.Fatal("the paced read never finished")
		}
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("read: %d", recorder.Code)
	}
	replyByteCount := int64(recorder.Body.Len())
	reply := decodeReadFrames(t, recorder.Body.Bytes())
	if !reply.ended || reply.head == nil {
		t.Fatalf("the paced reply does not end as a read's: %+v", reply.head)
	}
	read := []byte{}
	for _, object := range reply.objects {
		if object.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT || object.GetMissing() || int(object.GetOffset()) != len(read) {
			t.Fatalf("object kind %s missing %t at %d, with %d read", object.GetKind(), object.GetMissing(), object.GetOffset(), len(read))
		}
		read = append(read, object.GetBody()...)
	}
	if !bytes.Equal(read, segment) {
		t.Fatalf("the paced frames hold %d bytes that are not the segment's %d", len(read), len(segment))
	}
	// within one bucket: no more than a second's worth ahead of the rate, and no slower than a chunk behind it
	elapsed := fixture.clock.Now().Sub(start)
	if allowed := rate + rate*elapsed.Nanoseconds()/int64(time.Second); allowed < replyByteCount {
		t.Fatalf("%d bytes in %s, past the bucket and the rate's %d", replyByteCount, elapsed, allowed)
	}
	if want := time.Duration(replyByteCount-rate) * time.Second / time.Duration(rate); elapsed < want || want+2*chunkTimeout < elapsed {
		t.Fatalf("%d bytes took %s, want about %s", replyByteCount, elapsed, want)
	}
	// unpaid, and counted all the same: api finds no balance for them (reading 5)
	if err := fixture.usage.Drain(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if got := fixture.host.Quota.TransferUsed(fixture.networkId, sidecar.QuotaMeterEvs) - priorTransfer; got != int64(len(bodyBytes))+replyByteCount {
		t.Fatalf("transfer %d, want the request's %d and the reply's %d", got, len(bodyBytes), replyByteCount)
	}
}

// An unspent network's large read is not paced: it finishes with the clock standing still.
func TestUnspentReadIsNotPaced(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 3*1024*1024, 0x22)
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	// another network is spent, and this one only at its storage limit
	fixture.host.Quota.SetSpentRefusal(connect.Id(testId("network-b")), &sidecar.QuotaRefusal{LimitKey: "transfer"})
	fixture.host.Quota.SetStorageRefusal(fixture.networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1, Used: 1, Upgrade: true})
	fixture.gate.refresh(fixture.ctx)
	start := fixture.clock.Now()
	recorder := fixture.readRoute(http.MethodPost, "/read", &protocol.EvsReadRequest{
		RefId:  testId("unspent ref").Bytes(),
		Ranges: []*protocol.EvsReadRange{{SegmentId: segmentId[:], Offset: 0, Length: uint32(len(segment))}},
	})
	if recorder.Code != http.StatusOK || recorder.Body.Len() < len(segment) {
		t.Fatalf("read: %d, %d bytes", recorder.Code, recorder.Body.Len())
	}
	if !fixture.clock.Now().Equal(start) {
		t.Fatal("an unspent read waited")
	}
	if got := len(fixture.gate.reads.networkIdBuckets); got != 0 {
		t.Fatalf("%d buckets for an unspent network", got)
	}
}

// A paced reply past 60 s is a stream, so rev/ is read again each minute (§11.8): a token still good streams
// on, and one a rev/ object voids ends the stream short of its last frame.
func TestSpentReadPastAMinuteRereadsRevocation(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 3*1024*1024, 0x23)
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	// 16 KiB a second: the read would take over three minutes
	rate := int64(16 * 1024)
	fixture.spend(rate)
	if recorder := fixture.readRoute(http.MethodGet, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("GET repo: %d", recorder.Code)
	}
	fixture.gate.refresh(fixture.ctx)
	revocationCount := func() int {
		fixture.auth.stateLock.Lock()
		defer fixture.auth.stateLock.Unlock()
		return fixture.auth.revocationCount
	}
	priorCount := revocationCount()
	bodyBytes, err := proto.Marshal(&protocol.EvsReadRequest{
		RefId:  testId("long ref").Bytes(),
		Ranges: []*protocol.EvsReadRange{{SegmentId: segmentId[:], Offset: 0, Length: uint32(len(segment))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(fixture.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.repoId)+"/read", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+fixture.readerToken())
	recorder := httptest.NewRecorder()
	start := fixture.clock.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.engine.Handler().ServeHTTP(recorder, request)
	}()
	// each wait is one second, a bucket's worth: steps from wait to wait until the clock reaches until, or the
	// handler returns
	deadline := time.After(60 * time.Second)
	streamUntil := func(until time.Time) bool {
		for {
			pending, added := fixture.clock.WatchTimers()
			if 0 < len(pending) && !pending[0].After(fixture.clock.Now().Add(time.Second)) {
				if pending[0].After(until) {
					return false
				}
				fixture.clock.AdvanceTo(pending[0])
				continue
			}
			select {
			case <-done:
				return true
			case <-added:
			case <-deadline:
				t.Fatal("the paced read never reached its time")
			}
		}
	}
	if streamUntil(start.Add(50 * time.Second)) {
		t.Fatal("the read ended in its first minute")
	}
	if got := revocationCount() - priorCount; got != 0 {
		t.Fatalf("rev/ read %d times in a stream's first minute", got)
	}
	if streamUntil(start.Add(100 * time.Second)) {
		t.Fatal("a stream whose token still holds ended at a minute")
	}
	if got := revocationCount() - priorCount; got != 1 {
		t.Fatalf("rev/ read %d times by 100 s, want once at a minute", got)
	}
	fixture.auth.stateLock.Lock()
	fixture.auth.revokedSidecarIds[fixture.reader] = true
	fixture.auth.stateLock.Unlock()
	if !streamUntil(start.Add(130 * time.Second)) {
		t.Fatal("a voided token's stream ran past its second minute")
	}
	if elapsed := fixture.clock.Now().Sub(start); elapsed < 119*time.Second {
		t.Fatalf("the stream ended at %s, before rev/ was due", elapsed)
	}
	frames := sidecar.NewEvsReadFrames(bytes.NewReader(recorder.Body.Bytes()))
	for {
		frame, err := frames.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				t.Fatal("a stream cut for revocation read as a whole reply")
			}
			break
		}
		if frame.GetEnd() {
			t.Fatal("a stream cut for revocation carried its end frame")
		}
	}
}
