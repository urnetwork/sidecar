// A spent network's reads (QUOTA-M2-10; §20.6's Empty balance): a network with no balance left still reads its own
// repos, at evs_unpaid_read_rate, a phone's fallback download of everything included, and reads no other network's
// at all. The read path stays open on purpose: erasure, export and re-keying read before they write, so a spent
// network must always be able to. Only payload-adding writes stop while spent (§20.7), and that is CheckPush and
// CheckUpload.
//
//   - CheckRead answers from the spent set the gate already holds, Quota.OverLimit's, reread every 5 s on the
//     gate's goroutine. A network that is not spent costs one map read and nothing else: no call, no bucket and
//     no wait. A storage limit never slows or refuses a read.
//   - The rate is a token bucket per network in this process, on the gate's clock, with no shared counter on the
//     path (plan-QUOTA-small-readings reading 8): each of Blocks evs processes paces at rate ÷ Blocks, so the
//     network stays at the published rate however many serve it.
//   - The rate is the network's own limit, QuotaLimits' evs_unpaid_read_rate, read off the read path at the
//     gate's refresh for the spent networks that read here. Until that first answer, and while Limits cannot be
//     read, a bucket paces at FallbackRate, §20.4's published value. A limit that is not positive reads as
//     unpaced, as pro.yml's reader says of it: an unusable value never refuses or stalls a read (R-QUOTA-5,
//     D-QUOTA-2).
//   - Pacing is at the reply's writer: every byte is written, in order, after its wait, so a framed reply stays
//     a valid stream of frames and only arrives later. A client that leaves ends the wait and the stream.
//   - A paced reply can run past a minute, so it takes §11.8's rule for streams over 60 s: rev/ is read again
//     for the token's subjects each RevocationStreamInterval, and a voided token ends the stream short.
//   - A read of another network's repo answers the spent refusal with upgrade set, since a purchase lifts it.
//
// A bucket holds BurstDuration of its rate, so a short read is answered at once, and a bucket leaves with its
// network's place in the spent set, so the map is bounded by the spent networks reading here. Safe for
// concurrent use; no lock is held across a wait or a host call.

package evsservice

import (
	"cmp"
	"context"
	"errors"
	"math"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// §20.4's key for the rate, bytes a second, as QuotaLimits carries it.
const quotaLimitKeyUnpaidReadRate = "evs_unpaid_read_rate"

type QuotaReadSettings struct {
	// How many evs processes serve reads. Each paces a network at its rate ÷ Blocks, rounded up, so the network
	// stays at the published rate with no shared counter (reading 8). Non-positive reads as 1.
	Blocks int
	// Bytes a second, before the split by Blocks, a spent network's bucket paces at until its limits have been
	// read and while they cannot be: 1 MiB, §20.4's evs_unpaid_read_rate. Non-positive leaves such a bucket
	// unpaced.
	FallbackRate int64
	// How much of its rate a bucket holds, which is what a read takes at once after an idle stretch: 1 s.
	// Non-positive holds nothing, so every byte waits its turn.
	BurstDuration time.Duration
	// The most a paced writer sends between waits, so a large frame leaves in steps and not after one long
	// wait: 64 KiB. A bucket holding less sends at most what it holds. Non-positive reads as 1.
	ChunkByteCount int
	// The most networks whose limits one refresh reads, the least recently read first, so a refresh stays
	// bounded however many spent networks read here: 64. Non-positive reads none, leaving every bucket at
	// FallbackRate.
	RefreshNetworkMaxCount int
}

func DefaultQuotaReadSettings() *QuotaReadSettings {
	return &QuotaReadSettings{
		Blocks:                 1,
		FallbackRate:           1024 * 1024,
		BurstDuration:          1 * time.Second,
		ChunkByteCount:         64 * 1024,
		RefreshNetworkMaxCount: 64,
	}
}

// One spent network's bucket in this process.
type quotaReadBucket struct {
	// bytes a second in this process, after the split by blocks; 0 is unpaced
	rate int64
	// when Limits last answered for the network, zero until it has
	loadTime time.Time
	// when the bytes drawn so far are paid for at the rate: a draw waits until then
	paidTime time.Time
}

// The spent networks reading in this process. See the file header.
type quotaReadGate struct {
	settings *QuotaReadSettings
	clock    sidecar.Clock
	quota    sidecar.Quota

	stateLock        sync.Mutex
	networkIdBuckets map[connect.Id]*quotaReadBucket
}

func newQuotaReadGate(clock sidecar.Clock, quota sidecar.Quota, settings *QuotaReadSettings) *quotaReadGate {
	if settings == nil {
		settings = DefaultQuotaReadSettings()
	}
	return &quotaReadGate{
		settings:         settings,
		clock:            clock,
		quota:            quota,
		networkIdBuckets: map[connect.Id]*quotaReadBucket{},
	}
}

// This process's share of a network's rate: rate ÷ blocks rounded up, so a share is never zero while the rate is
// positive. A rate that is not positive is unpaced, 0.
func (self *quotaReadGate) share(rate int64) int64 {
	if rate <= 0 {
		return 0
	}
	blocks := int64(max(self.settings.Blocks, 1))
	return (rate-1)/blocks + 1
}

// The handle on the network's bucket, made full at the fallback rate when the network has none.
func (self *quotaReadGate) pace(networkId connect.Id) *QuotaReadPace {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.networkIdBuckets[networkId]; !ok {
		self.networkIdBuckets[networkId] = &quotaReadBucket{
			rate:     self.share(self.settings.FallbackRate),
			paidTime: now.Add(-self.settings.BurstDuration),
		}
	}
	return &QuotaReadPace{reads: self, networkId: networkId}
}

// How long byteCount bytes take at rate, rounded up, so a bucket never runs ahead of its rate.
func quotaReadCost(byteCount int64, rate int64) time.Duration {
	if byteCount <= (math.MaxInt64-rate)/int64(time.Second) {
		return time.Duration((byteCount*int64(time.Second) + rate - 1) / rate)
	}
	seconds := float64(byteCount) / float64(rate)
	if float64(math.MaxInt64)/float64(time.Second) <= seconds {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(seconds * float64(time.Second))
}

// Takes byteCount bytes of the network's bucket at now and returns how long their writer waits before sending
// them: zero while the bucket holds them, and zero for a network with no bucket, which is no longer spent, or
// an unpaced one.
func (self *quotaReadGate) draw(networkId connect.Id, byteCount int, now time.Time) time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	bucket, ok := self.networkIdBuckets[networkId]
	if !ok || bucket.rate <= 0 || byteCount <= 0 {
		return 0
	}
	// an idle bucket fills to its burst and no further
	paidTime := bucket.paidTime
	if full := now.Add(-self.settings.BurstDuration); paidTime.Before(full) {
		paidTime = full
	}
	bucket.paidTime = paidTime.Add(quotaReadCost(int64(byteCount), bucket.rate))
	return max(0, bucket.paidTime.Sub(now))
}

// The most one paced write sends between waits for the network: the settings' chunk, and at most what its
// bucket holds.
func (self *quotaReadGate) chunkByteCount(networkId connect.Id) int {
	chunkByteCount := max(self.settings.ChunkByteCount, 1)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	bucket, ok := self.networkIdBuckets[networkId]
	if !ok || bucket.rate <= 0 {
		return chunkByteCount
	}
	held := float64(bucket.rate) * self.settings.BurstDuration.Seconds()
	if held < float64(chunkByteCount) {
		return max(int(held), 1)
	}
	return chunkByteCount
}

// The network's rate in this process, bytes a second, 0 when it is unpaced or holds no bucket.
func (self *quotaReadGate) rate(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if bucket, ok := self.networkIdBuckets[networkId]; ok {
		return bucket.rate
	}
	return 0
}

// The gate's refresh, off every read's path: drops the bucket of each network the list no longer holds as spent,
// then reads the limits of at most RefreshNetworkMaxCount of the rest, the least recently read first. A read that
// fails keeps the bucket's rate.
func (self *quotaReadGate) refresh(ctx context.Context, overLimit *sidecar.QuotaOverLimit) {
	type candidate struct {
		networkId connect.Id
		loadTime  time.Time
	}
	candidates := []candidate{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for networkId, bucket := range self.networkIdBuckets {
			if refusal, ok := overLimit.SpentNetworkIdRefusals[networkId]; !ok || refusal == nil {
				delete(self.networkIdBuckets, networkId)
				continue
			}
			candidates = append(candidates, candidate{networkId: networkId, loadTime: bucket.loadTime})
		}
	}()
	slices.SortFunc(candidates, func(a candidate, b candidate) int {
		if c := a.loadTime.Compare(b.loadTime); c != 0 {
			return c
		}
		return cmp.Compare(a.networkId.String(), b.networkId.String())
	})
	if maxCount := max(self.settings.RefreshNetworkMaxCount, 0); maxCount < len(candidates) {
		candidates = candidates[:maxCount]
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		limits, err := self.quota.Limits(ctx, candidate.networkId)
		if err != nil || limits == nil {
			continue
		}
		rate := self.share(limits.Limits[quotaLimitKeyUnpaidReadRate])
		loadTime := self.clock.Now()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if bucket, ok := self.networkIdBuckets[candidate.networkId]; ok {
				bucket.rate = rate
				bucket.loadTime = loadTime
			}
		}()
	}
}

// A spent network's reads of its own repos in this process: what CheckRead hands the reply's writer. Every
// handle on one network draws on the one bucket, so its requests share the rate. Safe for concurrent use.
type QuotaReadPace struct {
	reads     *quotaReadGate
	networkId connect.Id
}

// Takes byteCount bytes and returns once they may be sent, or with ctx's error when it ends first. A network
// that has left the spent set, or whose rate is unpaced, never waits.
func (self *QuotaReadPace) Wait(ctx context.Context, byteCount int) error {
	timeout := self.reads.draw(self.networkId, byteCount, self.reads.clock.Now())
	if timeout <= 0 {
		return nil
	}
	select {
	case <-self.reads.clock.After(timeout):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Bytes a second the network reads at in this process, 0 when it is unpaced.
func (self *QuotaReadPace) Rate() int64 {
	return self.reads.rate(self.networkId)
}

// The most to send between two Waits.
func (self *QuotaReadPace) ChunkByteCount() int {
	return self.reads.chunkByteCount(self.networkId)
}

// The refusal the list holds for a spent network, nil while it is not spent. A storage limit is not this.
func (self *QuotaGate) spentRefusal(networkId connect.Id) *sidecar.QuotaRefusal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.overLimit == nil {
		return nil
	}
	if refusal, ok := self.overLimit.SpentNetworkIdRefusals[networkId]; ok && refusal != nil {
		copied := *refusal
		return &copied
	}
	return nil
}

// Whether the network is spent, with no balance left, as the last list read says.
func (self *QuotaGate) Spent(networkId connect.Id) bool {
	return self.spentRefusal(networkId) != nil
}

// A read by callerNetworkId, the token's network, of a repo of repoNetworkId. No I/O. A caller that is not spent
// reads anything it is authorized for: nil and nil, with no bucket made. A spent caller reads its own network's
// repos through the pace returned, and no other network's: the refusal, with upgrade set. See the file header.
func (self *QuotaGate) CheckRead(callerNetworkId connect.Id, repoNetworkId connect.Id) (*QuotaReadPace, *sidecar.QuotaRefusal) {
	refusal := self.spentRefusal(callerNetworkId)
	if refusal == nil {
		return nil, nil
	}
	if repoNetworkId != callerNetworkId {
		refusal.Upgrade = true
		return nil, refusal
	}
	return self.reads.pace(callerNetworkId), nil
}

// The guard's read check, for a repo route that does not write, once the token is authorized on the repo: an
// unspent caller passes with no further call; a spent caller's reply is paced on its own network's repo and
// refused on any other. The repo's network is what the newest verified state gives, from memory, as the segment
// route reads it; a repo the caller's projection does not hold is not the caller's. An engine given no gate knows
// no spent set and paces nothing, as a gate that has read no list does; server's evshost keeps such a block not
// ready. false once it has answered the refusal.
func (self *EvsRequest) checkRead() bool {
	uploads := self.engine.deps.Uploads
	if uploads == nil || uploads.Quota == nil {
		return true
	}
	callerNetworkId := self.Principal.NetworkId
	if !uploads.Quota.Spent(callerNetworkId) {
		return true
	}
	repoNetworkId := connect.Id{}
	facts, answer := self.engine.deps.AuthState.Repo(self.Principal, self.RepoId)
	switch answer {
	case EvsAuthAllowed:
		if facts != nil {
			repoNetworkId = connect.Id(facts.NetworkId)
		}
	case EvsAuthDenied:
		// no RepoCreate in the caller's projection: another network's repo, or none
	default:
		self.Unavailable(nil)
		return false
	}
	pace, refusal := uploads.Quota.CheckRead(callerNetworkId, repoNetworkId)
	if refusal != nil {
		self.Refuse(evsQuotaRefusalReply(refusal))
		return false
	}
	if pace != nil {
		self.Note("unpaid_read_rate")
		paced := newQuotaPacedWriter(self.Ctx, self.Writer, pace)
		paced.stillAuthorized = self.pacedStreamAuthorized
		self.Writer = paced
	}
	return true
}

// §11.8's rule for a stream over 60 s, which a paced reply can be: once the request has run
// RevocationStreamInterval, rev/ is read for the token's subjects, and again each interval. false ends the
// stream short, which the client reads as invalid and retries.
func (self *EvsRequest) pacedStreamAuthorized() bool {
	if self.Now().Sub(self.started) < self.engine.settings.RevocationStreamInterval {
		return true
	}
	if self.RecheckRevocation() {
		return true
	}
	self.Note("stream_revoked")
	return false
}

// A paced reply stopped because its token no longer holds: a rev/ object voids it, or evs cannot tell.
var errEvsPacedStreamUnauthorized = errors.New("evs paced stream no longer authorized")

// A reply's writer held to a pace: each Write goes out in chunks, each after its wait, and is flushed as it
// goes, so the client receives at the rate and no byte is dropped or reordered. Lives on its request's
// goroutine.
type quotaPacedWriter struct {
	http.ResponseWriter
	ctx     context.Context
	pace    *QuotaReadPace
	flusher http.Flusher
	// Asked before each chunk: false ends the write. nil asks nothing.
	stillAuthorized func() bool
}

func newQuotaPacedWriter(ctx context.Context, writer http.ResponseWriter, pace *QuotaReadPace) *quotaPacedWriter {
	paced := &quotaPacedWriter{ResponseWriter: writer, ctx: ctx, pace: pace}
	paced.flusher, _ = writer.(http.Flusher)
	return paced
}

// Writes all of body or returns the error that stopped it: the writer's, the request's context ending in a
// wait, or the token no longer holding.
func (self *quotaPacedWriter) Write(body []byte) (int, error) {
	writtenByteCount := 0
	for writtenByteCount < len(body) {
		if self.stillAuthorized != nil && !self.stillAuthorized() {
			return writtenByteCount, errEvsPacedStreamUnauthorized
		}
		chunk := body[writtenByteCount:min(len(body), writtenByteCount+self.pace.ChunkByteCount())]
		if err := self.pace.Wait(self.ctx, len(chunk)); err != nil {
			return writtenByteCount, err
		}
		n, err := self.ResponseWriter.Write(chunk)
		writtenByteCount += n
		if err != nil {
			return writtenByteCount, err
		}
		if writtenByteCount < len(body) && self.flusher != nil {
			// what the wait paid for leaves now, not with the rest of the frame
			self.flusher.Flush()
		}
	}
	return writtenByteCount, nil
}

// The read stream flushes each frame.
func (self *quotaPacedWriter) Flush() {
	if self.flusher != nil {
		self.flusher.Flush()
	}
}

// For http.ResponseController.
func (self *quotaPacedWriter) Unwrap() http.ResponseWriter {
	return self.ResponseWriter
}
