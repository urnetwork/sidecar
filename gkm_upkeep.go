// A sidecar's key upkeep at gkm (§10.5's readerkey row, §10.6's KeyPackages and acks, D-KEYS-25, D-KEYS-26): what
// every reader keeps current whatever else it does, a read_only device too, all of it under r (FS-106).
//
//   - ReaderKey: a fresh X-Wing pair once the current one is 6 days old, its not_after at most 7 days after signing,
//     never an old pair signed again. The private key and the Signed are kept in the network's keychain.ur (§5.9)
//     before the upload, so a kill between the two uploads the same bytes after the restart, and a replaced or
//     lapsed private key stays until 30 days past its not_after, for what was sealed to it; then it is erased.
//   - Self-check (g0-recheck-0-readerkey-forgery #2, decided): once a day this sidecar reads its own ReaderKey back
//     from gkm and compares the key's digest with those it signed; an unexpired key it never signed raises
//     key_changed naming the foreign digest, an active clone's mark (§10.5), and a key of its own that is not its
//     current one is sent again.
//   - KeyPackages: a member device keeps up to 128 one-time KeyPackages and a last-resort one at gkm, a full set at
//     first and a refill at each key-packages-low hint, and renews the set and the last-resort before their 90 days
//     lapse. Agents upload only a ReaderKey, and a device recovering by its member's code uploads no KeyPackage
//     until it has anchored (§7.9's anchor, §10.8).
//   - Acks: each group this device is a leaf of, at most once a day, with its newest applied epoch, which retention
//     reads (§10.6's ack row).
//
// One pass does each of these that is due, at start, every UpkeepInterval, at every resync of the hint intake and
// at each refill a hint asks for. A step that fails waits for the next pass, and no step blocks another, but for the
// ReaderKey's upload, which is tried again between passes: no holder seals a delivery to a sidecar gkm serves no
// ReaderKey for, so until it stands rotations stage nothing to this device and an admission's first wrap passes it
// by. A network's first device makes its first upload before its state gives it a scope to present, or while the
// token exchange and gkm are still loading its network's state, and its next pass is an hour off. So an upload that
// failed is tried again ReaderKeyRetryWait later, each failed try in a row ReaderKeyRetryFactor times later up to
// ReaderKeyRetryMaxWait, a 429's Retry-After at least, until a try or a pass uploads it; the backoff goes on across
// passes, which a late ask may ask for once a LateAskInterval, and starts over only after an upload went up. One
// that found no scope to present is tried again as soon as the api's scopes give it one (GkmApi's accessScopes),
// where the api can tell. gkm's 400 and 401, which no try of the same bytes and token mends, wait for the next pass.
//
// Safe for concurrent use. Passes and the ReaderKey's tries between them run one at a time, under passLock, so one
// upload is in flight at most: on the upkeep's own goroutine, or a test's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The keychain names upkeep keeps under its namespace: one record per ReaderKey, by its key's digest, and the
// KeyPackage set's times.
const (
	gkmUpkeepReaderKeyPrefix   = "readerkey/"
	gkmUpkeepKeyPackagesRecord = "keypackages"
)

// A ReaderKey record's format: version | signed_at_ms | not_after_ms | uploaded | seed | signed, integers big
// endian, the signed bytes after their u32 length, which GkmSettings.ReaderKeySignedMaxByteCount bounds.
const (
	gkmUpkeepRecordVersion       = 1
	gkmUpkeepSeedByteCount       = 32
	gkmUpkeepRecordHeadByteCount = 1 + 8 + 8 + 1 + gkmUpkeepSeedByteCount + 4
)

// What a device is, as upkeep needs it: whether it uploads KeyPackages at all.
type GkmUpkeepRole struct {
	// Untagged and not ephemeral: it holds leaves, so it keeps KeyPackages at gkm (§10.6). An agent holds wraps
	// only, and uploads only a ReaderKey.
	MemberDevice bool
	// Recovering by its member's code and not yet anchored (§7.9's anchor): its ReaderKey goes up, its KeyPackages
	// wait.
	AwaitingAnchor bool
	// When this device last joined a group through its last-resort KeyPackage, zero for never
	// (GkmGroupClient.LastResortJoinedAt): a last-resort KeyPackage uploaded before it is replaced at the next pass,
	// since its leaf key is every Welcome's that package served (RFC 9420 §16.8; DESIGN-DETAILS 6.2.2).
	LastResortJoinedAt time.Time
}

// One group this device is a leaf of, with its newest applied epoch.
type GkmAckGroup struct {
	RepoId  Id
	GroupId Id
	Epoch   uint64
}

// What upkeep calls at gkm: GkmApi's methods, so a test fakes them.
type GkmUpkeepApi interface {
	UploadReaderKey(ctx context.Context, readerKey *bridge.Signed) error
	ReaderKey(ctx context.Context, sidecarId Id) (*bridge.Signed, error)
	UploadKeyPackages(ctx context.Context, keyPackages [][]byte) error
	Ack(ctx context.Context, repoId Id, groupId Id, epoch uint64) error
}

// What upkeep watches of an api that can tell (GkmApi): whether the client's scopes hold one a ReaderKey's upload can
// present, and a channel closed once that changes, armed at the read. An api that cannot tell leaves an upload that
// found no scope to the backoff.
type gkmUpkeepScopes interface {
	accessScopes() (held bool, changed <-chan struct{})
}

var _ gkmUpkeepScopes = (*GkmApi)(nil)

// The ReaderKey upload's retry between passes (the file header): the backoff's wait as it stands, a 429's
// Retry-After, which the next try waits out at least, and whether the last try found no scope to present. Never
// changed once set: noteReaderKeyUpload replaces it.
type gkmReaderKeyRetry struct {
	backoff    time.Duration
	retryAfter time.Duration
	noScope    bool
}

// What NewGkmUpkeep takes.
type GkmUpkeepArgs struct {
	SidecarId Id
	Api       GkmUpkeepApi
	// Signs with the identity key, for ReaderKeys (purpose reader-key).
	Sign GkmSignFunction
	// The network's keychain.ur, under upkeep's own namespace (§5.9).
	Secrets SidecarSecrets
	// MlsEngine.CreateKeyPackage. nil uploads no KeyPackage.
	CreateKeyPackage func(lastResort bool) (*MlsKeyPackage, error)
	// What this device is now. nil reads as an agent: no KeyPackage.
	Role func() GkmUpkeepRole
	// The groups this device is a leaf of now, with their newest applied epochs. nil acks none, until the group
	// sync (KEYS-M2-23) supplies it.
	AckGroups func() []*GkmAckGroup
	// The hint intake, whose key-packages-low and resyncs upkeep takes. nil takes no hint.
	Hints *GkmHints
	// key_changed. nil drops it.
	Emit SidecarEventFunction
	// nil takes the defaults.
	Settings *GkmSettings
	// nil is real time.
	Clock Clock
	Log   Logger
}

// One ReaderKey this sidecar signed, as its keychain record holds it.
type gkmReaderKeyRecord struct {
	signedAt  time.Time
	notAfter  time.Time
	uploaded  bool
	seed      []byte
	signed    []byte
	keySha256 []byte
}

// The record's bytes.
func (self *gkmReaderKeyRecord) encode() []byte {
	encoded := make([]byte, 0, gkmUpkeepRecordHeadByteCount+len(self.signed))
	encoded = append(encoded, gkmUpkeepRecordVersion)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.signedAt.UnixMilli()))
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.notAfter.UnixMilli()))
	uploaded := byte(0)
	if self.uploaded {
		uploaded = 1
	}
	encoded = append(encoded, uploaded)
	encoded = append(encoded, self.seed...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.signed)))
	return append(encoded, self.signed...)
}

// A record from its bytes, which have passed the keychain's AEAD, its Signed at most signedMaxByteCount; the decoder
// stays total all the same.
func decodeGkmReaderKeyRecord(encoded []byte, signedMaxByteCount int) (*gkmReaderKeyRecord, error) {
	if len(encoded) < gkmUpkeepRecordHeadByteCount || encoded[0] != gkmUpkeepRecordVersion {
		return nil, fmt.Errorf("%w: a ReaderKey record", ErrGkmMalformed)
	}
	signedLength := binary.BigEndian.Uint32(encoded[gkmUpkeepRecordHeadByteCount-4:])
	if uint64(max(0, signedMaxByteCount)) < uint64(signedLength) || len(encoded) != gkmUpkeepRecordHeadByteCount+int(signedLength) {
		return nil, fmt.Errorf("%w: a ReaderKey record's length", ErrGkmMalformed)
	}
	record := &gkmReaderKeyRecord{
		signedAt: time.UnixMilli(int64(binary.BigEndian.Uint64(encoded[1:9]))),
		notAfter: time.UnixMilli(int64(binary.BigEndian.Uint64(encoded[9:17]))),
		uploaded: encoded[17] == 1,
		seed:     bytes.Clone(encoded[18 : 18+gkmUpkeepSeedByteCount]),
		signed:   bytes.Clone(encoded[gkmUpkeepRecordHeadByteCount:]),
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(record.signed, signed); err != nil {
		return nil, fmt.Errorf("%w: a ReaderKey record's Signed", ErrGkmMalformed)
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: a ReaderKey record's body", ErrGkmMalformed)
	}
	keySha256 := sha256.Sum256(body.GetXwingPublicKey())
	record.keySha256 = keySha256[:]
	return record, nil
}

// The keychain name of a ReaderKey record: its key's digest in hex.
func gkmReaderKeyRecordName(keySha256 []byte) string {
	return gkmUpkeepReaderKeyPrefix + hex.EncodeToString(keySha256)
}

// The KeyPackage set's times, as its keychain record holds them: when one-time KeyPackages last went up, or when
// a refused renewal asks to be tried again less KeyPackageRenewAge, and when the last-resort one did, each zero
// before the first.
type gkmKeyPackageTimes struct {
	refilledAt   time.Time
	lastResortAt time.Time
}

// The record's bytes: two big-endian ms.
func (self *gkmKeyPackageTimes) encode() []byte {
	encoded := binary.BigEndian.AppendUint64(nil, uint64(self.refilledAt.UnixMilli()))
	return binary.BigEndian.AppendUint64(encoded, uint64(self.lastResortAt.UnixMilli()))
}

// The times from their bytes; a zero ms is never.
func decodeGkmKeyPackageTimes(encoded []byte) (*gkmKeyPackageTimes, error) {
	if len(encoded) != 16 {
		return nil, fmt.Errorf("%w: a KeyPackage record", ErrGkmMalformed)
	}
	at := func(ms uint64) time.Time {
		if ms == 0 {
			return time.Time{}
		}
		return time.UnixMilli(int64(ms))
	}
	return &gkmKeyPackageTimes{
		refilledAt:   at(binary.BigEndian.Uint64(encoded[0:8])),
		lastResortAt: at(binary.BigEndian.Uint64(encoded[8:16])),
	}, nil
}

// One sidecar's upkeep. See the file header.
type GkmUpkeep struct {
	ctx      context.Context
	cancel   context.CancelFunc
	args     *GkmUpkeepArgs
	settings *GkmSettings
	clock    Clock
	log      Logger
	done     chan struct{}

	// held across a pass and across a ReaderKey try between passes, so they run one at a time; never taken under
	// stateLock
	passLock sync.Mutex

	stateLock sync.Mutex
	// a pass asked for, by a hint or a resync
	passAsked *MonitorValue[int]
	// a refill asked for by key-packages-low
	refillAsked bool
	// when the self-check last read gkm's copy, and each group's last ack
	selfCheckedAt  time.Time
	groupIdAckedAt map[Id]time.Time
	// the ReaderKey upload's retry between passes, nil while none is due
	readerKeyRetry *gkmReaderKeyRetry
	// passes finished
	passCount *MonitorValue[int]
	// ReaderKey tries between passes finished
	readerKeyRetryCount *MonitorValue[int]
}

// A running upkeep: a pass now, then every UpkeepInterval, at each resync and at each refill a hint asks for. It
// runs until ctx ends or Close.
func NewGkmUpkeep(ctx context.Context, args *GkmUpkeepArgs) (*GkmUpkeep, error) {
	self, err := newGkmUpkeep(ctx, args)
	if err != nil {
		return nil, err
	}
	go self.run()
	return self, nil
}

// The upkeep with no loop, which NewGkmUpkeep starts and a test drives pass by pass.
func newGkmUpkeep(ctx context.Context, args *GkmUpkeepArgs) (*GkmUpkeep, error) {
	if args == nil || args.Api == nil || args.Sign == nil || args.Secrets == nil || args.SidecarId == (Id{}) {
		return nil, fmt.Errorf("%w: upkeep needs its sidecar, api, signer and keychain", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGkmSettings()
	}
	if GkmReaderKeyLifetime < settings.ReaderKeyLifetime || settings.ReaderKeyLifetime <= settings.ReaderKeyReplaceAge {
		return nil, fmt.Errorf("%w: a ReaderKey lives at most %s and is replaced before it lapses", errInvalidSettings, GkmReaderKeyLifetime)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &GkmUpkeep{
		ctx:                 cancelCtx,
		cancel:              cancel,
		args:                args,
		settings:            settings,
		clock:               clockOrReal(args.Clock),
		log:                 loggerOrDefault(args.Log),
		done:                make(chan struct{}),
		passAsked:           NewMonitorValue(0),
		groupIdAckedAt:      map[Id]time.Time{},
		passCount:           NewMonitorValue(0),
		readerKeyRetryCount: NewMonitorValue(0),
	}
	if args.Hints != nil {
		args.Hints.SetHandler(protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, func(ctx context.Context, wake *GkmHintWake) {
			self.RefillKeyPackages()
		})
		args.Hints.AddResync(func(ctx context.Context) {
			self.Refresh()
		})
	}
	return self, nil
}

// Requests an upkeep pass after auth or published key state changes.
func (self *GkmUpkeep) Refresh() {
	self.passAsked.Update(func(count int) int { return count + 1 })
}

// key-packages-low: a refill at the next pass, which this asks for now.
func (self *GkmUpkeep) RefillKeyPackages() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refillAsked = true
	}()
	self.Refresh()
}

// The loop: a pass, then wait for UpkeepInterval or an ask, trying a ReaderKey upload that failed again meanwhile as
// its retry comes due. No pass or retry starts once the upkeep has ended, an ask, a due pass or a due retry taken as it
// ended included, since either drops the lapsed ReaderKeys and mints the one due in the keychain before its upload
// meets the dead context, and an ended upkeep asks the clock for nothing.
func (self *GkmUpkeep) run() {
	defer close(self.done)
	// select takes any of its ready cases at random: a case taken as the upkeep ended reads as the end
	for self.ctx.Err() == nil {
		_, asked := self.passAsked.Get()
		self.pass(self.ctx)
		if self.ctx.Err() != nil {
			// an upkeep that ended as the pass ran asks the clock for nothing
			return
		}
		passDue := self.clock.After(self.settings.UpkeepInterval)
		for waiting := true; waiting && self.ctx.Err() == nil; {
			retryDue, scopesChanged := self.readerKeyRetryWait()
			retry := false
			select {
			case <-self.ctx.Done():
			case <-asked:
				waiting = false
			case <-passDue:
				waiting = false
			case <-retryDue:
				retry = true
			case <-scopesChanged:
				retry = true
			}
			if retry && self.ctx.Err() == nil {
				self.retryReaderKey(self.ctx)
			}
		}
	}
}

// What the loop waits on for the ReaderKey's next try between passes: retryDue fires once it is due, at the backoff's
// wait or a 429's Retry-After, whichever is longer. A try that found no scope to present, where the api can tell,
// waits on scopesChanged instead, which closes once the api's scopes change, and goes at once where a state gave it
// one since. Both nil while no try is due.
func (self *GkmUpkeep) readerKeyRetryWait() (retryDue <-chan time.Time, scopesChanged <-chan struct{}) {
	retry := func() *gkmReaderKeyRetry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.readerKeyRetry
	}()
	if retry == nil {
		return nil, nil
	}
	if scopes, ok := self.args.Api.(gkmUpkeepScopes); ok && retry.noScope {
		held, changed := scopes.accessScopes()
		if !held {
			return nil, changed
		}
		return self.clock.After(0), nil
	}
	return self.clock.After(max(retry.backoff, retry.retryAfter)), nil
}

// One try of the ReaderKey step between passes, under passLock as a pass is, so one upload is in flight at most.
func (self *GkmUpkeep) retryReaderKey(ctx context.Context) {
	func() {
		self.passLock.Lock()
		defer self.passLock.Unlock()
		err := self.keepReaderKey(ctx, self.clock.Now())
		self.noteReaderKeyUpload(ctx, err)
		if err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[gkm] ReaderKey upkeep, tried again: %v", err)
		}
	}()
	self.readerKeyRetryCount.Update(func(count int) int { return count + 1 })
}

// Sets the ReaderKey's retry from how its step ended (the file header). None once it ended well, once ctx ended, for
// gkm's 400 or 401, which no try of the same bytes and token mends, and with ReaderKeyRetryWait non-positive; else
// the backoff's next wait: ReaderKeyRetryWait after a step that ended well, ReaderKeyRetryFactor times the last wait
// after one that failed, up to ReaderKeyRetryMaxWait, so a pass does not start it over. A step that found no scope to
// present waits for the api's scopes only while the api holds none, so an api that holds one by now is tried again
// on the backoff and never in a loop with no wait.
func (self *GkmUpkeep) noteReaderKeyUpload(ctx context.Context, err error) {
	settings := self.settings
	retries := err != nil && ctx.Err() == nil && 0 < settings.ReaderKeyRetryWait &&
		!errors.Is(err, ErrGkmTokenRefused) && !IsGkmStatus(err, http.StatusBadRequest)
	retryAfter := time.Duration(0)
	if gkmError, ok := GkmErrorOf(err); ok && gkmError.Status == http.StatusTooManyRequests {
		retryAfter = gkmError.RetryAfter
	}
	noScope := errors.Is(err, ErrGkmNoScope)
	if scopes, ok := self.args.Api.(gkmUpkeepScopes); ok && noScope {
		if held, _ := scopes.accessScopes(); held {
			noScope = false
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !retries {
		self.readerKeyRetry = nil
		return
	}
	backoff := settings.ReaderKeyRetryWait
	if previous := self.readerKeyRetry; previous != nil {
		maxWait := max(settings.ReaderKeyRetryMaxWait, settings.ReaderKeyRetryWait)
		// grown in floating point and held under the cap before it is a Duration again, so no factor overflows it
		grown := float64(previous.backoff) * max(1, settings.ReaderKeyRetryFactor)
		backoff = maxWait
		if grown < float64(maxWait) {
			backoff = time.Duration(grown)
		}
	}
	self.readerKeyRetry = &gkmReaderKeyRetry{backoff: backoff, retryAfter: retryAfter, noScope: noScope}
}

// How many passes have finished, and a channel that closes at the next: what a test waits on instead of sleeping.
func (self *GkmUpkeep) Passes() (count int, changed chan struct{}) {
	return self.passCount.Get()
}

// How many ReaderKey tries between passes have finished, and a channel that closes at the next: what a test waits on
// instead of sleeping, as with Passes.
func (self *GkmUpkeep) ReaderKeyRetries() (count int, changed chan struct{}) {
	return self.readerKeyRetryCount.Get()
}

// Ends the loop and waits for it.
func (self *GkmUpkeep) Close() {
	self.cancel()
	<-self.done
}

// One pass: each step that is due, each on its own, so a failure waits for the next pass and blocks no other step.
func (self *GkmUpkeep) pass(ctx context.Context) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	defer self.passCount.Update(func(count int) int { return count + 1 })
	now := self.clock.Now()
	err := self.keepReaderKey(ctx, now)
	self.noteReaderKeyUpload(ctx, err)
	if err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm] ReaderKey upkeep: %v", err)
	}
	if err := self.selfCheck(ctx, now); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm] ReaderKey self-check: %v", err)
	}
	if err := self.keepKeyPackages(ctx, now); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm] KeyPackage upkeep: %v", err)
	}
	self.ack(ctx, now)
}

// Every ReaderKey record, oldest signing first. A record that does not decode is erased: it can open nothing.
func (self *GkmUpkeep) readerKeyRecords() ([]*gkmReaderKeyRecord, error) {
	names, err := self.args.Secrets.List(gkmUpkeepReaderKeyPrefix)
	if err != nil {
		return nil, err
	}
	records := []*gkmReaderKeyRecord{}
	for _, name := range names {
		encoded, err := self.args.Secrets.Get(name)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		record, err := decodeGkmReaderKeyRecord(encoded, self.settings.ReaderKeySignedMaxByteCount)
		clear(encoded)
		if err != nil {
			self.log.Warningf("[gkm] erasing a ReaderKey record that does not decode")
			if err := self.args.Secrets.Delete(name); err != nil {
				return nil, err
			}
			continue
		}
		records = append(records, record)
	}
	slices.SortStableFunc(records, func(a *gkmReaderKeyRecord, b *gkmReaderKeyRecord) int {
		return a.signedAt.Compare(b.signedAt)
	})
	return records, nil
}

// Erases the private seeds records read, once a step is done with them: the keychain keeps them, not memory.
func clearGkmReaderKeySeeds(records []*gkmReaderKeyRecord) {
	for _, record := range records {
		clear(record.seed)
	}
}

// Writes a record.
func (self *GkmUpkeep) putReaderKeyRecord(record *gkmReaderKeyRecord) error {
	encoded := record.encode()
	defer clear(encoded)
	return self.args.Secrets.Put(gkmReaderKeyRecordName(record.keySha256), encoded)
}

// The ReaderKey steps: erase what is 30 days past its not_after, sign a fresh pair when the current one is 6 days
// old or there is none, and upload the current one until gkm has it.
func (self *GkmUpkeep) keepReaderKey(ctx context.Context, now time.Time) error {
	records, err := self.readerKeyRecords()
	if err != nil {
		return err
	}
	defer clearGkmReaderKeySeeds(records)
	kept := []*gkmReaderKeyRecord{}
	for _, record := range records {
		if !now.Before(record.notAfter.Add(self.settings.ReaderKeyKeepAfterNotAfter)) {
			if err := self.args.Secrets.Delete(gkmReaderKeyRecordName(record.keySha256)); err != nil {
				return err
			}
			continue
		}
		kept = append(kept, record)
	}
	var current *gkmReaderKeyRecord
	if 0 < len(kept) {
		current = kept[len(kept)-1]
	}
	if current == nil || !now.Before(current.signedAt.Add(self.settings.ReaderKeyReplaceAge)) {
		current, err = self.newReaderKey(now)
		if err != nil {
			return err
		}
		defer clear(current.seed)
	}
	if current.uploaded {
		return nil
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(current.signed, signed); err != nil {
		return err
	}
	if err := self.args.Api.UploadReaderKey(ctx, signed); err != nil {
		// tried again between passes (noteReaderKeyUpload): a parked device's until its lift, a second within 24 h
		// after its day, and one that went before gkm loaded the network's state, or before a state gave this device a
		// scope, within seconds
		return err
	}
	current.uploaded = true
	if err := self.putReaderKeyRecord(current); err != nil {
		return err
	}
	// A joining device may have asked before it had a ReaderKey. Retry its config wrap now the
	// published digest and its private key are durable.
	if self.args.Hints != nil && self.args.CreateKeyPackage == nil {
		self.args.Hints.Resync()
	}
	return nil
}

// A fresh X-Wing pair signed now, valid ReaderKeyLifetime, its private key in the keychain before anything sends it
// (D-KEYS-25).
func (self *GkmUpkeep) newReaderKey(now time.Time) (*gkmReaderKeyRecord, error) {
	signed, privateKey, err := NewGkmReaderKey(self.args.SidecarId, now, now.Add(self.settings.ReaderKeyLifetime), self.args.Sign)
	if err != nil {
		return nil, err
	}
	seed, err := privateKey.Bytes()
	if err != nil {
		return nil, err
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, err
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, err
	}
	keySha256 := sha256.Sum256(body.GetXwingPublicKey())
	record := &gkmReaderKeyRecord{
		signedAt:  now,
		notAfter:  time.UnixMilli(body.GetNotAfter()),
		seed:      bytes.Clone(seed),
		signed:    signedBytes,
		keySha256: keySha256[:],
	}
	if err := self.putReaderKeyRecord(record); err != nil {
		clear(record.seed)
		return nil, err
	}
	return record, nil
}

// The digest of the newest uploaded ReaderKey that remains valid at this device's clock.
func (self *GkmUpkeep) CurrentReaderKeySha256() []byte {
	records, err := self.readerKeyRecords()
	if err != nil {
		return nil
	}
	defer clearGkmReaderKeySeeds(records)
	now := self.clock.Now()
	for i := len(records) - 1; i >= 0; i-- {
		if record := records[i]; record.uploaded && now.Before(record.notAfter) {
			return bytes.Clone(record.keySha256)
		}
	}
	return nil
}

// The private key of a ReaderKey this sidecar signed, by its key's digest, while its record is kept: what opens a
// ReaderWrap sealed to it (KEYS-M2-22). ErrGkmKeyMissing once it is erased or for a key this sidecar never signed.
func (self *GkmUpkeep) ReaderPrivateKey(keySha256 []byte) (hpke.PrivateKey, error) {
	if len(keySha256) != sha256.Size {
		return nil, fmt.Errorf("%w: a key digest of %d bytes", ErrGkmMalformed, len(keySha256))
	}
	encoded, err := self.args.Secrets.Get(gkmReaderKeyRecordName(keySha256))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, ErrGkmKeyMissing
	}
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	record, err := decodeGkmReaderKeyRecord(encoded, self.settings.ReaderKeySignedMaxByteCount)
	if err != nil {
		return nil, err
	}
	defer clear(record.seed)
	return LoadGkmReaderKey(record.seed)
}

// Once a SelfCheckInterval: reads gkm's copy of this sidecar's ReaderKey. An unexpired key it never signed raises
// key_changed with the foreign digest; a key of its own that is not the current one, or none, sends the current one
// again at the next pass.
func (self *GkmUpkeep) selfCheck(ctx context.Context, now time.Time) error {
	due := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.selfCheckedAt.IsZero() || !now.Before(self.selfCheckedAt.Add(self.settings.ReaderKeySelfCheckInterval))
	}()
	if !due {
		return nil
	}
	served, err := self.args.Api.ReaderKey(ctx, self.args.SidecarId)
	if err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.selfCheckedAt = now
	}()
	records, err := self.readerKeyRecords()
	if err != nil {
		return err
	}
	defer clearGkmReaderKeySeeds(records)
	if len(records) == 0 {
		return nil
	}
	current := records[len(records)-1]
	if served == nil {
		return self.markNotUploaded(current)
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(served.GetBody(), body); err != nil {
		return fmt.Errorf("%w: gkm serves a ReaderKey that does not parse", ErrGkmMalformed)
	}
	servedSha256 := sha256.Sum256(body.GetXwingPublicKey())
	for _, record := range records {
		if bytes.Equal(record.keySha256, servedSha256[:]) {
			if record != current {
				return self.markNotUploaded(current)
			}
			return nil
		}
	}
	if now.UnixMilli() < body.GetNotAfter() {
		// a key someone holding this sidecar's identity key signed, and not this keychain: an active clone (§10.5)
		sidecarId := self.args.SidecarId
		if self.args.Emit != nil {
			self.args.Emit(SidecarEvent{
				Kind:      SidecarEventKeyChanged,
				SidecarId: &sidecarId,
				Evidence:  [2][]byte{bytes.Clone(servedSha256[:]), nil},
			})
		}
		return nil
	}
	// a lapsed key of its own long erased: the current one goes up again
	return self.markNotUploaded(current)
}

// Has the next pass upload a record again.
func (self *GkmUpkeep) markNotUploaded(record *gkmReaderKeyRecord) error {
	if !record.uploaded {
		return nil
	}
	record.uploaded = false
	return self.putReaderKeyRecord(record)
}

// The KeyPackage steps, for a member device that is not waiting to anchor. One-time KeyPackages go up as a full set
// at first and once every one uploaded has lapsed, KeyPackageRenewAge after the last upload, since gkm's
// key-packages-low hints come only with claims; at a hint's ask, what brings gkm back to the full count. A new
// last-resort goes up KeyPackageLastResortRenewAge after the last, well inside its 90 days, so one is always valid.
// gkm refuses one-time KeyPackages past its count with 429: a hint's refill then waits for the next hint, a
// renewal is tried again KeyPackageRetryInterval later, and a last-resort due with it goes up alone.
func (self *GkmUpkeep) keepKeyPackages(ctx context.Context, now time.Time) error {
	refill := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		asked := self.refillAsked
		self.refillAsked = false
		return asked
	}()
	if self.args.CreateKeyPackage == nil || self.args.Role == nil {
		return nil
	}
	role := self.args.Role()
	if !role.MemberDevice || role.AwaitingAnchor {
		return nil
	}
	times := &gkmKeyPackageTimes{}
	encoded, err := self.args.Secrets.Get(gkmUpkeepKeyPackagesRecord)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return err
	default:
		times, err = decodeGkmKeyPackageTimes(encoded)
		if err != nil {
			return err
		}
	}
	oneTimeCount := 0
	renewal := times.refilledAt.IsZero() || !now.Before(times.refilledAt.Add(self.settings.KeyPackageRenewAge))
	switch {
	case renewal:
		oneTimeCount = self.settings.KeyPackageCount
	case refill:
		// gkm hinted that fewer than KeyPackageLowCount remain: what brings it back to the full count
		oneTimeCount = self.settings.KeyPackageCount - self.settings.KeyPackageLowCount + 1
	}
	lastResort := times.lastResortAt.IsZero() || !now.Before(times.lastResortAt.Add(self.settings.KeyPackageLastResortRenewAge)) ||
		times.lastResortAt.Before(role.LastResortJoinedAt)
	if oneTimeCount == 0 && !lastResort {
		return nil
	}
	keyPackages := [][]byte{}
	for i := 0; i < oneTimeCount; i += 1 {
		keyPackage, err := self.args.CreateKeyPackage(false)
		if err != nil {
			return err
		}
		keyPackages = append(keyPackages, keyPackage.Encoded)
	}
	if lastResort {
		keyPackage, err := self.args.CreateKeyPackage(true)
		if err != nil {
			return err
		}
		keyPackages = append(keyPackages, keyPackage.Encoded)
	}
	err = self.args.Api.UploadKeyPackages(ctx, keyPackages)
	if IsGkmStatus(err, http.StatusTooManyRequests) && oneTimeCount != 0 {
		// gkm holds its count of one-time KeyPackages
		if renewal {
			times.refilledAt = now.Add(self.settings.KeyPackageRetryInterval - self.settings.KeyPackageRenewAge)
		}
		oneTimeCount = 0
		err = nil
		if lastResort {
			err = self.args.Api.UploadKeyPackages(ctx, keyPackages[len(keyPackages)-1:])
		}
	}
	if err != nil {
		return err
	}
	if oneTimeCount != 0 {
		times.refilledAt = now
	}
	if lastResort {
		times.lastResortAt = now
	}
	return self.args.Secrets.Put(gkmUpkeepKeyPackagesRecord, times.encode())
}

// Acks each group at most once an AckInterval with its newest applied epoch (§10.6's ack row). A failed ack is
// tried at the next pass.
func (self *GkmUpkeep) ack(ctx context.Context, now time.Time) {
	if self.args.AckGroups == nil {
		return
	}
	for _, group := range self.args.AckGroups() {
		due := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			ackedAt, ok := self.groupIdAckedAt[group.GroupId]
			return !ok || !now.Before(ackedAt.Add(self.settings.AckInterval))
		}()
		if !due {
			continue
		}
		if err := self.args.Api.Ack(ctx, group.RepoId, group.GroupId, group.Epoch); err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[gkm] an ack failed: %v", err)
			}
			continue
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.groupIdAckedAt[group.GroupId] = now
		}()
	}
}

// The namespace of keychain.ur gkm's upkeep keeps its ReaderKeys and KeyPackage times under (§5.9).
const gkmUpkeepSecretsNamespace = "gkm"

// The args a GkmApi takes from this Sidecar for the network it is enrolled in: the gkm url, SidecarApi's transport,
// ServiceToken, GrantedServiceToken and ForgetServiceToken, which drops a token gkm answered 401 so the call's one
// retry presents a new one, the clock and settings.Gkm. The caller sets the repo scopes its verified state gives
// (SetRepoScopes).
func (self *Sidecar) GkmApiArgs() (*GkmApiArgs, error) {
	if self.enrolledNetworkId() == nil || self.sidecarApi == nil {
		return nil, fmt.Errorf("%w: gkm needs an enrolled network", errInvalidSettings)
	}
	return &GkmApiArgs{
		GkmUrl:              self.settings.GkmUrl,
		Transport:           self.sidecarApi.Transport(),
		ServiceToken:        self.ServiceToken,
		GrantedServiceToken: self.GrantedServiceToken,
		ForgetServiceToken:  self.ForgetServiceToken,
		Settings:            self.settings.Gkm,
		Clock:               self.clock,
	}, nil
}

// The args GkmUpkeep takes from this Sidecar: its sidecar_id, Sign, its network's keychain under gkm's namespace,
// events, the clock, the log and settings.Gkm, with api and hints. What only MLS and the verified state know, a
// KeyPackage's making, the device's role and the groups to ack, the caller sets: KEYS-M2-22 and KEYS-M2-23 as they
// land, and until then no KeyPackage goes up and no group is acked.
func (self *Sidecar) GkmUpkeepArgs(api GkmUpkeepApi, hints *GkmHints) (*GkmUpkeepArgs, error) {
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil {
		return nil, fmt.Errorf("%w: gkm needs an enrolled network", errInvalidSettings)
	}
	return &GkmUpkeepArgs{
		SidecarId: identity.SidecarId,
		Api:       api,
		Sign:      self.Sign,
		Secrets:   self.instance.secrets(*networkId, gkmUpkeepSecretsNamespace),
		Hints:     hints,
		Emit:      self.emitEvent,
		Settings:  self.settings.Gkm,
		Clock:     self.clock,
		Log:       self.log,
	}, nil
}
