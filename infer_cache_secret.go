//go:build !ios_extension && !sidecar_http

// The member's cache secret, S_m (DESIGN-COMPUTE §6.6, Q-INFER-3, R2-12, D-INFER-8, R-INFER-5; INFER-M12-02): 32 random
// bytes every cache salt of the member's derives from (infer_cache_salt.go), so a prompt prefix another member shares
// never matches the member's in a provider's shared cache while the member's runs on each of their devices keep their
// hits. It derives from nothing another sidecar holds: not K_sock, which every admitted sidecar reads (DESIGN §2.6), nor
// a member id, which a Team's directory shows.
//
// Where it is kept: the versionless cache.json (InferCacheFile) of one owner-bound secret repo of the member's, made
// with no label or display name in the config repo, so other members' devices, tagged sidecars and other members'
// enclaves see one more secret repo id and nothing of it. Inside, S_m is sealed again, once per device, to the
// ReaderKey of each device on the repo's consented list (owner decision 702) through CONN's inner seal
// (InferCacheSealer, §25.6): the member's consented devices, their agents' enclaves' incarnations among them (CO-43),
// a read_only device too; never a Team's audit reader that holds the repo, a tagged sidecar or another member's device,
// so none of them opens a copy or computes a salt of the member's. ur and the apps share the repo with no one.
//
// A sync, at most once a CacheSecretSyncInterval and at a remote call that finds no secret held:
//
//  1. reads cache.json from each of the member's own secret repos in the verified state; where two stand, the lower
//     repo id stands and a device that may draw deletes the other, so two devices that raced the creation keep one;
//  2. with none standing, the member's first untagged device to make a remote call creates the repo, draws S_m and
//     seals it to every device on the consented list by a create-only write, then reads again, so a racing creation
//     whose id is lower wins and this one's repo is deleted;
//  3. with one standing, where a device that held a copy has left the consented list (a revocation, an enclave
//     incarnation's stop or loss, a withdrawn consent), draws a new S_m sealed to the devices that remain, by a write
//     held to the version read (EXACT_HEAD), so two that race keep one and the former device keeps only the old
//     secret, from which the new one cannot be derived;
//  4. else opens the copy sealed to this device, seals a copy to each listed device that has none, answers asks,
//     and re-seals its own copy to its newest ReaderKey, by a write held to the version read;
//  5. a device that finds no copy of its own asks for one in cache.json and salts meanwhile with a secret of its own,
//     at the cost of cache misses until a device that holds S_m seals it one.
//
// Who draws: a tagged sidecar, such as a CI runner or a cloud agent's sidecar, is consented for no member, so it never
// takes a member's secret: it draws its own 32 bytes at its first remote call and keeps them in its sealed state
// (infer-cache/own), its runs sharing cache hits with each other and with no one else, an ephemeral one starting cold
// each time. An agents' enclave never creates the repo or draws or rotates S_m, since it may delete no repo it did not
// create as a general one (§16.6): it opens the copy sealed to it, asks for one where it has none, and its remote calls
// wait for it (CacheSecretEnclaveWaitTimeout). A read_only device writes nothing: it opens its copy, and salts with a
// secret of its own until one is sealed to it.
//
// Until CONN's inner seal registers (CONN-M13-01's DeviceSealedSecret, through registerInferCacheSealer), no copy can
// be sealed, so no device creates the repo or writes one: each salts with a secret of its own, which costs cache misses
// across a member's devices and exposes nothing. A network outside format 2's gate cannot keep cache.json versionless,
// and its devices salt with their own secrets the same way.
//
// S_m lives only in this process, never in an agent, a tool result, a record entry, a log, a crash report or the
// agents' container: Secret answers an InferCacheKey, which derives salts and shows nothing of the bytes it holds, and
// no error or log line here names them. testHookSecret runs at every draw and open.
//
// Safe for concurrent use: syncLock makes one sync at a time across its I/O, and stateLock guards what syncs found.
// Order: syncLock, then stateLock, which is never held across I/O.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The format's names and sizes: identifiers and cryptographic constants, which change only with the format.
const (
	// The one file of the cache repo.
	inferCacheFileName = "cache.json"
	// cache.json's format.
	inferCacheFileFormat uint32 = 1
	// S_m, and a device's or a tagged sidecar's own: 32 random bytes, HKDF-SHA256's key.
	inferCacheSecretByteCount = 32
	// A draw's id, 16 random bytes in hex.
	inferCacheDrawIdByteCount = 16
	// What a copy's seal names beside the repo, followed by the draw's id, so a copy moved from another draw or repo
	// does not open.
	inferCacheSealPurposePrefix = "urnetwork-sidecar-v1/compute-cache-secret/"
	// The sealed local state's directory, class and file of this device's own secret.
	inferCacheStoreDirectory = "infer-cache"
	inferCacheStoreClass     = "infer-cache"
	inferCacheOwnFileName    = "own"
	// The component's name (compute_sidecar.go).
	inferCacheSecretComponentName = "infer-cache"
)

var (
	// No cache secret can be had: this sidecar holds no identity or admission, or its sealed state is locked, so no
	// remote call can be salted.
	ErrInferCacheSecretUnavailable = errors.New("no cache secret")
	// An agents' enclave holds no copy of its member's secret yet: its remote calls wait for a sponsor's device to seal
	// it one, and past CacheSecretEnclaveWaitTimeout are refused.
	ErrInferCacheSecretPending = errors.New("the member's cache secret is not sealed to this enclave yet")
	// cache.json moved between this device's read and its write.
	errInferCacheConflict = errors.New("cache.json moved since it was read")
	// cache.json that does not hold to its format.
	errInferCacheFile = errors.New("cache.json refused")
	// A network outside format 2's gate, where cache.json cannot be versionless.
	errInferCacheVersionless = errors.New("cache.json is versionless, which this network's evs does not take yet")
)

// cache.json, version 1: the member's secret as of one draw, sealed once per device, and the asks of devices that hold
// no copy. Clear fields name devices by sidecar id alone, which every admitted sidecar's config reads anyway.
type InferCacheFile struct {
	// inferCacheFileFormat.
	Format uint32 `json:"format"`
	// The draw's id, 32 hex: new at every draw, so a device tells a new secret from the one it holds.
	DrawId string `json:"draw_id"`
	// The device that drew it, and when, in Unix milliseconds by its clock.
	DrawnBy   Id    `json:"drawn_by"`
	DrawnAtMs int64 `json:"drawn_at_ms"`
	// One copy per device on the consented list, each sealed to that device's ReaderKey.
	Copies []*InferCacheCopy `json:"copies"`
	// Devices on the list that hold no copy that opens, each asking for one.
	Asks []*InferCacheAsk `json:"asks"`
}

// One device's copy of the secret.
type InferCacheCopy struct {
	SidecarId Id `json:"sidecar_id"`
	// The SHA-256 of the ReaderKey it is sealed to, 64 hex.
	ReaderKeySha256 string `json:"reader_key_sha256"`
	// The seal: HPKE-XWing to that key (§25.6), opaque here.
	Sealed []byte `json:"sealed"`
}

// One device's ask for a copy.
type InferCacheAsk struct {
	SidecarId Id `json:"sidecar_id"`
	// The SHA-256 of its newest ReaderKey, 64 hex, which the copy it asks for is to be sealed to.
	ReaderKeySha256 string `json:"reader_key_sha256"`
	// When it asked, in Unix milliseconds by its clock.
	AskedAtMs int64 `json:"asked_at_ms"`
}

// CONN's inner seal (§25.6, Q-CONN-15; CONN-M13-01's DeviceSealedSecret, the one mechanism for every owner-bound
// secret repo that holds a credential): a value sealed again inside the repo, HPKE-XWing (DESIGN §10.5) to one device's
// newest ReaderKey from gkm, its info naming the repo and the purpose and its aad the ReaderKey's SHA-256. Safe for
// concurrent use.
type InferCacheSealer interface {
	// The SHA-256 of this device's newest ReaderKey, which its own copy is to be sealed to.
	ReaderKeySha256(ctx context.Context) ([]byte, error)
	// value sealed to recipient's newest ReaderKey: the copy, naming the recipient and that key's SHA-256. An error
	// where the recipient holds no ReaderKey a seal may go to.
	Seal(ctx context.Context, repoId Id, purpose string, recipient Id, value []byte) (*InferCacheCopy, error)
	// The value of a copy sealed to this device under repoId and purpose: an error where it names another device, a
	// ReaderKey this device no longer holds, or does not open.
	Open(ctx context.Context, repoId Id, purpose string, copy *InferCacheCopy) ([]byte, error)
}

// What builds the inner seal for one Sidecar: CONN's, registered from its own file.
type InferCacheSealerConstructor func(sidecar *Sidecar) (InferCacheSealer, error)

// The inner seal's registration, nil until CONN's lands.
var inferCacheSealerRegistration InferCacheSealerConstructor

// Registers the inner seal, from an init function in its own file. A second registration, or a nil constructor, is a
// build error, which panics.
func registerInferCacheSealer(construct InferCacheSealerConstructor) {
	if construct == nil || inferCacheSealerRegistration != nil {
		panic("the cache secret's inner seal registered twice or without a constructor")
	}
	inferCacheSealerRegistration = construct
}

// What the cache secret is, for this sidecar, as the verified state admits it.
type inferCacheSelf struct {
	SidecarId Id
	// The member its untagged admission names; nil for a tagged sidecar, which takes no member's secret.
	MemberId *Id
	// Writes nothing (SIDECAR_CAPABILITY_READ_ONLY).
	ReadOnly bool
	// An agents' enclave's incarnation (SIDECAR_CAPABILITY_ENCLAVE): never creates, draws or rotates.
	Enclave bool
}

// What the cache secret reads and writes of its Sidecar: the verified state, the member's repos in evs, and its own
// sealed state. A test fakes it. Safe for concurrent use.
type inferCacheHost interface {
	// This sidecar as the verified state admits it; an error before it holds an identity and an admission.
	self() (*inferCacheSelf, error)
	// The devices on the consented list of memberId's owner-bound repos, sorted: each consented for the member, its
	// agents' enclaves' incarnations among them; never a tagged sidecar or another member's device.
	consentedDevices(memberId Id) ([]Id, error)
	// memberId's own secret repos in the verified state, deleted ones left out, sorted by id.
	secretRepos(memberId Id) ([]Id, error)
	// cache.json of repoId, at most maxByteCount bytes, and its path version; nil and 0 where none stands. A file
	// longer than maxByteCount answers errInferCacheFile.
	readCache(ctx context.Context, repoId Id, maxByteCount int) ([]byte, uint64, error)
	// Writes cache.json held to ifVersion, 0 for a create-only write: errInferCacheConflict where another write
	// landed between.
	writeCache(ctx context.Context, repoId Id, content []byte, ifVersion uint64) error
	// A new owner-bound secret repo of memberId's, with no label or display name.
	createRepo(ctx context.Context, memberId Id) (Id, error)
	deleteRepo(ctx context.Context, repoId Id) error
	// This device's own secret from its sealed state; nil where none was drawn.
	loadOwn() ([]byte, error)
	storeOwn(secret []byte) error
}

// The salts' source, which a call's record and badge may say (never the bytes).
type InferCacheSecretSource string

const (
	// The member's S_m, the same on each of their devices and enclaves.
	InferCacheSecretMember InferCacheSecretSource = "member"
	// This device's own: a tagged sidecar's, or a member device's while it holds no copy of S_m.
	InferCacheSecretOwn InferCacheSecretSource = "own"
)

// A cache secret held for one call's salts. It shows nothing of its bytes: String and its JSON name only its source,
// so a key in a log line, an error or a tool's answer leaks none of it. Immutable, safe for concurrent use.
type InferCacheKey struct {
	secret []byte
	source InferCacheSecretSource
	random io.Reader
}

// Whose secret it is.
func (self *InferCacheKey) Source() InferCacheSecretSource {
	return self.source
}

// The TEE path's salt line for a call to the provider of slug providerId (inferCacheSaltTee).
func (self *InferCacheKey) TeeSaltLine(providerId string) (string, error) {
	return inferCacheSaltTee(self.secret, providerId)
}

// The direct path's salt line for a call recorded in run or session scopeId, a fresh salt where nil
// (inferCacheSaltDirect).
func (self *InferCacheKey) DirectSaltLine(scopeId *Id) (string, error) {
	return inferCacheSaltDirect(self.secret, scopeId, self.random)
}

// Its source alone.
func (self *InferCacheKey) String() string {
	return "cache secret (" + string(self.source) + ")"
}

// Its source alone, for %#v.
func (self *InferCacheKey) GoString() string {
	return self.String()
}

// Its source alone: a key never marshals its bytes.
func (self *InferCacheKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"source": string(self.source)})
}

// What a sync left: the member's secret this device opened, its draw, and when; a nil secret where it opened none.
type inferCacheHeld struct {
	secret   []byte
	drawId   string
	syncedAt time.Time
}

// What builds an InferCacheSecret.
type inferCacheSecretArgs struct {
	Host inferCacheHost
	// The inner seal; nil while none is registered, which leaves every device salting with its own secret.
	Sealer   InferCacheSealer
	Settings *InferSettings
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil draws from crypto/rand.
	Random io.Reader
}

// The member's cache secret on one Sidecar. See the file header.
type InferCacheSecret struct {
	host     inferCacheHost
	sealer   InferCacheSealer
	settings *InferSettings
	clock    Clock
	log      Logger
	random   io.Reader

	// one sync at a time, held across its I/O
	syncLock sync.Mutex

	stateLock sync.Mutex
	held      *inferCacheHeld
	own       []byte
}

// A cache secret over args.
func newInferCacheSecret(args *inferCacheSecretArgs) (*InferCacheSecret, error) {
	if args == nil || args.Host == nil || args.Settings == nil {
		return nil, errors.New("cache secret: a host and settings")
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	return &InferCacheSecret{
		host:     args.Host,
		sealer:   args.Sealer,
		settings: args.Settings,
		clock:    clock,
		log:      log,
		random:   random,
	}, nil
}

// The secret this device's remote calls salt with now (§6.6): the member's S_m where this device holds a copy, else its
// own. A tagged sidecar's is always its own; an agents' enclave's is always its member's, waited for where no copy is
// sealed to it yet (ErrInferCacheSecretPending past CacheSecretEnclaveWaitTimeout). ErrInferCacheSecretUnavailable
// where this sidecar holds no admission yet or its sealed state does not open.
func (self *InferCacheSecret) Secret(ctx context.Context) (*InferCacheKey, error) {
	me, err := self.host.self()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInferCacheSecretUnavailable, err)
	}
	if me.MemberId == nil || self.sealer == nil {
		// a tagged sidecar, or a build in which no copy can be sealed
		return self.ownKey()
	}
	held, err := self.memberSecret(ctx, me)
	if err != nil && !me.Enclave {
		// a sync that failed costs cache misses, never a call
		self.log.Warningf("[infer]the member's cache secret did not sync, so this call salts with this device's own: %s", err)
		return self.ownKey()
	}
	if held != nil {
		return &InferCacheKey{secret: held, source: InferCacheSecretMember, random: self.random}, nil
	}
	if !me.Enclave {
		return self.ownKey()
	}
	return self.enclaveWait(ctx, me, err)
}

// An enclave's wait for its copy: it reads cache.json again every CacheSecretEnclaveWaitInterval until one opens, ctx
// ends or CacheSecretEnclaveWaitTimeout passes.
func (self *InferCacheSecret) enclaveWait(ctx context.Context, me *inferCacheSelf, lastErr error) (*InferCacheKey, error) {
	if self.settings.CacheSecretEnclaveWaitTimeout <= 0 {
		return nil, self.pending(lastErr)
	}
	deadline := self.clock.After(self.settings.CacheSecretEnclaveWaitTimeout)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrInferCacheSecretPending, ctx.Err())
		case <-deadline:
			return nil, self.pending(lastErr)
		case <-self.clock.After(max(0, self.settings.CacheSecretEnclaveWaitInterval)):
		}
		self.forget()
		held, err := self.memberSecret(ctx, me)
		lastErr = err
		if held != nil {
			return &InferCacheKey{secret: held, source: InferCacheSecretMember, random: self.random}, nil
		}
	}
}

// ErrInferCacheSecretPending, with why the last sync opened none where it failed.
func (self *InferCacheSecret) pending(err error) error {
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInferCacheSecretPending, err)
	}
	return ErrInferCacheSecretPending
}

// Drops what the last sync found, so the next call syncs.
func (self *InferCacheSecret) forget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held = nil
}

// What the last sync found while it is fresh; nil past CacheSecretSyncInterval.
func (self *InferCacheSecret) heldFresh() *inferCacheHeld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.held == nil || self.settings.CacheSecretSyncInterval <= 0 {
		return nil
	}
	if self.settings.CacheSecretSyncInterval <= self.clock.Now().Sub(self.held.syncedAt) {
		return nil
	}
	return self.held
}

// The member's secret this device opens, synced where what it holds is stale; nil where it opens none.
func (self *InferCacheSecret) memberSecret(ctx context.Context, me *inferCacheSelf) ([]byte, error) {
	if held := self.heldFresh(); held != nil {
		return held.secret, nil
	}
	self.syncLock.Lock()
	defer self.syncLock.Unlock()
	// a sync that ran while this one waited answers it
	if held := self.heldFresh(); held != nil {
		return held.secret, nil
	}
	secret, drawId, err := self.sync(ctx, me)
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.held = &inferCacheHeld{secret: secret, drawId: drawId, syncedAt: self.clock.Now()}
	}()
	return secret, nil
}

// The cache repo that stands, as read.
type inferCacheStanding struct {
	repoId Id
	// nil where cache.json stands and does not hold to its format, which a device that may draw replaces
	file    *InferCacheFile
	version uint64
}

// One sync: the file header's steps, with syncLock held. Answers the member's secret this device opened and its draw,
// nil where it opened none.
func (self *InferCacheSecret) sync(ctx context.Context, me *inferCacheSelf) ([]byte, string, error) {
	memberId := *me.MemberId
	devices, err := self.host.consentedDevices(memberId)
	if err != nil {
		return nil, "", err
	}
	// a device off its own member's consented list holds no copy and seals none
	listed := slices.Contains(devices, me.SidecarId)
	mayWrite := listed && !me.ReadOnly
	mayDraw := mayWrite && !me.Enclave
	retries := max(0, self.settings.CacheSecretWriteRetryCount)
	for attempt := 0; ; attempt += 1 {
		retry := func(err error) bool {
			return errors.Is(err, errInferCacheConflict) && attempt < retries
		}
		standing, err := self.standing(ctx, memberId, mayDraw)
		if err != nil {
			return nil, "", err
		}
		if standing == nil {
			if !mayDraw {
				return nil, "", nil
			}
			if err := self.create(ctx, me, devices); err != nil {
				if retry(err) {
					continue
				}
				return nil, "", err
			}
			// read again: a racing creation of a lower id stands, and this one's repo goes
			continue
		}
		departed := standing.file == nil || slices.ContainsFunc(standing.file.Copies, func(copy *InferCacheCopy) bool {
			return !slices.Contains(devices, copy.SidecarId)
		})
		if departed && mayDraw {
			if err := self.draw(ctx, me, standing, devices); err != nil {
				if retry(err) {
					continue
				}
				return nil, "", err
			}
			continue
		}
		if standing.file == nil {
			// nothing to open until a device that may draw replaces it
			return nil, "", nil
		}
		secret := self.openCopy(ctx, me, standing)
		if mayWrite && !departed {
			if err := self.reconcile(ctx, me, standing, devices, secret); err != nil {
				if retry(err) {
					continue
				}
				// what it opened still salts this call; the next sync tries the write again
				self.log.Warningf("[infer]the cache secret's copies were not brought up to date: %s", err)
			}
		}
		return secret, standing.file.DrawId, nil
	}
}

// The member's cache repo that stands: the lowest id among their own secret repos whose cache.json stands, nil where
// none does. A device that may draw deletes each higher one, which lost a race of creations.
func (self *InferCacheSecret) standing(ctx context.Context, memberId Id, mayDelete bool) (*inferCacheStanding, error) {
	repoIds, err := self.host.secretRepos(memberId)
	if err != nil {
		return nil, err
	}
	if len(repoIds) > max(0, self.settings.CacheSecretRepoScanMaxCount) {
		repoIds = repoIds[:max(0, self.settings.CacheSecretRepoScanMaxCount)]
	}
	var standing *inferCacheStanding
	for _, repoId := range repoIds {
		content, version, err := self.host.readCache(ctx, repoId, self.settings.CacheFileMaxByteCount)
		var file *InferCacheFile
		switch {
		case errors.Is(err, errInferCacheFile):
			// a file that stands and is too long: read as one not of the format
		case err != nil:
			// a repo that could not be read may be the one: no sync decides without it
			return nil, err
		case content == nil:
			continue
		default:
			file, err = parseInferCacheFile(content, self.settings)
			if err != nil {
				file = nil
			}
		}
		if standing == nil {
			standing = &inferCacheStanding{repoId: repoId, file: file, version: version}
			continue
		}
		if mayDelete {
			if err := self.host.deleteRepo(ctx, repoId); err != nil {
				self.log.Warningf("[infer]a second cache repo %s was not deleted: %s", repoId, err)
			}
		}
	}
	return standing, nil
}

// The secret the copy sealed to this device opens to, nil where none is sealed to it or it does not open.
func (self *InferCacheSecret) openCopy(ctx context.Context, me *inferCacheSelf, standing *inferCacheStanding) []byte {
	index := slices.IndexFunc(standing.file.Copies, func(copy *InferCacheCopy) bool {
		return copy.SidecarId == me.SidecarId
	})
	if index < 0 {
		return nil
	}
	secret, err := self.sealer.Open(ctx, standing.repoId, inferCachePurpose(standing.file.DrawId), standing.file.Copies[index])
	if err != nil || len(secret) != inferCacheSecretByteCount {
		if self.log.V(1).Enabled() {
			self.log.Infof("[infer]this device's copy of the cache secret in %s does not open", standing.repoId)
		}
		return nil
	}
	testHookSecret("S_m", secret)
	return secret
}

// A new repo with a new secret sealed to devices, by a create-only write.
func (self *InferCacheSecret) create(ctx context.Context, me *inferCacheSelf, devices []Id) error {
	repoId, err := self.host.createRepo(ctx, *me.MemberId)
	if err != nil {
		return err
	}
	file, err := self.newDraw(ctx, me, repoId, devices)
	if err == nil {
		err = self.write(ctx, repoId, file, 0)
	}
	if err != nil && !errors.Is(err, errInferCacheConflict) {
		// an empty repo would only cost the next sync a read
		if deleteErr := self.host.deleteRepo(ctx, repoId); deleteErr != nil {
			self.log.Warningf("[infer]a cache repo %s left without its file was not deleted: %s", repoId, deleteErr)
		}
	}
	return err
}

// A new secret sealed to devices in standing's repo, replacing what stands by a write held to the version read.
func (self *InferCacheSecret) draw(ctx context.Context, me *inferCacheSelf, standing *inferCacheStanding, devices []Id) error {
	file, err := self.newDraw(ctx, me, standing.repoId, devices)
	if err != nil {
		return err
	}
	return self.write(ctx, standing.repoId, file, standing.version)
}

// A fresh draw for repoId: S_m and its id drawn, and a copy sealed to each of devices whose ReaderKey takes one. A device
// that takes none asks at its next sync. This device's own copy must seal, else nothing is written, since the device
// that draws would hold a secret no one could open again.
func (self *InferCacheSecret) newDraw(ctx context.Context, me *inferCacheSelf, repoId Id, devices []Id) (*InferCacheFile, error) {
	secret := make([]byte, inferCacheSecretByteCount)
	if _, err := io.ReadFull(self.random, secret); err != nil {
		return nil, fmt.Errorf("cache secret: no draw: %w", err)
	}
	testHookSecret("S_m", secret)
	drawIdBytes := make([]byte, inferCacheDrawIdByteCount)
	if _, err := io.ReadFull(self.random, drawIdBytes); err != nil {
		return nil, fmt.Errorf("cache secret: no draw id: %w", err)
	}
	file := &InferCacheFile{
		Format:    inferCacheFileFormat,
		DrawId:    hex.EncodeToString(drawIdBytes),
		DrawnBy:   me.SidecarId,
		DrawnAtMs: self.clock.Now().UnixMilli(),
		Copies:    []*InferCacheCopy{},
		Asks:      []*InferCacheAsk{},
	}
	purpose := inferCachePurpose(file.DrawId)
	sealedOwn := false
	for _, device := range devices {
		copy, err := self.sealer.Seal(ctx, repoId, purpose, device, secret)
		if err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[infer]no copy of the cache secret was sealed to %s: %s", device, err)
			}
			continue
		}
		sealedOwn = sealedOwn || device == me.SidecarId
		file.Copies = append(file.Copies, copy)
	}
	clear(secret)
	if !sealedOwn {
		return nil, errors.New("cache secret: no copy seals to this device, so none is drawn")
	}
	return file, nil
}

// The writes a device that holds what stands owes it, in one write held to the version read: a copy sealed to each
// listed device that has none or asked for a new one, answered asks dropped, and its own copy re-sealed to its newest
// ReaderKey; or, holding no copy that opens, its own ask. Nothing is written where nothing changed.
func (self *InferCacheSecret) reconcile(ctx context.Context, me *inferCacheSelf, standing *inferCacheStanding, devices []Id, secret []byte) error {
	file := standing.file
	ownKeySha256, err := self.sealer.ReaderKeySha256(ctx)
	if err != nil {
		return err
	}
	ownKey := hex.EncodeToString(ownKeySha256)
	next := &InferCacheFile{
		Format:    file.Format,
		DrawId:    file.DrawId,
		DrawnBy:   file.DrawnBy,
		DrawnAtMs: file.DrawnAtMs,
		Copies:    slices.Clone(file.Copies),
		Asks:      []*InferCacheAsk{},
	}
	changed := false
	if secret == nil {
		next.Asks = slices.DeleteFunc(slices.Clone(file.Asks), func(ask *InferCacheAsk) bool {
			return !slices.Contains(devices, ask.SidecarId)
		})
		changed = len(next.Asks) != len(file.Asks)
		asked := slices.ContainsFunc(next.Asks, func(ask *InferCacheAsk) bool {
			return ask.SidecarId == me.SidecarId && ask.ReaderKeySha256 == ownKey
		})
		if !asked {
			next.Asks = slices.DeleteFunc(next.Asks, func(ask *InferCacheAsk) bool {
				return ask.SidecarId == me.SidecarId
			})
			next.Asks = append(next.Asks, &InferCacheAsk{SidecarId: me.SidecarId, ReaderKeySha256: ownKey, AskedAtMs: self.clock.Now().UnixMilli()})
			changed = true
		}
	} else {
		purpose := inferCachePurpose(file.DrawId)
		// whom to seal to: every listed device without a copy, each listed asker, and this device where its copy is
		// sealed to an older ReaderKey
		reseal := []Id{}
		for _, device := range devices {
			index := slices.IndexFunc(next.Copies, func(copy *InferCacheCopy) bool { return copy.SidecarId == device })
			askIndex := slices.IndexFunc(file.Asks, func(ask *InferCacheAsk) bool { return ask.SidecarId == device })
			switch {
			case index < 0:
				reseal = append(reseal, device)
			case 0 <= askIndex && file.Asks[askIndex].ReaderKeySha256 != next.Copies[index].ReaderKeySha256:
				reseal = append(reseal, device)
			case device == me.SidecarId && next.Copies[index].ReaderKeySha256 != ownKey:
				reseal = append(reseal, device)
			}
		}
		for _, device := range reseal {
			copy, err := self.sealer.Seal(ctx, standing.repoId, purpose, device, secret)
			if err != nil {
				if self.log.V(1).Enabled() {
					self.log.Infof("[infer]no copy of the cache secret was sealed to %s: %s", device, err)
				}
				continue
			}
			next.Copies = slices.DeleteFunc(next.Copies, func(existing *InferCacheCopy) bool { return existing.SidecarId == device })
			next.Copies = append(next.Copies, copy)
			changed = true
		}
		// an ask stands only while its device holds no copy sealed to the key it named
		for _, ask := range file.Asks {
			answered := slices.ContainsFunc(next.Copies, func(copy *InferCacheCopy) bool {
				return copy.SidecarId == ask.SidecarId && copy.ReaderKeySha256 == ask.ReaderKeySha256
			})
			if !answered && slices.Contains(devices, ask.SidecarId) {
				next.Asks = append(next.Asks, ask)
			}
		}
		changed = changed || len(next.Asks) != len(file.Asks)
	}
	if !changed {
		return nil
	}
	return self.write(ctx, standing.repoId, next, standing.version)
}

// file written to repoId's cache.json, held to ifVersion.
func (self *InferCacheSecret) write(ctx context.Context, repoId Id, file *InferCacheFile, ifVersion uint64) error {
	if err := file.validate(self.settings); err != nil {
		return err
	}
	content, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("%w: %w", errInferCacheFile, err)
	}
	testHookBarrier("infer.cache_write.before", repoId.String())
	err = self.host.writeCache(ctx, repoId, content, ifVersion)
	testHookBarrier("infer.cache_write.after", repoId.String())
	return err
}

// This device's own secret, drawn and kept in its sealed state at first need.
func (self *InferCacheSecret) ownKey() (*InferCacheKey, error) {
	own := func() []byte {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.own
	}()
	if own == nil {
		loaded, err := self.host.loadOwn()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInferCacheSecretUnavailable, err)
		}
		if len(loaded) != inferCacheSecretByteCount {
			// none drawn yet, or a file of another size, which no salt takes: drawn anew
			loaded = make([]byte, inferCacheSecretByteCount)
			if _, err := io.ReadFull(self.random, loaded); err != nil {
				return nil, fmt.Errorf("%w: no draw: %w", ErrInferCacheSecretUnavailable, err)
			}
			testHookSecret("cache_secret_own", loaded)
			if err := self.host.storeOwn(loaded); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrInferCacheSecretUnavailable, err)
			}
		} else {
			testHookSecret("cache_secret_own", loaded)
		}
		own = func() []byte {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.own == nil {
				self.own = loaded
			}
			return self.own
		}()
	}
	return &InferCacheKey{secret: own, source: InferCacheSecretOwn, random: self.random}, nil
}

// The purpose a draw's copies are sealed under.
func inferCachePurpose(drawId string) string {
	return inferCacheSealPurposePrefix + drawId
}

// content as cache.json, refused where it does not hold to its format.
func parseInferCacheFile(content []byte, settings *InferSettings) (*InferCacheFile, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	file := &InferCacheFile{}
	if err := decoder.Decode(file); err != nil {
		return nil, fmt.Errorf("%w: %w", errInferCacheFile, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: more than one value", errInferCacheFile)
	}
	if err := file.validate(settings); err != nil {
		return nil, err
	}
	return file, nil
}

// Nil where the file holds to its format: its format, a draw id of 32 hex, a drawing device, at most
// CacheFileMaxEntryCount copies and asks, each naming a device once with a key's 64 hex and a copy's seal.
func (self *InferCacheFile) validate(settings *InferSettings) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errInferCacheFile, fmt.Sprintf(format, args...))
	}
	keyHex := func(text string) bool {
		decoded, err := hex.DecodeString(text)
		return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == text
	}
	drawId, err := hex.DecodeString(self.DrawId)
	switch {
	case self.Format != inferCacheFileFormat:
		return refuse("format %d", self.Format)
	case err != nil || len(drawId) != inferCacheDrawIdByteCount || hex.EncodeToString(drawId) != self.DrawId:
		return refuse("a draw id that is not %d bytes of lowercase hex", inferCacheDrawIdByteCount)
	case self.DrawnBy == (Id{}):
		return refuse("no drawing device")
	case settings.CacheFileMaxEntryCount < len(self.Copies) || settings.CacheFileMaxEntryCount < len(self.Asks):
		return refuse("more than %d copies or asks", settings.CacheFileMaxEntryCount)
	}
	seen := map[Id]bool{}
	for _, copy := range self.Copies {
		if copy == nil || copy.SidecarId == (Id{}) || seen[copy.SidecarId] || !keyHex(copy.ReaderKeySha256) || len(copy.Sealed) == 0 {
			return refuse("a copy that is not whole, or a second for one device")
		}
		seen[copy.SidecarId] = true
	}
	clear(seen)
	for _, ask := range self.Asks {
		if ask == nil || ask.SidecarId == (Id{}) || seen[ask.SidecarId] || !keyHex(ask.ReaderKeySha256) {
			return refuse("an ask that is not whole, or a second for one device")
		}
		seen[ask.SidecarId] = true
	}
	return nil
}

// Registers the cache secret, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(inferCacheSecretComponentName, newSidecarInferCacheSecret, nil)
}

// The cache secret over sidecar's verified state, evs and sealed state, with the registered inner seal where one is.
// Reads nothing of the network while it constructs.
func newSidecarInferCacheSecret(sidecar *Sidecar) (*InferCacheSecret, error) {
	settings := sidecar.settings.Infer
	if settings == nil {
		settings = DefaultInferSettings()
	}
	var sealer InferCacheSealer
	if inferCacheSealerRegistration != nil {
		var err error
		sealer, err = inferCacheSealerRegistration(sidecar)
		if err != nil {
			// no seal: every remote call salts with this device's own secret
			sidecar.log.Warningf("[infer]the cache secret's inner seal did not construct: %s", err)
			sealer = nil
		}
	}
	return newInferCacheSecret(&inferCacheSecretArgs{
		Host:     &inferCacheSidecarHost{sidecar: sidecar},
		Sealer:   sealer,
		Settings: settings,
		Clock:    sidecar.clock,
		Log:      sidecar.log,
	})
}

// This Sidecar's cache secret, which the remote paths salt each call with (§6.6), or an error wrapping
// ErrComputeComponentUnavailable that says why there is none.
func (self *Sidecar) InferCacheSecret() (*InferCacheSecret, error) {
	return sidecarComputeComponent[InferCacheSecret](self, inferCacheSecretComponentName)
}

// The cache secret's host over a Sidecar: its authority, its verified authorization state, its evs client and its
// sealed local state, each looked up at use.
type inferCacheSidecarHost struct {
	sidecar *Sidecar
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) self() (*inferCacheSelf, error) {
	identity := self.sidecar.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	authority := self.sidecar.authority()
	if authority == nil {
		return nil, errors.New("no verified authorization state")
	}
	admission := authority.Admission(identity.SidecarId)
	if admission == nil || admission.Row == nil {
		return nil, errors.New("this sidecar's admission is not in the verified state")
	}
	me := &inferCacheSelf{
		SidecarId: identity.SidecarId,
		ReadOnly:  configRowReadOnly(admission.Row),
		Enclave:   configRowEnclave(admission.Row),
	}
	if admission.MemberId != (Id{}) && len(admission.TagIds) == 0 {
		memberId := admission.MemberId
		me.MemberId = &memberId
	}
	return me, nil
}

// See inferCacheHost: the member's devices the authority's one consent predicate passes (§8.5).
func (self *inferCacheSidecarHost) consentedDevices(memberId Id) ([]Id, error) {
	authority := self.sidecar.authority()
	if authority == nil {
		return nil, errors.New("no verified authorization state")
	}
	devices := []Id{}
	for _, device := range authority.MemberDevices(memberId) {
		if device == nil || device.Row == nil {
			continue
		}
		sidecarId, err := IdFromBytes(device.Row.GetSidecarId())
		if err != nil {
			continue
		}
		if authority.Consented(sidecarId, memberId) && !slices.Contains(devices, sidecarId) {
			devices = append(devices, sidecarId)
		}
	}
	slices.SortFunc(devices, func(a Id, b Id) int { return a.Cmp(b) })
	return devices, nil
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) secretRepos(memberId Id) ([]Id, error) {
	follower := self.sidecar.ConfigFollower()
	if follower == nil {
		return nil, errors.New("no verified authorization state")
	}
	engine := follower.AclEngine()
	if engine == nil {
		return nil, errors.New("no verified authorization state")
	}
	state := engine.State()
	if state == nil {
		return nil, errors.New("no verified authorization state")
	}
	repoIds := []Id{}
	for _, repoId := range state.RepoIds() {
		repo := state.Repo(repoId)
		deletion := repo.GetDeletion()
		if repo.GetKind() != protocol.RepoKind_REPO_KIND_SECRET || (deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0) {
			continue
		}
		if ownerId, err := IdFromBytes(repo.GetOwnerMemberId()); err == nil && ownerId == memberId {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, func(a Id, b Id) int { return a.Cmp(b) })
	return repoIds, nil
}

// This Sidecar's evs client, or why there is none.
func (self *inferCacheSidecarHost) evs() (*EvsClient, error) {
	client := self.sidecar.EvsClient()
	if client == nil {
		return nil, errors.New("no evs client runs")
	}
	return client, nil
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) readCache(ctx context.Context, repoId Id, maxByteCount int) ([]byte, uint64, error) {
	client, err := self.evs()
	if err != nil {
		return nil, 0, err
	}
	out := &inferCacheBoundedBuffer{maxByteCount: maxByteCount}
	info, err := client.Repo(repoId).ReadHead(ctx, &EvsReadArgs{Path: inferCacheFileName}, out)
	switch {
	case errors.Is(err, ErrEvsPathAbsent):
		return nil, 0, nil
	case out.over:
		return nil, 0, fmt.Errorf("%w: longer than %d bytes", errInferCacheFile, maxByteCount)
	case err != nil:
		return nil, 0, err
	}
	return out.buffer.Bytes(), info.Version, nil
}

// See inferCacheHost: one versionless write held to ifVersion, outside format 2's gate none.
func (self *inferCacheSidecarHost) writeCache(ctx context.Context, repoId Id, content []byte, ifVersion uint64) error {
	client, err := self.evs()
	if err != nil {
		return err
	}
	if !client.Format2Admitted() {
		return errInferCacheVersionless
	}
	version := ifVersion
	_, err = client.Repo(repoId).WritePaths(ctx, &EvsWritePathsArgs{
		Writes: []*EvsPathWrite{{
			Path:      inferCacheFileName,
			Content:   bytes.NewReader(content),
			IfVersion: &version,
			Options:   &EvsWriteOptions{Versioning: EvsVersioningOff},
		}},
	})
	var conflict *EvsPathConflictError
	if errors.As(err, &conflict) || errors.Is(err, ErrEvsVersionlessConflict) {
		return fmt.Errorf("%w: %w", errInferCacheConflict, err)
	}
	return err
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) createRepo(ctx context.Context, memberId Id) (Id, error) {
	client, err := self.evs()
	if err != nil {
		return Id{}, err
	}
	owner := memberId
	repo, err := client.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_SECRET, OwnerMemberId: &owner})
	if err != nil {
		return Id{}, err
	}
	return repo.RepoId(), nil
}

// See inferCacheHost: deleted now, since no one restores a cache repo.
func (self *inferCacheSidecarHost) deleteRepo(ctx context.Context, repoId Id) error {
	client, err := self.evs()
	if err != nil {
		return err
	}
	return client.Repo(repoId).Delete(ctx, true)
}

// The sealed directory this device's own secret is kept in.
func (self *inferCacheSidecarHost) store() (SidecarStore, error) {
	return self.sidecar.LocalStore().Directory(inferCacheStoreDirectory, inferCacheStoreClass)
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) loadOwn() ([]byte, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(inferCacheOwnFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	secret, err := io.ReadAll(io.LimitReader(reader, inferCacheSecretByteCount+1))
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// See inferCacheHost.
func (self *inferCacheSidecarHost) storeOwn(secret []byte) error {
	store, err := self.store()
	if err != nil {
		return err
	}
	writer, err := store.Create(inferCacheOwnFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(secret); err != nil {
		return err
	}
	return writer.Commit()
}

// A writer that keeps at most maxByteCount bytes and notes a longer stream.
type inferCacheBoundedBuffer struct {
	buffer       bytes.Buffer
	maxByteCount int
	over         bool
}

func (self *inferCacheBoundedBuffer) Write(data []byte) (int, error) {
	if self.maxByteCount < self.buffer.Len()+len(data) {
		self.over = true
		return 0, fmt.Errorf("%w: longer than %d bytes", errInferCacheFile, self.maxByteCount)
	}
	return self.buffer.Write(data)
}
