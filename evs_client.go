// EvsClient (§11.20): one network's client of evs, the only caller of evs on a device (git never reaches it, §11.11).
// It owns the transport (evs_http.go), the pins and read records (evs_pin_store.go), the verifying reader
// (evs_verify.go) and the hints evs raises (§11.10), and hands out an EvsRepo per repo. One directory is one repo is
// one key domain (R-EVS-1): every key an EvsRepo uses comes from GkmClient for that repo alone.
//
// Lifecycle calls stay thin (§11.12's log first row): CreateRepo, Delete, Restore and Shred each file §8.8's statement
// first, through the core's statement poster, then call the route, which evs refuses without that statement in its
// projection (409 STATEMENT_MISSING); CreateRepo runs KF1's GkmClient.CreateGroup and activation between the create
// and the first write. A device killed between the statement and the route leaves a state the log records, which
// taskworker's reconciler applies, so a retry is safe.
//
// What the client runs on comes in EvsClientArgs as seams, so a test builds one on fakes (§23.5): Sidecar.ServiceToken,
// Sidecar.Sign, GkmClient (sidecartest.FakeGkm until gkm lands), the component's SidecarStore, the newest verified
// config state, and the core's statement poster, which CORE-M2-02 provides; until it does, FileStatement is nil and
// every create, delete and restore refuses before anything is sent.
//
// On every leg: no connect type. evs_component.go attaches it to a Sidecar's client generations. Safe for concurrent
// use.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The evs component's name: its keychain namespace and its sealed directory (§5.9).
const evsComponentName = "evs"

var (
	// The core's statement poster is not wired (CORE-M2-02), so no access-log statement can be filed and nothing
	// that needs one is sent.
	ErrEvsNoStatementPoster = errors.New("evs: no statement poster")
	// The client has no verified config state to judge statements at, so nothing reads as verified.
	ErrEvsNoConfig = errors.New("evs: no verified config state")
)

// Files one of §8.8's access-log statements (RepoCreate, RepoDelete, RepoRestore): the core's poster builds its
// StatementHeader, signs it, posts it and retries the same bytes until it lands (CORE-M2-02's sidecarAct, C-02). body
// is the statement without its header. It answers once the statement has landed.
type EvsFileStatementFunction func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error

// The newest verified config state, which statements are judged at (§7.9, §8.12), or nil before one verifies.
type EvsConfigFunction func() GkmAuthView

// What an EvsClient runs on.
type EvsClientArgs struct {
	NetworkId Id
	// SidecarSettings.EvsUrl: absolute, no trailing slash.
	EvsUrl string
	// SidecarApi's transport: the client strategy's on a connect leg, fetch on sidecar_http. Nil refuses every call.
	Transport http.RoundTripper
	// Sidecar.ServiceToken.
	ServiceToken EvsServiceTokenFunction
	// Sidecar.Sign: the identity key, which signs every statement.
	Sign EvsSignFunction
	// This sidecar's ids and current client now.
	Identity func() *SidecarIdentity
	Gkm      GkmClient
	// The evs component's sealed directory.
	Store SidecarStore
	// Nil: no state verifies, so every read refuses.
	Config EvsConfigFunction
	// Nil until CORE-M2-02: every create, delete and restore refuses.
	FileStatement EvsFileStatementFunction
	// This device's epoch pin for a §10 group it is a leaf of (KEYS-M2-23's HeadCheckGroupSource.GroupHead), which a
	// push's sealed metadata carries for HeadCheck's epoch pins. Nil, or a group it holds none of, carries none.
	GroupHead func(groupId Id) (*protocol.GroupHead, bool)
	// Raises events; nil drops them.
	Emit     SidecarEventFunction
	Clock    Clock
	Log      Logger
	Settings *EvsSettings
	// Called once a repo CreateRepo made is active, before CreateRepo answers: a team network's directory announces a
	// general or record repo there, or writes its private marker (§16.11's default and private rows, RECORD-M6-15). A
	// failure answers CreateRepo's error with the repo made, and a retry with ResumeRepoId calls it again. Nil for
	// none.
	RepoCreated func(ctx context.Context, created *EvsRepoCreated) error
}

// A repo CreateRepo made, as EvsClientArgs.RepoCreated takes it.
type EvsRepoCreated struct {
	RepoId        Id
	Kind          protocol.RepoKind
	OwnerMemberId *Id
	// EvsCreateRepoArgs'.
	DisplayName string
	Private     bool
	GroupInbox  bool
	Confirmed   bool
}

// One network's client of evs.
type EvsClient struct {
	args     *EvsClientArgs
	settings *EvsSettings
	clock    Clock
	log      Logger
	http     *evsHttp
	pins     *EvsPinStore
	verifier *EvsVerifier

	stateLock sync.Mutex
	// the newest ref version a hint named, per repo and ref, which sends the next read past evs's head cache
	hintedVersions map[evsRefKey]uint64
	// each ref's epoch state as the last verified head gave it (evs_epoch_read.go)
	refEpochs map[evsRefKey]*evsRefEpoch
	// the receipt gate, nil for the default that refuses (evs_read.go)
	preDecryptHook EvsPreDecryptFunction
	// RefHeads' rotation (evs_witness.go)
	witnessCursors evsWitnessCursors
	// the local tier's mount registry, an *EvsMounts on desktop legs (evs_local_mount.go), nil in head mode
	localTier any
	// each repo's sealed mirror, one per repo so its puts serialize (evs_mirror_layout.go)
	repoIdMirrors map[Id]*EvsMirrorStore
	// where M10's index writer joins each write's plan (evs_plan.go), nil until then
	writeHook EvsWritePlanHook
	// subscriptions and catch-up (evs_subscribe.go), with its own lock
	subscriber *evsSubscriber
}

// A ref of a repo.
type evsRefKey struct {
	repoId Id
	refId  Id
}

// A client on args. Refuses args missing a seam it cannot run without: the transport, the token, the signer, gkm,
// the store and the settings.
func NewEvsClient(args *EvsClientArgs) (*EvsClient, error) {
	switch {
	case args == nil:
		return nil, fmt.Errorf("%w: no evs client args", errInvalidSettings)
	case args.Transport == nil || args.ServiceToken == nil || args.Sign == nil || args.Identity == nil:
		return nil, fmt.Errorf("%w: an evs client needs a transport, tokens, a signer and an identity", errInvalidSettings)
	case args.Gkm == nil || args.Store == nil || args.Settings == nil:
		return nil, fmt.Errorf("%w: an evs client needs gkm, a store and settings", errInvalidSettings)
	}
	if err := checkServiceUrl("EvsUrl", args.EvsUrl, "http", "https"); err != nil {
		return nil, err
	}
	if err := checkSettingsNumbers("EvsSettings", reflect.ValueOf(args.Settings).Elem(), false); err != nil {
		return nil, err
	}
	clock := clockOrReal(args.Clock)
	self := &EvsClient{
		args:     args,
		settings: args.Settings,
		clock:    clock,
		log:      loggerOrDefault(args.Log),
		http: &evsHttp{
			baseUrl:      args.EvsUrl,
			transport:    wrapSidecarApiTransport(args.Transport),
			serviceToken: args.ServiceToken,
			settings:     args.Settings,
			clock:        clock,
		},
		pins:           NewEvsPinStore(args.Store, args.Settings),
		hintedVersions: map[evsRefKey]uint64{},
		refEpochs:      map[evsRefKey]*evsRefEpoch{},
		repoIdMirrors:  map[Id]*EvsMirrorStore{},
	}
	self.verifier = newEvsVerifier(self)
	self.subscriber = newEvsSubscriber(self)
	return self, nil
}

// The network the client serves.
func (self *EvsClient) NetworkId() Id {
	return self.args.NetworkId
}

// The client's pins and read records.
func (self *EvsClient) Pins() *EvsPinStore {
	return self.pins
}

// The client's verifying reader.
func (self *EvsClient) Verifier() *EvsVerifier {
	return self.verifier
}

// The repo's sealed mirror in the evs component's directory (the sealed mirror layout, evs_mirror_layout.go), the same
// one for every caller. Nothing is written until a change.
func (self *EvsClient) Mirror(repoId Id) (*EvsMirrorStore, error) {
	held := func() *EvsMirrorStore {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.repoIdMirrors[repoId]
	}()
	if held != nil {
		return held, nil
	}
	mirror, err := newEvsMirrorStore(self.args.Store, repoId)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// a racing caller's, if it got here first
	if held := self.repoIdMirrors[repoId]; held != nil {
		return held, nil
	}
	self.repoIdMirrors[repoId] = mirror
	return mirror, nil
}

// The repo's client. Nothing is read or checked until a call needs it.
func (self *EvsClient) Repo(repoId Id) *EvsRepo {
	return &EvsRepo{client: self, repoId: repoId}
}

// Raises an event, never blocking (SidecarEventFunction's rule).
func (self *EvsClient) emit(event SidecarEvent) {
	if self.args.Emit != nil {
		self.args.Emit(event)
	}
}

// Raises evs_alarm (plan-EVS1-evs-events), naming no path in the log.
func (self *EvsClient) alarm(repoId Id, refId Id, reason SidecarEvsAlarm, path string, signerId *Id) {
	self.log.Warningf("[evs]alarm %s on repo %s ref %s", reason, repoId, refId)
	self.emit(SidecarEvent{
		Kind:      SidecarEventEvsAlarm,
		RepoId:    &repoId,
		RefId:     &refId,
		Path:      path,
		SidecarId: signerId,
		EvsAlarm:  reason,
	})
}

// What CreateRepo makes.
type EvsCreateRepoArgs struct {
	// Fixed at creation and bound into §10's ur_group (§11.12).
	Kind protocol.RepoKind
	// An owner-bound kind's owner member (vault, mailbox, secret); nil for any other.
	OwnerMemberId *Id
	// A create already filed and cut short: its repo id, to resume at the route without filing a second
	// RepoCreate. Nil draws a new random id and files.
	ResumeRepoId *Id
	// The repo's display name, which a team network's directory announces a general or record repo under (prose).
	DisplayName string
	// --private on every repo-creating command (§16.11's private row): the directory gets a private marker in place of
	// the announcement, so no device announces the repo on its own.
	Private bool
	// A group inbox (§15.8): announced with requests closed and no roles offered.
	GroupInbox bool
	// A person confirmed the creating command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
}

// A new random repo id: 16 random bytes, so the id says nothing of when or where it was made (§11.12's naming row).
func NewEvsRepoId() Id {
	repoId := Id{}
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(repoId[:])
	return repoId
}

// §11.12's creation: files RepoCreate, becoming the repo's admin; PUT /evs/v1/repos/<id> places it and writes repo/,
// keying; KF1's GkmClient.CreateGroup makes its group and generation 1; activation moves repo/ to active, after which
// the first write may go; then EvsClientArgs.RepoCreated, which a team network's directory announces it by. Each step
// resumes: evs answers a retried create and activation as the first, and gkm resumes KF1 after a crash. A failure of
// RepoCreated answers the repo with its error.
func (self *EvsClient) CreateRepo(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error) {
	if args == nil || args.Kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		return nil, fmt.Errorf("%w: a repo of no kind", errInvalidSettings)
	}
	if aclRepoKindOwnerBound(args.Kind) != (args.OwnerMemberId != nil) {
		return nil, fmt.Errorf("%w: an owner member exactly for an owner-bound kind", errInvalidSettings)
	}
	if self.args.FileStatement == nil {
		return nil, ErrEvsNoStatementPoster
	}
	repoId := NewEvsRepoId()
	if args.ResumeRepoId != nil {
		repoId = *args.ResumeRepoId
	} else {
		create := &protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: args.Kind}
		if err := self.args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_CREATE, create); err != nil {
			return nil, fmt.Errorf("evs: RepoCreate: %w", err)
		}
	}
	repo := self.Repo(repoId)
	if err := repo.callLifecycle(ctx, &evsCall{
		route:  "PUT /evs/v1/repos/{repo_id}",
		method: http.MethodPut,
		path:   "/evs/v1/repos/" + evsUrlId(repoId),
		repoId: repoId,
		role:   evsScopeAdmin,
	}); err != nil {
		return nil, err
	}
	groupArgs := &GkmCreateGroupArgs{NetworkId: self.args.NetworkId, RepoId: repoId, Kind: args.Kind, OwnerMemberId: args.OwnerMemberId}
	if _, err := self.args.Gkm.CreateGroup(ctx, groupArgs); err != nil {
		return nil, fmt.Errorf("evs: the repo's group: %w", err)
	}
	if err := repo.callLifecycle(ctx, &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/activate",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/activate",
		repoId: repoId,
		role:   evsScopeAdmin,
	}); err != nil {
		return nil, err
	}
	if self.args.RepoCreated != nil {
		created := &EvsRepoCreated{
			RepoId:        repoId,
			Kind:          args.Kind,
			OwnerMemberId: args.OwnerMemberId,
			DisplayName:   args.DisplayName,
			Private:       args.Private,
			GroupInbox:    args.GroupInbox,
			Confirmed:     args.Confirmed,
		}
		if err := self.args.RepoCreated(ctx, created); err != nil {
			return repo, fmt.Errorf("evs: the repo's directory item: %w", err)
		}
	}
	return repo, nil
}

// A hint on evs:<repo_id> (§11.10): PushHint.version, the repo's push sequence, and its delta, an EvsHeadChanged. It
// carries no authority: it sends the next read of the ref past evs's head cache, which the read then verifies as any
// other, and queues the subscriptions' reads it calls for (evs_hint.go). It never blocks, as a hint's subscriber must
// not (PROTO-M1-06).
func (self *EvsClient) ReceiveHint(repoId Id, sequence uint64, delta []byte) {
	changed := &protocol.EvsHeadChanged{}
	if err := proto.Unmarshal(delta, changed); err != nil {
		return
	}
	refId, err := IdFromBytes(changed.GetRefId())
	if err != nil {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key := evsRefKey{repoId: repoId, refId: refId}
		if self.hintedVersions[key] < changed.GetVersion() {
			self.hintedVersions[key] = changed.GetVersion()
		}
	}()
	// the subscriptions' reads (evs_hint.go)
	self.subscriber.noteHint(repoId, sequence, refId)
}

// The newest version a hint named for a ref, 0 when none did.
func (self *EvsClient) hintedVersion(repoId Id, refId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hintedVersions[evsRefKey{repoId: repoId, refId: refId}]
}
