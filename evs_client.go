// EvsClient (§11.20): one network's client of evs, the only caller of evs on a device (git never reaches it, §11.11).
// It owns the transport (evs_http.go), the pins and read records (evs_pin_store.go), the verifying reader
// (evs_verify.go) and the hints evs raises (§11.10), and hands out an EvsRepo per repo. One directory is one repo is
// one key domain (R-EVS-1): every key an EvsRepo uses comes from GkmClient for that repo alone.
//
// Lifecycle calls stay thin (§11.12's log first row): CreateRepo, Delete, Restore and Shred each file §8.8's statement
// first, through the core's statement poster, then call the route, which evs refuses without that statement in its
// projection (409 STATEMENT_MISSING); a create whose id another creator placed first (409 REPO_PLACED) files and places
// again under another id. CreateRepo runs KF1's GkmClient.CreateGroup and activation between the create and the first
// write, and asks EvsClientArgs.PrivateCreate before it files a create marked private (QD-748). A device killed
// between the statement and the route leaves a state the log records, which taskworker's reconciler applies, so a
// retry is safe.
//
// The config kind's first head is the exception to sealing on a repo that stands: its push is sealed and signed before
// its network's base 1, under generation 1 as KF1's bootstrap draft holds it, and sent once the repo is active
// (PrepareConfigHead and CommitConfigHead, evs_config_push.go; QD-824).
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
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"

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
	// A repo this sidecar, which holds no leaf, created waits keying for a member device to form its group and wrap
	// generation 1 to it (QD-638): the repo is made and stays keying, and CreateRepo with ResumeRepoId waits again.
	ErrEvsRepoKeying = errors.New("evs: the repo waits keying for a member device to form its group")
	// A create marked private found no PrivateCreate to ask whether the network's directory stands, so nothing would
	// keep the choice: nothing is filed (QD-748).
	ErrEvsPrivateUnchecked = errors.New("evs: nothing checks a private repo's directory")
)

// Files one of §8.8's access-log statements (RepoCreate, RepoDelete, RepoRestore): the core's poster builds its
// StatementHeader, signs it, posts it and retries the same bytes until it lands (CORE-M2-02's sidecarAct, C-02). body
// is the statement without its header. It answers once the statement has landed.
type EvsFileStatementFunction func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error

// The newest verified config state, which statements are judged at (§7.9, §8.12), or nil before one verifies.
type EvsConfigFunction func() GkmAuthView

// Waits until the authorization log whose state an EvsConfigFunction gives has applied position n, or ctx ends
// (ConfigClient.WaitForPin): what a reader asks of a statement pinned above the newest state it holds, so it judges
// the statement at its own pin once its log is there (QD-1202). n is a pin evs served, not yet verified, so it is no
// proof api serves n. An error, or an answer while the state still lies below n, leaves the statement withheld.
type EvsConfigWaitFunction func(ctx context.Context, n uint64) error

// What an EvsClient runs on.
type EvsClientArgs struct {
	NetworkId Id
	// SidecarSettings.EvsUrl: absolute, no trailing slash.
	EvsUrl string
	// SidecarApi's transport: the client strategy's on a connect leg, fetch on sidecar_http. Nil refuses every call.
	Transport http.RoundTripper
	// Sidecar.ServiceToken.
	ServiceToken EvsServiceTokenFunction
	// Sidecar.ForgetServiceToken: drops the token evs answered 401 UNAUTHENTICATED, so the call's one retry presents a
	// new one (evs_http.go). Nil for a ServiceToken that keeps no token, as an exchange each call does, whose retry
	// mints a new one anyway; beside a ServiceToken that keeps one, nil retries with the token refused.
	ForgetServiceToken EvsForgetServiceTokenFunction
	// Sidecar.Sign: the identity key, which signs every statement.
	Sign EvsSignFunction
	// This sidecar's ids and current client now.
	Identity func() *SidecarIdentity
	Gkm      GkmClient
	// The evs component's sealed directory.
	Store SidecarStore
	// Nil: no state verifies, so every read refuses.
	Config EvsConfigFunction
	// Waits for Config's log to reach a statement's pin above the state Config gives, within
	// EvsSettings.AuthPinWaitTimeout and the read's ctx, after which the statement is judged at its own pin (QD-1202).
	// Nil, on a leg or for a client whose Config no follower moves, withholds such a statement at once,
	// ErrConfigPinAhead.
	ConfigWait EvsConfigWaitFunction
	// Nil until CORE-M2-02: every create, delete and restore refuses.
	FileStatement EvsFileStatementFunction
	// This device's epoch pin for a §10 group it is a leaf of (KEYS-M2-23's HeadCheckGroupSource.GroupHead), which a
	// push's sealed metadata carries for HeadCheck's epoch pins. Nil, or a group it holds none of, carries none.
	GroupHead func(groupId Id) (*protocol.GroupHead, bool)
	// Sidecar.SignProvenance: an agent's subkey signs a push made for it (evs_provenance.go). Nil names the agent
	// alone, agent_asserted.
	SignProvenance EvsSignProvenanceFunction
	// The format's bound a reader holds agent certificates to (SidecarSettings.AgentSubkeys); nil its defaults.
	AgentSubkeys *SidecarAgentSubkeySettings
	// A replaying reader's committer check for a new commit (owner decision 81; plan-CORE-client-to-sidecar-lookup):
	// SidecarCommitter.Check. Nil takes only a committer that is the push's own client, as SidecarCommitter with no
	// lookup does, and refuses every other.
	Committer func(ctx context.Context, claim *SidecarCommitterClaim) error
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
	// Called with this client before a create marked Private files its RepoCreate (QD-748): the repo's private marker
	// needs the network's directory standing, so the Sidecar's refuses where none stands, naming it, or files it first
	// where this device may (directory_private.go). An error refuses the create with nothing of it filed. A create
	// resumed by its id filed its RepoCreate already and is not asked again. Nil refuses every private create, with
	// ErrEvsPrivateUnchecked.
	PrivateCreate func(ctx context.Context, client *EvsClient, args *EvsCreateRepoArgs) error
	// One follow of the authorization log now, answering once it ran (ConfigClient.CatchUp, within its FollowTimeout
	// and ctx): what the push sender asks once after evs's gate refuses a push that creates or re-creates a shared
	// ref, whose pin evs held at or above the repo's newest rule set (DESIGN-DETAILS 16.2.9, 8.2.5; QD-803) until
	// QD-1032 reverted that clause, and which the gate's predicate still closes on. It runs
	// with the write's locks held and applies entries on the caller's goroutine, so no entry callback may wait on
	// that write. Nil on a leg with no follower, which skips the follow.
	ConfigFollow func(ctx context.Context) error
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
	searchNames atomic.Bool
	args        *EvsClientArgs
	settings    *EvsSettings
	clock       Clock
	log         Logger
	http        *evsHttp
	pins        *EvsPinStore
	verifier    *EvsVerifier

	stateLock sync.Mutex
	// the newest ref version a hint named, per repo and ref, which sends the next read past evs's head cache
	hintedVersions map[evsRefKey]uint64
	// each ref's epoch state as the last verified head gave it, and the listings, alarms and waits beside it
	// (evs_epoch_read.go), under their own lock
	refEpochs map[evsRefKey]*evsRefEpoch
	epochs    *evsClientEpochs
	// the receipt gate, nil for the default that refuses (evs_read.go)
	preDecryptHook EvsPreDecryptFunction
	// RefHeads' rotation (evs_witness.go)
	witnessCursors evsWitnessCursors
	// the local tier's mount registry, an *EvsMounts on desktop legs (evs_local_mount.go), nil in head mode
	localTier any
	// each repo's sealed mirror, one per repo so its puts serialize (evs_mirror_layout.go)
	repoIdMirrors map[Id]*EvsMirrorStore
	// format 2's reader, nil until a composition installs it (EnableFormat2Reader, evs_verify_format2.go), and each
	// repo's ur/index and ur/lfs ref ids, derived once
	format2Reads       evsFormat2Reader
	repoIdReservedRefs map[Id]*evsReservedRefIds
	// where M10's index writer joins each write's plan (evs_plan.go), nil until then
	writeHook EvsWritePlanHook
	// whether the network is in §19.11's format2 gate, from the composition's core state (evs_format_client.go); nil
	// answers false
	format2Source func() (admitted bool, known bool)
	// a new path's versioning rules, from the composition's config state (evs_write_versionless.go); nil reads as
	// no rule
	versioningRules func(repoId Id, filePath string, size uint64) (uint32, error)
	// subscriptions and catch-up (evs_subscribe.go), with its own lock
	subscriber *evsSubscriber
	// the prefix write rules' reader, nil until a composition enables it (EnablePrefixRules, evs_prefix.go)
	prefixReads evsPrefixReader
	// each ref whose creating push evs's gate refused, with that statement's pin and generation: no second statement
	// is built for the ref on them (evs_push.go; QD-803)
	gateRefusals map[evsRefKey]*evsGateRefusal
	// the drop engine's state on the legs that drop, an *evsDropClient made on first use (evs_drop_push.go): the
	// completed dry runs DropHistory may name, the DROP index hook, and the checked DROP bodies this device keeps
	drops any
}

// A creating push's 412 GATE_CLOSED as the sender keeps it for its ref: the refused statement's auth pin and
// generation, and evs's answer.
type evsGateRefusal struct {
	pinVersion uint64
	generation uint64
	err        error
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
			baseUrl:            args.EvsUrl,
			transport:          wrapSidecarApiTransport(args.Transport),
			serviceToken:       args.ServiceToken,
			forgetServiceToken: args.ForgetServiceToken,
			settings:           args.Settings,
			clock:              clock,
		},
		pins:           NewEvsPinStore(args.Store, args.Settings),
		hintedVersions: map[evsRefKey]uint64{},
		gateRefusals:   map[evsRefKey]*evsGateRefusal{},
		refEpochs:      map[evsRefKey]*evsRefEpoch{},
		epochs:         newEvsClientEpochs(),
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

// Signs as Sidecar.SignProvenance does: the agent's subkey over purpose and message, with its certificate
// (EvsClientArgs.SignProvenance; evs_provenance.go).
type EvsSignProvenanceFunction func(agentId Id, purpose string, message []byte) (*AgentProvenanceSignature, error)

// What CreateRepo makes.
type EvsCreateRepoArgs struct {
	// Fixed at creation and bound into §10's ur_group (§11.12).
	Kind protocol.RepoKind
	// An owner-bound kind's owner member (vault, mailbox, secret, and the agent_repos feature's agents and agent,
	// DESIGN-COMPUTE §20.4), or the member whose Team scope a mailcfg is the own of, which only that member's consented
	// device creates: one that writes no config heads (QD-1093), or a config writer once the network's mailcfg stands
	// (QD-1108); nil for the network's mailcfg and any other kind.
	// RepoCreate carries no owner: the access log's fold binds the creator's member, so this names the caller's own
	// member, and its group's ur_group.
	OwnerMemberId *Id
	// A create already filed and cut short: its repo id, to resume at the route without filing a second
	// RepoCreate. Nil draws a new random id and files.
	ResumeRepoId *Id
	// A random ID already reserved by the caller's durable operation, before it filed RepoCreate.
	proposedRepoId *Id
	// The repo's display name, which a team network's directory announces a general or record repo under (prose).
	DisplayName string
	// --private on every repo-creating command (§16.11's private row): the directory gets a private marker in place of
	// the announcement, so no device announces the repo on its own. Asked of EvsClientArgs.PrivateCreate before the
	// RepoCreate is filed, which refuses while the network's directory does not stand (QD-748).
	Private bool
	// The role filed in RepoCreate: group or admin, a mail inbox, which a group's directory item announces with requests
	// closed and no roles offered; or team, the Team inbox (DESIGN-COMPUTE §20.4), a config writer's under the
	// agent_repos feature.
	Inbox protocol.RepoInbox
	// GroupInbox selects the group role for callers predating the signed marker.
	GroupInbox bool
	// An agent repo's keyed label, which its RepoCreate files (QD-1434): AgentRepoLabelKey.Mac of the agent's name,
	// exactly AgentRepoLabelMacByteCount bytes on the agent kind and nil on every other.
	LabelMac []byte
	// A person confirmed the creating command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
}

// Uses the explicit inbox role when set, falling back to the legacy group-inbox flag.
func (self *EvsCreateRepoArgs) inboxRole() protocol.RepoInbox {
	if self.Inbox == protocol.RepoInbox_REPO_INBOX_NONE && self.GroupInbox {
		return protocol.RepoInbox_REPO_INBOX_GROUP
	}
	return self.Inbox
}

// A new random repo id: 16 random bytes, so the id says nothing of when or where it was made (§11.12's naming row).
func NewEvsRepoId() Id {
	repoId := Id{}
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(repoId[:])
	return repoId
}

// §11.12's creation: a create marked private asks EvsClientArgs.PrivateCreate first, which refuses while the network's
// directory does not stand (QD-748); files RepoCreate, becoming the repo's admin; PUT /evs/v1/repos/<id> places it and
// writes repo/, keying, both going again under another id when evs answers 409 REPO_PLACED (placeRepo); KF1's
// GkmClient.CreateGroup makes its group and generation 1; activation moves repo/ to active, after which the first
// write may go; then EvsClientArgs.RepoCreated, which a team network's directory announces it by. Each step resumes:
// evs answers a retried create and activation as the first, and gkm resumes KF1 after a crash. A failure of
// RepoCreated answers the repo with its error.
func (self *EvsClient) CreateRepo(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error) {
	if args == nil || args.Kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		return nil, fmt.Errorf("%w: a repo of no kind", errInvalidSettings)
	}
	if !aclRepoInboxFits(args.Kind, args.inboxRole()) {
		return nil, fmt.Errorf("%w: invalid inbox role for repo kind", errInvalidSettings)
	}
	if !AclRepoKindOwnerFits(args.Kind, args.OwnerMemberId != nil) {
		return nil, fmt.Errorf("%w: an owner member for an owner-bound kind and a Team scope's mailcfg alone", errInvalidSettings)
	}
	if !aclRepoLabelMacFits(args.Kind, args.LabelMac) {
		return nil, fmt.Errorf("%w: a keyed label on an agent repo alone, of %d bytes", errInvalidSettings, AgentRepoLabelMacByteCount)
	}
	if self.args.FileStatement == nil {
		return nil, ErrEvsNoStatementPoster
	}
	if args.ResumeRepoId == nil && aclRepoCreateUsesAgentRepos(&protocol.RepoCreate{Kind: args.Kind, Inbox: args.inboxRole(), LabelMac: args.LabelMac}) {
		// §16.6's before row: a device files no entry that uses a feature its network has not turned on
		if err := self.checkAgentReposOn(); err != nil {
			return nil, err
		}
	}
	if args.ResumeRepoId == nil && args.Private {
		// the choice lives only in the private marker, which the directory holds: asked before anything is filed
		if self.args.PrivateCreate == nil {
			return nil, ErrEvsPrivateUnchecked
		}
		if err := self.args.PrivateCreate(ctx, self, args); err != nil {
			return nil, fmt.Errorf("evs: --private: %w", err)
		}
	}
	repoId, err := self.placeRepo(ctx, args)
	if err != nil {
		return nil, err
	}
	repo := self.Repo(repoId)
	if self.holdsNoLeaf() {
		// QD-638: a member device forms the group of a repo this sidecar creates, and wraps generation 1 to it;
		// activation waits for that wrap, as KF1's waits for its deliveries
		if err := self.awaitFirstGeneration(ctx, repoId); err != nil {
			return repo, err
		}
	} else {
		groupArgs := &GkmCreateGroupArgs{NetworkId: self.args.NetworkId, RepoId: repoId, Kind: args.Kind, Inbox: args.inboxRole(), OwnerMemberId: args.OwnerMemberId}
		if _, err := self.args.Gkm.CreateGroup(ctx, groupArgs); err != nil {
			return nil, fmt.Errorf("evs: the repo's group: %w", err)
		}
	}
	if err := repo.callLifecycle(ctx, evsActivateCall(repoId)); err != nil {
		return nil, err
	}
	if self.args.RepoCreated != nil {
		created := &EvsRepoCreated{
			RepoId:        repoId,
			Kind:          args.Kind,
			OwnerMemberId: args.OwnerMemberId,
			DisplayName:   args.DisplayName,
			Private:       args.Private,
			GroupInbox:    args.inboxRole() == protocol.RepoInbox_REPO_INBOX_GROUP || args.inboxRole() == protocol.RepoInbox_REPO_INBOX_ADMIN,
			Confirmed:     args.Confirmed,
		}
		if err := self.args.RepoCreated(ctx, created); err != nil {
			return repo, fmt.Errorf("evs: the repo's directory item: %w", err)
		}
	}
	return repo, nil
}

// Nil where this sidecar's verified state has the agent_repos feature on (DESIGN-COMPUTE §16.6); else an error wrapping
// ErrAuthFeatureOff, ErrEvsNoConfig before a verified state, so no RepoCreate of the feature's kinds or marker is filed
// for every reader to refuse.
func (self *EvsClient) checkAgentReposOn() error {
	if self.args.Config == nil {
		return ErrEvsNoConfig
	}
	view := self.args.Config()
	if view == nil {
		return ErrEvsNoConfig
	}
	state, ok := view.(interface{ AuthFeatureOn(AuthFeature) bool })
	if !ok || !state.AuthFeatureOn(AuthFeatureAgentRepos) {
		return fmt.Errorf("evs: %w: %s is not on for this network", ErrAuthFeatureOff, AuthFeatureAgentRepos)
	}
	return nil
}

// CreateRepo's filing and placement, answering the id placed: RepoCreate for a new random id, then PUT
// /evs/v1/repos/<id>. On 409 REPO_PLACED, the id another creator placed first (§11.8's place row; QD-927), both go
// again under another id, at most RepoPlacedRetryCount times, the id given up keeping only its RepoCreate; a lifecycle
// 409 such as STATEMENT_MISSING keeps the id, as callLifecycle waits it out. A create resuming ResumeRepoId filed its
// RepoCreate before and places that id alone, so its REPO_PLACED is the caller's error, as is the last past the
// retries.
func (self *EvsClient) placeRepo(ctx context.Context, args *EvsCreateRepoArgs) (Id, error) {
	if args.ResumeRepoId != nil {
		repoId := *args.ResumeRepoId
		return repoId, self.Repo(repoId).callLifecycle(ctx, evsPlaceCall(repoId))
	}
	for retryCount := 0; ; retryCount += 1 {
		repoId := NewEvsRepoId()
		if args.proposedRepoId != nil {
			repoId = *args.proposedRepoId
		}
		create := &protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: args.Kind, Inbox: args.inboxRole(), LabelMac: bytes.Clone(args.LabelMac)}
		if err := self.args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_CREATE, create); err != nil {
			return Id{}, fmt.Errorf("evs: RepoCreate: %w", err)
		}
		err := self.Repo(repoId).callLifecycle(ctx, evsPlaceCall(repoId))
		if args.proposedRepoId != nil || !IsEvsRepoPlaced(err) || self.settings.RepoPlacedRetryCount <= retryCount {
			return repoId, err
		}
		self.log.Warningf("[evs]repo %s is placed by another creator: creating under another id", repoId)
	}
}

// PUT /evs/v1/repos/<id>: places repoId and writes its repo/ (§11.8's place row).
func evsPlaceCall(repoId Id) *evsCall {
	return &evsCall{
		route:  "PUT /evs/v1/repos/{repo_id}",
		method: http.MethodPut,
		path:   "/evs/v1/repos/" + evsUrlId(repoId),
		repoId: repoId,
		role:   evsScopeAdmin,
	}
}

// POST /evs/v1/repos/<id>/activate: keying to active once the repo's group has its first generation (§11.12's
// activate row).
func evsActivateCall(repoId Id) *evsCall {
	return &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/activate",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/activate",
		repoId: repoId,
		role:   evsScopeAdmin,
	}
}

// Whether this sidecar holds no leaf at its verified state, a tagged or an ephemeral one, so a member device forms
// the groups of the repos it creates (QD-638). False with no state, whose CreateGroup refuses for such a sidecar.
func (self *EvsClient) holdsNoLeaf() bool {
	if client, ok := self.args.Gkm.(interface{ KeyDeliveryOnly() bool }); ok && client.KeyDeliveryOnly() {
		return false
	}
	if self.args.Config == nil || self.args.Identity == nil {
		return false
	}
	state := self.args.Config()
	identity := self.args.Identity()
	if state == nil || identity == nil {
		return false
	}
	row := state.SidecarRow(identity.SidecarId)
	return row != nil && (0 < len(row.GetTagIds()) || row.GetEphemeral())
}

// Waits for this sidecar's generation 1 of repoId, the wrap the member device that forms the group stages to it:
// asked again after GroupFormWait, at most GroupFormWaitCount times, then ErrEvsRepoKeying with what gkm answered, the
// repo left keying for a CreateRepo with ResumeRepoId.
func (self *EvsClient) awaitFirstGeneration(ctx context.Context, repoId Id) error {
	for waits := 0; ; waits += 1 {
		key, err := self.args.Gkm.CurrentRepoKey(ctx, repoId)
		if err == nil && key != nil {
			return nil
		}
		if self.settings.GroupFormWaitCount <= waits {
			return fmt.Errorf("%w: repo %s: %w", ErrEvsRepoKeying, repoId, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.clock.After(self.settings.GroupFormWait):
		}
	}
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
