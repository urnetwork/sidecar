// Each hosted network's key and evs clients (QD-804; KEYS-M2-22, EVS1-M2-22, QD-796): ur daemon builds, for every network
// it hosts, the network's GkmGroupClient over its MLS engine, a GkmApi and the key upkeep, an EvsClient over that key
// client with its evs component and its local git tier, and the config repo's head reader over that EvsClient
// (sidecar.EvsConfigHeadReader), and fills three hooks with them:
//
//	urDaemonGkmClient    the key client: the config follower's, which hands it each verified state once it stands, and
//	                     its rows-only states unconfirmed while it joins, and takes the config repo's generation keys
//	                     from it (RepoKeyAt), and ur keys rotate's
//	urDaemonConfigHeads  the head reader the follower checks each base's head through, on the EvsClient over the key
//	                     client urDaemonGkmClient gives: a daemon with either hook unset withholds every base
//	urDaemonEvsClient    the EvsClient, for git's service, a mount's git hooks, ur mount and the ur evs commands, once
//	                     the network's follower stands; before that each refuses, naming what the follower waits for
//
// The EvsClient judges statements at the follower's newest verified state, a start's own included
// (SidecarConfigFollower.VerifiedState), since a base's head is checked on the state the base lands on while the follower
// catches up; nothing but the head reader reaches the EvsClient before the follower stands. The key client takes a state
// only from the follower, so no state below the anchored head moves a key flow.
//
// A device joining its network (QD-817), which holds no generation of the config repo yet, gets the follower's
// rows-only states before it stands (sidecar.GkmConfigJoiner, which the key client is): kept as unconfirmed, they choose
// its group client, build its MLS engine under the admission they name, give the upkeep its member-device role, so its
// KeyPackages reach gkm (F1's order), and check the credentials of the config group's leaves, and the group client takes
// them for the config group's Welcome or wrap alone. Every other act of the key client waits for the first verified
// state. Asked whether the config key is held before its group client is built, the key client reads the keychain
// itself (Sidecar.GkmRepoKeyHeld), so a restart that holds the key keeps the full check from base 1.
//
//	intake   the network's GkmApi, its gkm hint intake and the key upkeep, built at the first client generation once
//	         the Sidecar knows its network and identity; the upkeep keeps KeyPackages at gkm only while the newest state
//	         makes this device a standing member device, and the api's repo scopes follow each state the key client
//	         is given (GkmApi.SetRepoScopes)
//	group    the GkmGroupClient, chosen from this sidecar's row at the first verified state that names it, the key
//	         client's newest or else the follower's: an untagged member device that is not ephemeral holds a leaf and
//	         gets the network's MLS engine, a tagged or ephemeral sidecar holds wraps only and gets none (§7.9's leaves
//	         row, §10.5), so it commits nothing and rotates by wraps; before its row, the Genesis's owner sidecar, the
//	         network's first device, holds a leaf. Before any state names it the key client answers ErrGkmUnavailable,
//	         a generation in the keychain included, which no device holds before a state names it
//	mls      the network's MLS engine, built at its first need under the admission the key client's newest state
//	         names (§10.4's admission_sha256): the row's, its SidecarAdmit or, for the network's first device, the
//	         Genesis's own hash, A_0, which base 1's compile gives its row (QD-825); before base 1, when that device
//	         has no row yet, the same A_0 from its anchor
//	git      the EvsClient's local tier, whose mounts' hooks exec the daemon's own ur git-hook, so a push reaches evs
//	         through this daemon; with no hook command every push is refused at its hook
//
// A network's clients are made at the first hook call for its Sidecar; their component ("daemon-clients") feeds each
// generation's gkm hints to the intake and ends them with the Sidecar.
//
// Not built here, each failing closed: the statement poster (CORE-M2-02's evs FileStatement), so a repo's create,
// delete and restore refuse; the readers' committer lookup, so a commit by another of this sidecar's clients is refused;
// a member's recovery key, so a rotation refuses where a member holds a recovery identity; and the current ReaderKey's
// digest, so a late ask names none. Not built and open: HeadCheck's witness stop (the key client's SealAllowed and
// ReportFork), which no host runs yet, so an unwitnessed device's sealing does not stop.

package main

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The component that feeds a network's clients each client generation's gkm hints and ends them with the Sidecar.
const urNetworkClientsComponentName = "daemon-clients"

// The local git tier's HOME under the instance's state directory, which every network's git commands share: it holds
// no config.
const urLocalGitHomeDirectoryName = "git-home"

var (
	// urDaemonGkmClient is unset, so the network's EvsClient and head reader are not built.
	errUrNoKeyClient = errors.New("this daemon builds no key client for the network, so it reads no repo")
	// What urDaemonEvsClient answers until the network's config follower stands.
	errUrEvsNotFollowing = errors.New("this network's evs client waits for its config follower to stand")
	// The network's clients ended with its Sidecar.
	errUrClientsClosed = errors.New("this network's clients have closed")
	// The MLS engine's admission is not the one the newest state names for this sidecar.
	errUrMlsAdmissionMoved = errors.New("this sidecar's admission is not the one its MLS engine was built under")
	// No verified state names this sidecar yet, so its key client is not chosen.
	errUrKeysUnchosen = fmt.Errorf("%w: no verified state names this sidecar yet", sidecar.ErrGkmUnavailable)
)

func init() {
	urDaemonGkmClient = urNetworkGkmClient
	urDaemonConfigHeads = urNetworkConfigHeadReader
	urDaemonEvsClient = urNetworkEvsClient
}

// What ur daemon gives every network's clients: where the local git tier keeps its trees, the git it runs and what its
// hooks exec, and the log. Nil, as in a test that sets none, builds no local tier, so git's service refuses with the
// EvsClient's own reason.
type urDaemonClientsArgs struct {
	// The instance's state directory, <state> (§5.9), under which each network's plaintext git tree is, and the git
	// tier's HOME. Empty builds no local tier.
	StateDirectory string
	// The system git's absolute path. Empty, git not found, builds no local tier.
	GitPath string
	// What each mount's pre-receive and proc-receive hook files exec, the hook's name appended, and the variables
	// git-receive-pack adds for them (EvsMounts.SetHookCommand): the daemon's own ur and git-hook, with UR_INSTANCE
	// naming its instance. Empty writes hooks that refuse every push.
	HookCommand     []string
	HookEnvironment []string
	Log             sidecar.Logger
}

// The hook command and environment ur daemon gives its mounts: executable git-hook, under instance.
func urDaemonGitHookCommand(executable string, instance string) ([]string, []string) {
	return []string{executable, "git-hook"}, []string{"UR_INSTANCE=" + instance}
}

// Set by ur daemon before it starts a Sidecar; nil for none.
var urDaemonClients *urDaemonClientsArgs

// Each running Sidecar's clients, made at the first hook call for it and dropped when it closes.
var (
	urNetworkClientsLock      sync.Mutex
	urNetworkClientsBySidecar = map[*sidecar.Sidecar]*urNetworkClients{}
)

// urDaemonGkmClient's: the network's key client, which builds its group client at its first need.
func urNetworkGkmClient(running *sidecar.Sidecar) (sidecar.GkmClient, error) {
	clients, err := urNetworkClientsOf(running)
	if err != nil {
		return nil, err
	}
	return clients.gkm, nil
}

// urDaemonConfigHeads's: the network's head reader over evs, nil once the Sidecar closed, which withholds every base.
func urNetworkConfigHeadReader(running *sidecar.Sidecar) sidecar.ConfigHeadReader {
	clients, err := urNetworkClientsOf(running)
	if err != nil {
		return nil
	}
	return clients.heads
}

// urDaemonEvsClient's: the network's EvsClient once its config follower stands, so nothing on this device judges a
// statement by a log below the one its enrollment vouched for. Before, it refuses, naming what the follower waits for
// or why it refused.
func urNetworkEvsClient(running *sidecar.Sidecar) (*sidecar.EvsClient, error) {
	follower := running.ConfigFollower()
	if follower == nil {
		return nil, fmt.Errorf("%w: it runs no config follower", errUrEvsNotFollowing)
	}
	if follower.Client() == nil {
		status := follower.Status()
		reason := string(status.State)
		if status.Reason != "" {
			reason += ": " + status.Reason
		}
		return nil, fmt.Errorf("%w (%s)", errUrEvsNotFollowing, reason)
	}
	clients, err := urNetworkClientsOf(running)
	if err != nil {
		return nil, err
	}
	return clients.evsClient()
}

// running's clients, made at the first call with their component on the Sidecar, and kept until it closes;
// ErrSidecarClosed once it has.
func urNetworkClientsOf(running *sidecar.Sidecar) (*urNetworkClients, error) {
	urNetworkClientsLock.Lock()
	defer urNetworkClientsLock.Unlock()
	if clients := urNetworkClientsBySidecar[running]; clients != nil {
		return clients, nil
	}
	clients := newUrNetworkClients(running, urDaemonClients, urDaemonGkmClient)
	if _, err := running.AddComponent(&urNetworkClientsComponent{clients: clients}); err != nil {
		clients.cancel()
		return nil, err
	}
	urNetworkClientsBySidecar[running] = clients
	return clients, nil
}

// One network's key and evs clients (the file's comment). Safe for concurrent use.
type urNetworkClients struct {
	running *sidecar.Sidecar
	// nil builds no local git tier
	args *urDaemonClientsArgs
	// urDaemonGkmClient as it stood when these clients were made, which the EvsClient's key client comes from: nil
	// builds no EvsClient. Taken once, so no goroutine of the clients reads the hook itself
	gkmHook func(running *sidecar.Sidecar) (sidecar.GkmClient, error)
	log     sidecar.Logger
	// ends the hint intake, the upkeep and the key client's timers
	ctx    context.Context
	cancel context.CancelFunc
	// what the hooks answer, and the MLS engine the group client runs on, each building what it needs at first need
	gkm   *urNetworkGkm
	heads *urNetworkConfigHeads
	mls   *urNetworkMls

	// held across building the group client, the intake and the EvsClient, taken in that order and never under
	// stateLock: the group client's build builds the intake it needs
	groupLock  sync.Mutex
	intakeLock sync.Mutex
	evsLock    sync.Mutex
	// held across computing and setting the GkmApi's repo scopes, so the last to set them read the newest state
	scopesLock sync.Mutex

	stateLock sync.Mutex
	closed    bool
	api       *sidecar.GkmApi
	// the GkmApi's clock, which a scope's grant is judged at
	clock  sidecar.Clock
	hints  *sidecar.GkmHints
	upkeep *sidecar.GkmUpkeep
	group  *sidecar.GkmGroupClient
	// closed once group is built, so a follower asking whether the config key is held asks the group client next
	groupBuiltSignal chan struct{}
	// whether the group client holds a leaf, chosen at its build (leafChoice)
	leaf bool
	evs  *sidecar.EvsClient
	// the head reader, over the config repo the trusted genesis names
	reader       *sidecar.EvsConfigHeadReader
	readerRepoId sidecar.Id
}

// running's clients, nothing built yet, the EvsClient's key client to come from gkmHook.
func newUrNetworkClients(running *sidecar.Sidecar, args *urDaemonClientsArgs, gkmHook func(running *sidecar.Sidecar) (sidecar.GkmClient, error)) *urNetworkClients {
	ctx, cancel := context.WithCancel(context.Background())
	log := sidecar.NewNoopLogger()
	if args != nil && args.Log != nil {
		log = args.Log
	}
	self := &urNetworkClients{
		running: running, args: args, gkmHook: gkmHook, log: log, ctx: ctx, cancel: cancel,
		groupBuiltSignal: make(chan struct{}),
	}
	self.gkm = &urNetworkGkm{clients: self}
	self.heads = &urNetworkConfigHeads{clients: self}
	self.mls = &urNetworkMls{clients: self}
	return self
}

// Ends the clients: the hint intake, the upkeep and the key client's timers stop, and the hooks build nothing more for
// this Sidecar. The evs component ends with the Sidecar on its own.
func (self *urNetworkClients) close() {
	var hints *sidecar.GkmHints
	var upkeep *sidecar.GkmUpkeep
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		hints, upkeep = self.hints, self.upkeep
		return true
	}()
	if !closed {
		return
	}
	self.cancel()
	if upkeep != nil {
		upkeep.Close()
	}
	if hints != nil {
		hints.Close()
	}
	urNetworkClientsLock.Lock()
	defer urNetworkClientsLock.Unlock()
	if urNetworkClientsBySidecar[self.running] == self {
		delete(urNetworkClientsBySidecar, self.running)
	}
}

// The group client, nil before it is built.
func (self *urNetworkClients) builtGroup() *sidecar.GkmGroupClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.group
}

// A channel closed once the group client is built.
func (self *urNetworkClients) groupBuilt() <-chan struct{} {
	return self.groupBuiltSignal
}

// The network's GkmApi, gkm hint intake and key upkeep, built at the first call once the Sidecar knows its network and
// identity: what the key client runs on whatever this sidecar's row says. The upkeep keeps KeyPackages at gkm only
// while the newest state makes this device a standing member device (upkeepRole), and acks the groups the group client
// holds once it is built.
func (self *urNetworkClients) intake() (*sidecar.GkmApi, *sidecar.GkmHints, error) {
	self.intakeLock.Lock()
	defer self.intakeLock.Unlock()
	api, hints, closed := func() (*sidecar.GkmApi, *sidecar.GkmHints, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.api, self.hints, self.closed
	}()
	if closed {
		return nil, nil, errUrClientsClosed
	}
	if hints != nil {
		return api, hints, nil
	}
	apiArgs, err := self.running.GkmApiArgs()
	if err != nil {
		return nil, nil, err
	}
	api, err = sidecar.NewGkmApi(apiArgs)
	if err != nil {
		return nil, nil, err
	}
	hints, err = sidecar.NewGkmHints(self.ctx, &sidecar.GkmHintsArgs{Settings: apiArgs.Settings, Clock: apiArgs.Clock, Log: self.log})
	if err != nil {
		return nil, nil, err
	}
	upkeepArgs, err := self.running.GkmUpkeepArgs(api, hints)
	if err != nil {
		hints.Close()
		return nil, nil, err
	}
	upkeepArgs.CreateKeyPackage = self.mls.CreateKeyPackage
	upkeepArgs.Role = self.upkeepRole
	upkeepArgs.AckGroups = self.ackGroups
	upkeep, err := sidecar.NewGkmUpkeep(self.ctx, upkeepArgs)
	if err != nil {
		hints.Close()
		return nil, nil, err
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.api, self.hints, self.upkeep, self.clock = api, hints, upkeep, apiArgs.Clock
		return true
	}()
	if !kept {
		upkeep.Close()
		hints.Close()
		return nil, nil, errUrClientsClosed
	}
	self.setRepoScopes()
	return api, hints, nil
}

// Hands the GkmApi the repo scopes the newest state the key client was given grants this sidecar at gkm, each repo's
// strongest role by §8's table (AclState.EvsAccess for gkm's audience, as the exchange grants them), so its tokens
// carry them in batches; nothing before the api or a state. A role the state no longer grants leaves the batches, and
// a call presents its own scope where its repo is in none.
func (self *urNetworkClients) setRepoScopes() {
	self.scopesLock.Lock()
	defer self.scopesLock.Unlock()
	api, clock := func() (*sidecar.GkmApi, sidecar.Clock) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.api, self.clock
	}()
	state, ok := self.gkm.newestState().(*sidecar.ConfigState)
	identity := self.running.Identity()
	if api == nil || !ok || identity == nil {
		return
	}
	acl, err := state.Acl()
	if err != nil {
		return
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	now := clock.Now()
	subject := sidecar.AclSidecarSubject(identity.SidecarId)
	scopes := []sidecar.GkmRepoScope{}
	for _, repoId := range acl.RepoIds() {
		rights := acl.EvsAccess(subject, repoId, sidecar.AclTokenAudienceGkm, now).Rights
		role := ""
		switch {
		case rights.Has(sidecar.AclEvsAdmin):
			role = sidecar.GkmScopeRoleAdmin
		case rights.Has(sidecar.AclEvsWrite):
			role = sidecar.GkmScopeRoleWrite
		case rights.Has(sidecar.AclEvsRead):
			role = sidecar.GkmScopeRoleRead
		case rights.Has(sidecar.AclEvsDeposit):
			role = sidecar.GkmScopeRoleDeposit
		default:
			continue
		}
		scopes = append(scopes, sidecar.GkmRepoScope{RepoId: repoId, Role: role})
	}
	api.SetRepoScopes(scopes)
}

// The network's group client, built at the first call once a verified state names this sidecar (leafChoice), or a
// joining device's unconfirmed one (QD-817), over the intake's GkmApi and hints: with the network's MLS engine for a
// device that holds a leaf, with none for a tagged or ephemeral sidecar, which holds wraps only. It is handed the newest
// state the key client was given, a verified one as AuthAdvanced, an unconfirmed one as AuthUnconfirmed.
// errUrKeysUnchosen before a state names this sidecar.
func (self *urNetworkClients) groupClient() (*sidecar.GkmGroupClient, error) {
	self.groupLock.Lock()
	defer self.groupLock.Unlock()
	group, closed := func() (*sidecar.GkmGroupClient, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.group, self.closed
	}()
	if closed {
		return nil, errUrClientsClosed
	}
	if group != nil {
		return group, nil
	}
	api, hints, err := self.intake()
	if err != nil {
		return nil, err
	}
	leaf, named := self.leafChoice()
	if !named {
		return nil, errUrKeysUnchosen
	}
	// a nil engine, not a nil *urNetworkMls in the interface, for a sidecar that holds no leaf
	var mls sidecar.MlsEngine
	if leaf {
		mls = self.mls
	}
	groupArgs, err := self.running.GkmGroupClientArgs(api, mls)
	if err != nil {
		return nil, err
	}
	groupArgs.ReaderPrivateKey = self.readerPrivateKey
	groupArgs.ReaderRepoIds = self.readerRepoIds
	group, err = sidecar.NewGkmGroupClient(groupArgs)
	if err != nil {
		return nil, err
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.group, self.leaf = group, leaf
		return true
	}()
	if !kept {
		return nil, errUrClientsClosed
	}
	group.AttachHints(self.ctx, hints)
	switch state, configRepoId, confirmed := self.gkm.joiningState(); {
	case state == nil:
	case confirmed:
		group.AuthAdvanced(state)
	default:
		group.AuthUnconfirmed(state, configRepoId)
	}
	// built under groupLock, so this closes once
	close(self.groupBuiltSignal)
	return group, nil
}

// Whether this sidecar holds a leaf, from its row at the newest state that names it, the key client's newest, a joining
// device's unconfirmed one included (QD-817), and else the follower's, a start's own included: a member device that is
// untagged and not ephemeral does, a tagged or ephemeral sidecar does not (§7.9's leaves row); before its row, the
// Genesis's owner sidecar, the network's first device, does. named is false while no state names it. A row's tags and
// ephemeral flag never change, so the choice stands for the clients' life.
func (self *urNetworkClients) leafChoice() (leaf bool, named bool) {
	identity := self.running.Identity()
	if identity == nil {
		return false, false
	}
	joining, _, _ := self.gkm.joiningState()
	for _, state := range []sidecar.GkmAuthView{joining, self.verifiedConfig()} {
		if state == nil {
			continue
		}
		if row := state.SidecarRow(identity.SidecarId); row != nil {
			return urRowHoldsLeaf(row), true
		}
		if urGenesisOwner(state, identity.SidecarId) {
			return true, true
		}
	}
	return false, false
}

// Whether a row is a member device's, which holds leaves (§7.9's leaves row): untagged, naming a member, not ephemeral.
func urRowHoldsLeaf(row *bridge.SidecarRow) bool {
	return len(row.GetTagIds()) == 0 && !row.GetEphemeral() && len(row.GetMemberId()) == len(sidecar.Id{})
}

// Whether the state's Genesis names sidecarId as its owner's sidecar: the network's first device (§7.9's bootstrap).
func urGenesisOwner(state sidecar.GkmAuthView, sidecarId sidecar.Id) bool {
	withGenesis, ok := state.(interface{ Genesis() *bridge.Genesis })
	if !ok {
		return false
	}
	return bytes.Equal(withGenesis.Genesis().GetOwnerSidecarId(), sidecarId.Bytes())
}

// The groups the group client holds, for the upkeep's acks: none before it is built.
func (self *urNetworkClients) ackGroups() []*sidecar.GkmAckGroup {
	group := self.builtGroup()
	if group == nil {
		return nil
	}
	return group.AckGroups()
}

// The private key of a ReaderKey this sidecar signed, by its digest, from the upkeep that keeps them.
func (self *urNetworkClients) readerPrivateKey(keySha256 []byte) (hpke.PrivateKey, error) {
	upkeep := func() *sidecar.GkmUpkeep {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.upkeep
	}()
	if upkeep == nil {
		return nil, sidecar.ErrGkmKeyMissing
	}
	return upkeep.ReaderPrivateKey(keySha256)
}

// This sidecar's row at the newest state the key client was given, a joining device's unconfirmed one included
// (QD-817), nil before one or for a sidecar it does not admit.
func (self *urNetworkClients) sidecarRow() *bridge.SidecarRow {
	state, _, _ := self.gkm.joiningState()
	identity := self.running.Identity()
	if state == nil || identity == nil {
		return nil
	}
	return state.SidecarRow(identity.SidecarId)
}

// What the upkeep keeps at gkm for this device: KeyPackages once the newest state admits it as an untagged, standing
// member device (§10.6), a joining device's unconfirmed state included, since F1 has a new device upload them before
// it reads the config back to genesis and its admitter claims one for the config group's Add (QD-817); held back while
// a restored binding's admission waits for its anchor (§10.8).
func (self *urNetworkClients) upkeepRole() sidecar.GkmUpkeepRole {
	role := sidecar.GkmUpkeepRole{AwaitingAnchor: self.running.RecoveryAwaitingAnchor()}
	row := self.sidecarRow()
	role.MemberDevice = row != nil && row.GetRevokedAt() == 0 && urRowHoldsLeaf(row)
	if group := self.builtGroup(); group != nil {
		role.LastResortJoinedAt = group.LastResortJoinedAt()
	}
	return role
}

// The admission this sidecar's MLS engine is built under (§10.4's admission_sha256), at the newest state the key client
// was given: its row's, the hash of the SidecarAdmit that admitted it or, for the network's first device, the Genesis's
// own hash A_0, which base 1's compile gives its row (QD-825; §10.4: "Genesis for the first device"). Before base 1 the
// first device has no row, and the hash is the same A_0 from the anchor its follower holds the log to. A joining
// device's engine is built under its unconfirmed state's row (QD-817), to take the config group's Welcome; a verified
// state naming another admission refuses the engine after (errUrMlsAdmissionMoved). ErrGkmUnavailable before a state
// admits this sidecar, and for a tagged or ephemeral sidecar, which holds no leaf.
func (self *urNetworkClients) admission() ([]byte, error) {
	state, _, _ := self.gkm.joiningState()
	identity := self.running.Identity()
	if state == nil || identity == nil {
		return nil, fmt.Errorf("%w: no verified state admits this sidecar yet", sidecar.ErrGkmUnavailable)
	}
	row := state.SidecarRow(identity.SidecarId)
	if row != nil && !urRowHoldsLeaf(row) {
		return nil, fmt.Errorf("%w: a tagged or ephemeral sidecar holds no leaf", sidecar.ErrGkmUnavailable)
	}
	if row != nil && len(row.GetAdmissionSha256()) == sha256.Size {
		return bytes.Clone(row.GetAdmissionSha256()), nil
	}
	if !urGenesisOwner(state, identity.SidecarId) {
		return nil, fmt.Errorf("%w: no verified state admits this sidecar yet", sidecar.ErrGkmUnavailable)
	}
	anchor, err := self.running.Anchor()
	if err != nil || len(anchor.GenesisSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: the network's first device holds no anchor of its Genesis", sidecar.ErrGkmUnavailable)
	}
	return bytes.Clone(anchor.GenesisSha256), nil
}

// The repos this sidecar reads at the newest state the key client was given, where a Welcome's group is looked for:
// the config repo and each repo of the state's rows whose readers name it.
func (self *urNetworkClients) readerRepoIds() []sidecar.Id {
	view := self.gkm.newestState()
	identity := self.running.Identity()
	state, ok := view.(*sidecar.ConfigState)
	if !ok || identity == nil {
		return nil
	}
	candidates := []sidecar.Id{}
	if configRepoId, err := sidecar.IdFromBytes(state.Genesis().GetConfigRepoId()); err == nil {
		candidates = append(candidates, configRepoId)
	}
	if acl, err := state.Acl(); err == nil {
		for _, repo := range acl.Rows().GetRepos() {
			if repoId, err := sidecar.IdFromBytes(repo.GetRepoId()); err == nil {
				candidates = append(candidates, repoId)
			}
		}
	}
	repoIds := []sidecar.Id{}
	for _, repoId := range candidates {
		if !slices.Contains(repoIds, repoId) && slices.Contains(state.RepoReaders(repoId), identity.SidecarId) {
			repoIds = append(repoIds, repoId)
		}
	}
	return repoIds
}

// The follower's newest verified state, a start's own included, as the EvsClient's Config: nil before it holds one,
// after it refused and once it closed.
func (self *urNetworkClients) verifiedConfig() sidecar.GkmAuthView {
	follower := self.running.ConfigFollower()
	if follower == nil {
		return nil
	}
	state := follower.VerifiedState()
	if state == nil {
		return nil
	}
	return state
}

// This device's epoch pin for a group it is a leaf of, which a push's sealed metadata carries for HeadCheck.
func (self *urNetworkClients) groupHead(groupId sidecar.Id) (*protocol.GroupHead, bool) {
	group := self.builtGroup()
	if group == nil {
		return nil, false
	}
	return group.GroupHead(groupId)
}

// The network's EvsClient, built at the first call over the key client gkmHook gives, judging statements at
// the follower's newest verified state (verifiedConfig), with its evs component on the Sidecar's generations and, where
// the daemon gave a state directory and found a git, its local git tier. errUrNoKeyClient with the hook unset.
func (self *urNetworkClients) evsClient() (*sidecar.EvsClient, error) {
	self.evsLock.Lock()
	defer self.evsLock.Unlock()
	client, closed := func() (*sidecar.EvsClient, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.evs, self.closed
	}()
	if closed {
		return nil, errUrClientsClosed
	}
	if client != nil {
		return client, nil
	}
	if self.gkmHook == nil {
		return nil, errUrNoKeyClient
	}
	gkm, err := self.gkmHook(self.running)
	if err != nil {
		return nil, err
	}
	args, err := self.running.EvsClientArgs(gkm, self.verifiedConfig, nil)
	if err != nil {
		return nil, err
	}
	args.GroupHead = self.groupHead
	client, err = sidecar.NewEvsClient(args)
	if err != nil {
		return nil, err
	}
	// the repo's prefix write rules, read and written through this Sidecar's follower (DESIGN-DETAILS 16.2.5, 16.2.7)
	prefixRules := self.running.EvsPrefixRulesArgs()
	// the daemon is a desktop's: it repairs what its mirrors journal (16.2.8's who)
	prefixRules.Repair = true
	client.EnablePrefixRules(prefixRules)
	if err := self.startLocalTier(client, args); err != nil {
		// git's service refuses for want of the tier, naming it, and the rest of evs runs on
		self.log.Warningf("[ur]network %s serves no local git tier: %s", client.NetworkId(), err)
	}
	if _, err := self.running.AddComponent(sidecar.NewEvsComponent(client)); err != nil {
		client.Close()
		return nil, err
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.evs = client
		return true
	}()
	if !kept {
		// the Sidecar closed meanwhile, and its component with it
		return nil, errUrClientsClosed
	}
	return client, nil
}

// The local git tier on client (§11.11): the mount registry under the instance's state directory, reopened from its
// records, run by the system git with a HOME of the daemon's, its committer check knowing this sidecar's own clients,
// and each mount's hooks exec'ing the daemon's hook command, written before the records reopen so every mount's
// hooks are this daemon's. Nothing where the daemon gave no state directory or found no git.
func (self *urNetworkClients) startLocalTier(client *sidecar.EvsClient, args *sidecar.EvsClientArgs) error {
	if self.args == nil || self.args.StateDirectory == "" || self.args.GitPath == "" {
		return nil
	}
	home := filepath.Join(self.args.StateDirectory, urLocalGitHomeDirectoryName)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	git, err := sidecar.NewEvsGitRunner(self.ctx, self.args.GitPath, home, args.Settings, args.Clock)
	if err != nil {
		return err
	}
	mounts, err := sidecar.NewEvsMounts(client, self.args.StateDirectory, git)
	if err != nil {
		return err
	}
	mounts.SetOwnClients(self.running.ClientIds)
	if 0 < len(self.args.HookCommand) {
		if err := mounts.SetHookCommand(self.args.HookCommand, self.args.HookEnvironment); err != nil {
			return err
		}
	}
	return mounts.Load(self.ctx)
}

// The head reader over the config repo genesis names, or, with nil, the one the follower's newest verified state's
// genesis names: built at the first call on the network's EvsClient. A read it cannot make is unavailable, which
// withholds the base.
func (self *urNetworkClients) headReader(genesis *bridge.Genesis) (*sidecar.EvsConfigHeadReader, error) {
	unavailable := func(what string, err error) error {
		if err == nil {
			return fmt.Errorf("%w: %s", sidecar.ErrConfigHeadUnavailable, what)
		}
		return fmt.Errorf("%w: %s: %w", sidecar.ErrConfigHeadUnavailable, what, err)
	}
	if genesis == nil {
		follower := self.running.ConfigFollower()
		if follower == nil {
			return nil, unavailable("no config follower runs", nil)
		}
		state := follower.VerifiedState()
		if state == nil {
			return nil, unavailable("no verified state names the config repo yet", nil)
		}
		genesis = state.Genesis()
	}
	configRepoId, err := sidecar.IdFromBytes(genesis.GetConfigRepoId())
	if err != nil {
		return nil, unavailable("the genesis names no config repo", err)
	}
	client, err := self.evsClient()
	if err != nil {
		return nil, unavailable("no evs client", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.reader != nil {
		if self.readerRepoId != configRepoId {
			// a network's genesis never changes, so another config repo is no head of this network's
			return nil, unavailable("another config repo than the one this network's reader reads", nil)
		}
		return self.reader, nil
	}
	reader, err := sidecar.NewEvsConfigHeadReader(&sidecar.EvsConfigHeadReaderArgs{Repo: client.Repo(configRepoId)})
	if err != nil {
		return nil, unavailable("the head reader", err)
	}
	self.reader, self.readerRepoId = reader, configRepoId
	return reader, nil
}

// The component on the Sidecar: each client generation's gkm hints go to the key client's intake, and the Sidecar's
// close ends the clients.
type urNetworkClientsComponent struct {
	clients *urNetworkClients
}

// "daemon-clients".
func (self *urNetworkClientsComponent) Name() string {
	return urNetworkClientsComponentName
}

// One generation: the intake is built if it is not, now that the Sidecar knows its network and identity, the group
// client too where a verified state names this sidecar already, as at a restart, and the generation's gkm and gkm:
// notices go to the hint intake until it ends. A generation whose dispatcher has no push client yet attaches without
// hints, which the intake's resync covers.
func (self *urNetworkClientsComponent) Attach(env *sidecar.SidecarEnv) error {
	_, hints, err := self.clients.intake()
	if err != nil {
		return err
	}
	if _, err := self.clients.groupClient(); err != nil && !errors.Is(err, errUrKeysUnchosen) && self.clients.log.V(1).Enabled() {
		self.clients.log.Infof("[ur]a network's group client is not built yet: %s", err)
	}
	if env.Subprotocol == nil {
		return nil
	}
	for _, topic := range []string{sidecar.PushTopicGkm, sidecar.PushTopicGkmGroupPrefix} {
		unsubscribe, err := env.Subprotocol.Subscribe(topic, hints.Receive)
		if err != nil {
			continue
		}
		go func() {
			<-env.Ctx.Done()
			unsubscribe()
		}()
	}
	return nil
}

// Ends the clients with the Sidecar.
func (self *urNetworkClientsComponent) Close() {
	self.clients.close()
}

// The key client urDaemonGkmClient answers for a network: the network's GkmGroupClient, built at the first call that
// needs it once a verified state names this sidecar (urNetworkClients.groupClient), ErrGkmUnavailable before. It keeps
// the newest state it was given, the follower's once it stands, which the MLS engine's admission, the upkeep's role and
// the repos the group client joins are read from; and, while the device joins its network (QD-817), the follower's
// newest rows-only state, which stands in for the first three until a verified state is given and reaches the group
// client for the config group's join alone.
type urNetworkGkm struct {
	clients *urNetworkClients

	stateLock sync.Mutex
	newest    sidecar.GkmAuthView
	// the follower's newest rows-only state before it stands, and the config repo it serves; nil once a verified state
	// is given
	unconfirmed             sidecar.GkmAuthView
	unconfirmedConfigRepoId sidecar.Id
}

var (
	_ sidecar.GkmClient       = (*urNetworkGkm)(nil)
	_ sidecar.GkmGroupDrafter = (*urNetworkGkm)(nil)
	_ sidecar.GkmConfigJoiner = (*urNetworkGkm)(nil)
)

// The newest verified state given, nil before one.
func (self *urNetworkGkm) newestState() sidecar.GkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.newest
}

// What a joining device's composition reads (QD-817): the newest verified state given, else the newest unconfirmed one
// with the config repo it serves; confirmed says which. A nil state before either.
func (self *urNetworkGkm) joiningState() (state sidecar.GkmAuthView, configRepoId sidecar.Id, confirmed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.newest != nil {
		return self.newest, sidecar.Id{}, true
	}
	return self.unconfirmed, self.unconfirmedConfigRepoId, false
}

// joiningState's state, which the MLS engine checks a leaf's credential at: a joining device takes the config group's
// Welcome before any verified state is given.
func (self *urNetworkGkm) joiningView() sidecar.GkmAuthView {
	state, _, _ := self.joiningState()
	return state
}

// The follower's rows-only state before it stands (sidecar.GkmConfigJoiner; QD-817): kept unless a verified state was
// given or a newer unconfirmed one was, and handed to the group client, built now where this state names this sidecar,
// for the config group's join alone. Never blocks on I/O.
func (self *urNetworkGkm) AuthUnconfirmed(state sidecar.GkmAuthView, configRepoId sidecar.Id) {
	if state == nil {
		return
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.newest != nil || self.unconfirmed != nil && state.Pin().GetVersion() <= self.unconfirmed.Pin().GetVersion() {
			return false
		}
		self.unconfirmed, self.unconfirmedConfigRepoId = state, configRepoId
		return true
	}()
	if !kept {
		return
	}
	if group, err := self.group(); err == nil {
		group.AuthUnconfirmed(state, configRepoId)
	}
}

// Whether the network's keychain holds a generation of the repo, and a channel closed once that may have changed
// (sidecar.GkmConfigJoiner): the group client's answer where it is built, else the keychain read with no key client
// (Sidecar.GkmRepoKeyHeld) and a channel closed once the group client is built, which the follower asks next.
func (self *urNetworkGkm) RepoKeyHeld(repoId sidecar.Id) (bool, <-chan struct{}) {
	// armed before the look, so a build between them wakes the follower to ask the group client
	built := self.clients.groupBuilt()
	if group := self.clients.builtGroup(); group != nil {
		return group.RepoKeyHeld(repoId)
	}
	return self.clients.running.GkmRepoKeyHeld(repoId), built
}

// The group client, building it where it is not built yet.
func (self *urNetworkGkm) group() (*sidecar.GkmGroupClient, error) {
	group, err := self.clients.groupClient()
	switch {
	case err == nil:
		return group, nil
	case errors.Is(err, sidecar.ErrGkmUnavailable):
		return nil, err
	}
	return nil, fmt.Errorf("%w: %w", sidecar.ErrGkmUnavailable, err)
}

// Keeps state when it is newer than the one held, and hands it to the group client, built now where it can be: a state
// given before the build is handed at it. Never blocks on I/O.
func (self *urNetworkGkm) AuthAdvanced(state sidecar.GkmAuthView) {
	if state == nil {
		return
	}
	advanced := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.newest != nil && state.Pin().GetVersion() <= self.newest.Pin().GetVersion() {
			return false
		}
		self.newest = state
		// a verified state supersedes the joining device's unconfirmed one
		self.unconfirmed, self.unconfirmedConfigRepoId = nil, sidecar.Id{}
		return true
	}()
	if !advanced {
		return
	}
	self.clients.setRepoScopes()
	if group, err := self.group(); err == nil {
		group.AuthAdvanced(state)
	}
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.CurrentRepoKey(ctx, repoId)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.RepoKey(ctx, repoId, generation)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.EnsureWritable(ctx, repoId)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.DropKey(ctx, repoId)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.CreateGroup(ctx, args)
}

// The group client's KF1 bootstrap draft (QD-824), for the network's first device before base 1: ErrGkmUnavailable
// before the group client is built.
func (self *urNetworkGkm) DraftGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.DraftGroup(ctx, args)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	group, err := self.group()
	if err != nil {
		return nil, err
	}
	return group.RotateRepo(ctx, repoId)
}

// The group client's, ErrGkmUnavailable before it is built.
func (self *urNetworkGkm) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	group, err := self.group()
	if err != nil {
		return err
	}
	return group.ForgetRepo(ctx, repoId)
}

// The network's MLS engine, built at the first call that needs it once the newest state the key client holds, a joining
// device's unconfirmed one included (QD-817), admits this sidecar as a member device, under the admission that state
// gives it (urNetworkClients.admission), on the network's store, checking each leaf's credential at that state:
// ErrGkmUnavailable before. The group client of a tagged or ephemeral sidecar is built with no engine (leafChoice), and
// this refuses one all the same; an admission the engine was not built under is refused. Both closed.
type urNetworkMls struct {
	clients *urNetworkClients

	stateLock       sync.Mutex
	engine          sidecar.MlsEngine
	admissionSha256 []byte
}

var _ sidecar.MlsEngine = (*urNetworkMls)(nil)

// The engine, built where it is not yet.
func (self *urNetworkMls) get() (sidecar.MlsEngine, error) {
	admissionSha256, err := self.clients.admission()
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.engine != nil {
		if !bytes.Equal(self.admissionSha256, admissionSha256) {
			return nil, errUrMlsAdmissionMoved
		}
		return self.engine, nil
	}
	args, err := self.clients.running.MlsEngineArgs(admissionSha256, sidecar.NewGkmCredentialCheck(self.clients.gkm.joiningView))
	if err != nil {
		return nil, err
	}
	engine, err := sidecar.NewMlsEngine(args)
	if err != nil {
		return nil, err
	}
	self.engine, self.admissionSha256 = engine, bytes.Clone(admissionSha256)
	return engine, nil
}

// The engine's, once it is built.
func (self *urNetworkMls) CreateKeyPackage(lastResort bool) (*sidecar.MlsKeyPackage, error) {
	engine, err := self.get()
	if err != nil {
		return nil, err
	}
	return engine.CreateKeyPackage(lastResort)
}

// The engine's, once it is built.
func (self *urNetworkMls) CreateGroup(groupId sidecar.Id, urGroup *sidecar.MlsUrGroup) (sidecar.MlsGroup, error) {
	engine, err := self.get()
	if err != nil {
		return nil, err
	}
	return engine.CreateGroup(groupId, urGroup)
}

// The engine's, once it is built.
func (self *urNetworkMls) JoinWelcome(welcome []byte) (sidecar.MlsPendingJoin, error) {
	engine, err := self.get()
	if err != nil {
		return nil, err
	}
	return engine.JoinWelcome(welcome)
}

// The engine's, once it is built.
func (self *urNetworkMls) JoinExternal(groupInfo []byte, args *sidecar.MlsCommitArgs) (sidecar.MlsStagedCommit, error) {
	engine, err := self.get()
	if err != nil {
		return nil, err
	}
	return engine.JoinExternal(groupInfo, args)
}

// The engine's, once it is built.
func (self *urNetworkMls) LoadGroup(groupId sidecar.Id) (sidecar.MlsGroup, error) {
	engine, err := self.get()
	if err != nil {
		return nil, err
	}
	return engine.LoadGroup(groupId)
}

// The head reader urDaemonConfigHeads answers for a network: sidecar.EvsConfigHeadReader over the network's EvsClient
// (evsClient, on the key client urDaemonGkmClient gives) and the config repo the trusted genesis names, built at the
// first read. A read it cannot make, with no key client, no EvsClient or no genesis known yet, is unavailable, which
// withholds the base.
type urNetworkConfigHeads struct {
	clients *urNetworkClients
}

var _ sidecar.ConfigHeadAnchorReader = (*urNetworkConfigHeads)(nil)

// The head at configVersion, each push after this device's pin judged at its own pin (ReadConfigHead).
func (self *urNetworkConfigHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	reader, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return reader.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The head the base a reader starts at names, judged by descent under anchor (QD-814; ReadConfigHeadAtAnchor), on the
// config repo anchor's genesis names.
func (self *urNetworkConfigHeads) ReadConfigHeadAtAnchor(ctx context.Context, configVersion uint64, configHeadSha256 []byte, anchor sidecar.ConfigHeadAnchor) (*sidecar.ConfigHead, error) {
	if anchor == nil {
		return nil, fmt.Errorf("%w: no base rows to judge the anchor's pushes by", sidecar.ErrConfigHeadUnavailable)
	}
	reader, err := self.clients.headReader(anchor.Genesis())
	if err != nil {
		return nil, err
	}
	return reader.ReadConfigHeadAtAnchor(ctx, configVersion, configHeadSha256, anchor)
}
