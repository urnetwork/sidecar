// Each hosted network's key and evs clients (QD-804; KEYS-M2-22, EVS1-M2-22, QD-796): ur daemon builds, for every network
// it hosts, the network's KeyDelivery group client over GkmApi, the ReaderKey upkeep, an EvsClient over that key
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
// A joining device can open its config group's first KeyDelivery against the follower's rows-only state. Its
// other repos wait for the full follower. The same group client forms, rotates and follows signed generations
// on every role. ReaderKey upkeep, token scopes and the member's verified recovery bindings follow the network.
//
// The EVS client's local-tier hooks run the daemon's ur git-hook. A push reaches the local daemon through them.
//
// A network's clients are made at the first hook call for its Sidecar; their component ("daemon-clients") feeds each
// generation's gkm hints to the intake and ends them with the Sidecar.
//

package main

import (
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
	// the per-network clients returned by the hooks
	gkm   *urNetworkGkm
	heads *urNetworkConfigHeads

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
	clock          sidecar.Clock
	hints          *sidecar.GkmHints
	upkeep         *sidecar.GkmUpkeep
	group          *sidecar.GkmGroupClient
	removeRecovery func()
	// closed once group is built, so a follower asking whether the config key is held asks the group client next
	groupBuiltSignal chan struct{}
	evs              *sidecar.EvsClient
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
	return self
}

// Ends the clients: the hint intake, the upkeep and the key client's timers stop, and the hooks build nothing more for
// this Sidecar. The evs component ends with the Sidecar on its own.
func (self *urNetworkClients) close() {
	var hints *sidecar.GkmHints
	var upkeep *sidecar.GkmUpkeep
	var removeRecovery func()
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		hints, upkeep, removeRecovery = self.hints, self.upkeep, self.removeRecovery
		return true
	}()
	if !closed {
		return
	}
	self.cancel()
	if removeRecovery != nil {
		removeRecovery()
	}
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
// identity. The upkeep publishes and renews the device's ReaderKey.
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
// a call presents its own scope where its repo is in none. A joining device's unconfirmed state asks for the config
// repo's alone (QD-817) so it can take its first wrap. The exchange judges those scopes on its own log.
func (self *urNetworkClients) setRepoScopes() {
	self.scopesLock.Lock()
	defer self.scopesLock.Unlock()
	api, clock := func() (*sidecar.GkmApi, sidecar.Clock) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.api, self.clock
	}()
	view, configRepoId, confirmed := self.gkm.joiningState()
	state, ok := view.(*sidecar.ConfigState)
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
		if !confirmed && repoId != configRepoId {
			continue
		}
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

// Builds the KeyDelivery client as soon as the network identity is available. First-owner drafting and recovery
// reads precede admission. Ordinary group operations enforce the verified state they need themselves.
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
	groupArgs, err := self.running.GkmGroupClientArgs(api, nil)
	if err != nil {
		return nil, err
	}
	groupArgs.ReaderPrivateKey = self.readerPrivateKey
	groupArgs.ReaderKeySha256 = self.upkeep.CurrentReaderKeySha256
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
		self.removeRecovery = self.running.InstallNetworkRecovery(group)
		self.group = group
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

// The repos this sidecar reads at the newest state the key client was given, where a Welcome's group is looked for:
// the config repo and each repo of the state's rows whose readers name it.
func (self *urNetworkClients) readerRepoIds() []sidecar.Id {
	view, joiningRepoId, confirmed := self.gkm.joiningState()
	if !confirmed && joiningRepoId != (sidecar.Id{}) {
		return []sidecar.Id{joiningRepoId}
	}
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
	if _, err := self.clients.groupClient(); err != nil && self.clients.log.V(1).Enabled() {
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

// This host forms and follows groups through their signed generation and KeyDelivery wraps.
func (self *urNetworkGkm) KeyDeliveryOnly() bool { return true }

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
	self.clients.setRepoScopes()
	if group, err := self.group(); err == nil {
		self.clients.upkeep.Refresh()
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
func (self *urNetworkGkm) ReformGroup(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
	group, err := self.group()
	if err != nil {
		return sidecar.Id{}, err
	}
	return group.ReformGroup(ctx, args)
}

func (self *urNetworkGkm) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	group, err := self.group()
	if err != nil {
		return err
	}
	return group.ForgetRepo(ctx, repoId)
}

// The head reader urDaemonConfigHeads answers for a network: sidecar.EvsConfigHeadReader over the network's EvsClient
// (evsClient, on the key client urDaemonGkmClient gives) and the config repo the trusted genesis names, built at the
// first read. A read it cannot make, with no key client, no EvsClient or no genesis known yet, is unavailable, which
// withholds the base.
type urNetworkConfigHeads struct {
	clients *urNetworkClients
}

var _ sidecar.ConfigHeadAnchorReader = (*urNetworkConfigHeads)(nil)
var _ sidecar.ConfigHeadTipReader = (*urNetworkConfigHeads)(nil)

// The current verified head that the enrolled device previews its ACL edits against.
func (self *urNetworkConfigHeads) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	reader, err := self.clients.headReader(nil)
	if err != nil {
		return nil, 0, [sha256.Size]byte{}, err
	}
	return reader.CurrentConfigHead(ctx)
}

// Only the verified heads already held by this daemon, with no network read.
func (self *urNetworkConfigHeads) CachedConfigHead(version uint64, chain []byte) *sidecar.ConfigHead {
	self.clients.stateLock.Lock()
	reader := self.clients.reader
	self.clients.stateLock.Unlock()
	if reader == nil {
		return nil
	}
	return reader.CachedConfigHead(version, chain)
}

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
