// A network bootstrapped by a hosted Sidecar as its first device (§7.9's bootstrap) on the engines, and the config
// writer's ref over evs (EvsConfigHeadRef) and the repo creation (CreateRepo) a test drives through that Sidecar.
//
//	genesis   BootstrapNetwork signs the Genesis, the first head and base 1 by the Sidecar's own identity key
//	          (Sidecar.Sign), the Genesis naming it as the owner's sidecar, and publishes base 1 at the Net's api
//	first     in the first head's prepare, before base 1 lands and so inside the network's bootstrap window
//	          (enginenet.go): the Sidecar records its own Genesis as its anchor, its key client is handed the genesis
//	          state S(0), and EvsClient.CreateRepo creates the config repo on evs, keying, KF1 forming the group by that
//	          key client, which keeps generation 1 in the Sidecar's keychain, and activation; then the head's files go
//	          up as the ref's first push, its auth {0, A_0}, by a client that judges at S(0) and keys from that
//	          generation, since the key client writes nothing at a state with no rows. The push is sent there, before
//	          base 1, where a writer's side would sign it there and send it after (QD-081 #4); the window then closes
//	          and the gate loads base 1
//	repos     CreateRepo files a RepoCreate as the Sidecar's poster would (CORE-M2-02's, which the daemon's
//	          composition does not have): signed by its identity key with a header at its follower's tip, landed at
//	          api, the gate loaded and the follower past it, so the key client holds the state that holds the repo;
//	          then EvsClient.CreateRepo's own sequence runs, PUT, KF1 by the given key client and activation
//
// Today the bootstrap stops at KF1: a GenRotate's auth pin must be past position 0, and the genesis state is the only
// state before base 1, whose head the first generation must key (question
// daemon-evs-gkm-clients-first-device-config-generation). Bootstrap answers that refusal, the window closed and base 1
// unlanded; what it does up to KF1 runs as written, and once the question is answered the rest follows its order.
//
// Every request outside a bootstrap window is judged by the real gate. Not safe for concurrent use with itself on one
// network.

package enginenet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What Bootstrap takes.
type BootstrapArgs struct {
	// The hosted Sidecar that becomes the network's first device: enrolled in the network and Online.
	Sidecar *sidecar.Sidecar
	// Its key client, the host's composition's: it is handed the genesis state and forms the config repo's group.
	Gkm sidecar.GkmClient
	// The owner member the Genesis names.
	OwnerMemberId sidecar.Id
	// The first head's files beside its genesis; nil for none.
	Files map[string][]byte
}

// What Bootstrap made.
type BootstrapResult struct {
	Bootstrap    *sidecar.ConfigBootstrapResult
	ConfigRepoId sidecar.Id
	// The config repo's main ref, and the first head at version 1 with its chain value C_1.
	MainRefId sidecar.Id
	Head      *sidecar.ConfigHead
	Chain     [sha256.Size]byte
}

// The bootstrap (the file's comment): base 1 landed, the window closed and the gate holding base 1.
func (self *Engines) Bootstrap(ctx context.Context, args *BootstrapArgs) (*BootstrapResult, error) {
	if args == nil || args.Sidecar == nil || args.Gkm == nil {
		return nil, errors.New("enginenet: a bootstrap needs a Sidecar and its key client")
	}
	running := args.Sidecar
	networkId := running.NetworkId()
	identity := running.Identity()
	if networkId == nil || identity == nil {
		return nil, errors.New("enginenet: the Sidecar is not enrolled")
	}
	self.OpenNetwork(*networkId)
	ref := &bootstrapHeadRef{engines: self, args: args, networkId: *networkId, configRepoId: sidecar.NewEvsRepoId()}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.windows, *networkId)
	}()
	result, err := sidecar.BootstrapNetwork(ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         *networkId,
		OwnerMemberId:     args.OwnerMemberId,
		SidecarId:         identity.SidecarId,
		IdentityPublicKey: identity.IdentityPublicKey,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return running.Sign(purpose, signedType, body, nil)
		},
		ConfigRepoId: ref.configRepoId,
		Heads:        ref,
		Publisher:    &sidecartest.FakeApiConfigPublisher{Api: self.api, NetworkId: *networkId},
		Projection:   &sidecartest.FakeApiConfigReader{Api: self.api, NetworkId: *networkId},
		Files:        args.Files,
		Clock:        self.net.Clock(),
	})
	if err != nil {
		return nil, err
	}
	if !result.Won {
		return nil, errors.New("enginenet: another genesis won the network")
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.windows, *networkId)
	}()
	if err := self.Sync(ctx, *networkId); err != nil {
		return nil, err
	}
	return &BootstrapResult{
		Bootstrap:    result,
		ConfigRepoId: ref.configRepoId,
		MainRefId:    ref.refId,
		Head:         ref.head,
		Chain:        ref.chain,
	}, nil
}

// BootstrapNetwork's ref of the config repo: its prepare makes the repo and sends the first head (the file's comment).
type bootstrapHeadRef struct {
	engines      *Engines
	args         *BootstrapArgs
	networkId    sidecar.Id
	configRepoId sidecar.Id

	// set by the prepare
	refId sidecar.Id
	head  *sidecar.ConfigHead
	chain [sha256.Size]byte
}

// No head before the first: BootstrapNetwork asks none.
func (self *bootstrapHeadRef) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	return nil, 0, [sha256.Size]byte{}, errors.New("enginenet: the bootstrap's ref answers its prepare alone")
}

// The first head, sent: see the file's comment.
func (self *bootstrapHeadRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	if version != 0 {
		return nil, fmt.Errorf("enginenet: the bootstrap's ref prepares the first head alone, not one after %d", version)
	}
	running := self.args.Sidecar
	identity := running.Identity()
	signedGenesis := head.File(sidecar.ConfigHeadGenesisPath)
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	genesisLog, err := sidecar.NewConfigLog(logSettings, signedGenesis)
	if err != nil {
		return nil, err
	}
	genesisState := genesisLog.State()
	genesisChain := bridge.GenesisChain(signedGenesis)
	if err := running.TrustFirstUse(genesisChain[:]); err != nil {
		return nil, fmt.Errorf("enginenet: the first device's anchor: %w", err)
	}
	func() {
		self.engines.stateLock.Lock()
		defer self.engines.stateLock.Unlock()
		self.engines.windows[self.networkId] = &bootstrapWindow{
			networkId:    self.networkId,
			sidecarId:    identity.SidecarId,
			memberId:     self.args.OwnerMemberId,
			configRepoId: self.configRepoId,
			identityKey:  bytes.Clone(identity.IdentityPublicKey),
			genesisState: genesisState,
		}
	}()
	self.args.Gkm.AuthAdvanced(genesisState)

	keys := &bootstrapKeys{gkm: self.args.Gkm, configRepoId: self.configRepoId}
	client, err := newEnginesEvsClient(running, keys, func() sidecar.GkmAuthView { return genesisState }, func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
		return errors.New("enginenet: the config repo files no RepoCreate: the Genesis names it")
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	repo, err := client.CreateRepo(ctx, &sidecar.EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_CONFIG, ResumeRepoId: &self.configRepoId})
	if err != nil {
		return nil, fmt.Errorf("enginenet: the config repo: %w", err)
	}
	firstKey, err := self.args.Gkm.RepoKey(ctx, self.configRepoId, 1)
	if err != nil {
		return nil, fmt.Errorf("enginenet: the config repo's generation 1: %w", err)
	}
	refKey, err := sidecar.NewEvsRefKey(firstKey)
	if err != nil {
		return nil, err
	}
	self.refId, err = sidecar.EvsRefId(refKey, sidecar.EvsMainRefName)
	if err != nil {
		return nil, err
	}
	ref := NewEvsConfigHeadRef(repo, self.refId, nil, 0)
	push, err := ref.PrepareConfigHead(ctx, head, 0)
	if err != nil {
		return nil, fmt.Errorf("enginenet: the first head: %w", err)
	}
	self.head, self.chain = push.Head, push.Chain
	return push, nil
}

// Sent at its prepare.
func (self *bootstrapHeadRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	return nil
}

// BootstrapNetwork asks none.
func (self *bootstrapHeadRef) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	return nil, errors.New("enginenet: the bootstrap's ref answers its prepare alone")
}

// The bootstrap's key source for the config repo's first push: generation 1 of the key client's keychain, which KF1
// put there, since the key client writes nothing at a state with no rows. Its CreateGroup is the key client's, so
// EvsClient.CreateRepo's KF1 is the device's own.
type bootstrapKeys struct {
	gkm          sidecar.GkmClient
	configRepoId sidecar.Id
}

var _ sidecar.GkmClient = (*bootstrapKeys)(nil)

// The genesis state is the key client's already.
func (self *bootstrapKeys) AuthAdvanced(state sidecar.GkmAuthView) {
}

func (self *bootstrapKeys) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return self.RepoKey(ctx, repoId, 1)
}

func (self *bootstrapKeys) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	if repoId != self.configRepoId {
		return nil, fmt.Errorf("%w: the bootstrap keys the config repo alone", sidecar.ErrGkmUnavailable)
	}
	return self.gkm.RepoKey(ctx, repoId, generation)
}

func (self *bootstrapKeys) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return self.RepoKey(ctx, repoId, 1)
}

func (self *bootstrapKeys) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	return nil, fmt.Errorf("%w: the bootstrap drops no key", sidecar.ErrGkmUnavailable)
}

func (self *bootstrapKeys) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	if args == nil || args.RepoId != self.configRepoId {
		return nil, fmt.Errorf("%w: the bootstrap forms the config repo's group alone", sidecar.ErrGkmUnavailable)
	}
	return self.gkm.CreateGroup(ctx, args)
}

func (self *bootstrapKeys) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return nil, fmt.Errorf("%w: the bootstrap rotates nothing", sidecar.ErrGkmUnavailable)
}

func (self *bootstrapKeys) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	return fmt.Errorf("%w: the bootstrap forgets nothing", sidecar.ErrGkmUnavailable)
}

// A short-lived EvsClient of running's, over gkm, judging at config and filing statements by fileStatement, on a store
// of its own, so no pin it takes is the Sidecar's own client's; nothing announces what it creates.
func newEnginesEvsClient(running *sidecar.Sidecar, gkm sidecar.GkmClient, config sidecar.EvsConfigFunction, fileStatement sidecar.EvsFileStatementFunction) (*sidecar.EvsClient, error) {
	args, err := running.EvsClientArgs(gkm, config, fileStatement)
	if err != nil {
		return nil, err
	}
	args.Store = sidecartest.NewFakeStore().Root()
	args.RepoCreated = nil
	args.PrivateCreate = nil
	return sidecar.NewEvsClient(args)
}

// A config writer's sidecar.ConfigHeadRef over the config repo's main ref on evs, which evs's client does not build
// yet (TEAM-M2-09's EvsClient for the config kind): a head is saved as one push of the files that changed, at its
// prepare, since evs prepares no push it does not send; the head the ref holds is the newest saved through it. Each
// push's chain value is read back by the repo's client's verifier, which judges it at that client's state. Safe for
// concurrent use; one save at a time.
type EvsConfigHeadRef struct {
	repo  *sidecar.EvsRepo
	refId sidecar.Id

	// held across a save, so a writer reads a head with its own version
	stateLock sync.Mutex
	files     map[string][]byte
	head      *sidecar.ConfigHead
	version   uint64
	chain     [sha256.Size]byte
}

var _ sidecar.ConfigHeadRef = (*EvsConfigHeadRef)(nil)

// A ref over repo's main ref, refId, holding head at version: nil and 0 before the first push.
func NewEvsConfigHeadRef(repo *sidecar.EvsRepo, refId sidecar.Id, head *sidecar.ConfigHead, version uint64) *EvsConfigHeadRef {
	self := &EvsConfigHeadRef{repo: repo, refId: refId, files: map[string][]byte{}, version: version}
	self.chain = sidecar.EvsChainStart(repo.RepoId(), refId)
	if head != nil {
		self.head, self.files = head, head.Files()
	}
	return self
}

// The ref's chain value at each version through version, from C_0, and each version's Signed EvsPush.
func (self *EvsConfigHeadRef) walk(ctx context.Context, version uint64) ([][sha256.Size]byte, [][]byte, error) {
	start := sidecar.EvsChainStart(self.repo.RepoId(), self.refId)
	walked, err := self.repo.Client().Verifier().Walk(ctx, self.repo.RepoId(), self.refId, 0, start, version)
	if err != nil {
		return nil, nil, err
	}
	chains := [][sha256.Size]byte{start}
	pushes := [][]byte{}
	for _, statement := range walked {
		chains = append(chains, statement.Chain)
		pushes = append(pushes, statement.Statement.Bytes)
	}
	if uint64(len(pushes)) != version {
		return nil, nil, fmt.Errorf("enginenet: the ref's walk to %d read %d pushes", version, len(pushes))
	}
	return chains, pushes, nil
}

// The newest head saved through the ref, none at C_0 before the first.
func (self *EvsConfigHeadRef) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.head, self.version, self.chain, nil
}

// Pushes head as the ref's version after version, one push of what changed, since evs prepares none it does not send:
// ErrConfigHeadConflict where the ref moved past version.
func (self *EvsConfigHeadRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if version != self.version {
		return nil, fmt.Errorf("%w: the ref holds %d, not %d", sidecar.ErrConfigHeadConflict, self.version, version)
	}
	files := head.Files()
	paths := []string{}
	for path, data := range files {
		if !bytes.Equal(self.files[path], data) {
			paths = append(paths, path)
		}
	}
	for path := range self.files {
		if _, kept := files[path]; !kept {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	writes := []*sidecar.EvsPathWrite{}
	for _, path := range paths {
		data, kept := files[path]
		write := &sidecar.EvsPathWrite{Path: path, Remove: !kept}
		if kept {
			write.Content = bytes.NewReader(data)
		}
		writes = append(writes, write)
	}
	result, err := self.repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: writes})
	if err != nil {
		return nil, err
	}
	if result.Version != version+1 {
		return nil, fmt.Errorf("%w: saved at %d after %d", sidecar.ErrConfigHeadConflict, result.Version, version)
	}
	chains, pushes, err := self.walk(ctx, result.Version)
	if err != nil {
		return nil, err
	}
	self.files, self.head, self.version, self.chain = files, head, result.Version, chains[result.Version]
	return &sidecar.ConfigHeadPush{Head: head, Version: result.Version, Chain: self.chain, SignedPush: pushes[result.Version-1]}, nil
}

// Sent at its prepare.
func (self *EvsConfigHeadRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	return nil
}

// Each version's Signed EvsPush in (after, through].
func (self *EvsConfigHeadRef) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	if through < after {
		return nil, fmt.Errorf("enginenet: no pushes in (%d, %d]", after, through)
	}
	_, pushes, err := self.walk(ctx, through)
	if err != nil {
		return nil, err
	}
	return pushes[after:through], nil
}

// What CreateRepo takes.
type CreateRepoArgs struct {
	// The hosted Sidecar that files the RepoCreate and becomes the repo's admin; its config follower stands.
	Sidecar *sidecar.Sidecar
	// Its key client, which forms the repo's group (KF1).
	Gkm  sidecar.GkmClient
	Kind protocol.RepoKind
	// An owner-bound kind's owner, else nil.
	OwnerMemberId *sidecar.Id
}

// A repo created as the file's comment says: its RepoCreate landed, the gate and the Sidecar's follower past it, and
// EvsClient.CreateRepo's PUT, KF1 and activation run. The repo's id.
func (self *Engines) CreateRepo(ctx context.Context, args *CreateRepoArgs) (sidecar.Id, error) {
	running := args.Sidecar
	follower := running.ConfigFollower()
	if follower == nil || follower.Client() == nil {
		return sidecar.Id{}, errors.New("enginenet: a repo's creator files by a follower that stands")
	}
	// the id CreateRepo draws, as its RepoCreate names it
	repoId := sidecar.Id{}
	poster := func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
		create, ok := body.(*protocol.RepoCreate)
		if !ok || signedType != bridge.SignedType_SIGNED_REPO_CREATE {
			return fmt.Errorf("enginenet: the poster files RepoCreates alone, not %s", signedType)
		}
		create = proto.Clone(create).(*protocol.RepoCreate)
		repoId, _ = sidecar.IdFromBytes(create.GetRepoId())
		_, err := self.PostStatement(ctx, running, signedType, func(header *bridge.StatementHeader) proto.Message {
			create.Header = header
			return create
		})
		return err
	}
	client, err := newEnginesEvsClient(running, args.Gkm, func() sidecar.GkmAuthView {
		if state := follower.VerifiedState(); state != nil {
			return state
		}
		return nil
	}, poster)
	if err != nil {
		return sidecar.Id{}, err
	}
	defer client.Close()
	if _, err := client.CreateRepo(ctx, &sidecar.EvsCreateRepoArgs{Kind: args.Kind, OwnerMemberId: args.OwnerMemberId}); err != nil {
		return sidecar.Id{}, err
	}
	return repoId, nil
}

// Signs the statement body makes around a header at running's follower's tip by running's identity key, lands it at
// api, and waits until the gate holds it and running's follower applied it, so the Sidecar's key client holds the
// state it lands in. The entry's pin.
func (self *Engines) PostStatement(ctx context.Context, running *sidecar.Sidecar, signedType bridge.SignedType, body func(header *bridge.StatementHeader) proto.Message) (*bridge.AuthPin, error) {
	client := running.ConfigFollower().Client()
	networkId := running.NetworkId()
	if client == nil || networkId == nil {
		return nil, errors.New("enginenet: a statement is filed by a follower that stands")
	}
	purpose, ok := sidecar.ConfigStatementPurpose(signedType)
	if !ok {
		return nil, fmt.Errorf("enginenet: %s is no config statement", signedType)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := &bridge.StatementHeader{
		NetworkId:  networkId.Bytes(),
		At:         proto.Clone(client.Pin()).(*bridge.AuthPin),
		Nonce:      nonce,
		NotAfterMs: self.net.Clock().Now().Add(time.Hour).UnixMilli(),
	}
	bodyBytes, err := enginesMarshal(body(header))
	if err != nil {
		return nil, err
	}
	signed, err := running.Sign(purpose, signedType, bodyBytes, nil)
	if err != nil {
		return nil, err
	}
	signedBytes, err := enginesMarshal(signed)
	if err != nil {
		return nil, err
	}
	pin, err := self.api.AppendStatement(ctx, *networkId, signedBytes)
	if err != nil {
		return nil, err
	}
	if err := self.Sync(ctx, *networkId); err != nil {
		return nil, err
	}
	if _, err := client.WaitFor(ctx, pin.GetVersion()); err != nil {
		return nil, err
	}
	return pin, nil
}
