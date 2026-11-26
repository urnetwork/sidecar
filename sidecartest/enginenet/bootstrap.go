// A network bootstrapped by a hosted Sidecar as its first device (§7.9's bootstrap) on the engines, and the config
// writer's ref over evs (EvsConfigHeadRef) and the repo creation (CreateRepo) a test drives through that Sidecar.
//
//	draft     BootstrapNetwork signs the Genesis by the Sidecar's own identity key (Sidecar.Sign), naming it as the
//	          owner's sidecar; the Sidecar records that Genesis as its anchor, its key client is handed the genesis
//	          state, S(0), and drafts the config group's id and RK_1 (sidecar.GkmGroupDrafter; QD-824)
//	prepare   the config kind's prepare, on an EvsClient of the Sidecar's, seals the first head's push under the
//	          drafted generation pin and signs it at {0, A_0}, sending nothing: nothing of the network exists at evs or
//	          gkm, and the real gate holds no log of it
//	base 1    published at the Net's api naming (1, C_1); the gate loads it, and the key client takes the Sidecar's own
//	          S(1), which BootstrapNetwork checked over the head it prepared
//	repo      EvsClient.CreateRepo for the config kind by the Genesis's id, filing nothing: placement, KF1 by the key
//	          client at S(1), which signs GenRotate_1 over the drafted RK_1 and posts the group, then activation
//	push      the config kind's commit sends the prepared push, which evs takes at the genesis pin as the config
//	          repo's first push
//	repos     CreateRepo files a RepoCreate as the Sidecar's poster would (CORE-M2-02's, which the daemon's
//	          composition does not have): signed by its identity key with a header at its follower's tip, landed at
//	          api, the gate loaded and the follower past it, so the key client holds the state that holds the repo;
//	          then EvsClient.CreateRepo's own sequence runs, PUT, KF1 by the given key client and activation
//
// Every request goes through the real gate. Not safe for concurrent use with itself on one network.

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
	// Its key client, the host's composition's: it drafts the config group before base 1, which takes a
	// sidecar.GkmGroupDrafter, is handed the genesis state and then the Sidecar's own S(1), and forms the group there.
	Gkm sidecar.GkmClient
	// The owner member the Genesis names.
	OwnerMemberId sidecar.Id
	// The first head's files beside its genesis; nil for none.
	Files map[string][]byte
	// Publishes base 1 in place of the Net's api, nil for the api: a test's way to cut the bootstrap short there.
	Publisher sidecar.ConfigBasePublisher
}

// What Bootstrap made.
type BootstrapResult struct {
	Bootstrap    *sidecar.ConfigBootstrapResult
	ConfigRepoId sidecar.Id
	// The config repo's main ref, and the first head at version 1 with its chain value C_1.
	MainRefId sidecar.Id
	Head      *sidecar.ConfigHead
	Chain     [sha256.Size]byte
	// Generation 1 of the config repo as KF1's bootstrap draft held it, which the first head's push was sealed under.
	DraftedKey *sidecar.EvsRepoKey
}

// The bootstrap (the file's comment): base 1 landed and the gate holding it, the config group formed and the first
// head committed. configRepoId names the config repo, nil to draw one; a retry of a bootstrap cut short passes the
// same. It opens evs and gkm to the network beside every network opened before (OpenNetwork), so one world bootstraps
// several networks and reads each.
func (self *Engines) Bootstrap(ctx context.Context, args *BootstrapArgs, configRepoId *sidecar.Id) (*BootstrapResult, error) {
	if args == nil || args.Sidecar == nil || args.Gkm == nil {
		return nil, errors.New("enginenet: a bootstrap needs a Sidecar and its key client")
	}
	drafter, ok := args.Gkm.(sidecar.GkmGroupDrafter)
	if !ok {
		return nil, errors.New("enginenet: the key client drafts no config group")
	}
	running := args.Sidecar
	networkId := running.NetworkId()
	identity := running.Identity()
	if networkId == nil || identity == nil {
		return nil, errors.New("enginenet: the Sidecar is not enrolled")
	}
	self.OpenNetwork(*networkId)
	result := &BootstrapResult{ConfigRepoId: sidecar.NewEvsRepoId()}
	if configRepoId != nil {
		result.ConfigRepoId = *configRepoId
	}
	// the state the bootstrap's evs client judges at: none before base 1, then the Sidecar's own S(1)
	var stateLock sync.Mutex
	var landed sidecar.GkmAuthView
	client, err := newEnginesEvsClient(running, args.Gkm, func() sidecar.GkmAuthView {
		stateLock.Lock()
		defer stateLock.Unlock()
		return landed
	}, func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
		return errors.New("enginenet: the config repo files no RepoCreate: the Genesis names it")
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	publisher := args.Publisher
	if publisher == nil {
		publisher = &sidecartest.FakeApiConfigPublisher{Api: self.api, NetworkId: *networkId}
	}
	bootstrap, err := sidecar.BootstrapNetwork(ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         *networkId,
		OwnerMemberId:     args.OwnerMemberId,
		SidecarId:         identity.SidecarId,
		IdentityPublicKey: identity.IdentityPublicKey,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return running.Sign(purpose, signedType, body, nil)
		},
		ConfigRepoId: result.ConfigRepoId,
		First: &sidecar.ConfigFirstHead{
			Draft: func(ctx context.Context, genesis *sidecar.ConfigState) (*sidecar.EvsRepoKey, error) {
				// A_0, the genesis state's chain
				if err := running.TrustFirstUse(genesis.Pin().GetChain()); err != nil {
					return nil, fmt.Errorf("enginenet: the first device's anchor: %w", err)
				}
				args.Gkm.AuthAdvanced(genesis)
				key, err := drafter.DraftGroup(ctx, &sidecar.GkmCreateGroupArgs{
					NetworkId: *networkId, RepoId: result.ConfigRepoId, Kind: protocol.RepoKind_REPO_KIND_CONFIG,
				})
				result.DraftedKey = key
				return key, err
			},
			Prepare: client.PrepareConfigHead,
			Commit:  client.CommitConfigHead,
		},
		Publisher:  publisher,
		Projection: &sidecartest.FakeApiConfigReader{Api: self.api, NetworkId: *networkId},
		BaseLanded: func(ctx context.Context, state *sidecar.ConfigState) error {
			if err := self.Sync(ctx, *networkId); err != nil {
				return err
			}
			func() {
				stateLock.Lock()
				defer stateLock.Unlock()
				landed = state
			}()
			args.Gkm.AuthAdvanced(state)
			return nil
		},
		CreateRepo: func(ctx context.Context) error {
			_, err := client.CreateRepo(ctx, &sidecar.EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_CONFIG, ResumeRepoId: &result.ConfigRepoId})
			return err
		},
		Files: args.Files,
		Clock: self.net.Clock(),
	})
	if err != nil {
		return result, err
	}
	if !bootstrap.Won {
		return result, errors.New("enginenet: another genesis won the network")
	}
	statement, err := sidecar.ParseEvsStatement(bootstrap.Push.SignedPush)
	if err != nil {
		return result, err
	}
	if result.MainRefId, err = sidecar.IdFromBytes(statement.Push.GetRefId()); err != nil {
		return result, err
	}
	result.Bootstrap, result.Head, result.Chain = bootstrap, bootstrap.Push.Head, bootstrap.Push.Chain
	return result, nil
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
		NotAfterMs: self.net.Clock().Now().Add(self.settings.StatementLife).UnixMilli(),
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
