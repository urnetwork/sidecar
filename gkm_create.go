// KF1 forms a repo while it is keying. The creator persists its chosen group ID and RK_1 before sending its
// signed GroupForm and first GenRotate. On a retry it uses the same signed bytes, then stages the first reader,
// delegation and recovery deliveries. EVS can activate the repo after CreateGroup succeeds (D-KEYS-18).
//
// For a first config repo, DraftGroup supplies the group ID and RK_1 before base 1 so the first config head
// can be sealed. Its commitment depends on the key, repo and generation. Once base 1 lands, CreateGroup uses
// its verified S(1) pin to sign GenRotate_1. A collision on the config group's drafted ID keeps the draft,
// since the published head already commits to that key (QD-824).
//
// KeyDelivery clients use the same formation flow for member devices and authorized agents (owner 610).
// The optional draft MLS engine adds the creator's leaf and epoch-0 material to the stored request.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose a GroupForm is signed under (QD-527), as gkmservice verifies it.
const gkmGroupFormPurpose = "group-form"

var (
	// Another device formed the repo's group first: this creation's draft is discarded, and the device joins the group
	// that stands by its Welcome.
	ErrGkmGroupFormed = errors.New("gkm: another device formed the repo's group")
	// gkm answered 409 for the config group's drafted id, another repo's or another device's form: no other id is drawn,
	// since the network's first config head is sealed under this one and base 1 names it (QD-824). The draft stays.
	ErrGkmDraftTaken = errors.New("gkm: the config group's drafted id is taken")
)

// What drafts KF1 before its network's base 1 (QD-824): GkmGroupClient, and a host's key client over one.
type GkmGroupDrafter interface {
	DraftGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error)
}

var _ GkmGroupDrafter = (*GkmGroupClient)(nil)

// KF1's draft as the keychain holds it: the group drawn, RK_1 and the request, byte for byte. A bootstrap draft holds
// no request until CreateGroup signs it at a state past base 1.
type gkmCreateDraft struct {
	groupId Id
	repoKey []byte
	request []byte
}

// KF1's bootstrap draft of the config repo's group (the file header; QD-824): its id and RK_1, drawn before base 1 and
// kept as KF1's draft before this answers, so a kill draws nothing new. Answers RK_1 as the key the network's first
// config head is sealed under, its generation pin {group_id, 1, C_1}; it carries no gen/1 statement yet, so cause
// REQUEST, as gen/1's will be, and no auth pin or time. A draft already kept answers its own id and RK_1, a group that
// stands its generation 1 as held. Before base 1 there is only the genesis. Only the config repo can be drafted,
// in a process that holds the network's state. The verified state determines who can sign its form.
func (self *GkmGroupClient) DraftGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	if args == nil || args.RepoId == (Id{}) || args.Kind != protocol.RepoKind_REPO_KIND_CONFIG {
		return nil, fmt.Errorf("%w: only the config repo's group is drafted before its network's base 1", ErrGkmMalformed)
	}
	if !self.holdsState() {
		return nil, fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	manager := self.manager(args.RepoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	if _, err := self.repoPins(args.RepoId); err == nil {
		// formed already: generation 1 as this device holds it
		first, err := self.heldGeneration(args.RepoId, 1)
		if err != nil {
			return nil, err
		}
		if first.key == nil {
			return nil, fmt.Errorf("%w: generation 1 is held without its key", ErrGkmKeyMissing)
		}
		return first.key, nil
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, err
	}
	record, err := manager.pendingRecord()
	if err != nil {
		return nil, err
	}
	if record.create == nil {
		groupId := Id{}
		// never fails: a broken system generator crashes the program instead
		rand.Read(groupId[:])
		record.create = &gkmCreateDraft{groupId: groupId, repoKey: gkmNewRepoKey()}
		// kept before the key is answered, so nothing is sealed under an id a kill would lose
		if err := manager.putPendingRecord(record); err != nil {
			return nil, err
		}
	}
	return newGkmDraftedFirstKey(args.RepoId, record.create.groupId, record.create.repoKey)
}

// RK_1 of a bootstrap draft before its gen/1 statement exists: the generation pin and every key RK_1 derives, ref's
// included. Cause REQUEST, as KF1's gen/1 states; an empty auth pin and no time, which gen/1 states once signed.
func newGkmDraftedFirstKey(repoId Id, groupId Id, repoKey []byte) (*EvsRepoKey, error) {
	if len(repoKey) != gkmRepoKeyByteCount {
		return nil, fmt.Errorf("%w: a drafted key of %d bytes", ErrGkmMalformed, len(repoKey))
	}
	held := bytes.Clone(repoKey)
	testHookSecret("RK_g", held)
	return &EvsRepoKey{
		repoId:       repoId,
		groupId:      groupId,
		generation:   1,
		commitment:   gkmCommitment(repoId, 1, held),
		cause:        GkmCauseRequest,
		auth:         &bridge.AuthPin{},
		repoKey:      held,
		firstRepoKey: held,
	}, nil
}

// KF1: the repo's group, epoch 0 and generation 1 at gkm, then generation 1's deliveries while the repo is still
// keying, resuming after a crash. Returns RK_1, whose GroupId names the group.
func (self *GkmGroupClient) CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	if args == nil || args.RepoId == (Id{}) || args.Kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		return nil, fmt.Errorf("%w: a group needs its repo and kind", ErrGkmMalformed)
	}
	manager := self.manager(args.RepoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.createInFlow(ctx, args)
}

// CreateGroup with the group's flow held.
func (self *gkmGroupManager) createInFlow(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	client := self.client
	state, err := client.currentState()
	if err != nil {
		return nil, err
	}
	repo := state.Repo(self.repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s: its RepoCreate has not reached this state", ErrGkmNoRepo, self.repoId)
	}
	if args.Inbox != protocol.RepoInbox_REPO_INBOX_NONE && (repo.GetInbox() != args.Inbox || !AclRepoIsInbox(repo)) {
		return nil, fmt.Errorf("%w: repo %s does not carry the expected inbox role", ErrGkmMalformed, self.repoId)
	}
	for drawCount := 0; drawCount < max(1, client.settings.CreateGroupDrawCount); drawCount += 1 {
		// the group stands: only its deliveries may be missing
		if pins, err := client.repoPins(self.repoId); err == nil {
			first, err := client.heldGeneration(self.repoId, 1)
			if err != nil {
				return nil, err
			}
			return self.finishCreate(ctx, state, pins.groupId, first)
		} else if !errors.Is(err, ErrGkmKeyMissing) {
			return nil, err
		}
		record, err := self.pendingRecord()
		if err != nil {
			return nil, err
		}
		draft := record.create
		if draft == nil || len(draft.request) == 0 {
			// a bootstrap draft's id and RK_1 are its own (DraftGroup); any other creation draws them here
			draft, err = self.draftCreate(ctx, state, args, draft)
			if err != nil {
				return nil, err
			}
			record.create = draft
			// persisted before the POST, so a kill resumes with the same bytes
			if err := self.putPendingRecord(record); err != nil {
				return nil, err
			}
		}
		taken, err := self.postCreate(ctx, draft)
		if err != nil {
			return nil, err
		}
		if taken && args.Kind == protocol.RepoKind_REPO_KIND_CONFIG {
			// the config group's id seals the first config head base 1 names (QD-824): never drawn again
			return nil, fmt.Errorf("%w: repo %s", ErrGkmDraftTaken, self.repoId)
		}
		if taken {
			// the id is another repo's, or another device formed this repo's group first: this draft goes, its MLS
			// state with it, and either another id is drawn or the device stops
			record.create = nil
			if err := self.putPendingRecord(record); err != nil {
				return nil, err
			}
			if forgetter, ok := client.args.Mls.(MlsGroupForgetter); ok {
				if err := forgetter.ForgetGroup(draft.groupId); err != nil && !errors.Is(err, ErrMlsGroupUnknown) {
					return nil, err
				}
			}
			reply, err := client.args.Api.Forms(ctx, self.repoId)
			if err != nil {
				return nil, err
			}
			if 0 < len(reply.GetForms()) {
				return nil, fmt.Errorf("%w: repo %s", ErrGkmGroupFormed, self.repoId)
			}
			continue
		}
		// the group stands at gkm: generation 1 and the pins go to the keychain
		request := &protocol.GkmGroupCreateRequest{}
		if err := proto.Unmarshal(draft.request, request); err != nil {
			return nil, fmt.Errorf("%w: a creation draft's request", ErrGkmMalformed)
		}
		signedBytes, err := gkmSignedBytes(request.GetGenRotate())
		if err != nil {
			return nil, err
		}
		generation, err := gkmStoredGeneration(signedBytes)
		if err != nil {
			return nil, err
		}
		key, err := OpenEvsRepoKey(generation, draft.repoKey)
		if err != nil {
			return nil, err
		}
		first := &gkmHeldGeneration{generation: generation, key: key}
		if err := client.putHeldGeneration(self.repoId, first); err != nil {
			return nil, err
		}
		var group MlsGroup
		var headerBytes []byte
		if client.args.Mls != nil {
			group, err = client.loadGroup(draft.groupId)
			if err != nil {
				return nil, err
			}
			headerBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: 1, Auth: generation.Rotate.GetAuth()})
			if err != nil {
				return nil, err
			}
		}
		err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
			pins.groupId = draft.groupId
			if group != nil {
				pins.epoch = group.Epoch()
				pins.epochAuthenticator = group.EpochAuthenticator()
				pins.epochHeader = headerBytes
			}
			pins.generation = 1
			pins.commitment = bytes.Clone(generation.Rotate.GetCommitment())
		})
		if err != nil {
			return nil, err
		}
		return self.finishCreate(ctx, state, draft.groupId, first)
	}
	return nil, fmt.Errorf("%w: every group id drawn was taken", ErrGkmWait)
}

// Step 2: the group's id, its MLS state, RK_1 and the whole POST /gkm/groups request. drawn is a bootstrap draft whose
// id and RK_1 stand (DraftGroup), nil to draw both here. A bootstrap draft's MLS group a kill left made is taken as it
// stands at epoch 0, since an engine makes no second group under one id.
func (self *gkmGroupManager) draftCreate(ctx context.Context, state GkmAuthView, args *GkmCreateGroupArgs, drawn *gkmCreateDraft) (*gkmCreateDraft, error) {
	client := self.client
	if err := GkmFormSignerAllowed(state, self.repoId, client.args.SidecarId); err != nil {
		return nil, err
	}
	groupId := Id{}
	if drawn != nil {
		groupId = drawn.groupId
	} else {
		// never fails: a broken system generator crashes the program instead
		rand.Read(groupId[:])
	}
	urGroup := &MlsUrGroup{NetworkId: args.NetworkId, RepoId: args.RepoId, Kind: args.Kind, OwnerMemberId: args.OwnerMemberId}
	var group MlsGroup
	if client.args.Mls != nil && drawn != nil {
		loaded, err := client.args.Mls.LoadGroup(groupId)
		switch {
		case err == nil && loaded.Epoch() != 0:
			return nil, fmt.Errorf("%w: the drafted group stands here past epoch 0", ErrGkmMalformed)
		case err == nil:
			group = loaded
		case !errors.Is(err, ErrMlsGroupUnknown):
			return nil, err
		}
	}
	if client.args.Mls != nil && group == nil {
		created, err := client.args.Mls.CreateGroup(groupId, urGroup)
		if err != nil {
			return nil, err
		}
		group = created
	}
	now := client.clock.Now()
	holders, err := KeyHolders(state, self.repoId, now)
	if err != nil {
		return nil, err
	}
	var roster []MlsMember
	if group != nil {
		roster = group.Roster()
	}
	targets, err := self.deliverySet(ctx, state, holders, now, roster, false)
	if err != nil {
		return nil, err
	}
	generationArgs := &GkmGenerationArgs{Cause: GkmCauseRequest, Auth: state.Pin(), Time: now, HoldersSha256: holders.Sha256(), WrapCount: uint32(len(targets))}
	if gkmRepoTakesDeposits(state.Repo(self.repoId)) {
		generationArgs.DropNotAfter = now.Add(client.settings.DropKeyLifetime)
	}
	var key *EvsRepoKey
	var rotate *protocol.GenRotate
	if drawn != nil {
		// over the drawn RK_1, held to the same floor: a state at position 0 signs no generation
		key, rotate, err = newGkmFirstGenerationOver(self.repoId, groupId, drawn.repoKey, generationArgs)
	} else {
		key, rotate, err = NewGkmFirstGeneration(self.repoId, groupId, generationArgs)
	}
	if err != nil {
		return nil, err
	}
	signedRotate, err := SignGenRotate(rotate, client.args.Sign)
	if err != nil {
		return nil, err
	}
	// the form carries the state its signer's right is judged at (QD-643), the one gen/1's holders are counted at
	formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{RepoId: self.repoId.Bytes(), GroupId: groupId.Bytes(), Generation: 1, Auth: state.Pin()})
	if err != nil {
		return nil, err
	}
	signedForm, err := gkmSign(gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, formBody, client.args.Sign)
	if err != nil {
		return nil, err
	}
	create := &protocol.GkmGroupCreateRequest{Form: signedForm, GenRotate: signedRotate}
	if group != nil {
		kek, err := MlsKek(group, self.repoId)
		if err != nil {
			return nil, err
		}
		genWrap, err := SealGkmGenWrap(key, groupId, group.Epoch(), kek)
		clear(kek)
		if err != nil {
			return nil, err
		}
		groupInfo, err := group.GroupInfo()
		if err != nil {
			return nil, err
		}
		sealedGroupInfo, err := SealGkmGroupInfo(key, groupId, group.Epoch(), groupInfo)
		if err != nil {
			return nil, err
		}
		create.GenWrap, create.SealedGroupInfo, create.CipherSuite = genWrap, sealedGroupInfo, uint32(mlsCipherSuiteXWing)
	}
	request, err := proto.MarshalOptions{Deterministic: true}.Marshal(create)
	if err != nil {
		return nil, err
	}
	return &gkmCreateDraft{groupId: groupId, repoKey: bytes.Clone(key.repoKey), request: request}, nil
}

// Step 3: POST /gkm/groups with the draft's bytes, sent again while its answer is lost. taken says the owner marker
// holds another repo.
func (self *gkmGroupManager) postCreate(ctx context.Context, draft *gkmCreateDraft) (taken bool, err error) {
	client := self.client
	request := &protocol.GkmGroupCreateRequest{}
	if err := proto.Unmarshal(draft.request, request); err != nil {
		return false, fmt.Errorf("%w: a creation draft's request", ErrGkmMalformed)
	}
	if client.KeyDeliveryOnly() {
		// An interrupted older draft can still file its original signed form and generation.
		request.GenWrap, request.SealedGroupInfo, request.CipherSuite = nil, nil, 0
	}
	for sendCount := 0; sendCount < max(1, client.settings.CommitSendCount); sendCount += 1 {
		err := client.args.Api.CreateGroup(ctx, self.repoId, request)
		gkmError, refused := GkmErrorOf(err)
		switch {
		case err == nil:
			return false, nil
		case refused && gkmError.Status == http.StatusConflict:
			return true, nil
		case refused:
			return false, err
		case ctx.Err() != nil:
			return false, err
		}
		// unknown: every write of the request is an If-None-Match create that equal bytes resume, so it goes again
	}
	return false, fmt.Errorf("%w: the group's creation got no answer", ErrGkmUnavailable)
}

// Step 4, and a resumed creation's end: generation 1's deliveries staged, the draft gone, RK_1 answered.
func (self *gkmGroupManager) finishCreate(ctx context.Context, state GkmAuthView, groupId Id, first *gkmHeldGeneration) (*EvsRepoKey, error) {
	client := self.client
	if first.key == nil {
		return nil, fmt.Errorf("%w: generation 1 is held without its key", ErrGkmKeyMissing)
	}
	if top, err := client.newestHeldGeneration(self.repoId); err == nil && 1 < top.generation.Rotate.GetGeneration() {
		// long past its creation: generation 1's deliveries stood before any later generation was claimed
		return first.key, nil
	}
	rotate := first.generation.Rotate
	// the set gen/1 counted: at its own state and time
	draftState, err := state.At(rotate.GetAuth())
	if err != nil {
		return nil, err
	}
	at := time.UnixMilli(rotate.GetTimeMs())
	holders, err := KeyHolders(draftState, self.repoId, at)
	if err != nil {
		return nil, err
	}
	var roster []MlsMember
	if group, err := client.loadGroup(groupId); err == nil {
		roster = group.Roster()
	}
	// Gen/1 is claimed before its wraps are staged. A restarted creator preserves the signed generation and
	// its reader deliveries, but must seal recovery wraps to bindings still effective when it finishes.
	changed := client.KeyDeliveryOnly() && draftState.Pin().GetVersion() != state.Pin().GetVersion()
	if changed {
		holders = slices.DeleteFunc(holders, func(holder GkmHolder) bool { return holder.Kind == GkmHolderRecovery })
	}
	targets, err := self.deliverySet(ctx, draftState, holders, at, roster, false)
	if err != nil {
		return nil, err
	}
	if changed {
		now := client.clock.Now()
		current, err := KeyHolders(state, self.repoId, now)
		if err != nil {
			return nil, err
		}
		recovery := slices.DeleteFunc(current, func(holder GkmHolder) bool { return holder.Kind != GkmHolderRecovery })
		wraps, err := self.deliverySet(ctx, state, recovery, now, nil, false)
		if err != nil {
			return nil, err
		}
		targets = append(targets, wraps...)
	}
	if err := self.stageDeliveries(ctx, state, groupId, first.key, targets); err != nil {
		return nil, err
	}
	record, err := self.pendingRecord()
	if err != nil {
		return nil, err
	}
	if record.create != nil {
		record.create = nil
		if err := self.putPendingRecord(record); err != nil {
			return nil, err
		}
	}
	return first.key, nil
}
