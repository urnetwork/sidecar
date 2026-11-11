// KF1, a new repo's group (KEYS-M2-21; D-KEYS-5, D-KEYS-18; DESIGN-DETAILS 6.2.4): what EvsClient.CreateRepo calls
// between the repo's placement, keying, and its activation.
//
//	2  draw group_id, 16 random bytes, RK_1 and GenRotate_1 {generation 1, no parent, cause REQUEST, this state's
//	   pin, holders_sha256 over KeyHolders there, wrap_count}; create the MLS group, whose only leaf is this
//	   sidecar's, with ur_group {network, repo, kind, owner}; seal GenWrap_0 and GroupInfo_0 under RK_1; persist the
//	   draft, the whole request with RK_1, in the keychain
//	3  POST /gkm/groups: gkm writes the owner marker, the form, epoch/0 and gen/1, each If-None-Match, equal bytes
//	   resuming; a 409 means the id is another repo's, and another is drawn
//	4  stage generation 1's deliveries as a rotation stages its own: ReaderWraps to agents and, in the config and
//	   directory groups, to the member devices among the holders; DelegationWraps; RecoveryWraps
//
// Only when step 4 has returned does CreateGroup answer, and only then does EvsClient.CreateRepo have evs activate
// the repo (plan-EVS1-repo-activate-route), so no content predates its recovery wraps (D-KEYS-18). The engine's
// first run then adds every pending member device in one Add commit (KF2).
//
// A kill resumes: before step 3 from the draft, with the same bytes; after it, the group stands at gkm and in the
// keychain, and step 4 runs again, each delivery an If-None-Match create. A second CreateGroup of a repo whose group
// stands answers its generation 1 once its deliveries stand. A creator whose only device is lost before activation
// leaves the repo keying, and a repo admin's device re-forms or deletes it (FS-20).
//
// A sidecar that holds no leaf creates no group: KF1's epoch 0 has one leaf, the creator's. A repo such a sidecar,
// a tagged or ephemeral one, creates is formed by the first member device gkm's pending hint reaches (QD-638;
// FormAgentRepos): it runs steps 2 to 4 as the group's creator, and the agent, which stays the repo's admin, activates
// the repo once it holds generation 1. Two member devices that act at once race at the repo's first form, and the
// loser's 409, a form standing that is not its own, discards its draft (ErrGkmGroupFormed). The state must already
// hold the repo's row, its RepoCreate applied, or the holders cannot be computed and CreateGroup answers
// ErrGkmNoRepo for its caller to retry once the log advances.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose a GroupForm is signed under (QD-527), as gkmservice verifies it.
const gkmGroupFormPurpose = "group-form"

// Another device formed the repo's group first: this creation's draft is discarded, and the device joins the group
// that stands by its Welcome.
var ErrGkmGroupFormed = errors.New("gkm: another device formed the repo's group")

// KF1's draft as the keychain holds it: the group drawn, RK_1 and the request, byte for byte.
type gkmCreateDraft struct {
	groupId Id
	repoKey []byte
	request []byte
}

// KF1: the repo's group, epoch 0 and generation 1 at gkm, then generation 1's deliveries while the repo is still
// keying, resuming after a crash. Returns RK_1, whose GroupId names the group.
func (self *GkmGroupClient) CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	if args == nil || args.RepoId == (Id{}) || args.Kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		return nil, fmt.Errorf("%w: a group needs its repo and kind", ErrGkmMalformed)
	}
	if self.args.Mls == nil {
		return nil, fmt.Errorf("%w: a sidecar that holds no leaf creates no group", ErrGkmUnavailable)
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
	if state.Repo(self.repoId) == nil {
		return nil, fmt.Errorf("%w: repo %s: its RepoCreate has not reached this state", ErrGkmNoRepo, self.repoId)
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
		if draft == nil {
			draft, err = self.draftCreate(state, args)
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
		group, err := client.loadGroup(draft.groupId)
		if err != nil {
			return nil, err
		}
		headerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: 1, Auth: generation.Rotate.GetAuth()})
		if err != nil {
			return nil, err
		}
		err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
			pins.groupId = draft.groupId
			pins.epoch = group.Epoch()
			pins.epochAuthenticator = group.EpochAuthenticator()
			pins.epochHeader = headerBytes
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

// Step 2: the group's id, its MLS state, RK_1 and the whole POST /gkm/groups request.
func (self *gkmGroupManager) draftCreate(state GkmAuthView, args *GkmCreateGroupArgs) (*gkmCreateDraft, error) {
	client := self.client
	groupId := Id{}
	// never fails: a broken system generator crashes the program instead
	rand.Read(groupId[:])
	group, err := client.args.Mls.CreateGroup(groupId, &MlsUrGroup{NetworkId: args.NetworkId, RepoId: args.RepoId, Kind: args.Kind, OwnerMemberId: args.OwnerMemberId})
	if err != nil {
		return nil, err
	}
	now := client.clock.Now()
	holders, err := KeyHolders(state, self.repoId, now)
	if err != nil {
		return nil, err
	}
	targets, err := self.deliverySet(context.Background(), state, holders, now, group.Roster(), false)
	if err != nil {
		return nil, err
	}
	generationArgs := &GkmGenerationArgs{Cause: GkmCauseRequest, Auth: state.Pin(), Time: now, HoldersSha256: holders.Sha256(), WrapCount: uint32(len(targets))}
	if GkmRepoKindTakesDeposits(args.Kind) {
		generationArgs.DropNotAfter = now.Add(client.settings.DropKeyLifetime)
	}
	key, rotate, err := NewGkmFirstGeneration(self.repoId, groupId, generationArgs)
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
	request, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmGroupCreateRequest{
		Form: signedForm, GenRotate: signedRotate, GenWrap: genWrap, SealedGroupInfo: sealedGroupInfo, CipherSuite: uint32(mlsCipherSuiteXWing),
	})
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
	targets, err := self.deliverySet(ctx, draftState, holders, at, roster, false)
	if err != nil {
		return nil, err
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
