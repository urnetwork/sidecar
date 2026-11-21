//go:build !ios_extension && !sidecar_http

// The first CLI device runs §7.9's bootstrap from its config follower. A sealed draft retains the
// repo, Genesis time and exact first push until EVS activates the config repo and accepts that push.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const sidecarFirstConfigDraftName = "first_config_draft"

// Each owner's candidate stays private to its sidecar. Its first push includes randomized sealed payload bytes.
type sidecarFirstConfigDraft struct {
	RepoId        Id
	OwnerMemberId Id
	SidecarId     Id
	TimeMillis    int64
	Team          bool              `json:",omitempty"`
	PolicyFiles   map[string][]byte `json:",omitempty"`
	Chain         [sha256.Size]byte
	SignedPush    []byte
	Payload       []byte
}

// Keeps the candidate before any POST that may win the race at the API.
func (self *sidecarFirstConfigDraft) keep(secrets SidecarSecrets) error {
	record, err := json.Marshal(self)
	if err != nil {
		return err
	}
	return secrets.Put(sidecarFirstConfigDraftName, record)
}

// Returns the API's winning signed Genesis. An existing winning draft must finish its repo and first
// head even if a prior process already published base 1. Only the verified winner becomes the anchor.
func (self *SidecarConfigFollower) firstOwnerGenesis(ctx context.Context, networkId Id, served []byte, readErr error) ([]byte, error) {
	running := self.sidecar
	identity := running.Identity()
	if identity == nil || identity.NetworkId != networkId {
		return nil, ErrSidecarNoIdentity
	}
	secrets := running.instance.secrets(networkId, sidecarCoreSecretsNamespace)
	draft := &sidecarFirstConfigDraft{}
	record, err := secrets.Get(sidecarFirstConfigDraftName)
	switch {
	case err == nil:
		if err := json.Unmarshal(record, draft); err != nil || draft.RepoId == (Id{}) ||
			draft.SidecarId != identity.SidecarId || draft.OwnerMemberId == (Id{}) {
			return nil, ErrSidecarStoreFailed
		}
		if len(served) > 0 {
			log, err := NewConfigLog(self.logSettings(), served)
			if err != nil || log.State().NetworkId() != networkId {
				return nil, ErrSidecarAnchorMismatch
			}
			genesis := log.State().Genesis()
			if !bytes.Equal(genesis.GetOwnerSidecarId(), identity.SidecarId.Bytes()) || !bytes.Equal(genesis.GetConfigRepoId(), draft.RepoId.Bytes()) {
				return served, secrets.Delete(sidecarFirstConfigDraftName)
			}
		}
	case errors.Is(err, ErrSidecarStoreAbsent):
		if readErr != nil {
			// A failed GET says nothing about the existence of another owner's Genesis.
			return nil, readErr
		}
		if len(served) > 0 {
			return served, nil
		}
		claims := parseSidecarJwt(running.sidecarApi.currentByJwt())
		member := claims.stringClaim("member_id")
		// Only a Team credential carries a member_id. The API authenticates this same
		// device and verifies its owner's membership before accepting its Genesis.
		team := member != ""
		if !team {
			member = claims.stringClaim("user_id")
		}
		memberId, err := ParseId(member)
		if err != nil || memberId == (Id{}) {
			return nil, errors.New("no owner membership is available for the first configuration")
		}
		draft = &sidecarFirstConfigDraft{RepoId: NewEvsRepoId(), OwnerMemberId: memberId, Team: team,
			SidecarId: identity.SidecarId, TimeMillis: self.clock.Now().UnixMilli()}
		if err := draft.keep(secrets); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	gkm := self.args.Gkm
	drafter, ok := gkm.(GkmGroupDrafter)
	if !ok {
		return nil, ErrGkmUnavailable
	}
	var landed atomic.Pointer[ConfigState]
	evsArgs, err := running.EvsClientArgs(gkm, func() GkmAuthView {
		if state := landed.Load(); state != nil {
			return state
		}
		return nil
	}, func(context.Context, bridge.SignedType, proto.Message) error {
		return errors.New("the config repo is named in Genesis")
	})
	if err != nil {
		return nil, err
	}
	evs, err := NewEvsClient(evsArgs)
	if err != nil {
		return nil, err
	}
	defer evs.Close()
	result, err := BootstrapNetwork(ctx, &ConfigBootstrapArgs{
		NetworkId: networkId, SidecarId: identity.SidecarId, IdentityPublicKey: identity.IdentityPublicKey,
		OwnerMemberId: draft.OwnerMemberId, ConfigRepoId: draft.RepoId, GenesisTime: time.UnixMilli(draft.TimeMillis),
		Sign: func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return running.Sign(purpose, signedType, body, nil)
		},
		Publisher: running.sidecarApi, Projection: running.sidecarApi,
		First: &ConfigFirstHead{
			Initialize: func(ctx context.Context, genesis *ConfigState, head *ConfigHead) (*ConfigHead, error) {
				if !draft.Team {
					return head, nil
				}
				if len(draft.SignedPush) != 0 {
					// Its randomized atom and rule ids are already in the signed push.
					return restoreFirstAclFiles(head, draft.PolicyFiles)
				}
				quota, err := running.sidecarApi.Limits(ctx)
				if err != nil {
					return nil, err
				}
				plan, err := planFirstTeamAcl(ctx, genesis, head, quota, self.clock.Now())
				if err != nil {
					return nil, err
				}
				draft.PolicyFiles = make(map[string][]byte, len(aclSaveHeadPaths))
				for _, path := range aclSaveHeadPaths {
					draft.PolicyFiles[path] = plan.Head.File(path)
				}
				return plan.Head, nil
			},
			Draft: func(ctx context.Context, genesis *ConfigState) (*EvsRepoKey, error) {
				// The tentative state serves only to draft the candidate's local config group.
				if joiner, ok := gkm.(GkmConfigJoiner); ok {
					joiner.AuthUnconfirmed(genesis, draft.RepoId)
				}
				return drafter.DraftGroup(ctx, &GkmCreateGroupArgs{NetworkId: networkId, RepoId: draft.RepoId, Kind: protocol.RepoKind_REPO_KIND_CONFIG})
			},
			Prepare: func(ctx context.Context, key *EvsRepoKey, genesis *ConfigState, head *ConfigHead) (*ConfigHeadPush, error) {
				if len(draft.SignedPush) > 0 {
					return &ConfigHeadPush{Head: head, Version: 1, Chain: draft.Chain, SignedPush: draft.SignedPush, Payload: draft.Payload}, nil
				}
				push, err := evs.PrepareConfigHead(ctx, key, genesis, head)
				if err != nil {
					return nil, err
				}
				draft.Chain, draft.SignedPush, draft.Payload = push.Chain, push.SignedPush, push.Payload
				return push, draft.keep(secrets)
			},
			Commit: evs.CommitConfigHead,
		},
		BaseLanded: func(ctx context.Context, state *ConfigState) error {
			landed.Store(state)
			gkm.AuthAdvanced(state)
			return nil
		},
		CreateRepo: func(ctx context.Context) error {
			_, err := evs.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_CONFIG, ResumeRepoId: &draft.RepoId})
			return err
		},
	})
	if err != nil {
		return nil, fmt.Errorf("the first configuration is pending: %w", err)
	}
	if !result.Won {
		winner, err := NewConfigLog(self.logSettings(), result.SignedGenesis)
		if err != nil || winner.State().NetworkId() != networkId {
			return nil, ErrSidecarAnchorMismatch
		}
	}
	return result.SignedGenesis, secrets.Delete(sidecarFirstConfigDraftName)
}

// A retry of the exact already-sealed Team head. Empty table files are significant.
func restoreFirstAclFiles(head *ConfigHead, files map[string][]byte) (*ConfigHead, error) {
	restored := head.Files()
	for _, path := range aclSaveHeadPaths {
		contents, found := files[path]
		if !found {
			return nil, ErrSidecarStoreFailed
		}
		if contents != nil {
			restored[path] = contents
		} else {
			delete(restored, path)
		}
	}
	return NewConfigHead(restored)
}

// The Owner's Team creation includes the fixed starter. Its request rule and grants must
// fit the network's effective limits, and its policy tests must pass before the first signature.
func planFirstTeamAcl(ctx context.Context, state *ConfigState, head *ConfigHead, quota *QuotaLimits, now time.Time) (*AclSavePlan, error) {
	requests := 0
	if quotaLocalLimit(quota, "acl_requests") != 0 {
		requests = -1
	}
	rules := min(quotaLocalLimit(quota, "acl_rules"), int64(math.MaxInt))
	limits := &AclLimits{Rules: int(rules), Requests: requests}
	plan, err := PlanAclSave(ctx, &AclSaveInput{Policy: AclTeamStartDocument(), Head: head, State: state, Limits: limits, Now: now})
	if err != nil {
		return nil, err
	}
	if err := plan.Tests.Err(); err != nil {
		return nil, err
	}
	return plan, nil
}
