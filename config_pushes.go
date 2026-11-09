// A base's config head descent at api (plan-TEAM-api-config-head-reach). api never reads the config repo, so a config
// writer's base carries config_pushes, the Signed EvsPush of each config version the base adds, oldest first, and api
// walks the config repo's ref chain (§11.8) from the previous base's head to this one's:
//
//	start   the previous base's (config_version, config_head_sha256); for base 1, (0, C_0) with
//	        C_0 = SHA-256("UR evs 1.0 ref" || config_repo_id || ref_id), Genesis's config repo and the pushes' ref
//	each    a push names the config repo and the walk's ref, its base_version and base_chain are the running (v, C),
//	        and then C = SHA-256(C || push_id || SHA-256(Signed EvsPush as received)) and v + 1
//	end     (v, C) is the header's (config_version, config_head_sha256)
//
// An unchanged config_version takes no push and names the previous base's head, so no base names another head at an
// old version. Base 1 names a head, the first one, whose push precedes it. At most 4,096 pushes ride one base, each at
// most an EvsPush statement's 1 KiB. api judges descent alone: who signed each push, its shape past what the walk
// reads, and what the head holds are readers' checks, which they make on the config repo itself, as are records,
// signer roles and the compile. main's ref id is HMAC'd under a config key api never holds, so base 1's ref is the one
// its pushes name, every push of one base naming the same, and a later base's chain value already binds its ref. The
// pushes are not stored, so the log's bytes are as before.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most config pushes one base carries.
const ConfigPushesMaxCount = 4096

// Whether configPushes walk the config repo's chain from previous's head to header's (above). previous is the newest
// base's header, nil before base 1; configRepoId is Genesis's config_repo_id. A refusal is an ErrConfigRule, which api
// answers 403.
func CheckConfigPushes(configRepoId Id, previous *bridge.ProjectionHeader, header *bridge.ProjectionHeader, configPushes [][]byte) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: config pushes: %s", ErrConfigRule, fmt.Sprintf(format, args...))
	}
	if ConfigPushesMaxCount < len(configPushes) {
		return refuse("%d pushes, past %d", len(configPushes), ConfigPushesMaxCount)
	}
	headSha256, err := EvsChainFromBytes(header.GetConfigHeadSha256())
	if err != nil {
		return refuse("config_head_sha256 is not a chain value")
	}
	version := uint64(0)
	var chain [sha256.Size]byte
	if previous == nil {
		if header.GetConfigVersion() == 0 {
			return refuse("base 1 names no config head")
		}
	} else {
		version = previous.GetConfigVersion()
		chain, err = EvsChainFromBytes(previous.GetConfigHeadSha256())
		if err != nil {
			return refuse("the previous base's config_head_sha256 is not a chain value")
		}
	}
	if header.GetConfigVersion() < version {
		return refuse("config_version %d below the previous base's %d", header.GetConfigVersion(), version)
	}
	if uint64(len(configPushes)) != header.GetConfigVersion()-version {
		return refuse("%d pushes for config versions %d to %d", len(configPushes), version, header.GetConfigVersion())
	}

	var refId []byte
	for i, pushBytes := range configPushes {
		if EvsStatementMaxByteCount < len(pushBytes) {
			return refuse("push %d of %d bytes, past an EvsPush statement's", i, len(pushBytes))
		}
		signed := &bridge.Signed{}
		push := &protocol.EvsPush{}
		if proto.Unmarshal(pushBytes, signed) != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_EVS_PUSH) ||
			proto.Unmarshal(signed.GetBody(), push) != nil {
			return refuse("push %d is no Signed EvsPush", i)
		}
		if !bytes.Equal(push.GetRepoId(), configRepoId.Bytes()) {
			return refuse("push %d names another repo than the config repo", i)
		}
		if len(push.GetRefId()) != len(Id{}) || len(push.GetPushId()) != len(Id{}) {
			return refuse("push %d's ref_id or push_id is not an id", i)
		}
		if refId == nil {
			refId = push.GetRefId()
			if previous == nil {
				chain = EvsChainStart(configRepoId, Id(refId))
			}
		} else if !bytes.Equal(push.GetRefId(), refId) {
			return refuse("push %d names another ref than push 0", i)
		}
		if push.GetBaseVersion() != version {
			return refuse("push %d reads version %d, not the walk's %d", i, push.GetBaseVersion(), version)
		}
		if !bytes.Equal(push.GetBaseChain(), chain[:]) {
			return refuse("push %d reads another chain value than the walk's at version %d", i, version)
		}
		chain = EvsChainNext(chain, Id(push.GetPushId()), EvsStatementSha256(pushBytes))
		version += 1
	}
	if chain != headSha256 {
		return refuse("the walk ends at another head than config_head_sha256 at version %d", version)
	}
	return nil
}

// CheckConfigPushes on the log's tip: the newest base's header and Genesis's config repo, for a base whose header
// CheckBase took. For the goroutine that applies, as Apply is.
func (self *ConfigLog) CheckConfigPushes(signedHeader []byte, configPushes [][]byte) error {
	signed := &bridge.Signed{}
	header := &bridge.ProjectionHeader{}
	if proto.Unmarshal(signedHeader, signed) != nil || proto.Unmarshal(signed.GetBody(), header) != nil {
		return fmt.Errorf("%w: a base header that does not parse", ErrConfigRule)
	}
	state := self.State()
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return fmt.Errorf("%w: the genesis names no config repo", ErrConfigRule)
	}
	return CheckConfigPushes(configRepoId, state.Base(), header, configPushes)
}
