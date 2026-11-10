// The config repo's file-mode main ref in memory (§11.8), as T2's config writers save heads to it and readers check
// them: each version's ConfigHead, the Signed EvsPush that made it and the chain value C_v, from C_0 =
// SHA-256("UR evs 1.0 ref" || repo_id || ref_id), with If-Match on the version, so two writers race as on evs. Every
// device of a network shares one; each writes through For, which signs its pushes by that device's identity key, and
// reads through ReadConfigHead, which answers the head at a version only when C_v is the one a base names. Pushes carry
// what api's walk reads (plan-TEAM-api-config-head-reach): the repo, the ref, the push id, the version and chain read,
// and the signer. Also here: a ConfigProjectionReader and a ConfigBasePublisher over FakeApi, for a ConfigClient and a
// ConfigWriter on T2 without a SidecarApi.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One network's config repo main ref.
type FakeConfigHeads struct {
	repoId sidecar.Id
	refId  sidecar.Id

	stateLock sync.Mutex
	// heads[v-1] and pushes[v-1] are version v's; chains[v] is C_v
	heads  []*sidecar.ConfigHead
	pushes [][]byte
	chains [][sha256.Size]byte
}

// The ref of the config repo repoId, empty: version 0 at C_0.
func NewFakeConfigHeads(repoId sidecar.Id) *FakeConfigHeads {
	var refId sidecar.Id
	rand.Read(refId[:])
	return &FakeConfigHeads{repoId: repoId, refId: refId, chains: [][sha256.Size]byte{sidecar.EvsChainStart(repoId, refId)}}
}

// The newest version.
func (self *FakeConfigHeads) Version() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return uint64(len(self.heads))
}

// sidecar.ConfigHeadReader: the head at version when the ref's C_v there is configHeadSha256; unavailable past the
// newest version, as a push not yet made, and another head's mismatch when C_v differs.
func (self *FakeConfigHeads) ReadConfigHead(ctx context.Context, version uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if version == 0 || uint64(len(self.heads)) < version {
		return nil, fmt.Errorf("%w: version %d not pushed", sidecar.ErrConfigHeadUnavailable, version)
	}
	if !bytes.Equal(self.chains[version][:], configHeadSha256) {
		return nil, fmt.Errorf("%w: the ref's chain at %d is another", sidecar.ErrConfigHeadMismatch, version)
	}
	return self.heads[version-1], nil
}

// The ref as one device writes it, signing its pushes by key.
func (self *FakeConfigHeads) For(sidecarId sidecar.Id, key ed25519.PrivateKey) *FakeConfigHeadStore {
	return &FakeConfigHeadStore{heads: self, sidecarId: sidecarId, key: key}
}

// One device's sidecar.ConfigHeadStore over the shared ref.
type FakeConfigHeadStore struct {
	heads     *FakeConfigHeads
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
}

// The newest head, version and C_v.
func (self *FakeConfigHeadStore) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	self.heads.stateLock.Lock()
	defer self.heads.stateLock.Unlock()
	version := uint64(len(self.heads.heads))
	if version == 0 {
		return nil, 0, self.heads.chains[0], nil
	}
	return self.heads.heads[version-1], version, self.heads.chains[version], nil
}

// A push of head after version, signed by this device, under evs-push's purpose (§6.11).
func (self *FakeConfigHeadStore) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	self.heads.stateLock.Lock()
	defer self.heads.stateLock.Unlock()
	if uint64(len(self.heads.heads)) < version {
		return nil, fmt.Errorf("%w: version %d is past the ref's %d", sidecar.ErrConfigHeadConflict, version, len(self.heads.heads))
	}
	baseChain := self.heads.chains[version]
	var pushId sidecar.Id
	rand.Read(pushId[:])
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsPush{
		RepoId:          self.heads.repoId.Bytes(),
		RefId:           self.heads.refId.Bytes(),
		PushId:          pushId.Bytes(),
		BaseVersion:     version,
		BaseChain:       bytes.Clone(baseChain[:]),
		SignerSidecarId: self.sidecarId.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	signedPush, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes("evs-push", bridge.SignedType_SIGNED_EVS_PUSH, body)),
		Type:      uint32(bridge.SignedType_SIGNED_EVS_PUSH),
	})
	if err != nil {
		return nil, err
	}
	return &sidecar.ConfigHeadPush{
		Head:       head,
		Version:    version + 1,
		Chain:      sidecar.EvsChainNext(baseChain, pushId, sidecar.EvsStatementSha256(signedPush)),
		SignedPush: signedPush,
	}, nil
}

// Applies a prepared push If-Match on its version: the same push again is success, another at that version a
// conflict.
func (self *FakeConfigHeadStore) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	self.heads.stateLock.Lock()
	defer self.heads.stateLock.Unlock()
	version := uint64(len(self.heads.heads))
	switch {
	case push.Version <= version && self.heads.chains[push.Version] == push.Chain:
		return nil
	case push.Version != version+1:
		return fmt.Errorf("%w: a push for %d at version %d", sidecar.ErrConfigHeadConflict, push.Version, version)
	}
	self.heads.heads = append(self.heads.heads, push.Head)
	self.heads.pushes = append(self.heads.pushes, bytes.Clone(push.SignedPush))
	self.heads.chains = append(self.heads.chains, push.Chain)
	return nil
}

// The Signed EvsPush of each version in (after, through].
func (self *FakeConfigHeadStore) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	self.heads.stateLock.Lock()
	defer self.heads.stateLock.Unlock()
	if through < after || uint64(len(self.heads.pushes)) < through {
		return nil, fmt.Errorf("%w: pushes (%d, %d] of %d", sidecar.ErrConfigHeadConflict, after, through, len(self.heads.pushes))
	}
	pushes := [][]byte{}
	for _, push := range self.heads.pushes[after:through] {
		pushes = append(pushes, bytes.Clone(push))
	}
	return pushes, nil
}

// sidecar.ConfigProjectionReader over a FakeApi's log of one network: GET /network/config/projection's read, with no
// HTTP between.
type FakeApiConfigReader struct {
	Api       *FakeApi
	NetworkId sidecar.Id
}

func (self *FakeApiConfigReader) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	read, err := self.Api.ReadProjection(ctx, self.NetworkId, after, true)
	if err != nil {
		return nil, err
	}
	projection := &sidecar.ConfigProjection{SignedGenesis: read.SignedGenesis, Entries: read.Entries, Tip: read.Tip, More: read.More}
	for _, rows := range read.Rows {
		projection.Rows = append(projection.Rows, rows)
	}
	return projection, nil
}

// sidecar.ConfigBasePublisher over a FakeApi: POST /network/config/projection's append, a 409 ErrConfigTipMoved and a
// 403 an ErrConfigRefused, as SidecarApi answers them.
type FakeApiConfigPublisher struct {
	Api       *FakeApi
	NetworkId sidecar.Id
	// Runs before each publish reaches api, as another appender landing first; nil runs none.
	Before func(ctx context.Context)
}

func (self *FakeApiConfigPublisher) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	if self.Before != nil {
		self.Before(ctx)
	}
	pin, err := self.Api.AppendBase(ctx, self.NetworkId, base.SignedHeader, base.Rows, base.Genesis, base.ConfigPushes)
	if err == nil {
		return pin, nil
	}
	refusal := &ConfigLogRefusal{}
	if errors.As(err, &refusal) {
		switch refusal.Status {
		case http.StatusConflict:
			return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigTipMoved, err)
		case http.StatusForbidden:
			return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigRefused, err)
		}
	}
	return nil, err
}
