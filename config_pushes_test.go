// api's descent walk of a base's config head (plan-TEAM-api-config-head-reach): a walk from C_0 for base 1 and from
// the previous base's head after it reaches the header's head, an unchanged version keeps its head, and each way a
// push could break the chain is refused.

package sidecar

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A config repo's ref, its pushes made as a config writer makes them, each signed by its key.
type configPushesTestRef struct {
	repoId Id
	refId  Id
	key    ed25519.PrivateKey
	// pushes[v-1] makes version v, chains[v] is C_v
	pushes [][]byte
	chains [][sha256.Size]byte
}

func newConfigPushesTestRef(t *testing.T, repoId Id) *configPushesTestRef {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	self := &configPushesTestRef{repoId: repoId, refId: NewId(), key: key}
	self.chains = append(self.chains, EvsChainStart(repoId, self.refId))
	return self
}

// A Signed EvsPush of push, its fields the walk reads and its signer's.
func (self *configPushesTestRef) sign(push *protocol.EvsPush) []byte {
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(push)
	signed, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  push.GetSignerSidecarId(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes("evs-push", bridge.SignedType_SIGNED_EVS_PUSH, body)),
		Type:      uint32(bridge.SignedType_SIGNED_EVS_PUSH),
	})
	return signed
}

// The push that makes the next version, on the ref's chain.
func (self *configPushesTestRef) next() []byte {
	version := uint64(len(self.pushes))
	pushId := NewId()
	pushBytes := self.sign(&protocol.EvsPush{
		RepoId:          self.repoId.Bytes(),
		RefId:           self.refId.Bytes(),
		PushId:          pushId.Bytes(),
		BaseVersion:     version,
		BaseChain:       slices.Clone(self.chains[version][:]),
		SignerSidecarId: NewId().Bytes(),
	})
	self.pushes = append(self.pushes, pushBytes)
	self.chains = append(self.chains, EvsChainNext(self.chains[version], pushId, EvsStatementSha256(pushBytes)))
	return pushBytes
}

// The pushes that make versions after from through to.
func (self *configPushesTestRef) between(from uint64, to uint64) [][]byte {
	for uint64(len(self.pushes)) < to {
		self.next()
	}
	return slices.Clone(self.pushes[from:to])
}

// A header naming the ref's head at version.
func (self *configPushesTestRef) header(version uint64) *bridge.ProjectionHeader {
	self.between(0, version)
	return &bridge.ProjectionHeader{ConfigVersion: version, ConfigHeadSha256: slices.Clone(self.chains[version][:])}
}

// Base 1 walks from C_0 of the config repo and its pushes' ref, and each later base from the previous base's head.
func TestConfigPushesWalkToTheHead(t *testing.T) {
	ref := newConfigPushesTestRef(t, NewId())
	baseOne := ref.header(3)
	if err := CheckConfigPushes(ref.repoId, nil, baseOne, ref.between(0, 3)); err != nil {
		t.Fatalf("base 1: %v", err)
	}
	later := ref.header(7)
	if err := CheckConfigPushes(ref.repoId, baseOne, later, ref.between(3, 7)); err != nil {
		t.Fatalf("a later base: %v", err)
	}
	if err := CheckConfigPushes(ref.repoId, later, ref.header(7), nil); err != nil {
		t.Errorf("an unchanged version: %v", err)
	}
	if err := CheckConfigPushes(ref.repoId, later, ref.header(7), [][]byte{}); err != nil {
		t.Errorf("an unchanged version with an empty list: %v", err)
	}
}

// Every way a push or a header breaks the walk is refused as a rule.
func TestConfigPushesRefuseABrokenWalk(t *testing.T) {
	ref := newConfigPushesTestRef(t, NewId())
	previous := ref.header(2)
	header := ref.header(5)
	pushes := ref.between(2, 5)
	otherRepo := newConfigPushesTestRef(t, NewId())
	otherRef := newConfigPushesTestRef(t, ref.repoId)
	otherHead := ref.header(5)
	otherHead.ConfigHeadSha256 = otherRef.header(5).ConfigHeadSha256
	unchangedElsewhere := ref.header(2)
	unchangedElsewhere.ConfigHeadSha256 = otherRef.header(2).ConfigHeadSha256

	forged := func(change func(push *protocol.EvsPush)) [][]byte {
		forged := slices.Clone(pushes)
		signed := &bridge.Signed{}
		push := &protocol.EvsPush{}
		if proto.Unmarshal(forged[1], signed) != nil || proto.Unmarshal(signed.GetBody(), push) != nil {
			t.Fatal("a test push does not parse")
		}
		change(push)
		forged[1] = ref.sign(push)
		return forged
	}
	notAPush := slices.Clone(pushes)
	notAPush[0], _ = proto.Marshal(&bridge.Signed{Body: []byte{1}, Type: uint32(bridge.SignedType_SIGNED_MEMBER_ADMIT)})
	tooLong := forged(func(push *protocol.EvsPush) { push.SealedMetadataSha256 = make([]byte, 1100) })

	cases := []struct {
		name     string
		previous *bridge.ProjectionHeader
		header   *bridge.ProjectionHeader
		pushes   [][]byte
	}{
		{name: "one push short", previous: previous, header: header, pushes: pushes[:2]},
		{name: "one push past", previous: previous, header: header, pushes: append(slices.Clone(pushes), ref.between(5, 6)...)},
		{name: "two pushes swapped", previous: previous, header: header, pushes: [][]byte{pushes[1], pushes[0], pushes[2]}},
		{name: "a push from before the previous base", previous: previous, header: header, pushes: ref.between(1, 4)},
		{name: "a head the walk does not reach", previous: previous, header: otherHead, pushes: pushes},
		{name: "an unchanged version naming another head", previous: previous, header: unchangedElsewhere, pushes: nil},
		{name: "another repo's pushes", previous: nil, header: otherRepo.header(3), pushes: otherRepo.between(0, 3)},
		{name: "a push of another ref", previous: previous, header: header, pushes: forged(func(push *protocol.EvsPush) { push.RefId = NewId().Bytes() })},
		{name: "a push of another repo", previous: previous, header: header, pushes: forged(func(push *protocol.EvsPush) { push.RepoId = NewId().Bytes() })},
		{name: "a push reading another version", previous: previous, header: header, pushes: forged(func(push *protocol.EvsPush) { push.BaseVersion += 1 })},
		{name: "a push reading another chain", previous: previous, header: header, pushes: forged(func(push *protocol.EvsPush) { push.BaseChain = make([]byte, sha256.Size) })},
		{name: "a push with no push id", previous: previous, header: header, pushes: forged(func(push *protocol.EvsPush) { push.PushId = nil })},
		{name: "a statement that is no EvsPush", previous: previous, header: header, pushes: notAPush},
		{name: "a push past 1 KiB", previous: previous, header: header, pushes: tooLong},
		{name: "base 1 naming no head", previous: nil, header: &bridge.ProjectionHeader{ConfigHeadSha256: make([]byte, sha256.Size)}, pushes: nil},
		{name: "a head that is no chain value", previous: previous, header: &bridge.ProjectionHeader{ConfigVersion: 5, ConfigHeadSha256: []byte{1}}, pushes: pushes},
		{name: "a version below the previous base's", previous: header, header: previous, pushes: nil},
		{name: "past 4,096 pushes", previous: previous, header: header, pushes: make([][]byte, ConfigPushesMaxCount+1)},
	}
	for _, c := range cases {
		if err := CheckConfigPushes(ref.repoId, c.previous, c.header, c.pushes); !errors.Is(err, ErrConfigRule) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// the same pushes walk, so each refusal above is its change's
	if err := CheckConfigPushes(ref.repoId, previous, header, pushes); err != nil {
		t.Errorf("the pushes unchanged: %v", err)
	}
}

// The log's method reads the newest base and Genesis's config repo at its tip: base 1 walks from C_0 of the genesis's
// config repo, and the next base from base 1's head.
func TestConfigLogChecksConfigPushesAtItsTip(t *testing.T) {
	net := newTestConfigNet(t)
	ref := newConfigPushesTestRef(t, testConfigId("config repo"))
	log, err := NewConfigLogRowsOnly(nil, net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	rows := testConfigMarshal(t, &bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: net.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         net.owner.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{net.owner.sidecarId.Bytes()},
			IdentityPublicKey: net.owner.publicKey(),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          net.ownerMemberId.Bytes(),
		}},
	})
	rowsSha256 := sha256.Sum256(rows)
	rowsSource := ConfigRowsOnlySource(func(networkId Id, wanted []byte) ([]byte, error) {
		return rows, nil
	})
	signedHeader := func(n uint64, prevChain []byte, foldedThrough uint64, configVersion uint64) []byte {
		return net.sign(net.owner, bridge.SignedType_SIGNED_PROJECTION_HEADER, &bridge.ProjectionHeader{
			NetworkId:        net.networkId.Bytes(),
			Version:          n,
			PrevChain:        prevChain,
			FoldedThrough:    foldedThrough,
			ConfigVersion:    configVersion,
			ConfigHeadSha256: ref.header(configVersion).GetConfigHeadSha256(),
			RowsSha256:       rowsSha256[:],
			RowsByteCount:    uint32(len(rows)),
		})
	}
	genesisChain := bridge.GenesisChain(net.signedGenesis)
	baseOne := signedHeader(1, genesisChain[:], 0, 2)
	if err := log.CheckBase(baseOne, rows, testConfigStartMs); err != nil {
		t.Fatal(err)
	}
	if err := log.CheckConfigPushes(baseOne, ref.between(0, 2)); err != nil {
		t.Fatalf("base 1: %v", err)
	}
	if err := log.CheckConfigPushes(baseOne, ref.between(0, 1)); !errors.Is(err, ErrConfigRule) {
		t.Errorf("base 1 one push short: %v", err)
	}
	entry := testConfigMarshal(t, &bridge.AuthEntry{
		NetworkId: net.networkId.Bytes(), N: 1, PrevChain: genesisChain[:], Kind: bridge.AuthEntryKindBase, TimeMs: testConfigStartMs, Body: baseOne,
	})
	if verdict, err := log.Apply(entry, rowsSource); err != nil || !verdict.Accepted() {
		t.Fatalf("base 1 applied: %v %v", err, verdict.Refusal)
	}
	next := signedHeader(2, log.Pin().GetChain(), 1, 4)
	if err := log.CheckConfigPushes(next, ref.between(2, 4)); err != nil {
		t.Errorf("base 2: %v", err)
	}
	if err := log.CheckConfigPushes(next, ref.between(0, 4)); !errors.Is(err, ErrConfigRule) {
		t.Errorf("base 2 walked from C_0: %v", err)
	}
	if err := log.CheckConfigPushes([]byte{0xff}, nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a header that does not parse: %v", err)
	}
}
