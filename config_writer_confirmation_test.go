package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The head visible while re-signing an ACL publication. A second prepared write is a test failure.
type testConfirmedAclRetryRef struct {
	ConfigHeadRef
	t   *testing.T
	tip ConfigHeadTip
}

func (self *testConfirmedAclRetryRef) CurrentConfigHead(ctx context.Context) (*ConfigHead, uint64, [sha256.Size]byte, error) {
	return self.tip.Head, self.tip.Version, self.tip.Chain, nil
}

func (self *testConfirmedAclRetryRef) PrepareConfigHead(ctx context.Context, head *ConfigHead, version uint64) (*ConfigHeadPush, error) {
	self.t.Fatal("an approved EVS push already landed. The projection retry prepared a second edit")
	return nil, nil
}

func TestConfirmedAclPublicationRetryKeepsItsCommittedHead(t *testing.T) {
	net := newTestConfigNet(t)
	first := net.log.State().Base()
	if verdict := net.fold(net.owner, 1, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	base := net.log.State().Base()
	head, err := newTestConfigHeadReader(net).ReadConfigHead(t.Context(), base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	ref := &testConfirmedAclRetryRef{t: t, tip: ConfigHeadTip{Head: head}}
	client := &ConfigClient{}
	client.configLog.Store(net.log)
	writer := newConfigWriter(t.Context(), &ConfigWriterArgs{Client: client, SidecarId: net.owner.sidecarId, Heads: ref})
	defer writer.Close()
	approved := &ConfigHeadTip{Version: 2, Chain: sha256.Sum256([]byte("previewed config head"))}
	committed := &configWriterPlan{previousN: first.GetVersion(), configVersion: 3, headChain: sha256.Sum256([]byte("confirmed policy"))}

	// Another BASE forced a fresh projection plan after the approved push landed.
	// A later disjoint head and a different chain at the same version both require fresh consent.
	for _, v := range []uint64{4, 3} {
		ref.tip.Version, ref.tip.Chain = v, sha256.Sum256([]byte("another config head"))
		if _, err := writer.plan(t.Context(), committed, &configWriterRequest{expected: approved}); !errors.Is(err, ErrConfigHeadConflict) {
			t.Fatalf("publication retry at %d accepted a different config ref: %v", v, err)
		}
	}
	// A newly required fold would send a second EVS push within this one approval.
	ref.tip.Version, ref.tip.Chain = committed.configVersion, committed.headChain
	if _, err := writer.plan(t.Context(), committed, &configWriterRequest{fold: true, expected: approved}); !errors.Is(err, ErrConfigHeadConflict) {
		t.Fatalf("publication retry with another required fold: %v", err)
	}

	// A new auth-log statement alone can re-sign the identical projection plan.
	committed.previousN = base.GetVersion()
	net.admitMember(net.owner, testConfigId("member after approval"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	plan, err := writer.plan(t.Context(), committed, &configWriterRequest{expected: approved})
	if err != nil || plan != committed {
		t.Fatalf("unrelated auth entry discarded the already committed config plan: %v", err)
	}
}
