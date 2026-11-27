//go:build !sidecar_http && !js && !ios_extension

// The network's acknowledgment saved through TEAM's writer on T2's fake api (CTRUST-M12-02), every reader recompiling
// the head with CompileAcl (acl_save_test.go's world): with no document it lands in the block-alone record, which sets
// no reach; in a document through the policy save path, which changes no rows; another writer's save carries it byte for
// byte; a removal narrows; and each entry the owner's device saved is taken at the state the readers stand at.

package sidecar_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The fixture policy's source: the root's disclosures line, engy and SayGM direct, Chutes AP.
type testNetworkDisclosureSource struct {
	policy *sidecar.ComputePolicy
}

func (self *testNetworkDisclosureSource) Newest() *sidecar.ComputePolicy {
	return self.policy
}

// The acl save world with a registry over the fixture policy.
type testNetworkDisclosureSaveWorld struct {
	*testAclSaveWorld
	registry *sidecar.ComputeDisclosureRegistry
}

func newTestNetworkDisclosureSaveWorld(t *testing.T) *testNetworkDisclosureSaveWorld {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "disclosure", "disclosures.json"))
	if err != nil {
		t.Fatal(err)
	}
	disclosures := []*sidecar.ComputePolicyDisclosure{}
	if err := json.Unmarshal(data, &disclosures); err != nil {
		t.Fatal(err)
	}
	policy := &sidecar.ComputePolicy{
		Version:   3,
		Providers: []*sidecar.ComputePolicyProvider{{Id: "chutes", Label: sidecar.ComputeLabelAp}},
		Direct: sidecar.ComputePolicyDirectLine{Providers: []*sidecar.ComputePolicyDirect{
			{Slug: "engy"}, {Slug: "saygm"},
		}},
		Disclosures: disclosures,
	}
	registry, err := sidecar.NewComputeDisclosureRegistry(&sidecar.ComputeDisclosureRegistryArgs{Source: &testNetworkDisclosureSource{policy: policy}})
	if err != nil {
		t.Fatal(err)
	}
	return &testNetworkDisclosureSaveWorld{testAclSaveWorld: newTestAclSaveWorld(t), registry: registry}
}

// The owner's device's parts at the state and head the readers stand at now.
func (self *testNetworkDisclosureSaveWorld) parts() *sidecar.NetworkDisclosureWriterForTest {
	self.t.Helper()
	state := self.caughtUp(self.client)
	head, version, chain, err := self.heads.For(self.owner.sidecarId, self.owner.key).CurrentConfigHead(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	sign := self.owner.sign()
	return &sidecar.NetworkDisclosureWriterForTest{
		SidecarId: self.owner.sidecarId,
		Sign: func(body []byte) (*bridge.Signed, error) {
			return sign(sidecar.ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body)
		},
		Writer:   self.ownerWriter,
		State:    state,
		Tip:      &sidecar.ConfigHeadTip{Head: head, Version: version, Chain: chain, SupportsExactHead: true},
		Registry: self.registry,
		Now:      self.clock.Now(),
	}
}

// The owner's acknowledgment of id for the network, at its current version in English.
func (self *testNetworkDisclosureSaveWorld) ack(id string) *bridge.AuthPin {
	self.t.Helper()
	disclosure, err := self.registry.Disclosure(id)
	if err != nil {
		self.t.Fatal(err)
	}
	pin, err := sidecar.AckNetworkDisclosureOnWriterForTest(self.ctx, self.parts(), &sidecar.ComputeNetworkDisclosureAckArgs{
		Id: id, Version: disclosure.Version(), Locale: "en", Revision: disclosure.Revision(), Origin: sidecar.SidecarActConfirmed,
	})
	if err != nil {
		self.t.Fatalf("acknowledging %s: %v", id, err)
	}
	return pin
}

// The block the head holds now, its document's or its record's, nil for none.
func (self *testNetworkDisclosureSaveWorld) block() *sidecar.AclComputeBlock {
	self.t.Helper()
	head, _ := self.head()
	if document := head.File(sidecar.ConfigHeadPolicyPath); document != nil {
		policy, err := sidecar.ParseAclPolicy(document)
		if err != nil {
			self.t.Fatal(err)
		}
		return policy.Compute
	}
	if record := head.File(sidecar.ConfigHeadComputePath); record != nil {
		block, err := sidecar.ParseAclComputeRecord(record)
		if err != nil {
			self.t.Fatal(err)
		}
		return block
	}
	return nil
}

// The block's entries judged at the state the readers stand at now, by id.
func (self *testNetworkDisclosureSaveWorld) judged() map[string]*sidecar.ComputeNetworkDisclosure {
	self.t.Helper()
	statements := []sidecar.AclComputeDisclosure{}
	if block := self.block(); block != nil {
		statements = block.Disclosures
	}
	entries, err := sidecar.JudgeNetworkDisclosuresForTest(self.caughtUp(self.client), statements, self.registry, self.clock.Now())
	if err != nil {
		self.t.Fatal(err)
	}
	idEntries := map[string]*sidecar.ComputeNetworkDisclosure{}
	for _, entry := range entries {
		idEntries[entry.Id] = entry
	}
	return idEntries
}

// The statement the block holds for id, empty for none.
func (self *testNetworkDisclosureSaveWorld) statement(id string) string {
	self.t.Helper()
	if block := self.block(); block != nil {
		for _, disclosure := range block.Disclosures {
			if disclosure.Id == id {
				return disclosure.Statement
			}
		}
	}
	return ""
}

// rows with compute_rows taken out where it holds only a block's defaults, which the broker reads as unset (§16.5).
func testNetworkDisclosureReach(rows *protocol.AclRows) *protocol.AclRows {
	reach := proto.Clone(rows).(*protocol.AclRows)
	if proto.Equal(reach.GetComputeRows(), &protocol.AclComputeRows{SearchEnabled: true}) {
		reach.ComputeRows = nil
	}
	return reach
}

// With no document the acknowledgment lands in the block-alone record: has_document stays false, the readers' reach is
// as before, and the entry is the owner's, taken and covering at the state the readers stand at.
func TestNetworkDisclosureNoDocument(t *testing.T) {
	world := newTestNetworkDisclosureSaveWorld(t)
	before, err := world.caughtUp(world.client).Acl()
	if err != nil {
		t.Fatal(err)
	}
	beforeRows := proto.Clone(before.Rows()).(*protocol.AclRows)
	signedAt := world.caughtUp(world.client).Pin()
	world.ack("inference:engy")

	head, _ := world.head()
	if head.File(sidecar.ConfigHeadPolicyPath) != nil || head.File(sidecar.ConfigHeadComputePath) == nil {
		t.Fatal("the acknowledgment is not in a block-alone record")
	}
	after, err := world.caughtUp(world.client).Acl()
	if err != nil {
		t.Fatal(err)
	}
	if after.HasDocument() {
		t.Error("the record set has_document")
	}
	if !proto.Equal(testNetworkDisclosureReach(beforeRows), testNetworkDisclosureReach(after.Rows())) {
		t.Errorf("the rows moved:\nbefore %v\nafter  %v", beforeRows, after.Rows())
	}
	entry := world.judged()["inference:engy"]
	if entry == nil || !entry.Taken || !entry.Stands || entry.MemberId != world.owner.memberId || entry.SidecarId != world.owner.sidecarId ||
		entry.PinVersion != signedAt.GetVersion() || entry.Version != 1 || entry.Locale != "en" || entry.SignedAtMs == 0 {
		t.Fatalf("the entry %+v", entry)
	}
	// the text shown in another locale is recorded as shown
	world.ack("search:parallel")
	if entry := world.judged()["search:parallel"]; entry == nil || !entry.Taken {
		t.Fatalf("a second entry %+v", entry)
	}
}

// In a document the acknowledgment saves through the policy save path, adding the compute key where the document has
// none, and the readers' reach is as before.
func TestNetworkDisclosureInDocument(t *testing.T) {
	world := newTestNetworkDisclosureSaveWorld(t)
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(testAclSavePolicyA)); err != nil {
		t.Fatal(err)
	}
	before, err := world.caughtUp(world.client).Acl()
	if err != nil {
		t.Fatal(err)
	}
	beforeRows := proto.Clone(before.Rows()).(*protocol.AclRows)
	world.ack("inference:saygm")
	head, _ := world.head()
	document := string(head.File(sidecar.ConfigHeadPolicyPath))
	// the compute key added after the last member, every other byte as written
	added := `, "compute": {"disclosures": {"inference:saygm": "` + world.statement("inference:saygm") + `"}}`
	if world.statement("inference:saygm") == "" || strings.Replace(document, added, "", 1) != testAclSavePolicyA {
		t.Fatalf("the document:\n%s", document)
	}
	after, err := world.caughtUp(world.client).Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !after.HasDocument() || !proto.Equal(testNetworkDisclosureReach(beforeRows), testNetworkDisclosureReach(after.Rows())) {
		t.Errorf("the rows moved:\nbefore %v\nafter  %v", beforeRows, after.Rows())
	}
	if entry := world.judged()["inference:saygm"]; entry == nil || !entry.Taken || !entry.Stands {
		t.Fatalf("the entry %+v", entry)
	}
}

// Another writer's save carries an entry byte for byte: the network's first document takes the record's block in, and a
// later save of the document with its grants changed keeps every statement as it was, each still taken.
func TestNetworkDisclosureCarriedBySave(t *testing.T) {
	world := newTestNetworkDisclosureSaveWorld(t)
	world.ack("inference:engy")
	engy := world.statement("inference:engy")
	if engy == "" {
		t.Fatal("no entry")
	}
	// the first document takes the record in
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(testAclSavePolicyB)); err != nil {
		t.Fatal(err)
	}
	head, _ := world.head()
	if head.File(sidecar.ConfigHeadComputePath) != nil || world.statement("inference:engy") != engy {
		t.Fatalf("the first document did not carry the entry:\n%s", head.File(sidecar.ConfigHeadPolicyPath))
	}
	// an acknowledgment in the document, then a save of the document with its grants changed
	world.ack("search:parallel")
	search := world.statement("search:parallel")
	head, _ = world.head()
	changed := strings.Replace(string(head.File(sidecar.ConfigHeadPolicyPath)), `"allow": ["dial", "route"]`, `"allow": ["dial"]`, 1)
	if changed == string(head.File(sidecar.ConfigHeadPolicyPath)) {
		t.Fatalf("no grant to change in:\n%s", changed)
	}
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(changed)); err != nil {
		t.Fatal(err)
	}
	head, _ = world.head()
	if !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(changed)) || world.statement("inference:engy") != engy ||
		world.statement("search:parallel") != search {
		t.Fatalf("the save did not carry the entries:\n%s", head.File(sidecar.ConfigHeadPolicyPath))
	}
	judged := world.judged()
	for _, id := range []string{"inference:engy", "search:parallel"} {
		if entry := judged[id]; entry == nil || !entry.Taken || !entry.Stands {
			t.Errorf("%s after the save: %+v", id, entry)
		}
	}
}

// Removing an entry narrows: it leaves the block and the readers take it no more, the others stand, and removing what
// the block does not hold saves nothing; in a record and in a document alike.
func TestNetworkDisclosureRemoveNarrows(t *testing.T) {
	world := newTestNetworkDisclosureSaveWorld(t)
	world.ack("inference:engy")
	world.ack("search:parallel")
	remove := func(id string) *bridge.AuthPin {
		t.Helper()
		pin, err := sidecar.RemoveNetworkDisclosureOnWriterForTest(world.ctx, world.parts(),
			&sidecar.ComputeNetworkDisclosureRemoveArgs{Id: id, Origin: sidecar.SidecarActConfirmed})
		if err != nil {
			t.Fatalf("removing %s: %v", id, err)
		}
		return pin
	}
	if remove("inference:engy") == nil {
		t.Fatal("the removal saved nothing")
	}
	judged := world.judged()
	if judged["inference:engy"] != nil || judged["search:parallel"] == nil || !judged["search:parallel"].Stands {
		t.Fatalf("after the removal: %+v", judged)
	}
	_, version := world.head()
	if remove("inference:engy") != nil {
		t.Fatal("removing what the block does not hold saved")
	}
	if _, again := world.head(); again != version {
		t.Fatalf("the head moved from %d to %d", version, again)
	}
	// in a document
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(testAclSavePolicyA)); err != nil {
		t.Fatal(err)
	}
	if world.statement("search:parallel") == "" {
		t.Fatal("the document did not carry the entry")
	}
	remove("search:parallel")
	if judged := world.judged(); len(judged) != 0 {
		t.Fatalf("after the document's removal: %+v", judged)
	}
}
