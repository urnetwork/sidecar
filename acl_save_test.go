//go:build !sidecar_http && !js

// ACL-M2-11's save on T2's fake api, through TEAM's writer and every reader's real compile: a saved policy lands as a
// head every reader recompiles, a rollback to an older source is a head at a higher config_version (I-16), a failing
// test blocks the head and leaves the one in force, a preview the head moved past is refused, a device that is no
// config writer saves nothing, and the change audit lists each head the log put in force.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The writer test's network, its acl compile the real one, with the owner's client and writer.
type testAclSaveWorld struct {
	*testWriterWorld
	client      *sidecar.ConfigClient
	ownerWriter *sidecar.ConfigWriter
}

func newTestAclSaveWorld(t *testing.T) *testAclSaveWorld {
	world := newTestWriterWorld(t)
	// the readers recompile every head with CompileAcl, as a real network's do
	t.Cleanup(sidecar.RegisterConfigAclCompiler(func(head *sidecar.ConfigHead, rows *sidecar.ConfigCompileRows) (*protocol.AclRows, error) {
		input, err := sidecar.NewAclCompileInput(head, rows)
		if err != nil {
			return nil, err
		}
		return sidecar.CompileAcl(input)
	}))
	world.started()
	client := world.client()
	world.caughtUp(client)
	return &testAclSaveWorld{testWriterWorld: world, client: client, ownerWriter: world.writer(world.owner, client, nil, 0.5, nil)}
}

// A plan of source on the owner's current head and client's state.
func (self *testAclSaveWorld) plan(source string) *sidecar.AclSavePlan {
	self.t.Helper()
	head, _, _, err := self.heads.For(self.owner.sidecarId, self.owner.key).CurrentConfigHead(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	plan, err := sidecar.PlanAclSave(self.ctx, &sidecar.AclSaveInput{Policy: []byte(source), Head: head, State: self.caughtUp(self.client), Now: self.clock.Now()})
	if err != nil {
		self.t.Fatal(err)
	}
	return plan
}

// The head the config repo holds now and its version.
func (self *testAclSaveWorld) head() (*sidecar.ConfigHead, uint64) {
	self.t.Helper()
	head, version, _, err := self.heads.For(self.owner.sidecarId, self.owner.key).CurrentConfigHead(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	return head, version
}

// Two documents whose tests pass, and one whose test fails.
const (
	testAclSavePolicyA = `{
  "grants": [ { "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial"] } ],
  "tests": [ { "src": "autogroup:member", "deny": ["evs:00000000000000000000000000000001#read"] } ],
}`
	testAclSavePolicyB = `{
  "grants": [ { "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial", "route"] } ],
}`
	testAclSavePolicyFailing = `{
  "grants": [ { "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial"] } ],
  "tests": [ { "src": "autogroup:tagged", "accept": ["autogroup:member#dial"] } ],
}`
)

// A save lands as a head the readers take, and a rollback to an older source is a new head at a higher version.
func TestAclSaveLandsAndARollbackGoesUp(t *testing.T) {
	world := newTestAclSaveWorld(t)
	versions := []uint64{}
	for _, source := range []string{testAclSavePolicyA, testAclSavePolicyB, testAclSavePolicyA} {
		plan := world.plan(source)
		if !plan.Tests.Passed() {
			t.Fatalf("tests: %v", plan.Tests.Err())
		}
		pin, err := sidecar.AclSave(world.ctx, world.ownerWriter, plan)
		if err != nil {
			t.Fatal(err)
		}
		state := world.caughtUp(world.client)
		if state.Pin().GetVersion() < pin.GetVersion() {
			t.Fatalf("the reader stands at %d, below the base at %d", state.Pin().GetVersion(), pin.GetVersion())
		}
		head, version := world.head()
		if !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(source)) || state.Base().GetConfigVersion() != version {
			t.Fatalf("the head at %d holds another policy, the base names %d", version, state.Base().GetConfigVersion())
		}
		acl, err := state.Acl()
		if err != nil || !acl.HasDocument() {
			t.Fatalf("the reader's rows: %v", err)
		}
		versions = append(versions, version)
	}
	if !(versions[0] < versions[1] && versions[1] < versions[2]) {
		t.Errorf("config versions %v", versions)
	}
}

// A failing test blocks the head, and the head and base in force stay.
func TestAclSaveBlocksAFailingTest(t *testing.T) {
	world := newTestAclSaveWorld(t)
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(testAclSavePolicyA)); err != nil {
		t.Fatal(err)
	}
	head, version := world.head()
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		t.Fatal(err)
	}
	plan := world.plan(testAclSavePolicyFailing)
	if plan.Tests.Passed() {
		t.Fatal("the failing test passed")
	}
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, plan); !errors.Is(err, sidecar.ErrAclPolicyTests) {
		t.Fatalf("a failing test: %v", err)
	}
	after, afterVersion := world.head()
	afterTip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		t.Fatal(err)
	}
	if afterVersion != version || !bytes.Equal(after.File(sidecar.ConfigHeadPolicyPath), head.File(sidecar.ConfigHeadPolicyPath)) ||
		afterTip.GetVersion() != tip.GetVersion() {
		t.Errorf("the head moved to %d, the tip to %d", afterVersion, afterTip.GetVersion())
	}
}

// A preview the head moved past is refused: the person signs only what they saw.
func TestAclSaveRefusesAStalePreview(t *testing.T) {
	world := newTestAclSaveWorld(t)
	stale := world.plan(testAclSavePolicyA)
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(testAclSavePolicyB)); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, stale); !errors.Is(err, sidecar.ErrAclSaveStale) {
		t.Errorf("a stale preview: %v", err)
	}
}

// A member device of a member who holds no AdminSet role writes no config head: its save is refused.
func TestAclSaveFromANonWriterIsRefused(t *testing.T) {
	world := newTestAclSaveWorld(t)
	member := testWriterId("plain member")
	if _, err := world.admitMember("plain member"); err != nil {
		t.Fatal(err)
	}
	device := testWriterDeviceOf("plain device", member)
	_, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header: world.header(), NetworkId: world.networkId.Bytes(), SidecarId: device.sidecarId.Bytes(),
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey), IdentityAlg: "ed25519", MemberId: member.Bytes(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	world.caughtUp(world.client)
	writer := world.writer(device, world.client, nil, 0.5, nil)
	if _, err := sidecar.AclSave(world.ctx, writer, world.plan(testAclSavePolicyA)); !errors.Is(err, sidecar.ErrConfigWriterNotWriter) {
		t.Errorf("a non-writer's save: %v", err)
	}
}

// The change audit lists each config version the log put in force, the base's signer and its time.
func TestAclLogListsEachHead(t *testing.T) {
	world := newTestAclSaveWorld(t)
	for _, source := range []string{testAclSavePolicyA, testAclSavePolicyB} {
		if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, world.plan(source)); err != nil {
			t.Fatal(err)
		}
	}
	state := world.caughtUp(world.client)
	// the reader started at base 1, so its window lists the heads from there on: the two saves' at least
	entries := sidecar.AclLog(state)
	if len(entries) < 2 {
		t.Fatalf("%d entries", len(entries))
	}
	for i, entry := range entries {
		if entry.SignerSidecarId != world.owner.sidecarId || entry.N == 0 || (0 < i && entry.ConfigVersion <= entries[i-1].ConfigVersion) {
			t.Errorf("entry %d: %+v", i, entry)
		}
		if time.UnixMilli(entry.TimeMs).After(world.clock.Now().Add(time.Minute)) {
			t.Errorf("entry %d's time %v", i, entry.TimeMs)
		}
	}
	if _, version := world.head(); entries[len(entries)-1].ConfigVersion != version {
		t.Errorf("the newest entry names %d, the head is %d", entries[len(entries)-1].ConfigVersion, version)
	}
}
