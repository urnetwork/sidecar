//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

// The daemon's devices methods and the cosign behind them (CORE-M3-04; D-CORE-20, D-CORE-13, FS-98, FS-124's CLI
// cases), on the revoke tests' world: the dispatcher with no socket, so each mode's call is the one a session sends,
// the scripted delta route, and a fake authenticator with fixture keys as the daemon's presence prompt.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The revoke authority with the open proposals a cosigner reads.
type devicesTestAuthority struct {
	*revokeTestAuthority
	proposals map[[sha256.Size]byte]*bridge.ProposalRow
}

var _ SidecarAuthorityProposals = (*devicesTestAuthority)(nil)

func (self *devicesTestAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(proposalId) != sha256.Size {
		return nil
	}
	row := self.proposals[[sha256.Size]byte(proposalId)]
	if row == nil {
		return nil
	}
	return proto.Clone(row).(*bridge.ProposalRow)
}

func (self *devicesTestAuthority) Settings() *bridge.ProjectionSettings {
	return &bridge.ProjectionSettings{}
}

// The revoke world behind a daemon that hosts its Sidecar and serves the devices methods.
type devicesTestWorld struct {
	*revokeTestWorld
	daemon    *Daemon
	proposals *devicesTestAuthority
}

func newDevicesTestWorld(t *testing.T) *devicesTestWorld {
	t.Helper()
	world := newRevokeTestWorld(t)
	proposals := &devicesTestAuthority{revokeTestAuthority: world.authority, proposals: map[[sha256.Size]byte]*bridge.ProposalRow{}}
	t.Cleanup(world.sidecar.InstallAuthority(proposals))
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(NewId(), world.sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonDevicesMethods(daemon) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &devicesTestWorld{revokeTestWorld: world, daemon: daemon, proposals: proposals}
}

// One call in mode, its reply decoded into reply, or the rpc's error.
func (self *devicesTestWorld) call(t *testing.T, mode string, method string, params any, confirmed bool, reply any) *DaemonRpcError {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(&daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: method, Params: encoded, UrConfirmed: confirmed})
	if err != nil {
		t.Fatal(err)
	}
	response := dispatchTest(self.daemon, mode, string(line))
	if response.Error != nil {
		return response.Error
	}
	if reply != nil {
		if err := json.Unmarshal(response.Result, reply); err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

// A live presence key of this sidecar's on a fake authenticator set as the daemon's, with the revocation's statements
// covered.
func (self *devicesTestWorld) addPresence(t *testing.T) *testPresenceProvider {
	t.Helper()
	provider := newTestPresenceProvider(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	handle, err := provider.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	row := provider.row(handle.KeyId, self.memberId, self.selfId)
	self.authority.edit(func() {
		self.authority.liveKeys = append(self.authority.liveKeys, row)
		for _, signedType := range []bridge.SignedType{
			bridge.SignedType_SIGNED_SIDECAR_REVOKE, bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL,
			bridge.SignedType_SIGNED_SUSPEND, bridge.SignedType_SIGNED_AUTHORITY_COSIGN,
		} {
			self.authority.covered[signedType] = true
		}
	})
	self.daemon.SetPresenceProvider(provider)
	return provider
}

// An open k-of-n proposal of a SidecarRevoke of targetId, signed so far by proposerId, in the authority's state.
func (self *devicesTestWorld) propose(targetId Id, proposerId Id, reason bridge.SidecarRevokeReason, sinceN uint64) []byte {
	statement, _ := proto.Marshal(&bridge.SidecarRevoke{
		Header:    &bridge.StatementHeader{NotAfterMs: self.clock.Now().Add(time.Hour).UnixMilli()},
		SidecarId: targetId.Bytes(),
		Reason:    reason,
		SinceN:    sinceN,
	})
	proposalId := sha256.Sum256(append([]byte("a proposal of "), statement...))
	self.authority.edit(func() {
		self.proposals.proposals[proposalId] = &bridge.ProposalRow{
			ProposalId:    proposalId[:],
			StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_REVOKE),
			Statement:     statement,
			ProposedAt:    self.n,
			NotAfterMs:    self.clock.Now().Add(time.Hour).UnixMilli(),
			Signers:       []*bridge.ProposalSigner{{Signer: proposerId.Bytes(), At: self.n}},
			Kind:          uint32(bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY),
		}
	})
	return proposalId[:]
}

// ur devices and ur devices revoke through the daemon: the list, this device first; the plan of a device named by its
// id; and the confirmed control call, which signs one SidecarRevoke{lost} and, with no presence key, no KeyRevoke.
func TestDevicesListPreviewAndRevokeThroughTheDaemon(t *testing.T) {
	world := newDevicesTestWorld(t)
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	list := &DaemonDevicesListReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesList, &DaemonDevicesListParams{}, false, list); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if len(list.Devices) != 2 || !list.Devices[0].This || list.Devices[0].SidecarId != world.selfId || list.Devices[1].SidecarId != world.otherId ||
		list.Devices[1].State != MemberDeviceLive {
		t.Fatalf("the devices: %+v", list.Devices)
	}
	preview := &DaemonDevicesPreviewReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeLost}, false, preview); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if preview.Refusal != nil || preview.Plan == nil || preview.Plan.SidecarId != world.otherId || preview.Plan.Signatures != 1 || preview.Plan.Presence ||
		len(preview.Plan.Items) != 1 || preview.Plan.Items[0].Effect != DeviceRevokeEffectKey || preview.Plan.Items[0].Id != hex.EncodeToString(keyId) {
		t.Fatalf("the plan: %+v, refusal %+v", preview.Plan, preview.Refusal)
	}
	revoke := &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke,
		&DaemonDevicesRevokeParams{PlanId: preview.Plan.PlanId, RevokeKeyIds: []string{hex.EncodeToString(keyId)}}, true, revoke); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || posts[0].GetWebauthn() != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	signed := &bridge.SidecarRevoke{}
	postedBody(t, posts[0], signed)
	if !bytes.Equal(signed.GetSidecarId(), world.otherId.Bytes()) || signed.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST {
		t.Fatalf("the revocation: %+v", signed)
	}
	if revoke.Refusal != nil || revoke.Position == 0 || revoke.ProposalId != "" || len(revoke.RevokedKeyIds) != 0 || revoke.Pending {
		t.Fatalf("the reply: %+v", revoke)
	}
	// the plan is spent: a second confirmed call answers REVOKE_STALE as a refusal, never an rpc error
	again := &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, &DaemonDevicesRevokeParams{PlanId: preview.Plan.PlanId}, true, again); rpcErr != nil ||
		again.Refusal == nil || again.Refusal.Code != DeviceRevokeCodeStale {
		t.Fatalf("a spent plan: %+v, %v", again, rpcErr)
	}
}

// Every refusal of a preview is an answer with its code: this sidecar, another member's device, an unknown id, a name
// none of the member's devices carries, and a compromise with nothing saying where P starts.
func TestDevicesPreviewAnswersRefusals(t *testing.T) {
	world := newDevicesTestWorld(t)
	strangerId := NewId()
	world.admit(strangerId, NewId(), 9)
	for _, c := range []struct {
		params *DaemonDevicesPreviewParams
		code   string
	}{
		{params: &DaemonDevicesPreviewParams{Device: world.selfId.String(), Reason: DeviceRevokeLost}, code: DeviceRevokeCodeSelf},
		{params: &DaemonDevicesPreviewParams{Device: strangerId.String(), Reason: DeviceRevokeLost}, code: DeviceRevokeCodeNotOwn},
		{params: &DaemonDevicesPreviewParams{Device: NewId().String(), Reason: DeviceRevokeLost}, code: DeviceRevokeCodeNotOwn},
		{params: &DaemonDevicesPreviewParams{Device: "a-name-no-device-carries", Reason: DeviceRevokeLost}, code: DeviceRevokeCodeNotOwn},
		{params: &DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeCompromise}, code: DeviceRevokeCodeSince},
		{params: &DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeCompromise, SinceN: world.n + 1}, code: DeviceRevokeCodeSince},
	} {
		reply := &DaemonDevicesPreviewReply{}
		if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview, c.params, false, reply); rpcErr != nil {
			t.Fatalf("%+v: %v", c.params, rpcErr)
		}
		if reply.Plan != nil || reply.Refusal == nil || reply.Refusal.Code != c.code {
			t.Errorf("%+v: %+v, want %s", c.params, reply.Refusal, c.code)
		}
	}
	// REVOKE_PARKS_SELF names the entry that puts this sidecar in P
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: world.n}] = []DeviceRevokeItem{
			{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: world.selfId.Bytes(), Position: 5},
		}
	})
	reply := &DaemonDevicesPreviewReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeCompromise, SinceN: world.n}, false, reply); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if reply.Refusal == nil || reply.Refusal.Code != DeviceRevokeCodeParksSelf || reply.Refusal.Position != 5 {
		t.Errorf("a plan that parks this sidecar: %+v", reply.Refusal)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Errorf("%d statements posted by previews", len(posts))
	}
}

// D-CORE-13, FS-98's refused paths: devices.revoke and devices.cosign run only from a control call whose sender
// confirmed. An MCP session's call, a harness hook's and an unconfirmed control call are refused before the handler,
// with their confirmation flag set or not, and nothing is signed.
func TestDevicesRevokeRefusedFromMcp(t *testing.T) {
	world := newDevicesTestWorld(t)
	plan, err := world.sidecar.PreviewDeviceRevoke(context.Background(), world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	proposalId := world.propose(world.otherId, NewId(), bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)
	for _, c := range []struct {
		mode      string
		confirmed bool
	}{
		{mode: DaemonModeMcp, confirmed: false},
		{mode: DaemonModeMcp, confirmed: true},
		{mode: DaemonModeHook, confirmed: false},
		{mode: DaemonModeHook, confirmed: true},
		{mode: DaemonModeControl, confirmed: false},
	} {
		rpcErr := world.call(t, c.mode, DaemonMethodDevicesRevoke, &DaemonDevicesRevokeParams{PlanId: plan.PlanId}, c.confirmed, nil)
		if rpcErr == nil || rpcErr.Code != DaemonRpcConfirmationRequired {
			t.Errorf("devices.revoke from %s, confirmed %t: %v", c.mode, c.confirmed, rpcErr)
		}
		rpcErr = world.call(t, c.mode, DaemonMethodDevicesCosign, &DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(proposalId)}, c.confirmed, nil)
		if rpcErr == nil || rpcErr.Code != DaemonRpcConfirmationRequired {
			t.Errorf("devices.cosign from %s, confirmed %t: %v", c.mode, c.confirmed, rpcErr)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted by refused calls", len(posts))
	}
	// the plan still stands for the person's own confirmed call
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, &DaemonDevicesRevokeParams{PlanId: plan.PlanId}, true, reply); rpcErr != nil || reply.Refusal != nil {
		t.Fatalf("the confirmed call: %+v, %v", reply, rpcErr)
	}
}

// FS-124's CLI case for ur devices revoke: under Presence the confirmed call runs the daemon's presence prompt, once,
// over the act's countersigned bytes, each statement carrying that key's countersignature, the selected key's
// KeyRevoke among them. A prompt the person refuses, and a host with no authenticator, answer REVOKE_CANCELLED with
// nothing signed.
func TestDevicesRevokeUnderPresenceRunsTheDaemonsPrompt(t *testing.T) {
	world := newDevicesTestWorld(t)
	provider := world.addPresence(t)
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	preview := func() *DaemonDeviceRevokePlan {
		reply := &DaemonDevicesPreviewReply{}
		if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
			&DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeLost}, false, reply); rpcErr != nil || reply.Plan == nil {
			t.Fatalf("the preview: %+v, %v", reply, rpcErr)
		}
		return reply.Plan
	}
	plan := preview()
	if !plan.Presence {
		t.Fatalf("the plan sets no Presence from the log: %+v", plan)
	}
	revokeParams := &DaemonDevicesRevokeParams{PlanId: plan.PlanId, RevokeKeyIds: []string{hex.EncodeToString(keyId)}}

	// no authenticator on this host
	world.daemon.SetPresenceProvider(nil)
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, revokeParams, true, reply); rpcErr != nil ||
		reply.Refusal == nil || reply.Refusal.Code != DeviceRevokeCodeCancelled {
		t.Fatalf("with no authenticator: %+v, %v", reply, rpcErr)
	}
	// the person refuses the prompt
	world.daemon.SetPresenceProvider(provider)
	provider.stateLock.Lock()
	provider.refuse = errors.New("the person refused")
	provider.stateLock.Unlock()
	reply = &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, revokeParams, true, reply); rpcErr != nil ||
		reply.Refusal == nil || reply.Refusal.Code != DeviceRevokeCodeCancelled {
		t.Fatalf("with a refused prompt: %+v, %v", reply, rpcErr)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted with no presence evidence", len(posts))
	}
	provider.stateLock.Lock()
	provider.refuse = nil
	provider.stateLock.Unlock()
	_, assertsBefore := provider.counts()

	// the prompt passes
	reply = &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, revokeParams, true, reply); rpcErr != nil || reply.Refusal != nil {
		t.Fatalf("with the prompt passed: %+v, %v", reply, rpcErr)
	}
	if _, asserts := provider.counts(); asserts != assertsBefore+1 {
		t.Errorf("the act ran %d presence checks, want one", asserts-assertsBefore)
	}
	posts := world.posted(t)
	if len(posts) != 2 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE ||
		bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_KEY_REVOKE {
		t.Fatalf("posted %d statements", len(posts))
	}
	liveKey := world.authority.LiveKeys(world.selfId)[0]
	for index, signed := range posts {
		if signed.GetWebauthn() == nil || signed.GetWebauthn().GetActSize() != 2 {
			t.Fatalf("statement %d carries no countersignature of the act", index)
		}
		if err := VerifyPresenceCountersignature(signed, bridge.SignedPurposeAuthority, liveKey); err != nil {
			t.Errorf("statement %d's countersignature: %v", index, err)
		}
	}
	if len(reply.RevokedKeyIds) != 1 || reply.RevokedKeyIds[0] != hex.EncodeToString(keyId) {
		t.Errorf("the keys revoked: %v", reply.RevokedKeyIds)
	}
}

// At k > 1 the confirmed call answers authority_pending: the proposal's id, with the target's Suspend signed in the
// same act under the one check.
func TestDevicesRevokeAtK2AnswersTheProposal(t *testing.T) {
	world := newDevicesTestWorld(t)
	world.addPresence(t)
	world.authority.edit(func() { world.authority.signatures[world.otherId] = 2 })
	preview := &DaemonDevicesPreviewReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: world.otherId.String(), Reason: DeviceRevokeLost}, false, preview); rpcErr != nil || preview.Plan == nil {
		t.Fatalf("the preview: %+v, %v", preview, rpcErr)
	}
	if preview.Plan.Signatures != 2 {
		t.Fatalf("the plan: %+v", preview.Plan)
	}
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesRevoke, &DaemonDevicesRevokeParams{PlanId: preview.Plan.PlanId}, true, reply); rpcErr != nil || reply.Refusal != nil {
		t.Fatalf("the revocation: %+v, %v", reply, rpcErr)
	}
	posts := world.posted(t)
	if len(posts) != 2 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL ||
		bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_SUSPEND {
		t.Fatalf("posted %d statements", len(posts))
	}
	wantId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, posts[0].GetBody())
	if reply.Position != 0 || reply.ProposalId != hex.EncodeToString(wantId[:]) {
		t.Errorf("the reply: %+v, want proposal %x", reply, wantId)
	}
}

// ur approve <proposal_id>: the plan of an open revocation proposal as its row states it, and the confirmed call's
// AuthorityCosign under the daemon's prompt; this device's Removes run from the entry that completes it. A proposal
// this device signed, one of its own revocation, one that expired and any other id sign nothing.
func TestDevicesCosignSignsTheProposalsCosign(t *testing.T) {
	world := newDevicesTestWorld(t)
	provider := world.addPresence(t)
	effects := newRevokeTestEffects()
	t.Cleanup(world.sidecar.InstallRevokeEffects(effects))
	proposerId := NewId()
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: 7}] = []DeviceRevokeItem{
			{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: countingBytes(0x60, 16), Position: 9},
		}
		world.authority.suspended[world.otherId] = true
	})
	proposalId := world.propose(world.otherId, proposerId, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, 7)
	params := &DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(proposalId)}

	shown := &DaemonDevicesProposalReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesProposal, params, false, shown); rpcErr != nil || shown.Proposal == nil {
		t.Fatalf("the proposal: %+v, %v", shown, rpcErr)
	}
	proposal := shown.Proposal
	if proposal.SidecarId != world.otherId || proposal.MemberId != world.memberId || proposal.Reason != DeviceRevokeCompromise || proposal.SinceN != 7 ||
		len(proposal.Items) != 1 || proposal.Items[0].Effect != DeviceRevokeEffectPark || len(proposal.Signers) != 1 ||
		proposal.Signers[0] != hex.EncodeToString(proposerId.Bytes()) || !proposal.Suspended || !proposal.Presence || proposal.NotAfterMs == 0 {
		t.Fatalf("the proposal's plan: %+v", proposal)
	}
	// any other id
	unknown := &DaemonDevicesProposalReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesProposal,
		&DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(countingBytes(0x77, 32))}, false, unknown); rpcErr != nil || !unknown.Unknown {
		t.Fatalf("an unknown proposal: %+v, %v", unknown, rpcErr)
	}
	// a refused prompt signs nothing
	provider.stateLock.Lock()
	provider.refuse = errors.New("the person refused")
	provider.stateLock.Unlock()
	cosign := &DaemonDevicesCosignReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesCosign, params, true, cosign); rpcErr != nil ||
		cosign.Refusal == nil || cosign.Refusal.Code != DeviceRevokeCodeCancelled {
		t.Fatalf("with a refused prompt: %+v, %v", cosign, rpcErr)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted with no presence evidence", len(posts))
	}
	provider.stateLock.Lock()
	provider.refuse = nil
	provider.stateLock.Unlock()

	cosign = &DaemonDevicesCosignReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesCosign, params, true, cosign); rpcErr != nil || cosign.Refusal != nil || cosign.Position == 0 {
		t.Fatalf("the cosign: %+v, %v", cosign, rpcErr)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_COSIGN || posts[0].GetWebauthn() == nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	signed := &protocol.AuthorityCosign{}
	postedBody(t, posts[0], signed)
	if !bytes.Equal(signed.GetProposalId(), proposalId) || signed.GetHeader() == nil {
		t.Fatalf("the cosign: %+v", signed)
	}
	if err := VerifyPresenceCountersignature(posts[0], bridge.SignedPurposeAuthority, world.authority.LiveKeys(world.selfId)[0]); err != nil {
		t.Errorf("the cosign's countersignature: %v", err)
	}
	// the completing entry closes the proposal and applies the revocation: this device's Removes run from it
	row := world.proposals.PendingProposal(proposalId)
	world.authority.edit(func() { delete(world.proposals.proposals, [sha256.Size]byte(proposalId)) })
	completing := world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE, Body: row.GetStatement()}}
	})
	<-effects.done
	if calls, positions := effects.snapshot(); len(calls) != 2 || calls[0] != "commit" || positions[0] != completing.Pin.GetVersion() {
		t.Errorf("the effects at the completing cosign: %v at %v", calls, positions)
	}

	// a closed proposal, one this device signed and one of its own revocation sign nothing
	closed := &DaemonDevicesCosignReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesCosign, params, true, closed); rpcErr != nil || !closed.Unknown {
		t.Errorf("a closed proposal: %+v, %v", closed, rpcErr)
	}
	for name, id := range map[string][]byte{
		"signed already": world.propose(world.otherId, world.selfId, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0),
		"of this device": world.propose(world.selfId, proposerId, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0),
	} {
		reply := &DaemonDevicesCosignReply{}
		if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesCosign, &DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(id)}, true, reply); rpcErr != nil ||
			reply.Refusal == nil || reply.Refusal.Code != DeviceRevokeCodeNotCapable {
			t.Errorf("a proposal %s: %+v, %v", name, reply, rpcErr)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 1 {
		t.Errorf("%d statements posted, want the one cosign", len(posts))
	}
}

// The cosign is a person's act (D-CORE-13): any origin but a confirmation signs nothing; a suspended or unconsented
// device is not capable; a proposal of anything but a SidecarRevoke is none of these; and a cosign api refuses at the
// tip answers REVOKE_REFUSED.
func TestCosignRevokeProposalRefusals(t *testing.T) {
	world := newDevicesTestWorld(t)
	ctx := context.Background()
	proposalId := world.propose(world.otherId, NewId(), bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := world.sidecar.CosignRevokeProposal(ctx, proposalId, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	world.authority.edit(func() { world.authority.suspended[world.selfId] = true })
	if _, err := world.sidecar.CosignRevokeProposal(ctx, proposalId, SidecarActConfirmed, nil); revokeCode(err) != DeviceRevokeCodeNotCapable {
		t.Errorf("a suspended cosigner: %v", err)
	}
	world.authority.edit(func() {
		world.authority.suspended[world.selfId] = false
		world.authority.consents[[2]Id{world.selfId, world.memberId}] = false
	})
	if _, err := world.sidecar.CosignRevokeProposal(ctx, proposalId, SidecarActConfirmed, nil); revokeCode(err) != DeviceRevokeCodeNotCapable {
		t.Errorf("an unconsented cosigner: %v", err)
	}
	world.authority.edit(func() { world.authority.consents[[2]Id{world.selfId, world.memberId}] = true })
	// a proposal of another statement type, and a recovery window's, are no revocation proposals
	world.authority.edit(func() {
		for index, edit := range []func(row *bridge.ProposalRow){
			func(row *bridge.ProposalRow) { row.StatementType = uint32(bridge.SignedType_SIGNED_SIDECAR_ADMIT) },
			func(row *bridge.ProposalRow) { row.Kind = uint32(bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED) },
		} {
			row := proto.Clone(world.proposals.proposals[[sha256.Size]byte(proposalId)]).(*bridge.ProposalRow)
			edit(row)
			otherId := sha256.Sum256([]byte(fmt.Sprintf("another proposal %d", index)))
			row.ProposalId = otherId[:]
			world.proposals.proposals[otherId] = row
		}
	})
	for index := range 2 {
		otherId := sha256.Sum256([]byte(fmt.Sprintf("another proposal %d", index)))
		if _, err := world.sidecar.PreviewRevokeProposal(otherId[:]); !errors.Is(err, ErrSidecarRevokeProposalUnknown) {
			t.Errorf("proposal %d previews as a revocation's: %v", index, err)
		}
		if _, err := world.sidecar.CosignRevokeProposal(ctx, otherId[:], SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarRevokeProposalUnknown) {
			t.Errorf("proposal %d cosigns as a revocation's: %v", index, err)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted by refused cosigns", len(posts))
	}
	// api refuses the cosign at the tip
	world.deltaApi.stateLock.Lock()
	world.deltaApi.answers = []string{"refused"}
	world.deltaApi.stateLock.Unlock()
	if _, err := world.sidecar.CosignRevokeProposal(ctx, proposalId, SidecarActConfirmed, nil); revokeCode(err) != DeviceRevokeCodeRefused {
		t.Errorf("a cosign api refuses: %v", err)
	}
}
