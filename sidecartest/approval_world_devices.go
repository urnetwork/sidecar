// What MCP-M3-25's rows add to an ApprovalWorld (§22.7's devices row, FS-27, FS-28; §16.6's harness_ok, D-MCP-9,
// D-MCP-14, D-MCP-16, D-MCP-19, I-8, I-9, TS1): the parts of P and of the daemon a pairing or a hook schedule sets.
//
//	pairing   SetMemberDevices: the requesting member's devices at P beside the laptop, each approval-capable (a
//	          second CLI, a phone) or admitted and not (a page Worker, a quick burner: read_only or ephemeral), so
//	          harness_ok's alone clause and the spend check's signer clause read the pairing a test names
//	evidence  SetEvidence: the governing evidence list, and whether a requests rule of its own names harness, which
//	          alone lets harness evidence count in a tainted run (owner decision 142)
//	presence  SetPresenceKeys: the member's presence keys live at P, and SignPresenceDecision, a decision a fixture
//	          key signs under its §16.6 profile, as the daemon's prompt signs this sidecar's own request
//	daemon    ApprovalWorldOptions: standing grants, the harness evidence the gate asks at its step 4, built again at
//	          each start since a daemon keeps it in memory, and what runs once the daemon has started; Runs and
//	          LocalStore are the running daemon's, every write of them taken at the Net's fault queue, for the hooks
//	          that bind runs there; HarnessSigner signs a harness decision as the laptop's Sidecar would
//	harness   ApprovalWorldHarness: harness_ok's state half alone, for a pairing's test: a harness whose hook always
//	          asked. The event half, the hook that asks about one call, is mcp's HarnessEvidence, which FS-28 runs
//	approver  ApprovalWorldRequests: the world's log as a second device of the member reads it, what `ur approve`
//	          there lists and files into
//
// The world's state is its own HarnessStates, read by harness_ok as ConfigApprovalStates is on a host.
//
// Safe for concurrent use, as the world is.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Where a sidecar's run files live in its local state, as sidecar.NewRunStore opens them: identifiers of §5.9's tree.
const (
	approvalWorldRunDirectory = "runs"
	approvalWorldRunClass     = "run"
)

// What a world's daemon is built with beyond the defaults. Every field may be nil.
type ApprovalWorldOptions struct {
	// The standing grants the gate asks in an untainted run (ACL-M4-02's seam).
	Grants sidecar.ApprovalStandingGrants
	// The harness evidence of a daemon just built over runs, asked again at each start: what a kill drops.
	Harness func(ctx context.Context, world *ApprovalWorld, runs sidecar.RecordRunView) sidecar.ApprovalHarnessEvidence
	// Runs once a daemon has started and reconciled, under the daemon's context, which ends when it is killed.
	Opened func(ctx context.Context, world *ApprovalWorld) error
}

// A standing grant that covers every action, or none: the gate's Grants for a schedule that needs one.
type ApprovalWorldGrants struct {
	Active bool
}

var _ sidecar.ApprovalStandingGrants = (*ApprovalWorldGrants)(nil)

func (self *ApprovalWorldGrants) ActiveGrant(action *sidecar.StoredCanonicalAction, spender sidecar.Id, now time.Time) bool {
	return self.Active
}

// The member an admitted device of P is: every device of the world is untagged and consented.
func (self *ApprovalWorldState) DeviceMember(sidecarId sidecar.Id) (sidecar.Id, bool) {
	for _, device := range self.devices {
		if device.SidecarId == sidecarId {
			return device.MemberId, true
		}
	}
	return sidecar.Id{}, false
}

// Any device of the member but except that is approval-capable at P.
func (self *ApprovalWorldState) OtherApprovalCapable(memberId sidecar.Id, except sidecar.Id) bool {
	for _, device := range self.devices {
		if device.SidecarId != except && device.MemberId == memberId && self.capable[device.SidecarId] {
			return true
		}
	}
	return false
}

// Whether a presence key of the member is live at P.
func (self *ApprovalWorldState) HoldsPresenceKey(memberId sidecar.Id) bool {
	for _, key := range self.presenceKeys {
		if bytes.Equal(key.GetMemberId(), memberId.Bytes()) {
			return true
		}
	}
	return false
}

// Installs a copy of P that update changed, at the same pin: what a test sets is the state the daemon reads next.
func (self *ApprovalWorld) updateState(update func(state *ApprovalWorldState)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	updated := *self.state
	updated.devices = slices.Clone(updated.devices)
	capable := map[sidecar.Id]bool{}
	for sidecarId, isCapable := range updated.capable {
		capable[sidecarId] = isCapable
	}
	updated.capable = capable
	update(&updated)
	self.state = &updated
}

// Sets the requesting member's devices at P beside the laptop: capable are approval-capable devices of the member, a
// second CLI or a phone; others are admitted and sign no decision, a page Worker or a quick burner. The other
// member's device and the stranger's stay. With neither, the laptop is the member's one device.
func (self *ApprovalWorld) SetMemberDevices(capable []*ApprovalWorldDevice, others []*ApprovalWorldDevice) {
	self.updateState(func(state *ApprovalWorldState) {
		devices := []*ApprovalWorldDevice{}
		for _, device := range state.devices {
			if device.MemberId != self.Member || device.SidecarId == self.Laptop.SidecarId {
				devices = append(devices, device)
			} else {
				delete(state.capable, device.SidecarId)
			}
		}
		for _, device := range capable {
			devices = append(devices, device)
			state.capable[device.SidecarId] = true
		}
		for _, device := range others {
			devices = append(devices, device)
			delete(state.capable, device.SidecarId)
		}
		state.devices = devices
	})
}

// Sets the governing evidence list, and whether a requests rule of its own names harness: false is the document's
// evidenceDefault speaking, which never lets harness count in a tainted run.
func (self *ApprovalWorld) SetEvidence(ruleNamesHarness bool, channels ...protocol.ApprovalChannel) {
	self.updateState(func(state *ApprovalWorldState) {
		state.evidence = slices.Clone(channels)
		state.ruleNamesHarness = ruleNamesHarness
	})
}

// Sets the presence keys live at P.
func (self *ApprovalWorld) SetPresenceKeys(keys ...*bridge.KeyRow) {
	self.updateState(func(state *ApprovalWorldState) {
		state.presenceKeys = slices.Clone(keys)
	})
}

// The running daemon's run store, its writes taken at the Net's fault queue: where the daemon's hooks bind runs.
func (self *ApprovalWorld) Runs() *sidecar.RunStore {
	return self.currentDaemon().runs
}

// The running daemon's local state, its writes taken at the Net's fault queue.
func (self *ApprovalWorld) LocalStore() sidecar.SidecarStore {
	return self.currentDaemon().local
}

// Overwrites runId's file with bytes that do not read, around the fault queue: a file corrupted while no daemon ran.
func (self *ApprovalWorld) CorruptRun(runId sidecar.Id) error {
	directory, err := self.store.Root().Directory(approvalWorldRunDirectory, approvalWorldRunClass)
	if err != nil {
		return err
	}
	writer, err := directory.Create(runId.String())
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("not a run file")); err != nil {
		return err
	}
	return writer.Commit()
}

// A presence decision approving the request filed under approvalId, as stored: one use, until notAfter, under P's
// pin, the member its approver, signed by key under its §16.6 profile over §6.9's bytes, as the daemon's prompt signs
// this sidecar's own request.
func (self *ApprovalWorld) SignPresenceDecision(approvalId sidecar.Id, notAfter time.Time, key *FixturePresenceKey) ([]byte, error) {
	request := self.log.Request(approvalId)
	if request == nil {
		return nil, errors.New("no request filed under the approval")
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(
		self.decisionOf(request, 1, notAfter, self.Member, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE, self.State().Pin()))
	if err != nil {
		return nil, err
	}
	return proto.Marshal(key.Sign(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body))
}

// Each decision the ledger keeps for approvalId, parsed, as the running daemon reads them.
func (self *ApprovalWorld) Decisions(approvalId sidecar.Id) ([]*sidecar.StoredApprovalDecision, error) {
	state, err := self.LedgerState(approvalId)
	if err != nil {
		return nil, err
	}
	decisions := []*sidecar.StoredApprovalDecision{}
	for _, signed := range state.Decisions {
		decision, err := sidecar.ParseStoredApprovalDecision(signed)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	return decisions, nil
}

// The laptop as what signs a harness decision: its identity, and the decision's bytes under its identity key, as
// Sidecar.SignHarnessDecision makes them.
type ApprovalWorldHarnessSigner struct {
	world *ApprovalWorld
}

// What signs the laptop's harness decisions.
func (self *ApprovalWorld) HarnessSigner() *ApprovalWorldHarnessSigner {
	return &ApprovalWorldHarnessSigner{world: self}
}

// The laptop's identity.
func (self *ApprovalWorldHarnessSigner) Identity() *sidecar.SidecarIdentity {
	return &sidecar.SidecarIdentity{
		SidecarId:         self.world.Laptop.SidecarId,
		IdentityPublicKey: self.world.Laptop.identityKey(),
	}
}

// A harness decision on request, the laptop's own, as stored.
func (self *ApprovalWorldHarnessSigner) SignHarnessDecision(request *sidecar.StoredApprovalRequest, memberId sidecar.Id, pin *bridge.AuthPin, evidenceSha256 []byte, notAfter time.Time) ([]byte, error) {
	body, err := sidecar.HarnessDecisionBody(request, memberId, pin, evidenceSha256, notAfter)
	if err != nil {
		return nil, err
	}
	return approvalWorldSignedBody(self.world.Laptop, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)
}

// A harness whose hook always asked about the call: the gate's harness evidence with harness_ok's state half alone
// between a request and a harness decision, so a pairing's test reads that half and nothing else. Each decision cites
// a fixed leaf and runs to the request's own bound.
type ApprovalWorldHarness struct {
	world *ApprovalWorld
	runs  sidecar.RecordRunView
}

var _ sidecar.ApprovalHarnessEvidence = (*ApprovalWorldHarness)(nil)

// The Harness option of a world whose harness always asked.
func NewApprovalWorldHarness(ctx context.Context, world *ApprovalWorld, runs sidecar.RecordRunView) sidecar.ApprovalHarnessEvidence {
	return &ApprovalWorldHarness{world: world, runs: runs}
}

func (self *ApprovalWorldHarness) HarnessDecision(ctx context.Context, action *sidecar.SidecarAction, request *sidecar.StoredApprovalRequest) ([]byte, error) {
	states := self.world.State()
	now := self.world.net.Clock().Now()
	memberId, err := sidecar.HarnessOk(states, &sidecar.HarnessOkArgs{
		Request:    request,
		Requester:  self.world.Laptop.SidecarId,
		RunTainted: action.RunId != nil && self.runs.RunTainted(*action.RunId),
		Now:        now,
	})
	if err != nil {
		return nil, err
	}
	leaf := sha256.Sum256([]byte("approval world hook event"))
	return self.world.HarnessSigner().SignHarnessDecision(request, memberId, states.Pin(), leaf[:], time.UnixMilli(request.Request.GetNotAfterMillis()))
}

// The world's requests as a second device reads them, and where its decision is filed: each request with no decision
// yet, in the order filed, and a decision delivered through the world's log to the requesting daemon's inbox.
type ApprovalWorldRequests struct {
	world *ApprovalWorld
	logId sidecar.Id
}

// The world's requests as another device's approver side reads them.
func (self *ApprovalWorld) Requests() *ApprovalWorldRequests {
	return &ApprovalWorldRequests{world: self, logId: NewApprovalWorldIdOf("log " + self.name)}
}

func (self *ApprovalWorldRequests) Pending(ctx context.Context) ([]*sidecar.RecordPendingApproval, error) {
	pending := []*sidecar.RecordPendingApproval{}
	for _, approvalId := range self.world.log.ApprovalIds() {
		if _, err := self.world.log.Decision(ctx, approvalId); !errors.Is(err, sidecar.ErrRecordApprovalPending) {
			continue
		}
		pending = append(pending, &sidecar.RecordPendingApproval{
			LogId:           self.logId,
			EntryId:         approvalId,
			Request:         self.world.log.Request(approvalId),
			WriterSidecarId: self.world.Laptop.SidecarId,
		})
	}
	return pending, nil
}

func (self *ApprovalWorldRequests) FileDecision(ctx context.Context, logId sidecar.Id, storedSigned []byte, runId *sidecar.Id) (*sidecar.RecordEntryRef, error) {
	decision, err := sidecar.ParseStoredApprovalDecision(storedSigned)
	if err != nil {
		return nil, err
	}
	approvalId, err := sidecar.IdFromBytes(decision.Decision.GetApprovalId())
	if err != nil {
		return nil, err
	}
	if err := self.world.Deliver(ctx, approvalId, storedSigned); err != nil {
		return nil, err
	}
	return &sidecar.RecordEntryRef{LogId: logId, EntryId: sidecar.NewId()}, nil
}

func (self *ApprovalWorldRequests) FileCancel(ctx context.Context, logId sidecar.Id, storedSigned []byte) (*sidecar.RecordEntryRef, error) {
	return nil, errors.New("the approval world's second device files no cancel")
}
