// ACL-M6-05's schedules (§22.8's FS-19, FS-21 and FS-85 at M6-out, S13's grant steps and S3b's and S4b's acl checks;
// R-ACL-11, D-ACL-19, D-ACL-22, D-ACL-24, I-EVS-14, FI-10, FI-26): a Team network's access rules, judged on the
// admission world with ACL's own compile, as fs_acl.go's are, so every reader standing, each new device and gate at a
// base and the writer's follower gives each answer, and the world fails a step the moment one stands elsewhere than
// the reference. The network is on the team tier, which its api alone says, holds Team's starting document and its
// directory, and its api and every reader install §16.6's spend check (sidecar.NewSpendCheck), so a GrantActivate's
// decisions are judged for real.
//
// Registered, each on T2 and on T3 through server's sidecart3:
//
//   - FS-19's team: an ephemeral under a Member and one under an Admin read the team directory and write it by the
//     kind default, admin of nothing, holding its key by a wrap, while each reads the config alone besides and deposits
//     into its member's vault; no document widens or narrows the directory's readers, and the directory takes no
//     RepoGrant, RepoRevoke or RepoAdmin add; a device an admin admitted under a member is parked for that member's
//     consent and writes nothing that counts until the member's OwnerConfirm (I-EVS-14).
//   - FS-19's invite: a member invite refuses an ephemeral enrollment at both ends, an ephemeral admitted with the
//     invited bit anyway is consented at no reader, and the member's next untagged device from the invite is, alone.
//
// Registered on T3 alone, since its clients run on server's exchange under server's contract gate: FS-21's team,
// fs21.go's schedule on a Team's cast and documents (Fs21Team).
//
// FS-85 is RECORD-M6-26's row (fs85_test.go), whose directory legs file requests and decisions through the directory
// daemon; its acl cases are clauses here, each a schedule RunClause runs, and FI-26's acl half is the invariant
// AclM6RequestSoundness over the requests a schedule filed, until RECORD-M6-26 binds FI-26's oracle:
//
//   - the repo request: any repo admin's approval yields one RepoGrant with the asked subject and expiry;
//   - the owner-bound request: only a consented device of the owner decides it, every reader refuses an admin's
//     EvsShare, and the share's expires ends it with no device online;
//   - the worker request: only its owner's or sponsor's device or presence decision approves it, a harness decision
//     is refused, and the requester's GrantActivate passes the spend check once;
//   - the copied decision: a decision copied onto another request activates nothing.
//
// S13's grant steps and S3b's and S4b's acl checks are schedules RECORD-M6-26's s13_test.go and the scenario runs
// take: AclS13GrantSteps, AclMemberAddsOnlyForReaders and AclMemberRemovalDropsEveryRight.

package fault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a Team schedule builds: the admission world's, the requests it filed, and what a reach grant's action needs.
type aclM6World struct {
	*fsTeamWorld
	// every directory request the schedule filed, which AclM6RequestSoundness judges the readers' rows against
	requests []*aclM6Request
	// the starting document's requests rule, the directory's (D-ACL-23)
	requestsRuleId []byte
	// the config repo's key, under which a reach grant's ports are sealed (QD-740)
	configKey *sidecar.EvsRepoKey
	// the id start creates the directory under: zero takes the world's own, and a schedule whose evs fakes hold the
	// directory names theirs (fs_acl_m8.go's wakes)
	directoryId sidecar.Id
}

// One directory request as §16.11 files it, and what became of it.
type aclM6Request struct {
	name      string
	request   *protocol.DirectoryRequest
	requester sidecar.Id
	// a reach request's grant action, nil for a repo request
	action *sidecar.StoredCanonicalAction
	// a reach request's announced port
	port uint32
	// set once an eligible decider approved it: the decider, and for a reach request the grant_id its spend fixed
	approved bool
	decider  sidecar.Id
	grantId  []byte
}

func newAclM6World() *aclM6World {
	return &aclM6World{fsTeamWorld: newFsTeamWorld()}
}

// A step of a Team schedule.
func (self *aclM6World) do(actor string, body func(net *sidecartest.AdmissionNet) error) *Step {
	return fsTeamDo(actor, self.fsTeamWorld, body)
}

// A Team schedule: steps, the world's close, the readers' agreement and FI-26's acl half after every step.
func (self *aclM6World) schedule(id string, steps ...*Step) *Schedule {
	return &Schedule{
		Id:    id,
		Steps: append(steps, fsTeamClose(self.fsTeamWorld)),
		Check: []Invariant{FsTeamAgreement(self.fsTeamWorld), AclM6RequestSoundness(self)},
	}
}

// The first step of a Team schedule: the network bootstrapped on the Net's tier with ACL's compile, the spend check
// and the team tier; an Admin beside the Owner, each with its first device, and Members m and b with theirs, every
// one consented; Team's starting document saved by the Owner's device; and the directory, created by it. Then body.
func (self *aclM6World) start(body func(net *sidecartest.AdmissionNet) error) *Step {
	world := self
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			tier.AclCompile = sidecartest.AclAdmissionCompile
			tier.AclSpendCheck = sidecar.NewSpendCheck(nil)
			tier.Team = true
			team := sidecartest.NewAdmissionNet(fsTeamFailer{}, tier)
			world.net = team
			owner := team.Owner()
			world.devices["owner first"] = owner
			adminMemberId := team.AdmitMember(owner, "admin", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			adminFirst := team.Device("admin first", adminMemberId)
			team.AdmitDevice(owner, adminFirst, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
			team.MustLand(team.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, team.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{adminMemberId}, 0)))
			world.devices["admin first"] = adminFirst
			_, world.devices["m first"] = team.ConsentedMember("m")
			_, world.devices["b first"] = team.ConsentedMember("b")
			// the compile expands the document's autogroups over the folded members
			team.Fold(true)
			plan, _ := team.SaveAclPolicy(sidecar.AclTeamStartDocument(), nil)
			if !plan.Rows.GetHasDocument() || len(plan.Rows.GetRequests()) != 1 {
				return fmt.Errorf("the starting document saved %d requests rules", len(plan.Rows.GetRequests()))
			}
			world.requestsRuleId = bytes.Clone(plan.Rows.GetRequests()[0].GetRuleId())
			tagId, found := sidecartest.AclTagAtom(plan, "recurd")
			if !found {
				return errors.New("the saved head names no tag:recurd")
			}
			world.ids["tag recurd"] = tagId.Bytes()
			directoryId := world.directoryId
			if directoryId == (sidecar.Id{}) {
				directoryId = team.Id("repo directory")
			}
			team.MustLand(team.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
				Header: team.Header(), RepoId: directoryId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY,
			}))
			world.ids["directory"] = directoryId.Bytes()
			// a second directory is refused: one per network
			second := team.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
				Header: team.Header(), RepoId: team.Id("repo a second directory").Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY,
			})
			team.MustRefuse(second, sidecar.ErrConfigRule)
			var groupId sidecar.Id
			copy(groupId[:], team.Id("config group").Bytes())
			world.configKey, _, err = sidecar.NewGkmFirstGeneration(team.ConfigRepoId(), groupId, &sidecar.GkmGenerationArgs{
				Cause:         sidecar.GkmCauseRequest,
				Auth:          team.Tip(),
				Time:          team.Clock().Now(),
				HoldersSha256: make([]byte, 32),
			})
			if err != nil {
				return err
			}
			if body == nil {
				return nil
			}
			return body(team)
		})
	}}
}

// The member a device's admission names.
func aclM6Member(device *sidecartest.AdmissionDevice) sidecar.Id {
	return device.MemberId
}

// A tagged worker (tag:recurd) the signer's member sponsors, admitted for a day.
func (self *aclM6World) admitWorker(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, name string) *sidecartest.AdmissionDevice {
	worker := net.Device(name, sidecar.Id{})
	net.MustLand(net.Sign(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.Admission(worker, []sidecar.Id{sidecar.Id(self.ids["tag recurd"])}, false, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	self.devices[name] = worker
	return worker
}

// An untagged ephemeral sidecar under the signer's member, admitted for a day.
func (self *aclM6World) admitEphemeral(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, name string) *sidecartest.AdmissionDevice {
	burner := net.Device(name, signer.MemberId)
	net.MustLand(net.Sign(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	self.devices[name] = burner
	return burner
}

// A sidecar's grant_dst text (§8.4's grammar).
func aclM6Dst(sidecarId sidecar.Id) string {
	return "sidecar:" + hex.EncodeToString(sidecarId.Bytes())
}

// Files a repo request in the world's ledger: requester asks role on the repo for subject until expiresMs, 0 asking
// the approver's default.
func (self *aclM6World) repoRequest(net *sidecartest.AdmissionNet, name string, requester *sidecartest.AdmissionDevice, repoId sidecar.Id,
	role protocol.RepoGrantRole, expiresMs int64) *aclM6Request {
	request := &aclM6Request{
		name:      name,
		requester: requester.SidecarId,
		request: &protocol.DirectoryRequest{
			RequestId:          net.Id("request " + name).Bytes(),
			Target:             &protocol.RequestTarget{RepoId: repoId.Bytes()},
			Subject:            requester.SidecarId.Bytes(),
			Role:               uint32(role),
			GrantExpiresMillis: expiresMs,
			NotAfterMillis:     net.Clock().Now().Add(7 * 24 * time.Hour).UnixMilli(),
			FiledBy:            1,
		},
	}
	self.requests = append(self.requests, request)
	return request
}

// Files a reach request in the world's ledger: requester asks to dial target on port until expiresMs, its grant the
// CanonicalAction a daemon builds (§8.8; QD-740): a forward under the directory's requests rule, its clear grant_dst
// the target alone, the port sealed in its detail under the config repo's key.
func (self *aclM6World) reachRequest(net *sidecartest.AdmissionNet, name string, requester *sidecartest.AdmissionDevice, target sidecar.Id,
	port uint32, expiresMs int64) (*aclM6Request, error) {
	clear := &protocol.CanonicalAction{
		Kind:          uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD),
		ExpiresMillis: expiresMs,
		GrantDst:      []string{aclM6Dst(target)},
		GrantAllow:    []string{"dial"},
		RuleId:        bytes.Clone(self.requestsRuleId),
		Subject:       requester.SidecarId.Bytes(),
	}
	detail := &protocol.CanonicalActionDetail{TargetPort: port, GrantDst: []string{fmt.Sprintf("%s:tcp:%d", aclM6Dst(target), port)}}
	action, err := sidecar.NewSealedCanonicalAction(clear, detail, self.configKey, net.NetworkId(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s's action: %w", name, err)
	}
	requestId := net.Id("request " + name)
	payloadSha256 := action.PayloadSha256()
	notAfterMs := net.Clock().Now().Add(7 * 24 * time.Hour).UnixMilli()
	request := &aclM6Request{
		name:      name,
		requester: requester.SidecarId,
		action:    action,
		port:      port,
		request: &protocol.DirectoryRequest{
			RequestId:          requestId.Bytes(),
			Target:             &protocol.RequestTarget{SidecarId: target.Bytes(), TcpPorts: []uint32{port}},
			Subject:            requester.SidecarId.Bytes(),
			Role:               uint32(protocol.AclAction_ACL_ACTION_DIAL),
			GrantExpiresMillis: expiresMs,
			NotAfterMillis:     notAfterMs,
			FiledBy:            1,
			Approval: &protocol.ApprovalRequest{
				ApprovalId:         requestId.Bytes(),
				CanonicalAction:    action.Bytes,
				PayloadSha256:      payloadSha256[:],
				RequesterSidecarId: requester.SidecarId.Bytes(),
				NotAfterMillis:     notAfterMs,
				Version:            1,
			},
		},
	}
	self.requests = append(self.requests, request)
	return request, nil
}

// Fails unless, at every reader, exactly the deciders named decide the request among candidates, each judged at the
// tip's pin as its decision entry's push would be (§16.11's receipt row).
func (self *aclM6World) expectDeciders(net *sidecartest.AdmissionNet, request *aclM6Request, candidates map[string]*sidecartest.AdmissionDevice, deciders ...string) error {
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		view := sidecar.NewDirectoryAuthView(state)
		for name, device := range candidates {
			decides, err := view.Decides(request.request, request.requester, device.SidecarId, state.Pin())
			if err != nil {
				return fmt.Errorf("%s: whether %s decides: %w", request.name, name, err)
			}
			if want := slices.Contains(deciders, name); decides != want {
				return fmt.Errorf("%s: %s decides %t, want %t", request.name, name, decides, want)
			}
		}
		return nil
	})
	return nil
}

// An ApprovalDecision approving a reach request on channel, as the approver's member, at the tip's pin, good for an
// hour and one use (§16.8).
func (self *aclM6World) decisionBody(net *sidecartest.AdmissionNet, request *aclM6Request, approverMemberId sidecar.Id, channel protocol.ApprovalChannel) ([]byte, error) {
	approvalBytes, err := protoMarshal(request.request.GetApproval())
	if err != nil {
		return nil, err
	}
	requestSha256 := sidecar.ApprovalRequestSha256(approvalBytes)
	payloadSha256 := request.action.PayloadSha256()
	body := &protocol.ApprovalDecision{
		ApprovalId:         bytes.Clone(request.request.GetRequestId()),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     net.Clock().Now().Add(time.Hour).UnixMilli(),
		ApproverMemberId:   approverMemberId.Bytes(),
		Channel:            uint32(channel),
		RequesterSidecarId: request.requester.Bytes(),
		AuthPin:            net.Tip(),
		Version:            1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		evidence := sha256Sum(append([]byte("a hook event of "), request.request.GetRequestId()...))
		body.EvidenceSha256 = evidence[:]
	}
	return protoMarshal(body)
}

// A device's decision on a reach request: its identity key's Signed, on the device channel or, where the test asks,
// the harness's.
func (self *aclM6World) deviceDecision(net *sidecartest.AdmissionNet, request *aclM6Request, device *sidecartest.AdmissionDevice, channel protocol.ApprovalChannel) (*bridge.Signed, error) {
	body, err := self.decisionBody(net, request, device.MemberId, channel)
	if err != nil {
		return nil, err
	}
	return &bridge.Signed{
		Body:      body,
		SignerId:  device.SidecarId.Bytes(),
		Signature: ed25519.Sign(device.Key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}, nil
}

// A member's presence decision on a reach request: its registered presence key's Signed.
func (self *aclM6World) presenceDecision(net *sidecartest.AdmissionNet, request *aclM6Request, memberId sidecar.Id, key *sidecartest.FixturePresenceKey) (*bridge.Signed, error) {
	body, err := self.decisionBody(net, request, memberId, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)
	if err != nil {
		return nil, err
	}
	return key.Sign(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body), nil
}

// The GrantActivate that spends decisions on a reach request's grant, signed by spender: its grant_id the approval
// fixes (§8.8).
func (self *aclM6World) grantActivate(net *sidecartest.AdmissionNet, request *aclM6Request, spender *sidecartest.AdmissionDevice, decisions ...*bridge.Signed) []byte {
	grantId := sidecar.AclGrantId(sidecar.Id(request.request.GetRequestId()), request.action.PayloadSha256())
	return net.Sign(spender, bridge.SignedType_SIGNED_GRANT_ACTIVATE, &protocol.GrantActivate{
		Header: net.Header(), GrantId: grantId[:], CanonicalAction: request.action.Bytes, Decisions: decisions,
	})
}

// Fails unless, at every reader, source reaches exactly the destinations named among candidates.
func aclM6ExpectReach(net *sidecartest.AdmissionNet, source *sidecartest.AdmissionDevice, candidates map[string]*sidecartest.AdmissionDevice, reached ...string) error {
	now := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for name, device := range candidates {
			allowed := acl.Reach(sidecar.AclSidecarSubject(source.SidecarId), sidecar.AclSidecarSubject(device.SidecarId), now).Allowed
			if want := slices.Contains(reached, name); allowed != want {
				return fmt.Errorf("%s reaches %s: %t, want %t", source.Name, name, allowed, want)
			}
		}
		return nil
	})
	return nil
}

// FI-26's acl half (§22.8's request soundness), over the requests a schedule filed, at every reader: every RepoGrant
// and EvsShare row and every activated grant in the rows exists for one approved request, signed or approved by the
// decider the schedule found eligible at its position, names exactly the request's target (for a worker, dial on the
// one target, its ports limited to the sealed ones) and the request's subject, and expires no later than asked; no
// request yields two, and one that was never approved yields none. In place of FI-26's oracle, which RECORD-M6-26
// binds with the directory's decision entries and notices.
func AclM6RequestSoundness(world *aclM6World) Invariant {
	return NewInvariant("FI-26/acl", func(ctx context.Context, oracle *Oracle) error {
		if world.net == nil {
			return nil
		}
		return fsTeamCatch(func() error {
			world.net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				return world.sound(acl)
			})
			return nil
		})
	})
}

// The repo request an access row answers: the one for the repo and subject, nil for none.
func (self *aclM6World) repoRequestFor(repoId []byte, subject []byte) *aclM6Request {
	for _, request := range self.requests {
		if request.action == nil && bytes.Equal(request.request.GetTarget().GetRepoId(), repoId) && bytes.Equal(request.request.GetSubject(), subject) {
			return request
		}
	}
	return nil
}

// AclM6RequestSoundness at one reader's rows.
func (self *aclM6World) sound(acl *sidecar.AclState) error {
	rows := acl.Rows()
	yields := map[*aclM6Request]int{}
	answered := func(what string, repoId []byte, subject []byte, expires int64, signer []byte) (*aclM6Request, error) {
		request := self.repoRequestFor(repoId, subject)
		if request == nil {
			return nil, fmt.Errorf("%s on %x for %x answers no request", what, repoId, subject)
		}
		if !request.approved {
			return nil, fmt.Errorf("%s exists for %s, which no one approved", what, request.name)
		}
		if !bytes.Equal(signer, request.decider.Bytes()) {
			return nil, fmt.Errorf("%s for %s is signed by %x, not its eligible decider", what, request.name, signer)
		}
		if asked := request.request.GetGrantExpiresMillis(); asked != 0 && (expires == 0 || asked < expires) {
			return nil, fmt.Errorf("%s for %s expires at %d, later than the %d asked", what, request.name, expires, asked)
		}
		yields[request] += 1
		return request, nil
	}
	for _, repo := range rows.GetRepos() {
		for _, grant := range repo.GetGrants() {
			request, err := answered("a RepoGrant", repo.GetRepoId(), grant.GetSubject(), grant.GetExpires(), grant.GetSigner())
			if err != nil {
				return err
			}
			if uint32(grant.GetRole()) != request.request.GetRole() {
				return fmt.Errorf("the RepoGrant for %s gives role %d, not the %d asked", request.name, grant.GetRole(), request.request.GetRole())
			}
		}
		for _, share := range repo.GetShares() {
			if _, err := answered("an EvsShare", repo.GetRepoId(), share.GetSubject(), share.GetExpires(), share.GetSigner()); err != nil {
				return err
			}
		}
	}
	for _, rule := range rows.GetRules() {
		if len(rule.GetSourceRuleId()) == 0 {
			// the document's own rule
			continue
		}
		index := slices.IndexFunc(self.requests, func(request *aclM6Request) bool {
			return request.grantId != nil && bytes.Equal(request.grantId, rule.GetRuleId())
		})
		if index < 0 {
			return fmt.Errorf("the activated grant %x spends no approved request", rule.GetRuleId())
		}
		request := self.requests[index]
		yields[request] += 1
		subjectAtom := sidecar.AclDerivedAtom(sidecar.AclDerivedAtomSidecar, request.requester.Bytes())
		if len(rule.GetSrcAtoms()) != 1 || !bytes.Equal(rule.GetSrcAtoms()[0], subjectAtom.Bytes()) {
			return fmt.Errorf("%s's grant names a subject other than its requester", request.name)
		}
		if len(rule.GetTargets()) != 1 || !bytes.Equal(rule.GetTargets()[0].GetSidecarId(), request.request.GetTarget().GetSidecarId()) {
			return fmt.Errorf("%s's grant names %d targets, not the one asked", request.name, len(rule.GetTargets()))
		}
		if !slices.Equal(rule.GetActions(), []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)}) {
			return fmt.Errorf("%s's grant allows %v, not dial alone", request.name, rule.GetActions())
		}
		if !rule.GetPortsLimited() {
			return fmt.Errorf("%s's grant opens every port of its worker", request.name)
		}
		if asked := request.request.GetGrantExpiresMillis(); asked != 0 && (rule.GetExpires() == 0 || asked < rule.GetExpires()) {
			return fmt.Errorf("%s's grant expires at %d, later than the %d asked", request.name, rule.GetExpires(), asked)
		}
		if !bytes.Equal(rule.GetSourceRuleId(), self.requestsRuleId) {
			return fmt.Errorf("%s's grant stands under a rule other than the directory's", request.name)
		}
	}
	for request, count := range yields {
		if !request.approved || 1 < count {
			return fmt.Errorf("%s, approved %t, yields %d grants", request.name, request.approved, count)
		}
	}
	return nil
}

// The port the workers of these schedules announce, and one they do not.
const (
	aclM6WorkerPort      = 8443
	aclM6UnannouncedPort = 22
)

// The worker world: m's second device, m's ephemeral, a worker m sponsors and one b sponsors, and m's presence key,
// registered on the log by m's first device.
func (self *aclM6World) startWorkers() *Step {
	world := self
	return self.start(func(net *sidecartest.AdmissionNet) error {
		mFirst, bFirst := world.devices["m first"], world.devices["b first"]
		phone := net.Device("m phone", mFirst.MemberId)
		net.AdmitDevice(mFirst, phone, 0)
		world.devices["m phone"] = phone
		world.admitEphemeral(net, mFirst, "m burner")
		world.admitWorker(net, mFirst, "m worker")
		world.admitWorker(net, bFirst, "b worker")
		key := sidecartest.NewFixturePresenceKey("m presence", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		net.RegisterPresenceKey(mFirst, key, nil)
		world.presenceKeys["m"] = key
		net.Fold(true)
		return nil
	})
}

// Everyone a worker schedule asks about.
func (self *aclM6World) cast() map[string]*sidecartest.AdmissionDevice {
	return self.devices
}

// FS-85's worker request (§22.8; D-ACL-23, owner decisions 179 and 180): b's device asks to dial a worker m sponsors
// on its announced port. Under the directory rule only a device of m, the worker's sponsor, decides it at every
// reader, never the Owner's, the Admin's, the requester's or an ephemeral; a harness decision by m and the
// requester's own each activate nothing; m's device decision does, once: the grant reaches the worker alone, its
// ports limited to the sealed one, and the same spend again is a replay. A second request, to a device m owns, takes
// m's presence decision.
//
// What the log's own quorum makes of an Admin's lone decision is not judged here: acl_grant.go counts an admin toward
// k for a grant touching another member, while the directory names the sponsor alone as its decider (question
// acl-m6-05-admin-alone-reach).
func Fs85AclWorkerRequest(net *Net) *Schedule {
	world := newAclM6World()
	return world.schedule("FS-85 acl worker request",
		world.startWorkers(),
		world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst, worker := world.devices["b first"], world.devices["m first"], world.devices["m worker"]
			request, err := world.reachRequest(net, "worker", bFirst, worker.SidecarId, aclM6WorkerPort, net.Clock().Now().Add(2*time.Hour).UnixMilli())
			if err != nil {
				return err
			}
			if err := world.expectDeciders(net, request, world.cast(), "m first", "m phone"); err != nil {
				return err
			}
			harness, err := world.deviceDecision(net, request, mFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)
			if err != nil {
				return err
			}
			net.MustRefuse(world.grantActivate(net, request, bFirst, harness), sidecar.ErrConfigAuthority)
			own, err := world.deviceDecision(net, request, bFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			if err != nil {
				return err
			}
			net.MustRefuse(world.grantActivate(net, request, bFirst, own), sidecar.ErrConfigAuthority)
			return aclM6ExpectReach(net, bFirst, world.cast(), "b first", "b worker")
		}),
		world.do("mFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst := world.devices["b first"], world.devices["m first"]
			request := world.requests[0]
			decision, err := world.deviceDecision(net, request, mFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			if err != nil {
				return err
			}
			activate := world.grantActivate(net, request, bFirst, decision)
			grantId := sidecar.AclGrantId(sidecar.Id(request.request.GetRequestId()), request.action.PayloadSha256())
			request.approved, request.decider, request.grantId = true, mFirst.SidecarId, grantId[:]
			net.MustLand(activate)
			if err := aclM6ExpectReach(net, bFirst, world.cast(), "b first", "b worker", "m worker"); err != nil {
				return err
			}
			// once: the same activation, and a fresh statement of the same spend, are replays
			net.MustRefuse(world.grantActivate(net, request, bFirst, decision), sidecar.ErrConfigReplay)
			// the grant opens the announced port alone: its clear form names no port, and the sealed detail every
			// holder of the config key opens names the one
			detail, err := sidecar.OpenCanonicalActionDetail(request.action, net.NetworkId(), func(generation uint64) *sidecar.EvsRepoKey {
				if generation != world.configKey.Generation() {
					return nil
				}
				return world.configKey
			})
			if err != nil {
				return err
			}
			want := fmt.Sprintf("%s:tcp:%d", aclM6Dst(world.devices["m worker"].SidecarId), aclM6WorkerPort)
			if detail.GetTargetPort() != aclM6WorkerPort || !slices.Equal(detail.GetGrantDst(), []string{want}) {
				return fmt.Errorf("the grant's sealed detail names port %d and %v", detail.GetTargetPort(), detail.GetGrantDst())
			}
			return nil
		}),
		world.do("mPresence", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst, phone := world.devices["b first"], world.devices["m first"], world.devices["m phone"]
			request, err := world.reachRequest(net, "device", bFirst, phone.SidecarId, aclM6WorkerPort, net.Clock().Now().Add(time.Hour).UnixMilli())
			if err != nil {
				return err
			}
			// a device m owns: m's other devices decide, never the target's own approval of itself by another member
			if err := world.expectDeciders(net, request, world.cast(), "m first", "m phone"); err != nil {
				return err
			}
			decision, err := world.presenceDecision(net, request, mFirst.MemberId, world.presenceKeys["m"])
			if err != nil {
				return err
			}
			grantId := sidecar.AclGrantId(sidecar.Id(request.request.GetRequestId()), request.action.PayloadSha256())
			request.approved, request.decider, request.grantId = true, mFirst.SidecarId, grantId[:]
			net.MustLand(world.grantActivate(net, request, bFirst, decision))
			return aclM6ExpectReach(net, bFirst, world.cast(), "b first", "b worker", "m worker", "m phone")
		}),
	)
}

// FS-85's copied decision (§22.8; FI-26): m's device decision approves b's request to dial m's worker on its
// announced port. Copied onto b's second request, for another port, onto the Admin's own request for the same
// worker, under another request's grant_id, or with its approval_id rewritten, it activates nothing at api or any
// reader, and on T2 a malicious api's append of the copy is refused at its position; then the request it approved
// spends it, as the twin.
func Fs85AclCopiedDecision(net *Net) *Schedule {
	world := newAclM6World()
	return world.schedule("FS-85 acl copied decision",
		world.startWorkers(),
		world.do("mFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst, adminFirst, worker := world.devices["b first"], world.devices["m first"], world.devices["admin first"], world.devices["m worker"]
			expiresMs := net.Clock().Now().Add(2 * time.Hour).UnixMilli()
			approved, err := world.reachRequest(net, "approved", bFirst, worker.SidecarId, aclM6WorkerPort, expiresMs)
			if err != nil {
				return err
			}
			otherPort, err := world.reachRequest(net, "another port", bFirst, worker.SidecarId, aclM6UnannouncedPort, expiresMs)
			if err != nil {
				return err
			}
			otherRequester, err := world.reachRequest(net, "another requester", adminFirst, worker.SidecarId, aclM6WorkerPort, expiresMs)
			if err != nil {
				return err
			}
			decision, err := world.deviceDecision(net, approved, mFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			if err != nil {
				return err
			}
			copies := [][]byte{
				world.grantActivate(net, otherPort, bFirst, decision),
				world.grantActivate(net, otherRequester, adminFirst, decision),
				world.grantActivate(net, otherRequester, bFirst, decision),
			}
			// the approved action under another request's grant_id
			otherGrantId := sidecar.AclGrantId(sidecar.Id(otherPort.request.GetRequestId()), otherPort.action.PayloadSha256())
			copies = append(copies, net.Sign(bFirst, bridge.SignedType_SIGNED_GRANT_ACTIVATE, &protocol.GrantActivate{
				Header: net.Header(), GrantId: otherGrantId[:], CanonicalAction: approved.action.Bytes, Decisions: []*bridge.Signed{decision},
			}))
			for i, copied := range copies {
				net.MustRefuse(copied, sidecar.ErrConfigRule)
				if net.ForgedAppends() {
					pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, copied)
					if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigRule) {
						return fmt.Errorf("the forged copy %d at %d: %v", i, pin.GetVersion(), verdict.Refusal)
					}
				}
			}
			// the decision's body rewritten to name the other request: its signature no longer covers it
			rewritten := &protocol.ApprovalDecision{}
			if err := proto.Unmarshal(decision.GetBody(), rewritten); err != nil {
				return err
			}
			otherPayload := otherPort.action.PayloadSha256()
			rewritten.ApprovalId, rewritten.PayloadSha256 = otherPort.request.GetRequestId(), otherPayload[:]
			rewrittenBody, err := protoMarshal(rewritten)
			if err != nil {
				return err
			}
			forged := &bridge.Signed{Body: rewrittenBody, SignerId: decision.GetSignerId(), Signature: decision.GetSignature(), Type: decision.GetType()}
			net.MustRefuse(world.grantActivate(net, otherPort, bFirst, forged), sidecar.ErrConfigAuthority)
			return aclM6ExpectReach(net, bFirst, world.cast(), "b first", "b worker")
		}),
		world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst := world.devices["b first"], world.devices["m first"]
			request := world.requests[0]
			// the twin: the request the decision approved spends it
			decision, err := world.deviceDecision(net, request, mFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			if err != nil {
				return err
			}
			grantId := sidecar.AclGrantId(sidecar.Id(request.request.GetRequestId()), request.action.PayloadSha256())
			request.approved, request.decider, request.grantId = true, mFirst.SidecarId, grantId[:]
			net.MustLand(world.grantActivate(net, request, bFirst, decision))
			if err := aclM6ExpectReach(net, bFirst, world.cast(), "b first", "b worker", "m worker"); err != nil {
				return err
			}
			// the Admin, whose request no one approved, reaches nothing by it
			return aclM6ExpectReach(net, world.devices["admin first"], world.cast(), "admin first")
		}),
	)
}

// Fails unless, at every reader, the sidecar's evs and gkm rights on the repo are exactly want, it is among the
// repo's readers exactly when want reads, and it holds the repo's key, a leaf or a wrap, exactly then.
func aclM6ExpectAccess(net *sidecartest.AdmissionNet, name string, sidecarId sidecar.Id, repoId sidecar.Id, want sidecar.AclEvsRights) error {
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if err := aclExpectRights(fmt.Sprintf("%s on %s", name, repoId), aclRights(net, acl, sidecarId, repoId, sidecar.AclTokenAudienceEvs), want); err != nil {
			return err
		}
		reads := want.Has(sidecar.AclEvsRead)
		if slices.Contains(acl.RepoReaders(repoId, at), sidecarId) != reads {
			return fmt.Errorf("%s among %s's readers: %t", name, repoId, !reads)
		}
		return aclExpectHolder(state, repoId, at, sidecarId, reads, sidecar.GkmHolderLeaf, sidecar.GkmHolderAgent)
	})
	return nil
}

// Fails unless every reader finds the repo's key holders' first expiry in (now, at], with no entry (§7.9's expiry
// row).
func aclM6ExpectExpiry(net *sidecartest.AdmissionNet, repoId sidecar.Id, at time.Time) error {
	after := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		found, ok, err := state.ExpiriesFor(repoId, after, at.Add(time.Minute))
		if err != nil || !ok || found.After(at) || found.Before(after) {
			return fmt.Errorf("%s's expiry: %t at %s, %v", repoId, ok, found, err)
		}
		return nil
	})
	return nil
}

// The repo requests' world: m's general repo notes, private and named by its id alone, with m's phone a second admin
// of it; m's vault; a device of m the Owner admitted, which m has not confirmed; and m's ephemeral.
func (self *aclM6World) startRepos() *Step {
	world := self
	return self.start(func(net *sidecartest.AdmissionNet) error {
		mFirst := world.devices["m first"]
		phone := net.Device("m phone", mFirst.MemberId)
		net.AdmitDevice(mFirst, phone, 0)
		world.devices["m phone"] = phone
		tablet := net.Device("m tablet", mFirst.MemberId)
		net.AdmitDevice(net.Owner(), tablet, 0)
		world.devices["m tablet"] = tablet
		world.admitEphemeral(net, mFirst, "m burner")
		notes := aclCreateRepo(net, mFirst, "notes", protocol.RepoKind_REPO_KIND_GENERAL)
		net.MustLand(net.Sign(mFirst, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
			Header: net.Header(), RepoId: notes.Bytes(), SidecarId: phone.SidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
		}))
		world.ids["notes"] = notes.Bytes()
		world.ids["vault"] = aclCreateRepo(net, mFirst, "m vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
		net.Fold(true)
		return nil
	})
}

// A request's RepoGrant as its approver signs it: the request's repo, subject, role and expiry.
func aclM6RepoGrant(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, request *aclM6Request) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header:  net.Header(),
		RepoId:  request.request.GetTarget().GetRepoId(),
		Subject: request.request.GetSubject(),
		Role:    protocol.RepoGrantRole(request.request.GetRole()),
		Expires: request.request.GetGrantExpiresMillis(),
	})
}

// A request's EvsShare as its approver signs it: the request's repo, subject and expiry.
func aclM6EvsShare(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, request *aclM6Request) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
		Header:  net.Header(),
		RepoId:  request.request.GetTarget().GetRepoId(),
		Subject: request.request.GetSubject(),
		Expires: request.request.GetGrantExpiresMillis(),
	})
}

// The repo request's steps, FS-85's and S13's: b's device asks to read m's private repo by its id for two hours; each
// repo admin decides it and no one else, the requester's own RepoGrant being refused; m's phone approves, and the one
// RepoGrant, with the asked subject and expiry, stands at its position at every reader, which seats b's device as a
// reader and key holder at once; a request no one approves yields nothing.
func (self *aclM6World) repoRequestSteps() []*Step {
	world := self
	return []*Step{
		world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, notes := world.devices["b first"], sidecar.Id(world.ids["notes"])
			request := world.repoRequest(net, "notes", bFirst, notes, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, net.Clock().Now().Add(2*time.Hour).UnixMilli())
			// denied: the Admin's own request to write the repo, which no step approves
			world.repoRequest(net, "denied", world.devices["admin first"], notes, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, 0)
			if err := world.expectDeciders(net, request, world.cast(), "m first", "m phone"); err != nil {
				return err
			}
			net.MustRefuse(aclM6RepoGrant(net, bFirst, request), sidecar.ErrConfigAuthority)
			net.MustRefuse(aclM6RepoGrant(net, world.devices["m burner"], request), sidecar.ErrConfigAuthority)
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, notes, 0)
		}),
		world.do("mPhone", func(net *sidecartest.AdmissionNet) error {
			bFirst, phone, notes := world.devices["b first"], world.devices["m phone"], sidecar.Id(world.ids["notes"])
			request := world.requests[0]
			request.approved, request.decider = true, phone.SidecarId
			verdict := net.MustLand(aclM6RepoGrant(net, phone, request))
			position := verdict.Pin.GetVersion()
			world.positions["grant"] = position
			// the requester's daemon verifies the grant at its log position: the entry there carries it, every reader
			// accepted it, and its signer held the repo's admin right there (D-MCP-35)
			net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				admin, err := sidecar.NewDirectoryAuthView(state).RepoAdminRight(notes, phone.SidecarId, position)
				if err != nil || !admin {
					return fmt.Errorf("the grant's signer at %d: admin %t, %v", position, admin, err)
				}
				rows := 0
				for _, repo := range acl.Rows().GetRepos() {
					if !bytes.Equal(repo.GetRepoId(), notes.Bytes()) {
						continue
					}
					for _, grant := range repo.GetGrants() {
						if !bytes.Equal(grant.GetSubject(), bFirst.SidecarId.Bytes()) {
							continue
						}
						rows += 1
						if grant.GetExpires() != request.request.GetGrantExpiresMillis() || grant.GetAt() != position ||
							grant.GetRole() != protocol.RepoGrantRole_REPO_GRANT_ROLE_READER {
							return fmt.Errorf("the grant's row: role %s, expires %d, at %d", grant.GetRole(), grant.GetExpires(), grant.GetAt())
						}
					}
				}
				if rows != 1 {
					return fmt.Errorf("%d grant rows for the request, want one", rows)
				}
				return nil
			})
			if accepted := net.VerdictAt(position); !accepted.Accepted() {
				return fmt.Errorf("the grant at %d: %v", position, accepted.Refusal)
			}
			if err := aclM6ExpectAccess(net, "b first", bFirst.SidecarId, notes, sidecar.AclEvsRead); err != nil {
				return err
			}
			// the grant opens that repo alone
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, sidecar.Id(world.ids["vault"]), 0)
		}),
	}
}

// FS-85's repo request (§22.8; FI-26; owner decision 181): repoRequestSteps, then the grant's expiry ends it at its
// own time with no entry and no device online.
func Fs85AclRepoRequest(net *Net) *Schedule {
	world := newAclM6World()
	steps := append([]*Step{world.startRepos()}, world.repoRequestSteps()...)
	steps = append(steps, world.do("clock", func(net *sidecartest.AdmissionNet) error {
		bFirst, notes := world.devices["b first"], sidecar.Id(world.ids["notes"])
		expires := time.UnixMilli(world.requests[0].request.GetGrantExpiresMillis())
		if err := aclM6ExpectExpiry(net, notes, expires); err != nil {
			return err
		}
		net.Wait(2*time.Hour + time.Minute)
		return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, notes, 0)
	}))
	return world.schedule("FS-85 acl repo request", steps...)
}

// FS-85's owner-bound request (§22.8; FI-26; owner decision 126): b's device asks to read m's vault for two hours.
// Only a consented device of m decides it: not the Owner's or the Admin's, not m's ephemeral, and not the device of m
// an admin admitted and m has not confirmed. Api and every reader refuse the Admin's EvsShare, the Owner's, the
// unconfirmed device's and any RepoGrant on the vault, and on T2 a malicious api's append of the Admin's share is
// refused at its position, opening nothing. m's consented device's EvsShare opens exactly the vault to b's device at
// once, and its expires ends it at every reader with no entry and no device online.
func Fs85AclOwnerBoundRequest(net *Net) *Schedule {
	world := newAclM6World()
	return world.schedule("FS-85 acl owner-bound request",
		world.startRepos(),
		world.do("adminFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, vault := world.devices["b first"], sidecar.Id(world.ids["vault"])
			request := world.repoRequest(net, "vault", bFirst, vault, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, net.Clock().Now().Add(2*time.Hour).UnixMilli())
			if err := world.expectDeciders(net, request, world.cast(), "m first", "m phone"); err != nil {
				return err
			}
			adminShare := aclM6EvsShare(net, world.devices["admin first"], request)
			for _, name := range []string{"admin first", "owner first", "m tablet", "m burner", "b first"} {
				net.MustRefuse(aclM6EvsShare(net, world.devices[name], request), sidecar.ErrConfigAuthority)
			}
			// an owner-bound repo takes no RepoGrant, its owner's included
			for _, name := range []string{"admin first", "m first"} {
				net.MustRefuse(aclM6RepoGrant(net, world.devices[name], request), sidecar.ErrConfigRule)
			}
			if net.ForgedAppends() {
				pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, adminShare)
				if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigAuthority) {
					return fmt.Errorf("the Admin's forged share at %d: %v", pin.GetVersion(), verdict.Refusal)
				}
			}
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, vault, 0)
		}),
		world.do("mFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst, vault := world.devices["b first"], world.devices["m first"], sidecar.Id(world.ids["vault"])
			request := world.requests[0]
			request.approved, request.decider = true, mFirst.SidecarId
			net.MustLand(aclM6EvsShare(net, mFirst, request))
			// a share's reader reads, and deposits as every reader of an owner-bound repo that does not write it does,
			// its read receipts among them (D-MCP-18); it never writes
			if err := aclM6ExpectAccess(net, "b first", bFirst.SidecarId, vault, sidecar.AclEvsRead|sidecar.AclEvsDeposit); err != nil {
				return err
			}
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, sidecar.Id(world.ids["notes"]), 0)
		}),
		world.do("clock", func(net *sidecartest.AdmissionNet) error {
			bFirst, vault := world.devices["b first"], sidecar.Id(world.ids["vault"])
			expires := time.UnixMilli(world.requests[0].request.GetGrantExpiresMillis())
			if err := aclM6ExpectExpiry(net, vault, expires); err != nil {
				return err
			}
			// no device signs anything: the clock alone ends the share
			net.Wait(2*time.Hour + time.Minute)
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, vault, 0)
		}),
	)
}

// S13's grant steps (§22.7's S13, F13; FS-85; owner decisions 179, 180, 181): b's device asks to read m's private repo
// by its id, a person approves on a repo admin's device, b's device reads the repo and the RepoGrant verifies at its
// log position; b's device then asks to reach a worker m sponsors, m approves as autogroup:dst-owner, and b's device
// spends the approval once into a GrantActivate that reaches the worker alone, on the sealed, announced port. The
// directory's own steps, the find, the hint and the notice, are RECORD-M6-26's.
func AclS13GrantSteps(net *Net) *Schedule {
	world := newAclM6World()
	steps := []*Step{
		world.startRepos(),
		world.do("mFirst", func(net *sidecartest.AdmissionNet) error {
			world.admitWorker(net, world.devices["m first"], "m worker")
			net.Fold(true)
			return nil
		}),
	}
	steps = append(steps, world.repoRequestSteps()...)
	steps = append(steps,
		world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
			bFirst, mFirst, worker := world.devices["b first"], world.devices["m first"], world.devices["m worker"]
			request, err := world.reachRequest(net, "worker", bFirst, worker.SidecarId, aclM6WorkerPort, net.Clock().Now().Add(time.Hour).UnixMilli())
			if err != nil {
				return err
			}
			if err := world.expectDeciders(net, request, world.cast(), "m first", "m phone"); err != nil {
				return err
			}
			if err := aclM6ExpectReach(net, bFirst, world.cast(), "b first"); err != nil {
				return err
			}
			decision, err := world.deviceDecision(net, request, mFirst, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			if err != nil {
				return err
			}
			grantId := sidecar.AclGrantId(sidecar.Id(request.request.GetRequestId()), request.action.PayloadSha256())
			request.approved, request.decider, request.grantId = true, mFirst.SidecarId, grantId[:]
			net.MustLand(world.grantActivate(net, request, bFirst, decision))
			net.MustRefuse(world.grantActivate(net, request, bFirst, decision), sidecar.ErrConfigReplay)
			// the worker alone, none of m's devices; and the repo's read stands beside it
			if err := aclM6ExpectReach(net, bFirst, world.cast(), "b first", "m worker"); err != nil {
				return err
			}
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, sidecar.Id(world.ids["notes"]), sidecar.AclEvsRead)
		}),
		world.do("gate", func(net *sidecartest.AdmissionNet) error {
			// across a base, each new device and gate holds the grant and the read as the reference does
			net.Fold(true)
			bFirst := world.devices["b first"]
			if err := aclM6ExpectReach(net, bFirst, world.cast(), "b first", "m worker"); err != nil {
				return err
			}
			return aclM6ExpectAccess(net, "b first", bFirst.SidecarId, sidecar.Id(world.ids["notes"]), sidecar.AclEvsRead)
		}),
	)
	return world.schedule("S13's grant steps", steps...)
}

var (
	Fs19TeamCase   = Register("FS-19", "team", []Tier{TierT2, TierT3}, Fs19Team)
	Fs19InviteCase = Register("FS-19", "invite", []Tier{TierT2, TierT3}, Fs19Invite)
)

// A Team's document that opens everything a document can: every member device every action on every resource, with
// the starting document's requests rule. What it cannot open is the directory, whose readers the binary fixes
// (D-ACL-24).
const fs19M6WidePolicy = `{
	"tagOwners": { "tag:recurd": ["autogroup:member"] },
	"grants": [
		{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
		{ "src": ["tag:recurd"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
	],
	"requests": [
		{ "src": ["autogroup:member", "autogroup:tagged"],
		  "dst": ["autogroup:member", "autogroup:tagged", "sock:*"], "allow": ["dial"],
		  "approver": ["autogroup:dst-owner"], "evidence": ["device", "presence"], "maxExpiry": "30d" },
	],
}`

// A Team's document that opens nothing: no grant and no requests rule.
const fs19M6NarrowPolicy = `{ "grants": [] }`

// What each sidecar of FS-19's team holds on the directory, by its name in the world.
func fs19M6DirectoryRights() map[string]sidecar.AclEvsRights {
	write := sidecar.AclEvsRead | sidecar.AclEvsWrite
	return map[string]sidecar.AclEvsRights{
		"owner first":  write | sidecar.AclEvsAdmin,
		"admin first":  write | sidecar.AclEvsAdmin,
		"m first":      write,
		"b first":      write,
		"m burner":     write,
		"admin burner": write,
		"m tablet":     write,
	}
}

// Fails unless, at every reader, the directory is the network's one directory, its readers and writers are exactly
// every admitted sidecar of the team, each holds exactly the kind default's rights on it and the exchange issues it
// exactly those scopes for evs and gkm, the two ephemerals hold its key by a wrap and never a leaf, and only the
// Owner's and the Admin's devices are its admins.
func fs19M6ExpectDirectory(net *sidecartest.AdmissionNet, world *aclM6World) error {
	directory := sidecar.Id(world.ids["directory"])
	at := net.Clock().Now()
	rights := fs19M6DirectoryRights()
	everyone := []sidecar.Id{}
	for name := range rights {
		everyone = append(everyone, world.devices[name].SidecarId)
	}
	slices.SortFunc(everyone, sidecar.Id.Cmp)
	admins := []sidecar.Id{world.devices["owner first"].SidecarId, world.devices["admin first"].SidecarId}
	slices.SortFunc(admins, sidecar.Id.Cmp)
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		view := sidecar.NewDirectoryAuthView(state)
		if found, ok := view.Directory(); !ok || found != directory {
			return fmt.Errorf("the network's directory: %s, %t", found, ok)
		}
		if readers := acl.RepoReaders(directory, at); !slices.Equal(readers, everyone) {
			return fmt.Errorf("the directory's readers: %v, want %v", readers, everyone)
		}
		if writers := acl.RepoWriters(directory, at); !slices.Equal(writers, everyone) {
			return fmt.Errorf("the directory's writers: %v, want %v", writers, everyone)
		}
		if directoryAdmins, err := view.DirectoryAdmins(state.Pin()); err != nil || !slices.Equal(directoryAdmins, admins) {
			return fmt.Errorf("the directory's admins: %v, %v", directoryAdmins, err)
		}
		for name, want := range rights {
			sidecarId := world.devices[name].SidecarId
			scopes := []string{aclScope(directory, "r"), aclScope(directory, "rw"), aclScope(directory, "admin")}
			granted := []string{aclScope(directory, "r"), aclScope(directory, "rw")}
			if want.Has(sidecar.AclEvsAdmin) {
				granted = append(granted, aclScope(directory, "admin"))
			}
			for _, audience := range []sidecar.AclTokenAudience{sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm} {
				if err := aclExpectRights(fmt.Sprintf("%s on the directory", name), aclRights(net, acl, sidecarId, directory, audience), want); err != nil {
					return err
				}
				if err := aclExpectScopes(net, state, sidecarId, audience, scopes, granted); err != nil {
					return fmt.Errorf("%s's: %w", name, err)
				}
			}
		}
		for _, name := range []string{"m burner", "admin burner"} {
			sidecarId := world.devices[name].SidecarId
			if err := aclExpectHolder(state, directory, at, sidecarId, true, sidecar.GkmHolderAgent); err != nil {
				return err
			}
			if err := aclExpectHolder(state, directory, at, sidecarId, false, sidecar.GkmHolderLeaf); err != nil {
				return err
			}
		}
		return nil
	})
	return nil
}

// Fails unless, at every reader, the sidecar's standing to sign and write in the directory is want (§16.11's card
// row; I-EVS-14).
func aclM6ExpectStanding(net *sidecartest.AdmissionNet, name string, sidecarId sidecar.Id, want sidecar.DirectoryStanding) error {
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		standing, err := sidecar.NewDirectoryAuthView(state).SignerStanding(sidecarId, state.Pin())
		if err != nil || standing != want {
			return fmt.Errorf("%s's standing in the directory: %s, %v, want %s", name, standing, err, want)
		}
		return nil
	})
	return nil
}

// FS-19's team (M6-out; §8.6's ceiling, D-ACL-19, D-ACL-24, I-EVS-14); see the file header.
func Fs19Team(net *Net) *Schedule {
	world := newAclM6World()
	return world.schedule("FS-19 team",
		world.start(func(net *sidecartest.AdmissionNet) error {
			mFirst, adminFirst := world.devices["m first"], world.devices["admin first"]
			world.ids["notes"] = aclCreateRepo(net, mFirst, "notes", protocol.RepoKind_REPO_KIND_GENERAL).Bytes()
			world.ids["m vault"] = aclCreateRepo(net, mFirst, "m vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			world.ids["admin vault"] = aclCreateRepo(net, adminFirst, "admin vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			world.admitEphemeral(net, mFirst, "m burner")
			world.admitEphemeral(net, adminFirst, "admin burner")
			// a device of m the Owner admitted: parked for m's consent (KF2)
			tablet := net.Device("m tablet", mFirst.MemberId)
			net.AdmitDevice(net.Owner(), tablet, 0)
			world.devices["m tablet"] = tablet
			net.Fold(true)
			return nil
		}),
		world.do("ephemerals", func(net *sidecartest.AdmissionNet) error {
			if err := fs19M6ExpectDirectory(net, world); err != nil {
				return err
			}
			notes, mVault, adminVault := sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["m vault"]), sidecar.Id(world.ids["admin vault"])
			// the ceiling beside the directory: the config's read, its member's vault's deposit, nothing else, under
			// the Admin as under the Member, whose devices write the config
			for name, ownVault := range map[string]sidecar.Id{"m burner": mVault, "admin burner": adminVault} {
				burner := world.devices[name]
				otherVault := mVault
				if ownVault == mVault {
					otherVault = adminVault
				}
				if err := fs19M4ExpectRights(net, burner.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
					net.ConfigRepoId(): sidecar.AclEvsRead,
					notes:              0,
					ownVault:           sidecar.AclEvsDeposit,
					otherVault:         0,
				}); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if err := aclM6ExpectStanding(net, name, burner.SidecarId, sidecar.DirectoryStandingStanding); err != nil {
					return err
				}
				net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
					if state.IsConfigWriter(burner.SidecarId) || acl.Consented(burner.SidecarId) || acl.ApprovalCapable(burner.SidecarId) {
						return fmt.Errorf("%s writes the config, is consented or approves", name)
					}
					return nil
				})
			}
			return nil
		}),
		world.do("server", func(net *sidecartest.AdmissionNet) error {
			directory := sidecar.Id(world.ids["directory"])
			owner, burner := world.devices["owner first"], world.devices["m burner"]
			// the directory takes no RepoGrant, RepoRevoke or RepoAdmin add, from its admins or anyone, so no statement
			// adds or removes a reader; on T2 a malicious api lands each anyway and every reader refuses it there
			statements := [][]byte{
				aclRepoGrant(net, owner, directory, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER),
				aclRepoRevoke(net, owner, directory, burner.SidecarId),
				net.Sign(owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
					Header: net.Header(), RepoId: directory.Bytes(), SidecarId: world.devices["m first"].SidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
				}),
			}
			for i, statement := range statements {
				net.MustRefuse(statement, sidecar.ErrConfigRule)
				if net.ForgedAppends() {
					pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, statement)
					if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigRule) {
						return fmt.Errorf("the forged directory statement %d at %d: %v", i, pin.GetVersion(), verdict.Refusal)
					}
				}
			}
			return fs19M6ExpectDirectory(net, world)
		}),
		world.do("ownerFirst", func(net *sidecartest.AdmissionNet) error {
			// no document adds or removes a reader: one that opens everything, then one that opens nothing
			for _, policy := range []string{fs19M6WidePolicy, fs19M6NarrowPolicy} {
				if plan, _ := net.SaveAclPolicy([]byte(policy), nil); !plan.Rows.GetHasDocument() {
					return errors.New("the saved head has no document")
				}
				if err := fs19M6ExpectDirectory(net, world); err != nil {
					return err
				}
			}
			return nil
		}),
		world.do("mFirst", func(net *sidecartest.AdmissionNet) error {
			mFirst, tablet := world.devices["m first"], world.devices["m tablet"]
			// the device KF2 parks for consent reads the directory as every admitted sidecar does, and writes nothing
			// that counts until m's consented device confirms it (I-EVS-14)
			if err := aclM6ExpectStanding(net, "m tablet", tablet.SidecarId, sidecar.DirectoryStandingUnconsented); err != nil {
				return err
			}
			if err := aclM6ExpectStanding(net, "m first", mFirst.SidecarId, sidecar.DirectoryStandingStanding); err != nil {
				return err
			}
			net.MustLand(net.Sign(mFirst, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)))
			if err := aclM6ExpectStanding(net, "m tablet", tablet.SidecarId, sidecar.DirectoryStandingStanding); err != nil {
				return err
			}
			net.Fold(true)
			if err := aclM6ExpectStanding(net, "m tablet", tablet.SidecarId, sidecar.DirectoryStandingStanding); err != nil {
				return err
			}
			return fs19M6ExpectDirectory(net, world)
		}),
	)
}

// Fails unless, at every reader, exactly the devices named among candidates are consented for the member (§8.5's
// consented(d, M); D-ACL-22).
func aclM6ExpectConsented(net *sidecartest.AdmissionNet, memberId sidecar.Id, candidates map[string]*sidecartest.AdmissionDevice, consented ...string) error {
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for name, device := range candidates {
			if device.MemberId != memberId {
				continue
			}
			want := slices.Contains(consented, name)
			if got := acl.ConsentedFor(device.SidecarId, memberId); got != want || acl.Consented(device.SidecarId) != want {
				return fmt.Errorf("%s consented %t, want %t", name, got, want)
			}
		}
		return nil
	})
	return nil
}

// FS-19's invite (M6-out; D-ACL-22, §7.5's member invite): the Owner's device admits member n and makes its invite.
// An ephemeral enrollment does not redeem it: the invitee's side makes no join MAC for one and the inviting device
// verifies none; an ephemeral sidecar and a read_only one, each admitted under n with the invited bit anyway, are
// consented at no reader, so neither creates n's vault. n's next untagged device from the invite is consented by it at
// every reader, across a base too, and creates the vault; a later device carrying the bit is not.
func Fs19Invite(net *Net) *Schedule {
	world := newAclM6World()
	invited := uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
	vaultCreate := func(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice) []byte {
		return net.Sign(signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: net.Header(), RepoId: net.Id("repo n vault").Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT,
		})
	}
	return world.schedule("FS-19 invite",
		world.start(nil),
		world.do("ownerFirst", func(net *sidecartest.AdmissionNet) error {
			owner := world.devices["owner first"]
			memberId := net.AdmitMember(owner, "n", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			world.ids["n"] = memberId.Bytes()
			genesis := net.GenesisChain()
			fragment, err := sidecar.NewMemberInviteFragment(genesis[:], net.Tip(), owner.SidecarId, owner.PublicKey())
			if err != nil {
				return err
			}
			defer fragment.Erase()
			inviteId := net.Id("n's invite")
			joinOf := func(device *sidecartest.AdmissionDevice, ephemeral bool, readOnly bool) *sidecar.MemberInviteJoin {
				return &sidecar.MemberInviteJoin{
					NetworkId:         net.NetworkId(),
					InviteId:          inviteId,
					SidecarId:         device.SidecarId,
					IdentityPublicKey: device.PublicKey(),
					MemberId:          memberId,
					Ephemeral:         ephemeral,
					ReadOnly:          readOnly,
				}
			}
			burner, worker, laptop := net.Device("n burner", memberId), net.Device("n page worker", memberId), net.Device("n laptop", memberId)
			world.devices["n burner"], world.devices["n page worker"], world.devices["n laptop"] = burner, worker, laptop
			for name, join := range map[string]*sidecar.MemberInviteJoin{"an ephemeral": joinOf(burner, true, false), "a read_only": joinOf(worker, false, true)} {
				if _, err := fragment.JoinMac(join); !errors.Is(err, sidecar.ErrMemberInviteJoinEphemeral) {
					return fmt.Errorf("%s join's MAC: %v", name, err)
				}
				// the inviting device refuses it whatever MAC rides it, the untagged join's own included
				mac, err := fragment.JoinMac(joinOf(laptop, false, false))
				if err != nil {
					return err
				}
				if err := sidecar.VerifyMemberInviteJoin(fragment, join, mac); !errors.Is(err, sidecar.ErrMemberInviteJoinEphemeral) {
					return fmt.Errorf("the inviting device took %s join: %v", name, err)
				}
			}
			// admitted with the invited bit anyway, as an inviting device that skipped the check would: the log's
			// predicate consents neither
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), invited)))
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(worker, nil, false, 0, invited|uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))))
			if err := aclM6ExpectConsented(net, memberId, world.cast()); err != nil {
				return err
			}
			net.MustRefuse(vaultCreate(net, burner), sidecar.ErrConfigAuthority)
			net.MustRefuse(vaultCreate(net, worker), sidecar.ErrConfigReadOnly)
			// n's next untagged device redeems the invite
			mac, err := fragment.JoinMac(joinOf(laptop, false, false))
			if err != nil {
				return err
			}
			if err := sidecar.VerifyMemberInviteJoin(fragment, joinOf(laptop, false, false), mac); err != nil {
				return fmt.Errorf("the untagged join: %w", err)
			}
			net.AdmitDevice(owner, laptop, invited)
			return aclM6ExpectConsented(net, memberId, world.cast(), "n laptop")
		}),
		world.do("nLaptop", func(net *sidecartest.AdmissionNet) error {
			owner, laptop, memberId := world.devices["owner first"], world.devices["n laptop"], sidecar.Id(world.ids["n"])
			net.MustLand(vaultCreate(net, laptop))
			// the invite consents one device: a later one carrying the bit waits for n's own confirmation
			phone := net.Device("n phone", memberId)
			world.devices["n phone"] = phone
			net.AdmitDevice(owner, phone, invited)
			if err := aclM6ExpectConsented(net, memberId, world.cast(), "n laptop"); err != nil {
				return err
			}
			net.Fold(true)
			if err := aclM6ExpectConsented(net, memberId, world.cast(), "n laptop"); err != nil {
				return err
			}
			net.MustLand(net.Sign(laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(phone)))
			return aclM6ExpectConsented(net, memberId, world.cast(), "n laptop", "n phone")
		}),
	)
}

// One Add or wrap S3b asks every reader about.
type aclM6MemberCheck struct {
	what   string
	repoId sidecar.Id
	device string
	// a leaf of a tree of two, or a ReaderWrap
	leaf  bool
	allow bool
	// the refusal's reason, 0 for any
	reason sidecar.AclReason
}

// Fails unless every reader judges each Add and wrap as its check says, at the tip's state and time (§10.9).
func aclM6ExpectMembers(net *sidecartest.AdmissionNet, world *aclM6World, checks []aclM6MemberCheck) error {
	now := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for _, check := range checks {
			member := sidecar.AclRepoMember{SidecarId: world.devices[check.device].SidecarId, Form: sidecar.AclRepoMemberWrap}
			if check.leaf {
				member.Form, member.LeafCount = sidecar.AclRepoMemberLeaf, 2
			}
			decision := acl.CheckRepoMember(check.repoId, member, now)
			if decision.Allowed != check.allow || (check.reason != 0 && decision.Reason != check.reason) {
				return fmt.Errorf("%s: allowed %t (%s), want %t", check.what, decision.Allowed, decision.Reason, check.allow)
			}
		}
		return nil
	})
	return nil
}

// S3b's acl checks (§22.7's S3, F3 in its member form; R-ACL-7, §10.9, §8.12, D-ACL-22): who a commit or a wrap may
// add once a member joins a Team whose document opens its general repos to member devices, judged by every reader on
// the state as the log built it. A member the Owner admitted has no device, so nothing is added for it; its ephemeral
// takes the directory's wrap and no leaf or wrap of a general repo; its first device from the invite takes leaves in
// the directory, the config and the general repo, and in its own vault once it creates it, never in another member's;
// a device an admin admits under it afterwards takes the general repo's leaf and no part of the member's vault until
// the member's OwnerConfirm; a sidecar of a member the log never admitted takes nothing, and on T2 a malicious api's
// MemberAdmit by a device that is no admin is refused at its position by every reader, so it adds no member.
func AclMemberAddsOnlyForReaders(net *Net) *Schedule {
	world := newAclM6World()
	invited := uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
	checks := func(net *sidecartest.AdmissionNet, laptop bool, vault bool, confirmed bool) []aclM6MemberCheck {
		notes, directory, mVault := sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["directory"]), sidecar.Id(world.ids["m vault"])
		unadmitted := sidecar.AclReason(0)
		if !laptop {
			unadmitted = sidecar.AclReasonUnadmitted
		}
		checks := []aclM6MemberCheck{
			{what: "the burner's directory wrap", repoId: directory, device: "n burner", allow: true},
			{what: "the burner's directory leaf", repoId: directory, device: "n burner", leaf: true},
			{what: "the burner's wrap in the general repo", repoId: notes, device: "n burner"},
			{what: "the burner's wrap in another member's vault", repoId: mVault, device: "n burner"},
			{what: "the laptop's leaf in the general repo", repoId: notes, device: "n laptop", leaf: true, allow: laptop, reason: unadmitted},
			{what: "the laptop's directory leaf", repoId: directory, device: "n laptop", leaf: true, allow: laptop, reason: unadmitted},
			{what: "the laptop's config leaf", repoId: net.ConfigRepoId(), device: "n laptop", leaf: true, allow: laptop, reason: unadmitted},
			{what: "the laptop's leaf in another member's vault", repoId: mVault, device: "n laptop", leaf: true},
			{what: "the laptop's wrap in another member's vault", repoId: mVault, device: "n laptop"},
			{what: "a ghost's wrap in the general repo", repoId: notes, device: "ghost", reason: sidecar.AclReasonUnadmitted},
			{what: "a ghost's directory wrap", repoId: directory, device: "ghost", reason: sidecar.AclReasonUnadmitted},
		}
		if vault {
			nVault := sidecar.Id(world.ids["n vault"])
			checks = append(checks,
				aclM6MemberCheck{what: "the laptop's leaf in its member's vault", repoId: nVault, device: "n laptop", leaf: true, allow: true},
				aclM6MemberCheck{what: "the tablet's leaf in the general repo", repoId: notes, device: "n tablet", leaf: true, allow: true},
				aclM6MemberCheck{what: "the tablet's leaf in its member's vault", repoId: nVault, device: "n tablet", leaf: true, allow: confirmed},
				aclM6MemberCheck{what: "another member's leaf in the vault", repoId: nVault, device: "m first", leaf: true},
				aclM6MemberCheck{what: "the Admin's wrap in the vault", repoId: nVault, device: "admin first"},
			)
		}
		return checks
	}
	return world.schedule("S3b's acl checks",
		world.start(func(net *sidecartest.AdmissionNet) error {
			mFirst := world.devices["m first"]
			if plan, _ := net.SaveAclPolicy([]byte(fs19M6WidePolicy), nil); !plan.Rows.GetHasDocument() {
				return errors.New("the saved head has no document")
			}
			world.ids["notes"] = aclCreateRepo(net, mFirst, "notes", protocol.RepoKind_REPO_KIND_GENERAL).Bytes()
			world.ids["m vault"] = aclCreateRepo(net, mFirst, "m vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			world.devices["ghost"] = net.Device("ghost", net.Id("member ghost"))
			return nil
		}),
		world.do("server", func(net *sidecartest.AdmissionNet) error {
			mFirst := world.devices["m first"]
			// a device that is no admin admits no member: api refuses, and on T2 a malicious api lands it, which every
			// reader refuses at its position
			admit := net.Sign(mFirst, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id("member ghost"), bridge.MemberRole_MEMBER_ROLE_MEMBER))
			net.MustRefuse(admit, sidecar.ErrConfigAuthority)
			if net.ForgedAppends() {
				pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, admit)
				if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigAuthority) {
					return fmt.Errorf("the forged MemberAdmit at %d: %v", pin.GetVersion(), verdict.Refusal)
				}
			}
			return nil
		}),
		world.do("ownerFirst", func(net *sidecartest.AdmissionNet) error {
			owner := world.devices["owner first"]
			memberId := net.AdmitMember(owner, "n", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			world.ids["n"] = memberId.Bytes()
			burner := net.Device("n burner", memberId)
			world.devices["n burner"] = burner
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			world.devices["n laptop"] = net.Device("n laptop", memberId)
			if err := aclM6ExpectMembers(net, world, checks(net, false, false, false)); err != nil {
				return err
			}
			net.AdmitDevice(owner, world.devices["n laptop"], invited)
			return aclM6ExpectMembers(net, world, checks(net, true, false, false))
		}),
		world.do("nLaptop", func(net *sidecartest.AdmissionNet) error {
			owner, laptop, memberId := world.devices["owner first"], world.devices["n laptop"], sidecar.Id(world.ids["n"])
			world.ids["n vault"] = aclCreateRepo(net, laptop, "n vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			tablet := net.Device("n tablet", memberId)
			world.devices["n tablet"] = tablet
			net.AdmitDevice(owner, tablet, 0)
			if err := aclM6ExpectMembers(net, world, checks(net, true, true, false)); err != nil {
				return err
			}
			net.MustLand(net.Sign(laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)))
			if err := aclM6ExpectMembers(net, world, checks(net, true, true, true)); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 48)
			return aclM6ExpectMembers(net, world, checks(net, true, true, true))
		}),
	)
}

// Fails unless, at every reader, removed holds no right and no scope on any of the repos, is a non-reader of each for
// the reason given, holds no key of any, and each repo's gate refuses a generation from before the removal and takes
// one at it.
func aclM6ExpectRemoved(net *sidecartest.AdmissionNet, world *aclM6World, removed *sidecartest.AdmissionDevice, reason sidecar.AclReason, repoIds ...sidecar.Id) error {
	now := net.Clock().Now()
	before := &bridge.AuthPin{Version: world.positions["before"], Chain: world.signed["before"]}
	revoke := &bridge.AuthPin{Version: world.positions["revoke"], Chain: world.signed["revoke"]}
	standing := world.devices["m first"].SidecarId
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for _, repoId := range repoIds {
			scopes := []string{aclScope(repoId, "r"), aclScope(repoId, "rw"), aclScope(repoId, "admin"), aclScope(repoId, "deposit")}
			for _, audience := range []sidecar.AclTokenAudience{sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm} {
				if rights := aclRights(net, acl, removed.SidecarId, repoId, audience); rights != 0 {
					return fmt.Errorf("%s keeps rights %04b on %s", removed.Name, rights, repoId)
				}
				if err := aclExpectScopes(net, state, removed.SidecarId, audience, scopes, []string{}); err != nil {
					return fmt.Errorf("%s's: %w", removed.Name, err)
				}
			}
			nonReaders := acl.NonReaders(repoId, []sidecar.Id{removed.SidecarId, standing}, now)
			if len(nonReaders) != 1 || nonReaders[0].SidecarId != removed.SidecarId || nonReaders[0].Reason != reason {
				return fmt.Errorf("%s's non-readers %+v, want %s for %s", repoId, nonReaders, reason, removed.Name)
			}
			if err := aclExpectHolder(state, repoId, now, removed.SidecarId, false, sidecar.GkmHolderLeaf, sidecar.GkmHolderAgent); err != nil {
				return err
			}
			if shrunkAt := state.ShrunkAt(repoId); shrunkAt < revoke.GetVersion() {
				return fmt.Errorf("%s's holders_shrunk_at %d, below the removal's %d", repoId, shrunkAt, revoke.GetVersion())
			}
			if err := sidecar.GkmGateCheck(state, repoId, before, now, now); !errors.Is(err, sidecar.ErrGkmGateClosed) {
				return fmt.Errorf("%s: a generation from before the removal: %v", repoId, err)
			}
			if err := sidecar.GkmGateCheck(state, repoId, revoke, now, now); err != nil {
				return fmt.Errorf("%s: a generation at the removal: %w", repoId, err)
			}
		}
		return nil
	})
	return nil
}

// S4b's acl checks (§22.7's S4, F9 in its member form; I-15, D-ACL-21, §7.9's shrink row): member n, whose devices
// read a Team's general repo, its directory and its config, is removed by the Owner's MemberRevoke. At every reader
// each of n's devices and its ephemeral loses every right and scope at once, in the directory and the config too,
// which no document gave, is named a non-reader, leaves each repo's key holders, and stops signing in the directory,
// its cards masked; each repo's gate refuses a write under a generation from before the removal. Another member's
// devices keep theirs.
func AclMemberRemovalDropsEveryRight(net *Net) *Schedule {
	world := newAclM6World()
	return world.schedule("S4b's acl checks",
		world.start(func(net *sidecartest.AdmissionNet) error {
			owner, mFirst := world.devices["owner first"], world.devices["m first"]
			if plan, _ := net.SaveAclPolicy([]byte(fs19M6WidePolicy), nil); !plan.Rows.GetHasDocument() {
				return errors.New("the saved head has no document")
			}
			world.ids["notes"] = aclCreateRepo(net, mFirst, "notes", protocol.RepoKind_REPO_KIND_GENERAL).Bytes()
			memberId := net.AdmitMember(owner, "n", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			world.ids["n"] = memberId.Bytes()
			laptop := net.Device("n laptop", memberId)
			net.AdmitDevice(owner, laptop, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
			phone := net.Device("n phone", memberId)
			net.AdmitDevice(laptop, phone, 0)
			world.devices["n laptop"], world.devices["n phone"] = laptop, phone
			world.admitEphemeral(net, laptop, "n burner")
			net.Fold(true)
			notes := sidecar.Id(world.ids["notes"])
			for _, name := range []string{"n laptop", "n phone"} {
				if err := aclM6ExpectAccess(net, name, world.devices[name].SidecarId, notes, sidecar.AclEvsRead|sidecar.AclEvsWrite|sidecar.AclEvsAdmin|sidecar.AclEvsDeposit); err != nil {
					return err
				}
			}
			return nil
		}),
		world.do("ownerFirst", func(net *sidecartest.AdmissionNet) error {
			owner, memberId := world.devices["owner first"], sidecar.Id(world.ids["n"])
			notes, directory := sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["directory"])
			before := net.Tip()
			world.positions["before"], world.signed["before"] = before.GetVersion(), before.GetChain()
			verdict := net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(memberId)))
			world.positions["revoke"], world.signed["revoke"] = verdict.Pin.GetVersion(), verdict.Pin.GetChain()
			for _, name := range []string{"n laptop", "n phone", "n burner"} {
				removed := world.devices[name]
				repoIds := []sidecar.Id{directory, net.ConfigRepoId()}
				if name != "n burner" {
					repoIds = append(repoIds, notes)
				}
				// a removed member's sidecars stand as ones the state never admitted
				if err := aclM6ExpectRemoved(net, world, removed, sidecar.AclReasonUnadmitted, repoIds...); err != nil {
					return err
				}
				net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
					view := sidecar.NewDirectoryAuthView(state)
					standing, err := view.SignerStanding(removed.SidecarId, state.Pin())
					if err != nil || standing == sidecar.DirectoryStandingStanding {
						return fmt.Errorf("%s's standing in the directory: %s, %v", name, standing, err)
					}
					if !view.Masked(removed.SidecarId) {
						return fmt.Errorf("%s's cards are not masked", name)
					}
					return nil
				})
			}
			// another member's device keeps its rights
			mFirst := world.devices["m first"]
			if err := aclM6ExpectAccess(net, "m first", mFirst.SidecarId, directory, sidecar.AclEvsRead|sidecar.AclEvsWrite); err != nil {
				return err
			}
			return aclM6ExpectStanding(net, "m first", mFirst.SidecarId, sidecar.DirectoryStandingStanding)
		}),
	)
}

var Fs21TeamCase = Register("FS-21", "team", []Tier{TierT3}, Fs21Team)

// Team's starting document with one more grant, source dialing destination: the second document of FS-21's team. It
// carries no tests, since the starting document's own deny a member's dial of another member's device, which this
// grant is.
func fs21TeamDialPolicy(source sidecar.Id, destination sidecar.Id) []byte {
	return []byte(fmt.Sprintf(`{
	"tagOwners": { "tag:recurd": ["autogroup:member"] },
	"grants": [
		{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] },
		{ "src": ["tag:recurd"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
		{ "src": ["sidecar:%s"], "dst": ["sidecar:%s"], "allow": ["dial"] },
	],
	"requests": [
		{ "src": ["autogroup:member", "autogroup:tagged"],
		  "dst": ["autogroup:member", "autogroup:tagged", "sock:*"], "allow": ["dial"],
		  "approver": ["autogroup:dst-owner"], "evidence": ["device", "presence"], "maxExpiry": "30d" },
	],
}`, source, destination))
}

// The Team case's world: w, x, r and d each the first device of a member of its own, admitted by the Owner's laptop
// from that member's invite, r's member an Admin; Team's starting document, under which a member's devices reach each
// other and no other member's; and one group that holds another member's devices, as a Team's repos do.
func fs21Team() *fs21Scenario {
	members := map[string]sidecar.Id{}
	sharedGroup := sha256Sum([]byte("fs21 a shared group"))
	return &fs21Scenario{
		id: "FS-21 team",
		member: func(admission *sidecartest.AdmissionNet, name string) sidecar.Id {
			memberId, found := members[name]
			if !found {
				memberId = admission.AdmitMember(admission.Owner(), "fs21 member "+name, bridge.MemberRole_MEMBER_ROLE_MEMBER)
				members[name] = memberId
			}
			return memberId
		},
		capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED),
		cast: func(admission *sidecartest.AdmissionNet, world *fs21World) error {
			owner := admission.Owner()
			// an Admin's device reaches no more than a Member's under the starting document
			admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET,
				admission.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{members["r"]}, 0)))
			for name, device := range world.devices {
				if !admission.Consented(device.identity, members[name]) {
					return fmt.Errorf("%s is not its member's consented device", name)
				}
			}
			// the compile expands the document's autogroups over the folded members
			admission.Fold(true)
			return nil
		},
		policy:        sidecar.AclTeamStartDocument,
		dialPolicy:    fs21TeamDialPolicy,
		sharedGroupId: sidecar.Id(sharedGroup[:16]),
	}
}

// FS-21's team (M6-out; §2, §6; D-PROTO-18, D-TRUST-10, I-10; FI-10): fs21.go's schedule on a Team whose document is
// the starting one, its devices four members' own, every client on server's exchange under server's contract gate and
// every receiver PROTO-M4-03's. The default document gives the members' devices no reach to each other, so the gate
// gives each pair of them the witness exception's control contract: HeadCheck passes and counts, and a data RPC, a
// stream and IP on it are refused. The server partitions its relays, r off the exchange: w and x still witness each
// other; r alarms unwitnessed at 24 h, and at witness_bound_hours stops sealing in the group it shares with another
// member's devices while it still seals in its own, and w, witnessed, seals in both; relayed again, r witnesses and
// seals. A second document lets w dial d, and w's contract to d is data.
func Fs21Team(net *Net) *Schedule {
	return Fs21TeamWith(nil)(net)
}

// FS-21's team on settings, nil for the defaults.
func Fs21TeamWith(settings *Fs21Settings) Builder {
	return fs21Builder(settings, fs21Team)
}
