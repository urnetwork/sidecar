//go:build !ios_extension

// §16.11's access requests (RECORD-M6-18; D-MCP-30, R-MCP-17, FS-85): a member, an agent or a tagged sidecar asks for
// access to a repo, a worker or a socket by a request entry in its own directory stream and a notice under the
// target's q/ prefix, which the target's approvers, computed by every reader from its own state, decide
// (directory_decide.go).
//
//	file      the requester's daemon holds the request to its form, its target to open, its subject to its own, and
//	          its counts under §20.4's limits (directory_limits.go); an agent's or a tagged sidecar's request then
//	          needs the member's endorsement through §5.4's gate before anything is filed (the endorse row: harness
//	          evidence only in an untainted run); then it appends the request entry and writes the pending notice. A
//	          notice that did not land is the repair's to write (directory_notice.go)
//	subject   a person's own request names the member, an agent's or a tagged sidecar's the requesting sidecar, a
//	          member only when the endorsing person widens it; reach always names the spending sidecar
//	targets   a repo by its id, announced or private, never one whose item closed its requests; a worker by its
//	          announced item, never a closed one, asking only ports it announces (FI-26), its announced bridge ports
//	          when it names none; a socket by its name token
//	reach     a worker's or a socket's request carries §16.8's ApprovalRequest, whose CanonicalAction is the version-3
//	          access_request (DirectoryAccessAction): the clear fields name the worker alone and its ports ride
//	          sealed_detail (QD-740), sealed by the device's sealer, without which no reach request is filed
//	read      every reader folds request and decision entries and the notices it accepts into one state a request:
//	          pending, approved, denied, cancelled or expired. Past not_after a pending request is expired, with no
//	          entry written, and never shown as denied. A request past its requester's limits is ignored with an
//	          over_limit alarm, a target shows its older pending requests first up to directory_target_pending, and
//	          with limits that cannot be read no other sidecar's request is shown
//
// The endorsement, the limits, the sealer and the events are seams a daemon binds (DirectoryRequestsBinding); unbound,
// filing refuses. Barriers: directory.request.before and .after around the request entry's append, keyed by the
// request's id. Safe for concurrent use. Locks: writeLock, then stateLock, which is never held across a call out.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The client's part.
const directoryRequestsPartName = "requests"

var (
	// The request's target is not one a request reaches: no live repo of that id, a worker that announces no item or
	// not the ports asked, or a target of no kind.
	ErrDirectoryRequestTarget = errors.New("directory request target not found")
	// The target's item closed its requests (§16.11's what.requests): FAILED_PRECONDITION to a tool.
	ErrDirectoryRequestsClosed = errors.New("directory target takes no requests")
	// An agent's or a tagged sidecar's request with no endorsement: none is bound here, or it answered a channel its
	// run may not use. Nothing was filed.
	ErrDirectoryRequestUnendorsed = errors.New("directory request not endorsed")
	// A reach request where nothing seals its action's detail: nothing was filed.
	ErrDirectoryRequestUnsealed = errors.New("directory reach request cannot be sealed here")
	// No request of that id stands in this copy.
	ErrDirectoryRequestUnknown = errors.New("directory request not found")
)

// A request's state in a reader's view.
type DirectoryRequestState string

const (
	DirectoryRequestPending   DirectoryRequestState = "pending"
	DirectoryRequestApproved  DirectoryRequestState = "approved"
	DirectoryRequestDenied    DirectoryRequestState = "denied"
	DirectoryRequestCancelled DirectoryRequestState = "cancelled"
	// Past not_after with no decision: never shown as denied.
	DirectoryRequestExpired DirectoryRequestState = "expired"
)

// SHA-256 of an entry's Signed header as stored: what DirectoryDecision.request_entry_sha256 and
// DecisionRef.header_sha256 name.
func DirectoryEntryHeaderSha256(signedBytes []byte) [sha256.Size]byte {
	return sha256.Sum256(signedBytes)
}

// One decision entry binding a request, as a reader verified it.
type DirectoryDecisionView struct {
	DeciderSidecarId Id
	EntryId          Id
	Seq              uint64
	HeaderSha256     [sha256.Size]byte
	Decision         *protocol.DirectoryDecision
	Stored           *StoredDirectoryDecision
	// The pin its push declared, where its decider's standing is judged, and evs's time for that push.
	PushPin        *bridge.AuthPin
	PushTimeMillis int64
	// Whether its decider was eligible for the target at PushPin; false too while that state cannot be asked.
	Eligible bool
}

// One request as this reader shows it. Its prose, Request.reason, is the requester's words: untrusted text.
type DirectoryRequestView struct {
	RequestId          Id
	RequesterSidecarId Id
	Request            *protocol.DirectoryRequest
	Stored             *StoredDirectoryRequest
	TargetKind         DirectoryTargetKind
	EntryId            Id
	EntrySeq           uint64
	EntrySha256        [sha256.Size]byte
	PushPin            *bridge.AuthPin
	PushTimeMillis     int64
	// The filing run, nil for a person's own request.
	RunId *Id
	State DirectoryRequestState
	// q/<h>/<tgt>/<rid>.
	NoticePath string
	// The notice version this reader accepted, nil for none, and the path's version it is.
	Notice        *protocol.DirectoryNotice
	NoticeVersion uint64
	// Every decision entry that binds this request, in push order.
	Decisions []*DirectoryDecisionView
	// This sidecar filed it.
	Mine bool
	// This device decides it now: pending, and this sidecar eligible for its target at the state now.
	Decidable bool
	// Past one of its requester's limits: ignored by this reader, with an over_limit alarm.
	OverLimit bool
	// Pending behind directory_target_pending older requests to its target: shown once they clear.
	Deferred bool

	// the newest file the path holds, taken or not, nil for none
	noticeFile *DirectoryCardFile
	// the requester's own cancel entry, nil for none
	cancelEntry *DirectoryDecisionView
}

// What a filer asks.
type DirectoryRequestAsk struct {
	Target *protocol.RequestTarget
	// A repo's RepoGrantRole, 1 deposit, 2 reader, 3 writer; a worker's or a socket's AclAction dial.
	Role uint32
	// The grant's expiry asked, 0 for the approver's default.
	GrantExpiresMillis int64
	// The request's own life, 0 for RequestExpiry; at most RequestMaxExpiry.
	NotAfter time.Duration
	// Prose, at most 512 B.
	Reason string
	// The announcement the requester acted on, if any.
	AnnouncementId *Id
	// A person's own act on /dev/tty or in an app, or an agent's through a tool. A tagged sidecar's is always its
	// own kind, whatever this says.
	FiledBy DirectoryFiledBy
	// The filing run and its agent, nil for a person's.
	RunId   *Id
	AgentId *Id
	// The filing run's taint.
	Tainted bool
	// A repo request for the member rather than this sidecar: a person's own always is; an agent's is only when the
	// endorsing person widens it.
	ForMember bool
	// The request's id when a filing waits on its endorsement and is asked again; nil draws one.
	RequestId *Id
	// The endorsement's decision when the caller holds it, nil to ask the gate.
	Decision *bridge.Signed
}

// What Request answers once the entry is appended.
type DirectoryRequestFiled struct {
	RequestId       Id
	Subject         Id
	SubjectIsMember bool
	NotAfterMillis  int64
	NoticePath      string
	// The request entry's seq in this sidecar's stream, 0 while the entry waits in the spool.
	EntrySeq uint64
	// Whether the pending notice landed; when not, the repair writes it at a later sync.
	NoticeWritten bool
	// The endorsement's channel, unspecified for a person's own request.
	Channel protocol.ApprovalChannel
}

// What an endorsement is asked for.
type DirectoryEndorsement struct {
	RequestId Id
	// The version-3 access_request the member endorses, as stored.
	Action  *StoredCanonicalAction
	RunId   *Id
	AgentId *Id
	Tainted bool
	FiledBy DirectoryFiledBy
	// The decision the caller holds, nil for none.
	Decision *bridge.Signed
}

// What the member's endorsement came to.
type DirectoryEndorsed struct {
	// device, presence, or harness under harness_ok.
	Channel protocol.ApprovalChannel
	// SHA-256 of that ApprovalDecision, which the member's vault or the sponsor's keeps.
	DecisionSha256 []byte
	// The endorsing person widened an agent's repo request to the member.
	ForMember bool
}

// §5.4's gate for a request (the endorse row): nil with the endorsement once the member decided, *ApprovalPendingError
// while the decision is awaited, any other error a refusal.
type DirectoryEndorser func(ctx context.Context, endorsement *DirectoryEndorsement) (*DirectoryEndorsed, error)

// §5.4's events for requests, which *Sidecar raises.
type DirectoryRequestEvents interface {
	RaiseAccessRequest(requestId Id) error
	RaiseAccessDecided(requestId Id, outcome string) error
}

// What a daemon binds a client's requests to. A nil field leaves that seam unbound, which refuses what needs it.
type DirectoryRequestsBinding struct {
	// GET /sidecar/limits (QuotaLimits); unbound, no request is filed and no other sidecar's is shown.
	Limits func(ctx context.Context) (*QuotaLimits, error)
	// The endorsement; unbound, only a person's own request is filed.
	Endorse DirectoryEndorser
	// Seals a reach action's detail (Sidecar.SealActionDetail); unbound, no worker request is filed.
	Sealer CanonicalActionDetailSealer
	Events DirectoryRequestEvents
	// Pushes what this sidecar's record holds (SidecarRecord.Flush), so an entry lands before its notice names it;
	// unbound, the record's own schedule pushes it.
	Land func(ctx context.Context) error
	// Signs and files a repo approval's statement and signs a reach approval's decision (RECORD-M6-19); unbound, no
	// approval is decided, and a denial still is.
	Statements DirectoryStatements
	// The decider's journal over the approval ledger; unbound, nothing is decided.
	Journal *ApprovalLedger
	// What a requester does with an approval: the statement's check, the spend and the vault's record; unbound, no
	// approval is taken.
	Receipts DirectoryReceipts
	// Opens a reach action's sealed detail (Sidecar.OpenActionDetail), for an approver's check of a worker's services;
	// unbound, no worker request that seals one is approved.
	Opener   CanonicalActionDetailOpener
	Settings *DirectoryRequestSettings
	Random   io.Reader
}

// A request this process filed, counted toward its limits until a sync reads its entry back.
type directoryRequestFiling struct {
	requestId  Id
	runId      *Id
	timeMillis int64
	notAfter   int64
}

// The requests of one network's team directory, as this sidecar files, reads and decides them.
type DirectoryAccessRequests struct {
	client *DirectoryClient

	// one filing, repair, decision or receipt at a time
	writeLock sync.Mutex

	stateLock sync.Mutex
	binding   *DirectoryRequestsBinding
	// path -> the notice version last accepted
	accepted map[string]*directoryNoticeAccepted
	// path -> the version a path_rule alarm was raised for
	breached map[string]uint64
	// requests an alarm or an event was raised for, by its kind
	raised map[string]bool
	// prefix or path -> its lease's release
	leases map[string]func()
	filed  []*directoryRequestFiling
	closed bool
}

// This client's requests, made unbound at the first ask: BindRequests binds their seams.
func (self *DirectoryClient) Requests() *DirectoryAccessRequests {
	made := false
	requests := self.part(directoryRequestsPartName, func() any {
		made = true
		return &DirectoryAccessRequests{
			client:   self,
			binding:  &DirectoryRequestsBinding{},
			accepted: map[string]*directoryNoticeAccepted{},
			breached: map[string]uint64{},
			raised:   map[string]bool{},
			leases:   map[string]func(){},
		}
	}).(*DirectoryAccessRequests)
	if made && !self.readOnly {
		self.addSyncHook(func(ctx context.Context) {
			if err := requests.Maintain(ctx); err != nil && !errors.Is(err, ErrDirectoryNone) {
				self.log.Infof("[directory]requests: %s", err)
			}
		})
	}
	return requests
}

// Binds the requests' seams, replacing what was bound: what a daemon's composition calls once.
func (self *DirectoryClient) BindRequests(binding *DirectoryRequestsBinding) *DirectoryAccessRequests {
	requests := self.Requests()
	if binding != nil {
		copied := *binding
		requests.stateLock.Lock()
		defer requests.stateLock.Unlock()
		requests.binding = &copied
	}
	return requests
}

// Files a request: see the file's header. Answers once the request entry is appended; ErrDirectoryReadOnly on a
// read_only client, ErrDirectoryNone without a directory, a *DirectoryLimitError past a limit,
// ErrDirectoryRequestsClosed for a closed target and *ApprovalPendingError while an endorsement is awaited.
func (self *DirectoryClient) Request(ctx context.Context, ask *DirectoryRequestAsk) (*DirectoryRequestFiled, error) {
	return self.Requests().File(ctx, ask)
}

// The requests filter keeps, the older first: this sidecar's own in any state, and others' that stand under their
// limits. ErrDirectoryLimitsUnavailable, with this sidecar's own alone, when the limits cannot be read and the filter
// asks for others'.
func (self *DirectoryClient) GetRequests(ctx context.Context, filter *DirectoryRequestFilter) ([]*DirectoryRequestView, error) {
	return self.Requests().List(ctx, filter)
}

// The seams bound now.
func (self *DirectoryAccessRequests) bound() *DirectoryRequestsBinding {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.binding
}

// The settings bound, the defaults for none.
func (self *DirectoryAccessRequests) settings() *DirectoryRequestSettings {
	if settings := self.bound().Settings; settings != nil {
		return settings
	}
	return DefaultDirectoryRequestSettings()
}

// 16 random bytes as an id.
func (self *DirectoryAccessRequests) newId() (Id, error) {
	random := self.bound().Random
	if random == nil {
		random = cryptorand.Reader
	}
	var id Id
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return Id{}, fmt.Errorf("directory request: an id: %w", err)
	}
	return id, nil
}

// Whether something was raised for key before; marks it raised.
func (self *DirectoryAccessRequests) raiseOnce(key string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.raised[key] {
		return false
	}
	self.raised[key] = true
	return true
}

// Releases the leases and stops every write after.
func (self *DirectoryAccessRequests) Close() {
	releases := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		releases := []func(){}
		for prefix, release := range self.leases {
			releases = append(releases, release)
			delete(self.leases, prefix)
		}
		return releases
	}()
	for _, release := range releases {
		release()
	}
}

// What an access request asks for, before its action is built.
type DirectoryAccess struct {
	Target *protocol.RequestTarget
	// The spending sidecar, or a repo's member.
	Subject Id
	// A repo's RepoGrantRole, or dial.
	Role uint32
	// 0 for the approver's default.
	ExpiresMillis int64
	// A worker's ports asked, each once.
	Ports []uint32
}

// The grant_dst entry of an id.
func directoryGrantDst(kind string, id []byte) string {
	return kind + ":" + hex.EncodeToString(id)
}

// §8.4's actions a repo role asks.
func directoryRoleAllow(role uint32) ([]string, bool) {
	switch protocol.RepoGrantRole(role) {
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT:
		return []string{"deposit"}, true
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_READER:
		return []string{"read"}, true
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER:
		return []string{"read", "write"}, true
	}
	return nil, false
}

// The version-3 access_request action of access (§16.11's endorse row; §16.8's version comment; QD-740), in fields 8,
// 10, 11, 14, 26 and 29, and what its sealed_detail holds, nil for none: a repo by evs:<repo_id> and its role's
// actions; a worker by sidecar:<id> and dial, its ports and their sidecar:<id>:tcp:<port> entries in the detail alone,
// so no server reads a port; a socket by sock:<its name token in hex> and dial. The caller builds the stored action
// with NewCanonicalAction, or seals the detail beside these final fields (CanonicalActionDetailSealer).
func DirectoryAccessAction(access *DirectoryAccess) (*protocol.CanonicalAction, *protocol.CanonicalActionDetail, error) {
	if access == nil {
		return nil, nil, directoryRefusal("no access asked")
	}
	targetKind, err := DirectoryRequestTargetKind(access.Target)
	if err != nil {
		return nil, nil, err
	}
	if !DirectoryRequestRoleAllowed(access.Target, access.Role) || access.ExpiresMillis < 0 {
		return nil, nil, directoryRefusal("role %d or expiry %d for this target", access.Role, access.ExpiresMillis)
	}
	action := &protocol.CanonicalAction{
		Kind:          uint32(SidecarActionAccessRequest),
		Version:       sidecarAccessRequestVersion,
		ExpiresMillis: access.ExpiresMillis,
		Subject:       access.Subject.Bytes(),
	}
	switch targetKind {
	case DirectoryTargetKindRepo:
		allow, ok := directoryRoleAllow(access.Role)
		if !ok {
			return nil, nil, directoryRefusal("role %d for a repo", access.Role)
		}
		action.RepoId = bytes.Clone(access.Target.GetRepoId())
		action.GrantDst = []string{directoryGrantDst("evs", access.Target.GetRepoId())}
		action.GrantAllow = allow
		return action, nil, nil
	case DirectoryTargetKindWorker:
		worker := directoryGrantDst("sidecar", access.Target.GetSidecarId())
		action.TargetSidecarId = bytes.Clone(access.Target.GetSidecarId())
		action.GrantDst = []string{worker}
		action.GrantAllow = []string{"dial"}
		if len(access.Ports) == 0 {
			return nil, nil, directoryRefusal("a worker request naming no port")
		}
		ports := slices.Clone(access.Ports)
		slices.Sort(ports)
		detail := &protocol.CanonicalActionDetail{}
		for _, port := range slices.Compact(ports) {
			if port == 0 || 65535 < port {
				return nil, nil, directoryRefusal("port %d", port)
			}
			detail.GrantDst = append(detail.GrantDst, fmt.Sprintf("%s:tcp:%d", worker, port))
		}
		if len(detail.GrantDst) == 1 {
			detail.TargetPort = ports[0]
		}
		return action, detail, nil
	default:
		action.GrantDst = []string{directoryGrantDst("sock", access.Target.GetSocketToken())}
		action.GrantAllow = []string{"dial"}
		return action, nil, nil
	}
}

// The stored action of access: built by NewCanonicalAction, or sealed by the bound sealer when it carries a detail.
func (self *DirectoryAccessRequests) storedAccessAction(ctx context.Context, access *DirectoryAccess) (*StoredCanonicalAction, error) {
	action, detail, err := DirectoryAccessAction(access)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return NewCanonicalAction(action)
	}
	sealer := self.bound().Sealer
	if sealer == nil {
		return nil, ErrDirectoryRequestUnsealed
	}
	return sealer.SealActionDetail(ctx, action, detail)
}

// The worker item a request's target names, as this copy shows it active: nil for none.
func (self *DirectoryAccessRequests) workerItem(workerId Id) *DirectoryItem {
	items, err := self.client.List(&DirectoryFilter{Kind: DirectoryAnnouncementKindWorker, ActiveOnly: true})
	if err != nil {
		return nil
	}
	for _, item := range items {
		if item.SignerSidecarId == workerId {
			return item
		}
	}
	return nil
}

// The bridge ports a worker's item announces, in order.
func directoryWorkerPorts(item *DirectoryItem) []uint32 {
	ports := []uint32{}
	for _, service := range item.Announcement.GetWhat().GetServices() {
		if DirectoryServiceKind(service.GetKind()) != DirectoryServiceKindBridgePort {
			continue
		}
		var port uint32
		if _, err := fmt.Sscanf(service.GetName(), "tcp:%d", &port); err == nil && 0 < port && port <= 65535 {
			ports = append(ports, port)
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// Holds a filing's target to one that takes requests, and answers a worker's ports: the ones asked, each announced,
// or its announced bridge ports when none is asked.
func (self *DirectoryAccessRequests) checkTarget(auth DirectoryAuthView, targetKind DirectoryTargetKind, target *protocol.RequestTarget) ([]uint32, error) {
	switch targetKind {
	case DirectoryTargetKindRepo:
		repoId := Id(target.GetRepoId())
		repo, ok := auth.Repo(repoId)
		if !ok || repo == nil || !repo.Live {
			return nil, fmt.Errorf("%w: no live repo of that id", ErrDirectoryRequestTarget)
		}
		// a private or unannounced repo takes a request by its id; an announced one says whether it takes any
		if item, ok := self.client.RepoItem(repoId); ok && item != nil &&
			DirectoryRequests(item.Announcement.GetWhat().GetRequests()) == DirectoryRequestsClosed {
			return nil, ErrDirectoryRequestsClosed
		}
		return nil, nil
	case DirectoryTargetKindWorker:
		item := self.workerItem(Id(target.GetSidecarId()))
		if item == nil {
			return nil, fmt.Errorf("%w: no worker announced by that sidecar", ErrDirectoryRequestTarget)
		}
		if DirectoryRequests(item.Announcement.GetWhat().GetRequests()) == DirectoryRequestsClosed {
			return nil, ErrDirectoryRequestsClosed
		}
		announced := directoryWorkerPorts(item)
		asked := slices.Clone(target.GetTcpPorts())
		if len(asked) == 0 {
			asked = announced
		}
		if len(asked) == 0 {
			return nil, fmt.Errorf("%w: the worker announces no bridge port", ErrDirectoryRequestTarget)
		}
		for _, port := range asked {
			if !slices.Contains(announced, port) {
				// a grant names only what the worker serves (FI-26)
				return nil, fmt.Errorf("%w: a port the worker does not announce", ErrDirectoryRequestTarget)
			}
		}
		return asked, nil
	}
	return nil, nil
}

// Files a request: DirectoryClient.Request.
func (self *DirectoryAccessRequests) File(ctx context.Context, ask *DirectoryRequestAsk) (*DirectoryRequestFiled, error) {
	client := self.client
	if client.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	directoryId, ok := client.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	if client.writer == nil {
		return nil, ErrDirectoryNoWriter
	}
	if ask == nil {
		return nil, directoryRefusal("no request")
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()

	settings := self.settings()
	binding := self.bound()
	auth := client.auth()
	sidecarId := client.sidecarId
	nowMillis := client.clock.Now().UnixMilli()
	targetKind, err := DirectoryRequestTargetKind(ask.Target)
	if err != nil {
		return nil, err
	}
	reach := targetKind != DirectoryTargetKindRepo
	memberId, isMember := auth.MemberOf(sidecarId)
	filedBy := ask.FiledBy
	if !isMember {
		// a tagged sidecar's request goes to its sponsor, whoever asks on it
		filedBy = DirectoryFiledByTaggedSidecar
	}
	if filedBy != DirectoryFiledByPerson && filedBy != DirectoryFiledByAgent && filedBy != DirectoryFiledByTaggedSidecar {
		return nil, directoryRefusal("filed_by %d", filedBy)
	}
	notAfter := ask.NotAfter
	if notAfter == 0 {
		notAfter = settings.RequestExpiry
	}
	if notAfter <= 0 || settings.RequestMaxExpiry < notAfter {
		return nil, directoryRefusal("a request's life of %s", notAfter)
	}
	if ask.GrantExpiresMillis != 0 && ask.GrantExpiresMillis <= nowMillis {
		return nil, directoryRefusal("a grant expiry in the past")
	}
	ports, err := self.checkTarget(auth, targetKind, ask.Target)
	if err != nil {
		return nil, err
	}
	target := proto.Clone(ask.Target).(*protocol.RequestTarget)
	if targetKind == DirectoryTargetKindWorker {
		target.TcpPorts = ports
	}

	// the limits, read before anything is asked of a person
	limits, err := directoryLimitsOf(ctx, binding.Limits)
	if err != nil {
		return nil, err
	}
	fold, err := self.fold(ctx)
	if err != nil {
		return nil, err
	}
	if err := self.checkFilingLimits(fold, limits, target, ask.RunId, nowMillis); err != nil {
		return nil, err
	}

	requestId := Id{}
	if ask.RequestId != nil {
		requestId = *ask.RequestId
	} else if requestId, err = self.newId(); err != nil {
		return nil, err
	}
	if _, held := fold.byId[requestId]; held {
		return nil, directoryRefusal("a request id already filed")
	}
	subject, subjectIsMember := sidecarId, false
	if !reach && isMember && filedBy == DirectoryFiledByPerson {
		subject, subjectIsMember = memberId, true
	}
	request := &protocol.DirectoryRequest{
		RequestId:          requestId.Bytes(),
		Target:             target,
		Subject:            subject.Bytes(),
		SubjectIsMember:    subjectIsMember,
		Role:               ask.Role,
		GrantExpiresMillis: ask.GrantExpiresMillis,
		NotAfterMillis:     nowMillis + notAfter.Milliseconds(),
		Reason:             DirectoryNormalizeProse(ask.Reason),
		FiledBy:            uint32(filedBy),
		Tainted:            ask.Tainted,
	}
	if ask.AnnouncementId != nil {
		request.AnnouncementId = ask.AnnouncementId.Bytes()
	}
	// the access_request the member endorses and, for reach, the approvers decide: always the spending sidecar's
	action, err := self.storedAccessAction(ctx, &DirectoryAccess{
		Target: target, Subject: sidecarId, Role: ask.Role, ExpiresMillis: ask.GrantExpiresMillis, Ports: ports,
	})
	if err != nil {
		return nil, err
	}
	if reach {
		payloadSha256 := ApprovalPayloadSha256(action.Bytes)
		actionId := ApprovalActionId(requestId, action.Bytes)
		request.Approval = &protocol.ApprovalRequest{
			ApprovalId:         requestId.Bytes(),
			ActionId:           actionId[:],
			CanonicalAction:    action.Bytes,
			PayloadSha256:      payloadSha256[:],
			Risk:               uint32(SidecarRiskNormal),
			RequesterSidecarId: sidecarId.Bytes(),
			Tainted:            ask.Tainted,
			NotAfterMillis:     request.NotAfterMillis,
			Version:            1,
		}
		if ask.RunId != nil {
			request.Approval.RunId = ask.RunId.Bytes()
		}
		if ask.AgentId != nil {
			request.Approval.AgentId = ask.AgentId.Bytes()
		}
	}
	// someone must be able to decide it, by this device's own state
	approvers, err := auth.EligibleApprovers(request, sidecarId, auth.Pin())
	if err != nil {
		return nil, err
	}
	if reach {
		for _, approverId := range approvers.MemberIds {
			request.Approval.Approvers = append(request.Approval.Approvers, approverId.Bytes())
		}
	}

	channel := protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED
	if filedBy != DirectoryFiledByPerson {
		if binding.Endorse == nil {
			return nil, fmt.Errorf("%w: nothing endorses a request here", ErrDirectoryRequestUnendorsed)
		}
		endorsed, err := binding.Endorse(ctx, &DirectoryEndorsement{
			RequestId: requestId, Action: action, RunId: ask.RunId, AgentId: ask.AgentId, Tainted: ask.Tainted, FiledBy: filedBy,
			Decision: ask.Decision,
		})
		if err != nil {
			return nil, err
		}
		if endorsed == nil {
			return nil, fmt.Errorf("%w: no endorsement answered", ErrDirectoryRequestUnendorsed)
		}
		channel = endorsed.Channel
		switch channel {
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
			if ask.Tainted {
				// no requests rule governs the endorsement, so a tainted run's needs device or presence
				return nil, fmt.Errorf("%w: harness evidence in a tainted run", ErrDirectoryRequestUnendorsed)
			}
		default:
			return nil, fmt.Errorf("%w: channel %d", ErrDirectoryRequestUnendorsed, channel)
		}
		request.EndorsementChannel = uint32(channel)
		request.EndorsementSha256 = bytes.Clone(endorsed.DecisionSha256)
		if endorsed.ForMember && ask.ForMember && !reach && isMember {
			request.Subject, request.SubjectIsMember = memberId.Bytes(), true
		}
	}
	if client.redactor != nil {
		if _, err := DirectoryRedact(client.redactor, request); err != nil {
			return nil, err
		}
	}
	if err := DirectoryCheckRequest(request); err != nil {
		return nil, err
	}
	noticePath, err := DirectoryNoticePath(target, requestId)
	if err != nil {
		return nil, err
	}

	draft := &RecordDraft{Kind: RecordKindRequest, Source: RecordSourceObserved, RunId: ask.RunId, AgentId: ask.AgentId, Body: request}
	if ask.RunId == nil {
		draft.NoSession = true
	}
	hookKey := recordChainIdText(requestId)
	testHookBarrier("directory.request.before", hookKey)
	refs, err := client.writer.Append(draft)
	testHookBarrier("directory.request.after", hookKey)
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.filed = append(self.filed, &directoryRequestFiling{
			requestId: requestId, runId: ask.RunId, timeMillis: nowMillis, notAfter: request.NotAfterMillis,
		})
	}()
	filed := &DirectoryRequestFiled{
		RequestId:       requestId,
		Subject:         Id(request.GetSubject()),
		SubjectIsMember: request.GetSubjectIsMember(),
		NotAfterMillis:  request.NotAfterMillis,
		NoticePath:      noticePath,
		Channel:         channel,
	}
	for _, ref := range refs {
		if ref != nil && !ref.Spooled && ref.LogId == directoryId {
			filed.EntrySeq = ref.Seq
		}
	}
	if filed.EntrySeq == 0 {
		// the entry waits in the spool: its notice is the repair's, once the entry lands
		return filed, nil
	}
	if binding.Land != nil {
		if err := binding.Land(ctx); err != nil {
			client.log.Infof("[directory]a request's entry waits for its push: %s", err)
		}
	}
	pushId, err := self.newId()
	if err != nil {
		return filed, nil
	}
	pending := &protocol.DirectoryNotice{
		RequestId:          requestId.Bytes(),
		RequesterSidecarId: sidecarId.Bytes(),
		EntrySeq:           filed.EntrySeq,
		NotAfterMillis:     request.NotAfterMillis,
		State:              uint32(DirectoryNoticeStatePending),
	}
	if _, err := self.putNotice(ctx, noticePath, 0, pending, pushId); err != nil {
		client.log.Infof("[directory]a request's notice waits for its repair: %s", err)
		return filed, nil
	}
	filed.NoticeWritten = true
	return filed, nil
}

// Holds one more filing to §16.11's limits by this sidecar's own requests, the ones a sync read and the ones this
// process filed since.
func (self *DirectoryAccessRequests) checkFilingLimits(fold *directoryRequestFold, limits *directoryLimits, target *protocol.RequestTarget, runId *Id, nowMillis int64) error {
	settings := self.settings()
	pending, perDay, perRun := int64(0), int64(0), int64(0)
	counted := map[Id]bool{}
	for _, view := range fold.views {
		if !view.Mine {
			continue
		}
		counted[view.RequestId] = true
		if view.State == DirectoryRequestPending {
			pending += 1
		}
		if nowMillis-settings.DayWindow.Milliseconds() < view.PushTimeMillis {
			perDay += 1
		}
		if runId != nil && view.RunId != nil && *view.RunId == *runId {
			perRun += 1
		}
	}
	filings := func() []*directoryRequestFiling {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// what a sync read back, and what is past its day and its life, is no longer this list's to count
		self.filed = slices.DeleteFunc(self.filed, func(filing *directoryRequestFiling) bool {
			return counted[filing.requestId] ||
				(filing.timeMillis <= nowMillis-settings.DayWindow.Milliseconds() && filing.notAfter < nowMillis)
		})
		return slices.Clone(self.filed)
	}()
	for _, filing := range filings {
		if nowMillis <= filing.notAfter {
			pending += 1
		}
		if nowMillis-settings.DayWindow.Milliseconds() < filing.timeMillis {
			perDay += 1
		}
		if runId != nil && filing.runId != nil && *filing.runId == *runId {
			perRun += 1
		}
	}
	if err := directoryLimitCheck(DirectoryLimitRequestsPending, limits.requestsPending, pending); err != nil {
		return err
	}
	if err := directoryLimitCheck(DirectoryLimitRequestsPerDay, limits.requestsPerDay, perDay); err != nil {
		return err
	}
	if runId != nil {
		if err := directoryLimitCheck(DirectoryLimitRequestsPerRun, limits.requestsPerRun, perRun); err != nil {
			return err
		}
	}
	targetName, err := DirectoryNoticeTarget(target)
	if err != nil {
		return err
	}
	targetPending := int64(0)
	for _, view := range fold.views {
		if view.State == DirectoryRequestPending && view.Notice != nil && !view.OverLimit && view.targetName() == targetName {
			targetPending += 1
		}
	}
	return directoryLimitCheck(DirectoryLimitTargetPending, limits.targetPending, targetPending)
}

// <tgt> of the view's target.
func (self *DirectoryRequestView) targetName() string {
	name, _ := DirectoryNoticeTarget(self.Request.GetTarget())
	return name
}

// Every request this copy holds, in one state each.
type directoryRequestFold struct {
	nowMillis int64
	// by push time, then requester and seq
	views []*DirectoryRequestView
	byId  map[Id]*DirectoryRequestView
	// nil when they could not be read, and why
	limits    *directoryLimits
	limitsErr error
}

// The directory's request and decision entries as the reader verified them.
func (self *DirectoryClient) entriesOfKinds(kinds ...RecordKind) []*RecordReadEntry {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil
	}
	self.syncLock.Lock()
	reader := self.reader
	self.syncLock.Unlock()
	entries, _ := reader.EntriesOfKinds(directoryId, 0, kinds...)
	return entries
}

// An entry's writer, and the pin and time of the push that carried it in its writer's own stream; false for an entry
// with no body this reader holds, or no copy in its writer's stream.
func directoryEntryPush(entry *RecordReadEntry) (Id, *bridge.AuthPin, int64, bool) {
	if entry == nil || entry.Header == nil || entry.Header.Header == nil || entry.Body == nil || entry.BodyInvalid || entry.State != RecordEntryLive {
		return Id{}, nil, 0, false
	}
	writerId := Id(entry.Header.Header.GetWriterSidecarId())
	for _, entryCopy := range entry.Copies {
		if entryCopy.StreamSidecarId == writerId {
			return writerId, entryCopy.AuthPin, entryCopy.TimeMillis, true
		}
	}
	return Id{}, nil, 0, false
}

// Folds the copy's entries and notices: see the file's header's read row.
func (self *DirectoryAccessRequests) fold(ctx context.Context) (*directoryRequestFold, error) {
	client := self.client
	directoryId, ok := client.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	auth := client.auth()
	sidecarId := client.sidecarId
	fold := &directoryRequestFold{nowMillis: client.clock.Now().UnixMilli(), byId: map[Id]*DirectoryRequestView{}}
	fold.limits, fold.limitsErr = directoryLimitsOf(ctx, self.bound().Limits)

	decisions := map[Id][]*DirectoryDecisionView{}
	for _, entry := range client.entriesOfKinds(RecordKindRequest, RecordKindDecision) {
		writerId, pushPin, pushTimeMillis, ok := directoryEntryPush(entry)
		if !ok {
			continue
		}
		header := entry.Header.Header
		switch entry.Header.Kind() {
		case RecordKindRequest:
			stored, err := DirectoryDecodeRequest(entry.Body)
			if err != nil || auth.Masked(writerId) {
				// a removed member's requests are masked with its cards (§16.11's member row)
				continue
			}
			request := stored.Request
			targetKind, err := DirectoryRequestTargetKind(request.GetTarget())
			if err != nil {
				continue
			}
			// the subject is the requester's own: itself, or its member
			subject := Id(request.GetSubject())
			memberId, isMember := auth.MemberOf(writerId)
			if (request.GetSubjectIsMember() && (!isMember || subject != memberId)) || (!request.GetSubjectIsMember() && subject != writerId) {
				continue
			}
			requestId := Id(request.GetRequestId())
			noticePath, err := DirectoryNoticePath(request.GetTarget(), requestId)
			if err != nil {
				continue
			}
			view := &DirectoryRequestView{
				RequestId:          requestId,
				RequesterSidecarId: writerId,
				Request:            request,
				Stored:             stored,
				TargetKind:         targetKind,
				EntryId:            entry.EntryId,
				EntrySeq:           header.GetSeq(),
				EntrySha256:        DirectoryEntryHeaderSha256(entry.SignedBytes),
				PushPin:            pushPin,
				PushTimeMillis:     pushTimeMillis,
				NoticePath:         noticePath,
				Mine:               writerId == sidecarId,
			}
			if len(header.GetRunId()) == len(Id{}) {
				runId := Id(header.GetRunId())
				view.RunId = &runId
			}
			fold.views = append(fold.views, view)
		case RecordKindDecision:
			stored, err := DirectoryDecodeDecision(entry.Body)
			if err != nil {
				continue
			}
			requestId := Id(stored.Decision.GetRequestId())
			decisions[requestId] = append(decisions[requestId], &DirectoryDecisionView{
				DeciderSidecarId: writerId,
				EntryId:          entry.EntryId,
				Seq:              header.GetSeq(),
				HeaderSha256:     DirectoryEntryHeaderSha256(entry.SignedBytes),
				Decision:         stored.Decision,
				Stored:           stored,
				PushPin:          pushPin,
				PushTimeMillis:   pushTimeMillis,
			})
		}
	}
	slices.SortStableFunc(fold.views, func(a *DirectoryRequestView, b *DirectoryRequestView) int {
		return cmp.Or(cmp.Compare(a.PushTimeMillis, b.PushTimeMillis), a.RequesterSidecarId.Cmp(b.RequesterSidecarId), cmp.Compare(a.EntrySeq, b.EntrySeq))
	})
	// one request an id: the first stands, and a later use of its id is ignored with an alarm
	fold.views = slices.DeleteFunc(fold.views, func(view *DirectoryRequestView) bool {
		if _, held := fold.byId[view.RequestId]; held {
			if self.raiseOnce("id_reuse/" + recordChainIdText(view.EntryId)) {
				requesterId := view.RequesterSidecarId
				client.raise(SidecarRecordAlarmIdReuse, directoryId, &requesterId)
			}
			return true
		}
		fold.byId[view.RequestId] = view
		return false
	})

	notices := map[string]*DirectoryCardFile{}
	for _, file := range client.Cards() {
		if !file.Removed {
			notices[file.Path] = file
		}
	}
	for _, view := range fold.views {
		for _, decision := range decisions[view.RequestId] {
			if !bytes.Equal(decision.Decision.GetRequestEntrySha256(), view.EntrySha256[:]) {
				// a decision that binds another entry than this request's decides nothing
				if self.raiseOnce("bad_decision/" + recordChainIdText(decision.EntryId)) {
					deciderId := decision.DeciderSidecarId
					client.raise(SidecarRecordAlarmBadDecision, directoryId, &deciderId)
				}
				continue
			}
			if DirectoryOutcome(decision.Decision.GetOutcome()) == DirectoryOutcomeCancelled {
				// a cancel is its requester's alone
				if decision.DeciderSidecarId == view.RequesterSidecarId && view.cancelEntry == nil {
					view.cancelEntry = decision
					view.Decisions = append(view.Decisions, decision)
				}
				continue
			}
			if decides, err := auth.Decides(view.Request, view.RequesterSidecarId, decision.DeciderSidecarId, decision.PushPin); err == nil {
				decision.Eligible = decides
			}
			view.Decisions = append(view.Decisions, decision)
		}
		slices.SortStableFunc(view.Decisions, func(a *DirectoryDecisionView, b *DirectoryDecisionView) int {
			return cmp.Compare(a.PushTimeMillis, b.PushTimeMillis)
		})
		view.noticeFile = notices[view.NoticePath]
		if accepted := self.acceptNotice(auth, view, view.noticeFile); accepted != nil {
			view.Notice = accepted.notice
			view.NoticeVersion = accepted.version
		}
		view.State = self.stateOf(auth, view, fold.nowMillis)
	}
	self.applyLimits(fold, directoryId)
	return fold, nil
}

// One request's state: its accepted notice's decision first; else its requester's cancel; else, with no notice at its
// path, what its eligible deciders' entries say, an approval over a denial; else pending until not_after and expired
// past it.
func (self *DirectoryAccessRequests) stateOf(auth DirectoryAuthView, view *DirectoryRequestView, nowMillis int64) DirectoryRequestState {
	if view.Notice != nil && DirectoryNoticeState(view.Notice.GetState()) == DirectoryNoticeStateDecided {
		if DirectoryOutcome(view.Notice.GetOutcome()) == DirectoryOutcomeApproved {
			return DirectoryRequestApproved
		}
		return DirectoryRequestDenied
	}
	if view.cancelEntry != nil {
		return DirectoryRequestCancelled
	}
	if view.noticeFile == nil {
		// closed or removed: the entries say what was decided
		need := 1
		if approvers, err := auth.EligibleApprovers(view.Request, view.RequesterSidecarId, auth.Pin()); err == nil {
			need = max(1, approvers.Count)
		}
		approverIds := []Id{}
		denied := false
		for _, decision := range view.Decisions {
			if !decision.Eligible {
				continue
			}
			switch DirectoryOutcome(decision.Decision.GetOutcome()) {
			case DirectoryOutcomeApproved:
				if !slices.Contains(approverIds, decision.DeciderSidecarId) {
					approverIds = append(approverIds, decision.DeciderSidecarId)
				}
			case DirectoryOutcomeDenied:
				denied = true
			}
		}
		switch {
		case need <= len(approverIds):
			return DirectoryRequestApproved
		case denied:
			return DirectoryRequestDenied
		}
	}
	if view.Request.GetNotAfterMillis() < nowMillis {
		return DirectoryRequestExpired
	}
	return DirectoryRequestPending
}

// The readers' side of §16.11's limits: a requester's requests past directory_requests_per_day in a day,
// directory_requests_per_run in a run or directory_requests_pending pending are ignored, another sidecar's with an
// over_limit alarm; a target's pending requests past directory_target_pending wait behind its older ones. With no
// limits read, nothing is judged here and List shows no other sidecar's request.
func (self *DirectoryAccessRequests) applyLimits(fold *directoryRequestFold, directoryId Id) {
	limits := fold.limits
	if limits == nil {
		return
	}
	window := self.settings().DayWindow.Milliseconds()
	type requesterCounts struct {
		pending int64
		times   []int64
		runs    map[Id]int64
	}
	requesters := map[Id]*requesterCounts{}
	targets := map[string]int64{}
	for _, view := range fold.views {
		counts := requesters[view.RequesterSidecarId]
		if counts == nil {
			counts = &requesterCounts{runs: map[Id]int64{}}
			requesters[view.RequesterSidecarId] = counts
		}
		inDay := int64(0)
		for _, timeMillis := range counts.times {
			if view.PushTimeMillis-window < timeMillis {
				inDay += 1
			}
		}
		pending := view.State == DirectoryRequestPending && view.Notice != nil
		switch {
		case !directoryLimitFits(limits.requestsPerDay, inDay):
			view.OverLimit = true
		case view.RunId != nil && !directoryLimitFits(limits.requestsPerRun, counts.runs[*view.RunId]):
			view.OverLimit = true
		case pending && !directoryLimitFits(limits.requestsPending, counts.pending):
			view.OverLimit = true
		}
		if view.OverLimit {
			if !view.Mine && self.raiseOnce("over_limit/"+recordChainIdText(view.RequestId)) {
				requesterId := view.RequesterSidecarId
				self.client.raise(SidecarRecordAlarmOverLimit, directoryId, &requesterId)
			}
			continue
		}
		counts.times = append(counts.times, view.PushTimeMillis)
		if view.RunId != nil {
			counts.runs[*view.RunId] += 1
		}
		if !pending {
			continue
		}
		counts.pending += 1
		targetName := view.targetName()
		if !directoryLimitFits(limits.targetPending, targets[targetName]) {
			view.Deferred = true
			continue
		}
		targets[targetName] += 1
	}
}

// Which requests List answers.
type DirectoryRequestFilter struct {
	// Only this sidecar's own.
	Mine bool
	// Only the ones this device decides now.
	Decidable bool
	// Only these states; empty for every state.
	States []DirectoryRequestState
	// Only this request.
	RequestId *Id
}

// The requests filter keeps: DirectoryClient.GetRequests.
func (self *DirectoryAccessRequests) List(ctx context.Context, filter *DirectoryRequestFilter) ([]*DirectoryRequestView, error) {
	if filter == nil {
		filter = &DirectoryRequestFilter{}
	}
	fold, err := self.fold(ctx)
	if err != nil {
		return nil, err
	}
	// what a person is about to read is asked for again
	self.client.ViewSync()
	auth := self.client.auth()
	sidecarId := self.client.sidecarId
	views := []*DirectoryRequestView{}
	for _, view := range fold.views {
		switch {
		case filter.RequestId != nil && view.RequestId != *filter.RequestId:
			continue
		case filter.Mine && !view.Mine:
			continue
		case len(filter.States) != 0 && !slices.Contains(filter.States, view.State):
			continue
		}
		if !view.Mine {
			// another's request shows only under the limits, and while its notice or its decision stands
			if fold.limits == nil || view.OverLimit || view.Deferred || (view.State == DirectoryRequestPending && view.Notice == nil) {
				continue
			}
		}
		if view.State == DirectoryRequestPending && !self.client.readOnly {
			if decides, err := auth.Decides(view.Request, view.RequesterSidecarId, sidecarId, auth.Pin()); err == nil {
				view.Decidable = decides
			}
		}
		if filter.Decidable && !view.Decidable {
			continue
		}
		views = append(views, view)
	}
	if fold.limits == nil && !filter.Mine {
		return views, fold.limitsErr
	}
	return views, nil
}

// One request by its id, in this reader's view: ErrDirectoryRequestUnknown for none.
func (self *DirectoryAccessRequests) Get(ctx context.Context, requestId Id) (*DirectoryRequestView, error) {
	views, err := self.List(ctx, &DirectoryRequestFilter{RequestId: &requestId})
	if len(views) == 1 {
		return views[0], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrDirectoryRequestUnknown
}

// The requests' upkeep, which each sync runs: the requester's notices repaired, the leases held, and access_request
// raised once for each pending request this device decides.
func (self *DirectoryAccessRequests) Maintain(ctx context.Context) error {
	if self.client.readOnly {
		return nil
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	fold, err := self.fold(ctx)
	if err != nil {
		return err
	}
	_, firstErr := self.repairNotices(ctx, fold)
	self.maintainLeases(fold)
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	self.finishCancels(ctx, fold)
	_, err = self.resumeDecisionsWithLock(ctx)
	keep(err)
	keep(self.receiveWithLock(ctx, fold))
	auth := self.client.auth()
	sidecarId := self.client.sidecarId
	events := self.bound().Events
	for _, view := range fold.views {
		if view.Mine || view.State != DirectoryRequestPending || view.Notice == nil || view.OverLimit || view.Deferred || events == nil {
			continue
		}
		if decides, err := auth.Decides(view.Request, view.RequesterSidecarId, sidecarId, auth.Pin()); err != nil || !decides {
			continue
		}
		if self.raiseOnce("access_request/" + recordChainIdText(view.RequestId)) {
			if err := events.RaiseAccessRequest(view.RequestId); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
