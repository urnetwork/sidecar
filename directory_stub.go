//go:build !ios_extension

// §16.11's stubs (RECORD-M6-22; D-MCP-29's stubs row, I-9, FS-88): what a tool, a search or a record read returns of
// an announcement, a request or a decision before a run is tainted. A stub holds the attested fields, which this
// reader's own state and the verified headers say (ids, kinds, versions, times, states), and the identifier fields
// (labels, branches, service names), never prose:
//
//	prose        withheld whoever wrote it: titles, descriptions, claims, notes and reasons are filed automatically
//	             or to persuade, so they are untrusted even from a member's untainted run. Each field that held text
//	             counts as untrusted_withheld; a query's match in prose reads as the field's name, never its text
//	identifiers  member trust when the writing run was untainted and the writer is a member device or a
//	             member-sponsored sidecar; else untrusted, and withheld as prose is
//	include      a caller that tainted its run first (untrusted: include, fsynced write-ahead, D-MCP-16) builds the
//	             stub with the withheld fields in Untrusted, by field name, to return between §16.6's markers
//
// The types carry JSON names so a tool returns them as they are. Pure functions: nothing here reads a store.

package sidecar

import (
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The trust of a stub's identifier fields.
const (
	DirectoryStubTrustMember    = "member"
	DirectoryStubTrustUntrusted = "untrusted"
)

// One service of a worker's stub.
type DirectoryStubService struct {
	// socket, tls_host or bridge_port.
	Kind string `json:"kind"`
	// Withheld with the other identifiers when their trust is untrusted.
	Name string `json:"name,omitempty"`
}

// An announcement as a stub.
type DirectoryStub struct {
	AnnouncementId string `json:"announcement_id"`
	// run, worker or repo.
	Kind    string `json:"kind"`
	Version uint64 `json:"version"`
	// active, stale, ended or private.
	Display   string `json:"display"`
	SidecarId string `json:"sidecar_id"`
	// The item's member in the reader's state, "" where none stands.
	MemberId string `json:"member_id,omitempty"`
	// The writing run's taint.
	Tainted       bool  `json:"tainted"`
	RenewedMillis int64 `json:"renewed_millis"`
	ExpiresMillis int64 `json:"expires_millis"`
	// A run's id and a repo's, attested.
	RunId  string `json:"run_id,omitempty"`
	RepoId string `json:"repo_id,omitempty"`
	// A worker's or a repo's requests: open or closed.
	Requests string `json:"requests,omitempty"`
	// member or untrusted: whether Identifiers are returned or withheld.
	IdentifierTrust string `json:"identifier_trust"`
	// The identifier fields by name, when their trust is member.
	Identifiers map[string]string      `json:"identifiers,omitempty"`
	Services    []DirectoryStubService `json:"services,omitempty"`
	// The fields a query matched, by name.
	Matches []string `json:"matches,omitempty"`
	// How many fields held text this stub does not return.
	UntrustedWithheld int `json:"untrusted_withheld"`
	// The withheld fields by name, only for a caller that tainted its run first; a tool fences each value.
	Untrusted map[string]string `json:"untrusted,omitempty"`
}

// The name a stub gives a kind.
func directoryStubKind(kind DirectoryAnnouncementKind) string {
	switch kind {
	case DirectoryAnnouncementKindRun:
		return "run"
	case DirectoryAnnouncementKindWorker:
		return "worker"
	case DirectoryAnnouncementKindRepo:
		return "repo"
	}
	return "unknown"
}

// open or closed, "" for a kind that takes no requests.
func directoryStubRequests(requests uint32) string {
	switch DirectoryRequests(requests) {
	case DirectoryRequestsOpen:
		return "open"
	case DirectoryRequestsClosed:
		return "closed"
	}
	return ""
}

// A service kind's name.
func directoryStubServiceKind(kind uint32) string {
	switch DirectoryServiceKind(kind) {
	case DirectoryServiceKindSocket:
		return "socket"
	case DirectoryServiceKindTlsHost:
		return "tls_host"
	case DirectoryServiceKindBridgePort:
		return "bridge_port"
	}
	return "unknown"
}

// An id's text, "" for bytes that are none.
func directoryStubId(idBytes []byte) string {
	if len(idBytes) != len(Id{}) {
		return ""
	}
	return Id(idBytes).String()
}

// Sorts a message's text fields into a stub's parts: identifiers returned when trusted, everything else withheld and
// counted, or kept in untrusted when include asks.
func directoryStubFields(message proto.Message, identifiersTrusted bool, include bool) (identifiers map[string]string, untrusted map[string]string, withheld int, err error) {
	identifiers = map[string]string{}
	untrusted = map[string]string{}
	err = directoryRedactedFields(proto.Clone(message), func(field string, class directoryRedactedClass, value *string) {
		if *value == "" {
			return
		}
		if class != directoryRedactedProse && identifiersTrusted {
			identifiers[field] = *value
			return
		}
		if include {
			untrusted[field] = *value
			return
		}
		withheld += 1
	})
	if err != nil {
		return nil, nil, 0, err
	}
	if len(identifiers) == 0 {
		identifiers = nil
	}
	if len(untrusted) == 0 {
		untrusted = nil
	}
	return identifiers, untrusted, withheld, nil
}

// The stub of an item (DirectoryClient.List's, Get's): see the file's header. include is true only for a caller whose
// run is tainted already.
func DirectoryStubOf(item *DirectoryItem, include bool) (*DirectoryStub, error) {
	if item == nil || item.Announcement == nil {
		return nil, directoryRefusal("no item")
	}
	announcement := item.Announcement
	// §16.11's identifiers row: an untainted writing run of a member device or a member-sponsored sidecar
	trusted := !item.Tainted && !announcement.GetTainted() && (item.MemberDevice || item.MemberId != nil)
	stub := &DirectoryStub{
		AnnouncementId:  directoryStubId(announcement.GetAnnouncementId()),
		Kind:            directoryStubKind(DirectoryAnnouncementKind(announcement.GetKind())),
		Version:         announcement.GetVersion(),
		Display:         string(item.Display),
		SidecarId:       item.SignerSidecarId.String(),
		Tainted:         item.Tainted || announcement.GetTainted(),
		RenewedMillis:   announcement.GetRenewedMillis(),
		ExpiresMillis:   announcement.GetExpiresMillis(),
		RunId:           directoryStubId(announcement.GetWhat().GetRunId()),
		RepoId:          directoryStubId(announcement.GetWhere().GetRepoId()),
		IdentifierTrust: DirectoryStubTrustUntrusted,
		Matches:         slices.Clone(item.Matches),
	}
	if trusted {
		stub.IdentifierTrust = DirectoryStubTrustMember
	}
	if item.MemberId != nil {
		stub.MemberId = item.MemberId.String()
	}
	if DirectoryAnnouncementKind(announcement.GetKind()) != DirectoryAnnouncementKindRun {
		stub.Requests = directoryStubRequests(announcement.GetWhat().GetRequests())
	}
	var err error
	if stub.Identifiers, stub.Untrusted, stub.UntrustedWithheld, err = directoryStubFields(announcement, trusted, include); err != nil {
		return nil, err
	}
	// the two labels §16.11's redaction row does not visit, since config and the host write them: identifiers too
	for _, label := range []struct {
		field string
		value string
	}{
		{field: "who.member_label", value: announcement.GetWho().GetMemberLabel()},
		{field: "where.host_label", value: announcement.GetWhere().GetHostLabel()},
	} {
		switch {
		case label.value == "":
		case trusted:
			if stub.Identifiers == nil {
				stub.Identifiers = map[string]string{}
			}
			stub.Identifiers[label.field] = label.value
		case include:
			if stub.Untrusted == nil {
				stub.Untrusted = map[string]string{}
			}
			stub.Untrusted[label.field] = label.value
		default:
			stub.UntrustedWithheld += 1
		}
	}
	for _, service := range announcement.GetWhat().GetServices() {
		stubService := DirectoryStubService{Kind: directoryStubServiceKind(service.GetKind())}
		if trusted {
			stubService.Name = service.GetName()
		}
		stub.Services = append(stub.Services, stubService)
	}
	return stub, nil
}

// A decision as a stub.
type DirectoryDecisionStub struct {
	DeciderSidecarId string `json:"decider_sidecar_id"`
	// approved, denied or cancelled.
	Outcome string `json:"outcome"`
	// Whether its decider was eligible for the target at its push's pin, by this reader's state.
	Eligible bool `json:"eligible"`
	// As approved.
	Subject            string `json:"subject,omitempty"`
	GrantExpiresMillis int64  `json:"grant_expires_millis,omitempty"`
	// A repo approval's position in the authorization log.
	StatementPosition uint64 `json:"statement_position,omitempty"`
	UntrustedWithheld int    `json:"untrusted_withheld"`
	// Its note, only for a caller that tainted its run first.
	Untrusted map[string]string `json:"untrusted,omitempty"`
}

// A request as a stub.
type DirectoryRequestStub struct {
	RequestId          string `json:"request_id"`
	RequesterSidecarId string `json:"requester_sidecar_id"`
	// pending, approved, denied, cancelled or expired.
	State string `json:"state"`
	// repo, worker or socket, and the target's id: a repo's, a worker's sidecar's; a socket's is its notice target.
	TargetKind string   `json:"target_kind"`
	Target     string   `json:"target"`
	TcpPorts   []uint32 `json:"tcp_ports,omitempty"`
	Subject    string   `json:"subject"`
	// The subject is a member, else a sidecar.
	SubjectIsMember bool `json:"subject_is_member"`
	// deposit, reader, writer or dial.
	Access             string `json:"access"`
	GrantExpiresMillis int64  `json:"grant_expires_millis,omitempty"`
	NotAfterMillis     int64  `json:"not_after_millis"`
	// person, agent or tagged_sidecar, and an agent's or a tagged sidecar's endorsement evidence: device, presence or
	// harness.
	FiledBy     string `json:"filed_by"`
	Endorsement string `json:"endorsement,omitempty"`
	// The filing run's taint.
	Tainted bool `json:"tainted"`
	// This sidecar filed it; this device decides it now.
	Mine      bool                     `json:"mine"`
	Decidable bool                     `json:"decidable"`
	Decisions []*DirectoryDecisionStub `json:"decisions,omitempty"`
	// How many prose fields, its reason and its decisions' notes, this stub does not return.
	UntrustedWithheld int               `json:"untrusted_withheld"`
	Untrusted         map[string]string `json:"untrusted,omitempty"`
}

// A request's access by name.
func directoryStubAccess(targetKind DirectoryTargetKind, role uint32) string {
	if targetKind != DirectoryTargetKindRepo {
		return "dial"
	}
	switch protocol.RepoGrantRole(role) {
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT:
		return "deposit"
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_READER:
		return "reader"
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER:
		return "writer"
	}
	return "unknown"
}

// An outcome by name.
func directoryStubOutcome(outcome uint32) string {
	switch DirectoryOutcome(outcome) {
	case DirectoryOutcomeApproved:
		return "approved"
	case DirectoryOutcomeDenied:
		return "denied"
	case DirectoryOutcomeCancelled:
		return "cancelled"
	}
	return "unknown"
}

// The stub of a request and its decisions (DirectoryClient.GetRequests'): see the file's header.
func DirectoryRequestStubOf(view *DirectoryRequestView, include bool) (*DirectoryRequestStub, error) {
	if view == nil || view.Request == nil {
		return nil, directoryRefusal("no request")
	}
	request := view.Request
	stub := &DirectoryRequestStub{
		RequestId:          view.RequestId.String(),
		RequesterSidecarId: view.RequesterSidecarId.String(),
		State:              string(view.State),
		TcpPorts:           slices.Clone(request.GetTarget().GetTcpPorts()),
		Subject:            directoryStubId(request.GetSubject()),
		SubjectIsMember:    request.GetSubjectIsMember(),
		Access:             directoryStubAccess(view.TargetKind, request.GetRole()),
		GrantExpiresMillis: request.GetGrantExpiresMillis(),
		NotAfterMillis:     request.GetNotAfterMillis(),
		Tainted:            request.GetTainted(),
		Mine:               view.Mine,
		Decidable:          view.Decidable,
	}
	switch view.TargetKind {
	case DirectoryTargetKindRepo:
		stub.TargetKind, stub.Target = "repo", directoryStubId(request.GetTarget().GetRepoId())
	case DirectoryTargetKindWorker:
		stub.TargetKind, stub.Target = "worker", directoryStubId(request.GetTarget().GetSidecarId())
	default:
		stub.TargetKind = "socket"
		stub.Target, _ = DirectoryNoticeTarget(request.GetTarget())
	}
	switch DirectoryFiledBy(request.GetFiledBy()) {
	case DirectoryFiledByPerson:
		stub.FiledBy = "person"
	case DirectoryFiledByAgent:
		stub.FiledBy = "agent"
	case DirectoryFiledByTaggedSidecar:
		stub.FiledBy = "tagged_sidecar"
	}
	switch protocol.ApprovalChannel(request.GetEndorsementChannel()) {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE:
		stub.Endorsement = "device"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		stub.Endorsement = "presence"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		stub.Endorsement = "harness"
	}
	var err error
	// a request holds prose alone
	if _, stub.Untrusted, stub.UntrustedWithheld, err = directoryStubFields(request, false, include); err != nil {
		return nil, err
	}
	for _, decision := range view.Decisions {
		decisionStub := &DirectoryDecisionStub{
			DeciderSidecarId:   decision.DeciderSidecarId.String(),
			Outcome:            directoryStubOutcome(decision.Decision.GetOutcome()),
			Eligible:           decision.Eligible,
			Subject:            directoryStubId(decision.Decision.GetSubject()),
			GrantExpiresMillis: decision.Decision.GetGrantExpiresMillis(),
			StatementPosition:  decision.Decision.GetStatementPosition(),
		}
		if _, decisionStub.Untrusted, decisionStub.UntrustedWithheld, err = directoryStubFields(decision.Decision, false, include); err != nil {
			return nil, err
		}
		stub.UntrustedWithheld += decisionStub.UntrustedWithheld
		stub.Decisions = append(stub.Decisions, decisionStub)
	}
	return stub, nil
}

// The directory's verified ref versions this copy was read at (§16.5's directory_list coverage): the cards ref's
// version, the push sequence the last listing ended at, and how many writers' streams the copy holds.
type DirectoryRefVersions struct {
	CardsVersion uint64
	Sequence     uint64
	StreamCount  int
}

// What this copy covers now.
func (self *DirectoryClient) RefVersions() *DirectoryRefVersions {
	if self.store == nil {
		return &DirectoryRefVersions{}
	}
	state := self.store.State()
	if state == nil {
		return &DirectoryRefVersions{}
	}
	return &DirectoryRefVersions{CardsVersion: state.CardsVersion, Sequence: state.Sequence, StreamCount: len(state.StreamVersions)}
}
