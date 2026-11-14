//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's directory tools (RECORD-M6-22; §16.11's surfaces table, D-MCP-29, D-MCP-30, FS-88):
//
//	directory_list      R  the team directory's announcements as stubs: attested and identifier fields and the fields
//	                       a query matched, never prose. untrusted: include taints the run first, write-ahead, and
//	                       then returns the withheld text between §16.6's markers; a taint that does not fsync fails
//	                       the call
//	directory_requests  R  access requests and their decisions as stubs: this sidecar's own (view: mine) or the ones
//	                       this device decides (view: incoming), read-only
//	directory_request   O  files an access request to a repo, a worker or a socket: the member endorses it through
//	                       §5.4's gate before anything is filed, so it answers approval_pending with the approval's id
//	                       until a person decides
//
// Deciding, announcing, revoking, marking private, the claims value, the worker and team settings and erasure are a
// person's acts on /dev/tty or in an app: no tool here does one, and McpGuard refuses a tool that reports one. In a
// personal network, or before the team's directory is made, each tool stays in the catalog and answers
// FAILED_PRECONDITION saying so (plan-RECORD-small-readings#8). Page sizes are McpDirectorySettings' fields.

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The directory as the tools read it: *sidecar.DirectoryClient is one.
type McpDirectory interface {
	DirectoryId() (sidecar.Id, bool)
	List(filter *sidecar.DirectoryFilter) ([]*sidecar.DirectoryItem, error)
	RefVersions() *sidecar.DirectoryRefVersions
	GetRequests(ctx context.Context, filter *sidecar.DirectoryRequestFilter) ([]*sidecar.DirectoryRequestView, error)
	Request(ctx context.Context, ask *sidecar.DirectoryRequestAsk) (*sidecar.DirectoryRequestFiled, error)
}

// A network that may hold a team directory.
type McpDirectoryNetwork interface {
	// The network's directory, nil in a personal network or one whose client cannot be made.
	McpDirectory() McpDirectory
}

// The hosted Sidecar's directory client.
func (self *mcpSidecarNetwork) McpDirectory() McpDirectory {
	client := self.Sidecar.Directory()
	if client == nil {
		return nil
	}
	return client
}

// The tools' own sizes.
type McpDirectorySettings struct {
	// Stubs a page of directory_list or directory_requests carries before it answers next_cursor.
	PageCount int
}

// The defaults, a fresh value each call.
func DefaultMcpDirectorySettings() *McpDirectorySettings {
	return &McpDirectorySettings{PageCount: 100}
}

// The tools' refusals, each constant.
var (
	errMcpDirectoryNone        = NewMcpError(McpCodeFailedPrecondition, "this network is personal, or its team directory is not made yet: an admin runs ur directory init in their own terminal", false)
	errMcpDirectoryArguments   = NewMcpError(McpCodeInvalidArguments, "kind is run, worker or repo; member and repo are ids; untrusted is include; view is mine or incoming; cursor is one a page answered", false)
	errMcpDirectoryTarget      = NewMcpError(McpCodeInvalidArguments, "target is repo:<id>, worker:<sidecar id> with an optional :tcp:<port>, or sock:<name token in hex>; access is deposit, reader or writer for a repo and dial for the rest; expires is an RFC 3339 time ahead; subject is sidecar or member", false)
	errMcpDirectoryNoTarget    = NewMcpError(McpCodeFailedPrecondition, "no such target is announced in the directory, or it does not serve what was asked", false)
	errMcpDirectoryClosed      = NewMcpError(McpCodeFailedPrecondition, "the target takes no requests", false)
	errMcpDirectoryLimit       = NewMcpError(McpCodeRefused, "a directory request limit is reached: wait for pending requests to be decided", false)
	errMcpDirectoryNoApprover  = NewMcpError(McpCodeFailedPrecondition, "nobody in the network approves requests for that target", false)
	errMcpDirectoryUnendorsed  = NewMcpError(McpCodeRefused, "the member's endorsement is not available here: a person files it with ur directory request in their own terminal", false)
	errMcpDirectoryUnavailable = NewMcpError(McpCodeUnavailable, "the directory cannot be read now: send the call again", true)
)

// The call's directory, or the refusal a network without one answers.
func mcpDirectoryOf(call *McpCall) (McpDirectory, error) {
	network, ok := call.Network.(McpDirectoryNetwork)
	if !ok {
		return nil, errMcpDirectoryNone
	}
	directory := network.McpDirectory()
	if directory == nil {
		return nil, errMcpDirectoryNone
	}
	if _, ok := directory.DirectoryId(); !ok {
		return nil, errMcpDirectoryNone
	}
	return directory, nil
}

// A page's bounds over count items from cursor, a decimal offset a page answered: the first index, one past the last,
// and the next cursor, "" at the end.
func mcpDirectoryPage(cursor string, count int, settings *McpDirectorySettings) (int, int, string, error) {
	first := 0
	if cursor != "" {
		offset, err := strconv.Atoi(cursor)
		if err != nil || offset < 0 || count < offset || strconv.Itoa(offset) != cursor {
			return 0, 0, "", errMcpDirectoryArguments
		}
		first = offset
	}
	end := min(count, first+max(1, settings.PageCount))
	next := ""
	if end < count {
		next = strconv.Itoa(end)
	}
	return first, end, next, nil
}

// Whether untrusted asks for the withheld text: "" keeps stubs, include returns it.
func mcpDirectoryInclude(untrusted string) (bool, error) {
	switch untrusted {
	case "":
		return false, nil
	case "include":
		return true, nil
	}
	return false, errMcpDirectoryArguments
}

// Fences each withheld value of a stub.
func mcpDirectoryFence(result *McpResult, untrusted map[string]string) {
	for field, text := range untrusted {
		untrusted[field] = result.Fence(text)
	}
}

// directory_list's arguments.
type mcpDirectoryListIn struct {
	// run, worker or repo; empty for every kind.
	Kind string `json:"kind,omitempty"`
	// A member's id, to list its items alone.
	Member string `json:"member,omitempty"`
	// A repo's id: its own item and the runs in it.
	Repo       string `json:"repo,omitempty"`
	ActiveOnly bool   `json:"active_only,omitempty"`
	// Words each of which must appear in some text field.
	Query string `json:"query,omitempty"`
	// include returns the withheld text, after tainting the run.
	Untrusted string `json:"untrusted,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

// The directory's verified ref versions a listing was read at.
type mcpDirectoryCoverageOut struct {
	CardsVersion uint64 `json:"cards_version"`
	Sequence     uint64 `json:"sequence"`
	StreamCount  int    `json:"stream_count"`
}

// directory_list's result.
type mcpDirectoryListOut struct {
	Announcements []*sidecar.DirectoryStub `json:"announcements"`
	// How many text fields the page's stubs do not return.
	UntrustedWithheld int                     `json:"untrusted_withheld"`
	Coverage          mcpDirectoryCoverageOut `json:"coverage"`
	NextCursor        string                  `json:"next_cursor,omitempty"`
}

// directory_requests' arguments.
type mcpDirectoryRequestsIn struct {
	// mine, this sidecar's own requests, or incoming, the ones this device decides.
	View string `json:"view"`
	// pending, approved, denied, cancelled or expired; empty for every state.
	State     string `json:"state,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

// directory_requests' result.
type mcpDirectoryRequestsOut struct {
	Requests          []*sidecar.DirectoryRequestStub `json:"requests"`
	UntrustedWithheld int                             `json:"untrusted_withheld"`
	NextCursor        string                          `json:"next_cursor,omitempty"`
}

// directory_request's arguments.
type mcpDirectoryRequestIn struct {
	// repo:<id>, worker:<sidecar id>[:tcp:<port>] or sock:<name token in hex>.
	Target string `json:"target"`
	// deposit, reader or writer for a repo; dial for a worker or a socket.
	Access string `json:"access"`
	Reason string `json:"reason,omitempty"`
	// The grant's expiry asked, an RFC 3339 time; empty asks for the approver's default.
	Expires string `json:"expires,omitempty"`
	// sidecar, the default, or member, which the endorsing person must widen it to.
	Subject string `json:"subject,omitempty"`
}

// directory_request's result.
type mcpDirectoryRequestOut struct {
	// pending once filed, or approval_pending with approval_id while the member's endorsement is awaited: the same
	// call again then files it.
	State      string `json:"state"`
	RequestId  string `json:"request_id,omitempty"`
	ApprovalId string `json:"approval_id,omitempty"`
	// When the request itself lapses, Unix milliseconds.
	NotAfterMillis int64 `json:"not_after_millis,omitempty"`
}

// A target and its access as a request names them.
func mcpDirectoryTarget(target string, access string) (*protocol.RequestTarget, uint32, error) {
	kind, rest, found := strings.Cut(target, ":")
	if !found || rest == "" {
		return nil, 0, errMcpDirectoryTarget
	}
	switch kind {
	case "repo":
		repoId, err := sidecar.ParseId(rest)
		if err != nil {
			return nil, 0, errMcpDirectoryTarget
		}
		role := protocol.RepoGrantRole_REPO_GRANT_ROLE_UNSPECIFIED
		switch access {
		case "deposit":
			role = protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT
		case "reader":
			role = protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
		case "writer":
			role = protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER
		default:
			return nil, 0, errMcpDirectoryTarget
		}
		return &protocol.RequestTarget{RepoId: repoId.Bytes()}, uint32(role), nil
	case "worker":
		if access != "dial" {
			return nil, 0, errMcpDirectoryTarget
		}
		idText, portText, hasPort := strings.Cut(rest, ":tcp:")
		workerId, err := sidecar.ParseId(idText)
		if err != nil {
			return nil, 0, errMcpDirectoryTarget
		}
		requestTarget := &protocol.RequestTarget{SidecarId: workerId.Bytes()}
		if hasPort {
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
				return nil, 0, errMcpDirectoryTarget
			}
			requestTarget.TcpPorts = []uint32{uint32(port)}
		}
		return requestTarget, uint32(protocol.AclAction_ACL_ACTION_DIAL), nil
	case "sock":
		if access != "dial" {
			return nil, 0, errMcpDirectoryTarget
		}
		token, err := hex.DecodeString(rest)
		if err != nil || len(token) == 0 || strings.ToLower(rest) != rest {
			return nil, 0, errMcpDirectoryTarget
		}
		return &protocol.RequestTarget{SocketToken: token}, uint32(protocol.AclAction_ACL_ACTION_DIAL), nil
	}
	return nil, 0, errMcpDirectoryTarget
}

// A filing's error as the tool answers it: constant text, never the request's.
func mcpDirectoryRequestError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrDirectoryNone):
		return errMcpDirectoryNone
	case errors.Is(err, sidecar.ErrDirectoryRequestsClosed):
		return errMcpDirectoryClosed
	case errors.Is(err, sidecar.ErrDirectoryRequestLimit):
		return errMcpDirectoryLimit
	case errors.Is(err, sidecar.ErrDirectoryRequestTarget):
		return errMcpDirectoryNoTarget
	case errors.Is(err, sidecar.ErrDirectoryAuthNoApprovers):
		return errMcpDirectoryNoApprover
	case errors.Is(err, sidecar.ErrDirectoryRequestUnendorsed), errors.Is(err, sidecar.ErrDirectoryRequestUnsealed), errors.Is(err, sidecar.ErrDirectoryReadOnly):
		return errMcpDirectoryUnendorsed
	case errors.Is(err, sidecar.ErrDirectoryLimitsUnavailable):
		return errMcpDirectoryUnavailable
	case errors.Is(err, sidecar.ErrDirectoryFormatInvalid):
		return errMcpDirectoryTarget
	}
	return errMcpFailed
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addDirectoryTools(catalog, DefaultMcpDirectorySettings())
	})
}

// Registers the three tools on catalog.
func addDirectoryTools(catalog *McpCatalog, settings *McpDirectorySettings) {
	AddTool(catalog, &McpToolSpec[mcpDirectoryListIn]{
		Name:        "directory_list",
		Tier:        McpTierRead,
		Description: "Lists the team directory's announcements, runs, workers and repos, as stubs: ids, states, labels and the fields a query matched, with other members' text withheld; untrusted: include returns that text and taints the run.",
		Access:      func(call *McpCall, in *mcpDirectoryListIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDirectoryListIn, result *McpResult) (*mcpDirectoryListOut, error) {
		include, err := mcpDirectoryInclude(in.Untrusted)
		if err != nil {
			return nil, err
		}
		filter := &sidecar.DirectoryFilter{ActiveOnly: in.ActiveOnly, Query: in.Query}
		switch in.Kind {
		case "":
		case "run":
			filter.Kind = sidecar.DirectoryAnnouncementKindRun
		case "worker":
			filter.Kind = sidecar.DirectoryAnnouncementKindWorker
		case "repo":
			filter.Kind = sidecar.DirectoryAnnouncementKindRepo
		default:
			return nil, errMcpDirectoryArguments
		}
		if in.Member != "" {
			memberId, err := sidecar.ParseId(in.Member)
			if err != nil {
				return nil, errMcpDirectoryArguments
			}
			filter.MemberId = &memberId
		}
		if in.Repo != "" {
			repoId, err := sidecar.ParseId(in.Repo)
			if err != nil {
				return nil, errMcpDirectoryArguments
			}
			filter.RepoId = &repoId
		}
		directory, err := mcpDirectoryOf(call)
		if err != nil {
			return nil, err
		}
		items, err := directory.List(filter)
		if err != nil {
			return nil, mcpDirectoryRequestError(err)
		}
		first, end, next, err := mcpDirectoryPage(in.Cursor, len(items), settings)
		if err != nil {
			return nil, err
		}
		result.SetSource("directory:announcements")
		if include {
			// the run is tainted, fsynced, before any withheld text is read into the result (D-MCP-16)
			if err := result.Untrusted(ctx); err != nil {
				return nil, err
			}
		} else {
			result.Member()
		}
		out := &mcpDirectoryListOut{Announcements: []*sidecar.DirectoryStub{}, NextCursor: next}
		for _, item := range items[first:end] {
			stub, err := sidecar.DirectoryStubOf(item, include)
			if err != nil {
				return nil, errMcpFailed
			}
			mcpDirectoryFence(result, stub.Untrusted)
			out.UntrustedWithheld += stub.UntrustedWithheld
			out.Announcements = append(out.Announcements, stub)
		}
		if coverage := directory.RefVersions(); coverage != nil {
			out.Coverage = mcpDirectoryCoverageOut{CardsVersion: coverage.CardsVersion, Sequence: coverage.Sequence, StreamCount: coverage.StreamCount}
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpDirectoryRequestsIn]{
		Name:        "directory_requests",
		Tier:        McpTierRead,
		Description: "Lists access requests and their decisions as stubs: this sidecar's own (view: mine) or the ones this device's member decides (view: incoming); read-only, since deciding is a person's act in their own terminal or app.",
		Access:      func(call *McpCall, in *mcpDirectoryRequestsIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDirectoryRequestsIn, result *McpResult) (*mcpDirectoryRequestsOut, error) {
		include, err := mcpDirectoryInclude(in.Untrusted)
		if err != nil {
			return nil, err
		}
		filter := &sidecar.DirectoryRequestFilter{}
		switch in.View {
		case "mine":
			filter.Mine = true
		case "incoming":
			filter.Decidable = true
		default:
			return nil, errMcpDirectoryArguments
		}
		switch state := sidecar.DirectoryRequestState(in.State); state {
		case "":
		case sidecar.DirectoryRequestPending, sidecar.DirectoryRequestApproved, sidecar.DirectoryRequestDenied,
			sidecar.DirectoryRequestCancelled, sidecar.DirectoryRequestExpired:
			filter.States = []sidecar.DirectoryRequestState{state}
		default:
			return nil, errMcpDirectoryArguments
		}
		directory, err := mcpDirectoryOf(call)
		if err != nil {
			return nil, err
		}
		views, err := directory.GetRequests(ctx, filter)
		if err != nil {
			return nil, mcpDirectoryRequestError(err)
		}
		first, end, next, err := mcpDirectoryPage(in.Cursor, len(views), settings)
		if err != nil {
			return nil, err
		}
		result.SetSource("directory:requests")
		if include {
			if err := result.Untrusted(ctx); err != nil {
				return nil, err
			}
		} else {
			result.Member()
		}
		out := &mcpDirectoryRequestsOut{Requests: []*sidecar.DirectoryRequestStub{}, NextCursor: next}
		for _, view := range views[first:end] {
			stub, err := sidecar.DirectoryRequestStubOf(view, include)
			if err != nil {
				return nil, errMcpFailed
			}
			mcpDirectoryFence(result, stub.Untrusted)
			for _, decision := range stub.Decisions {
				mcpDirectoryFence(result, decision.Untrusted)
			}
			out.UntrustedWithheld += stub.UntrustedWithheld
			out.Requests = append(out.Requests, stub)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpDirectoryRequestIn]{
		Name:        "directory_request",
		Tier:        McpTierOutward,
		Description: "Files an access request to a repo, a worker or a socket of the team directory, for its approvers to decide; outward, so it answers approval_pending until the member endorses it.",
		Access:      func(call *McpCall, in *mcpDirectoryRequestIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDirectoryRequestIn, result *McpResult) (*mcpDirectoryRequestOut, error) {
		target, role, err := mcpDirectoryTarget(in.Target, in.Access)
		if err != nil {
			return nil, err
		}
		ask := &sidecar.DirectoryRequestAsk{
			Target:  target,
			Role:    role,
			Reason:  in.Reason,
			FiledBy: sidecar.DirectoryFiledByAgent,
			Tainted: call.Tainted(),
		}
		runId := call.RunId
		ask.RunId = &runId
		switch in.Subject {
		case "", "sidecar":
		case "member":
			ask.ForMember = true
		default:
			return nil, errMcpDirectoryTarget
		}
		if in.Expires != "" {
			expires, err := time.Parse(time.RFC3339, in.Expires)
			if err != nil || !mcpCallNow(call).Before(expires) {
				return nil, errMcpDirectoryTarget
			}
			ask.GrantExpiresMillis = expires.UnixMilli()
		}
		directory, err := mcpDirectoryOf(call)
		if err != nil {
			return nil, err
		}
		result.SetSource("directory:request")
		filed, err := directory.Request(ctx, ask)
		if err != nil {
			var pending *sidecar.ApprovalPendingError
			if errors.As(err, &pending) {
				return &mcpDirectoryRequestOut{State: "approval_pending", ApprovalId: pending.ApprovalId.String()}, nil
			}
			return nil, mcpDirectoryRequestError(err)
		}
		if filed == nil {
			return nil, errMcpFailed
		}
		return &mcpDirectoryRequestOut{State: "pending", RequestId: filed.RequestId.String(), NotAfterMillis: filed.NotAfterMillis}, nil
	})
}
