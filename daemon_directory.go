//go:build !js && !ios && !android && !sdk_mobile_bind

// ur directory's control methods (§5.8, §16.11's Surfaces and signing rows, D-CORE-13, D-CORE-18; CORE-M6-02): what ur
// directory's commands (RECORD-M6-23) and a remote-mode app call over the control socket, each on one network by
// §5.8's rule.
//
//	person acts  announcing a repo or revoking its announcement, approving or denying a request, and erasing sign
//	             only for a ur command confirmed on /dev/tty or in an app's UI, so each is a Confirm method: no mcp or
//	             hook session reaches it, and a control call without ur_confirmed is refused before its handler runs
//	             (D-CORE-13; §16.6 refuses them from MCP besides)
//	claims       directory.claims chooses the caller's project's claims value: a narrower or equal one at once from
//	             any caller, and a wider one answers needs_confirmation, which ur confirms on /dev/tty and sends again
//	             as directory.claims.confirm, a Confirm method; never through MCP (D-CORE-18)
//	listing      directory.list answers stubs, the attested and identifier fields and the match label with no prose,
//	             unless the call asks for untrusted text; then it first taints, fsynced, each run whose harness process
//	             is the caller's ancestor, by the peer pid the system reports and never the hello's, and a caller whose
//	             process cannot be read, or a taint that fails, gets no prose (§5.8, §16.6, §16.7's pid ancestry)
//	backends     the acts run through DaemonDirectoryBackends: the announcement through RECORD-M6-15's AnnounceRepo,
//	             and revoking, deciding and erasing refuse, naming the task that builds each, until it sets its field
//	             (RECORD-M6-19, RECORD-M6-20)
//
// A personal network, or a team whose directory does not exist yet, answers the network's refusal (reading #8 of
// plan-RECORD-small-readings). Replies carry prose only on request and never a secret (the daemon's reply walk).

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The directory's control methods.
const (
	DaemonMethodDirectoryList          = "directory.list"
	DaemonMethodDirectoryAnnounce      = "directory.announce"
	DaemonMethodDirectoryRevoke        = "directory.revoke"
	DaemonMethodDirectoryApprove       = "directory.approve"
	DaemonMethodDirectoryDeny          = "directory.deny"
	DaemonMethodDirectoryErase         = "directory.erase"
	DaemonMethodDirectoryClaims        = "directory.claims"
	DaemonMethodDirectoryClaimsConfirm = "directory.claims.confirm"
)

// directory.list's untrusted argument that returns prose.
const DaemonDirectoryUntrustedInclude = "include"

// A person act whose backend has not landed: nothing was signed.
var ErrDaemonDirectoryUnbuilt = errors.New("this directory act is not built yet")

// A person's decision on a directory request (§16.11's decide row), as RECORD-M6-19's completion protocol takes it.
type DirectoryDecideArgs struct {
	RequestId Id
	Approve   bool
	// An approval's subject narrowed to one sidecar of a member subject (§16.11's subjects row); nil keeps the
	// request's.
	ForSidecarId *Id
	// An approval's grant expiry, never later than asked; 0 takes the request's ask.
	GrantExpiresMillis int64
	// An approval's role, a repo's RepoGrantRole; 0 takes the request's.
	Role uint32
	// A denial's note, prose.
	Note string
}

// What the directory's methods act through, for the call's Sidecar. A nil List, TaintAncestors or Announce takes the
// Sidecar's own; a nil Revoke, Decide or Erase refuses with ErrDaemonDirectoryUnbuilt, signing nothing.
type DaemonDirectoryBackends struct {
	// The directory's current items: DirectoryClient.List.
	List func(ctx context.Context, sidecar *Sidecar, filter *DirectoryFilter) ([]*DirectoryItem, error)
	// Taints, fsynced, each run of the network whose harness process is an ancestor of pid: Sidecar.TaintAncestorRuns.
	TaintAncestors func(ctx context.Context, sidecar *Sidecar, pid int) error
	// A repo's announcement or private marker, the person having confirmed it: DirectoryClient.AnnounceRepo.
	Announce func(ctx context.Context, sidecar *Sidecar, args *DirectoryRepoAnnounceArgs) (any, error)
	// §16.11's revoke row: the private marker over the repo's item and its erasure_request (RECORD-M6-20).
	Revoke func(ctx context.Context, sidecar *Sidecar, repoId Id) (any, error)
	// §16.11's decide row (RECORD-M6-19).
	Decide func(ctx context.Context, sidecar *Sidecar, args *DirectoryDecideArgs) (any, error)
	// A directory admin's erasure of an announcement or an entry (RECORD-M6-20).
	Erase func(ctx context.Context, sidecar *Sidecar, id Id) (any, error)
}

// directory.list's params.
type DaemonDirectoryListParams struct {
	Network string `json:"network,omitempty"`
	// run, worker or repo; "" for every kind.
	Kind     string `json:"kind,omitempty"`
	MemberId *Id    `json:"member_id,omitempty"`
	RepoId   *Id    `json:"repo_id,omitempty"`
	Active   bool   `json:"active,omitempty"`
	Query    string `json:"query,omitempty"`
	// DaemonDirectoryUntrustedInclude returns prose, after the caller's ancestor runs are tainted; anything else
	// withholds it.
	Untrusted string `json:"untrusted,omitempty"`
}

// One item of directory.list's reply.
type DaemonDirectoryListItem struct {
	Kind            string `json:"kind"`
	AnnouncementId  Id     `json:"announcement_id"`
	WriterSidecarId Id     `json:"writer_sidecar_id"`
	Display         string `json:"display"`
	MemberId        *Id    `json:"member_id,omitempty"`
	AutogroupAdmin  bool   `json:"autogroup_admin,omitempty"`
	MemberDevice    bool   `json:"member_device,omitempty"`
	Tainted         bool   `json:"tainted,omitempty"`
	// The fields a query matched, by name; a prose field is named, never quoted.
	Matches []string `json:"matches,omitempty"`
	// The item as protojson writes it: every prose field emptied in a stub.
	Announcement json.RawMessage `json:"announcement"`
}

// directory.list's reply.
type DaemonDirectoryListReply struct {
	Items []*DaemonDirectoryListItem `json:"items"`
	// Prose was included, after the taint; false for stubs.
	Untrusted bool `json:"untrusted"`
	// Prose fields withheld across the stubs: §16.11's untrusted_withheld.
	Withheld int `json:"withheld"`
}

// directory.announce's params: a repo's announcement, or with Private its private marker.
type DaemonDirectoryAnnounceParams struct {
	Network     string   `json:"network,omitempty"`
	RepoId      Id       `json:"repo_id"`
	DisplayName string   `json:"display_name,omitempty"`
	Description string   `json:"description,omitempty"`
	Topics      []string `json:"topics,omitempty"`
	// RepoGrantRole values; nil offers the kind's default roles.
	Roles []uint32 `json:"roles,omitempty"`
	// open or closed; "" for the kind's default.
	Requests string `json:"requests,omitempty"`
	Private  bool   `json:"private,omitempty"`
}

// directory.revoke's params.
type DaemonDirectoryRevokeParams struct {
	Network string `json:"network,omitempty"`
	RepoId  Id     `json:"repo_id"`
}

// directory.approve's and directory.deny's params.
type DaemonDirectoryDecideParams struct {
	Network            string `json:"network,omitempty"`
	RequestId          Id     `json:"request_id"`
	ForSidecarId       *Id    `json:"for_sidecar_id,omitempty"`
	GrantExpiresMillis int64  `json:"grant_expires_millis,omitempty"`
	Role               uint32 `json:"role,omitempty"`
	Note               string `json:"note,omitempty"`
}

// directory.erase's params: an announcement's or an entry's id.
type DaemonDirectoryEraseParams struct {
	Network string `json:"network,omitempty"`
	Id      Id     `json:"id"`
}

// directory.claims's and directory.claims.confirm's params.
type DaemonDirectoryClaimsParams struct {
	Network string `json:"network,omitempty"`
	// off, prompt or auto.
	Claims string `json:"claims"`
}

// What directory.claims and directory.claims.confirm answer: the value a new session in the caller's project starts
// under, or that the choice is wider and needs the person's confirmation.
type DaemonDirectoryClaimsReply struct {
	Claims            string `json:"claims"`
	Pending           string `json:"pending,omitempty"`
	Source            string `json:"source"`
	ProjectLabel      string `json:"project_label,omitempty"`
	NeedsConfirmation bool   `json:"needs_confirmation,omitempty"`
}

// A directory item's kind as ur names it, "" for none known.
func daemonDirectoryKindName(kind DirectoryAnnouncementKind) string {
	switch kind {
	case DirectoryAnnouncementKindRun:
		return "run"
	case DirectoryAnnouncementKindWorker:
		return "worker"
	case DirectoryAnnouncementKindRepo:
		return "repo"
	}
	return ""
}

// The kind ur's name names; 0 for every kind with "", false for a name that is none.
func daemonDirectoryKindOf(name string) (DirectoryAnnouncementKind, bool) {
	switch name {
	case "":
		return 0, true
	case "run":
		return DirectoryAnnouncementKindRun, true
	case "worker":
		return DirectoryAnnouncementKindWorker, true
	case "repo":
		return DirectoryAnnouncementKindRepo, true
	}
	return 0, false
}

// A copy of item with every prose field emptied, and how many held text: §16.11's stub, its attested and identifier
// fields kept.
func daemonDirectoryStub(item *protocol.Announcement) (*protocol.Announcement, int, error) {
	stub := proto.Clone(item).(*protocol.Announcement)
	withheld := 0
	err := directoryRedactedFields(stub, func(field string, class directoryRedactedClass, value *string) {
		if class == directoryRedactedProse && *value != "" {
			*value = ""
			withheld += 1
		}
	})
	if err != nil {
		return nil, 0, err
	}
	return stub, withheld, nil
}

// The params as their type, refusing a body that does not decode.
func decodeDaemonDirectoryParams(call *DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return errors.New("the call takes params")
	}
	if err := json.Unmarshal(call.Params, params); err != nil {
		return errors.New("the params do not decode")
	}
	return nil
}

// The call's Sidecar's directory, or the refusal a network without one answers.
func daemonDirectoryOf(call *DaemonCall) (*DirectoryClient, error) {
	client := call.Sidecar.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
	}
	return client, nil
}

// The resolution as the claims methods answer it.
func daemonDirectoryClaimsReply(resolution *SidecarClaimsResolution) *DaemonDirectoryClaimsReply {
	return &DaemonDirectoryClaimsReply{
		Claims:       resolution.Claims.String(),
		Pending:      resolution.Pending.String(),
		Source:       resolution.Source,
		ProjectLabel: resolution.ProjectLabel,
	}
}

// The directory's control methods over daemon, through backends (see the file header): what a host registers with
// RegisterMethod.
func DaemonDirectoryMethods(daemon *Daemon, backends *DaemonDirectoryBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonDirectoryBackends{}
	}
	list := backends.List
	if list == nil {
		list = func(ctx context.Context, sidecar *Sidecar, filter *DirectoryFilter) ([]*DirectoryItem, error) {
			client := sidecar.Directory()
			if client == nil {
				return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
			}
			return client.List(filter)
		}
	}
	taint := backends.TaintAncestors
	if taint == nil {
		taint = func(ctx context.Context, sidecar *Sidecar, pid int) error {
			return sidecar.TaintAncestorRuns(ctx, pid)
		}
	}
	announce := backends.Announce
	if announce == nil {
		announce = func(ctx context.Context, sidecar *Sidecar, args *DirectoryRepoAnnounceArgs) (any, error) {
			client := sidecar.Directory()
			if client == nil {
				return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
			}
			write, err := client.AnnounceRepo(ctx, args)
			if err != nil {
				return nil, err
			}
			return &DaemonDirectoryAnnounceReply{Warnings: write.Warnings}, nil
		}
	}
	unbuilt := func(task string) error {
		return fmt.Errorf("%w: it waits on %s, and nothing was signed", ErrDaemonDirectoryUnbuilt, task)
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodDirectoryList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDirectoryListParams{}
				if len(call.Params) != 0 {
					if err := decodeDaemonDirectoryParams(call, params); err != nil {
						return nil, err
					}
				}
				kind, ok := daemonDirectoryKindOf(params.Kind)
				if !ok {
					return nil, errors.New("kind is run, worker or repo")
				}
				items, err := list(ctx, call.Sidecar, &DirectoryFilter{
					Kind:       kind,
					MemberId:   params.MemberId,
					RepoId:     params.RepoId,
					ActiveOnly: params.Active,
					Query:      params.Query,
				})
				if err != nil {
					return nil, err
				}
				reply := &DaemonDirectoryListReply{Items: []*DaemonDirectoryListItem{}}
				if params.Untrusted == DaemonDirectoryUntrustedInclude {
					// the caller's harness runs read untrusted text through this answer: they are tainted first, by the
					// pid the system reports for the socket's peer, never the hello's, which the caller writes
					pid := int(call.Hello.PeerPid)
					if pid <= 0 {
						return nil, errors.New("the caller's process cannot be read, so no untrusted text is returned")
					}
					testHookBarrier("daemon.directory.list.taint.before", call.NetworkId.String())
					err := taint(ctx, call.Sidecar, pid)
					testHookBarrier("daemon.directory.list.taint.after", call.NetworkId.String())
					if err != nil {
						return nil, fmt.Errorf("the caller's runs were not tainted, so no untrusted text is returned: %w", err)
					}
					reply.Untrusted = true
				}
				for _, item := range items {
					announcement := item.Announcement
					if !reply.Untrusted {
						stub, withheld, err := daemonDirectoryStub(announcement)
						if err != nil {
							return nil, err
						}
						announcement = stub
						reply.Withheld += withheld
					}
					encoded, err := protojson.Marshal(announcement)
					if err != nil {
						return nil, err
					}
					reply.Items = append(reply.Items, &DaemonDirectoryListItem{
						Kind:            daemonDirectoryKindName(item.Key.Kind),
						AnnouncementId:  item.Key.AnnouncementId,
						WriterSidecarId: item.SignerSidecarId,
						Display:         string(item.Display),
						MemberId:        item.MemberId,
						AutogroupAdmin:  item.AutogroupAdmin,
						MemberDevice:    item.MemberDevice,
						Tainted:         item.Tainted,
						Matches:         item.Matches,
						Announcement:    encoded,
					})
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodDirectoryAnnounce,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDirectoryAnnounceParams{}
				if err := decodeDaemonDirectoryParams(call, params); err != nil || params.RepoId == (Id{}) {
					return nil, errors.New("an announcement names its repo")
				}
				args := &DirectoryRepoAnnounceArgs{
					RepoId:      params.RepoId,
					DisplayName: params.DisplayName,
					Description: params.Description,
					Topics:      params.Topics,
					Private:     params.Private,
					Confirmed:   call.Confirmed,
				}
				if params.Roles != nil {
					args.Roles = []protocol.RepoGrantRole{}
					for _, role := range params.Roles {
						args.Roles = append(args.Roles, protocol.RepoGrantRole(role))
					}
				}
				switch params.Requests {
				case "":
				case "open":
					args.Requests = DirectoryRequestsOpen
				case "closed":
					args.Requests = DirectoryRequestsClosed
				default:
					return nil, errors.New("requests is open or closed")
				}
				return announce(ctx, call.Sidecar, args)
			},
		},
		{
			Name:    DaemonMethodDirectoryRevoke,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDirectoryRevokeParams{}
				if err := decodeDaemonDirectoryParams(call, params); err != nil || params.RepoId == (Id{}) {
					return nil, errors.New("a revocation names its repo")
				}
				if backends.Revoke == nil {
					return nil, unbuilt("RECORD-M6-20")
				}
				return backends.Revoke(ctx, call.Sidecar, params.RepoId)
			},
		},
		daemonDirectoryDecideMethod(DaemonMethodDirectoryApprove, true, backends, unbuilt),
		daemonDirectoryDecideMethod(DaemonMethodDirectoryDeny, false, backends, unbuilt),
		{
			Name:    DaemonMethodDirectoryErase,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDirectoryEraseParams{}
				if err := decodeDaemonDirectoryParams(call, params); err != nil || params.Id == (Id{}) {
					return nil, errors.New("an erasure names an announcement or an entry")
				}
				if backends.Erase == nil {
					return nil, unbuilt("RECORD-M6-20")
				}
				return backends.Erase(ctx, call.Sidecar, params.Id)
			},
		},
		daemonDirectoryClaimsMethod(daemon, DaemonMethodDirectoryClaims, false),
		daemonDirectoryClaimsMethod(daemon, DaemonMethodDirectoryClaimsConfirm, true),
	}
}

// directory.announce's reply: what the person should hear, as DirectoryRepoLabelWarning.
type DaemonDirectoryAnnounceReply struct {
	Warnings []string `json:"warnings,omitempty"`
}

// directory.approve or directory.deny.
func daemonDirectoryDecideMethod(name string, approve bool, backends *DaemonDirectoryBackends, unbuilt func(task string) error) *DaemonMethod {
	return &DaemonMethod{
		Name:    name,
		Network: true,
		Confirm: true,
		Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			params := &DaemonDirectoryDecideParams{}
			if err := decodeDaemonDirectoryParams(call, params); err != nil || params.RequestId == (Id{}) {
				return nil, errors.New("a decision names its request")
			}
			if backends.Decide == nil {
				return nil, unbuilt("RECORD-M6-19")
			}
			return backends.Decide(ctx, call.Sidecar, &DirectoryDecideArgs{
				RequestId:          params.RequestId,
				Approve:            approve,
				ForSidecarId:       params.ForSidecarId,
				GrantExpiresMillis: params.GrantExpiresMillis,
				Role:               params.Role,
				Note:               params.Note,
			})
		},
	}
}

// directory.claims, any caller's, which applies a choice no wider than the session's and answers needs_confirmation
// for a wider one; or directory.claims.confirm, a Confirm method, which applies either.
func daemonDirectoryClaimsMethod(daemon *Daemon, name string, confirm bool) *DaemonMethod {
	return &DaemonMethod{
		Name:    name,
		Network: true,
		Confirm: confirm,
		Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			params := &DaemonDirectoryClaimsParams{}
			if err := decodeDaemonDirectoryParams(call, params); err != nil {
				return nil, err
			}
			value, err := ParseSidecarClaims(params.Claims)
			if err != nil {
				return nil, err
			}
			resolution, err := daemon.ChooseClaims(ctx, call.Hello, call.NetworkId, value, confirm && call.Confirmed)
			if errors.Is(err, ErrSidecarClaimsWider) {
				current := daemon.ResolveClaims(ctx, call.Hello, call.NetworkId)
				reply := daemonDirectoryClaimsReply(current)
				reply.NeedsConfirmation = true
				return reply, nil
			}
			if err != nil {
				return nil, err
			}
			return daemonDirectoryClaimsReply(resolution), nil
		},
	}
}
