// ur directory (§16.11's Surfaces, signing and output rows; R-MCP-15, R-MCP-16, D-MCP-29, D-CORE-13, D-MCP-33;
// RECORD-M6-23):
//
//	ur directory ls [--kind=<kind>] [--member=<member>] [--repo=<repo>] [--active] [--query=<query>] [--format=<format>]
//	ur directory show <id>
//	ur directory runs [<claims>] [--project=<path>]
//	ur directory worker [<setting>] [--description=<text>] [--requests=<requests>]
//	ur directory announce repo <repo> [--description=<text>] [--topics=<topics>] [--roles=<roles>] [--requests=<requests>]
//	ur directory revoke <repo>
//	ur directory withdraw <id>
//	ur directory erase <id>
//	ur directory request <target> [--role=<role>] [--ports=<ports>] [--for=<duration>] [--reason=<text>] [--subject=<subject>]
//	ur directory requests [--mine | --incoming] [--state=<state>]
//	ur directory approve <request> [--for=<duration>] [--role=<role>] [--subject=<subject>]
//	ur directory deny <request> [--note=<text>]
//	ur directory cancel <request>
//
// Each takes --network, which the daemon resolves by §5.8's rule when it is left out.
//
//	signing  announce, revoke, approve, deny, erase, request (filed_by person) and a runs value wider than the
//	         project's present one sign only after a yes on /dev/tty, never stdin, each through a Confirm method the
//	         daemon refuses from MCP, a hook or an unconfirmed call; no terminal, or a no, sends nothing. A person's
//	         acts never pass through MCP (§16.6)
//	output   16.10's cli rule: on a terminal ls, show and requests print prose after the daemon taints, fsynced, each
//	         run whose harness process is an ancestor of this ur (by the peer pid the system reports); on a
//	         non-terminal they print stubs, prose withheld whatever flag the command carries
//	revoke   prints the private marker's entry, then the erasure pending with its age until a directory admin's ERASE
//	         names its erasure_request, then done; the same command again shows where it stands, filing nothing more
//	network  a personal network, or a team whose directory does not exist yet, answers the network's refusal and exits
//	         non-zero (plan-RECORD-small-readings #8)
//
// The person acts CORE-M6-02 registered (cmd_directory_confirm.go) run here through its helpers; the rest are this
// file's methods over the call's Sidecar's DirectoryClient. A socket's name token needs the network's K_sock ring,
// which this surface does not reach yet, so `ur directory request sock:<name>` refuses, filing nothing.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur directory adds beside CORE-M6-02's.
const (
	urMethodDirectoryRunsShow = "directory.runs.show"
	urMethodDirectoryRunsKeep = "directory.runs.keep"
	urMethodDirectoryWorker   = "directory.worker"
	urMethodDirectoryWithdraw = "directory.withdraw"
	urMethodDirectoryRequest  = "directory.request"
	urMethodDirectoryRequests = "directory.requests"
	urMethodDirectoryCancel   = "directory.cancel"
)

// The usage lines, each also taking --network.
var urDirectoryUsage = []string{
	"ur directory ls [--kind=<kind>] [--member=<member>] [--repo=<repo>] [--active] [--query=<query>] [--format=<format>] [--network=<network>]",
	"ur directory show <id> [--network=<network>]",
	"ur directory runs [<claims>] [--project=<path>] [--network=<network>]",
	"ur directory worker [<setting>] [--description=<text>] [--requests=<requests>] [--network=<network>]",
	"ur directory announce repo <repo> [--description=<text>] [--topics=<topics>] [--roles=<roles>] [--requests=<requests>] [--network=<network>]",
	"ur directory revoke <repo> [--network=<network>]",
	"ur directory withdraw <id> [--network=<network>]",
	"ur directory erase <id> [--network=<network>]",
	"ur directory request <target> [--role=<role>] [--ports=<ports>] [--for=<duration>] [--reason=<text>] [--subject=<subject>] [--network=<network>]",
	"ur directory requests [--mine | --incoming] [--state=<state>] [--network=<network>]",
	"ur directory approve <request> [--for=<duration>] [--role=<role>] [--subject=<subject>] [--network=<network>]",
	"ur directory deny <request> [--note=<text>] [--network=<network>]",
	"ur directory cancel <request> [--network=<network>]",
}

func init() {
	usage := []string{}
	for _, line := range urDirectoryUsage {
		usage = append(usage, "  "+line)
	}
	registerUrCommand(&urCommand{
		name:    "directory",
		usage:   strings.Join(usage, "\n"),
		summary: "the team directory: list announcements, announce or revoke a repo, request and decide access; a person's acts confirmed on the terminal",
		run:     runUrDirectory,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDirectoryCommandMethods)
}

// Whether ur's stdout is a terminal, where prose prints after the taint; a test replaces it.
var urDirectoryStdoutIsTerminal = func(cli *urCli) bool {
	file, ok := cli.stdout.(*os.File)
	return ok && isTerminal(file)
}

// What a method of this file acts on: the call's Sidecar's directory, or the refusal of a network without one.
func urDirectoryClientOf(call *sidecar.DaemonCall) (*sidecar.DirectoryClient, error) {
	if call.Sidecar == nil {
		return nil, fmt.Errorf("%w: no network", sidecar.ErrDirectoryNone)
	}
	client := call.Sidecar.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", sidecar.ErrDirectoryNone)
	}
	return client, nil
}

// directory.runs.show's and directory.runs.keep's params: the claims value, and the project the hello's cwd names.
type urDirectoryRunsParams struct {
	Network string `json:"network,omitempty"`
	Claims  string `json:"claims,omitempty"`
}

// directory.runs.keep's reply: whether the member's value was kept in the harness config, and why not.
type urDirectoryRunsKept struct {
	Kept   bool   `json:"kept"`
	Reason string `json:"reason,omitempty"`
}

// directory.worker's params; a field left out keeps the device's setting.
type urDirectoryWorkerParams struct {
	Network     string  `json:"network,omitempty"`
	On          *bool   `json:"on,omitempty"`
	Description *string `json:"description,omitempty"`
	// open or closed; "" keeps.
	Requests string `json:"requests,omitempty"`
}

// directory.worker's reply: the worker item as this device keeps it.
type urDirectoryWorkerReply struct {
	On          bool   `json:"on"`
	Description string `json:"description,omitempty"`
	Requests    string `json:"requests"`
}

// directory.withdraw's and directory.cancel's params.
type urDirectoryIdParams struct {
	Network string     `json:"network,omitempty"`
	Id      sidecar.Id `json:"id"`
}

// directory.request's params: a person's own request.
type urDirectoryRequestParams struct {
	Network string `json:"network,omitempty"`
	// repo:<id>, worker:<id>, a bare id (a worker when an announced worker has it, else a repo), or sock:<name>.
	Target string `json:"target"`
	// reader, writer or deposit for a repo; a worker's is dial.
	Role  string   `json:"role,omitempty"`
	Ports []uint32 `json:"ports,omitempty"`
	// The grant's life asked, from now; 0 for the approver's default.
	ForMillis int64  `json:"for_millis,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// member or sidecar; a person's own request names its member unless sidecar.
	Subject string `json:"subject,omitempty"`
}

// directory.requests's params.
type urDirectoryRequestsParams struct {
	Network  string `json:"network,omitempty"`
	Mine     bool   `json:"mine,omitempty"`
	Incoming bool   `json:"incoming,omitempty"`
	// pending, approved, denied, cancelled or expired; "" for every state, decided for approved, denied and cancelled.
	State     string      `json:"state,omitempty"`
	RequestId *sidecar.Id `json:"request_id,omitempty"`
	// include returns the prose, after the caller's ancestor runs are tainted.
	Untrusted string `json:"untrusted,omitempty"`
}

// One request as directory.requests answers it.
type urDirectoryRequestItem struct {
	RequestId          sidecar.Id `json:"request_id"`
	RequesterSidecarId sidecar.Id `json:"requester_sidecar_id"`
	State              string     `json:"state"`
	Target             string     `json:"target"`
	Role               uint32     `json:"role"`
	Subject            sidecar.Id `json:"subject"`
	SubjectIsMember    bool       `json:"subject_is_member,omitempty"`
	FiledBy            uint32     `json:"filed_by"`
	NotAfterMillis     int64      `json:"not_after_millis"`
	Mine               bool       `json:"mine,omitempty"`
	Decidable          bool       `json:"decidable,omitempty"`
	Tainted            bool       `json:"tainted,omitempty"`
	// Prose, only when asked and after the taint.
	Reason string   `json:"reason,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// directory.requests's reply.
type urDirectoryRequestsReply struct {
	Requests  []*urDirectoryRequestItem `json:"requests"`
	Untrusted bool                      `json:"untrusted"`
	Withheld  int                       `json:"withheld"`
}

// The DirectoryRunClaims a claims value names.
func urDirectoryRunClaims(text string) (sidecar.DirectoryRunClaims, error) {
	return sidecar.ParseDirectoryRunClaims(text)
}

// This file's methods over target's networks, when it hosts them.
func urDirectoryCommandMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.daemon == nil {
		return nil
	}
	daemon := network.daemon
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodDirectoryRunsShow,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				resolution := daemon.ResolveClaims(ctx, call.Hello, call.NetworkId)
				return &sidecar.DaemonDirectoryClaimsReply{
					Claims: resolution.Claims.String(), Pending: resolution.Pending.String(), Source: resolution.Source, ProjectLabel: resolution.ProjectLabel,
				}, nil
			},
		},
		{
			// the member's value kept in the harness config (plan-RECORD-small-readings #11), off withdrawing the
			// project's running items at once; a value wider than the session's takes a confirmed call
			Name:    urMethodDirectoryRunsKeep,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryRunsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				claims, err := urDirectoryRunClaims(params.Claims)
				if err != nil {
					return nil, err
				}
				resolution := daemon.ResolveClaims(ctx, call.Hello, call.NetworkId)
				if int(resolution.Claims) < int(claims) && !call.Confirmed {
					return nil, errors.New("a runs value wider than the project's present one needs the person's confirmation")
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				err = client.SetRuns(ctx, resolution.ProjectKey, claims)
				if errors.Is(err, sidecar.ErrDirectoryRunsConfigUnavailable) {
					return &urDirectoryRunsKept{Reason: "the harness config's writer is not built yet (QD-577), so the member's value is kept on this device only"}, nil
				}
				if err != nil {
					return nil, err
				}
				return &urDirectoryRunsKept{Kept: true}, nil
			},
		},
		{
			Name:    urMethodDirectoryWorker,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryWorkerParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				setting := &sidecar.DirectoryWorkerSetting{On: params.On, Description: params.Description}
				switch params.Requests {
				case "":
				case "open":
					setting.Requests = sidecar.DirectoryRequestsOpen
				case "closed":
					setting.Requests = sidecar.DirectoryRequestsClosed
				default:
					return nil, errors.New("requests is open or closed")
				}
				if setting.On != nil || setting.Description != nil || setting.Requests != 0 {
					if err := client.SetWorker(ctx, setting); err != nil {
						return nil, err
					}
				}
				worker := client.Worker()
				if worker == nil {
					return nil, sidecar.ErrDirectoryWorkerHost
				}
				shown, err := worker.Shown()
				if err != nil {
					return nil, err
				}
				reply := &urDirectoryWorkerReply{On: shown.On, Description: shown.Description, Requests: "open"}
				if shown.Requests == sidecar.DirectoryRequestsClosed {
					reply.Requests = "closed"
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodDirectoryWithdraw,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryIdParams{}
				if err := decodeUrParams(call, params); err != nil || params.Id == (sidecar.Id{}) {
					return nil, errors.New("a withdrawal names its announcement")
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				err = client.Withdraw(params.Id)
				if errors.Is(err, sidecar.ErrDirectoryItemNone) {
					// a worker item of this device's goes as the worker's off does
					if worker := client.Worker(); worker != nil {
						if shown, shownErr := worker.Shown(); shownErr == nil && shown.AnnouncementId == params.Id {
							off := false
							err = client.SetWorker(ctx, &sidecar.DirectoryWorkerSetting{On: &off})
						}
					}
				}
				if err != nil {
					return nil, err
				}
				return map[string]bool{"withdrawn": true}, nil
			},
		},
		{
			Name:    urMethodDirectoryRequest,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryRequestParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if call.Sidecar.HarnessAncestor(ctx, urCallPid(call)) {
					return nil, errors.New("a person's request is refused under a harness process: an agent files through directory_request")
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				ask, err := urDirectoryRequestAsk(client, params, time.Now())
				if err != nil {
					return nil, err
				}
				return client.Request(ctx, ask)
			},
		},
		{
			Name:    urMethodDirectoryRequests,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryRequestsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				reply := &urDirectoryRequestsReply{Requests: []*urDirectoryRequestItem{}}
				if params.Untrusted == sidecar.DaemonDirectoryUntrustedInclude {
					pid := urCallPid(call)
					if pid <= 0 {
						return nil, errors.New("the caller's process cannot be read, so no untrusted text is returned")
					}
					if err := call.Sidecar.TaintAncestorRuns(ctx, pid); err != nil {
						return nil, fmt.Errorf("the caller's runs were not tainted, so no untrusted text is returned: %w", err)
					}
					reply.Untrusted = true
				}
				filter := &sidecar.DirectoryRequestFilter{Mine: params.Mine, Decidable: params.Incoming, RequestId: params.RequestId}
				states, err := urDirectoryRequestStates(params.State)
				if err != nil {
					return nil, err
				}
				filter.States = states
				views, err := client.GetRequests(ctx, filter)
				if err != nil {
					return nil, err
				}
				for _, view := range views {
					item := urDirectoryRequestItemOf(view)
					prose := []string{view.Request.GetReason()}
					for _, decision := range view.Decisions {
						if decision.Decision != nil {
							prose = append(prose, decision.Decision.GetNote())
						}
					}
					if reply.Untrusted {
						item.Reason = prose[0]
						for _, note := range prose[1:] {
							if note != "" {
								item.Notes = append(item.Notes, note)
							}
						}
					} else {
						for _, text := range prose {
							if text != "" {
								reply.Withheld += 1
							}
						}
					}
					reply.Requests = append(reply.Requests, item)
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodDirectoryCancel,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDirectoryIdParams{}
				if err := decodeUrParams(call, params); err != nil || params.Id == (sidecar.Id{}) {
					return nil, errors.New("a cancel names its request")
				}
				client, err := urDirectoryClientOf(call)
				if err != nil {
					return nil, err
				}
				if err := client.Cancel(ctx, params.Id); err != nil {
					return nil, err
				}
				return map[string]bool{"cancelled": true}, nil
			},
		},
	}
}

// DaemonDirectoryBackends.Decide: the call's Sidecar's decision, the daemon having run the method only for a confirmed
// call (RECORD-M6-19's protocol, which refuses while no statements seam is bound).
func urDirectoryDecideBackend(ctx context.Context, running *sidecar.Sidecar, args *sidecar.DirectoryDecideArgs) (any, error) {
	client := running.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", sidecar.ErrDirectoryNone)
	}
	return client.Decide(ctx, args)
}

// --state's values as the filter takes them: decided stands for approved, denied and cancelled.
func urDirectoryRequestStates(text string) ([]sidecar.DirectoryRequestState, error) {
	switch text {
	case "":
		return nil, nil
	case "decided":
		return []sidecar.DirectoryRequestState{sidecar.DirectoryRequestApproved, sidecar.DirectoryRequestDenied, sidecar.DirectoryRequestCancelled}, nil
	case string(sidecar.DirectoryRequestPending), string(sidecar.DirectoryRequestApproved), string(sidecar.DirectoryRequestDenied),
		string(sidecar.DirectoryRequestCancelled), string(sidecar.DirectoryRequestExpired):
		return []sidecar.DirectoryRequestState{sidecar.DirectoryRequestState(text)}, nil
	}
	return nil, fmt.Errorf("--state is pending, decided, approved, denied, cancelled or expired, not %q", text)
}

// A request's attested and identifier fields, its prose left out.
func urDirectoryRequestItemOf(view *sidecar.DirectoryRequestView) *urDirectoryRequestItem {
	item := &urDirectoryRequestItem{
		RequestId:          view.RequestId,
		RequesterSidecarId: view.RequesterSidecarId,
		State:              string(view.State),
		Role:               view.Request.GetRole(),
		SubjectIsMember:    view.Request.GetSubjectIsMember(),
		FiledBy:            view.Request.GetFiledBy(),
		NotAfterMillis:     view.Request.GetNotAfterMillis(),
		Mine:               view.Mine,
		Decidable:          view.Decidable,
		Tainted:            view.Request.GetTainted(),
	}
	if subject, err := sidecar.IdFromBytes(view.Request.GetSubject()); err == nil {
		item.Subject = subject
	}
	target := view.Request.GetTarget()
	switch {
	case len(target.GetRepoId()) != 0:
		if id, err := sidecar.IdFromBytes(target.GetRepoId()); err == nil {
			item.Target = "repo:" + id.String()
		}
	case len(target.GetSidecarId()) != 0:
		if id, err := sidecar.IdFromBytes(target.GetSidecarId()); err == nil {
			item.Target = "worker:" + id.String()
		}
	default:
		item.Target = "sock:" + view.NoticePath
	}
	return item
}

// A person's own request from params: its target resolved against the folded directory, a worker when an announced
// worker has the id and else a repo, unless params name which.
func urDirectoryRequestAsk(client *sidecar.DirectoryClient, params *urDirectoryRequestParams, now time.Time) (*sidecar.DirectoryRequestAsk, error) {
	ask := &sidecar.DirectoryRequestAsk{Reason: params.Reason, FiledBy: sidecar.DirectoryFiledByPerson, ForMember: params.Subject != "sidecar"}
	switch params.Subject {
	case "", "member", "sidecar":
	default:
		return nil, errors.New("--subject is member or sidecar")
	}
	if 0 < params.ForMillis {
		ask.GrantExpiresMillis = now.UnixMilli() + params.ForMillis
	}
	kind, text, _ := strings.Cut(params.Target, ":")
	if text == "" {
		kind, text = "", params.Target
	}
	if kind == "sock" {
		return nil, fmt.Errorf("%w: a socket's name token needs the network's socket key, which ur directory does not reach yet; nothing was filed", sidecar.ErrDaemonDirectoryUnbuilt)
	}
	id, err := sidecar.ParseId(text)
	if err != nil {
		return nil, errors.New("the target is repo:<id>, worker:<id>, an id, or sock:<name>")
	}
	if kind == "" {
		kind = "repo"
		workers, err := client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindWorker})
		if err != nil {
			return nil, err
		}
		for _, worker := range workers {
			if worker.SignerSidecarId == id {
				kind = "worker"
			}
		}
	}
	switch kind {
	case "repo":
		ask.Target = &protocol.RequestTarget{RepoId: id.Bytes()}
		switch params.Role {
		case "", "reader":
			ask.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER)
		case "writer":
			ask.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
		case "deposit":
			ask.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT)
		default:
			return nil, errors.New("--role is reader, writer or deposit for a repo")
		}
		if len(params.Ports) != 0 {
			return nil, errors.New("--ports names a worker's ports")
		}
	case "worker":
		ask.Target = &protocol.RequestTarget{SidecarId: id.Bytes(), TcpPorts: params.Ports}
		if params.Role != "" && params.Role != "dial" {
			return nil, errors.New("a worker's role is dial")
		}
		ask.Role = uint32(protocol.AclAction_ACL_ACTION_DIAL)
		// a reach grant's subject is always the spending sidecar
		ask.ForMember = false
	default:
		return nil, errors.New("the target is repo:<id>, worker:<id>, an id, or sock:<name>")
	}
	return ask, nil
}

// The network option, "" for the daemon's rule.
func urDirectoryNetwork(options docopt.Opts) string {
	return urOptionString(options, "--network")
}

// A duration option, as Go writes one, or a whole count of days with a d: 0 when absent.
func parseUrDirectoryDuration(options docopt.Opts, key string) (time.Duration, error) {
	text := urOptionString(options, key)
	if text == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(text, "d"); ok {
		count, err := strconv.ParseUint(days, 10, 32)
		if err == nil && 0 < count {
			return time.Duration(count) * 24 * time.Hour, nil
		}
	}
	duration, err := time.ParseDuration(text)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s is a duration such as 12h or 30d, not %q", key, text)
	}
	return duration, nil
}

// A comma list option, empty items dropped.
func urDirectoryList(options docopt.Opts, key string) []string {
	values := []string{}
	for _, value := range strings.Split(urOptionString(options, key), ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// An id argument.
func urDirectoryIdArgument(options docopt.Opts, key string) (sidecar.Id, error) {
	id, err := sidecar.ParseId(urOptionString(options, key))
	if err != nil {
		return sidecar.Id{}, fmt.Errorf("%s is an id", key)
	}
	return id, nil
}

// Runs the part the first word after directory names.
func runUrDirectory(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "ls"):
		return runUrDirectoryLs(ctx, cli, options)
	case urOptionBool(options, "show"):
		return runUrDirectoryShow(ctx, cli, options)
	case urOptionBool(options, "runs"):
		return runUrDirectoryRuns(ctx, cli, options)
	case urOptionBool(options, "worker"):
		return runUrDirectoryWorker(ctx, cli, options)
	case urOptionBool(options, "announce"):
		return runUrDirectoryAnnounce(ctx, cli, options)
	case urOptionBool(options, "revoke"):
		return runUrDirectoryRevoke(ctx, cli, options)
	case urOptionBool(options, "withdraw"):
		return runUrDirectoryWithdraw(ctx, cli, options)
	case urOptionBool(options, "erase"):
		return runUrDirectoryErase(ctx, cli, options)
	case urOptionBool(options, "request"):
		return runUrDirectoryRequest(ctx, cli, options)
	case urOptionBool(options, "requests"):
		return runUrDirectoryRequests(ctx, cli, options)
	case urOptionBool(options, "approve"), urOptionBool(options, "deny"):
		return runUrDirectoryDecide(ctx, cli, options)
	case urOptionBool(options, "cancel"):
		return runUrDirectoryCancel(ctx, cli, options)
	}
	return errors.New("ur directory takes ls, show, runs, worker, announce, revoke, withdraw, erase, request, requests, approve, deny or cancel")
}

// ls's params from its options: a non-terminal never asks for prose.
func urDirectoryLsParams(options docopt.Opts, terminal bool) (*sidecar.DaemonDirectoryListParams, error) {
	params := &sidecar.DaemonDirectoryListParams{
		Network: urDirectoryNetwork(options),
		Kind:    urOptionString(options, "--kind"),
		Active:  urOptionBool(options, "--active"),
		Query:   urOptionString(options, "--query"),
	}
	switch params.Kind {
	case "", "run", "worker", "repo":
	case "service":
		// a service is a worker's item
		params.Kind = "worker"
	default:
		return nil, errors.New("--kind is run, worker, repo or service")
	}
	if text := urOptionString(options, "--member"); text != "" {
		memberId, err := sidecar.ParseId(text)
		if err != nil {
			return nil, errors.New("--member is a member's id")
		}
		params.MemberId = &memberId
	}
	if text := urOptionString(options, "--repo"); text != "" {
		repoId, err := sidecar.ParseId(text)
		if err != nil {
			return nil, errors.New("--repo is a repo's id")
		}
		params.RepoId = &repoId
	}
	switch urOptionString(options, "--format") {
	case "", "text", "json":
	default:
		return nil, errors.New("--format is text or json")
	}
	if terminal {
		params.Untrusted = sidecar.DaemonDirectoryUntrustedInclude
	}
	return params, nil
}

// One item's line: its kind, display, who and its identifier fields, then on a terminal its prose.
func printUrDirectoryItem(cli *urCli, item *sidecar.DaemonDirectoryListItem, prose bool) {
	announcement := &protocol.Announcement{}
	if err := protojson.Unmarshal(item.Announcement, announcement); err != nil {
		cli.printf("%s %s: does not decode\n", item.Kind, item.AnnouncementId)
		return
	}
	who := "autogroup:admin"
	if item.MemberId != nil {
		who = "member " + item.MemberId.String()
	}
	line := fmt.Sprintf("%-6s %-10s %s  %s, sidecar %s", item.Kind, item.Display, item.AnnouncementId, who, item.WriterSidecarId)
	where := announcement.GetWhere()
	switch item.Kind {
	case "run":
		line += fmt.Sprintf(", agent %s (%s)", announcement.GetWho().GetAgentLabel(), announcement.GetWho().GetHarness())
		switch {
		case where.GetPrivate():
			if repoId, err := sidecar.IdFromBytes(where.GetRepoId()); err == nil {
				line += ", repo " + repoId.String() + " private"
			}
		case where.GetProject() != "":
			line += fmt.Sprintf(", %s on %s", where.GetProject(), where.GetBranch())
		}
	case "worker":
		names := []string{}
		for _, service := range announcement.GetWhat().GetServices() {
			names = append(names, service.GetName())
		}
		line += fmt.Sprintf(", host %s, services %s", where.GetHostLabel(), strings.Join(names, " "))
	case "repo":
		if repoId, err := sidecar.IdFromBytes(where.GetRepoId()); err == nil {
			line += ", repo " + repoId.String()
		}
		if 0 < len(announcement.GetWhat().GetTopics()) {
			line += ", topics " + strings.Join(announcement.GetWhat().GetTopics(), " ")
		}
	}
	if item.Tainted {
		line += ", tainted"
	}
	if 0 < len(item.Matches) {
		line += ", matched " + strings.Join(item.Matches, " ")
	}
	cli.printf("%s\n", line)
	if !prose {
		return
	}
	what := announcement.GetWhat()
	for _, text := range []string{what.GetTitle(), what.GetDescription()} {
		if text != "" {
			cli.printf("    untrusted: %q\n", text)
		}
	}
	for _, claim := range announcement.GetClaims() {
		if claim.GetText() != "" {
			cli.printf("    untrusted claim: %q\n", claim.GetText())
		}
	}
	if note := announcement.GetHandoff().GetNote(); note != "" {
		cli.printf("    untrusted handoff: %q\n", note)
	}
}

// ls: stubs on a non-terminal; on a terminal the daemon taints this ur's ancestor runs before answering prose.
func runUrDirectoryLs(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urDirectoryLsParams(options, urDirectoryStdoutIsTerminal(cli))
	if err != nil {
		return err
	}
	reply := &sidecar.DaemonDirectoryListReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDirectoryList, params, false, reply); err != nil {
		return err
	}
	return printUrDirectoryList(cli, reply, urOptionString(options, "--format") == "json")
}

// The listing as text or JSON.
func printUrDirectoryList(cli *urCli, reply *sidecar.DaemonDirectoryListReply, asJson bool) error {
	if asJson {
		encoded, err := json.MarshalIndent(reply, "", "  ")
		if err != nil {
			return err
		}
		cli.printf("%s\n", encoded)
		return nil
	}
	for _, item := range reply.Items {
		printUrDirectoryItem(cli, item, reply.Untrusted)
	}
	if !reply.Untrusted && 0 < reply.Withheld {
		cli.printf("%d prose field(s) withheld: untrusted text prints only on a terminal\n", reply.Withheld)
	}
	if len(reply.Items) == 0 {
		cli.printf("no announcement shows\n")
	}
	return nil
}

// show: every item of the id, which two writers may share, as ls prints them.
func runUrDirectoryShow(ctx context.Context, cli *urCli, options docopt.Opts) error {
	id, err := urDirectoryIdArgument(options, "<id>")
	if err != nil {
		return err
	}
	params, err := urDirectoryLsParams(docopt.Opts{"--network": urDirectoryNetwork(options)}, urDirectoryStdoutIsTerminal(cli))
	if err != nil {
		return err
	}
	reply := &sidecar.DaemonDirectoryListReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDirectoryList, params, false, reply); err != nil {
		return err
	}
	shown := &sidecar.DaemonDirectoryListReply{Untrusted: reply.Untrusted, Items: []*sidecar.DaemonDirectoryListItem{}}
	for _, item := range reply.Items {
		if item.AnnouncementId == id {
			shown.Items = append(shown.Items, item)
		}
	}
	if len(shown.Items) == 0 {
		return fmt.Errorf("no announcement %s shows", id)
	}
	return printUrDirectoryList(cli, shown, false)
}

// runs: with no value, the project's value now; with one, the choice (a wider one confirmed on /dev/tty), then the
// member's value kept, off withdrawing the project's running items.
func runUrDirectoryRuns(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urDirectoryNetwork(options)
	if project := urOptionString(options, "--project"); project != "" {
		info, err := os.Stat(project)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("--project is a project's directory")
		}
		cwd := cli.cwd
		cli.cwd = func() (string, error) { return project, nil }
		defer func() { cli.cwd = cwd }()
	}
	value := urOptionString(options, "<claims>")
	if value == "" {
		reply := &sidecar.DaemonDirectoryClaimsReply{}
		if err := cli.callDaemon(ctx, urMethodDirectoryRunsShow, &urDirectoryRunsParams{Network: network}, false, reply); err != nil {
			return err
		}
		printUrDirectoryClaims(cli, reply)
		return nil
	}
	if _, err := urDirectoryRunClaims(value); err != nil {
		return err
	}
	chosen, err := urDirectoryChooseClaims(ctx, cli, network, value)
	if err != nil {
		return err
	}
	printUrDirectoryClaims(cli, chosen)
	kept := &urDirectoryRunsKept{}
	if err := cli.callDaemon(ctx, urMethodDirectoryRunsKeep, &urDirectoryRunsParams{Network: network, Claims: value}, chosen.Source == sidecar.SidecarClaimsSourceConfirmed, kept); err != nil {
		return err
	}
	if !kept.Kept {
		cli.printf("%s\n", kept.Reason)
	}
	return nil
}

// A claims reply as the person reads it.
func printUrDirectoryClaims(cli *urCli, reply *sidecar.DaemonDirectoryClaimsReply) {
	project := reply.ProjectLabel
	if project == "" {
		project = "this project"
	}
	cli.printf("runs in %s: %s (%s)\n", project, reply.Claims, reply.Source)
	if reply.Pending != "" && reply.Pending != "off" && reply.Pending != reply.Claims {
		cli.printf(".ur asks for %s, which waits for your confirmation: ur directory runs %s\n", reply.Pending, reply.Pending)
	}
}

// worker's params from its options.
func urDirectoryWorkerParamsOf(options docopt.Opts) (*urDirectoryWorkerParams, error) {
	params := &urDirectoryWorkerParams{Network: urDirectoryNetwork(options), Requests: urOptionString(options, "--requests")}
	switch setting := urOptionString(options, "<setting>"); setting {
	case "":
	case "on", "off":
		on := setting == "on"
		params.On = &on
	default:
		return nil, errors.New("ur directory worker takes on or off")
	}
	if description, ok := options["--description"].(string); ok {
		params.Description = &description
	}
	switch params.Requests {
	case "", "open", "closed":
	default:
		return nil, errors.New("--requests is open or closed")
	}
	return params, nil
}

// worker: this host's worker item, by hand or from the script that provisions it (QD-115).
func runUrDirectoryWorker(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urDirectoryWorkerParamsOf(options)
	if err != nil {
		return err
	}
	reply := &urDirectoryWorkerReply{}
	if err := cli.callDaemon(ctx, urMethodDirectoryWorker, params, false, reply); err != nil {
		return err
	}
	state := "off"
	if reply.On {
		state = "on"
	}
	cli.printf("worker item: %s, requests %s\n", state, reply.Requests)
	return nil
}

// announce's params from its options.
func urDirectoryAnnounceParams(options docopt.Opts) (*sidecar.DaemonDirectoryAnnounceParams, error) {
	repoId, err := urDirectoryIdArgument(options, "<repo>")
	if err != nil {
		return nil, err
	}
	params := &sidecar.DaemonDirectoryAnnounceParams{
		Network:     urDirectoryNetwork(options),
		RepoId:      repoId,
		Description: urOptionString(options, "--description"),
		Topics:      urDirectoryList(options, "--topics"),
		Requests:    urOptionString(options, "--requests"),
	}
	switch params.Requests {
	case "", "open", "closed":
	default:
		return nil, errors.New("--requests is open or closed")
	}
	for _, role := range urDirectoryList(options, "--roles") {
		switch role {
		case "reader":
			params.Roles = append(params.Roles, uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
		case "writer":
			params.Roles = append(params.Roles, uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER))
		case "deposit":
			params.Roles = append(params.Roles, uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT))
		default:
			return nil, errors.New("--roles takes reader, writer and deposit")
		}
	}
	return params, nil
}

// announce repo: a full item, a person's act.
func runUrDirectoryAnnounce(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urDirectoryAnnounceParams(options)
	if err != nil {
		return err
	}
	reply := &sidecar.DaemonDirectoryAnnounceReply{}
	question := fmt.Sprintf("Announce repo %s in the team directory, its name and description to every member and agent?", params.RepoId)
	if err := urDirectoryConfirmedCall(ctx, cli, sidecar.DaemonMethodDirectoryAnnounce, params, question, reply); err != nil {
		return err
	}
	cli.printf("repo %s is announced\n", params.RepoId)
	for _, warning := range reply.Warnings {
		cli.printf("%s\n", warning)
	}
	return nil
}

// revoke: the private marker, then the erasure pending with its age until an ERASE names its request.
func runUrDirectoryRevoke(ctx context.Context, cli *urCli, options docopt.Opts) error {
	repoId, err := urDirectoryIdArgument(options, "<repo>")
	if err != nil {
		return err
	}
	params := &sidecar.DaemonDirectoryRevokeParams{Network: urDirectoryNetwork(options), RepoId: repoId}
	revocation := &sidecar.DirectoryRevocation{}
	question := fmt.Sprintf("Revoke repo %s's announcement, so the directory stops naming it and its copies are erased?", repoId)
	if err := urDirectoryConfirmedCall(ctx, cli, sidecar.DaemonMethodDirectoryRevoke, params, question, revocation); err != nil {
		return err
	}
	printUrDirectoryRevocation(cli, revocation)
	return nil
}

// A revocation as it stands.
func printUrDirectoryRevocation(cli *urCli, revocation *sidecar.DirectoryRevocation) {
	marker := "waits in the spool to be sealed"
	if revocation.MarkerEntryId != nil {
		marker = "entry " + revocation.MarkerEntryId.String()
	}
	cli.printf("repo %s: private marker version %d, %s\n", revocation.RepoId, revocation.MarkerVersion, marker)
	switch revocation.State {
	case sidecar.DirectoryRevocationDone:
		eraser := "a directory admin"
		if revocation.EraserSidecarId != nil {
			eraser = "directory admin " + revocation.EraserSidecarId.String()
		}
		cli.printf("erasure %s: done at %s by %s\n", revocation.RequestId, time.UnixMilli(revocation.ErasedMillis).UTC().Format(time.RFC3339), eraser)
	case sidecar.DirectoryRevocationLapsed:
		cli.printf("erasure %s: lapsed, the repo announced again above the marker\n", revocation.RequestId)
	default:
		cli.printf("erasure %s: pending for %s, until a directory admin's daemon erases the copies that name the repo\n", revocation.RequestId, revocation.Age.Truncate(time.Second))
	}
	for _, warning := range revocation.Warnings {
		cli.printf("%s\n", warning)
	}
}

// withdraw: this device's run or worker item, tombstoned; destroying keys is a directory admin's erasure.
func runUrDirectoryWithdraw(ctx context.Context, cli *urCli, options docopt.Opts) error {
	id, err := urDirectoryIdArgument(options, "<id>")
	if err != nil {
		return err
	}
	if err := cli.callDaemon(ctx, urMethodDirectoryWithdraw, &urDirectoryIdParams{Network: urDirectoryNetwork(options), Id: id}, false, nil); err != nil {
		return err
	}
	cli.printf("announcement %s is withdrawn; its earlier entries stay readable until retention or a directory admin's erasure\n", id)
	return nil
}

// erase: a directory admin's erasure of an announcement or an entry, a person's act.
func runUrDirectoryErase(ctx context.Context, cli *urCli, options docopt.Opts) error {
	id, err := urDirectoryIdArgument(options, "<id>")
	if err != nil {
		return err
	}
	params := &sidecar.DaemonDirectoryEraseParams{Network: urDirectoryNetwork(options), Id: id}
	result := &sidecar.DirectoryEraseResult{}
	question := fmt.Sprintf("Erase %s from the team directory? Its keys go for good.", id)
	if err := urDirectoryConfirmedCall(ctx, cli, sidecar.DaemonMethodDirectoryErase, params, question, result); err != nil {
		return err
	}
	reason := "a person's"
	if result.Reason == sidecar.RecordErasureReasonModeration {
		reason = "moderation, another sidecar's entries among them"
	}
	cli.printf("erasure %s: %d entries erased, reason %s\n", result.ErasureId, len(result.EntryIds), reason)
	return nil
}

// request's params from its options.
func urDirectoryRequestParamsOf(options docopt.Opts) (*urDirectoryRequestParams, error) {
	params := &urDirectoryRequestParams{
		Network: urDirectoryNetwork(options),
		Target:  urOptionString(options, "<target>"),
		Role:    urOptionString(options, "--role"),
		Reason:  urOptionString(options, "--reason"),
		Subject: urOptionString(options, "--subject"),
	}
	switch params.Subject {
	case "", "member", "sidecar":
	default:
		return nil, errors.New("--subject is member or sidecar")
	}
	for _, text := range urDirectoryList(options, "--ports") {
		port, err := strconv.ParseUint(text, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("--ports takes tcp ports, not %q", text)
		}
		params.Ports = append(params.Ports, uint32(port))
	}
	duration, err := parseUrDirectoryDuration(options, "--for")
	if err != nil {
		return nil, err
	}
	params.ForMillis = duration.Milliseconds()
	return params, nil
}

// request: a person's own request, filed_by person, confirmed on /dev/tty.
func runUrDirectoryRequest(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urDirectoryRequestParamsOf(options)
	if err != nil {
		return err
	}
	filed := &sidecar.DirectoryRequestFiled{}
	question := fmt.Sprintf("File a request for access to %s, signed as your own?", params.Target)
	if err := urDirectoryConfirmedCall(ctx, cli, urMethodDirectoryRequest, params, question, filed); err != nil {
		return err
	}
	cli.printf("request %s: pending until %s\n", filed.RequestId, time.UnixMilli(filed.NotAfterMillis).UTC().Format(time.RFC3339))
	if !filed.NoticeWritten {
		cli.printf("its notice is written at the next sync\n")
	}
	return nil
}

// requests' params from its options: a non-terminal never asks for prose.
func urDirectoryRequestsParamsOf(options docopt.Opts, terminal bool) (*urDirectoryRequestsParams, error) {
	params := &urDirectoryRequestsParams{
		Network:  urDirectoryNetwork(options),
		Mine:     urOptionBool(options, "--mine"),
		Incoming: urOptionBool(options, "--incoming"),
		State:    urOptionString(options, "--state"),
	}
	if _, err := urDirectoryRequestStates(params.State); err != nil {
		return nil, err
	}
	if terminal {
		params.Untrusted = sidecar.DaemonDirectoryUntrustedInclude
	}
	return params, nil
}

// requests: this device's own and the ones it decides, prose on a terminal only.
func runUrDirectoryRequests(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urDirectoryRequestsParamsOf(options, urDirectoryStdoutIsTerminal(cli))
	if err != nil {
		return err
	}
	reply := &urDirectoryRequestsReply{}
	if err := cli.callDaemon(ctx, urMethodDirectoryRequests, params, false, reply); err != nil {
		return err
	}
	for _, request := range reply.Requests {
		side := "incoming"
		if request.Mine {
			side = "mine"
		}
		cli.printf("%s %-9s %s, role %d, requester %s, %s\n", request.RequestId, request.State, request.Target, request.Role, request.RequesterSidecarId, side)
		if reply.Untrusted {
			if request.Reason != "" {
				cli.printf("    untrusted reason: %q\n", request.Reason)
			}
			for _, note := range request.Notes {
				cli.printf("    untrusted note: %q\n", note)
			}
		}
	}
	if !reply.Untrusted && 0 < reply.Withheld {
		cli.printf("%d prose field(s) withheld: untrusted text prints only on a terminal\n", reply.Withheld)
	}
	if len(reply.Requests) == 0 {
		cli.printf("no request shows\n")
	}
	return nil
}

// approve's or deny's params from its options; a narrowing to one sidecar names the request's requester, which the
// caller fills from the request.
func urDirectoryDecideParamsOf(options docopt.Opts, now time.Time) (*sidecar.DaemonDirectoryDecideParams, bool, error) {
	requestId, err := urDirectoryIdArgument(options, "<request>")
	if err != nil {
		return nil, false, err
	}
	params := &sidecar.DaemonDirectoryDecideParams{Network: urDirectoryNetwork(options), RequestId: requestId, Note: urOptionString(options, "--note")}
	duration, err := parseUrDirectoryDuration(options, "--for")
	if err != nil {
		return nil, false, err
	}
	if 0 < duration {
		params.GrantExpiresMillis = now.Add(duration).UnixMilli()
	}
	switch role := urOptionString(options, "--role"); role {
	case "":
	case "reader":
		params.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER)
	case "writer":
		params.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
	case "deposit":
		params.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT)
	default:
		return nil, false, errors.New("--role is reader, writer or deposit")
	}
	narrow := false
	switch urOptionString(options, "--subject") {
	case "", "member":
	case "sidecar":
		narrow = true
	default:
		return nil, false, errors.New("--subject is member or sidecar")
	}
	return params, narrow, nil
}

// approve or deny: a person's decision, confirmed on /dev/tty.
func runUrDirectoryDecide(ctx context.Context, cli *urCli, options docopt.Opts) error {
	approve := urOptionBool(options, "approve")
	params, narrow, err := urDirectoryDecideParamsOf(options, time.Now())
	if err != nil {
		return err
	}
	if narrow {
		reply := &urDirectoryRequestsReply{}
		if err := cli.callDaemon(ctx, urMethodDirectoryRequests, &urDirectoryRequestsParams{Network: params.Network, RequestId: &params.RequestId}, false, reply); err != nil {
			return err
		}
		if len(reply.Requests) != 1 {
			return fmt.Errorf("no request %s shows here", params.RequestId)
		}
		requesterId := reply.Requests[0].RequesterSidecarId
		params.ForSidecarId = &requesterId
	}
	method, verb := sidecar.DaemonMethodDirectoryDeny, "Deny"
	if approve {
		method, verb = sidecar.DaemonMethodDirectoryApprove, "Approve"
	}
	decided := &sidecar.DirectoryDecided{}
	question := fmt.Sprintf("%s request %s?", verb, params.RequestId)
	if err := urDirectoryConfirmedCall(ctx, cli, method, params, question, decided); err != nil {
		return err
	}
	ended := decided.Ended
	if ended == "" {
		ended = "the notice's rewrite waits for this device's decision entry to land"
	}
	cli.printf("request %s: %s\n", params.RequestId, ended)
	return nil
}

// cancel: the requester's own request, by its decision entry with outcome cancelled and the notice's removal.
func runUrDirectoryCancel(ctx context.Context, cli *urCli, options docopt.Opts) error {
	requestId, err := urDirectoryIdArgument(options, "<request>")
	if err != nil {
		return err
	}
	if err := cli.callDaemon(ctx, urMethodDirectoryCancel, &urDirectoryIdParams{Network: urDirectoryNetwork(options), Id: requestId}, false, nil); err != nil {
		return err
	}
	cli.printf("request %s is cancelled; after an approval, cancelling is a GrantRevoke or RepoRevoke\n", requestId)
	return nil
}
