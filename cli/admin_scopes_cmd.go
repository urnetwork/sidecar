// ur admin scopes (QD-1163; §7.9's ServiceSettings, §8.8, §12.5, §13.8; owner decisions 40, 58, 126):
//
//	ur admin scopes [list] [--network=<network>]
//	ur admin scopes add <label> (--member=<member> | --tag=<tag>) [--network=<network>]
//
// list prints the Team scopes the newest verified base holds, each label with its member or tag atom: what every
// reader of a scope takes, and nothing else, so a binding a head declared shows once a base holds it. add creates a
// label's first binding to a member, by its member_id, or to a tag, by its name: it shows what it binds and that a
// first binding never changes, then signs, only after a yes on /dev/tty, through a Confirm method: the daemon files the
// binding into the config head's ServiceSettings, the head's other settings kept, from an Owner's or Admin's device that
// runs the network's config writer (sidecar.SaveTeamScope), and refuses any other device, a label §12.5 refuses, a client
// name or published host, a label bound already and an owner holding one, before it signs anything. Reassignment is not
// offered: it waits for a consented-member transition rule (DESIGN-DEFER.md). The daemon refuses a caller with a
// harness process among its ancestors, by the pid it read off the socket, and no MCP tool reaches any of it.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur admin scopes calls.
const (
	urMethodAdminScopesShow = "admin.scopes.show"
	urMethodAdminScopesAdd  = "admin.scopes.add"
)

var _ = registerUrAdminPart(&urAdminPart{
	word: "scopes",
	usage: []string{
		"  ur admin scopes [list] [--network=<network>]",
		"  ur admin scopes add <label> (--member=<member> | --tag=<tag>) [--network=<network>]",
	},
	run: runUrAdminScopes,
})

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminScopesMethods)
}

// What the methods take.
type urAdminScopesParams struct {
	Network string `json:"network,omitempty"`
	Label   string `json:"label,omitempty"`
	// The member's member_id, or the tag's name: one of them.
	Member string `json:"member,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

// One scope as the methods answer it, ids as text.
type urAdminScope struct {
	Label    string `json:"label"`
	MemberId string `json:"member_id,omitempty"`
	TagId    string `json:"tag_id,omitempty"`
}

type urAdminScopesReply struct {
	Scopes []*urAdminScope `json:"scopes"`
}

// A scope as the methods answer it.
func urAdminScopeOf(scope sidecar.AclScope) *urAdminScope {
	row := &urAdminScope{Label: scope.Label}
	if scope.MemberId != (sidecar.Id{}) {
		row.MemberId = scope.MemberId.String()
	} else {
		row.TagId = scope.TagId.String()
	}
	return row
}

// The binding the params ask for: a label and exactly one owner, the member by its member_id.
func urAdminScopeBindingOf(params *urAdminScopesParams) (*sidecar.TeamScopeBinding, error) {
	if params.Label == "" || (params.Member == "") == (params.Tag == "") {
		return nil, errors.New("ur admin scopes add takes a label and one of --member or --tag")
	}
	binding := &sidecar.TeamScopeBinding{Label: params.Label, Tag: params.Tag}
	if params.Member != "" {
		memberId, err := sidecar.ParseId(params.Member)
		if err != nil || memberId == (sidecar.Id{}) {
			return nil, fmt.Errorf("--member takes a member_id: %q", params.Member)
		}
		binding.MemberId = memberId
	}
	return binding, nil
}

// The admin scopes methods over target's networks, when it hosts them.
func urAdminScopesMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if network, ok := target.(*urDaemonNetwork); !ok || network.daemon == nil {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodAdminScopesShow,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				scopes, err := call.Sidecar.TeamScopes()
				if err != nil {
					return nil, err
				}
				reply := &urAdminScopesReply{Scopes: []*urAdminScope{}}
				for _, scope := range scopes {
					reply.Scopes = append(reply.Scopes, urAdminScopeOf(scope))
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodAdminScopesAdd,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urAdminScopesParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if call.Sidecar.HarnessAncestor(ctx, urCallPid(call)) {
					return nil, errors.New("ur admin scopes is refused under a harness process")
				}
				binding, err := urAdminScopeBindingOf(params)
				if err != nil {
					return nil, err
				}
				// a person confirmed it on /dev/tty, which the Confirm method holds the call to
				filed, err := call.Sidecar.SaveTeamScope(ctx, binding, sidecar.SidecarActConfirmed)
				if err != nil {
					return nil, err
				}
				return &urAdminScopesReply{Scopes: []*urAdminScope{urAdminScopeOf(filed)}}, nil
			},
		},
	}
}

// A scope's line as ur prints it.
func urAdminScopeLine(scope *urAdminScope) string {
	if scope.MemberId != "" {
		return fmt.Sprintf("%s member %s", scope.Label, scope.MemberId)
	}
	return fmt.Sprintf("%s tag %s", scope.Label, scope.TagId)
}

// Lists the verified base's scopes, or files a first binding after a yes on /dev/tty.
func runUrAdminScopes(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urAdminScopesParams{Network: urOptionString(options, "--network")}
	if !urOptionBool(options, "add") {
		reply := &urAdminScopesReply{}
		if err := cli.callDaemon(ctx, urMethodAdminScopesShow, params, false, reply); err != nil {
			return err
		}
		if len(reply.Scopes) == 0 {
			cli.printf("no Team scope: the network's verified base binds none\n")
		}
		for _, scope := range reply.Scopes {
			cli.printf("%s\n", urAdminScopeLine(scope))
		}
		return nil
	}
	params.Label = urOptionString(options, "<label>")
	params.Member = urOptionString(options, "--member")
	params.Tag = urOptionString(options, "--tag")
	binding, err := urAdminScopeBindingOf(params)
	if err != nil {
		return err
	}
	owner := "tag " + binding.Tag
	if binding.MemberId != (sidecar.Id{}) {
		owner = "member " + binding.MemberId.String()
	}
	cli.printf("bind Team scope %s to %s: its hosts, certificates and mail go to that owner's devices, and a label's first "+
		"binding never changes; reassignment waits for its consent rule\n", binding.Label, owner)
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Sign the network's ServiceSettings binding %s?", binding.Label))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: nothing was signed")
	}
	reply := &urAdminScopesReply{}
	if err := cli.callDaemon(ctx, urMethodAdminScopesAdd, params, true, reply); err != nil {
		return err
	}
	for _, scope := range reply.Scopes {
		cli.printf("filed %s; readers take it once a base holds the head\n", urAdminScopeLine(scope))
	}
	return nil
}
