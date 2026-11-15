// ur admin (TEAM-M2-18, TEAM-M10-01, TEAM-M6-08; §7.8, D-TEAM-7, D-CORE-13): one command whose parts register
// themselves, so an area adds a part without touching a shared list (C-21). The config parts, agents, delegations and
// versioning (cmd_admin_agents.go), sign through the daemon's sidecarAct, confirmed on /dev/tty. The Team parts here
// run each server command with ur-cli's one-command admin token, DPoP-bound and used once, from a consent the person
// matched in the browser by its code: loopback PKCE, or with --device RFC 8628's device grant (urcli_token.go,
// cmd_login_device.go). A token never runs a second command, and ur-cli drops it and its key at once:
//
//	ur admin members [list]                     GET /network/members, its first page
//	ur admin members invite <email>             POST /network/member-invite; the bearer is printed, and the link's
//	                                            client-only fragment, which the inviting device appends, is not yet
//	ur admin members remove <member_id>         the MemberRevoke's plan from the verified log, confirmed on
//	                                            /dev/tty; then POST /network/member-remove, the server's denial at
//	                                            once; then the MemberRevoke the daemon signs, which is the removal
//	                                            (§7.10): an AdminSet member's as a proposal its cosigns complete
//	ur admin oauth-clients [list]               GET /network/oauth-clients
//	ur admin oauth-clients create --scopes=...  POST /network/oauth-clients, its secret printed once
//	ur admin oauth-clients revoke <id>          POST /network/oauth-client-revoke
//	ur admin scim-changes                       GET /network/scim-changes, its first page
//
// Nothing here runs from MCP or a hook (D-CORE-13), and nothing here prints a token: the OAuth client's secret, shown
// once for the person to give CI, is the one credential any part prints.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// One part of ur admin: the word after admin that selects it, its docopt usage lines, and its run.
type urAdminPart struct {
	word  string
	usage []string
	run   func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// Every part, in registration order. Written only by registerUrAdminPart, during package initialization.
var urAdminParts = []*urAdminPart{}

// Adds a part. Called from a package variable's initializer, so every part is in before init registers the command;
// a word registered twice is a programming error, found at start.
func registerUrAdminPart(part *urAdminPart) bool {
	if part == nil || part.word == "" || part.run == nil || slices.ContainsFunc(urAdminParts, func(other *urAdminPart) bool { return other.word == part.word }) {
		panic(fmt.Sprintf("ur admin part %q registered twice or without a run", part.word))
	}
	urAdminParts = append(urAdminParts, part)
	return true
}

func init() {
	usage := []string{}
	words := []string{}
	for _, part := range urAdminParts {
		usage = append(usage, part.usage...)
		words = append(words, part.word)
	}
	registerUrCommand(&urCommand{
		name:    "admin",
		usage:   strings.Join(usage, "\n"),
		summary: "a network admin's acts: " + strings.Join(words, ", ") + "; config acts confirmed on the terminal, Team commands by a one-command admin token",
		run:     runUrAdmin,
	})
}

// Runs the part of ur admin its first word names.
func runUrAdmin(ctx context.Context, cli *urCli, options docopt.Opts) error {
	words := []string{}
	for _, part := range urAdminParts {
		if urOptionBool(options, part.word) {
			return part.run(ctx, cli, options)
		}
		words = append(words, part.word)
	}
	return fmt.Errorf("ur admin takes %s", strings.Join(words, ", "))
}

// A docopt flag or command word, false when absent.
func urOptionBool(options docopt.Opts, key string) bool {
	value, _ := options.Bool(key)
	return value
}

// The Team parts.
var (
	_ = registerUrAdminPart(&urAdminPart{
		word: "members",
		usage: []string{
			"  ur admin members [list] [--device]",
			"  ur admin members invite <email> [--role=<role>] [--expire-days=<days>] [--device]",
			"  ur admin members remove <member_id> [--device]",
		},
		run: runUrAdminMembers,
	})
	_ = registerUrAdminPart(&urAdminPart{
		word: "oauth-clients",
		usage: []string{
			"  ur admin oauth-clients [list] [--device]",
			"  ur admin oauth-clients create --scopes=<scopes> [--device]",
			"  ur admin oauth-clients revoke <oauth_client_id> [--device]",
		},
		run: runUrAdminOauthClients,
	})
	_ = registerUrAdminPart(&urAdminPart{
		word:  "scim-changes",
		usage: []string{"  ur admin scim-changes [--device]"},
		run:   runUrAdminScimChanges,
	})
)

// The control methods ur admin members remove calls.
const (
	urMethodAdminMemberPlan = "admin.members.plan"
	urMethodAdminMemberAct  = "admin.members.act"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminMemberMethods)
}

// Runs one Team command with an admin token got for it alone, by PKCE or with device the device grant, and answers
// the command's body. The token and its DPoP key are dropped before this returns. Tests replace it.
var urAdminRunCommand = func(ctx context.Context, cli *urCli, command *sidecar.AdminCommand, device bool) ([]byte, error) {
	if device {
		env, err := newUrcliDeviceEnv(cli)
		if err != nil {
			return nil, err
		}
		grant, err := urcliDeviceToken(ctx, env, command)
		if err != nil {
			return nil, err
		}
		defer grant.erase()
		return urcliRunCommand(ctx, env.urcliEnv, grant)
	}
	env, err := newUrcliEnv(cli)
	if err != nil {
		return nil, err
	}
	grant, err := urcliAdminToken(ctx, env, command)
	if err != nil {
		return nil, err
	}
	defer grant.erase()
	return urcliRunCommand(ctx, env, grant)
}

// A command whose body is value's JSON, nil for none.
func urAdminCommand(method string, path string, value any) (*sidecar.AdminCommand, error) {
	command := &sidecar.AdminCommand{Method: method, Path: path}
	if value != nil {
		body, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		command.Body = body
	}
	return command, nil
}

// A route model's refusal of a Team command, its fixed text, which names no credential.
type urAdminRefusal struct {
	message string
}

// The refusal's text, as ur prints it.
func (self *urAdminRefusal) Error() string {
	return "refused: " + self.message
}

// The server's text for a member it holds no membership of (model.ErrNetworkMemberNotFound): already denied, by an
// earlier removal or SCIM.
const urAdminNoSuchMember = "No such member of the team."

// Runs a Team command and decodes its answer into result; a route's model refusal, {error: {message}}, is a
// *urAdminRefusal.
func urAdminRun(ctx context.Context, cli *urCli, options docopt.Opts, command *sidecar.AdminCommand, result any) error {
	body, err := urAdminRunCommand(ctx, cli, command, urOptionBool(options, "--device"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("the answer to %s %s does not parse", command.Method, command.Path)
	}
	refusal := &struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}{}
	if json.Unmarshal(body, refusal) == nil && refusal.Error != nil {
		return &urAdminRefusal{message: refusal.Error.Message}
	}
	return nil
}

// ur admin members.
func runUrAdminMembers(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "invite"):
		email, _ := options.String("<email>")
		role, _ := options.String("--role")
		if role == "" {
			role = "member"
		}
		expireDays := 7
		if text, _ := options.String("--expire-days"); text != "" {
			if _, err := fmt.Sscanf(text, "%d", &expireDays); err != nil {
				return fmt.Errorf("--expire-days takes a number of days: %q", text)
			}
		}
		command, err := urAdminCommand("POST", "/network/member-invite", map[string]any{"email": email, "role": role, "expire_days": expireDays})
		if err != nil {
			return err
		}
		result := &struct {
			InviteId     string    `json:"invite_id"`
			InviteBearer string    `json:"invite_bearer"`
			ExpireTime   time.Time `json:"expire_time"`
		}{}
		if err := urAdminRun(ctx, cli, options, command, result); err != nil {
			return err
		}
		cli.printf("invite %s for %s as %s, until %s\n", result.InviteId, email, role, result.ExpireTime.UTC().Format(time.RFC3339))
		cli.printf("its bearer, for the person alone: %s\n", result.InviteBearer)
		cli.printf("the link's fragment, which lets the person's first device be admitted from the invite, is not appended yet\n")
		return nil
	case urOptionBool(options, "remove"):
		return runUrAdminMemberRemove(ctx, cli, options)
	}
	command, err := urAdminCommand("GET", "/network/members", nil)
	if err != nil {
		return err
	}
	result := &struct {
		Members []struct {
			MemberId string  `json:"member_id"`
			Email    *string `json:"email"`
			Role     string  `json:"role"`
			Pending  bool    `json:"pending"`
		} `json:"members"`
		More bool `json:"more"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	for _, member := range result.Members {
		email := ""
		if member.Email != nil {
			email = *member.Email
		}
		line := fmt.Sprintf("%s %s %s", member.MemberId, member.Role, email)
		if member.Pending {
			line += " (pending)"
		}
		cli.printf("%s\n", strings.TrimSpace(line))
	}
	if result.More {
		cli.printf("more members follow; the console lists them all\n")
	}
	return nil
}

// What ur admin members remove asks of a target hosting a Sidecar.
type urAdminMembersTarget interface {
	planMemberRevoke(memberId sidecar.Id) (*sidecar.MemberRevokePlan, error)
	signMemberRevoke(ctx context.Context, memberId sidecar.Id) (*sidecar.MemberRevocation, error)
}

func (self *urDaemonNetwork) planMemberRevoke(memberId sidecar.Id) (*sidecar.MemberRevokePlan, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PlanMemberRevoke(memberId)
}

// A confirmed control call, the person having answered on /dev/tty. The daemon's presence prompt is §16's, so an act
// the log covers is refused until it lands, never signed without the check.
func (self *urDaemonNetwork) signMemberRevoke(ctx context.Context, memberId sidecar.Id) (*sidecar.MemberRevocation, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.SignMemberRevoke(ctx, memberId, sidecar.SidecarActConfirmed, nil)
}

// admin.members.plan's and admin.members.act's params.
type urMemberRevokeParams struct {
	MemberId sidecar.Id `json:"member_id"`
}

// A plan as the methods answer it: ids and counts, never a secret.
type urMemberRevokePlanReply struct {
	MemberId      sidecar.Id   `json:"member_id"`
	Role          string       `json:"role"`
	AdminSet      bool         `json:"admin_set,omitempty"`
	Signatures    int          `json:"signatures"`
	DeviceIds     []sidecar.Id `json:"device_ids"`
	AgentIds      []sidecar.Id `json:"agent_ids"`
	ReposRotating []sidecar.Id `json:"repos_rotating"`
}

// What admin.members.act answers.
type urMemberRevokeActReply struct {
	EntryVersion uint64 `json:"entry_version,omitempty"`
	ProposalId   string `json:"proposal_id,omitempty"`
	Pending      bool   `json:"pending,omitempty"`
}

// The members methods over target, when it hosts a Sidecar.
func urAdminMemberMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	members, ok := target.(urAdminMembersTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodAdminMemberPlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urMemberRevokeParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				plan, err := members.planMemberRevoke(params.MemberId)
				if err != nil {
					return nil, err
				}
				return &urMemberRevokePlanReply{
					MemberId:      plan.MemberId,
					Role:          strings.ToLower(strings.TrimPrefix(plan.Role.String(), "MEMBER_ROLE_")),
					AdminSet:      plan.AdminSet,
					Signatures:    plan.Signatures,
					DeviceIds:     plan.DeviceIds,
					AgentIds:      plan.AgentIds,
					ReposRotating: plan.ReposRotating,
				}, nil
			},
		},
		{
			Name:    urMethodAdminMemberAct,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urMemberRevokeParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				revocation, err := members.signMemberRevoke(ctx, params.MemberId)
				if revocation == nil {
					return nil, err
				}
				reply := &urMemberRevokeActReply{Pending: revocation.Pending}
				if revocation.Entry != nil {
					reply.EntryVersion = revocation.Entry.GetVersion()
				}
				if revocation.ProposalId != nil {
					reply.ProposalId = fmt.Sprintf("%x", revocation.ProposalId)
				}
				return reply, err
			},
		},
	}
}

// The plan's lines, as the terminal shows them before the person answers.
func urMemberRevokePlanLines(plan *urMemberRevokePlanReply) []string {
	ids := func(values []sidecar.Id) string {
		texts := []string{}
		for _, value := range values {
			texts = append(texts, value.String())
		}
		return strings.Join(texts, ",")
	}
	lines := []string{fmt.Sprintf("remove member %s (%s)", plan.MemberId, plan.Role)}
	if plan.AdminSet {
		lines = append(lines, fmt.Sprintf("  in the admin set: %d of the admins' signatures, this device's the first; the rest cosign", plan.Signatures))
	}
	lines = append(lines, fmt.Sprintf("  its %d device(s) are revoked: %s", len(plan.DeviceIds), ids(plan.DeviceIds)))
	if 0 < len(plan.AgentIds) {
		lines = append(lines, fmt.Sprintf("  its %d tagged agent(s) stay with their tags' grants, autogroup:admin their sponsor until a SponsorSet: %s",
			len(plan.AgentIds), ids(plan.AgentIds)))
	}
	lines = append(lines, fmt.Sprintf("  %d repo(s) need a new generation before the next write: %s", len(plan.ReposRotating), ids(plan.ReposRotating)))
	lines = append(lines, "  the server denies the member at once; the signed MemberRevoke is the removal")
	return lines
}

// ur admin members remove: the plan on the terminal; on a yes, the server's denial, then the MemberRevoke.
func runUrAdminMemberRemove(ctx context.Context, cli *urCli, options docopt.Opts) error {
	text, _ := options.String("<member_id>")
	memberId, err := sidecar.ParseId(text)
	if err != nil {
		return fmt.Errorf("a member is its member_id: %q", text)
	}
	params := &urMemberRevokeParams{MemberId: memberId}
	plan := &urMemberRevokePlanReply{}
	if err := cli.callDaemon(ctx, urMethodAdminMemberPlan, params, false, plan); err != nil {
		return err
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	for _, line := range urMemberRevokePlanLines(plan) {
		fmt.Fprintln(tty, line)
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "remove the member?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	command, err := urAdminCommand("POST", "/network/member-remove", map[string]any{"member_id": memberId.String()})
	if err != nil {
		return err
	}
	denied := &struct {
		DeactivatedClientCount int64 `json:"deactivated_client_count"`
	}{}
	err = urAdminRun(ctx, cli, options, command, denied)
	refusal := &urAdminRefusal{}
	switch {
	case errors.As(err, &refusal) && refusal.message == urAdminNoSuchMember:
		// denied already, by an earlier removal or SCIM's active=false: the signature is what is owed
		cli.printf("the server had denied member %s already\n", memberId)
	case err != nil:
		return err
	default:
		cli.printf("the server denied member %s, %d client(s) deactivated\n", memberId, denied.DeactivatedClientCount)
	}
	act := &urMemberRevokeActReply{}
	if err := cli.callDaemon(ctx, urMethodAdminMemberAct, params, true, act); err != nil {
		return fmt.Errorf("the MemberRevoke is still owed, and members still encrypt to the member's devices: %w", err)
	}
	switch {
	case act.ProposalId != "":
		cli.printf("the MemberRevoke is proposed (%s): other admins cosign it\n", act.ProposalId)
	case act.Pending:
		cli.printf("the MemberRevoke is signed; its post goes again\n")
	default:
		cli.printf("the MemberRevoke landed at %d\n", act.EntryVersion)
	}
	return nil
}

// ur admin oauth-clients.
func runUrAdminOauthClients(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "create"):
		scopesText, _ := options.String("--scopes")
		scopes := []string{}
		for _, scope := range strings.Split(scopesText, ",") {
			if scope = strings.TrimSpace(scope); scope != "" {
				scopes = append(scopes, scope)
			}
		}
		command, err := urAdminCommand("POST", "/network/oauth-clients", map[string]any{"scopes": scopes})
		if err != nil {
			return err
		}
		result := &struct {
			ClientId     string   `json:"client_id"`
			ClientSecret string   `json:"client_secret"`
			Scopes       []string `json:"scopes"`
		}{}
		if err := urAdminRun(ctx, cli, options, command, result); err != nil {
			return err
		}
		cli.printf("client_id %s, scopes %s\n", result.ClientId, strings.Join(result.Scopes, ","))
		cli.printf("client_secret, shown once, for CI alone: %s\n", result.ClientSecret)
		return nil
	case urOptionBool(options, "revoke"):
		text, _ := options.String("<oauth_client_id>")
		oauthClientId, err := sidecar.ParseId(text)
		if err != nil {
			return fmt.Errorf("an OAuth client is its oauth_client_id: %q", text)
		}
		command, err := urAdminCommand("POST", "/network/oauth-client-revoke", map[string]any{"oauth_client_id": oauthClientId.String()})
		if err != nil {
			return err
		}
		if err := urAdminRun(ctx, cli, options, command, &struct{}{}); err != nil {
			return err
		}
		cli.printf("revoked %s: its live tokens stop at their next request\n", oauthClientId)
		return nil
	}
	command, err := urAdminCommand("GET", "/network/oauth-clients", nil)
	if err != nil {
		return err
	}
	result := &struct {
		OauthClients []struct {
			OauthClientId   string   `json:"oauth_client_id"`
			ClientId        string   `json:"client_id"`
			Scopes          []string `json:"scopes"`
			CreatorMemberId string   `json:"creator_member_id"`
		} `json:"oauth_clients"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	for _, client := range result.OauthClients {
		cli.printf("%s %s %s by %s\n", client.OauthClientId, client.ClientId, strings.Join(client.Scopes, ","), client.CreatorMemberId)
	}
	return nil
}

// ur admin scim-changes.
func runUrAdminScimChanges(ctx context.Context, cli *urCli, options docopt.Opts) error {
	command, err := urAdminCommand("GET", "/network/scim-changes", nil)
	if err != nil {
		return err
	}
	result := &struct {
		Changes []struct {
			ChangeId   string    `json:"change_id"`
			MemberId   *string   `json:"member_id"`
			Kind       string    `json:"kind"`
			CreateTime time.Time `json:"create_time"`
		} `json:"changes"`
		More bool `json:"more"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	for _, change := range result.Changes {
		line := fmt.Sprintf("%s %s %s", change.ChangeId, change.Kind, change.CreateTime.UTC().Format(time.RFC3339))
		if change.MemberId != nil {
			line += " member " + *change.MemberId
		}
		cli.printf("%s\n", line)
	}
	if result.More {
		cli.printf("more changes follow; the console lists them all\n")
	}
	if 0 < len(result.Changes) {
		cli.printf("a member_revoke's MemberRevoke is owed: ur admin members remove <member_id> signs it\n")
	}
	return nil
}
