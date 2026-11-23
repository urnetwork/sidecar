// ur admin (TEAM-M2-18, TEAM-M10-01, TEAM-M6-08; §7.8, D-TEAM-7, D-CORE-13): one command whose parts register
// themselves, so an area adds a part without touching a shared list (C-21). The config parts, agents, delegations and
// versioning (cmd_admin_agents.go), sign through the daemon's sidecarAct, confirmed on /dev/tty. The Team parts here
// run each server command with ur-cli's one-command admin token, DPoP-bound and used once, from a consent the person
// matched in the browser by its code: loopback PKCE, or with --device RFC 8628's device grant (urcli_token.go,
// cmd_login_device.go). A token never runs a second command, and ur-cli drops it and its key at once:
//
//	ur admin members [list] [--after=]          GET /network/members, a page: the first, or with --after the one past
//	                                            that member_id, which the command's signed body names, since the
//	                                            command covers no query, each page its own authorization (QD-1162)
//	ur admin members invite <email>             POST /network/member-invite; the bearer is printed, and the link's
//	                                            client-only fragment, which the inviting device appends, is not yet
//	ur admin members remove <member_id>         the MemberRevoke's plan from the verified log, confirmed on
//	                                            /dev/tty; then POST /network/member-remove, the server's denial at
//	                                            once, the member's auth keys among what it ends, with the server's
//	                                            note when a pre-approved key's bundle still admits (QD-1211); then
//	                                            the MemberRevoke the daemon signs, which is the removal (§7.10): an
//	                                            AdminSet member's as a proposal its cosigns complete
//	ur admin oauth-clients [list]               GET /network/oauth-clients
//	ur admin oauth-clients create --scopes=...  POST /network/oauth-clients, its secret printed once
//	ur admin oauth-clients revoke <id>          POST /network/oauth-client-revoke
//	ur admin scim-changes                       GET /network/scim-changes, its first page
//	ur admin idp add --issuer= --client-id=     POST /network/idp, a private_key_jwt IdP; a client_secret IdP is
//	                                            refused here, before any consent, since the authorization URL and
//	                                            the consent page carry the command's body: the console adds it
//	ur admin domains add|verify|remove <domain> POST /network/domain-add, domain-verify, domain-remove
//	ur admin audit-webhook [list]               POST /network/audit-webhook {}, the team's SIEM webhooks
//	ur admin audit-webhook add <url>            POST /network/audit-webhook {url}, its signing key printed once
//	ur admin audit-webhook remove <id>          POST /network/audit-webhook {remove_webhook_id}
//	ur admin events                             GET /network/admin-events: the oldest page kept, since a command
//	                                            covers no query, with the page's chain head
//
// Nothing here runs from MCP or a hook (D-CORE-13), and nothing here prints a token. The credentials a part prints are
// each shown once, for the one who needs it: an invite's bearer for the person invited, an OAuth client's secret for
// CI and a webhook's signing key for its receiver. A replay's answer carries none of them, since the server never
// keeps them, and the part says how to make another.

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
			"  ur admin members [list] [--after=<after>] [--device]",
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
	_ = registerUrAdminPart(&urAdminPart{
		word:  "idp",
		usage: []string{"  ur admin idp add --issuer=<issuer> --client-id=<client_id> [--client-auth=<client_auth>] [--device]"},
		run:   runUrAdminIdp,
	})
	_ = registerUrAdminPart(&urAdminPart{
		word: "domains",
		usage: []string{
			"  ur admin domains add <domain> [--device]",
			"  ur admin domains verify <domain> [--device]",
			"  ur admin domains remove <domain> [--device]",
		},
		run: runUrAdminDomains,
	})
	_ = registerUrAdminPart(&urAdminPart{
		word: "audit-webhook",
		usage: []string{
			"  ur admin audit-webhook [list] [--device]",
			"  ur admin audit-webhook add <webhook_url> [--device]",
			"  ur admin audit-webhook remove <webhook_id> [--device]",
		},
		run: runUrAdminAuditWebhook,
	})
	_ = registerUrAdminPart(&urAdminPart{
		word:  "events",
		usage: []string{"  ur admin events [--device]"},
		run:   runUrAdminEvents,
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

// The member directory's page command (QD-1162): GET /network/members, whose one-command admin token binds the method,
// the query-free path and the canonical body, so a page past the first names the member_id it reads after in the body,
// inside the consent's digest. The first page's carries no body. The body names nothing else, no email among it.
func urAdminMembersPageCommand(after sidecar.Id) (*sidecar.AdminCommand, error) {
	if after == (sidecar.Id{}) {
		return urAdminCommand("GET", "/network/members", nil)
	}
	return urAdminCommand("GET", "/network/members", map[string]string{"after": after.String()})
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

// What ur says when a member's removal revoked a pre-approved auth key (D-TEAM-31): revoking stops the key's bearer
// only.
const urAdminMemberRemoveBundleNote = "a revoked auth key was pre-approved: a copy of its bundle still admits devices until its Delegation ends; `ur admin delegations` lists it, and `ur admin delegations revoke <delegation_id>` ends it"

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
		if result.InviteBearer == "" {
			// the first answer was lost, and the server keeps no bearer to answer a retry with
			cli.printf("its bearer was in an answer that was lost: invite the person again; this invite expires unspent\n")
			return nil
		}
		cli.printf("its bearer, for the person alone: %s\n", result.InviteBearer)
		cli.printf("the link's fragment, which lets the person's first device be admitted from the invite, is not appended yet\n")
		return nil
	case urOptionBool(options, "remove"):
		return runUrAdminMemberRemove(ctx, cli, options)
	}
	after := sidecar.Id{}
	if text := urOptionString(options, "--after"); text != "" {
		parsed, err := sidecar.ParseId(text)
		if err != nil || parsed == (sidecar.Id{}) {
			return fmt.Errorf("--after takes a member_id: %q", text)
		}
		after = parsed
	}
	command, err := urAdminMembersPageCommand(after)
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
	if result.More && 0 < len(result.Members) {
		cli.printf("more members follow: ur admin members list --after=%s reads the next page, by its own authorization\n",
			result.Members[len(result.Members)-1].MemberId)
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
				// signed and kept, its post going again, is no failure: the decision is made
				if revocation == nil || err != nil && !errors.Is(err, sidecar.ErrSidecarActPending) {
					return nil, err
				}
				reply := &urMemberRevokeActReply{Pending: revocation.Pending}
				if revocation.Entry != nil {
					reply.EntryVersion = revocation.Entry.GetVersion()
				}
				if revocation.ProposalId != nil {
					reply.ProposalId = fmt.Sprintf("%x", revocation.ProposalId)
				}
				return reply, nil
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
		RevokedAuthKeyCount    int64 `json:"revoked_auth_key_count"`
		// a revoked key was pre-approved: a copy of its bundle still admits until its Delegation ends (D-TEAM-31),
		// which ur says in its own words rather than printing the server's note
		BundleStillAdmits bool `json:"bundle_still_admits"`
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
		cli.printf(
			"the server denied member %s, %d client(s) deactivated, %d auth key(s) revoked\n",
			memberId,
			denied.DeactivatedClientCount,
			denied.RevokedAuthKeyCount,
		)
		if denied.BundleStillAdmits {
			cli.printf("%s\n", urAdminMemberRemoveBundleNote)
		}
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
		if result.ClientSecret == "" {
			// the first answer was lost, and the server keeps no secret to answer a retry with
			cli.printf("its secret was in an answer that was lost: revoke this client and create another\n")
			return nil
		}
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

// The IdP client authentications: ur admin adds a private_key_jwt IdP alone. A client_secret IdP's secret would ride
// in the authorization URL ur prints and opens, and show on the consent page, so it is refused here before any of
// that, as the server refuses such a command at its consent too; the console adds it from a signed-in session.
const (
	urAdminIdpClientAuthPrivateKeyJwt = "private_key_jwt"
	urAdminIdpClientAuthClientSecret  = "client_secret"
)

// ur admin idp add.
func runUrAdminIdp(ctx context.Context, cli *urCli, options docopt.Opts) error {
	issuer, _ := options.String("--issuer")
	clientId, _ := options.String("--client-id")
	clientAuth, _ := options.String("--client-auth")
	if clientAuth == "" {
		clientAuth = urAdminIdpClientAuthPrivateKeyJwt
	}
	switch clientAuth {
	case urAdminIdpClientAuthPrivateKeyJwt:
	case urAdminIdpClientAuthClientSecret:
		return errors.New("a client_secret IdP is added from the console: ur admin's command rides in the authorization URL and shows on the consent page, and an IdP's secret never goes there")
	default:
		return fmt.Errorf("--client-auth takes private_key_jwt: %q", clientAuth)
	}
	if issuer == "" || clientId == "" {
		return errors.New("ur admin idp add takes --issuer and --client-id")
	}
	command, err := urAdminCommand("POST", "/network/idp", map[string]any{"issuer": issuer, "client_id": clientId, "client_auth": clientAuth})
	if err != nil {
		return err
	}
	result := &struct {
		IdpId string `json:"idp_id"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	cli.printf("IdP %s added for %s: it signs people in to this team alone\n", result.IdpId, issuer)
	return nil
}

// A domain as the domain routes answer it, with the TXT record that proves it.
type urAdminDomainState struct {
	Domain   string     `json:"domain"`
	TxtName  string     `json:"txt_name"`
	TxtValue string     `json:"txt_value"`
	Verified bool       `json:"verified"`
	FailTime *time.Time `json:"fail_time"`
}

// ur admin domains add|verify|remove.
func runUrAdminDomains(ctx context.Context, cli *urCli, options docopt.Opts) error {
	domain, _ := options.String("<domain>")
	path := ""
	switch {
	case urOptionBool(options, "add"):
		path = "/network/domain-add"
	case urOptionBool(options, "verify"):
		path = "/network/domain-verify"
	case urOptionBool(options, "remove"):
		path = "/network/domain-remove"
	default:
		return errors.New("ur admin domains takes add, verify or remove")
	}
	command, err := urAdminCommand("POST", path, map[string]any{"domain": domain})
	if err != nil {
		return err
	}
	result := &struct {
		Domain  *urAdminDomainState `json:"domain"`
		Removed bool                `json:"removed"`
	}{}
	err = urAdminRun(ctx, cli, options, command, result)
	refusal := &urAdminRefusal{}
	if errors.As(err, &refusal) && result.Domain != nil && !result.Domain.Verified {
		// a record not found, or looked up a moment ago: the record still to publish
		cli.printf("publish TXT %s with the value %s\n", result.Domain.TxtName, result.Domain.TxtValue)
	}
	if err != nil {
		return err
	}
	if path == "/network/domain-remove" {
		if result.Removed {
			cli.printf("removed %s: its sign-ins route to no IdP from now on\n", domain)
		} else {
			cli.printf("the team held no %s\n", domain)
		}
		return nil
	}
	if result.Domain == nil {
		return fmt.Errorf("the answer to POST %s names no domain", path)
	}
	if result.Domain.Verified {
		cli.printf("%s is verified: its sign-ins route to the team's IdP, and it is looked up again daily\n", result.Domain.Domain)
		return nil
	}
	cli.printf("%s is added: publish TXT %s with the value %s, then run ur admin domains verify %s\n",
		result.Domain.Domain, result.Domain.TxtName, result.Domain.TxtValue, result.Domain.Domain)
	return nil
}

// A webhook as POST /network/audit-webhook lists it, never its key.
type urAdminWebhookState struct {
	WebhookId    string     `json:"webhook_id"`
	Url          string     `json:"url"`
	DeliveredSeq int64      `json:"delivered_seq"`
	FailTime     *time.Time `json:"fail_time"`
	NextTime     *time.Time `json:"next_time"`
}

// ur admin audit-webhook [list|add|remove].
func runUrAdminAuditWebhook(ctx context.Context, cli *urCli, options docopt.Opts) error {
	add := urOptionBool(options, "add")
	remove := urOptionBool(options, "remove")
	body := map[string]any{}
	switch {
	case add:
		webhookUrl, _ := options.String("<webhook_url>")
		body["url"] = webhookUrl
	case remove:
		text, _ := options.String("<webhook_id>")
		webhookId, err := sidecar.ParseId(text)
		if err != nil {
			return fmt.Errorf("a webhook is its webhook_id: %q", text)
		}
		body["remove_webhook_id"] = webhookId.String()
	}
	command, err := urAdminCommand("POST", "/network/audit-webhook", body)
	if err != nil {
		return err
	}
	result := &struct {
		WebhookId  string                 `json:"webhook_id"`
		SigningKey string                 `json:"signing_key"`
		Removed    bool                   `json:"removed"`
		Webhooks   []*urAdminWebhookState `json:"webhooks"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	switch {
	case add:
		cli.printf("webhook %s added: the team's admin events go to it from now on\n", result.WebhookId)
		if result.SigningKey == "" {
			// the first answer was lost, and the server keeps no key to answer a retry with
			cli.printf("its signing key was in an answer that was lost: remove this webhook and add another\n")
			return nil
		}
		cli.printf("its signing key, shown once, for the receiver alone: %s\n", result.SigningKey)
		return nil
	case remove:
		text, _ := options.String("<webhook_id>")
		if result.Removed {
			cli.printf("removed webhook %s\n", text)
		} else {
			cli.printf("the team has no webhook %s\n", text)
		}
		return nil
	}
	for _, webhook := range result.Webhooks {
		line := fmt.Sprintf("%s %s delivered through seq %d", webhook.WebhookId, webhook.Url, webhook.DeliveredSeq)
		if webhook.FailTime != nil {
			line += ", failing since " + webhook.FailTime.UTC().Format(time.RFC3339)
			if webhook.NextTime != nil {
				line += ", next try " + webhook.NextTime.UTC().Format(time.RFC3339)
			}
		}
		cli.printf("%s\n", line)
	}
	return nil
}

// ur admin events: the team's admin events from the oldest kept, a page the server bounds, since an admin token's
// command covers no query and so names no seq to read after; the page's chain head, for a person to compare with a
// SIEM's or an earlier read's.
func runUrAdminEvents(ctx context.Context, cli *urCli, options docopt.Opts) error {
	command, err := urAdminCommand("GET", "/network/admin-events", nil)
	if err != nil {
		return err
	}
	result := &struct {
		Events []struct {
			Seq         int64     `json:"seq"`
			EventTime   time.Time `json:"event_time"`
			ActorKind   string    `json:"actor_kind"`
			ActorId     *string   `json:"actor_id"`
			Action      string    `json:"action"`
			TargetKind  string    `json:"target_kind"`
			TargetId    *string   `json:"target_id"`
			Result      string    `json:"result"`
			ChainSha256 string    `json:"chain_sha256"`
		} `json:"events"`
		More bool `json:"more"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	for _, event := range result.Events {
		actor := event.ActorKind
		if event.ActorId != nil {
			actor += " " + *event.ActorId
		}
		target := event.TargetKind
		if event.TargetId != nil {
			target += " " + *event.TargetId
		}
		cli.printf("%d %s %s %s %s %s\n", event.Seq, event.EventTime.UTC().Format(time.RFC3339), actor, event.Action, target, event.Result)
	}
	if count := len(result.Events); 0 < count {
		last := result.Events[count-1]
		cli.printf("chain head %s at seq %d\n", last.ChainSha256, last.Seq)
	}
	if result.More {
		cli.printf("more events follow: ur admin reads the oldest page kept, and the console or an OAuth client with logs:read reads the rest\n")
	}
	return nil
}
