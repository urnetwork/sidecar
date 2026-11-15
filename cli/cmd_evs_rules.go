// ur evs rules (EVS1-M6-05; DESIGN-DETAILS 16.2.9, QD-212, QD-792, QD-802, QD-803): a repo's prefix write rules, shown
// from what this device holds, or a next set filed as RepoPrefixRules through this device's act once the person
// confirms on /dev/tty, never through MCP:
//
//	ur evs rules <repo_id> show [--history]                the set in force, each rule's subject and prefix, and each
//	                                                       shared ref against the newest set: bound, not bound yet,
//	                                                       deleted and held at its re-creation, a tag, or stopped here;
//	                                                       --history adds each row's position, signer and state
//	ur evs rules <repo_id> allow <subject> <path>...      the set in force with a rule for each path
//	ur evs rules <repo_id> deny <subject>                 the set in force without the subject's rules
//	ur evs rules <repo_id> set <file> [--as-written]      the file's rules, JSON (below)
//	ur evs rules <repo_id> lift                           the one rule {autogroup:sidecar, every path}
//
// Every filing but --as-written writes each standing admin of the repo in with every path, which the filer does
// (AclPrefixRulesFiler, QD-792); --as-written files the file's rules alone, and the answer names each admin it leaves
// unable to write. A subject is sidecar:<id>, user:<email>, tag:<name> or autogroup:sidecar, member, tagged or
// ephemeral; group:<name> is refused before anything is asked, with its members' user: subjects to file instead. A
// path is its raw names joined by /, and / alone is every path. Once the set is filed the daemon sends its pin push to
// each shared ref (EvsClient.PinPushRules), and a repo's first set says once that devices older than this release do
// not follow the rules (16.2.12).
//
// set's file is JSON, a path left out or "/" for every path:
//
//	{"rules": [{"subject": "tag:ci", "path": "agents/build"}, {"subject": "user:ops@example.com"}]}
//
// Paths and subjects are the person's own and go only between ur and its daemon on this device (I-13).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur evs rules calls.
const (
	urMethodEvsRulesShow     = "evs.rules.show"
	urMethodEvsRulesSubjects = "evs.rules.subjects"
	urMethodEvsRulesFile     = "evs.rules.file"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsRulesMethods)
}

// What the rules methods act on: the hosted network's Sidecar and its evs client.
type urEvsRulesTarget interface {
	evsClient() (*sidecar.EvsClient, error)
	prefixRulesSidecar() (*sidecar.Sidecar, error)
}

// The only hosted network's Sidecar.
func (self *urDaemonNetwork) prefixRulesSidecar() (*sidecar.Sidecar, error) {
	return self.onlySidecar()
}

// One rule as set's file and the file method carry it.
type urEvsRuleJson struct {
	Subject string `json:"subject"`
	// Raw names joined by /; empty or "/" for every path.
	Path string `json:"path,omitempty"`
}

type urEvsRulesJson struct {
	Rules []*urEvsRuleJson `json:"rules"`
}

// What the rules methods ask.
type urEvsRulesParams struct {
	RepoId  string `json:"repo_id"`
	History bool   `json:"history,omitempty"`
	// allow, deny, set or lift
	Change    string           `json:"change,omitempty"`
	Subject   string           `json:"subject,omitempty"`
	Paths     []string         `json:"paths,omitempty"`
	Rules     []*urEvsRuleJson `json:"rules,omitempty"`
	AsWritten bool             `json:"as_written,omitempty"`
	// evs.rules.subjects': each subject to read against the head before anything is asked
	Subjects []string `json:"subjects,omitempty"`
}

// A path's raw names as a rule carries them: none for "/" or "", which is every path.
func urEvsRulePath(path string) ([][]byte, error) {
	if path == "" || path == "/" {
		return nil, nil
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		if name == "" || strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("a path's names are not empty and hold no NUL: %q", path)
		}
		names = append(names, []byte(name))
	}
	return names, nil
}

// A rule's path as show prints it.
func urEvsRulePathText(path [][]byte) string {
	if len(path) == 0 {
		return "every path"
	}
	names := make([]string, 0, len(path))
	for _, name := range path {
		names = append(names, string(name))
	}
	return strings.Join(names, "/") + "/"
}

// A ref as the lines name it.
func urEvsRefText(ref *sidecar.EvsPrefixRef) string {
	if len(ref.Name) == 0 {
		return "ref " + ref.RefId.String()
	}
	return string(ref.Name)
}

// What a binding says, as show and a filing print it.
func urEvsBindingText(ref *sidecar.EvsPrefixRef) string {
	switch ref.Binding {
	case sidecar.EvsPrefixBound:
		if ref.PushId != nil {
			return fmt.Sprintf("bound by its pin push at version %d", ref.Version)
		}
		return fmt.Sprintf("bound (its head's pin is %d)", ref.PinVersion)
	case sidecar.EvsPrefixUnbound:
		return fmt.Sprintf("not bound yet (its head's pin is %d): the filer's pin push or any honest push binds it", ref.PinVersion)
	case sidecar.EvsPrefixDeleted:
		return "deleted, held at re-creation"
	case sidecar.EvsPrefixTag:
		return "a tag: it holds no file and takes no pin push"
	case sidecar.EvsPrefixStopped:
		return "stopped on this device: its recovery binds it"
	case sidecar.EvsPrefixFailed:
		return "its pin push failed (" + ref.Err + "); the journal sends it again"
	case sidecar.EvsPrefixWaiting:
		return "waits for this device's log to hold the set; the journal sends its pin push"
	}
	return string(ref.Binding)
}

// show's lines, each subject printed by subjectText.
func urEvsRulesStatusLines(status *sidecar.EvsPrefixRulesStatus, history bool, subjectText func(sidecar.Id) string) []string {
	if len(status.Sets) == 0 {
		return []string{fmt.Sprintf("repo %s has no prefix rules: every writer writes every path", status.RepoId)}
	}
	lines := []string{}
	switch {
	case status.Unread != nil && status.Unread.State == sidecar.AclPrefixSetNewer:
		lines = append(lines, fmt.Sprintf("the set at position %d is a later release's: this device shows what it accepted before and writes nothing to the repo until it is updated", status.Unread.At))
	case status.Unread != nil:
		lines = append(lines, fmt.Sprintf("the set at position %d is pending on this device: it shows what it accepted before and writes nothing to the repo until it opens the set", status.Unread.At))
	case status.InForce == nil:
		lines = append(lines, fmt.Sprintf("no set is in force at this device's position %d: every writer writes every path", status.PinVersion))
	default:
		lines = append(lines, fmt.Sprintf("the set in force at position %d, filed by %s:", status.InForce.At, subjectText(status.InForce.Signer)))
		if len(status.InForce.Rules) == 0 {
			lines = append(lines, "  no rule: nobody writes")
		}
		for _, rule := range status.InForce.Rules {
			subject, _ := sidecar.IdFromBytes(rule.GetSubject())
			lines = append(lines, fmt.Sprintf("  %-40s %s", subjectText(subject), urEvsRulePathText(rule.GetPath())))
		}
	}
	if history {
		lines = append(lines, "sets:")
		for _, set := range status.Sets {
			state := set.State.String()
			if set.State == sidecar.AclPrefixSetVoid {
				state += " (" + set.VoidCause.String() + ")"
			}
			if status.InForce != nil && set.At == status.InForce.At {
				state += ", in force"
			}
			lines = append(lines, fmt.Sprintf("  at %d  %s  %s", set.At, subjectText(set.Signer), state))
		}
	}
	if 0 < len(status.Refs) {
		lines = append(lines, fmt.Sprintf("refs against the newest set, at position %d:", status.NewestAt))
		for _, ref := range status.Refs {
			lines = append(lines, fmt.Sprintf("  %-24s %s", urEvsRefText(ref), urEvsBindingText(ref)))
		}
	}
	return lines
}

// A filing's lines.
func urEvsRulesFilingLines(filing *sidecar.EvsPrefixRulesFiling, subjectText func(sidecar.Id) string) []string {
	lines := []string{fmt.Sprintf("filed the set at position %d, %d rule(s)", filing.Filed.Pin.GetVersion(), len(filing.Filed.Set.GetRules()))}
	if filing.FirstSet {
		lines = append(lines, "this is the repo's first set: devices older than the release that carries prefix rules do not follow them")
	}
	for _, adminId := range filing.Filed.UnnamedAdmins {
		lines = append(lines, fmt.Sprintf("the set names no rule for the repo's admin %s, which writes nothing while it is in force", subjectText(adminId)))
	}
	for _, ref := range filing.Refs {
		lines = append(lines, fmt.Sprintf("  %-24s %s", urEvsRefText(ref), urEvsBindingText(ref)))
	}
	return lines
}

// Each subject read against the head, a refused one's reason in its place: a group's names its members.
func urEvsRulesSubjectRefusals(running *sidecar.Sidecar, subjects []string) []string {
	refusals := []string{}
	for _, subject := range subjects {
		_, err := running.PrefixRuleSubject(subject)
		var group *sidecar.EvsPrefixGroupSubjectError
		switch {
		case errors.As(err, &group):
			refusals = append(refusals, fmt.Sprintf("%s names nobody in a prefix rule; file its members instead: %s", subject, strings.Join(group.Members, " ")))
		case err != nil:
			refusals = append(refusals, fmt.Sprintf("%s: %s", subject, err))
		}
	}
	return refusals
}

// The request params ask for, each subject read against the head.
func urEvsRulesRequest(running *sidecar.Sidecar, repoId sidecar.Id, params *urEvsRulesParams) (*sidecar.AclPrefixRulesRequest, error) {
	request := &sidecar.AclPrefixRulesRequest{RepoId: repoId, AsWritten: params.AsWritten}
	subject := func(text string) (sidecar.Id, error) {
		id, err := running.PrefixRuleSubject(text)
		var group *sidecar.EvsPrefixGroupSubjectError
		if errors.As(err, &group) {
			return sidecar.Id{}, fmt.Errorf("%s names nobody in a prefix rule; file its members instead: %s", text, strings.Join(group.Members, " "))
		}
		return id, err
	}
	var err error
	switch params.Change {
	case "allow":
		request.Change = sidecar.AclPrefixRulesAllow
		if request.Subject, err = subject(params.Subject); err != nil {
			return nil, err
		}
		for _, path := range params.Paths {
			names, err := urEvsRulePath(path)
			if err != nil {
				return nil, err
			}
			request.Paths = append(request.Paths, names)
		}
		if len(request.Paths) == 0 {
			return nil, errors.New("allow takes at least one path, / for every path")
		}
	case "deny":
		request.Change = sidecar.AclPrefixRulesDeny
		if request.Subject, err = subject(params.Subject); err != nil {
			return nil, err
		}
	case "set":
		request.Change = sidecar.AclPrefixRulesSet
		for _, rule := range params.Rules {
			if rule == nil {
				return nil, errors.New("an empty rule")
			}
			id, err := subject(rule.Subject)
			if err != nil {
				return nil, err
			}
			names, err := urEvsRulePath(rule.Path)
			if err != nil {
				return nil, err
			}
			request.Rules = append(request.Rules, &protocol.PrefixRule{Subject: id.Bytes(), Path: names, Action: protocol.PrefixAction_PREFIX_ACTION_WRITE})
		}
	case "lift":
		request.Change = sidecar.AclPrefixRulesLift
	default:
		return nil, fmt.Errorf("no such change %q", params.Change)
	}
	return request, nil
}

// The rules methods over target, when it hosts a Sidecar: show and the subjects' check read; the filing is a Confirm
// one, so nothing but a control call a person confirmed files a set.
func urEvsRulesMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	rules, ok := target.(urEvsRulesTarget)
	if !ok {
		return nil
	}
	of := func(call *sidecar.DaemonCall) (*urEvsRulesParams, *sidecar.Sidecar, *sidecar.EvsClient, sidecar.Id, error) {
		params := &urEvsRulesParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, nil, nil, sidecar.Id{}, err
		}
		repoId, err := sidecar.ParseId(params.RepoId)
		if err != nil {
			return nil, nil, nil, sidecar.Id{}, errors.New("no repo id")
		}
		running, err := rules.prefixRulesSidecar()
		if err != nil {
			return nil, nil, nil, sidecar.Id{}, err
		}
		client, err := rules.evsClient()
		if err != nil {
			return nil, nil, nil, sidecar.Id{}, err
		}
		return params, running, client, repoId, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodEvsRulesShow,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, running, client, repoId, err := of(call)
				if err != nil {
					return nil, err
				}
				status, err := client.PrefixRulesStatus(ctx, repoId)
				if err != nil {
					return nil, err
				}
				return &urEvsRepoReply{Lines: urEvsRulesStatusLines(status, params.History, running.PrefixRuleSubjectText)}, nil
			},
		},
		{
			Name: urMethodEvsRulesSubjects,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, running, _, _, err := of(call)
				if err != nil {
					return nil, err
				}
				return &urEvsRepoReply{Lines: urEvsRulesSubjectRefusals(running, params.Subjects)}, nil
			},
		},
		{
			Name:    urMethodEvsRulesFile,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, running, client, repoId, err := of(call)
				if err != nil {
					return nil, err
				}
				request, err := urEvsRulesRequest(running, repoId, params)
				if err != nil {
					return nil, err
				}
				filing, err := running.FilePrefixRules(ctx, client, request, sidecar.SidecarActConfirmed)
				if err != nil {
					return nil, err
				}
				return &urEvsRepoReply{Lines: urEvsRulesFilingLines(filing, running.PrefixRuleSubjectText)}, nil
			},
		},
	}
}

// Runs ur evs rules: show prints the daemon's lines; a filing reads its subjects against the head, asks on the
// terminal, then files.
func runUrEvsRules(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urEvsRulesParams{RepoId: urOptionString(options, "<repo_id>")}
	if _, err := sidecar.ParseId(params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	printLines := func(reply *urEvsRepoReply) {
		for _, line := range reply.Lines {
			cli.printf("%s\n", line)
		}
	}
	if urOptionBool(options, "show") {
		params.History = urOptionBool(options, "--history")
		reply := &urEvsRepoReply{}
		if err := cli.callDaemon(ctx, urMethodEvsRulesShow, params, false, reply); err != nil {
			return err
		}
		printLines(reply)
		return nil
	}
	question := ""
	switch {
	case urOptionBool(options, "allow"):
		params.Change, params.Subject = "allow", urOptionString(options, "<subject>")
		params.Paths = urOptionStrings(options, "<path>")
		if len(params.Paths) == 0 {
			return errors.New("ur evs rules allow takes at least one path, / for every path")
		}
		params.Subjects = []string{params.Subject}
		question = fmt.Sprintf("let %s write under %s in %s, the repo's admins written in?", params.Subject, strings.Join(params.Paths, ", "), params.RepoId)
	case urOptionBool(options, "deny"):
		params.Change, params.Subject = "deny", urOptionString(options, "<subject>")
		params.Subjects = []string{params.Subject}
		question = fmt.Sprintf("take every rule of %s out of %s's set, the repo's admins written in?", params.Subject, params.RepoId)
	case urOptionBool(options, "set"):
		params.Change, params.AsWritten = "set", urOptionBool(options, "--as-written")
		data, err := os.ReadFile(urOptionString(options, "<file>"))
		if err != nil {
			return err
		}
		parsed := &urEvsRulesJson{}
		if err := json.Unmarshal(data, parsed); err != nil {
			return fmt.Errorf("the rules do not parse: %w", err)
		}
		params.Rules = parsed.Rules
		for _, rule := range parsed.Rules {
			if rule == nil {
				return errors.New("an empty rule")
			}
			if _, err := urEvsRulePath(rule.Path); err != nil {
				return err
			}
			params.Subjects = append(params.Subjects, rule.Subject)
		}
		question = fmt.Sprintf("replace %s's prefix rules with %d rule(s), the repo's admins written in?", params.RepoId, len(parsed.Rules))
		if params.AsWritten {
			question = fmt.Sprintf("replace %s's prefix rules with exactly these %d rule(s), no admin written in?", params.RepoId, len(parsed.Rules))
		}
	case urOptionBool(options, "lift"):
		params.Change = "lift"
		question = fmt.Sprintf("lift %s's prefix rules, so every writer writes every path?", params.RepoId)
	default:
		return errors.New("ur evs rules takes show, allow, deny, set or lift")
	}
	if 0 < len(params.Subjects) {
		refusals := &urEvsRepoReply{}
		if err := cli.callDaemon(ctx, urMethodEvsRulesSubjects, params, false, refusals); err != nil {
			return err
		}
		if 0 < len(refusals.Lines) {
			printLines(refusals)
			return errors.New("nothing was filed")
		}
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, urMethodEvsRulesFile, params, true, reply); err != nil {
		return err
	}
	printLines(reply)
	return nil
}
