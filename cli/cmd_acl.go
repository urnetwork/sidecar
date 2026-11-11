// ur acl (ACL-M2-11; §8.8's Saving, D-ACL-9, R-ACL-10, QD-555): a person's commands on the network's access policy.
// None is an MCP tool, and nothing here takes policy text from anywhere but the file named.
//
//	ur acl test <file>   the document's tests (§8.5) over this device's last verified state, run by the daemon when
//	                     one answers, which reads no network for it; with no daemon, over the document's own world,
//	                     every user it names a member, which the output says. A failing test exits 1
//	ur acl push <file>   on a config writer: validate, compile, test and preview, then sign and save once the person
//	                     confirms on /dev/tty; a caller with no terminal is refused before anything is planned, and the
//	                     save names the preview's digest, so the head signed is the one shown. A rollback is a push of
//	                     an older source, a new head at the next config_version (I-16)
//	ur acl log           the change audit: each config version the verified log put in force, the config writer that
//	                     signed its base and when
//
// Spellings follow plan-ACL-small-readings #13 until cli/UI.md is copied in (QD-024).

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The control methods ur acl calls.
const (
	urMethodAclTest     = "acl.test"
	urMethodAclPushPlan = "acl.push.plan"
	urMethodAclPush     = "acl.push"
	urMethodAclLog      = "acl.log"
)

// The most a policy file may hold: §8.8's 4 MiB source bound, which ParseAclPolicy holds every reader to, and one byte
// more, so a longer file is refused rather than cut.
const urAclPolicyMaxByteCount = 4*1024*1024 + 1

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAclMethods)
	registerUrCommand(&urCommand{
		name: "acl",
		usage: strings.Join([]string{
			"  ur acl test <file>",
			"  ur acl push <file>",
			"  ur acl log",
		}, "\n"),
		summary: "the network's access policy: run its tests, save it on a config writer, and its change audit",
		run:     runUrAcl,
	})
}

// What the acl methods act on.
type urAclTarget interface {
	testAclPolicy(ctx context.Context, source []byte) (*sidecar.AclPolicyTestReport, error)
	planAclPolicy(ctx context.Context, source []byte) (*sidecar.AclSavePlan, error)
	saveAclPolicy(ctx context.Context, source []byte, digest [32]byte) (*bridge.AuthPin, error)
	aclLog() ([]sidecar.AclLogEntry, error)
}

func (self *urDaemonNetwork) testAclPolicy(ctx context.Context, source []byte) (*sidecar.AclPolicyTestReport, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.TestAclPolicy(ctx, source)
}

func (self *urDaemonNetwork) planAclPolicy(ctx context.Context, source []byte) (*sidecar.AclSavePlan, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PlanAclPolicy(ctx, source)
}

// A confirmed control call.
func (self *urDaemonNetwork) saveAclPolicy(ctx context.Context, source []byte, digest [32]byte) (*bridge.AuthPin, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.SaveAclPolicy(ctx, source, digest, sidecar.SidecarActConfirmed)
}

func (self *urDaemonNetwork) aclLog() ([]sidecar.AclLogEntry, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.AclLog()
}

// A document as the acl methods carry it.
type urAclParams struct {
	Source string `json:"source"`
	// acl.push's: the preview's digest, hex.
	Digest string `json:"digest,omitempty"`
}

// One failing check, by index.
type urAclTestFailure struct {
	Test   int    `json:"test"`
	List   string `json:"list"`
	Check  int    `json:"check"`
	Reason string `json:"reason"`
}

// A test run's answer.
type urAclTestReply struct {
	TestCount     int                 `json:"test_count"`
	CheckCount    int                 `json:"check_count"`
	Failures      []*urAclTestFailure `json:"failures,omitempty"`
	DocumentAlone bool                `json:"document_alone,omitempty"`
}

func urAclTestReplyOf(report *sidecar.AclPolicyTestReport) *urAclTestReply {
	reply := &urAclTestReply{TestCount: report.TestCount, CheckCount: report.CheckCount, DocumentAlone: report.DocumentAlone}
	for _, failure := range report.Failures {
		reply.Failures = append(reply.Failures, &urAclTestFailure{Test: failure.Test, List: failure.List, Check: failure.Check, Reason: failure.Reason})
	}
	return reply
}

// One repo's readers before and after, ids as text.
type urAclReaderChange struct {
	RepoId  string   `json:"repo_id"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// One repo that cannot seat a reader.
type urAclUnseated struct {
	RepoId      string   `json:"repo_id"`
	ReaderCount int      `json:"reader_count"`
	SidecarIds  []string `json:"sidecar_ids,omitempty"`
}

// One new or changed resolve row.
type urAclResolution struct {
	Kind          string   `json:"kind"`
	Text          string   `json:"text"`
	Id            string   `json:"id"`
	PreviousId    string   `json:"previous_id,omitempty"`
	Role          string   `json:"role,omitempty"`
	SidecarIds    []string `json:"sidecar_ids,omitempty"`
	MemberUnknown bool     `json:"member_unknown,omitempty"`
}

// A save's preview, as acl.push.plan answers it.
type urAclPlanReply struct {
	Digest       string               `json:"digest"`
	Tests        *urAclTestReply      `json:"tests"`
	Readers      []*urAclReaderChange `json:"readers,omitempty"`
	Unseated     []*urAclUnseated     `json:"unseated,omitempty"`
	Resolutions  []*urAclResolution   `json:"resolutions,omitempty"`
	RulesAdded   []string             `json:"rules_added,omitempty"`
	RulesRemoved []string             `json:"rules_removed,omitempty"`
}

// Ids as text.
func urAclIds(ids []sidecar.Id) []string {
	texts := make([]string, 0, len(ids))
	for _, id := range ids {
		texts = append(texts, id.String())
	}
	return texts
}

func urAclPlanReplyOf(plan *sidecar.AclSavePlan) *urAclPlanReply {
	reply := &urAclPlanReply{Digest: hex.EncodeToString(plan.Digest[:]), Tests: urAclTestReplyOf(plan.Tests)}
	preview := plan.Preview
	for _, change := range preview.Readers {
		reply.Readers = append(reply.Readers, &urAclReaderChange{RepoId: change.RepoId.String(), Added: urAclIds(change.Added), Removed: urAclIds(change.Removed)})
	}
	for _, unseated := range preview.Unseated {
		reply.Unseated = append(reply.Unseated, &urAclUnseated{RepoId: unseated.RepoId.String(), ReaderCount: unseated.ReaderCount, SidecarIds: urAclIds(unseated.SidecarIds)})
	}
	for _, resolution := range preview.Resolutions {
		row := &urAclResolution{Kind: resolution.Kind, Text: resolution.Text, Id: resolution.Id.String(), SidecarIds: urAclIds(resolution.SidecarIds), MemberUnknown: resolution.MemberUnknown}
		if resolution.PreviousId != (sidecar.Id{}) {
			row.PreviousId = resolution.PreviousId.String()
		}
		if resolution.Kind == "user" && !resolution.MemberUnknown {
			row.Role = strings.ToLower(strings.TrimPrefix(resolution.Role.String(), "MEMBER_ROLE_"))
		}
		reply.Resolutions = append(reply.Resolutions, row)
	}
	reply.RulesAdded, reply.RulesRemoved = urAclIds(preview.RulesAdded), urAclIds(preview.RulesRemoved)
	return reply
}

// The saved base's position.
type urAclPushReply struct {
	N uint64 `json:"n"`
}

// One head of the change audit.
type urAclLogEntry struct {
	ConfigVersion uint64 `json:"config_version"`
	N             uint64 `json:"n"`
	TimeMs        int64  `json:"time_ms"`
	Signer        string `json:"signer"`
}

type urAclLogReply struct {
	Entries []*urAclLogEntry `json:"entries"`
}

// The acl methods over target, when it hosts a Sidecar.
func urAclMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	acl, ok := target.(urAclTarget)
	if !ok {
		return nil
	}
	source := func(call *sidecar.DaemonCall) (*urAclParams, error) {
		params := &urAclParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, err
		}
		if params.Source == "" {
			return nil, errors.New("no policy source")
		}
		return params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodAclTest,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := source(call)
				if err != nil {
					return nil, err
				}
				report, err := acl.testAclPolicy(ctx, []byte(params.Source))
				if err != nil {
					return nil, err
				}
				return urAclTestReplyOf(report), nil
			},
		},
		{
			Name: urMethodAclPushPlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := source(call)
				if err != nil {
					return nil, err
				}
				plan, err := acl.planAclPolicy(ctx, []byte(params.Source))
				if err != nil {
					return nil, err
				}
				return urAclPlanReplyOf(plan), nil
			},
		},
		{
			Name:    urMethodAclPush,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := source(call)
				if err != nil {
					return nil, err
				}
				digest, err := hex.DecodeString(params.Digest)
				if err != nil || len(digest) != 32 {
					return nil, errors.New("no preview digest")
				}
				pin, err := acl.saveAclPolicy(ctx, []byte(params.Source), [32]byte(digest))
				if err != nil {
					return nil, err
				}
				return &urAclPushReply{N: pin.GetVersion()}, nil
			},
		},
		{
			Name: urMethodAclLog,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				entries, err := acl.aclLog()
				if err != nil {
					return nil, err
				}
				reply := &urAclLogReply{Entries: []*urAclLogEntry{}}
				for _, entry := range entries {
					reply.Entries = append(reply.Entries, &urAclLogEntry{ConfigVersion: entry.ConfigVersion, N: entry.N, TimeMs: entry.TimeMs, Signer: entry.SignerSidecarId.String()})
				}
				return reply, nil
			},
		},
	}
}

// Runs the part the first word names.
func runUrAcl(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "test"):
		return runUrAclTest(ctx, cli, urOptionString(options, "<file>"))
	case urOptionBool(options, "push"):
		return runUrAclPush(ctx, cli, urOptionString(options, "<file>"))
	case urOptionBool(options, "log"):
		return runUrAclLog(ctx, cli)
	}
	return errors.New("ur acl takes test, push or log")
}

// The policy file's bytes, held to the source bound, and parsed here so a document that does not parse reaches no
// daemon.
func urAclReadPolicy(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	source, err := io.ReadAll(io.LimitReader(file, urAclPolicyMaxByteCount))
	if err != nil {
		return nil, err
	}
	if _, err := sidecar.ParseAclPolicy(source); err != nil {
		return nil, err
	}
	return source, nil
}

// The instance's running daemon, or nil when none answers: nothing spawns one.
func (self *urCli) runningDaemon(ctx context.Context) *sidecar.DaemonClient {
	socketPath, err := self.socketPath(self.instance)
	if err != nil {
		return nil
	}
	client, err := self.dialDaemon(ctx, socketPath, self.hello(sidecar.DaemonModeControl))
	if err != nil {
		return nil
	}
	return client
}

// Prints a test run's answer, the failing checks' text from the document beside each, and fails on any failure.
func (self *urCli) printAclTests(source []byte, reply *urAclTestReply) error {
	policy, _ := sidecar.ParseAclPolicy(source)
	if reply.DocumentAlone {
		self.printf("no daemon state: the tests ran over the document's own world, every user it names a member, not over the network's state\n")
	}
	for _, failure := range reply.Failures {
		text := ""
		if policy != nil && 0 <= failure.Test && failure.Test < len(policy.Tests) {
			test := policy.Tests[failure.Test]
			checks := test.Accept
			if failure.List == "deny" {
				checks = test.Deny
			}
			text = test.Src.String()
			if 0 <= failure.Check && failure.Check < len(checks) {
				text += " " + checks[failure.Check].Resource.String() + "#" + strings.ToLower(strings.TrimPrefix(checks[failure.Check].Action.String(), "ACL_ACTION_"))
			}
		}
		where := fmt.Sprintf("tests[%d].%s[%d]", failure.Test, failure.List, failure.Check)
		if failure.List == "src" {
			where = fmt.Sprintf("tests[%d].src", failure.Test)
		}
		self.printf("FAIL %s %s: %s\n", where, text, failure.Reason)
	}
	if 0 < len(reply.Failures) {
		return fmt.Errorf("%d of %d checks in %d tests failed", len(reply.Failures), reply.CheckCount, reply.TestCount)
	}
	self.printf("%d tests, %d checks passed\n", reply.TestCount, reply.CheckCount)
	return nil
}

// ur acl test: the daemon's run where one answers, else the document's own.
func runUrAclTest(ctx context.Context, cli *urCli, path string) error {
	source, err := urAclReadPolicy(path)
	if err != nil {
		return err
	}
	if client := cli.runningDaemon(ctx); client != nil {
		defer client.Close()
		callCtx, cancel := context.WithTimeout(ctx, cli.settings.CallTimeout)
		defer cancel()
		reply := &urAclTestReply{}
		if err := client.Call(callCtx, urMethodAclTest, &urAclParams{Source: string(source)}, false, reply); err != nil {
			return err
		}
		return cli.printAclTests(source, reply)
	}
	report, err := sidecar.AclPolicyTestOver(source, nil, nil, time.Now())
	if err != nil {
		return err
	}
	return cli.printAclTests(source, urAclTestReplyOf(report))
}

// Prints a save's preview for the person.
func (self *urCli) printAclPlan(reply *urAclPlanReply) {
	for _, change := range reply.Readers {
		self.printf("readers of %s: +%d -%d\n", change.RepoId, len(change.Added), len(change.Removed))
		for _, added := range change.Added {
			self.printf("  + %s\n", added)
		}
		for _, removed := range change.Removed {
			self.printf("  - %s\n", removed)
		}
	}
	for _, unseated := range reply.Unseated {
		self.printf("%s cannot seat %d of its %d reading devices, which wait keyless (§8.12)\n", unseated.RepoId, len(unseated.SidecarIds), unseated.ReaderCount)
	}
	for _, resolution := range reply.Resolutions {
		switch {
		case resolution.MemberUnknown:
			self.printf("%s %s resolves to %s, which the network holds no member of\n", resolution.Kind, resolution.Text, resolution.Id)
		case resolution.Kind == "user":
			self.printf("user %s is member %s (%s) with %d devices\n", resolution.Text, resolution.Id, resolution.Role, len(resolution.SidecarIds))
		default:
			self.printf("%s %s resolves to %s\n", resolution.Kind, resolution.Text, resolution.Id)
		}
	}
	self.printf("%d rules added, %d removed\n", len(reply.RulesAdded), len(reply.RulesRemoved))
}

// ur acl push: a person on a terminal, a config writer's preview, a yes, then the save of exactly that preview.
func runUrAclPush(ctx context.Context, cli *urCli, path string) error {
	source, err := urAclReadPolicy(path)
	if err != nil {
		return err
	}
	// a caller with no terminal is refused before anything is planned (§22.7's actions suite)
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: ur acl push needs a person on a terminal: %w", errUrNoTty, err)
	}
	tty.Close()
	plan := &urAclPlanReply{}
	if err := cli.callDaemon(ctx, urMethodAclPushPlan, &urAclParams{Source: string(source)}, false, plan); err != nil {
		return err
	}
	cli.printAclPlan(plan)
	if err := cli.printAclTests(source, plan.Tests); err != nil {
		return fmt.Errorf("nothing saved: %w", err)
	}
	confirmed, err := confirmOnTty(cli, "sign and save this policy as the network's?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &urAclPushReply{}
	if err := cli.callDaemon(ctx, urMethodAclPush, &urAclParams{Source: string(source), Digest: plan.Digest}, true, reply); err != nil {
		return err
	}
	cli.printf("the policy is saved, in force from the base at %d\n", reply.N)
	return nil
}

// ur acl log: the change audit.
func runUrAclLog(ctx context.Context, cli *urCli) error {
	reply := &urAclLogReply{}
	if err := cli.callDaemon(ctx, urMethodAclLog, nil, false, reply); err != nil {
		return err
	}
	if len(reply.Entries) == 0 {
		cli.printf("no config head in the log this device keeps\n")
		return nil
	}
	for _, entry := range reply.Entries {
		cli.printf("config version %d  base %d  signer %s  %s\n", entry.ConfigVersion, entry.N, entry.Signer,
			time.UnixMilli(entry.TimeMs).UTC().Format(time.RFC3339))
	}
	return nil
}
