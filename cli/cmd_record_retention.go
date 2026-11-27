// ur record retention (RECORD.md section 8; RECORD-M6-03).
//
//	ur record retention show [--log=<log>]
//	ur record retention set --log=<log> --class=<class> --keep=<days> [--searchable=<days>] [--archive]
//
// show prints each class's policy in a log, the vault by default: the newest retention entry a log admin signed, or
// the log's default. set is a log admin's act, in a vault its owner's consented device: a policy that shortens a
// class's life has the next expiry pass erase entries with no further act, so the command says what it will do on the
// terminal and signs only on a yes there. The daemon refuses a caller with a harness process among its ancestors, by
// the pid it read off the socket, and no MCP tool reaches it. On the team record a life from 1 to 364 days, or
// searchable from 1 to 89, is refused; 0 keeps entries, or leaves them searchable, with no limit.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur record retention calls.
const (
	urMethodRecordRetentionShow = "record.retention.show"
	urMethodRecordRetentionPlan = "record.retention.plan"
	urMethodRecordRetentionSet  = "record.retention.set"
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "retention",
		usage: []string{
			"  ur record retention show [--log=<log>]",
			"  ur record retention set --log=<log> --class=<class> --keep=<days> [--searchable=<days>] [--archive]",
		},
		run: runUrRecordRetention,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordRetentionMethods)
}

// What the retention methods take: the log alone for show.
type urRecordRetentionParams struct {
	Log            string `json:"log"`
	Class          string `json:"class,omitempty"`
	KeepDays       uint32 `json:"keep_days,omitempty"`
	SearchableDays uint32 `json:"searchable_days,omitempty"`
	Archive        bool   `json:"archive,omitempty"`
}

// One class's policy as printed.
type urRecordRetentionPolicy struct {
	Class          string `json:"class"`
	KeepDays       uint32 `json:"keep_days"`
	SearchableDays uint32 `json:"searchable_days"`
	Archive        bool   `json:"archive,omitempty"`
	// no retention entry governs: the log's default
	Default bool        `json:"default,omitempty"`
	EntryId *sidecar.Id `json:"entry_id,omitempty"`
}

// A log's policies, a plan's current policy and whether the asked one shortens it, or the entry a set wrote.
type urRecordRetentionReply struct {
	LogId    sidecar.Id                 `json:"log_id"`
	Policies []*urRecordRetentionPolicy `json:"policies,omitempty"`
	Shortens bool                       `json:"shortens,omitempty"`
	EntryId  *sidecar.Id                `json:"entry_id,omitempty"`
}

// What the retention methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon
// read it.
type urRecordRetentionTarget interface {
	recordRetentionShow(ctx context.Context, params *urRecordRetentionParams) (*urRecordRetentionReply, error)
	recordRetentionPlan(ctx context.Context, params *urRecordRetentionParams, pid int) (*urRecordRetentionReply, error)
	recordRetentionSet(ctx context.Context, params *urRecordRetentionParams, pid int, confirmed bool) (*urRecordRetentionReply, error)
}

// Section 8's class names, as --class takes them.
var urRecordRetentionClasses = []sidecar.RecordClass{
	sidecar.RecordClassCapture, sidecar.RecordClassAction, sidecar.RecordClassCoordination, sidecar.RecordClassAnnounce,
	sidecar.RecordClassRequest, sidecar.RecordClassAccounting, sidecar.RecordClassBulk,
}

// --class's values: a class a policy takes, by section 8's name.
func parseUrRecordRetentionClass(text string) (sidecar.RecordClass, error) {
	for _, class := range urRecordRetentionClasses {
		if class.String() == text {
			return class, nil
		}
	}
	return sidecar.RecordClassUnspecified, fmt.Errorf("--class is capture, action, coordination, announce, request, accounting or bulk, not %q", text)
}

// A policy as printed.
func urRecordRetentionPolicyOf(policy *sidecar.RecordRetentionPolicy) *urRecordRetentionPolicy {
	printed := &urRecordRetentionPolicy{
		Class: policy.Class.String(), KeepDays: policy.KeepDays, SearchableDays: policy.SearchableDays, Archive: policy.Archive, Default: policy.Default,
	}
	if !policy.Default {
		entryId := policy.EntryId
		printed.EntryId = &entryId
	}
	return printed
}

// The hosted record's retention and the log params names, read to its head.
func (self *urDaemonNetwork) recordRetention(ctx context.Context, params *urRecordRetentionParams) (*sidecar.Sidecar, *sidecar.RecordRetention, sidecar.Id, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, sidecar.Id{}, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, nil, sidecar.Id{}, err
	}
	log := params.Log
	if log == "" {
		log = "vault"
	}
	logId, err := record.ResolveLog(log)
	if err != nil {
		return nil, nil, sidecar.Id{}, err
	}
	if err := record.Reader().Sync(ctx, logId); err != nil {
		return nil, nil, sidecar.Id{}, err
	}
	return running, record.Retention(), logId, nil
}

func (self *urDaemonNetwork) recordRetentionShow(ctx context.Context, params *urRecordRetentionParams) (*urRecordRetentionReply, error) {
	_, retention, logId, err := self.recordRetention(ctx, params)
	if err != nil {
		return nil, err
	}
	reply := &urRecordRetentionReply{LogId: logId}
	for _, policy := range retention.Policies(logId) {
		reply.Policies = append(reply.Policies, urRecordRetentionPolicyOf(policy))
	}
	return reply, nil
}

// The set params names, for the hosted record, with whether pid runs under a harness.
func (self *urDaemonNetwork) recordRetentionSetArgs(ctx context.Context, params *urRecordRetentionParams, pid int) (*sidecar.RecordRetention, *sidecar.RecordRetentionSetArgs, error) {
	class, err := parseUrRecordRetentionClass(params.Class)
	if err != nil {
		return nil, nil, err
	}
	running, retention, logId, err := self.recordRetention(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	return retention, &sidecar.RecordRetentionSetArgs{
		LogId: logId, Class: class, KeepDays: params.KeepDays, SearchableDays: params.SearchableDays, Archive: params.Archive,
		HarnessAncestor: running.HarnessAncestor(ctx, pid),
	}, nil
}

func (self *urDaemonNetwork) recordRetentionPlan(ctx context.Context, params *urRecordRetentionParams, pid int) (*urRecordRetentionReply, error) {
	retention, args, err := self.recordRetentionSetArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	reply := &urRecordRetentionReply{LogId: args.LogId, Shortens: retention.Shortens(args)}
	if policy := retention.Policy(args.LogId, args.Class); policy != nil {
		reply.Policies = append(reply.Policies, urRecordRetentionPolicyOf(policy))
	}
	return reply, nil
}

func (self *urDaemonNetwork) recordRetentionSet(ctx context.Context, params *urRecordRetentionParams, pid int, confirmed bool) (*urRecordRetentionReply, error) {
	retention, args, err := self.recordRetentionSetArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	args.Confirmed = confirmed
	ref, err := retention.Set(ctx, args)
	if err != nil {
		return nil, err
	}
	entryId := ref.EntryId
	return &urRecordRetentionReply{LogId: args.LogId, EntryId: &entryId}, nil
}

// The retention methods over target, when it runs a Sidecar's record.
func urRecordRetentionMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	retention, ok := target.(urRecordRetentionTarget)
	if !ok {
		return nil
	}
	decode := func(call *sidecar.DaemonCall, set bool) (*urRecordRetentionParams, error) {
		params := &urRecordRetentionParams{}
		if err := decodeUrParams(call, params); err != nil || (set && (params.Log == "" || params.Class == "")) {
			return nil, errors.New("a retention policy takes the log and its class")
		}
		return params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodRecordRetentionShow,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call, false)
				if err != nil {
					return nil, err
				}
				return retention.recordRetentionShow(ctx, params)
			},
		},
		{
			Name: urMethodRecordRetentionPlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call, true)
				if err != nil {
					return nil, err
				}
				return retention.recordRetentionPlan(ctx, params, urCallPid(call))
			},
		},
		{
			Name:    urMethodRecordRetentionSet,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call, true)
				if err != nil {
					return nil, err
				}
				return retention.recordRetentionSet(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// A policy's life in words: its days, or no limit for 0.
func urRecordRetentionDays(days uint32) string {
	if days == 0 {
		return "no limit"
	}
	return fmt.Sprintf("%d days", days)
}

// One class's line.
func printUrRecordRetentionPolicy(out interface{ Write([]byte) (int, error) }, policy *urRecordRetentionPolicy) {
	after := "expires"
	if policy.Archive {
		after = "archived"
	}
	source := "the log's default"
	if policy.EntryId != nil {
		source = "entry " + policy.EntryId.String()
	}
	fmt.Fprintf(out, "  %-12s  keep %s, then %s; searchable %s  (%s)\n", policy.Class, urRecordRetentionDays(policy.KeepDays), after,
		urRecordRetentionDays(policy.SearchableDays), source)
}

// A count of days an option holds: absent is 0.
func parseUrRecordRetentionDays(options docopt.Opts, key string) (uint32, error) {
	text := urOptionString(options, key)
	if text == "" {
		return 0, nil
	}
	days, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s is a count of days, not %q", key, text)
	}
	return uint32(days), nil
}

// show prints; set says what it will do, asks on the terminal, then has the daemon sign.
func runUrRecordRetention(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordRetentionParams{Log: urOptionString(options, "--log")}
	if urOptionBool(options, "show") {
		reply := &urRecordRetentionReply{}
		if err := cli.callDaemon(ctx, urMethodRecordRetentionShow, params, false, reply); err != nil {
			return err
		}
		cli.printf("log %s: class 7 (retention, log_settings, checkpoint, ledger_scope) lasts as long as the log\n", reply.LogId)
		for _, policy := range reply.Policies {
			printUrRecordRetentionPolicy(cli.stdout, policy)
		}
		return nil
	}
	params.Class = urOptionString(options, "--class")
	if _, err := parseUrRecordRetentionClass(params.Class); err != nil {
		return err
	}
	var err error
	if params.KeepDays, err = parseUrRecordRetentionDays(options, "--keep"); err != nil {
		return err
	}
	if params.SearchableDays, err = parseUrRecordRetentionDays(options, "--searchable"); err != nil {
		return err
	}
	params.Archive = urOptionBool(options, "--archive")
	plan := &urRecordRetentionReply{}
	if err := cli.callDaemon(ctx, urMethodRecordRetentionPlan, params, false, plan); err != nil {
		return err
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "log %s, class %s now:\n", plan.LogId, params.Class)
	for _, policy := range plan.Policies {
		printUrRecordRetentionPolicy(tty, policy)
	}
	after := "expire: their keys go for good"
	if params.Archive {
		after = "are archived: their keys stay, and default views and search leave them out"
	}
	fmt.Fprintf(tty, "new: keep %s, searchable %s; entries past it %s\n", urRecordRetentionDays(params.KeepDays), urRecordRetentionDays(params.SearchableDays), after)
	if plan.Shortens {
		fmt.Fprintf(tty, "This shortens the class's life: each admin's next expiry pass erases entries older than %d days with no further question.\n", params.KeepDays)
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Sign this retention policy for log %s?", plan.LogId))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was signed\n")
		return nil
	}
	set := &urRecordRetentionReply{}
	if err := cli.callDaemon(ctx, urMethodRecordRetentionSet, params, true, set); err != nil {
		return err
	}
	cli.printf("retention entry %s is in your stream of log %s; it takes effect at each admin's next expiry pass\n", set.EntryId, set.LogId)
	return nil
}
