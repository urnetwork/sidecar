// ur record erase (RECORD.md section 8, §16.8's Erasure; RECORD-M3-06, RECORD-M10-01; DESIGN-COMPUTE §24.10's prune row,
// CTXH-M11-06).
//
//	ur record erase --log=<log> --entry=<id>... [--reason=<reason>] [--dry-run]
//	ur record erase --run=<id> [--context | --blobs-only] [--log=<log>] [--reason=<reason>] [--dry-run]
//
// A log admin's erasure of entries by key destruction, which cannot be undone, so a person does it: the command lists
// what it will destroy on the terminal and erases only on a yes there, and --dry-run prints the list and erases
// nothing. For a context entry in a format-2 log the list says how many search documents of its run's other entries
// keep its agent label and session ids, which a person who wants those gone erases too (DESIGN-DETAILS 15.2.8). The daemon refuses a caller with a harness process among its ancestors, by the pid it read off the socket,
// and no MCP tool reaches it. --reason is person, the default, or moderation. The answer names the one log the
// erasure reached: a copy or twin in another log is not reached, and an erasure there is its own.
//
// --run erases a run's context history (the root's record_erase_run.go): every entry of the run, its transcript,
// context, tool call, model call and coverage entries among them; with --context its session entries and blobs; with
// --blobs-only its blobs alone; in the author's vault unless --log names another. Erasing a session entry, by --entry
// or --run, erases its parts' blobs too. The list then names what the erasure cuts beside the entries it takes: the
// run's nodes left without their item (same_as), the model calls whose context it cuts, and the continued and forked
// runs whose paths cross into it. What the person confirms is what is erased: the erasure takes the entries listed,
// never those a live run journals after the list.

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur record erase calls.
const (
	urMethodRecordErasePlan = "record.erase.plan"
	urMethodRecordErase     = "record.erase"
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "erase",
		usage: []string{
			"  ur record erase --log=<log> --entry=<id>... [--reason=<reason>] [--dry-run]",
			"  ur record erase --run=<id> [--context | --blobs-only] [--log=<log>] [--reason=<reason>] [--dry-run]",
		},
		run: runUrRecordErase,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordEraseMethods)
}

// What an erasure asks for, as the methods take it: entries of a log, or a run's.
type urRecordEraseParams struct {
	Log     string       `json:"log,omitempty"`
	Entries []sidecar.Id `json:"entries,omitempty"`
	// A run's entries by scope (all, context or blobs), in the author's vault where Log is empty: the plan's alone; the
	// erasure takes the entries the plan listed.
	Run   *sidecar.Id `json:"run,omitempty"`
	Scope string      `json:"scope,omitempty"`
	// person or moderation; empty is person
	Reason string `json:"reason,omitempty"`
}

// One entry an erasure takes.
type urRecordEraseItem struct {
	EntryId    sidecar.Id `json:"entry_id"`
	Kind       string     `json:"kind"`
	TimeMillis int64      `json:"time_millis"`
	CopyCount  int        `json:"copy_count"`
	Erased     bool       `json:"erased,omitempty"`
	// For a context entry in a format-2 log, the documents of its run's other entries that keep its agent label and
	// session ids (RecordErasePlanItem.KeptContextCount).
	KeptContextCount int `json:"kept_context_count,omitempty"`
}

// A plan, and once erased, the erasure.
type urRecordEraseReply struct {
	LogId   sidecar.Id           `json:"log_id"`
	Items   []*urRecordEraseItem `json:"items"`
	Missing []sidecar.Id         `json:"missing,omitempty"`
	// What erasing session history cuts beside its entries: nodes left without their item, model calls whose context
	// it cuts, and runs that continue it.
	SameAs []sidecar.Id `json:"same_as,omitempty"`
	Calls  []sidecar.Id `json:"calls,omitempty"`
	Runs   []sidecar.Id `json:"runs,omitempty"`
	// an erasure's; empty for a plan
	ErasureId *sidecar.Id  `json:"erasure_id,omitempty"`
	Erased    []sidecar.Id `json:"erased,omitempty"`
	KeyCount  int          `json:"key_count,omitempty"`
}

// What the erase methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon
// read it.
type urRecordEraseTarget interface {
	recordErasePlan(ctx context.Context, params *urRecordEraseParams, pid int) (*urRecordEraseReply, error)
	recordErase(ctx context.Context, params *urRecordEraseParams, pid int, confirmed bool) (*urRecordEraseReply, error)
}

// --reason's values: a person's own erasure, or a moderator's.
func parseUrRecordEraseReason(text string) (sidecar.RecordErasureReason, error) {
	switch text {
	case "", "person":
		return sidecar.RecordErasureReasonPerson, nil
	case "moderation":
		return sidecar.RecordErasureReasonModeration, nil
	}
	return sidecar.RecordErasureReasonUnspecified, fmt.Errorf("--reason is person or moderation, not %q", text)
}

// The erasure request for params on the hosted record, with whether pid runs under a harness: its entries, a run's by
// scope where it names one, each session entry's blobs added.
func (self *urDaemonNetwork) recordEraseArgs(ctx context.Context, params *urRecordEraseParams, pid int) (*sidecar.SidecarRecord, *sidecar.RecordEraseArgs, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, nil, err
	}
	reason, err := parseUrRecordEraseReason(params.Reason)
	if err != nil {
		return nil, nil, err
	}
	spec := &sidecar.SessionPruneSpec{RunId: params.Run, Scope: sidecar.RecordEraseRunScope(params.Scope), EntryIds: params.Entries}
	if params.Log != "" {
		logId, err := record.ResolveLog(params.Log)
		if err != nil {
			return nil, nil, err
		}
		spec.LogId = &logId
	}
	logId, entryIds, err := record.SessionPruneEntries(ctx, spec)
	if err != nil {
		return nil, nil, err
	}
	return record, &sidecar.RecordEraseArgs{LogId: logId, EntryIds: entryIds, Reason: reason, HarnessAncestor: running.HarnessAncestor(ctx, pid)}, nil
}

func (self *urDaemonNetwork) recordErasePlan(ctx context.Context, params *urRecordEraseParams, pid int) (*urRecordEraseReply, error) {
	record, args, err := self.recordEraseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	reply := &urRecordEraseReply{LogId: args.LogId, Items: []*urRecordEraseItem{}}
	if len(args.EntryIds) == 0 {
		return reply, nil
	}
	plan, err := record.Eraser().PlanAll(ctx, args)
	if err != nil {
		return nil, err
	}
	reply.Missing = plan.Missing
	for _, item := range plan.Items {
		reply.Items = append(reply.Items, &urRecordEraseItem{
			EntryId: item.EntryId, Kind: item.Kind.String(), TimeMillis: item.TimeMillis, CopyCount: item.CopyCount, Erased: item.Erased,
			KeptContextCount: item.KeptContextCount,
		})
	}
	impact, err := record.Eraser().SessionImpact(ctx, args.LogId, args.EntryIds)
	if err != nil {
		return nil, err
	}
	reply.SameAs, reply.Calls, reply.Runs = impact.SameAs, impact.Calls, impact.Runs
	return reply, nil
}

func (self *urDaemonNetwork) recordErase(ctx context.Context, params *urRecordEraseParams, pid int, confirmed bool) (*urRecordEraseReply, error) {
	if params.Run != nil {
		// the erasure takes the entries the plan listed, which the command sends back
		return nil, errors.New("an erasure names the entries its plan listed")
	}
	record, args, err := self.recordEraseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	args.Confirmed = confirmed
	results, err := record.Eraser().EraseAll(ctx, args)
	reply := &urRecordEraseReply{LogId: args.LogId, Items: []*urRecordEraseItem{}}
	for _, result := range results {
		erasureId := result.ErasureId
		reply.ErasureId = &erasureId
		reply.Erased = append(reply.Erased, result.Erased...)
		reply.Missing = append(reply.Missing, result.Missing...)
		reply.KeyCount += len(result.Keys)
	}
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// The erase methods over target, when it runs a Sidecar's record.
func urRecordEraseMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	erasures, ok := target.(urRecordEraseTarget)
	if !ok {
		return nil
	}
	decode := func(call *sidecar.DaemonCall) (*urRecordEraseParams, error) {
		params := &urRecordEraseParams{}
		if err := decodeUrParams(call, params); err != nil || (params.Run == nil && (params.Log == "" || len(params.Entries) == 0)) {
			return nil, errors.New("an erasure takes the log and its entries, or a run")
		}
		return params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodRecordErasePlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call)
				if err != nil {
					return nil, err
				}
				return erasures.recordErasePlan(ctx, params, urCallPid(call))
			},
		},
		{
			Name:    urMethodRecordErase,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call)
				if err != nil {
					return nil, err
				}
				return erasures.recordErase(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// What an erasure would take, as the person reads it before the question.
func printUrRecordErasePlan(out interface{ Write([]byte) (int, error) }, reply *urRecordEraseReply) {
	fmt.Fprintf(out, "log %s: %d entries to erase\n", reply.LogId, len(reply.Items))
	for _, item := range reply.Items {
		when := time.UnixMilli(item.TimeMillis).UTC().Format(time.RFC3339)
		state := fmt.Sprintf("%d copies", item.CopyCount)
		if item.Erased {
			state = "erased already"
		}
		fmt.Fprintf(out, "  %s  %s  %s  %s\n", item.EntryId, item.Kind, when, state)
		if 0 < item.KeptContextCount {
			// DESIGN-DETAILS 15.2.8 (QD-782): rows written before the erasure keep what this context gave them
			fmt.Fprintf(out, "    %d search documents of its run's other entries keep this context's agent label and session ids; erase those entries too to remove them\n", item.KeptContextCount)
		}
	}
	for _, entryId := range reply.Missing {
		fmt.Fprintf(out, "  %s  not in this log\n", entryId)
	}
	for _, entryId := range reply.SameAs {
		fmt.Fprintf(out, "  %s  a node of the run that stays but loses its item (same_as or a shared part)\n", entryId)
	}
	for _, entryId := range reply.Calls {
		fmt.Fprintf(out, "  %s  a model call whose context this cuts: its rebuild reads unverifiable there\n", entryId)
	}
	for _, runId := range reply.Runs {
		fmt.Fprintf(out, "  run %s continues or forks from this run: its path reads erased there\n", runId)
	}
	fmt.Fprintf(out, "Each body's key goes for good; headers and chains stay. Copies in other logs are not reached.\n")
}

// Lists, asks on the terminal, then has the daemon erase what it listed.
func runUrRecordErase(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordEraseParams{Log: urOptionString(options, "--log"), Reason: urOptionString(options, "--reason")}
	if _, err := parseUrRecordEraseReason(params.Reason); err != nil {
		return err
	}
	var err error
	if run := urOptionString(options, "--run"); run != "" {
		runId, err := parseUrRecordId(run)
		if err != nil {
			return err
		}
		params.Run = &runId
		params.Scope = string(sidecar.RecordEraseRunAll)
		switch {
		case urOptionBool(options, "--context"):
			params.Scope = string(sidecar.RecordEraseRunContext)
		case urOptionBool(options, "--blobs-only"):
			params.Scope = string(sidecar.RecordEraseRunBlobs)
		}
	} else if params.Entries, err = parseUrRecordIds(urOptionStrings(options, "--entry")); err != nil {
		return err
	}
	plan := &urRecordEraseReply{}
	if err := cli.callDaemon(ctx, urMethodRecordErasePlan, params, false, plan); err != nil {
		return err
	}
	if urOptionBool(options, "--dry-run") {
		printUrRecordErasePlan(cli.stdout, plan)
		return nil
	}
	if len(plan.Items) == 0 {
		printUrRecordErasePlan(cli.stdout, plan)
		cli.printf("nothing to erase\n")
		return nil
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	printUrRecordErasePlan(tty, plan)
	tty.Close()
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Erase %d entries of log %s for good?", len(plan.Items), plan.LogId))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was erased\n")
		return nil
	}
	// what was listed is what is erased
	erase := &urRecordEraseParams{Log: plan.LogId.String(), Reason: params.Reason}
	for _, item := range plan.Items {
		erase.Entries = append(erase.Entries, item.EntryId)
	}
	erased := &urRecordEraseReply{}
	if err := cli.callDaemon(ctx, urMethodRecordErase, erase, true, erased); err != nil {
		return err
	}
	erasure := ""
	if erased.ErasureId != nil {
		erasure = erased.ErasureId.String()
	}
	cli.printf("erased %d entries of log %s by %d keys, erasure %s; its erasure entry follows in your stream there, and copies in other logs are not reached\n",
		len(erased.Erased), erased.LogId, erased.KeyCount, erasure)
	for _, entryId := range erased.Missing {
		cli.printf("not in this log: %s\n", entryId)
	}
	return nil
}
