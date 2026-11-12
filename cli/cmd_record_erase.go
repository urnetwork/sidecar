// ur record erase (RECORD.md section 8, §16.8's Erasure; RECORD-M3-06).
//
//	ur record erase --log=<log> --entry=<id>... [--reason=<reason>] [--dry-run]
//
// A log admin's erasure of entries by key destruction, which cannot be undone, so a person does it: the command lists
// what it will destroy on the terminal and erases only on a yes there, and --dry-run prints the list and erases
// nothing. The daemon refuses a caller with a harness process among its ancestors, by the pid it read off the socket,
// and no MCP tool reaches it. --reason is person, the default, or moderation. The answer names the one log the
// erasure reached: a copy or twin in another log is not reached, and an erasure there is its own.

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
		word:  "erase",
		usage: []string{"  ur record erase --log=<log> --entry=<id>... [--reason=<reason>] [--dry-run]"},
		run:   runUrRecordErase,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordEraseMethods)
}

// What an erasure asks for, as the methods take it.
type urRecordEraseParams struct {
	Log     string       `json:"log"`
	Entries []sidecar.Id `json:"entries"`
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
}

// A plan, and once erased, the erasure.
type urRecordEraseReply struct {
	LogId   sidecar.Id           `json:"log_id"`
	Items   []*urRecordEraseItem `json:"items"`
	Missing []sidecar.Id         `json:"missing,omitempty"`
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

// The erasure request for params on the hosted record, with whether pid runs under a harness.
func (self *urDaemonNetwork) recordEraseArgs(ctx context.Context, params *urRecordEraseParams, pid int) (*sidecar.SidecarRecord, *sidecar.RecordEraseArgs, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, nil, err
	}
	logId, err := record.ResolveLog(params.Log)
	if err != nil {
		return nil, nil, err
	}
	reason, err := parseUrRecordEraseReason(params.Reason)
	if err != nil {
		return nil, nil, err
	}
	return record, &sidecar.RecordEraseArgs{LogId: logId, EntryIds: params.Entries, Reason: reason, HarnessAncestor: running.HarnessAncestor(ctx, pid)}, nil
}

func (self *urDaemonNetwork) recordErasePlan(ctx context.Context, params *urRecordEraseParams, pid int) (*urRecordEraseReply, error) {
	record, args, err := self.recordEraseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	plan, err := record.Eraser().Plan(ctx, args)
	if err != nil {
		return nil, err
	}
	reply := &urRecordEraseReply{LogId: plan.LogId, Items: []*urRecordEraseItem{}, Missing: plan.Missing}
	for _, item := range plan.Items {
		reply.Items = append(reply.Items, &urRecordEraseItem{
			EntryId: item.EntryId, Kind: item.Kind.String(), TimeMillis: item.TimeMillis, CopyCount: item.CopyCount, Erased: item.Erased,
		})
	}
	return reply, nil
}

func (self *urDaemonNetwork) recordErase(ctx context.Context, params *urRecordEraseParams, pid int, confirmed bool) (*urRecordEraseReply, error) {
	record, args, err := self.recordEraseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	args.Confirmed = confirmed
	result, err := record.Eraser().Erase(ctx, args)
	if err != nil {
		return nil, err
	}
	erasureId := result.ErasureId
	return &urRecordEraseReply{LogId: result.LogId, Items: []*urRecordEraseItem{}, Missing: result.Missing, ErasureId: &erasureId, Erased: result.Erased, KeyCount: len(result.Keys)}, nil
}

// The erase methods over target, when it runs a Sidecar's record.
func urRecordEraseMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	erasures, ok := target.(urRecordEraseTarget)
	if !ok {
		return nil
	}
	decode := func(call *sidecar.DaemonCall) (*urRecordEraseParams, error) {
		params := &urRecordEraseParams{}
		if err := decodeUrParams(call, params); err != nil || params.Log == "" || len(params.Entries) == 0 {
			return nil, errors.New("an erasure takes the log and its entries")
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
	}
	for _, entryId := range reply.Missing {
		fmt.Fprintf(out, "  %s  not in this log\n", entryId)
	}
	fmt.Fprintf(out, "Each body's key goes for good; headers and chains stay. Copies in other logs are not reached.\n")
}

// Lists, asks on the terminal, then has the daemon erase.
func runUrRecordErase(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordEraseParams{Log: urOptionString(options, "--log"), Reason: urOptionString(options, "--reason")}
	if _, err := parseUrRecordEraseReason(params.Reason); err != nil {
		return err
	}
	var err error
	if params.Entries, err = parseUrRecordIds(urOptionStrings(options, "--entry")); err != nil {
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
	erased := &urRecordEraseReply{}
	if err := cli.callDaemon(ctx, urMethodRecordErase, params, true, erased); err != nil {
		return err
	}
	cli.printf("erased %d entries of log %s by %d keys, erasure %s; its erasure entry follows in your stream there, and copies in other logs are not reached\n",
		len(erased.Erased), erased.LogId, erased.KeyCount, erased.ErasureId)
	for _, entryId := range erased.Missing {
		cli.printf("not in this log: %s\n", entryId)
	}
	return nil
}
