// ur record export (RECORD.md section 9, RECORD-M6-07).
//
//	ur record export --log=<log> [--since=<time>] [--until=<time>] [--run=<id>] [--kind=<kinds>] [--bodies]
//	                 [--format=<format>] [--out=<path>] [--follow]
//
// Lines go to --out, a file this command creates and never replaces, or to stdout: never to a network address. A
// plain jsonl export holds header fields alone and asks nothing. --bodies, --format ocsf or otel, and --follow carry
// body data or outlive the command, so each is confirmed on the terminal first, and the daemon taints the runs of a
// harness process among the caller's ancestors before it reads. The daemon files the export's record in the log, and
// holds its commit, before it answers with a line. --follow leaves a job in the daemon, which appends to --out as
// entries verify and ends with this sidecar's read of the log.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur record export calls.
const (
	urMethodRecordExport       = "record.export"
	urMethodRecordExportFollow = "record.export.follow"
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "export",
		usage: []string{
			"  ur record export --log=<log> [--since=<time>] [--until=<time>] [--run=<id>] [--kind=<kinds>] [--bodies] [--format=<format>] [--out=<path>] [--follow]",
		},
		run: runUrRecordExport,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordExportMethods)
}

// What an export asks for, as the methods take it.
type urRecordExportParams struct {
	Log         string      `json:"log"`
	SinceMillis int64       `json:"since_millis,omitempty"`
	UntilMillis int64       `json:"until_millis,omitempty"`
	Run         *sidecar.Id `json:"run,omitempty"`
	Kinds       []uint32    `json:"kinds,omitempty"`
	Bodies      bool        `json:"bodies,omitempty"`
	Format      string      `json:"format,omitempty"`
	// a follow job's file, absolute
	Path string `json:"path,omitempty"`
}

// record.export's reply: the lines, none ending in a newline.
type urRecordExportReply struct {
	Lines        []string `json:"lines"`
	ReceiptsOnly bool     `json:"receipts_only,omitempty"`
}

// record.export.follow's reply.
type urRecordExportFollowReply struct {
	JobId sidecar.Id `json:"job_id"`
}

// What the export methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon
// read it.
type urRecordExportTarget interface {
	recordExport(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportReply, error)
	recordExportFollow(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportFollowReply, error)
}

// The export request for params on the hosted record. A request that carries body data taints the runs of a harness
// among the caller's ancestors first, and is refused when that taint fails.
func (self *urDaemonNetwork) recordExportArgs(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool, follow bool) (*sidecar.SidecarRecord, *sidecar.RecordExportArgs, error) {
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
	format, ok := sidecar.RecordExportFormatNamed(params.Format)
	if !ok {
		return nil, nil, fmt.Errorf("%w: format %q", sidecar.ErrRecordExportArgs, params.Format)
	}
	args := &sidecar.RecordExportArgs{
		LogId: logId, SinceMillis: params.SinceMillis, UntilMillis: params.UntilMillis, RunId: params.Run, Bodies: params.Bodies, Format: format, Confirmed: confirmed,
	}
	for _, kind := range params.Kinds {
		args.Kinds = append(args.Kinds, sidecar.RecordKind(kind))
	}
	if follow || params.Bodies || format != sidecar.RecordExportFormatJsonl {
		if err := running.TaintAncestorRuns(ctx, pid); err != nil {
			return nil, nil, fmt.Errorf("the runs of the harness this command runs under could not be tainted: %w", err)
		}
	}
	return record, args, nil
}

func (self *urDaemonNetwork) recordExport(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportReply, error) {
	record, args, err := self.recordExportArgs(ctx, params, pid, confirmed, false)
	if err != nil {
		return nil, err
	}
	exported, err := record.Export().Export(ctx, args)
	if err != nil {
		return nil, err
	}
	reply := &urRecordExportReply{Lines: []string{}, ReceiptsOnly: exported.ReceiptsOnly}
	for _, line := range exported.Lines {
		reply.Lines = append(reply.Lines, string(line))
	}
	return reply, nil
}

func (self *urDaemonNetwork) recordExportFollow(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportFollowReply, error) {
	if !filepath.IsAbs(params.Path) {
		return nil, fmt.Errorf("%w: a follow job takes an absolute file path", sidecar.ErrRecordExportArgs)
	}
	record, args, err := self.recordExportArgs(ctx, params, pid, confirmed, true)
	if err != nil {
		return nil, err
	}
	jobId, err := record.Export().Follow(ctx, args, params.Path)
	if err != nil {
		return nil, err
	}
	return &urRecordExportFollowReply{JobId: jobId}, nil
}

// The export methods over target, when it runs a Sidecar's record.
func urRecordExportMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	exports, ok := target.(urRecordExportTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			// a plain export runs unconfirmed; the record refuses body data from a call that is not confirmed
			Name: urMethodRecordExport,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordExportParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" {
					return nil, errors.New("an export takes the log")
				}
				return exports.recordExport(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
		{
			Name:    urMethodRecordExportFollow,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordExportParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" || params.Path == "" {
					return nil, errors.New("a follow job takes the log and a file")
				}
				return exports.recordExportFollow(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// A time as typed: RFC 3339, or a day, which is its first instant in UTC. Unix milliseconds.
func parseUrRecordTime(text string) (int64, error) {
	if text == "" {
		return 0, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.DateOnly} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.UnixMilli(), nil
		}
	}
	return 0, fmt.Errorf("%q is not a time: use 2026-11-05 or 2026-11-05T07:12:09Z", text)
}

// --kind's list: each a kind's name or its number.
func parseUrRecordKinds(text string) ([]uint32, error) {
	kinds := []uint32{}
	if text == "" {
		return kinds, nil
	}
	for _, name := range strings.Split(text, ",") {
		if kind, ok := sidecar.RecordKindNamed(name); ok {
			kinds = append(kinds, uint32(kind))
			continue
		}
		number, err := strconv.ParseUint(name, 10, 32)
		if err != nil || number == 0 {
			return nil, fmt.Errorf("%q is no kind's name or number", name)
		}
		kinds = append(kinds, uint32(number))
	}
	return kinds, nil
}

// Asks when the export carries body data or follows, then writes the lines the daemon answers.
func runUrRecordExport(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordExportParams{
		Log: urOptionString(options, "--log"), Bodies: urOptionBool(options, "--bodies"), Format: urOptionString(options, "--format"),
	}
	format, ok := sidecar.RecordExportFormatNamed(params.Format)
	if !ok {
		return fmt.Errorf("--format takes jsonl, ocsf or otel, not %q", params.Format)
	}
	var err error
	if params.SinceMillis, err = parseUrRecordTime(urOptionString(options, "--since")); err != nil {
		return err
	}
	if params.UntilMillis, err = parseUrRecordTime(urOptionString(options, "--until")); err != nil {
		return err
	}
	if params.Kinds, err = parseUrRecordKinds(urOptionString(options, "--kind")); err != nil {
		return err
	}
	if text := urOptionString(options, "--run"); text != "" {
		runId, err := parseUrRecordId(text)
		if err != nil {
			return err
		}
		params.Run = &runId
	}
	out := urOptionString(options, "--out")
	follow := urOptionBool(options, "--follow")
	if follow && out == "" {
		return errors.New("--follow takes --out, the file its job appends to")
	}
	confirmed := false
	if follow || params.Bodies || format != sidecar.RecordExportFormatJsonl {
		what := []string{}
		if params.Bodies {
			what = append(what, "bodies leave the log, with the addresses of relays, routes and actions and any captured text they hold")
		}
		if format != sidecar.RecordExportFormatJsonl {
			what = append(what, "the format carries the ids, hashes and counts of each body")
		}
		if follow {
			what = append(what, "a job in the daemon goes on appending to "+out+" while this sidecar reads the log")
		}
		confirmed, err = confirmOnTty(cli, "Export "+params.Log+": "+strings.Join(what, "; ")+". A copy that leaves is beyond recall. Go on?")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing was exported\n")
			return nil
		}
	}
	if follow {
		path, err := filepath.Abs(out)
		if err != nil {
			return fmt.Errorf("--out: %w", err)
		}
		params.Path = path
		reply := &urRecordExportFollowReply{}
		if err := cli.callDaemon(ctx, urMethodRecordExportFollow, params, true, reply); err != nil {
			return err
		}
		cli.printf("job %s follows %s into %s\n", reply.JobId, params.Log, path)
		return nil
	}
	var file *os.File
	if out != "" {
		if file, err = createUrRecordOut(out); err != nil {
			return err
		}
	}
	reply := &urRecordExportReply{}
	if err := cli.callDaemon(ctx, urMethodRecordExport, params, confirmed, reply); err != nil {
		if file != nil {
			file.Close()
			os.Remove(file.Name())
		}
		return err
	}
	text := ""
	if 0 < len(reply.Lines) {
		text = strings.Join(reply.Lines, "\n") + "\n"
	}
	if file == nil {
		cli.printf("%s", text)
		return nil
	}
	if err := writeUrRecordOut(file, []byte(text)); err != nil {
		return err
	}
	fmt.Fprintf(cli.stderr, "wrote %d lines to %s\n", len(reply.Lines), file.Name())
	return nil
}
