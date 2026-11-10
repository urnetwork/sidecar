// ur record disclose, open and verify (RECORD.md section 11, RECORD-M6-06).
//
//	ur record disclose --log=<log> (--entry=<id>... | --approval=<id> | --run=<id>) [--profile=<profile>]
//	                   [--recipient=<recipient>] [--purpose=<purpose>] [--content=<file>]... [--dry-run] --out=<file>
//	ur record open --entry=<id>... [--recipient=<recipient>] [--purpose=<purpose>] --out=<file>
//	ur record verify <packet> --log-key=<vkey>... [--witness=<vkey>]... [--quorum=<n>] [--ssh-key=<allowed_signers>]
//	                 [--format=<format>]
//
// disclose shows every field the packet would open, on the terminal, and builds it only on a yes; --dry-run prints
// the same list and builds nothing. The daemon files the log's disclosure entry and holds its commit before it
// answers, so the file is written only once the act is on record, and it refuses a caller with a harness process
// among its ancestors, by the pid the daemon itself read off the socket. open is the author's half, on a consented
// device of its vault. verify calls no daemon: it reads the packet and the keys on its command line, and exits 0
// when every check passed, 1 when one failed, and 2 when the file cannot be read.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur record disclose and open call.
const (
	urMethodRecordDisclosePlan = "record.disclose.plan"
	urMethodRecordDisclose     = "record.disclose"
	urMethodRecordOpen         = "record.open"
	// ur record verify's exit code for a file that cannot be read
	urExitUnreadable = 2
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "disclose",
		usage: []string{
			"  ur record disclose --log=<log> (--entry=<id>... | --approval=<id> | --run=<id>) [--profile=<profile>] [--recipient=<recipient>] [--purpose=<purpose>] [--content=<file>]... [--dry-run] --out=<file>",
		},
		run: runUrRecordDisclose,
	})
	registerUrRecordPart(&urRecordPart{
		word:  "open",
		usage: []string{"  ur record open --entry=<id>... [--recipient=<recipient>] [--purpose=<purpose>] --out=<file>"},
		run:   runUrRecordOpen,
	})
	registerUrRecordPart(&urRecordPart{
		word: "verify",
		usage: []string{
			"  ur record verify <packet> --log-key=<vkey>... [--witness=<vkey>]... [--quorum=<n>] [--ssh-key=<allowed_signers>] [--format=<format>]",
		},
		run: runUrRecordVerify,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordDiscloseMethods)
}

// What a disclosure asks for, as the methods take it.
type urRecordDiscloseParams struct {
	Log       string       `json:"log"`
	Entries   []sidecar.Id `json:"entries,omitempty"`
	Approval  *sidecar.Id  `json:"approval,omitempty"`
	Run       *sidecar.Id  `json:"run,omitempty"`
	Profile   string       `json:"profile,omitempty"`
	Recipient string       `json:"recipient,omitempty"`
	Purpose   string       `json:"purpose,omitempty"`
	// each --content file's bytes
	Content [][]byte `json:"content,omitempty"`
	// the entries the person was shown, which the packet must hold and no other
	Expect []sidecar.Id `json:"expect,omitempty"`
}

// record.open's params.
type urRecordOpenParams struct {
	Entries   []sidecar.Id `json:"entries"`
	Recipient string       `json:"recipient,omitempty"`
	Purpose   string       `json:"purpose,omitempty"`
}

// One entry of a plan.
type urRecordDiscloseItem struct {
	EntryId      sidecar.Id `json:"entry_id"`
	Kind         string     `json:"kind"`
	TimeMillis   int64      `json:"time_millis"`
	Opened       bool       `json:"opened"`
	Erased       bool       `json:"erased,omitempty"`
	Fields       []string   `json:"fields,omitempty"`
	ContentCount int        `json:"content_count,omitempty"`
}

// A plan, and with a packet's bytes, a disclosure made.
type urRecordDisclosedReply struct {
	LogId   sidecar.Id              `json:"log_id"`
	Profile string                  `json:"profile"`
	Items   []*urRecordDiscloseItem `json:"items"`
	// the packet file's bytes and their SHA-256; empty for a plan
	Packet       []byte `json:"packet,omitempty"`
	PacketSha256 string `json:"packet_sha256,omitempty"`
	ReceiptsOnly bool   `json:"receipts_only,omitempty"`
}

// What the disclosure methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the
// daemon read it.
type urRecordDiscloseTarget interface {
	recordDisclosePlan(ctx context.Context, params *urRecordDiscloseParams, pid int) (*urRecordDisclosedReply, error)
	recordDisclose(ctx context.Context, params *urRecordDiscloseParams, pid int, confirmed bool) (*urRecordDisclosedReply, error)
	recordOpen(ctx context.Context, params *urRecordOpenParams, pid int, confirmed bool) (*urRecordDisclosedReply, error)
}

// A plan as the reply carries it.
func urRecordDisclosedReplyOf(plan *sidecar.RecordDisclosurePlan) *urRecordDisclosedReply {
	reply := &urRecordDisclosedReply{LogId: plan.LogId, Profile: string(plan.Profile), Items: []*urRecordDiscloseItem{}}
	for _, item := range plan.Items {
		reply.Items = append(reply.Items, &urRecordDiscloseItem{
			EntryId: item.EntryId, Kind: item.Kind.String(), TimeMillis: item.TimeMillis, Opened: item.Opened, Erased: item.Erased,
			Fields: item.Fields, ContentCount: item.ContentCount,
		})
	}
	return reply
}

// The disclosure request for params on the hosted record, with whether pid runs under a harness.
func (self *urDaemonNetwork) recordDiscloseArgs(ctx context.Context, params *urRecordDiscloseParams, pid int) (*sidecar.SidecarRecord, *sidecar.RecordDiscloseArgs, error) {
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
	return record, &sidecar.RecordDiscloseArgs{
		LogId: logId, EntryIds: params.Entries, ApprovalId: params.Approval, RunId: params.Run, Profile: sidecar.RecordDisclosureProfile(params.Profile),
		Recipient: params.Recipient, Purpose: params.Purpose, Content: params.Content, ExpectEntryIds: params.Expect,
		HarnessAncestor: running.HarnessAncestor(ctx, pid),
	}, nil
}

func (self *urDaemonNetwork) recordDisclosePlan(ctx context.Context, params *urRecordDiscloseParams, pid int) (*urRecordDisclosedReply, error) {
	record, args, err := self.recordDiscloseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	plan, err := record.Disclosure().Plan(ctx, args)
	if err != nil {
		return nil, err
	}
	return urRecordDisclosedReplyOf(plan), nil
}

func (self *urDaemonNetwork) recordDisclose(ctx context.Context, params *urRecordDiscloseParams, pid int, confirmed bool) (*urRecordDisclosedReply, error) {
	record, args, err := self.recordDiscloseArgs(ctx, params, pid)
	if err != nil {
		return nil, err
	}
	args.Confirmed = confirmed
	disclosed, err := record.Disclosure().Disclose(ctx, args)
	if err != nil {
		return nil, err
	}
	reply := urRecordDisclosedReplyOf(disclosed.Plan)
	reply.Packet, reply.PacketSha256, reply.ReceiptsOnly = disclosed.Packet, hex.EncodeToString(disclosed.PacketSha256[:]), disclosed.ReceiptsOnly
	return reply, nil
}

func (self *urDaemonNetwork) recordOpen(ctx context.Context, params *urRecordOpenParams, pid int, confirmed bool) (*urRecordDisclosedReply, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	disclosed, err := record.Disclosure().Open(ctx, &sidecar.RecordOpenArgs{
		EntryIds: params.Entries, Recipient: params.Recipient, Purpose: params.Purpose, Confirmed: confirmed, HarnessAncestor: running.HarnessAncestor(ctx, pid),
	})
	if err != nil {
		return nil, err
	}
	reply := urRecordDisclosedReplyOf(disclosed.Plan)
	reply.Packet, reply.PacketSha256 = disclosed.Packet, hex.EncodeToString(disclosed.PacketSha256[:])
	return reply, nil
}

// The pid of a call's process, as the daemon read it off the socket: 0 where the system gave none, which the
// ancestry check then refuses.
func urCallPid(call *sidecar.DaemonCall) int {
	if call.Hello == nil {
		return 0
	}
	return int(call.Hello.PeerPid)
}

// The disclosure methods over target, when it runs a Sidecar's record.
func urRecordDiscloseMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	disclosures, ok := target.(urRecordDiscloseTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodRecordDisclosePlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordDiscloseParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" {
					return nil, errors.New("a disclosure takes the log and what to disclose")
				}
				return disclosures.recordDisclosePlan(ctx, params, urCallPid(call))
			},
		},
		{
			Name:    urMethodRecordDisclose,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordDiscloseParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" {
					return nil, errors.New("a disclosure takes the log and what to disclose")
				}
				return disclosures.recordDisclose(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
		{
			Name:    urMethodRecordOpen,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordOpenParams{}
				if err := decodeUrParams(call, params); err != nil || len(params.Entries) == 0 {
					return nil, errors.New("an opening takes the entries to open")
				}
				return disclosures.recordOpen(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// An error that ends ur with a code of its own.
type urExitError struct {
	code int
	err  error
}

// The error's own text.
func (self *urExitError) Error() string {
	return self.err.Error()
}

// The error it carries.
func (self *urExitError) Unwrap() error {
	return self.err
}

// Ids as typed: dashed, or 32 hex characters.
func parseUrRecordIds(texts []string) ([]sidecar.Id, error) {
	ids := []sidecar.Id{}
	for _, text := range texts {
		id, err := parseUrRecordId(text)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// One id as typed.
func parseUrRecordId(text string) (sidecar.Id, error) {
	if id, err := sidecar.ParseId(text); err == nil {
		return id, nil
	}
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == len(sidecar.Id{}) {
		return sidecar.Id(decoded), nil
	}
	return sidecar.Id{}, fmt.Errorf("%q is not an id", text)
}

// What a packet opens, a line an entry, for the terminal and for --dry-run.
func printUrRecordDisclosePlan(out interface{ Write([]byte) (int, error) }, reply *urRecordDisclosedReply) {
	fmt.Fprintf(out, "log %s, profile %s: %d entries\n", reply.LogId, reply.Profile, len(reply.Items))
	for _, item := range reply.Items {
		when := time.UnixMilli(item.TimeMillis).UTC().Format(time.RFC3339)
		switch {
		case item.Erased:
			fmt.Fprintf(out, "  %s  %s  %s  erased: its header alone\n", item.EntryId, item.Kind, when)
		case !item.Opened:
			fmt.Fprintf(out, "  %s  %s  %s  its header alone\n", item.EntryId, item.Kind, when)
		default:
			fmt.Fprintf(out, "  %s  %s  %s  opens: %s\n", item.EntryId, item.Kind, when, strings.Join(item.Fields, ", "))
		}
		if 0 < item.ContentCount {
			fmt.Fprintf(out, "      with %d of its author's openings\n", item.ContentCount)
		}
	}
	fmt.Fprintf(out, "Every header goes too: its kind, time, writer, run, agent, action and grant ids. A copy that leaves is beyond recall.\n")
}

// Creates the file a packet goes to, refusing to replace one, before anything is put on record.
func createUrRecordOut(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("--out takes a file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("--out: %w", err)
	}
	return file, nil
}

// Writes a packet to its file, removing the file when the write fails.
func writeUrRecordOut(file *os.File, packet []byte) error {
	_, err := file.Write(packet)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(file.Name())
		return fmt.Errorf("--out: %w", err)
	}
	return nil
}

// Shows the plan, asks, then has the daemon build the packet and writes it.
func runUrRecordDisclose(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordDiscloseParams{
		Log: urOptionString(options, "--log"), Profile: urOptionString(options, "--profile"),
		Recipient: urOptionString(options, "--recipient"), Purpose: urOptionString(options, "--purpose"),
	}
	var err error
	if params.Entries, err = parseUrRecordIds(urOptionStrings(options, "--entry")); err != nil {
		return err
	}
	if text := urOptionString(options, "--approval"); text != "" {
		approvalId, err := parseUrRecordId(text)
		if err != nil {
			return err
		}
		params.Approval = &approvalId
	}
	if text := urOptionString(options, "--run"); text != "" {
		runId, err := parseUrRecordId(text)
		if err != nil {
			return err
		}
		params.Run = &runId
	}
	for _, path := range urOptionStrings(options, "--content") {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("--content: %w", err)
		}
		params.Content = append(params.Content, content)
	}
	plan := &urRecordDisclosedReply{}
	if err := cli.callDaemon(ctx, urMethodRecordDisclosePlan, params, false, plan); err != nil {
		return err
	}
	if urOptionBool(options, "--dry-run") {
		printUrRecordDisclosePlan(cli.stdout, plan)
		return nil
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	printUrRecordDisclosePlan(tty, plan)
	tty.Close()
	confirmed, err := confirmOnTty(cli, "Write this packet for "+strconv.Quote(params.Recipient)+" and record the disclosure in the log?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was disclosed\n")
		return nil
	}
	file, err := createUrRecordOut(urOptionString(options, "--out"))
	if err != nil {
		return err
	}
	for _, item := range plan.Items {
		params.Expect = append(params.Expect, item.EntryId)
	}
	disclosed := &urRecordDisclosedReply{}
	if err := cli.callDaemon(ctx, urMethodRecordDisclose, params, true, disclosed); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}
	if err := writeUrRecordOut(file, disclosed.Packet); err != nil {
		return err
	}
	record := "its disclosure entry is in the log"
	if disclosed.ReceiptsOnly {
		record = "this device's read receipts are its record"
	}
	cli.printf("wrote %s, sha256 %s; %s\n", file.Name(), disclosed.PacketSha256, record)
	return nil
}

// Asks, then has the daemon open the vault entries and writes the file.
func runUrRecordOpen(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordOpenParams{Recipient: urOptionString(options, "--recipient"), Purpose: urOptionString(options, "--purpose")}
	var err error
	if params.Entries, err = parseUrRecordIds(urOptionStrings(options, "--entry")); err != nil {
		return err
	}
	question := fmt.Sprintf("Open the bodies of %d entries of your vault for %s, and record it there?", len(params.Entries), strconv.Quote(params.Recipient))
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was opened\n")
		return nil
	}
	file, err := createUrRecordOut(urOptionString(options, "--out"))
	if err != nil {
		return err
	}
	opened := &urRecordDisclosedReply{}
	if err := cli.callDaemon(ctx, urMethodRecordOpen, params, true, opened); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}
	if err := writeUrRecordOut(file, opened.Packet); err != nil {
		return err
	}
	cli.printf("wrote %s, sha256 %s; its disclosure entry is in your vault\n", file.Name(), opened.PacketSha256)
	return nil
}

// Verifies a packet with what the command line pins, calling no daemon and opening nothing but the packet.
func runUrRecordVerify(ctx context.Context, cli *urCli, options docopt.Opts) error {
	args := &sidecar.RecordVerifyArgs{
		LogKeys: urOptionStrings(options, "--log-key"), WitnessKeys: urOptionStrings(options, "--witness"),
		SshKeys: urOptionString(options, "--ssh-key") != "",
	}
	if text := urOptionString(options, "--quorum"); text != "" {
		quorum, err := strconv.Atoi(text)
		if err != nil || quorum <= 0 {
			return fmt.Errorf("--quorum takes a count, not %q", text)
		}
		args.Quorum = quorum
	}
	format := urOptionString(options, "--format")
	if format != "" && format != "text" && format != "json" {
		return fmt.Errorf("--format takes text or json, not %q", format)
	}
	packet, err := os.ReadFile(urOptionString(options, "<packet>"))
	if err != nil {
		return &urExitError{code: urExitUnreadable, err: err}
	}
	report, err := sidecar.VerifyRecordDisclosurePacket(packet, args)
	if errors.Is(err, sidecar.ErrRecordPacketUnreadable) {
		return &urExitError{code: urExitUnreadable, err: err}
	}
	if err != nil {
		return err
	}
	if format == "json" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		cli.printf("%s\n", encoded)
	} else {
		printUrRecordVerifyReport(cli, report)
	}
	if !report.Ok {
		return errors.New("a check failed")
	}
	return nil
}

// The report, a line a note, an entry and a key.
func printUrRecordVerifyReport(cli *urCli, report *sidecar.RecordVerifyReport) {
	cli.printf("log %s, origin %s\n", report.LogId, report.Origin)
	if report.Purpose != "" {
		cli.printf("purpose, as its sender typed it: %s\n", strconv.Quote(report.Purpose))
	}
	for i, checkpoint := range report.Checkpoints {
		cli.printf("checkpoint %d: size %d", i, checkpoint.Size)
		if checkpoint.LogKey != "" {
			cli.printf(", signed by the log key given")
		}
		if len(checkpoint.Cosigned) == 0 {
			cli.printf("; no witness cosigned it, so it is the team's own statement")
		}
		for _, cosigned := range checkpoint.Cosigned {
			cli.printf("; cosigned by %s at %s", cosigned.Name, time.Unix(int64(cosigned.TimeSeconds), 0).UTC().Format(time.RFC3339))
		}
		cli.printf("\n")
		for _, failure := range checkpoint.Failures {
			cli.printf("  FAILED: %s\n", failure)
		}
	}
	pass := func(passed bool) string {
		if passed {
			return "ok"
		}
		return "FAILED"
	}
	for _, entry := range report.Entries {
		body := "header alone"
		if entry.Opened {
			body = "body " + pass(entry.Body)
		}
		cli.printf("entry %s  %s  %s  in the log: %s; header: %s; %s", entry.EntryId, entry.Kind, time.UnixMilli(entry.TimeMillis).UTC().Format(time.RFC3339),
			pass(entry.Inclusion), pass(entry.Header), body)
		if 0 < entry.ContentCount {
			cli.printf("; %d content openings: %s", entry.ContentCount, pass(entry.Content))
		}
		if entry.Kind == sidecar.RecordKindApprovalDecision && entry.Opened {
			cli.printf("; decision: %s", pass(entry.Approval))
		}
		cli.printf("\n")
		for _, failure := range entry.Failures {
			cli.printf("  FAILED: %s\n", failure)
		}
	}
	for _, key := range report.Keys {
		cli.printf("key of %s: %s (the team's statement: no check here ties a key to a person)\n", key.SidecarId, strconv.Quote(key.Label))
	}
	for _, failure := range report.Failures {
		cli.printf("FAILED: %s\n", failure)
	}
	if report.Ok {
		cli.printf("every check passed. A packet shows these entries were in the team's log under these notes; it does not show the log holds every action.\n")
	}
}
