// ur support's conversation forms (DESIGN-COMPUTE §28.4, §15.1, D-SUP-1), each over the network's support client in
// the daemon (the root's support_client.go), which alone holds the feedback service's token and the outbox:
//
//	ur support [--json] [--network=<net>]
//	    the items: at a terminal no run binds, the member's whole conversation; from a harness's process, its agent's
//	    items, as support_list's stubs, never text
//	ur support show <id> [--json] [--network=<net>]
//	    one item, its messages and support's replies, printed only to the terminal and first tainting each run the
//	    caller's process ancestry binds, as ur calendar does
//	ur support send <text> [--re=<id>] [--kind=<k>] [--logs] [--attach=<file>...] [--network=<net>]
//	    at a terminal no run binds, the person's own message, tier human, confirmed on /dev/tty, its files read where
//	    the person names them; from a harness's process, that run's message, kind 27, which the person decides
//	    (Q-SUP-8), its files read beneath the run's worktree and always the person's to approve (rule attachment). ur
//	    names each file by its absolute path and the daemon reads it, so no file rides the request
//	ur support report <code> [--network=<net>]
//	    FB section 10.3's enumerated report of one of the support log's codes, unchanged: at a terminal no run binds,
//	    the person's, confirmed on /dev/tty; from a harness's process, an agent's, which needs FB's feedback.auto grant
//	    that nothing builds yet, so it is refused grant_required
//	ur support watch [<id>] [--notes] [--network=<net>]
//	    FB's feedback.watch: a line for each event of the member's conversation, or of one item, its enumerated fields
//	    alone; --notes adds each reply's text, after tainting each run the caller's process ancestry binds (§28.9)
//	ur support delete <id> [--network=<net>]
//	    the item's bodies and attachments removed at the service (FB section 10.4), confirmed on /dev/tty
//	ur support settings [--network=<net>]
//	ur support set [--agents=<on|off>] [--agent-logs=<on|off>] [--network=<net>]
//	    the person's support key, set only on /dev/tty, refused to a caller under a harness (§28.6)
//
// ur support logs and ur support export are cmd_support.go's. Until G-SUP-service passes, the release's switch is off:
// send and report answer that support is reached through the app's form, nothing is posted, and the conversation the
// other forms read stays empty (§28.21).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur support's conversation forms call.
const (
	urMethodSupportCaller      = "support.caller"
	urMethodSupportList        = "support.ls"
	urMethodSupportShow        = "support.show"
	urMethodSupportSend        = "support.send"
	urMethodSupportAgentSend   = "support.agent_send"
	urMethodSupportDelete      = "support.delete"
	urMethodSupportSettings    = "support.settings"
	urMethodSupportSet         = "support.set"
	urMethodSupportWatch       = "support.watch"
	urMethodSupportReport      = "support.report"
	urMethodSupportAgentReport = "support.agent_report"
)

// The person's acts, refused to a caller with a harness process among its ancestors (§28.6).
var errUrSupportPersonOnly = errors.New("this is the person's own act, at a terminal with no harness process among its ancestors (§28.6)")

// Adds the conversation's control methods to the daemon's.
func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urSupportConversationMethods)
}

// The conversation methods' params.
type urSupportParams struct {
	Network string `json:"network,omitempty"`
	Entry   string `json:"entry,omitempty"`
	Status  string `json:"status,omitempty"`
	Text    string `json:"text,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Logs    bool   `json:"logs,omitempty"`
	// each file an app's person chose, its base name and bytes; ur names its files in paths instead, which an agent's
	// message must
	Files []*urSupportFile `json:"files,omitempty"`
	// each file ur names, by its absolute path, which the daemon reads: the person's where they name it, a harness
	// process's beneath its run's worktree
	Paths []string `json:"paths,omitempty"`
	// report: one of the support log's codes, component.code
	Code string `json:"code,omitempty"`
	// a person's message the scan warned on, which the person confirmed
	SecretConfirmed bool   `json:"secret_confirmed,omitempty"`
	Agents          string `json:"agents,omitempty"`
	AgentLogs       string `json:"agent_logs,omitempty"`
	// watch: replies' text too, tainting first
	Notes bool `json:"notes,omitempty"`
}

// support.watch's reply: the updates since the call began, each with a reply's text where notes asked for it.
type urSupportWatchReply struct {
	Updates []*urSupportWatchLine `json:"updates"`
}

// One update as watch prints it.
type urSupportWatchLine struct {
	Update *sidecar.SupportUpdate `json:"update"`
	// a note's text, with --notes alone
	Note string `json:"note,omitempty"`
}

// One file ur read for a message.
type urSupportFile struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// support.caller's reply: whether the caller runs under a harness.
type urSupportCallerReply struct {
	UnderHarness bool `json:"under_harness"`
}

// support.ls's reply.
type urSupportListReply struct {
	Items []*sidecar.SupportItemStub `json:"items"`
}

// What a send's refusal carries back to ur, so it can ask the person about a warning.
type urSupportSendReply struct {
	Result  *sidecar.SupportSendResult `json:"result,omitempty"`
	Refusal string                     `json:"refusal,omitempty"`
	Detail  string                     `json:"detail,omitempty"`
}

// The network's support client, or why there is none.
func urSupportClient(call *sidecar.DaemonCall) (*sidecar.SupportClient, error) {
	if call.Sidecar == nil {
		return nil, errors.New("no sidecar runs for this network")
	}
	client, err := call.Sidecar.Support()
	if err != nil {
		return nil, sidecar.ErrSupportUnavailable
	}
	return client, nil
}

// The conversation methods, over the daemon's hosted networks.
func urSupportConversationMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	daemonOf := func(call *sidecar.DaemonCall) []*sidecar.Sidecar {
		hosted := []*sidecar.Sidecar{}
		for _, network := range call.Networks {
			hosted = append(hosted, network.Sidecar)
		}
		if call.Sidecar != nil {
			hosted = append(hosted, call.Sidecar)
		}
		return hosted
	}
	underHarness := func(ctx context.Context, call *sidecar.DaemonCall) bool {
		if call.Hello == nil || call.Hello.PeerPid <= 0 {
			return true
		}
		for _, hosted := range daemonOf(call) {
			if hosted.HarnessAncestor(ctx, int(call.Hello.PeerPid)) {
				return true
			}
		}
		return false
	}
	agentName := func(call *sidecar.DaemonCall) string {
		if call.Agent != nil && call.Agent.Label != "" {
			return call.Agent.Label
		}
		return "harness"
	}
	decode := func(call *sidecar.DaemonCall) (*urSupportParams, *sidecar.SupportClient, error) {
		params := &urSupportParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, nil, err
		}
		client, err := urSupportClient(call)
		return params, client, err
	}
	// A refusal as a reply ur reads, any other error as the call's.
	answer := func(result *sidecar.SupportSendResult, err error) (any, error) {
		var refusal *sidecar.SupportRefusalError
		if errors.As(err, &refusal) {
			return &urSupportSendReply{Refusal: string(refusal.Refusal), Detail: refusal.Error()}, nil
		}
		if err != nil {
			return nil, err
		}
		return &urSupportSendReply{Result: result}, nil
	}
	// The agent a harness's process sends as, and the run its ancestry binds, nil for none.
	agentOf := func(ctx context.Context, call *sidecar.DaemonCall, where string) (*sidecar.SupportSender, *sidecar.RunFile) {
		sender := &sidecar.SupportSender{AgentName: agentName(call), Where: where}
		if call.Agent != nil {
			sender.AgentId = call.Agent.Id
		}
		var run *sidecar.RunFile
		if call.Hello != nil && 0 < call.Hello.PeerPid {
			run, _ = call.Sidecar.SupportCallerRun(ctx, int(call.Hello.PeerPid))
		}
		return sender, run
	}
	send := func(ctx context.Context, call *sidecar.DaemonCall, surface sidecar.SupportSurface) (any, error) {
		params, client, err := decode(call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.SupportSendArgs{
			Surface: surface, Text: params.Text, Entry: params.Entry, Kind: params.Kind, Logs: params.Logs,
			SecretConfirmed: params.SecretConfirmed,
		}
		if surface == sidecar.SupportSurfacePerson {
			// the person's own: an app's chosen bytes, and ur's files where the person named them
			for _, file := range params.Files {
				args.Files = append(args.Files, &sidecar.SupportFile{Name: file.Name, Data: file.Data})
			}
			if 0 < len(params.Paths) {
				files, err := sidecar.SupportReadPersonFiles(params.Paths, client.Settings())
				if err != nil {
					return answer(nil, err)
				}
				args.Files = append(args.Files, files...)
			}
			return answer(client.Send(ctx, args))
		}
		// a harness process's: its run's message, its files read beneath the run's worktree as the Harness's file
		// tools read them, never bytes it read itself
		if 0 < len(params.Files) {
			return answer(nil, &sidecar.SupportRefusalError{Refusal: sidecar.SupportRefusalFileRefused})
		}
		sender, run := agentOf(ctx, call, "ur support send")
		args.Sender = sender
		if run != nil {
			args.Run = sidecar.SupportRunOfFile(run.RunId, run)
		}
		if 0 < len(params.Paths) {
			root := ""
			switch {
			case run != nil && run.Worktree != "":
				root = run.Worktree
			case call.Hello != nil:
				root = call.Hello.Cwd
			}
			files, err := sidecar.SupportReadFiles(root, params.Paths, client.Settings())
			if err != nil {
				return answer(nil, err)
			}
			args.Files = files
		}
		return answer(client.Send(ctx, args))
	}
	report := func(ctx context.Context, call *sidecar.DaemonCall, surface sidecar.SupportSurface) (any, error) {
		params, client, err := decode(call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.SupportReportArgs{Surface: surface, Code: params.Code, Host: urSupportLogHost()}
		if surface != sidecar.SupportSurfacePerson {
			args.Sender, _ = agentOf(ctx, call, "ur support report")
		}
		return answer(client.Report(ctx, args))
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodSupportCaller,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return &urSupportCallerReply{UnderHarness: underHarness(ctx, call)}, nil
			},
		},
		{
			Name:    urMethodSupportList,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				args := &sidecar.SupportListArgs{Status: params.Status}
				if underHarness(ctx, call) {
					args.AgentName = agentName(call)
				}
				items, err := client.List(args)
				if err != nil {
					return nil, err
				}
				return &urSupportListReply{Items: items}, nil
			},
		},
		{
			Name:    urMethodSupportShow,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				args := &sidecar.SupportReadArgs{Entry: params.Entry}
				if underHarness(ctx, call) {
					args.AgentName = agentName(call)
				}
				// every run the caller's ancestry binds is tainted before a reply's text returns (§28.9)
				args.Taint = func(ctx context.Context) error {
					return call.Sidecar.TaintAncestorRuns(ctx, int(call.Hello.PeerPid))
				}
				return client.Read(ctx, args)
			},
		},
		{
			Name:    urMethodSupportSend,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				if underHarness(ctx, call) {
					return nil, errUrSupportPersonOnly
				}
				return send(ctx, call, sidecar.SupportSurfacePerson)
			},
		},
		{
			Name:    urMethodSupportAgentSend,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				// a harness's process: its run's message, which the person decides (Q-SUP-8)
				return send(ctx, call, sidecar.SupportSurfaceCliHarness)
			},
		},
		{
			Name:    urMethodSupportReport,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				if underHarness(ctx, call) {
					return nil, errUrSupportPersonOnly
				}
				return report(ctx, call, sidecar.SupportSurfacePerson)
			},
		},
		{
			Name:    urMethodSupportAgentReport,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				// a harness's process: an agent's report, which needs FB's feedback.auto grant
				return report(ctx, call, sidecar.SupportSurfaceCliHarness)
			},
		},
		{
			Name:    urMethodSupportWatch,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				if params.Notes {
					// a reply's text reaches the caller only once every run its ancestry binds is tainted (§28.9)
					if err := call.Sidecar.TaintAncestorRuns(ctx, int(call.Hello.PeerPid)); err != nil {
						return nil, err
					}
				}
				updates := make(chan *sidecar.SupportUpdate, 64)
				remove := client.AddListener(func(update *sidecar.SupportUpdate) {
					if params.Entry != "" && update.Entry != params.Entry {
						return
					}
					select {
					case updates <- update:
					default:
					}
				})
				defer remove()
				reply := &urSupportWatchReply{Updates: []*urSupportWatchLine{}}
				select {
				case update := <-updates:
					reply.Updates = append(reply.Updates, &urSupportWatchLine{Update: update})
				case <-call.SessionDone:
					return reply, nil
				case <-ctx.Done():
					return reply, nil
				case <-time.After(client.Settings().WatchWait):
					return reply, nil
				}
				for drained := false; !drained; {
					select {
					case update := <-updates:
						reply.Updates = append(reply.Updates, &urSupportWatchLine{Update: update})
					default:
						drained = true
					}
				}
				if params.Notes {
					for _, line := range reply.Updates {
						if line.Update.Type != "note" || line.Update.Seq == 0 {
							continue
						}
						read, err := client.Read(ctx, &sidecar.SupportReadArgs{Entry: line.Update.Entry, After: line.Update.Seq - 1})
						if err == nil && 0 < len(read.Messages) {
							line.Note = read.Messages[0].Text
						}
					}
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodSupportDelete,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				if underHarness(ctx, call) {
					return nil, errUrSupportPersonOnly
				}
				params, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				return nil, client.Delete(ctx, params.Entry)
			},
		},
		{
			Name:    urMethodSupportSettings,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				_, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				return client.PersonKey()
			},
		},
		{
			Name:    urMethodSupportSet,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				if underHarness(ctx, call) {
					return nil, errUrSupportPersonOnly
				}
				params, client, err := decode(call)
				if err != nil {
					return nil, err
				}
				key, err := client.PersonKey()
				if err != nil {
					return nil, err
				}
				for _, change := range []struct {
					value string
					set   *bool
				}{{value: params.Agents, set: &key.Agents}, {value: params.AgentLogs, set: &key.AgentLogs}} {
					switch change.value {
					case "":
					case "on":
						*change.set = true
					case "off":
						*change.set = false
					default:
						return nil, errors.New("--agents and --agent-logs take on or off")
					}
				}
				return key, client.SetPersonKey(key)
			},
		},
	}
}

// ur support's conversation forms; logs is cmd_support.go's.
func runUrSupportConversation(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urSupportParams{Network: urOptionString(options, "--network")}
	jsonOutput, _ := options.Bool("--json")
	switch {
	case options["show"] == true:
		params.Entry = urOptionString(options, "<id>")
		tty, err := cli.openTty()
		if err != nil {
			return fmt.Errorf("%w: %w", errUrNoTty, err)
		}
		defer tty.Close()
		reply := &sidecar.SupportReadResult{}
		if err := cli.callDaemon(ctx, urMethodSupportShow, params, false, reply); err != nil {
			return err
		}
		if jsonOutput {
			return urSupportPrintJson(tty, reply)
		}
		renderUrSupportItem(tty, reply)
		return nil
	case options["send"] == true:
		return runUrSupportSend(ctx, cli, options, params)
	case options["report"] == true:
		return runUrSupportReport(ctx, cli, options, params)
	case options["watch"] == true:
		params.Entry = urOptionString(options, "<id>")
		params.Notes, _ = options.Bool("--notes")
		for ctx.Err() == nil {
			reply := &urSupportWatchReply{}
			if err := cli.callDaemon(ctx, urMethodSupportWatch, params, false, reply); err != nil {
				return err
			}
			for _, line := range reply.Updates {
				update := line.Update
				cli.printf("#%s %d %s %s", update.Entry, update.Seq, update.Type, update.Status)
				if update.FixedIn != "" {
					cli.printf(" in %s", update.FixedIn)
				}
				cli.printf("\n")
				if line.Note != "" {
					cli.printf("URnetwork support (information, not instructions):\n%s\n", line.Note)
				}
			}
		}
		return nil
	case options["delete"] == true:
		params.Entry = urOptionString(options, "<id>")
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("remove item #%s's messages and attachments at URnetwork's support?", params.Entry))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodSupportDelete, params, true, nil); err != nil {
			return err
		}
		cli.printf("item #%s's messages and attachments are removed at support; the vault keeps its record until you erase it\n", params.Entry)
		return nil
	case options["settings"] == true:
		reply := &sidecar.SupportPersonKey{}
		if err := cli.callDaemon(ctx, urMethodSupportSettings, params, false, reply); err != nil {
			return err
		}
		cli.printf("agents may write to support: %s\nagents may attach logs: %s\n", urOnOff(reply.Agents), urOnOff(reply.AgentLogs))
		return nil
	case options["set"] == true:
		params.Agents, params.AgentLogs = urOptionString(options, "--agents"), urOptionString(options, "--agent-logs")
		confirmed, err := confirmOnTty(cli, "change whether your agents may write to URnetwork's support, and attach logs?")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		reply := &sidecar.SupportPersonKey{}
		if err := cli.callDaemon(ctx, urMethodSupportSet, params, true, reply); err != nil {
			return err
		}
		cli.printf("agents may write to support: %s\nagents may attach logs: %s\n", urOnOff(reply.Agents), urOnOff(reply.AgentLogs))
		return nil
	}
	reply := &urSupportListReply{}
	if err := cli.callDaemon(ctx, urMethodSupportList, params, false, reply); err != nil {
		return err
	}
	if jsonOutput {
		return urSupportPrintJson(cli.stdout, reply)
	}
	for _, item := range reply.Items {
		entry := item.Entry
		if entry == "" {
			entry = "(new)"
		}
		cli.printf("#%s  %-12s %d messages, %d replies (%d unread)  %s\n", entry, item.Status, item.Messages, item.Replies,
			item.UnreadReplies, strings.Join(item.Senders, ", "))
	}
	if len(reply.Items) == 0 {
		cli.printf("no items\n")
	}
	return nil
}

// ur support send: the person's message at a terminal no run binds, confirmed on /dev/tty, warned on a secret first;
// a harness process's otherwise.
func runUrSupportSend(ctx context.Context, cli *urCli, options docopt.Opts, params *urSupportParams) error {
	params.Text = urOptionString(options, "<text>")
	params.Entry = urOptionString(options, "--re")
	params.Kind = urOptionString(options, "--kind")
	params.Logs, _ = options.Bool("--logs")
	attach, _ := options["--attach"].([]string)
	for _, path := range attach {
		// the daemon reads each file, beneath a harness run's worktree or where the person names it
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		params.Paths = append(params.Paths, absolute)
	}
	caller := &urSupportCallerReply{}
	if err := cli.callDaemon(ctx, urMethodSupportCaller, params, false, caller); err != nil {
		return err
	}
	reply := &urSupportSendReply{}
	if caller.UnderHarness {
		if err := cli.callDaemon(ctx, urMethodSupportAgentSend, params, false, reply); err != nil {
			return err
		}
	} else {
		confirmed, err := confirmOnTty(cli, "send this to URnetwork's support, whose team and the subprocessors its disclosure names will read it?")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing sent\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodSupportSend, params, true, reply); err != nil {
			return err
		}
		if reply.Refusal == string(sidecar.SupportRefusalSecretWarned) {
			// FB section 10.1: the scan warns the person, who decides
			confirmed, err := confirmOnTty(cli, "it looks like this holds a secret ("+reply.Detail+"); send it anyway?")
			if err != nil {
				return err
			}
			if !confirmed {
				cli.printf("nothing sent\n")
				return nil
			}
			params.SecretConfirmed = true
			reply = &urSupportSendReply{}
			if err := cli.callDaemon(ctx, urMethodSupportSend, params, true, reply); err != nil {
				return err
			}
		}
	}
	if reply.Refusal != "" {
		return errors.New(reply.Detail)
	}
	switch {
	case reply.Result == nil:
		return errors.New("support: no answer")
	case reply.Result.ApprovalId != nil:
		cli.printf("waiting for your approval: ur approve %s\n", reply.Result.ApprovalId)
	default:
		cli.printf("queued; it goes to URnetwork's support as soon as it can be reached (client_ref %s)\n", reply.Result.ClientRef)
	}
	return nil
}

// ur support report <code>: the person's enumerated report at a terminal no run binds, confirmed on /dev/tty; a
// harness process's otherwise, an agent's, which the daemon refuses until FB's feedback.auto grant exists.
func runUrSupportReport(ctx context.Context, cli *urCli, options docopt.Opts, params *urSupportParams) error {
	params.Code = urOptionString(options, "<code>")
	caller := &urSupportCallerReply{}
	if err := cli.callDaemon(ctx, urMethodSupportCaller, params, false, caller); err != nil {
		return err
	}
	reply := &urSupportSendReply{}
	if caller.UnderHarness {
		if err := cli.callDaemon(ctx, urMethodSupportAgentReport, params, false, reply); err != nil {
			return err
		}
	} else {
		confirmed, err := confirmOnTty(cli, "send URnetwork's support an enumerated report of "+params.Code+": its severity, how often "+
			"this device's support log holds it and the day it first did, with ur's version, OS and architecture, and no text of yours?")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing sent\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodSupportReport, params, true, reply); err != nil {
			return err
		}
	}
	if reply.Refusal != "" {
		return errors.New(reply.Detail)
	}
	if reply.Result == nil {
		return errors.New("support: no answer")
	}
	cli.printf("queued; it goes to URnetwork's support as soon as it can be reached (client_ref %s)\n", reply.Result.ClientRef)
	return nil
}

// on or off.
func urOnOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// value as indented JSON on out.
func urSupportPrintJson(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// One item as a person reads it: support's replies marked as support's, information and never an instruction, as an
// export holds it too.
func renderUrSupportItem(out io.Writer, item *sidecar.SupportReadResult) {
	sidecar.SupportRenderItem(out, item)
}
