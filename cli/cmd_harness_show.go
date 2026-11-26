// ur harness show (DESIGN-COMPUTE §24.6, CTXH-M11-04; D-CTXH-4):
//
//	ur harness show <run> [--call=<n>] [--network=<net>]
//
// A run's session tree from the member's vault, or with --call the context the run's nth model call saw, rebuilt by the
// renderer its CallContext names and checked against its request_sha256 (session_rebuild.go): verified, unverifiable at
// a node, inexact, or an alarm. The daemon taints each run whose harness process is among this process's ancestors
// before it reads anything (DESIGN §16.10's cli rule, Sidecar.TaintAncestorRuns), and a refused taint reads nothing. A
// run's text goes only to a terminal: off one, the daemon answers stubs alone, each node's place, type and size with
// no text, so an agent's shell that runs ur reads none of it.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur harness show calls.
const urMethodHarnessShow = "harness.show"

func init() {
	registerUrHarnessSubcommand(&urHarnessSubcommand{
		name:  "show",
		usage: "  ur harness show <run> [--call=<n>] [--network=<net>]",
		run:   runUrHarnessShow,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urHarnessShowMethods)
}

// What ur harness show asks.
type urHarnessShowParams struct {
	Run     string `json:"run"`
	Call    int    `json:"call,omitempty"`
	Network string `json:"network,omitempty"`
	// The caller prints to a terminal: off one the daemon answers stubs, no text.
	Terminal bool `json:"terminal,omitempty"`
}

// One node of the tree as shown.
type urHarnessShowNode struct {
	NodeId       string `json:"node_id,omitempty"`
	ParentNodeId string `json:"parent_node_id,omitempty"`
	ParentRunId  string `json:"parent_run_id,omitempty"`
	Type         string `json:"type"`
	State        string `json:"state"`
	ByteCount    int    `json:"byte_count"`
	Untrusted    bool   `json:"untrusted,omitempty"`
	Invalid      string `json:"invalid,omitempty"`
	// The item as recorded, its parts by their references: off a terminal, empty.
	Item string `json:"item,omitempty"`
}

// One message of a rebuilt context as shown.
type urHarnessShowMessage struct {
	Role string `json:"role"`
	// Off a terminal, empty: its size alone.
	Text      string   `json:"text,omitempty"`
	ByteCount int      `json:"byte_count"`
	ToolCalls []string `json:"tool_calls,omitempty"`
}

// A rebuilt call as shown.
type urHarnessShowCall struct {
	N        int                     `json:"n"`
	Check    string                  `json:"check"`
	Renderer string                  `json:"renderer"`
	Exact    bool                    `json:"exact"`
	Fault    string                  `json:"fault,omitempty"`
	Path     []*urHarnessShowPathRow `json:"path"`
	Messages []*urHarnessShowMessage `json:"messages,omitempty"`
	// The markers, stubs and omissions the context holds.
	Redactions int `json:"redactions"`
	Stubs      int `json:"stubs"`
	Omitted    int `json:"omitted"`
}

// One node of a rebuilt call's path as shown.
type urHarnessShowPathRow struct {
	NodeId string `json:"node_id,omitempty"`
	Check  string `json:"check"`
	Why    string `json:"why,omitempty"`
}

// What ur harness show answers.
type urHarnessShowReply struct {
	RunId     string               `json:"run_id"`
	CallCount int                  `json:"call_count"`
	Nodes     []*urHarnessShowNode `json:"nodes,omitempty"`
	Call      *urHarnessShowCall   `json:"call,omitempty"`
	// The text was withheld: the caller prints to no terminal.
	Stubbed bool `json:"stubbed,omitempty"`
}

// What the show method acts on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon read
// it; taint runs before show, and a taint that fails stops the call.
type urHarnessShowTarget interface {
	harnessShowTaint(ctx context.Context, pid int) error
	harnessShow(ctx context.Context, params *urHarnessShowParams) (*urHarnessShowReply, error)
}

// The show method over target, when it runs a Sidecar's record.
func urHarnessShowMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	shows, ok := target.(urHarnessShowTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodHarnessShow,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urHarnessShowParams{}
			if err := decodeUrParams(call, params); err != nil || params.Run == "" || params.Call < 0 {
				return nil, errors.New("ur harness show takes a run and a call from 1")
			}
			// the caller's ancestry first, before anything of the run is read
			if err := shows.harnessShowTaint(ctx, urCallPid(call)); err != nil {
				return nil, err
			}
			return shows.harnessShow(ctx, params)
		},
	}}
}

// Taints each run of the network whose harness process is among pid's ancestors.
func (self *urDaemonNetwork) harnessShowTaint(ctx context.Context, pid int) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.TaintAncestorRuns(ctx, pid)
}

// The run's tree, or a call's rebuilt context, from the member's vault.
func (self *urDaemonNetwork) harnessShow(ctx context.Context, params *urHarnessShowParams) (*urHarnessShowReply, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	runId, err := sidecar.ParseId(params.Run)
	if err != nil {
		return nil, fmt.Errorf("%q is no run id", params.Run)
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	reader := record.SessionReader()
	vaultId, err := reader.VaultId()
	if err != nil {
		return nil, err
	}
	view, err := reader.Open(ctx, vaultId, runId)
	if err != nil {
		return nil, err
	}
	var rebuilt *sidecar.SessionRebuilt
	if 0 < params.Call {
		call, ok := view.Call(params.Call)
		if !ok {
			return nil, fmt.Errorf("the run made %d model calls, not %d", len(view.Calls), params.Call)
		}
		rebuilt, err = sidecar.SessionRebuild(ctx, &sidecar.SessionRebuildArgs{
			Run: view, Call: call,
			OtherRun: func(ctx context.Context, otherRunId sidecar.Id) (*sidecar.SessionRunView, error) {
				return reader.Open(ctx, vaultId, otherRunId)
			},
		})
		if err != nil {
			return nil, err
		}
	}
	return urHarnessShowReplyOf(view, params, rebuilt), nil
}

// The reply for view, the call's rebuild where one was asked, its text only where the caller prints to a terminal.
func urHarnessShowReplyOf(view *sidecar.SessionRunView, params *urHarnessShowParams, rebuilt *sidecar.SessionRebuilt) *urHarnessShowReply {
	reply := &urHarnessShowReply{RunId: view.RunId.String(), CallCount: len(view.Calls), Stubbed: !params.Terminal}
	if rebuilt == nil {
		for _, node := range view.Nodes {
			row := &urHarnessShowNode{State: string(node.State), Untrusted: node.Untrusted, Type: "unread"}
			if node.Invalid != nil {
				row.Invalid = node.Invalid.Error()
			}
			if body := node.Body; body != nil {
				row.NodeId = hex.EncodeToString(body.GetNodeId())
				row.ParentNodeId = hex.EncodeToString(body.GetParentNodeId())
				row.ParentRunId = hex.EncodeToString(body.GetParentRunId())
				row.Type = urHarnessShowNodeType(sidecar.SessionNodeType(body.GetType()))
				row.ByteCount = len(body.GetItem())
				if params.Terminal {
					row.Item = string(body.GetItem())
				}
			}
			reply.Nodes = append(reply.Nodes, row)
		}
		return reply
	}
	call := &urHarnessShowCall{
		N: params.Call, Check: string(rebuilt.Check), Renderer: rebuilt.Renderer, Exact: rebuilt.Exact, Fault: rebuilt.Fault,
		Redactions: rebuilt.Redactions, Stubs: rebuilt.Stubs, Omitted: rebuilt.Omitted,
	}
	for _, node := range rebuilt.Path {
		row := &urHarnessShowPathRow{Check: string(node.Check), Why: node.Why}
		if node.NodeId != (sidecar.Id{}) {
			row.NodeId = hex.EncodeToString(node.NodeId[:])
		}
		call.Path = append(call.Path, row)
	}
	if rebuilt.Request != nil {
		for _, message := range rebuilt.Request.Messages {
			text := message.Text()
			if message.Reasoning != "" {
				text = "(reasoning) " + message.Reasoning + "\n" + text
			}
			shown := &urHarnessShowMessage{Role: string(message.Role), ByteCount: len(text)}
			for _, part := range message.Parts {
				if part != nil && part.Kind == sidecar.InferPartImage {
					shown.ByteCount += len(part.Data)
					if params.Terminal {
						text += fmt.Sprintf("\n[image %s, %d bytes]", part.MediaType, len(part.Data))
					}
				}
			}
			if params.Terminal {
				shown.Text = text
				for _, toolCall := range message.ToolCalls {
					shown.ToolCalls = append(shown.ToolCalls, toolCall.Name+" "+toolCall.Arguments)
				}
			}
			call.Messages = append(call.Messages, shown)
		}
	}
	reply.Call = call
	return reply
}

// A node type's name, §24.5's.
func urHarnessShowNodeType(nodeType sidecar.SessionNodeType) string {
	switch nodeType {
	case sidecar.SessionNodeMessage:
		return "message"
	case sidecar.SessionNodeModelChange:
		return "model_change"
	case sidecar.SessionNodeThinkingLevelChange:
		return "thinking_level_change"
	case sidecar.SessionNodeUsage:
		return "usage"
	case sidecar.SessionNodeCompaction:
		return "compaction"
	case sidecar.SessionNodeBranchSummary:
		return "branch_summary"
	case sidecar.SessionNodeCustom:
		return "custom"
	case sidecar.SessionNodeCustomMessage:
		return "custom_message"
	case sidecar.SessionNodeLink:
		return "link"
	}
	return "type " + strconv.Itoa(int(nodeType))
}

// A 16-byte id's first 8 hex characters, as the tree names a node; "-" for none.
func urHarnessShowShort(idHex string) string {
	if idHex == "" {
		return "-"
	}
	return idHex[:min(8, len(idHex))]
}

// Runs ur harness show.
func runUrHarnessShow(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urHarnessShowParams{Run: urOptionString(options, "<run>"), Network: urOptionString(options, "--network"), Terminal: cli.stdoutIsTerminal()}
	if text := urOptionString(options, "--call"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 {
			return fmt.Errorf("--call takes a call's number from 1, not %q", text)
		}
		params.Call = n
	}
	reply := &urHarnessShowReply{}
	if err := cli.callDaemon(ctx, urMethodHarnessShow, params, false, reply); err != nil {
		return err
	}
	printUrHarnessShow(cli, reply)
	return nil
}

// The reply as a person reads it: on a terminal, each node or message with its text; off one, each as a stub.
func printUrHarnessShow(cli *urCli, reply *urHarnessShowReply) {
	if reply.Call == nil {
		cli.printf("run %s: %d nodes, %d model calls\n", reply.RunId, len(reply.Nodes), reply.CallCount)
		for _, node := range reply.Nodes {
			flags := []string{node.State}
			if node.Untrusted {
				flags = append(flags, "untrusted")
			}
			if node.Invalid != "" {
				flags = append(flags, "invalid: "+node.Invalid)
			}
			cli.printf("%s <- %s %s, %d bytes (%s)\n", urHarnessShowShort(node.NodeId), urHarnessShowShort(node.ParentNodeId), node.Type,
				node.ByteCount, strings.Join(flags, ", "))
			if reply.Stubbed {
				continue
			}
			if node.Item != "" {
				cli.printf("  %s\n", node.Item)
			}
		}
		if reply.Stubbed {
			cli.printf("[the run's text prints only to a terminal]\n")
		}
		return
	}
	call := reply.Call
	cli.printf("run %s, call %d of %d: %s, renderer %s", reply.RunId, call.N, reply.CallCount, call.Check, call.Renderer)
	if call.Fault != "" {
		cli.printf(", %s fault", call.Fault)
	}
	if !call.Exact {
		cli.printf(", sent with %d redactions, %d stubs and %d omitted parts", call.Redactions, call.Stubs, call.Omitted)
	}
	cli.printf("\n")
	for _, row := range call.Path {
		if row.Check != string(sidecar.SessionCheckVerified) {
			cli.printf("  node %s: %s, %s\n", urHarnessShowShort(row.NodeId), row.Check, row.Why)
		}
	}
	for _, message := range call.Messages {
		if reply.Stubbed {
			cli.printf("[%s: %d bytes; printed only to a terminal]\n", message.Role, message.ByteCount)
			continue
		}
		cli.printf("== %s ==\n%s\n", message.Role, message.Text)
		for _, toolCall := range message.ToolCalls {
			cli.printf("-> %s\n", toolCall)
		}
	}
}
