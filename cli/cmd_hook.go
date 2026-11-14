// ur hook <harness> (§16.7, D-MCP-5): a harness runs this at each hook event, its payload on stdin, and it passes the
// payload to the daemon (hello mode hook, method hook.event) and exits 0, within Ingest.HookExitTimeout, or, for a
// PreToolUse naming paths, once the daemon holds them, within Ingest.HookPathTimeout. It fails open: with no daemon it
// starts one for the next event and exits at once, and a daemon that does not answer in time is passed over, since a
// lapse taints the run (hook_coverage.go) where a failed hook would stop the person's work.
//
// It prints nothing for Claude Code and Codex, whose SessionStart and UserPromptSubmit put stdout into the model's
// context, and for Cursor's beforeMCPExecution it prints permission ask for ur's outward tools from the catalog built
// into this binary, which needs no daemon (mcp.CursorHookAnswer). A payload past Ingest.PayloadByteCount goes as its
// size alone, a gap; what goes wrong goes to stderr, without the payload's text.
//
// --required, which the fail-closed form ur install-harness writes for a Team's record_required puts on each command
// (MCP-M6-04; plan-MCP-record-required), makes a hook whose event the daemon could not take exit 2, which Claude
// Code's onFailure block and Cursor's failClosed read as stop, and which blocks a Codex PreToolUse while it runs: no
// daemon answering, a refusal, an answer past the bound or a failed call. A payload that could not be read is not
// the daemon's to take, so it fails open as before.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "hook",
		usage:   "  ur hook <harness> [--required]",
		summary: "pass a harness hook's payload to the daemon: " + strings.Join(mcp.HookHarnesses(), ", "),
		run:     runUrHook,
	})
}

// The exit a --required hook gives when the daemon could not take its event: the code the harnesses read as block.
const urExitHookRequired = 2

// A hook's run. Every outcome but a usage error exits 0, but a --required hook's event the daemon could not take.
func runUrHook(ctx context.Context, cli *urCli, options docopt.Opts) error {
	harness, _ := options.String("<harness>")
	required, _ := options.Bool("--required")
	blocked := func(reason string) error {
		if !required {
			return nil
		}
		return &urExitError{code: urExitHookRequired, err: fmt.Errorf("ur hook --required: %s", reason)}
	}
	ingest := cli.ingest
	start := time.Now()
	deadline := start.Add(ingest.HookExitTimeout)
	adapter, ok := mcp.HookAdapterFor(harness)
	if !ok {
		fmt.Fprintf(cli.stderr, "ur hook: no harness %q: one of %s\n", harness, strings.Join(mcp.HookHarnesses(), ", "))
		return nil
	}
	payload, byteCount, oversize, err := readUrHookPayload(cli.stdin, ingest.PayloadByteCount, time.Until(start.Add(ingest.HookPathTimeout)))
	if err != nil {
		fmt.Fprintf(cli.stderr, "ur hook: the payload could not be read: %s\n", err)
		return nil
	}
	params := &mcp.HookEventParams{ByteCount: byteCount, Oversize: oversize}
	if !oversize {
		params.Payload = payload
		if event, err := adapter.Parse(payload, ingest); err == nil {
			if answer := mcp.CursorHookAnswer(event); answer != nil {
				cli.stdout.Write(append(answer, '\n'))
			}
			if event.Kind == mcp.HookEventPreToolUse && 0 < len(event.Paths) {
				deadline = start.Add(ingest.HookPathTimeout)
			}
		}
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	socketPath, err := cli.socketPath(cli.instance)
	if err != nil {
		fmt.Fprintf(cli.stderr, "ur hook: %s\n", err)
		return blocked("no daemon socket")
	}
	hello := cli.hello(sidecar.DaemonModeHook)
	hello.Harness = harness
	client, err := cli.dialDaemon(callCtx, socketPath, hello)
	if err != nil {
		var refusal *sidecar.DaemonHelloRefusal
		if errors.As(err, &refusal) {
			fmt.Fprintf(cli.stderr, "ur hook: the daemon refused the hook: %s\n", refusal.Code)
			return blocked("the daemon refused the hook")
		}
		// none answers: one starts for the next event, and this one fails open, or, required, stops the harness
		if err := cli.spawnDaemon([]string{"--instance", cli.instance, "--auto-spawned"}); err != nil {
			fmt.Fprintf(cli.stderr, "ur hook: no daemon answers and none could start: %s\n", err)
		}
		return blocked("no daemon answers")
	}
	defer client.Close()
	if err := client.Call(callCtx, mcp.McpHookMethod, params, false, nil); err != nil {
		fmt.Fprintf(cli.stderr, "ur hook: the daemon did not take the event: %s\n", urHookCallError(err))
		return blocked("the daemon did not take the event")
	}
	return nil
}

// A call's failure as stderr says it: a refusal's code alone, since a message may hold what the daemon read.
func urHookCallError(err error) string {
	var rpcError *sidecar.DaemonRpcError
	if errors.As(err, &rpcError) {
		return fmt.Sprintf("daemon rpc %d", rpcError.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "no answer in time"
	}
	return "the session ended"
}

// The payload on stdin: up to maxByteCount bytes, or, past that, its size alone and oversize set. A stdin that does
// not end within timeout is read no further.
func readUrHookPayload(stdin io.Reader, maxByteCount int64, timeout time.Duration) ([]byte, int64, bool, error) {
	type read struct {
		payload   []byte
		byteCount int64
		err       error
	}
	done := make(chan read, 1)
	go func() {
		buffer := &bytes.Buffer{}
		kept, err := io.Copy(buffer, io.LimitReader(stdin, maxByteCount+1))
		byteCount := kept
		if err == nil && maxByteCount < kept {
			// counted, never kept
			rest, restErr := io.Copy(io.Discard, stdin)
			byteCount += rest
			err = restErr
		}
		done <- read{payload: buffer.Bytes(), byteCount: byteCount, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			return nil, 0, false, result.err
		}
		if maxByteCount < result.byteCount {
			return nil, result.byteCount, true, nil
		}
		return result.payload, result.byteCount, false, nil
	case <-time.After(timeout):
		return nil, 0, false, errors.New("stdin did not end in time")
	}
}
