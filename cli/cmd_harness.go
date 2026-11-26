// ur harness (DESIGN-COMPUTE §7.11, §15.1, R-HARN-1, R-HARN-2, D-HARN-10): a view of the daemon's Harness in the
// terminal, through the daemon's harness methods (the root's harness_daemon.go, appended to the daemon's with
// urDaemonMethodExtensions), so a run started here stays open after its terminal closes, and /close closes it:
//
//	ur harness [--agent=<name>] [--model=<name>] [--json] [--network=<net>]
//	    an agent of the daemon's Harness: the open one registered as <name>, else a new one on <model>, or on this
//	    device's recommended local model where none is named; its events rendered as terminal text (§7.11's renderer,
//	    the root's harness_render_terminal.go), or with --json printed raw, one a line
//	ur harness --enclave=<name> [--json] [--network=<net>]
//	    an attached remote session, which urHarnessAttachEntry runs (HARN-M14-03): refused while it is nil
//	ur harness <subcommand> ...
//	    each subcommand (rpc, ls, serve, show, runs, continue, export) from its own cmd_harness_<name>.go, which
//	    registers it with registerUrHarnessSubcommand at init, as registerUrCommand does for commands
//
// The person's input is read from /dev/tty, never stdin, and each call that carries it is confirmed, so the daemon takes
// it as the person's where no harness process is among this process's ancestors and as an unknown run's otherwise,
// which taints the run it reaches (§7.10's origin); with no terminal, lines come from stdin, unconfirmed: an unknown
// run's. A line is a prompt while the agent is idle and a steer while it runs; /follow <text> queues a follow-up,
// /abort ends the turn, /model <name> changes the model at the next call, /close ends the run, and /quit or the end of
// input leaves the view, the run open. While a dialog waits, the next line answers it (HarnessTerminalRenderer.Answer):
// a disclosure's "I understand" goes through CTRUST's acknowledgment (urHarnessDisclosureEntry), never as a reply to
// the model. With --json, stdout holds the events alone and the view's own lines go to stderr.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur harness's own forms.
const urHarnessUsage = "  ur harness [--agent=<name>] [--model=<name>] [--json] [--network=<net>]\n" +
	"  ur harness --enclave=<name> [--json] [--network=<net>]"

var (
	// --enclave until HARN-M14-03's attach lands.
	errUrHarnessAttachNotBuilt = errors.New("attaching to an enclave's Harness is not built yet")
	// The run the view watched closed: the view ends without an error.
	errUrHarnessRunClosed = errors.New("the run is closed")
)

// A subcommand of ur harness, registered from its own cmd_harness_<name>.go.
type urHarnessSubcommand struct {
	// The word after harness that selects it.
	name string
	// Its docopt usage lines, each starting "  ur harness <name>".
	usage string
	// Runs it with what docopt parsed.
	run func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// Every subcommand, by name. Written only by registerUrHarnessSubcommand, at init.
var urHarnessSubcommands = map[string]*urHarnessSubcommand{}

// Adds a subcommand, its usage lines joining ur harness's whichever file's init runs first. A second subcommand of one
// name, or usage lines that do not name it, is a programming error, found at start.
func registerUrHarnessSubcommand(subcommand *urHarnessSubcommand) {
	if subcommand == nil || subcommand.name == "" || subcommand.run == nil || urHarnessSubcommands[subcommand.name] != nil {
		panic(fmt.Sprintf("ur harness subcommand %q registered twice or without a run", subcommand.name))
	}
	for _, line := range strings.Split(subcommand.usage, "\n") {
		if !strings.HasPrefix(line, "  ur harness "+subcommand.name) {
			panic(fmt.Sprintf("ur harness subcommand %q has a usage line not its own: %q", subcommand.name, line))
		}
	}
	urHarnessSubcommands[subcommand.name] = subcommand
	if command := urCommands["harness"]; command != nil {
		command.usage = urHarnessUsageLines()
	}
}

// ur harness's usage: its own forms, then each subcommand's, by name.
func urHarnessUsageLines() string {
	lines := []string{urHarnessUsage}
	names := []string{}
	for name := range urHarnessSubcommands {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		lines = append(lines, urHarnessSubcommands[name].usage)
	}
	return strings.Join(lines, "\n")
}

// What `ur harness --enclave <name>` runs, an attached remote session: HARN-M14-03 sets it. Nil, --enclave refuses.
var urHarnessAttachEntry func(ctx context.Context, cli *urCli, options docopt.Opts) error

// The signed policy's disclosure texts and the person's acknowledgment that ur harness's disclosure prompts use, for
// network: CTRUST's registry and its /dev/tty acknowledgment (§2.8), which its own cli file sets. Nil, a disclosure
// prompt says its text is not available here, and a line can only decline it.
var urHarnessDisclosureEntry func(cli *urCli, network string) (sidecar.HarnessDisclosureTexts, sidecar.HarnessDisclosureAcker)

// Registers ur harness, and the daemon's harness methods.
func init() {
	registerUrCommand(&urCommand{
		name:    "harness",
		usage:   urHarnessUsageLines(),
		summary: "the Harness in the terminal: prompt an agent of the daemon's and watch it work",
		run:     runUrHarness,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urHarnessMethods)
}

// The daemon's harness methods, each over the network's Sidecar.
func urHarnessMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	return sidecar.HarnessDaemonMethods()
}

// ur harness: a subcommand where docopt matched one, an attached session with --enclave, else the view.
func runUrHarness(ctx context.Context, cli *urCli, options docopt.Opts) error {
	for name, subcommand := range urHarnessSubcommands {
		if on, _ := options.Bool(name); on {
			return subcommand.run(ctx, cli, options)
		}
	}
	if enclave, _ := options.String("--enclave"); enclave != "" {
		if urHarnessAttachEntry == nil {
			return errUrHarnessAttachNotBuilt
		}
		return urHarnessAttachEntry(ctx, cli, options)
	}
	network, _ := options.String("--network")
	name, _ := options.String("--agent")
	model, _ := options.String("--model")
	jsonOut, _ := options.Bool("--json")

	// the person's input comes from /dev/tty; with none, lines come from stdin, an unknown run's
	view := &urHarnessView{cli: cli, network: network, json: jsonOut, settled: make(chan struct{}, 1)}
	tty, err := cli.openTty()
	if err == nil {
		defer tty.Close()
		view.person = true
		view.input = tty.readLine
	} else {
		reader := bufio.NewReader(cli.stdin)
		view.input = func() (string, error) {
			line, err := reader.ReadString('\n')
			if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
				return "", err
			}
			return strings.TrimRight(line, "\r\n"), nil
		}
	}
	agent := &sidecar.HarnessAgentReply{}
	params := &sidecar.HarnessAgentParams{Network: network, Name: name, Model: model}
	if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodAgent, params, view.person, agent); err != nil {
		return err
	}
	view.agent = agent
	view.running = agent.Running
	if !jsonOut {
		var texts sidecar.HarnessDisclosureTexts
		if urHarnessDisclosureEntry != nil {
			texts, view.acker = urHarnessDisclosureEntry(cli, network)
		}
		view.renderer = sidecar.NewHarnessTerminalRenderer(&sidecar.HarnessTerminalRendererArgs{
			Out:         cli.stdout,
			Styled:      cli.stdoutIsTerminal(),
			Disclosures: texts,
		})
	}
	view.notice(fmt.Sprintf("%s on %s, run %s. Type to prompt; /help lists the commands.", agent.Name, agent.Model, agent.Run))
	if !view.person {
		view.notice("no terminal: lines are read from stdin, as an unknown run's, which taints the run")
	}
	return view.run(ctx)
}

// One view of an agent: its input, its renderer or raw output, and what it tracks of the run.
type urHarnessView struct {
	cli     *urCli
	network string
	agent   *sidecar.HarnessAgentReply
	json    bool
	// input read from /dev/tty, so its calls carry the person's confirmation
	person bool
	input  func() (string, error)
	// nil with --json
	renderer *sidecar.HarnessTerminalRenderer
	acker    sidecar.HarnessDisclosureAcker
	// takes one token at each agent_settled the view reads
	settled chan struct{}

	stateLock sync.Mutex
	// whether the agent runs a prompt now, from its agent_start and agent_settled
	running bool
	// whether a prompt this view sent has not settled yet
	awaiting bool
}

// Tells the person something: on the terminal through the renderer, or with --json on stderr, so stdout holds events.
func (self *urHarnessView) notice(text string) {
	if self.renderer != nil {
		self.renderer.Notice(text)
		return
	}
	fmt.Fprintln(self.cli.stderr, sidecar.HarnessSanitize(text))
}

// Calls a harness method, the person's confirmation on it where the view's input is the person's.
func (self *urHarnessView) call(ctx context.Context, method string, params any, result any) error {
	return self.cli.callDaemon(ctx, method, params, self.person, result)
}

// Runs the view until the run closes, the person leaves, or the daemon goes: events on one goroutine, input on another,
// each line handled here in order.
func (self *urHarnessView) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	eventsDone := make(chan error, 1)
	go func() {
		eventsDone <- self.events(ctx)
	}()
	lines := make(chan string)
	inputDone := make(chan error, 1)
	go func() {
		for {
			line, err := self.input()
			if err != nil {
				inputDone <- err
				return
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	ended := func(err error) error {
		if errors.Is(err, errUrHarnessRunClosed) {
			self.notice("the run is closed")
			return nil
		}
		return err
	}
	for {
		select {
		case err := <-eventsDone:
			return ended(err)
		case <-inputDone:
			// the end of input leaves the view, after the prompt it sent settles; the run stays open in the daemon
			for self.awaitingSettle() {
				select {
				case <-self.settled:
				case err := <-eventsDone:
					return ended(err)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			self.notice(fmt.Sprintf("left the view; the run stays open (ur harness --agent=%s returns to it, /close ends it)", self.agent.Name))
			return nil
		case line := <-lines:
			leave, err := self.line(ctx, line)
			if err != nil {
				self.notice(err.Error())
			}
			if leave {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Whether a prompt this view sent has not settled yet.
func (self *urHarnessView) awaitingSettle() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.awaiting
}

// Long-polls the agent's events on a session of its own, which the daemon takes as the person's view while it lasts,
// rendering or printing each, until the run closes or ctx ends.
func (self *urHarnessView) events(ctx context.Context) error {
	client, err := self.cli.connectDaemon(ctx, self.cli.hello(sidecar.DaemonModeControl), nil)
	if err != nil {
		return err
	}
	defer client.Close()
	waitMs := self.cli.settings.HarnessEventsWait.Milliseconds()
	after := uint64(0)
	for {
		reply := &sidecar.HarnessEventsReply{}
		params := &sidecar.HarnessEventsParams{Network: self.network, Agent: self.agent.Agent, After: after, WaitMs: waitMs}
		err := func() error {
			callCtx, cancel := context.WithTimeout(ctx, self.cli.settings.CallTimeout)
			defer cancel()
			return client.Call(callCtx, sidecar.HarnessDaemonMethodEvents, params, self.person, reply)
		}()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if reply.Gap {
			self.notice("(some of the run's events are no longer kept, so they are not shown)")
		}
		for _, raw := range reply.Events {
			self.show(ctx, raw)
		}
		if self.renderer != nil {
			// a dialog raised before this view read its event still asks
			for _, request := range reply.Pending {
				self.renderer.Render(ctx, sidecar.NewHarnessUiRequestEvent(request))
			}
		}
		after = reply.Next
		if reply.Closed {
			return errUrHarnessRunClosed
		}
	}
}

// One event: printed raw with --json, rendered otherwise; agent_start and agent_settled tracked either way.
func (self *urHarnessView) show(ctx context.Context, raw json.RawMessage) {
	if self.json {
		self.cli.stdout.Write(append(sidecar.HarnessJsonTerminalSafe(raw), '\n'))
	}
	event := &sidecar.HarnessEvent{}
	if err := json.Unmarshal(raw, event); err != nil {
		self.notice("(an event that does not read)")
		return
	}
	switch event.Type {
	case sidecar.HarnessEventAgentStart:
		self.stateLock.Lock()
		self.running = true
		self.stateLock.Unlock()
	case sidecar.HarnessEventAgentSettled:
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.running = false
			self.awaiting = false
		}()
		select {
		case self.settled <- struct{}{}:
		default:
		}
	}
	if self.renderer != nil {
		self.renderer.Render(ctx, event)
	}
}

// Handles one line of input: a waiting dialog's answer, a view command, or a prompt or steer. Answers whether the view
// leaves.
func (self *urHarnessView) line(ctx context.Context, line string) (bool, error) {
	agentId := self.agent.Agent
	if self.renderer != nil && self.renderer.Dialog() != nil {
		answer := self.renderer.Answer(ctx, line, self.acker)
		if answer != nil && answer.Response != nil {
			params := &sidecar.HarnessRespondUiParams{Network: self.network, Agent: agentId, Response: answer.Response}
			return false, self.call(ctx, sidecar.HarnessDaemonMethodRespondUi, params, nil)
		}
		return false, nil
	}
	trimmed := strings.TrimSpace(line)
	prompt := func(mode string, text string) error {
		params := &sidecar.HarnessPromptParams{Network: self.network, Agent: agentId, Text: text, Mode: mode}
		return self.call(ctx, sidecar.HarnessDaemonMethodPrompt, params, &sidecar.HarnessPromptReply{})
	}
	switch {
	case trimmed == "":
		return false, nil
	case trimmed == "/quit":
		return true, nil
	case trimmed == "/help":
		self.notice("a line prompts the agent, or steers it while it works; /follow <text> queues a follow-up; " +
			"/abort ends the turn; /model <name> changes the model; /close ends the run; /quit leaves it open")
		return false, nil
	case trimmed == "/close":
		params := &sidecar.HarnessCloseParams{Network: self.network, Agent: agentId}
		if err := self.call(ctx, sidecar.HarnessDaemonMethodClose, params, nil); err != nil {
			return false, err
		}
		return true, nil
	case trimmed == "/abort":
		return false, prompt(sidecar.HarnessPromptModeAbort, "")
	case strings.HasPrefix(trimmed, "/model "):
		params := &sidecar.HarnessAgentParams{Network: self.network, Agent: agentId, Model: strings.TrimSpace(trimmed[len("/model "):])}
		return false, self.call(ctx, sidecar.HarnessDaemonMethodAgent, params, &sidecar.HarnessAgentReply{})
	case strings.HasPrefix(trimmed, "/follow "):
		return false, prompt(sidecar.HarnessPromptModeFollowUp, strings.TrimSpace(trimmed[len("/follow "):]))
	case strings.HasPrefix(trimmed, "/"):
		return false, fmt.Errorf("no command %s: /help lists them", strings.Fields(trimmed)[0])
	}
	running := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.running
	}()
	if running {
		return false, prompt(sidecar.HarnessPromptModeSteer, line)
	}
	// marked before the call, so a run that settles before its answer still counts
	setAwaiting := func(awaiting bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.awaiting = awaiting
	}
	setAwaiting(true)
	err := prompt(sidecar.HarnessPromptModePrompt, line)
	if err != nil {
		setAwaiting(false)
	}
	if err != nil && strings.Contains(err.Error(), sidecar.ErrHarnessAgentRunning.Error()) {
		// the run started from another view since this one last read: the line steers it
		return false, prompt(sidecar.HarnessPromptModeSteer, line)
	}
	return false, err
}
