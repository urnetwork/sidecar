// ur infer (DESIGN-COMPUTE §6.4, §15.1; R-INFER-1, R-INFER-6, D-INFER-7; INFER-M11-08): one prompt to a model through
// the daemon's router, its answer streamed as terminal text, over the daemon's infer.run (the root's infer_daemon.go):
//
//	ur infer --model=<name> [--reasoning=<effort>] [--network=<net>] <prompt>
//
// The call runs in a run the daemon opens for the command and is recorded there as a model_call through InferModelCall,
// so R-INFER-6 holds outside the Harness too; a daemon that cannot keep the record runs nothing. Before a first call to
// a model labeled none whose disclosure is not acknowledged the router answers disclosure_required: with a terminal, the
// disclosure's whole text prints on /dev/tty and the person's answer is taken as ur disclosures ack takes it, through
// CTRUST's acknowledgment (urHarnessDisclosureEntry, which ur harness's dialog uses too), and the prompt asked again;
// without a terminal, or in a build CTRUST's texts are not in yet, the command answers disclosure_required with its fix.
// Every delta passes HarnessSanitize before it reaches the terminal, and a refusal prints its code and the router's own
// words, never a provider's.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur infer's form.
const urInferUsage = "  ur infer --model=<name> [--reasoning=<effort>] [--network=<net>] <prompt>"

// What the person types to acknowledge a disclosure, as ur harness's dialog takes it.
const urInferAcknowledgeAnswer = "i understand"

func init() {
	registerUrCommand(&urCommand{
		name:    "infer",
		usage:   urInferUsage,
		summary: "one prompt to a model, its answer as terminal text, recorded as a model_call",
		run:     runUrInfer,
	})
}

// The router's refusal or the call's failure, as ur prints it: the code and the router's words.
type urInferError struct {
	refusal *sidecar.InferError
}

func (self *urInferError) Error() string {
	return string(self.refusal.Code) + ": " + sidecar.HarnessSanitizeLine(self.refusal.Message)
}

// ur infer: the prompt once, and again after the person acknowledges the disclosure it waited for.
func runUrInfer(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &sidecar.DaemonInferRunParams{}
	params.Network, _ = options.String("--network")
	params.Model, _ = options.String("--model")
	params.Reasoning, _ = options.String("--reasoning")
	params.Prompt, _ = options.String("<prompt>")
	if params.Model == "" || strings.TrimSpace(params.Prompt) == "" {
		return errors.New("ur infer takes a model and a prompt")
	}
	reply, err := urInferOnce(ctx, cli, params)
	if err != nil {
		return err
	}
	if reply.Error != nil && reply.Error.Code == sidecar.InferErrorDisclosureRequired {
		acknowledged, err := urInferAcknowledge(ctx, cli, params.Network, reply.Error)
		if err != nil {
			return err
		}
		if !acknowledged {
			return &urInferError{refusal: reply.Error}
		}
		if reply, err = urInferOnce(ctx, cli, params); err != nil {
			return err
		}
	}
	if !reply.Recorded && reply.Error == nil {
		fmt.Fprintf(cli.stderr, "ur: the call ran but its model_call was not recorded: %s\n", sidecar.HarnessSanitizeLine(reply.RecordError))
	}
	if reply.Error != nil {
		return &urInferError{refusal: reply.Error}
	}
	return nil
}

// One infer.run, its text streamed to stdout as it comes, a newline after it.
func urInferOnce(ctx context.Context, cli *urCli, params *sidecar.DaemonInferRunParams) (*sidecar.DaemonInferRunReply, error) {
	reply := &sidecar.DaemonInferRunReply{}
	wrote := false
	err := urCallDaemonFollowing(ctx, cli, sidecar.DaemonMethodInferRun, params, false, reply, func(method string, raw json.RawMessage) {
		if method != sidecar.DaemonNotifyInferEvent {
			return
		}
		event := &sidecar.InferEvent{}
		if json.Unmarshal(raw, event) != nil || event.Kind != sidecar.InferEventText {
			return
		}
		cli.printf("%s", sidecar.HarnessSanitize(event.Text))
		wrote = true
	})
	if wrote {
		cli.printf("\n")
	}
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// The person's acknowledgment of the disclosure refusal names, on /dev/tty: its whole text, then their answer, taken
// through CTRUST's acknowledgment. false where they declined, where there is no terminal, or where this build holds no
// disclosure texts; an error where the acknowledgment did not land.
func urInferAcknowledge(ctx context.Context, cli *urCli, network string, refusal *sidecar.InferError) (bool, error) {
	tty, err := cli.openTty()
	if err != nil {
		return false, nil
	}
	defer tty.Close()
	if urHarnessDisclosureEntry == nil {
		fmt.Fprintf(tty, "%s waits for its disclosure %s, whose text this ur does not hold yet, so it cannot be acknowledged here\n",
			sidecar.HarnessSanitizeLine(refusal.Model), sidecar.HarnessSanitizeLine(refusal.DisclosureId))
		return false, nil
	}
	texts, acker := urHarnessDisclosureEntry(cli, network)
	if texts == nil || acker == nil {
		return false, nil
	}
	text, err := texts.Text(ctx, refusal.DisclosureId, refusal.DisclosureVersion)
	if err != nil {
		return false, fmt.Errorf("the disclosure %s's text does not read: %w", sidecar.HarnessSanitizeLine(refusal.DisclosureId), err)
	}
	fmt.Fprintln(tty, sidecar.HarnessSanitize(text))
	fmt.Fprintf(tty, "Type \"I understand\" to acknowledge %s, or anything else to decline: ", sidecar.HarnessSanitizeLine(refusal.DisclosureId))
	answer, err := tty.readLine()
	if err != nil {
		return false, err
	}
	if strings.ToLower(strings.TrimSpace(answer)) != urInferAcknowledgeAnswer {
		return false, nil
	}
	if err := acker.Ack(ctx, refusal.DisclosureId, refusal.DisclosureVersion); err != nil {
		return false, fmt.Errorf("the acknowledgment did not land: %w", err)
	}
	return true, nil
}
