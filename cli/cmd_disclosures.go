// ur disclosures (DESIGN-COMPUTE §2.8, §15.1; R-CCTX-25, D-CTRUST-3; CTRUST-M11-01): every disclosure of the newest
// verified compute policy, over the daemon's disclosure methods (the root's disclosure_daemon.go, registered here with
// every other control method), each on the call's network:
//
//	ur disclosures [--json] [--in=<net>]
//	    each id's version, summary and whether it asks before use, in the terminal's locale (LC_ALL, LC_MESSAGES, then
//	    LANG), else English; with no verified policy, policy_unavailable and nothing listed
//
// The network option is --in, since §15.1 gives `ur disclosures ack <id> --network` to an Owner's or Admin's
// acknowledgment for the network (CTRUST-M12-02). Every string printed comes from the signed policy through the
// daemon's registry, made printable there and here again.
//
// This file also gives ur harness the registry's texts for its disclosure prompt (urHarnessDisclosureEntry), read from
// the daemon on the view's network, so the prompt shows the whole text before the person answers.

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

// ur disclosures's forms.
const urDisclosuresUsage = "  ur disclosures [--json] [--in=<net>]"

// The environment variables a terminal's locale is read from, in order (POSIX's precedence for messages).
var urDisclosureLocaleVariables = []string{"LC_ALL", "LC_MESSAGES", "LANG"}

// What ur disclosures answers where the device holds no verified policy.
var errUrDisclosuresPolicyUnavailable = errors.New(sidecar.ComputeDisclosureCodePolicyUnavailable +
	": this device holds no verified compute policy yet, so it has no disclosure to show; the daemon fetches one once remote compute is asked for")

// Registers ur disclosures, the daemon's disclosure methods, and ur harness's disclosure texts.
func init() {
	registerUrCommand(&urCommand{
		name:    "disclosures",
		usage:   urDisclosuresUsage,
		summary: "what each compute service and provider can and cannot see, from the signed policy",
		run:     runUrDisclosures,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDisclosureMethods)
	urHarnessDisclosureEntry = urDisclosureHarnessEntry
}

// The daemon's disclosure methods, on a target that hosts Sidecars.
func urDisclosureMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonComputeDisclosureMethods(nil)
}

// The terminal's locale, as its environment names it; empty for none.
func urDisclosureLocale(cli *urCli) string {
	for _, name := range urDisclosureLocaleVariables {
		if value := cli.getenv(name); value != "" {
			return value
		}
	}
	return ""
}

// The daemon's list on network, in the terminal's locale; errUrDisclosuresPolicyUnavailable with no verified policy.
func urDisclosureList(ctx context.Context, cli *urCli, network string) (*sidecar.ComputeDisclosureList, error) {
	list := &sidecar.ComputeDisclosureList{}
	params := &sidecar.DaemonComputeDisclosureListParams{Network: network, Locale: urDisclosureLocale(cli)}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodComputeDisclosureList, params, false, list); err != nil {
		return nil, err
	}
	if list.Unavailable == sidecar.ComputeDisclosureCodePolicyUnavailable {
		return nil, errUrDisclosuresPolicyUnavailable
	}
	if list.Unavailable != "" {
		return nil, fmt.Errorf("the daemon lists no disclosures: %s", sidecar.HarnessSanitizeLine(list.Unavailable))
	}
	return list, nil
}

// The view of id in list, nil for none.
func urDisclosureView(list *sidecar.ComputeDisclosureList, id string) *sidecar.ComputeDisclosureView {
	for _, view := range list.Disclosures {
		if view != nil && view.Id == id {
			return view
		}
	}
	return nil
}

// ur disclosures: the list.
func runUrDisclosures(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--in")
	jsonOut := urOptionBool(options, "--json")
	list, err := urDisclosureList(ctx, cli, network)
	if err != nil {
		return err
	}
	if jsonOut {
		encoded, err := json.Marshal(list)
		if err != nil {
			return err
		}
		cli.stdout.Write(sidecar.HarnessJsonTerminalSafe(append(encoded, '\n')))
		return nil
	}
	for _, line := range urDisclosureListLines(list) {
		cli.printf("%s\n", line)
	}
	return nil
}

// The list as the terminal shows it: a line an id, its version and what it asks before, its summary indented under it.
func urDisclosureListLines(list *sidecar.ComputeDisclosureList) []string {
	lines := []string{}
	for _, view := range list.Disclosures {
		if view == nil {
			continue
		}
		parts := []string{sidecar.HarnessSanitizeLine(view.Id), fmt.Sprintf("version %d", view.Version)}
		if view.LabelText != "" {
			parts = append(parts, sidecar.HarnessSanitizeLine(view.LabelText))
		}
		parts = append(parts, sidecar.HarnessSanitizeLine(view.AsksText))
		lines = append(lines, strings.Join(parts, "  "), "    "+sidecar.HarnessSanitizeLine(view.Summary))
	}
	if len(list.Disclosures) == 0 {
		lines = append(lines, "the newest verified compute policy carries no disclosure")
	}
	return lines
}

// ur harness's disclosure texts and acknowledgment on network: the daemon's registry, in the terminal's locale. The
// acknowledgment is CTRUST-M12-01's; until then none, so a prompt's text shows and the person acknowledges in the app.
func urDisclosureHarnessEntry(cli *urCli, network string) (sidecar.HarnessDisclosureTexts, sidecar.HarnessDisclosureAcker) {
	return &urDisclosureHarnessTexts{cli: cli, network: network}, nil
}

// HarnessDisclosureTexts over the daemon's list.
type urDisclosureHarnessTexts struct {
	cli     *urCli
	network string
}

// See sidecar.HarnessDisclosureTexts.
func (self *urDisclosureHarnessTexts) Line(ctx context.Context, id string) (string, error) {
	list, err := urDisclosureList(ctx, self.cli, self.network)
	if err != nil {
		return "", err
	}
	view := urDisclosureView(list, id)
	if view == nil {
		return "", sidecar.ErrComputeDisclosureNotCarried
	}
	return view.Summary, nil
}

// See sidecar.HarnessDisclosureTexts: the whole text, only at the current version.
func (self *urDisclosureHarnessTexts) Text(ctx context.Context, id string, version uint32) (string, error) {
	list, err := urDisclosureList(ctx, self.cli, self.network)
	if err != nil {
		return "", err
	}
	view := urDisclosureView(list, id)
	if view == nil {
		return "", sidecar.ErrComputeDisclosureNotCarried
	}
	if view.Version != version {
		return "", sidecar.ErrDisclosureChanged
	}
	return view.TerminalText(), nil
}
