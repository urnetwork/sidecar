// ur disclosures (DESIGN-COMPUTE §2.8, §15.1; R-CCTX-25, D-CTRUST-3; CTRUST-M11-01, CTRUST-M12-01, CTRUST-M12-02): every
// disclosure of the newest verified compute policy, the person's acknowledgment of one, and an Owner's or Admin's for
// the network, over the daemon's disclosure methods (the root's disclosure_daemon.go, registered here with every other
// control method), each on the call's network:
//
//	ur disclosures [--json] [--in=<net>]
//	    each id's version, summary and whether it asks before use, in the terminal's locale (LC_ALL, LC_MESSAGES, then
//	    LANG), else English, with the version the acknowledgments that cover this sidecar hold and whether its lines
//	    are marked changed, and under it the network's acknowledgment where the network's compute block holds one:
//	    its version, who gave it on which device and when, and whether it covers a use now; with no verified policy,
//	    policy_unavailable and nothing listed
//	ur disclosures ack <id> [--in=<net>]
//	    the whole text, printed on /dev/tty, then "I understand" typed there acknowledges its current version: the
//	    Confirm method compute.disclosure.ack, sent confirmed; refused without a terminal, and by the daemon to a
//	    caller with a harness process among its ancestors. Showing the text also ends its changed mark
//	ur disclosures ack <id> --network [--in=<net>]
//	    an Owner's or Admin's acknowledgment for the network's tagged and cloud sidecars (CO-41): the whole text on
//	    /dev/tty, then "I understand" typed there sends the Confirm method compute.disclosure.ack_network with the
//	    version, locale and revision shown, which signs the network's disclosure-ack and saves it into the compute
//	    block; refused without a terminal, and by the daemon under a harness process or on any device but an Owner's
//	    or Admin's approval-capable one that runs the network's config writer
//	ur disclosures remove <id> --network [--in=<net>]
//	    that acknowledgment taken out of the compute block, which only narrows, confirmed on /dev/tty: the Confirm
//	    method compute.disclosure.remove_network
//
// The network option is --in, since --network names an Owner's or Admin's acknowledgment for the network. Every
// string printed comes from the signed policy through the daemon's registry, made printable there and here again.
// `ur status` names, on a tagged or cloud sidecar, each network acknowledgment it relies on, its version, who gave it
// and when (§2.8's network row), through status.disclosures.
//
// urAskDisclosureOnTty is the same acknowledgment for a command about to use what a disclosure covers, `ur infer`, `ur
// search`, `ur enclave create`, `ur listeners`, `ur connect` and `ur install-harness --gateway` among them, each its
// owner's call: nothing where the use is covered, the text and the question on a terminal, disclosure_required without
// one. This file also gives ur harness the registry's texts for its disclosure prompt and, where ur reads the person's
// lines from a terminal, the acknowledgment (urHarnessDisclosureEntry).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur disclosures's forms.
const urDisclosuresUsage = "  ur disclosures [--json] [--in=<net>]\n" +
	"  ur disclosures ack <id> [--network] [--in=<net>]\n" +
	"  ur disclosures remove <id> --network [--in=<net>]"

// The environment variables a terminal's locale is read from, in order (POSIX's precedence for messages).
var urDisclosureLocaleVariables = []string{"LC_ALL", "LC_MESSAGES", "LANG"}

var (
	// What ur disclosures answers where the device holds no verified policy.
	errUrDisclosuresPolicyUnavailable = errors.New(sidecar.ComputeDisclosureCodePolicyUnavailable +
		": this device holds no verified compute policy yet, so it has no disclosure to show; the daemon fetches one once remote compute is asked for")
	// The person answered other than "I understand": nothing was recorded.
	errUrDisclosuresNotNow = errors.New("not acknowledged: nothing was recorded")
	// The person answered other than yes to a removal: nothing was removed.
	errUrDisclosuresNotRemoved = errors.New("not removed: the network's acknowledgment stands")
)

// Registers ur disclosures, the daemon's disclosure methods, and ur harness's disclosure texts.
func init() {
	registerUrCommand(&urCommand{
		name:    "disclosures",
		usage:   urDisclosuresUsage,
		summary: "what each compute service and provider can and cannot see, from the signed policy",
		run:     runUrDisclosures,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDisclosureMethods, urDisclosureStatusMethods)
	urStatusSections = append(urStatusSections, printUrStatusDisclosures)
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

// ur disclosures: ack, ack --network or remove where docopt matched it, else the list.
func runUrDisclosures(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--in")
	id, _ := options.String("<id>")
	switch {
	case urOptionBool(options, "remove"):
		return runUrDisclosuresRemoveNetwork(ctx, cli, network, id)
	case urOptionBool(options, "ack") && urOptionBool(options, "--network"):
		return runUrDisclosuresAckNetwork(ctx, cli, network, id)
	case urOptionBool(options, "ack"):
		return runUrDisclosuresAck(ctx, cli, network, id)
	}
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

// The list as the terminal shows it: a line an id, its version, what it asks before and, where it asks, its
// acknowledgment, then "changed" where its lines are marked; its summary indented under it.
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
		if view.Asks {
			parts = append(parts, urDisclosureAckWords(view))
		}
		if view.Changed {
			parts = append(parts, "changed")
		}
		lines = append(lines, strings.Join(parts, "  "), "    "+sidecar.HarnessSanitizeLine(view.Summary))
		if words := urDisclosureNetworkWords(view); words != "" {
			lines = append(lines, "    for the network: "+words)
		}
	}
	if len(list.Disclosures) == 0 {
		lines = append(lines, "the newest verified compute policy carries no disclosure")
	}
	return lines
}

// What a list line says of the acknowledgment of a disclosure that asks: whose, and at which version.
func urDisclosureAckWords(view *sidecar.ComputeDisclosureView) string {
	whose := ""
	if view.Scope == sidecar.ComputeDisclosureScopeNetwork {
		whose = " for the network"
	}
	switch {
	case view.Scope == "":
		return "acknowledgments unreadable"
	case view.Version <= view.Acknowledged:
		return "acknowledged" + whose
	case view.Acknowledged == 0:
		return "not acknowledged" + whose
	case view.Covered:
		return fmt.Sprintf("acknowledged%s at version %d, in its grace", whose, view.Acknowledged)
	}
	return fmt.Sprintf("acknowledged%s at version %d only", whose, view.Acknowledged)
}

// What a list line or a status line says of the network's acknowledgment of view's id: its version, who gave it on
// which device and when, and whether it covers a use now; empty where the network's block holds none.
func urDisclosureNetworkWords(view *sidecar.ComputeDisclosureView) string {
	network := view.Network
	if network == nil {
		return ""
	}
	if network.Version == 0 {
		return fmt.Sprintf("a statement this device does not read (%s)", sidecar.HarnessSanitizeLine(network.Refusal))
	}
	who := fmt.Sprintf("version %d, by member %s on device %s", network.Version, network.MemberId, network.SidecarId)
	if network.SignedAtMs != 0 {
		who += " at " + time.UnixMilli(network.SignedAtMs).UTC().Format(time.RFC3339)
	}
	switch {
	case !network.Taken:
		return fmt.Sprintf("%s, not taken (%s)", who, sidecar.HarnessSanitizeLine(network.Refusal))
	case network.InGrace:
		return fmt.Sprintf("%s, covering through version %d's grace, until %s", who, view.Version,
			time.UnixMilli(network.GraceEndMs).UTC().Format(time.RFC3339))
	case network.Stands:
		return who + ", covering"
	}
	return fmt.Sprintf("%s, covering no use of version %d", who, view.Version)
}

// ur disclosures ack <id>: the whole text and the person's answer on /dev/tty.
func runUrDisclosuresAck(ctx context.Context, cli *urCli, network string, id string) error {
	list, err := urDisclosureList(ctx, cli, network)
	if err != nil {
		return err
	}
	view := urDisclosureView(list, id)
	if view == nil {
		return fmt.Errorf("the newest verified compute policy carries no disclosure %s", sidecar.HarnessSanitizeLine(id))
	}
	if err := urDisclosureAckOnTty(ctx, cli, network, view); err != nil {
		return err
	}
	cli.printf("acknowledged %s version %d\n", view.Id, view.Version)
	return nil
}

// view's whole text on /dev/tty, its opening recorded, then "I understand" typed there acknowledges its version through
// the Confirm method; anything else records nothing (errUrDisclosuresNotNow). errUrNoTty without a terminal.
func urDisclosureAckOnTty(ctx context.Context, cli *urCli, network string, view *sidecar.ComputeDisclosureView) error {
	if err := urDisclosureShowOnTty(ctx, cli, network, view, "to acknowledge it"); err != nil {
		return err
	}
	return urDisclosureAck(ctx, cli, &sidecar.DaemonComputeDisclosureActParams{Network: network, Id: view.Id, Version: view.Version})
}

// view's whole text on /dev/tty, its opening recorded, then nil once "I understand" is typed there, for what; anything
// else is errUrDisclosuresNotNow, and errUrNoTty without a terminal.
func urDisclosureShowOnTty(ctx context.Context, cli *urCli, network string, view *sidecar.ComputeDisclosureView, what string) error {
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	for _, line := range strings.Split(strings.TrimRight(view.TerminalText(), "\n"), "\n") {
		fmt.Fprintln(tty, sidecar.HarnessSanitizeLine(line))
	}
	params := &sidecar.DaemonComputeDisclosureActParams{Network: network, Id: view.Id, Version: view.Version}
	// the person read the whole text, which ends its changed mark; a mark not ended only shows again
	cli.callDaemon(ctx, sidecar.DaemonMethodComputeDisclosureOpen, params, true, &sidecar.DaemonComputeDisclosureActReply{})
	fmt.Fprintf(tty, "\ntype %q %s, or anything else for Not now: ", sidecar.HarnessDisclosureAcknowledgment, what)
	answer, err := tty.readLine()
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(answer), sidecar.HarnessDisclosureAcknowledgment) {
		return errUrDisclosuresNotNow
	}
	return nil
}

// ur disclosures ack <id> --network: the whole text and an Owner's or Admin's answer on /dev/tty, then the Confirm
// method compute.disclosure.ack_network for the version, locale and revision shown.
func runUrDisclosuresAckNetwork(ctx context.Context, cli *urCli, network string, id string) error {
	list, err := urDisclosureList(ctx, cli, network)
	if err != nil {
		return err
	}
	view := urDisclosureView(list, id)
	if view == nil {
		return fmt.Errorf("the newest verified compute policy carries no disclosure %s", sidecar.HarnessSanitizeLine(id))
	}
	if err := urDisclosureShowOnTty(ctx, cli, network, view, "to acknowledge it for the network's tagged and cloud sidecars, whose uses it then covers"); err != nil {
		return err
	}
	params := &sidecar.DaemonComputeDisclosureNetworkActParams{Network: network, Id: view.Id, Version: view.Version, Locale: view.Locale, Revision: view.Revision}
	reply := &sidecar.DaemonComputeDisclosureActReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodComputeDisclosureAckNetwork, params, true, reply); err != nil {
		return err
	}
	if err := urDisclosureActRefusal(params.Id, reply, " --network"); err != nil {
		return err
	}
	cli.printf("acknowledged %s version %d for the network\n", view.Id, view.Version)
	return nil
}

// ur disclosures remove <id> --network: the network's acknowledgment taken out once the person confirms on /dev/tty.
func runUrDisclosuresRemoveNetwork(ctx context.Context, cli *urCli, network string, id string) error {
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("take the network's acknowledgment of %s out, so its tagged and cloud sidecars rely on it no more?",
		sidecar.HarnessSanitizeLine(id)))
	if err != nil {
		return err
	}
	if !confirmed {
		return errUrDisclosuresNotRemoved
	}
	reply := &sidecar.DaemonComputeDisclosureActReply{}
	params := &sidecar.DaemonComputeDisclosureRemoveParams{Network: network, Id: id}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodComputeDisclosureRemoveNetwork, params, true, reply); err != nil {
		return err
	}
	cli.printf("removed the network's acknowledgment of %s\n", sidecar.HarnessSanitizeLine(id))
	return nil
}

// An act's reply as its error: nil where it recorded, disclosure_changed naming the command to run again, and any other
// refusal's code. again is what the command takes after its id.
func urDisclosureActRefusal(id string, reply *sidecar.DaemonComputeDisclosureActReply, again string) error {
	switch reply.Refusal {
	case "":
		return nil
	case sidecar.ComputeDisclosureCodeChanged:
		return fmt.Errorf("%s: %s changed while it was shown, so nothing was recorded; run ur disclosures ack %s%s again",
			sidecar.ComputeDisclosureCodeChanged, id, id, again)
	}
	return fmt.Errorf("%s: %s was not recorded", sidecar.HarnessSanitizeLine(reply.Refusal), id)
}

// The Confirm method compute.disclosure.ack, sent confirmed: the person typed the acknowledgment on /dev/tty.
func urDisclosureAck(ctx context.Context, cli *urCli, params *sidecar.DaemonComputeDisclosureActParams) error {
	reply := &sidecar.DaemonComputeDisclosureActReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodComputeDisclosureAck, params, true, reply); err != nil {
		return err
	}
	return urDisclosureActRefusal(params.Id, reply, "")
}

// Before a first use of what disclosure id covers, for a command at a terminal (§2.8's prompt row, §15.1): nil where the
// use is covered or id asks nothing; else its whole text and the person's answer on /dev/tty, nil once acknowledged.
// Without a terminal, disclosure_required naming `ur disclosures ack <id>`, and nothing leaves the device.
func urAskDisclosureOnTty(ctx context.Context, cli *urCli, network string, id string) error {
	list, err := urDisclosureList(ctx, cli, network)
	if err != nil {
		return err
	}
	view := urDisclosureView(list, id)
	if view == nil {
		return fmt.Errorf("%s: the newest verified compute policy carries no disclosure %s", sidecar.ComputeDisclosureCodeRequired,
			sidecar.HarnessSanitizeLine(id))
	}
	if !view.Asks || view.Covered {
		return nil
	}
	if view.Scope == sidecar.ComputeDisclosureScopeNetwork {
		return fmt.Errorf("%s: %s version %d (%s); an Owner or Admin acknowledges it for the network with ur disclosures ack %s --network",
			sidecar.ComputeDisclosureCodeRequired, view.Id, view.Version, sidecar.HarnessSanitizeLine(view.Summary), view.Id)
	}
	if err := urDisclosureAckOnTty(ctx, cli, network, view); err != nil {
		if errors.Is(err, errUrNoTty) {
			return fmt.Errorf("%s: %s version %d (%s); the person acknowledges it with ur disclosures ack %s at a terminal, or in the app",
				sidecar.ComputeDisclosureCodeRequired, view.Id, view.Version, sidecar.HarnessSanitizeLine(view.Summary), view.Id)
		}
		return err
	}
	return nil
}

// ur harness's disclosure texts and acknowledgment on network: the daemon's registry, in the terminal's locale, and,
// only where ur has a terminal to read the person's lines from, the acknowledgment through the Confirm method, so a
// line from stdin, which an agent could write, never acknowledges for the person.
func urDisclosureHarnessEntry(cli *urCli, network string) (sidecar.HarnessDisclosureTexts, sidecar.HarnessDisclosureAcker) {
	texts := &urDisclosureHarnessTexts{cli: cli, network: network}
	tty, err := cli.openTty()
	if err != nil {
		return texts, nil
	}
	tty.Close()
	return texts, &urDisclosureHarnessAcker{cli: cli, network: network}
}

// HarnessDisclosureAcker over the daemon's Confirm method.
type urDisclosureHarnessAcker struct {
	cli     *urCli
	network string
}

// See sidecar.HarnessDisclosureAcker: the person typed "I understand" at the terminal ur harness reads.
func (self *urDisclosureHarnessAcker) Ack(ctx context.Context, id string, version uint32) error {
	return urDisclosureAck(ctx, self.cli, &sidecar.DaemonComputeDisclosureActParams{Network: self.network, Id: id, Version: version})
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

// The control method `ur status` names a tagged or cloud sidecar's network acknowledgments by (§2.8's network row).
const urMethodStatusDisclosures = "status.disclosures"

// status.disclosures' reply: a line per network acknowledgment a hosted tagged or cloud sidecar relies on.
type urStatusDisclosuresReply struct {
	Lines []string `json:"lines,omitempty"`
}

// The lines of one hosted network's list: on a tagged or cloud sidecar, whose acknowledgments are the network's, each
// one its compute block holds, its version, who gave it on which device and when, and whether it covers a use now;
// nothing on a member's device, whose are the person's. Ids, versions and times only.
func urStatusDisclosureLines(networkId sidecar.Id, list *sidecar.ComputeDisclosureList) []string {
	lines := []string{}
	for _, view := range list.Disclosures {
		if view == nil || view.Scope != sidecar.ComputeDisclosureScopeNetwork || view.Network == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("disclosure: network %s %s acknowledged for the network, %s", networkId,
			sidecar.HarnessSanitizeLine(view.Id), urDisclosureNetworkWords(view)))
	}
	return lines
}

// The method over target, when it hosts Sidecars: each hosted network's lines, a network that lists no disclosure, as
// one with no verified policy, passed over.
func urDisclosureStatusMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusDisclosures,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			reply := &urStatusDisclosuresReply{}
			for _, network := range hosting.hosted() {
				if network.Sidecar == nil {
					continue
				}
				list, err := network.Sidecar.ComputeDisclosures(ctx, "")
				if err != nil {
					continue
				}
				reply.Lines = append(reply.Lines, urStatusDisclosureLines(network.NetworkId, list)...)
			}
			return reply, nil
		},
	}}
}

// The lines, after status's own; nothing for a daemon that does not answer, or holds none.
func printUrStatusDisclosures(ctx context.Context, cli *urCli) {
	reply := &urStatusDisclosuresReply{}
	if err := cli.callDaemon(ctx, urMethodStatusDisclosures, struct{}{}, false, reply); err != nil {
		return
	}
	for _, line := range reply.Lines {
		fmt.Fprintf(cli.stdout, "%s\n", line)
	}
}
