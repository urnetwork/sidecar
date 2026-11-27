// ur agents send, broadcast, reply and inbox (DESIGN-COMPUTE §15.1's ur agents rows, §20.7's person in a thread and
// trust rows, §20.8; SKILL-M11-08): the person's messages to their agents and the threads they come back in, through
// ur daemon's agents methods (the root's agents_daemon.go, registered here with urDaemonMethodExtensions).
//
//	ur agents send <name> <text> [--subject=<subject>]
//	ur agents broadcast <text> [--subject=<subject>]
//	ur agents reply <thread> <text> [--to=<name>]
//	ur agents inbox [--thread=<thread>] [--untrusted=<untrusted>]
//
// The person's input path: send, broadcast and reply show the message on /dev/tty and ask; a yes is sent confirmed,
// and the daemon writes it as the person's own words (§20.7's kind (a), bound to no run) only when no harness process
// is among this ur's ancestors, which it reads from the peer's pid. Under a harness it is that run's message, its
// session agent's, untrusted, whatever the terminal answered. With no terminal to ask the call goes unconfirmed, and the
// daemon refuses it unless a harness is an ancestor: the person's path is refused, never written down as someone
// else's. A no sends nothing.
//
// inbox prints the person's threads, or one: each message with its verified sender and how its trust reads, an
// untrusted writer's text withheld off a terminal unless --untrusted include, which taints first each run this ur's
// ancestry binds, as ur agents ls does. Every text is printed safe: controls and bidi controls dropped.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// What a no on the terminal answers.
var errUrAgentsNotSent = errors.New("not sent")

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAgentsMethods)
}

// The agents methods over target, where it hosts Sidecars: the caller's ancestry and its runs' taint read from the
// peer's pid; a caller the daemon cannot name is under a harness, and has no runs to taint, so it gets no untrusted text.
func urAgentsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonAgentsMethods(&sidecar.DaemonAgentsBackends{
		UnderHarness: func(ctx context.Context, call *sidecar.DaemonCall) bool {
			pid := urCallPid(call)
			if pid <= 0 || call.Sidecar == nil {
				return true
			}
			return call.Sidecar.HarnessAncestor(ctx, pid)
		},
		TaintAncestors: func(ctx context.Context, call *sidecar.DaemonCall) error {
			pid := urCallPid(call)
			if pid <= 0 || call.Sidecar == nil {
				return errors.New("the caller's process cannot be read, so no untrusted text is returned")
			}
			return call.Sidecar.TaintAncestorRuns(ctx, pid)
		},
	})
}

// ur agents send <name> <text>.
func runUrAgentsSend(ctx context.Context, cli *urCli, options docopt.Opts) error {
	name := urOptionString(options, "<name>")
	params := &sidecar.DaemonAgentsSendParams{Network: urOptionString(options, "--network"), To: name,
		Subject: urOptionString(options, "--subject"), Body: urOptionString(options, "<text>")}
	return urAgentsSendConfirmed(ctx, cli, options, params, "to "+name)
}

// ur agents broadcast <text>.
func runUrAgentsBroadcast(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &sidecar.DaemonAgentsSendParams{Network: urOptionString(options, "--network"), Broadcast: true,
		Subject: urOptionString(options, "--subject"), Body: urOptionString(options, "<text>")}
	return urAgentsSendConfirmed(ctx, cli, options, params, "to every agent")
}

// ur agents reply <thread> <text>.
func runUrAgentsReply(ctx context.Context, cli *urCli, options docopt.Opts) error {
	thread := urOptionString(options, "<thread>")
	params := &sidecar.DaemonAgentsSendParams{Network: urOptionString(options, "--network"), Thread: thread,
		To: urOptionString(options, "--to"), Body: urOptionString(options, "<text>")}
	return urAgentsSendConfirmed(ctx, cli, options, params, "in thread "+thread)
}

// Shows the message on /dev/tty and sends it confirmed on a yes, unconfirmed where no terminal answers (see the file
// header), and prints what was written.
func urAgentsSendConfirmed(ctx context.Context, cli *urCli, options docopt.Opts, params *sidecar.DaemonAgentsSendParams, where string) error {
	question := "Send this message " + where
	if params.Subject != "" {
		question += ", subject " + urSearchSafe(params.Subject)
	}
	question += ", as you?\n" + urSearchSafe(params.Body) + "\n"
	confirmed, err := confirmOnTty(cli, question)
	switch {
	case errors.Is(err, errUrNoTty):
		// no terminal: the daemon writes it as a harness run's, where one is this ur's ancestor, or refuses it
		confirmed = false
	case err != nil:
		return err
	case !confirmed:
		return errUrAgentsNotSent
	}
	reply := &sidecar.DaemonAgentsSendReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodAgentsSend, params, confirmed, reply); err != nil {
		return err
	}
	if urOptionBool(options, "--json") {
		encoded, err := urSearchJson(reply)
		if err != nil {
			return err
		}
		_, err = cli.stdout.Write(encoded)
		return err
	}
	if reply.AgentSendToolResult == nil {
		return errors.New("the daemon answered no message")
	}
	as := "as you"
	if !reply.Person {
		as = "as your harness run's agent, which its readers take as untrusted"
	}
	line := fmt.Sprintf("sent %s %d of thread %s to %s, %s", reply.Kind, reply.Seq, reply.Thread, reply.To, as)
	if reply.RecipientState != "" {
		line += fmt.Sprintf("; %s is %s", reply.To, reply.RecipientState)
	}
	cli.printf("%s\n", urSearchSafe(line))
	return nil
}

// ur agents inbox [--thread=<thread>].
func runUrAgentsInbox(ctx context.Context, cli *urCli, options docopt.Opts) error {
	untrusted, err := urSearchUntrusted(cli, urOptionString(options, "--untrusted"))
	if err != nil {
		return err
	}
	params := &sidecar.DaemonAgentsInboxParams{Network: urOptionString(options, "--network"), Thread: urOptionString(options, "--thread"),
		Untrusted: untrusted}
	inbox := &sidecar.AgentPersonInbox{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodAgentsInbox, params, false, inbox); err != nil {
		return err
	}
	if urOptionBool(options, "--json") {
		encoded, err := urSearchJson(inbox)
		if err != nil {
			return err
		}
		_, err = cli.stdout.Write(encoded)
		return err
	}
	if len(inbox.Threads) == 0 {
		cli.printf("no threads\n")
		return nil
	}
	for i, thread := range inbox.Threads {
		if 0 < i {
			cli.printf("\n")
		}
		head := "thread " + thread.Thread
		if thread.ToAll {
			head += "  to every agent"
		}
		if thread.Closed {
			head += "  closed"
		}
		cli.printf("%s\n", urSearchSafe(head))
		for _, message := range thread.Messages {
			for _, line := range urAgentsInboxLines(message) {
				cli.printf("%s\n", urSearchSafe(line))
			}
		}
	}
	if 0 < inbox.Withheld {
		cli.printf("%s\n", urSearchSafe(fmt.Sprintf("-- %d messages' text withheld: untrusted writers wrote it; --untrusted include shows it", inbox.Withheld)))
	}
	if 0 < inbox.More {
		cli.printf("%s\n", urSearchSafe(fmt.Sprintf("-- %d more messages: --thread shows one thread whole", inbox.More)))
	}
	return nil
}

// One message's lines: its head, then its subject and body indented, or the withheld mark.
func urAgentsInboxLines(message *sidecar.AgentInboxMessage) []string {
	head := fmt.Sprintf("  %d %s from %s (%s) to %s, %s", message.Seq, message.Kind, message.From, message.Trust, message.To, message.Created)
	lines := []string{head}
	if message.Withheld {
		return append(lines, "    [untrusted: withheld]")
	}
	if message.Subject != "" {
		lines = append(lines, "    subject: "+message.Subject)
	}
	for _, line := range strings.Split(message.Body, "\n") {
		if line != "" {
			lines = append(lines, "    "+line)
		}
	}
	return lines
}
