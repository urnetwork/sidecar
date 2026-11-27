// `ur status`'s context lines (Q-CTXH-14; CTXH-M13-01): a harness not set to the gateway named with the command that
// sets it, and nothing for a network whose gateway saw every call.

package main

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestUrStatusNamesHarnessNotOnGateway(t *testing.T) {
	networkId, runId := sidecar.NewId(), sidecar.NewId()
	reply := &urStatusContextReply{Lines: urStatusContextLines(networkId, []*sidecar.SessionGatewayPartial{{Harness: "claude-code", RunId: runId, Millis: 1}})}
	reply.Lines = append(reply.Lines, urStatusContextLines(sidecar.NewId(), nil)...)
	cli, stdout, _ := newTestUrCli("")
	printUrStatusContextReply(cli, reply)
	text := stdout.String()
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "network "+networkId.String()+": claude-code calls its own provider") ||
		!strings.Contains(text, "context_partial, run "+runId.String()) || !strings.Contains(text, "`ur install-harness claude-code --gateway`") {
		t.Errorf("the lines:\n%s", text)
	}
}
