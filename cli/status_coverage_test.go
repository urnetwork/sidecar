// `ur status`'s coverage section (EVSB-M2-19): each hosted network's lines printed as the daemon gives them, a network
// whose coverage cannot be read named unknown, and a daemon with no mirrors saying so rather than showing coverage.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestUrStatusCoveragePrintsEachNetworksLines(t *testing.T) {
	first, second := sidecar.NewId(), sidecar.NewId()
	hosted := []sidecar.DaemonNetwork{{NetworkId: first}, {NetworkId: second}}
	calls := 0
	reply := urStatusCoverageOf(context.Background(), hosted, func(ctx context.Context, running *sidecar.Sidecar) ([]string, error) {
		calls += 1
		if calls == 2 {
			return nil, errors.New("no verified config state")
		}
		return []string{"coverage:   repo r full", "indexer:    i (network scope): services mirror; no sign of it held"}, nil
	})
	cli, stdout, _ := newTestUrCli("")
	printUrCoverageReply(cli, reply)
	text := stdout.String()
	for _, want := range []string{
		"coverage:   repo r full\n",
		"indexer:    i (network scope): services mirror; no sign of it held\n",
		"coverage:   network " + second.String() + " unknown: no verified config state\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in:\n%s", want, text)
		}
	}
}

func TestUrStatusCoverageWithNoMirrorsSaysSo(t *testing.T) {
	networkId := sidecar.NewId()
	reply := urStatusCoverageOf(context.Background(), []sidecar.DaemonNetwork{{NetworkId: networkId}}, nil)
	if len(reply.Networks) != 1 || reply.Networks[0].Unknown != errUrNoMirrors.Error() || 0 < len(reply.Networks[0].Lines) {
		t.Fatalf("the reply: %+v", reply.Networks[0])
	}
	cli, stdout, _ := newTestUrCli("")
	printUrCoverageReply(cli, reply)
	if !strings.Contains(stdout.String(), "keeps no mirror") || strings.Contains(stdout.String(), "full") {
		t.Errorf("the lines: %s", stdout.String())
	}
}
