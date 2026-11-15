// `ur status`'s directory section (RECORD-M6-20): each hosted network's waiting erasures printed as the daemon gives
// them, a network with none printing nothing.

package main

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestUrStatusDirectoryPrintsWaitingErasures(t *testing.T) {
	team, personal := sidecar.NewId(), sidecar.NewId()
	hosted := []sidecar.DaemonNetwork{{NetworkId: team}, {NetworkId: personal}}
	calls := 0
	reply := urStatusDirectoryOf(hosted, func(running *sidecar.Sidecar) []string {
		calls += 1
		if calls == 2 {
			return nil
		}
		return []string{"directory: the erasure for repo r is pending for 25h (request q): it waits for a directory admin's daemon"}
	})
	if len(reply.Networks) != 1 || reply.Networks[0].NetworkId != team {
		t.Fatalf("the reply: %+v", reply.Networks)
	}
	cli, stdout, _ := newTestUrCli("")
	printUrDirectoryReply(cli, reply)
	if text := stdout.String(); !strings.Contains(text, "is pending for 25h (request q)") || strings.Count(text, "\n") != 1 {
		t.Errorf("the lines:\n%s", text)
	}
}
