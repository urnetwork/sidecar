// ur evs lfs window (EVS2-M10-28): the command reaches its method over a target that hosts a Sidecar, with the daemon's
// refusal printed, and refuses a window under 7 days or past 365 before anything is sent. What SetWindow writes, and
// how the prune reads it, is the root's (evs_lfs_prune_test.go).

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestEvsLfsWindowReachesTheDaemonsMethod(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsTarget{err: errors.New("the evs client is not up")}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	args := []string{"ur", "evs", "lfs", repoId.String(), "window", "30"}
	if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
		t.Fatalf("%v: exit %d: %s", args, code, stderr.String())
	}
}

func TestEvsLfsWindowRefusesItsBoundsLocally(t *testing.T) {
	repoId := sidecar.NewId()
	for _, days := range []string{"6", "366", "a week"} {
		cli, _, stderr := newTestUrCli("")
		args := []string{"ur", "evs", "lfs", repoId.String(), "window", days}
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "a window of 7 to 365 days") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
}
