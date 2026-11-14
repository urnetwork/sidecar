// ur evs versioning and ur evs ls -l (EVS2-M10-16): the command reaches its method over a target that hosts a
// Sidecar, with the daemon's refusal printed; without a path it asks for one; and the lines both print. What
// SetVersioning does against evs is sidecartest's (evs_write_versionless_test.go).

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A daemon target whose evs client is not there, with the reason a test sets.
type testUrEvsTarget struct {
	testUrDaemonTarget
	err error
}

func (self *testUrEvsTarget) evsClient() (*sidecar.EvsClient, error) {
	return nil, self.err
}

func TestEvsVersioningReachesTheDaemonsMethod(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsTarget{err: errors.New("the evs client is not up")}
	daemon := startTestControlDaemon(t, target, nil)
	for _, args := range [][]string{
		{"ur", "evs", "versioning", repoId.String(), "off", "--ref", "notes", "build/**", "a.bin"},
		{"ur", "evs", "versioning", repoId.String(), "on", "a.bin"},
		{"ur", "evs", "ls", repoId.String(), "-l", "build"},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "evs", "versioning", "not-a-repo", "off", "a.bin"}); code == urExitOk || !strings.Contains(stderr.String(), "is no repo id") {
		t.Errorf("a bad repo id: exit %d: %s", code, stderr.String())
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "evs", "versioning", repoId.String(), "off"}); code == urExitOk {
		t.Error("ur evs versioning with no path ran")
	}
}

func TestEvsVersioningAndListingLines(t *testing.T) {
	listing := &sidecar.EvsListing{Path: "build", HeadVersion: 7, Entries: []*sidecar.EvsListEntry{
		{Name: []byte("a.bin"), Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE, Versioning: 1},
		{Name: []byte("deep"), Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY},
		{Name: []byte("notes.txt"), Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE},
		{Name: []byte("shard"), Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE, Versioning: 2},
	}}
	long := strings.Join(urEvsListingLines(listing, true), "\n")
	for _, want := range []string{"build at version 7", "off    a.bin", "-      deep/", "on     notes.txt", "index  shard"} {
		if !strings.Contains(long, want) {
			t.Errorf("ls -l does not show %q:\n%s", want, long)
		}
	}
	short := strings.Join(urEvsListingLines(listing, false), "\n")
	if strings.Contains(short, "off") || !strings.Contains(short, "  deep/") {
		t.Errorf("ls shows:\n%s", short)
	}
	result := &sidecar.EvsSetVersioningResult{Version: 9, Changed: []string{"build/a.bin"}, Unchanged: []string{"build/b.bin"}}
	lines := strings.Join(urEvsVersioningLines(result, sidecar.EvsVersioningOff), "\n")
	for _, want := range []string{"versioning off  build/a.bin", "already off     build/b.bin", "1 file(s) at ref version 9"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the result does not show %q:\n%s", want, lines)
		}
	}
	if lines := urEvsVersioningLines(&sidecar.EvsSetVersioningResult{Unchanged: []string{"a"}}, sidecar.EvsVersioningOn); lines[len(lines)-1] != "nothing changed" {
		t.Errorf("no change shows %v", lines)
	}
}
