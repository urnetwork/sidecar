// git-remote-ur's and ur mount's cli side (EVS1-M2-38): the git service refuses in git's own protocol while the daemon
// builds no evs client; git-remote-ur needs git's two arguments; ur mount share refuses until the statement poster
// lands; and git's credential helper does nothing for store and erase.

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// With no evs client in the daemon, a git session gets git's ERR pkt-line saying so.
func TestGitRemoteUrRefusesWithoutAnEvsClient(t *testing.T) {
	held := urDaemonEvsClient
	urDaemonEvsClient = nil
	defer func() { urDaemonEvsClient = held }()
	stream := &bytes.Buffer{}
	err := urServeGit(context.Background(), &sidecar.DaemonGitSession{Repo: "id:x", Service: "git-upload-pack", Stream: stream})
	if err == nil || !strings.Contains(stream.String(), "ERR ur: this daemon builds no evs client") {
		t.Fatalf("the refusal %q %v", stream.String(), err)
	}
}

// git runs the helper with a remote's name and url; anything less is a usage error.
func TestGitRemoteUrNeedsItsArguments(t *testing.T) {
	cli := newUrCli()
	cli.stderr = &bytes.Buffer{}
	if code := runGitRemoteUr(context.Background(), cli, []string{"origin"}); code != urExitUsage {
		t.Fatalf("one argument: %d", code)
	}
}

// ur mount share waits on the statement poster, and git-credential's store and erase do nothing.
func TestUrMountShareAndCredentialStore(t *testing.T) {
	cli := newUrCli()
	stderr := &bytes.Buffer{}
	cli.stderr = stderr
	cli.stdout = &bytes.Buffer{}
	if code := cli.runCommand(context.Background(), urCommands["mount"], []string{"mount", "share", "/tmp/x", "member"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "statement poster") {
		t.Fatalf("share: %d %s", code, stderr.String())
	}
	cli.stdin = strings.NewReader("protocol=http\nhost=127.0.0.1:17000\n\n")
	if code := cli.runCommand(context.Background(), urCommands["git-credential"], []string{"git-credential", "store"}); code != urExitOk {
		t.Fatalf("store: %d", code)
	}
}

// The daemon's git-hook mode with no evs client, or no network holding the session, ends the hook with a line on its
// stderr and exit code 1, which refuses the push.
func TestUrGitHookModeRefusesAnUnknownSession(t *testing.T) {
	held := urDaemonEvsClient
	urDaemonEvsClient = nil
	defer func() { urDaemonEvsClient = held }()
	out := &bytes.Buffer{}
	stream := &urReplayedStream{reader: strings.NewReader(`{"session":"0123"}` + "\n"), writer: out}
	if err := urDaemonGitHookMode(nil)(context.Background(), &sidecar.DaemonHello{Service: "pre-receive"}, stream); err != nil {
		t.Fatal(err)
	}
	frames := out.Bytes()
	if len(frames) < 5 || frames[0] != 3 || !strings.Contains(string(frames), "no network of this daemon holds") ||
		!bytes.HasSuffix(frames, []byte{4, 0, 0, 0, 1, 1}) {
		t.Fatalf("the frames %q", frames)
	}
}
