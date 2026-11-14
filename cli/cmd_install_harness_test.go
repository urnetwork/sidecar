// ur install-harness (MCP-M3-16): the diff is shown before anything is written, nothing is written unless the person
// confirms on the terminal, and a second run with nothing to change asks nothing.

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A ur whose install-harness writes under home and state, as /opt/ur/bin/ur, its output and the terminal's one log.
func newTestInstallHarnessCli(t *testing.T, home string, state string, answers ...string) (*urCli, *testTty) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the install names POSIX paths")
	}
	executable, homeDirectory := urHarnessExecutable, urHarnessHome
	t.Cleanup(func() {
		urHarnessExecutable, urHarnessHome = executable, homeDirectory
	})
	urHarnessExecutable = func() (string, error) { return "/opt/ur/bin/ur", nil }
	urHarnessHome = func() (string, error) { return home, nil }
	cli, _, _ := newTestUrCli(filepath.Join(shortTestDirectory(t), "none"))
	tty := &testTty{lines: answers}
	cli.openTty = func() (urTty, error) { return tty, nil }
	// the output and the question in one log, so their order shows
	cli.stdout = tty
	cli.stateDirectory = func(instance string) (string, error) { return state, nil }
	return cli, tty
}

// The diff is on the terminal before the question, a no writes nothing, and a yes writes the files and the seal.
func TestDiffShownBeforeWrite(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	cli, tty := newTestInstallHarnessCli(t, home, state, "n")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	log := tty.written.String()
	diffAt := strings.Index(log, "+++ b"+filepath.ToSlash(filepath.Join(home, ".cursor", "hooks.json")))
	questionAt := strings.Index(log, "write these changes")
	if diffAt < 0 || questionAt < 0 || questionAt < diffAt {
		t.Fatalf("the diff does not come before the question:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "hooks.json")); !os.IsNotExist(err) {
		t.Errorf("a declined install wrote: %v", err)
	}
	if entries, _ := os.ReadDir(state); 0 < len(entries) {
		t.Error("a declined install sealed")
	}

	cli, _ = newTestInstallHarnessCli(t, home, state, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	hooks, err := os.ReadFile(filepath.Join(home, ".cursor", "hooks.json"))
	if err != nil || !strings.Contains(string(hooks), "/opt/ur/bin/ur hook cursor") {
		t.Fatalf("the hooks were not written: %v\n%s", err, hooks)
	}
	if _, err := os.Stat(filepath.Join(state, "harness", "cursor.json")); err != nil {
		t.Errorf("no seal: %v", err)
	}

	// nothing left to change: nothing asked
	cli, tty = newTestInstallHarnessCli(t, home, state)
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(tty.written.String(), "nothing to change") || strings.Contains(tty.written.String(), "write these changes") {
		t.Errorf("a second install:\n%s", tty.written.String())
	}
}

// A harness ur does not install into is refused, and nothing is asked or written.
func TestInstallHarnessRefusesUnknown(t *testing.T) {
	home := t.TempDir()
	cli, tty := newTestInstallHarnessCli(t, home, t.TempDir())
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "notepad"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if tty.written.Len() != 0 {
		t.Errorf("asked or wrote: %s", tty.written.String())
	}
}
