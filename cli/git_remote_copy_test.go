// Subcommands selected by the separately named helper in the Windows archive.
package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A previously configured clone can smudge immediately after upgrading, before its next git fetch rewrites the path.
func TestGitHelperRunsTheLfsCommandSavedByOlderClones(t *testing.T) {
	cli, stdout, stderr := newTestUrCli("")
	t.Setenv("GIT_DIR", t.TempDir())
	cli.getenv = os.Getenv
	cli.stdin = strings.NewReader("{\"event\":\"init\"}\n{\"event\":\"terminate\"}\n")
	args := []string{"git-remote-ur.exe", "lfs-agent", "--repo=test/id:00000000000000000000000000000001"}
	if code := cli.main(t.Context(), args); code != 0 || stdout.String() != "{}\n" {
		t.Fatalf("legacy agent returned %d: %q (%s)", code, stdout.Bytes(), stderr)
	}
	cli.stdin = strings.NewReader("capabilities\n\n")
	stdout.Reset()
	cli.getenv = func(string) string { return "" }
	if code := cli.main(t.Context(), []string{"git-remote-ur.exe", "lfs-agent", "ur://test/id:00000000000000000000000000000001"}); code != 0 || stdout.String() != "connect\n\n" {
		t.Fatalf("remote named lfs-agent: %d, %q (%s)", code, stdout.Bytes(), stderr)
	}
}

// Runs the real resolver and clone configuration from a binary physically named like the packaged helper.
func TestPackagedGitHelperSelectsUrForDaemonAndLfs(t *testing.T) {
	const variable = "UR_TEST_PACKAGED_GIT_DIR"
	if gitDir := os.Getenv(variable); gitDir != "" {
		path, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(filepath.Dir(path), "ur.exe")
		command, err := urDaemonCommand([]string{"--auto-spawned"})
		if err != nil || command.Path != want || !slices.Equal(command.Args, []string{want, "daemon", "--auto-spawned"}) {
			t.Fatalf("cold daemon command: %v, %v", command, err)
		}
		cli := newUrCli()
		repo := "test/id:00000000000000000000000000000001"
		if err := urConfigureRemoteLfs(t.Context(), cli, "ur://"+repo); err != nil {
			t.Fatal(err)
		}
		config := func(key string) string {
			t.Helper()
			result, err := exec.CommandContext(t.Context(), "git", "config", "--file", filepath.Join(gitDir, "config"), key).Output()
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimSpace(string(result))
		}
		if got := config("lfs.customtransfer.ur.path"); got != want {
			t.Fatalf("transfer executable %q, want %q", got, want)
		}
		if got := config("lfs.customtransfer.ur.args"); got != "lfs-agent --repo="+repo {
			t.Fatalf("transfer arguments %q", got)
		}
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	helper := filepath.Join(t.TempDir(), "git-remote-ur.exe")
	out, err := os.OpenFile(helper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	if err := out.Close(); err != nil || copyErr != nil {
		t.Fatalf("copy helper: %v, %v", copyErr, err)
	}
	gitDir := t.TempDir()
	command := exec.CommandContext(t.Context(), helper, "-test.run=^TestPackagedGitHelperSelectsUrForDaemonAndLfs$")
	command.Env = append(os.Environ(), variable+"="+gitDir, "GIT_DIR="+gitDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("packaged helper: %v\n%s", err, output)
	}
}
