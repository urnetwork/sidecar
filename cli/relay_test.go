package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// With no daemon answering, the relay spawns one, once, with the instance and the auto-spawned flag, and dials until
// it answers.
func TestRelaySpawnsDaemonOnce(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, _, stderr := newTestUrCli(filepath.Join(directory, "s"))
	stdout := newSyncBuffer()
	cli.stdout = stdout
	var spawns atomic.Int32
	var spawnArgs []string
	cli.spawnDaemon = func(args []string) error {
		spawns.Add(1)
		spawnArgs = args
		startTestUrDaemon(t, directory, echoMcpMode)
		return nil
	}
	pipeReader, pipeWriter := io.Pipe()
	cli.stdin = pipeReader
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur", "--instance", "work", "mcp"})
	}()
	io.WriteString(pipeWriter, "ping\n")
	stdout.awaitContains(t, "echo: ping")
	pipeWriter.Close()
	select {
	case code := <-finished:
		if code != urExitOk {
			t.Errorf("exit %d; stderr %q", code, stderr.String())
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the relay did not end")
	}
	if spawns.Load() != 1 {
		t.Errorf("spawned %d times", spawns.Load())
	}
	if strings.Join(spawnArgs, " ") != "--instance work --auto-spawned" {
		t.Errorf("spawned with %q", spawnArgs)
	}
}

// A relay that cannot reach a daemon says so on stderr; stdout, which the harness reads as MCP, stays empty.
func TestRelayNeverWritesLogsToStdout(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, cli *urCli, directory string)
	}{
		{name: "no daemon starts", setup: func(t *testing.T, cli *urCli, directory string) {
			cli.spawnDaemon = func(args []string) error { return errors.New("synthetic spawn failure") }
		}},
		{name: "no mcp mode", setup: func(t *testing.T, cli *urCli, directory string) {
			startTestUrDaemon(t, directory, nil)
		}},
		{name: "another version", setup: func(t *testing.T, cli *urCli, directory string) {
			cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
				return nil, &sidecar.DaemonHelloRefusal{Code: sidecar.DaemonHelloErrorVersionSkew, Version: "2026.1.1-old"}
			}
			cli.spawnDaemon = func(args []string) error {
				t.Error("a version-skewed daemon made the relay spawn another")
				return nil
			}
		}},
	}
	for _, c := range cases {
		directory := shortTestDirectory(t)
		cli, stdout, stderr := newTestUrCli(filepath.Join(directory, "s"))
		cli.settings.SpawnWaitTimeout = 50 * time.Millisecond
		c.setup(t, cli, directory)
		cli.stdin = strings.NewReader("{}\n")
		if code := cli.main(context.Background(), []string{"ur", "mcp"}); code != urExitFailed {
			t.Errorf("%s: exit %d", c.name, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout %q", c.name, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Errorf("%s: nothing on stderr", c.name)
		}
	}
}
