package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon with its support log under directory, and the stop the daemon would run at its end.
func startTestUrSupportDaemon(t *testing.T, directory string) (*testUrDaemon, func(reason sidecar.SupportLogStopReason)) {
	t.Helper()
	settings := sidecar.DefaultSidecarSettings()
	var stop func(reason sidecar.SupportLogStopReason)
	started := startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		var err error
		stop, err = startUrSupportLog(daemon, directory, settings, false, true, sidecar.NewNoopLogger())
		if err != nil {
			t.Fatal(err)
		}
	})
	if settings.SupportLog == nil {
		t.Fatal("the daemon's settings carry no support log")
	}
	return started, stop
}

func TestUrSupportLogsPrintsTheBundleOnTheTerminalAlone(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	cli, stdout, _ := newTestUrCli(started.socketPath)
	tty := &testTty{}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "support", "logs"}); code != urExitOk {
		t.Fatalf("ur support logs exited %d", code)
	}
	written := tty.written.String()
	if !strings.Contains(written, "daemon.started") || !strings.Contains(written, "support_log.opened") || !strings.Contains(written, "auto_spawned=true") {
		t.Fatalf("the terminal shows:\n%s", written)
	}
	if stdout.Len() != 0 {
		t.Fatalf("the bundle reached stdout: %s", stdout.String())
	}

	tty.written.Reset()
	if code := cli.main(context.Background(), []string{"ur", "support", "logs", "--json"}); code != urExitOk {
		t.Fatalf("ur support logs --json exited %d", code)
	}
	if !strings.Contains(tty.written.String(), `"format": "urnetwork-support-log-bundle-v1"`) || stdout.Len() != 0 {
		t.Fatalf("the terminal shows:\n%s", tty.written.String())
	}
}

func TestUrSupportLogsNeedsATerminal(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	cli, stdout, stderr := newTestUrCli(started.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "support", "logs"}); code != urExitFailed {
		t.Fatalf("ur support logs with no terminal exited %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func TestUrSupportLogsRefusesASentBundleItDoesNotKeep(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	cli, _, stderr := newTestUrCli(started.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{}, nil }
	if code := cli.main(context.Background(), []string{"ur", "support", "logs", "--sent=100171"}); code != urExitFailed {
		t.Fatalf("ur support logs --sent exited %d", code)
	}
	if !strings.Contains(stderr.String(), "100171") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

// A caller the daemon cannot name is taken as under a harness, so no bundle reaches it.
func TestUrSupportUnderHarnessTakesAnUnnamedCallerAsUnderOne(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	if !urSupportUnderHarness(context.Background(), started.daemon, &sidecar.DaemonCall{Hello: &sidecar.DaemonHello{}}) {
		t.Fatal("a caller with no pid passed")
	}
	if urSupportUnderHarness(context.Background(), started.daemon, &sidecar.DaemonCall{Hello: &sidecar.DaemonHello{PeerPid: int64(os.Getpid())}}) {
		t.Fatal("a caller with no hosted network's harness among its ancestors was refused")
	}
}

func TestUrSupportLogRecordsTheDaemonsStopAndCloses(t *testing.T) {
	directory := shortTestDirectory(t)
	_, stop := startTestUrSupportDaemon(t, directory)
	stop(sidecar.SupportLogStopReasonSignal)
	log, err := sidecar.OpenSupportLog(&sidecar.SupportLogArgs{Directory: sidecar.SupportLogDirectory(directory), Settings: sidecar.DefaultSupportSettings()})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	bundle, err := log.Bundle(nil)
	if err != nil {
		t.Fatal(err)
	}
	stopped := 0
	for _, event := range bundle.Document.Events {
		if event.Component == "daemon" && event.Code == "stopped" {
			stopped += 1
			if event.Fields["stop_reason"] != "signal" {
				t.Fatalf("daemon.stopped reads %v", event.Fields)
			}
		}
	}
	if stopped != 1 {
		t.Fatalf("%d daemon.stopped events", stopped)
	}
	if _, err := os.Stat(filepath.Join(sidecar.SupportLogDirectory(directory), "key")); err != nil {
		t.Fatal(err)
	}
}

func TestUrSupportStopReasonReadsHowRunReturned(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		ctx         context.Context
		err         error
		autoSpawned bool
		want        sidecar.SupportLogStopReason
	}{
		{ctx: context.Background(), err: errors.New("listen failed"), want: sidecar.SupportLogStopReasonFailed},
		{ctx: cancelled, want: sidecar.SupportLogStopReasonSignal},
		{ctx: context.Background(), autoSpawned: true, want: sidecar.SupportLogStopReasonIdle},
		{ctx: context.Background(), want: sidecar.SupportLogStopReasonClosed},
	}
	for i, c := range cases {
		if got := urSupportStopReason(c.ctx, c.err, c.autoSpawned); got != c.want {
			t.Errorf("case %d: %d, want %d", i, got, c.want)
		}
	}
}

func TestUrSupportEphemeralDaemonKeepsNoRing(t *testing.T) {
	directory := shortTestDirectory(t)
	settings := sidecar.DefaultSidecarSettings()
	startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		stop, err := startUrSupportLog(daemon, directory, settings, true, false, sidecar.NewNoopLogger())
		if err != nil {
			t.Fatal(err)
		}
		stop(sidecar.SupportLogStopReasonClosed)
	})
	if settings.SupportLog != nil {
		t.Fatal("an ephemeral daemon set a support log")
	}
	if _, err := os.Stat(sidecar.SupportLogDirectory(directory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an ephemeral daemon made %s", sidecar.SupportLogDirectory(directory))
	}
}
