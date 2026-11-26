package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
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

// ur support export with no id needs no conversation: it writes the support log's next bundle to a new file, with no
// network hosted, never over a file that is there, and an item no hosted network holds writes nothing.
func TestUrSupportExportWritesTheNextBundleToANewFile(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	cli, stdout, stderr := newTestUrCli(started.socketPath)
	out := filepath.Join(t.TempDir(), "support.zip")
	if code := cli.main(context.Background(), []string{"ur", "support", "export", "--out=" + out}); code != urExitOk {
		t.Fatalf("ur support export exited %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	members := map[string][]byte{}
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		members[file.Name], err = io.ReadAll(opened)
		opened.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(members) != 2 || members["README.txt"] == nil {
		t.Fatalf("the archive holds %d members", len(members))
	}
	document, err := sidecar.SupportLogBundleOpen(members["support-log-bundle.json.gz"], sidecar.DefaultSupportSettings().BundleMaxByteCount)
	if err != nil {
		t.Fatal(err)
	}
	starts := 0
	for _, event := range document.Events {
		if event.Component == "daemon" && event.Code == "started" {
			starts += 1
		}
	}
	if starts != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), out) {
		t.Fatalf("%d daemon.started; stdout %q, stderr %q", starts, stdout.String(), stderr.String())
	}
	// never over a file that is there
	if code := cli.main(context.Background(), []string{"ur", "support", "export", "--out=" + out}); code != urExitFailed {
		t.Fatalf("an export over a file exited %d", code)
	}
	if kept, err := os.ReadFile(out); err != nil || !bytes.Equal(kept, data) {
		t.Fatal("an export over a file changed it")
	}
	// an item no hosted network holds: nothing written
	other := filepath.Join(t.TempDir(), "item.zip")
	if code := cli.main(context.Background(), []string{"ur", "support", "export", "100171", "--out=" + other}); code != urExitFailed {
		t.Fatalf("an item's export with no network exited %d", code)
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused export left %s", other)
	}
}
