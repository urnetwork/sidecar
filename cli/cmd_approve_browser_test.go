package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestApproveBrowserComparesSafetyAndSignsOnlyAfterTerminalYes(t *testing.T) {
	target, mailbox, network, member := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	number := strings.Repeat("123456", 10)
	decisions := make(chan urBrowserAdmission, 2)
	requestedBurnerExpiry := make(chan int64, 1)
	// A retry displays the earlier deadline retained by the signer, including its millisecond component.
	retainedExpiry := time.Now().Add(59 * time.Minute).Truncate(time.Second).Add(321 * time.Millisecond).UnixMilli()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		preview := &sidecar.DaemonMethod{Name: urMethodBrowserPreview, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			var args urBrowserAdmission
			if err := decodeUrParams(call, &args); err != nil {
				return nil, err
			}
			if args.Terms.Mode == sidecar.BrowserAdmissionBurner {
				requestedBurnerExpiry <- args.Terms.NotAfterMs
				args.Terms.NotAfterMs = retainedExpiry
			}
			return &sidecar.BrowserAdmissionPreview{Terms: args.Terms, SafetyNumber: number, NetworkId: network, MemberId: member}, nil
		}}
		confirm := &sidecar.DaemonMethod{Name: urMethodBrowserConfirm, Confirm: true, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			var args urBrowserAdmission
			if err := decodeUrParams(call, &args); err != nil {
				return nil, err
			}
			decisions <- args
			return nil, nil
		}}
		for _, method := range []*sidecar.DaemonMethod{preview, confirm} {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	page := []string{"ur", "approve", "browser", target.String()}
	cli.stdin = strings.NewReader("yes\n")
	if exit := cli.main(t.Context(), page); exit != urExitFailed || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("no terminal: exit %d %s", exit, stderr)
	}
	for _, row := range []struct {
		argv   []string
		answer string
		mode   string
	}{
		{page, "n", sidecar.BrowserAdmissionPage}, {page, "yes", sidecar.BrowserAdmissionPage},
		{[]string{"ur", "approve", "burner", target.String(), mailbox.String(), "--for=1h", "--network=example"}, "yes", sidecar.BrowserAdmissionBurner},
	} {
		tty := &testTty{lines: []string{row.answer}}
		cli.openTty = func() (urTty, error) { return tty, nil }
		before := time.Now()
		if exit := cli.main(t.Context(), row.argv); exit != urExitOk {
			t.Fatalf("exit %d: %s", exit, stderr)
		}
		screen := tty.written.String()
		if !strings.Contains(screen, target.String()) || !strings.Contains(screen, sidecar.FormatSafetyNumber(number)) {
			t.Fatalf("missing comparison: %q", screen)
		}
		if row.answer == "n" {
			if len(decisions) != 0 {
				t.Fatal("signed on decline")
			}
			continue
		}
		select {
		case args := <-decisions:
			if args.Target != target || args.Terms.Mode != row.mode || args.SafetyNumber != number || args.NetworkId != network || args.MemberId != member {
				t.Fatalf("decision: %+v", args)
			}
			if row.mode == sidecar.BrowserAdmissionBurner {
				requested := <-requestedBurnerExpiry
				if args.Network != "example" || args.Terms.MailboxId != mailbox || requested < before.Add(time.Hour).UnixMilli() || requested > time.Now().Add(time.Hour).UnixMilli() ||
					args.Terms.NotAfterMs != retainedExpiry || !strings.Contains(screen, mailbox.String()) || !strings.Contains(screen, time.UnixMilli(retainedExpiry).Format(time.RFC3339Nano)) {
					t.Fatalf("burner terms: %+v %q", args, screen)
				}
			}
		default:
			t.Fatal("missing confirmed control call")
		}
	}
}
