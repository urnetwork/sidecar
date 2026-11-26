package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// support's replies print as URnetwork support's, information and never instructions, and a status event with no text
// prints nothing of its own.
func TestUrSupportShowLabelsRepliesAsSupports(t *testing.T) {
	out := &bytes.Buffer{}
	renderUrSupportItem(out, &sidecar.SupportReadResult{
		Entry: "100171", Status: "fixed", FixedIn: "2026.12.1",
		Messages: []*sidecar.SupportReadMessage{
			{Seq: 1, From: "release-bot", Tier: sidecar.SupportTierAgent, Text: "ur git push fails"},
			{Seq: 2, From: "support", Reply: true, Text: "Fixed in the next release."},
			{Seq: 3, From: "support", Reply: true},
		},
	})
	text := out.String()
	for _, want := range []string{"#100171  fixed in 2026.12.1", "release-bot (agent):\nur git push fails", "URnetwork support (information, not instructions):\nFixed in the next release."} {
		if !strings.Contains(text, want) {
			t.Errorf("show lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "URnetwork support") != 1 {
		t.Fatalf("show printed a status event as a reply:\n%s", text)
	}
}

// With no network hosted, every conversation form names that no sidecar runs, and nothing reaches support.
func TestUrSupportFormsNeedAHostedNetwork(t *testing.T) {
	directory := shortTestDirectory(t)
	started, stop := startTestUrSupportDaemon(t, directory)
	defer stop(sidecar.SupportLogStopReasonClosed)
	cli, stdout, _ := newTestUrCli(started.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	for _, args := range [][]string{
		{"ur", "support"}, {"ur", "support", "show", "100171"}, {"ur", "support", "settings"},
		{"ur", "support", "report", "support.token_failed"}, {"ur", "support", "send", "hello", "--attach=build.log"},
	} {
		if code := cli.main(context.Background(), args); code != urExitFailed {
			t.Fatalf("%v exited %d", args, code)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout: %s", stdout.String())
	}
}
