package main

// ur directory's person acts (cmd_directory_confirm.go): a Confirm method goes only after a yes on /dev/tty, never
// with no terminal or a no, and a wider claims value takes the person's yes before its confirming call.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What a stand-in daemon's directory methods were sent.
type testUrDirectoryDaemon struct {
	stateLock sync.Mutex
	calls     []string
	confirmed []bool
	// directory.claims's answer
	needsConfirmation bool
}

func (self *testUrDirectoryDaemon) record(name string, confirmed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, name)
	self.confirmed = append(self.confirmed, confirmed)
}

// The stand-in's methods, by the directory's names and Confirm flags.
func (self *testUrDirectoryDaemon) methods() []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{Name: sidecar.DaemonMethodDirectoryRevoke, Confirm: true, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.record(sidecar.DaemonMethodDirectoryRevoke, call.Confirmed)
			return map[string]bool{"ok": true}, nil
		}},
		{Name: sidecar.DaemonMethodDirectoryClaims, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.record(sidecar.DaemonMethodDirectoryClaims, call.Confirmed)
			params := &sidecar.DaemonDirectoryClaimsParams{}
			json.Unmarshal(call.Params, params)
			if self.needsConfirmation {
				return &sidecar.DaemonDirectoryClaimsReply{Claims: "off", NeedsConfirmation: true}, nil
			}
			return &sidecar.DaemonDirectoryClaimsReply{Claims: params.Claims, Source: sidecar.SidecarClaimsSourceConfirmed}, nil
		}},
		{Name: sidecar.DaemonMethodDirectoryClaimsConfirm, Confirm: true, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.record(sidecar.DaemonMethodDirectoryClaimsConfirm, call.Confirmed)
			params := &sidecar.DaemonDirectoryClaimsParams{}
			json.Unmarshal(call.Params, params)
			return &sidecar.DaemonDirectoryClaimsReply{Claims: params.Claims, Source: sidecar.SidecarClaimsSourceConfirmed}, nil
		}},
	}
}

func (self *testUrDirectoryDaemon) recorded() ([]string, []bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.calls...), append([]bool{}, self.confirmed...)
}

// A person act goes only after a yes on the terminal, confirmed; no terminal or a no sends nothing.
func TestDirectoryActNeedsTheTerminal(t *testing.T) {
	stand := &testUrDirectoryDaemon{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, _ := newTestUrCli(daemon.socketPath)
	params := &sidecar.DaemonDirectoryRevokeParams{RepoId: sidecar.NewId()}
	if err := urDirectoryConfirmedCall(context.Background(), cli, sidecar.DaemonMethodDirectoryRevoke, params, "Revoke?", nil); !errors.Is(err, errUrNoTty) {
		t.Fatalf("no terminal: %v", err)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if err := urDirectoryConfirmedCall(context.Background(), cli, sidecar.DaemonMethodDirectoryRevoke, params, "Revoke?", nil); !errors.Is(err, errUrDirectoryNotConfirmed) {
		t.Fatalf("a no: %v", err)
	}
	if calls, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("an unconfirmed act was sent: %v", calls)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if err := urDirectoryConfirmedCall(context.Background(), cli, sidecar.DaemonMethodDirectoryRevoke, params, "Revoke?", nil); err != nil {
		t.Fatal(err)
	}
	if calls, confirmed := stand.recorded(); len(calls) != 1 || !confirmed[0] {
		t.Fatalf("the confirmed act: %v %v", calls, confirmed)
	}
}

// A narrower claims value goes at once; a wider one is sent confirmed only after a yes on the terminal.
func TestDirectoryRunsWiderAsksThePerson(t *testing.T) {
	stand := &testUrDirectoryDaemon{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, _ := newTestUrCli(daemon.socketPath)
	reply, err := urDirectoryChooseClaims(context.Background(), cli, "", "off")
	if err != nil || reply.Claims != "off" {
		t.Fatalf("a narrower value: %+v %v", reply, err)
	}

	stand.needsConfirmation = true
	if _, err := urDirectoryChooseClaims(context.Background(), cli, "", "auto"); !errors.Is(err, errUrNoTty) {
		t.Fatalf("a wider value with no terminal: %v", err)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	reply, err = urDirectoryChooseClaims(context.Background(), cli, "", "auto")
	if err != nil || reply.Claims != "auto" {
		t.Fatalf("a confirmed wider value: %+v %v", reply, err)
	}
	calls, confirmed := stand.recorded()
	want := []string{sidecar.DaemonMethodDirectoryClaims, sidecar.DaemonMethodDirectoryClaims, sidecar.DaemonMethodDirectoryClaims, sidecar.DaemonMethodDirectoryClaimsConfirm}
	if len(calls) != len(want) {
		t.Fatalf("calls %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] || confirmed[i] != (i == 3) {
			t.Fatalf("calls %v confirmed %v", calls, confirmed)
		}
	}
}
