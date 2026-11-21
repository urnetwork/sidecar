// ur tls account (TLS-M6-05; DESIGN-DETAILS 17.2.13): status prints each account the daemon answers; create shows the
// CA's terms, needs --agree-tos and a yes on the terminal before its confirmed call, and prints the CAA records to
// publish; roll needs a yes and says when no change is due; and the daemon's methods refuse while no ACME directory is
// configured, before any CA or evs is reached. The daemon here is scripted; Pebble's runs are tls_acme_pebble_test.go.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One account as the scripted daemon answers it.
func testUrTlsAccountView() *urTlsAccountView {
	return &urTlsAccountView{
		Domain:     "customer.example",
		Ca:         "letsencrypt",
		AccountUri: "https://ca.example/acct/1",
		KeySeq:     2,
		KeyRepoId:  sidecar.NewId().String(),
		HeldKeySeq: 2,
		WorkCount:  3,
		AcmeName:   "abcdefghij.acme.sidecar.example",
	}
}

func TestUrTlsAccountStatusPrintsEachAccount(t *testing.T) {
	daemon := &testUrBridgeDaemon{}
	view := testUrTlsAccountView()
	due := testUrTlsAccountView()
	due.Domain = "other.example"
	due.RolloverDue = true
	due.MayRoll = true
	due.HoldNewMs = 90 * 1000
	cli, out, _ := startTestUrSocketCli(t, daemon.method(urMethodTlsAccountStatus, false, func(callCount int) (any, error) {
		return &urTlsAccountStatusReply{Accounts: []*urTlsAccountView{view, due}}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "status", "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	printed := out.String()
	for _, want := range []string{
		"customer.example\n", "account   https://ca.example/acct/1 at letsencrypt, key 2", "this desktop holds key 2",
		"work      3 rows", "_acme-challenge.<host> CNAME abcdefghij.acme.sidecar.example",
		"a key change is due: ur tls account roll other.example", "held by the CA: renewals only for 2 min",
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
	calls, confirmed := daemon.calls()
	params := &urTlsAccountParams{}
	if len(calls) != 1 || confirmed[0] || json.Unmarshal(calls[0], params) != nil || params.Network != "acme" || params.Domain != "" {
		t.Fatalf("the call: %d, %v, %+v", len(calls), confirmed, params)
	}
}

// create shows the terms and asks for --agree-tos, asks on the terminal, files only a confirmed call, and prints the
// CAA records; an account the domain already has is printed and refused.
func TestUrTlsAccountCreateNeedsTheTermsAndAYes(t *testing.T) {
	statusDaemon := &testUrBridgeDaemon{}
	createDaemon := &testUrBridgeDaemon{}
	view := testUrTlsAccountView()
	repoId := sidecar.NewId()
	cli, out, _ := startTestUrSocketCli(t,
		statusDaemon.method(urMethodTlsAccountStatus, false, func(callCount int) (any, error) {
			return &urTlsAccountStatusReply{Accounts: []*urTlsAccountView{}, TermsOfService: "https://ca.example/terms"}, nil
		}),
		createDaemon.method(urMethodTlsAccountCreate, true, func(callCount int) (any, error) {
			return &urTlsAccountCreateReply{Account: view, RepoId: repoId.String(), RepoCreated: true}, nil
		}),
	)
	// no --agree-tos: the terms printed, nothing filed
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "create", "Customer.Example."}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "the CA's terms of service: https://ca.example/terms") {
		t.Fatalf("no terms in: %s", out.String())
	}
	// a no on the terminal: nothing filed
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "create", "customer.example", "--agree-tos"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if calls, _ := createDaemon.calls(); len(calls) != 0 {
		t.Fatalf("%d creates after a no", len(calls))
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "create", "customer.example", "--agree-tos"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	calls, confirmed := createDaemon.calls()
	params := &urTlsAccountParams{}
	if len(calls) != 1 || !confirmed[0] || json.Unmarshal(calls[0], params) != nil || params.Domain != "customer.example" || !params.AgreeTos {
		t.Fatalf("the create: %d, %v, %+v", len(calls), confirmed, params)
	}
	printed := out.String()
	for _, want := range []string{
		"made your secret repo " + repoId.String(),
		`customer.example. CAA 0 issue "letsencrypt.org; accounturi=https://ca.example/acct/1"`,
		`customer.example. CAA 0 issuewild ";"`,
		"share secret repo " + repoId.String() + " with the ordering desktops' users",
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
	// a domain that has its account: printed and refused, nothing filed
	existsDaemon := &testUrBridgeDaemon{}
	refusedDaemon := &testUrBridgeDaemon{}
	cli, out, _ = startTestUrSocketCli(t,
		existsDaemon.method(urMethodTlsAccountStatus, false, func(callCount int) (any, error) {
			return &urTlsAccountStatusReply{Accounts: []*urTlsAccountView{view}}, nil
		}),
		refusedDaemon.method(urMethodTlsAccountCreate, true, func(callCount int) (any, error) {
			return nil, errors.New("no create here")
		}),
	)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "create", "customer.example", "--agree-tos"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if calls, _ := refusedDaemon.calls(); len(calls) != 0 {
		t.Fatalf("a create for a domain that has an account")
	}
	if !strings.Contains(out.String(), "account   https://ca.example/acct/1") {
		t.Fatalf("the standing account not printed: %s", out.String())
	}
}

func TestUrTlsAccountRollSaysWhatItDid(t *testing.T) {
	for _, step := range []struct {
		reply *urTlsAccountRollReply
		code  int
		want  string
	}{
		{reply: &urTlsAccountRollReply{}, code: urExitOk, want: "no key change is due for customer.example"},
		{reply: &urTlsAccountRollReply{Due: true}, code: urExitFailed, want: "which this desktop may not make"},
		{reply: &urTlsAccountRollReply{Due: true, MayRoll: true, Rolled: true, Account: &urTlsAccountView{KeySeq: 3}}, code: urExitOk, want: "the account key of customer.example changed: key 3"},
	} {
		daemon := &testUrBridgeDaemon{}
		cli, out, _ := startTestUrSocketCli(t, daemon.method(urMethodTlsAccountRoll, true, func(callCount int) (any, error) {
			return step.reply, nil
		}))
		cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
		if code := cli.main(context.Background(), []string{"ur", "tls", "account", "roll", "customer.example"}); code != step.code {
			t.Fatalf("%+v: exit %d", step.reply, code)
		}
		if !strings.Contains(out.String(), step.want) {
			t.Fatalf("no %q in: %s", step.want, out.String())
		}
		if calls, confirmed := daemon.calls(); len(calls) != 1 || !confirmed[0] {
			t.Fatalf("the roll: %d, %v", len(calls), confirmed)
		}
	}
	// a no on the terminal files nothing
	daemon := &testUrBridgeDaemon{}
	cli, _, _ := startTestUrSocketCli(t, daemon.method(urMethodTlsAccountRoll, true, func(callCount int) (any, error) {
		return &urTlsAccountRollReply{}, nil
	}))
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "tls", "account", "roll", "customer.example"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if calls, _ := daemon.calls(); len(calls) != 0 {
		t.Fatalf("a roll after a no")
	}
}

// With no ACME directory configured, every account method refuses before it reaches a Sidecar, a CA or evs; create
// and roll are a person's, confirmed, and create refuses terms not agreed first.
func TestUrTlsAccountMethodsRefuseWithNoDirectory(t *testing.T) {
	if urDesktopTlsSettings().DirectoryUrl == "" {
		t.Fatal("the stock daemon needs its ACME directory")
	}
	methods := urTlsAccountMethods(&urDaemonNetwork{})
	if len(methods) != 3 {
		t.Fatalf("%d methods", len(methods))
	}
	for _, method := range methods {
		if !method.Network || method.Confirm != (method.Name != urMethodTlsAccountStatus) {
			t.Fatalf("%s: network %v, confirm %v", method.Name, method.Network, method.Confirm)
		}
		params := json.RawMessage(`{"domain":"customer.example","agree_tos":true}`)
		if _, err := method.Handler(context.Background(), &sidecar.DaemonCall{Params: params, Confirmed: true}); !errors.Is(err, errUrTlsNoDirectory) {
			t.Fatalf("%s: %v", method.Name, err)
		}
	}
	for _, method := range methods {
		if method.Name != urMethodTlsAccountCreate {
			continue
		}
		if _, err := method.Handler(context.Background(), &sidecar.DaemonCall{Params: json.RawMessage(`{"domain":"customer.example"}`), Confirmed: true}); !errors.Is(err, errUrTlsTermsNotAgreed) {
			t.Fatalf("terms not agreed: %v", err)
		}
	}
	if methods := urTlsAccountMethods(nil); methods != nil {
		t.Fatalf("methods on a target that hosts no Sidecar")
	}
}

func TestUrDesktopTlsReservesItsDaemonListeners(t *testing.T) {
	listeners := []sidecar.DaemonLocalListenerStatus{{Addresses: []string{"127.0.0.1:18001", "[::1]:18001", "[::1]:18002"}}}
	if got := urTlsDaemonPorts(listeners); !slices.Equal(got, []int{18001, 18002}) {
		t.Fatalf("reserved daemon ports: %v", got)
	}
}
