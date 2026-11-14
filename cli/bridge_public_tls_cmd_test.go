// ur bridge public-tls's command lines, its approval wait and what it prints, on a daemon whose tls methods a test
// answers.

package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// <host>:[<local ip>:]<local port> and each flag.
func TestUrBridgePublicTlsParsesItsArgumentAndFlags(t *testing.T) {
	plain, err := parseUrBridgePublicTls("blog:8080", "", "", "", "", false, false)
	if err != nil || !reflect.DeepEqual(plain, &sidecar.DaemonTlsPublishParams{Host: "blog", Target: "8080"}) {
		t.Fatalf("the short form: %+v, %v", plain, err)
	}
	local, err := parseUrBridgePublicTls("@:192.0.2.7:3000", "8443", "36h", "public", "h2,http/1.1", false, true)
	if err != nil || !reflect.DeepEqual(local, &sidecar.DaemonTlsPublishParams{
		Host: "@", Port: 8443, Target: "192.0.2.7:3000", Audience: "public", Alpn: []string{"h2", "http/1.1"},
		ProxyProtocol: true, ExpiresMs: (36 * time.Hour).Milliseconds(),
	}) {
		t.Fatalf("a local ip and flags: %+v, %v", local, err)
	}
	raw, err := parseUrBridgePublicTls("db:[2001:db8::7]:5432", "5671", "", "link", "postgresql", true, false)
	if err != nil || raw.Host != "db" || raw.Target != "[2001:db8::7]:5432" || !raw.Tcp || raw.Port != 5671 || raw.Audience != "link" {
		t.Fatalf("an ipv6 local ip with --tcp: %+v, %v", raw, err)
	}
	for name, attempt := range map[string][5]string{
		"no port":             {"blog", "", "", "", ""},
		"no host":             {":8080", "", "", "", ""},
		"no target":           {"blog:", "", "", "", ""},
		"a local port's name": {"blog:http", "", "", "", ""},
		"local port zero":     {"blog:0", "", "", "", ""},
		"a local port past":   {"blog:70000", "", "", "", ""},
		"--port a name":       {"blog:8080", "https", "", "", ""},
		"--port zero":         {"blog:8080", "0", "", "", ""},
		"--expires a word":    {"blog:8080", "", "soon", "", ""},
		"--expires negative":  {"blog:8080", "", "-1h", "", ""},
		"--alpn empty id":     {"blog:8080", "", "", "", "h2,,http/1.1"},
	} {
		_, err := parseUrBridgePublicTls(attempt[0], attempt[1], attempt[2], attempt[3], attempt[4], false, false)
		exit, ok := err.(*urExitError)
		if !ok || exit.code != urExitUsage {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Without an active grant a publish prints the approval prompt once and waits, asking the daemon again, then prints
// §13.10 step 4's lines: the URL, the expiry, the audience and where the key is.
func TestUrBridgePublicTlsPrintsThePromptWaitsThenPublishes(t *testing.T) {
	waits := setTestUrBridgeWait(t, &urBridgeSettings{ApprovalPollInterval: time.Second, ApprovalWaitTimeout: time.Minute})
	daemon := &testUrBridgeDaemon{}
	approvalId := sidecar.NewId()
	expires := time.Date(2026, time.March, 5, 5, 6, 7, 0, time.UTC)
	cli, out, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodTlsPublish, false, func(callCount int) (any, error) {
		if callCount < 3 {
			return &sidecar.DaemonTlsPublishReply{ApprovalId: &approvalId}, nil
		}
		return &sidecar.DaemonTlsPublishReply{Publish: &sidecar.DaemonTlsPublishStatus{
			Name: "tls/443/blog", Url: "https://blog.abcdefghij.sidecar.example", ServerNames: []string{"blog.abcdefghij.sidecar.example"},
			GrantId: "0a0b", ExpiresMs: expires.UnixMilli(), Audience: "members", AppMode: "http",
			Passthrough: sidecar.TlsPublishPassthrough, Serving: true,
		}}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "blog:8080", "--expires=24h", "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	printed := out.String()
	if strings.Count(printed, "approval pending: run ur approve "+approvalId.String()) != 1 {
		t.Fatalf("the prompt, once: %s", printed)
	}
	if *waits != 2 {
		t.Fatalf("%d waits", *waits)
	}
	for _, want := range []string{
		"published  https://blog.abcdefghij.sidecar.example", "expires    2026-03-05T05:06:07Z", "audience   members",
		"passthrough: key on this device", "ur bridge public-tls --stop blog",
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
	if strings.Contains(printed, "warning") || strings.Contains(printed, "client certificate") {
		t.Fatalf("a serving http publish printed: %s", printed)
	}
	calls, confirmed := daemon.calls()
	if len(calls) != 3 || confirmed[0] {
		t.Fatalf("%d calls, confirmed %v", len(calls), confirmed)
	}
	params := &sidecar.DaemonTlsPublishParams{}
	if err := json.Unmarshal(calls[2], params); err != nil || params.Network != "acme" || params.Host != "blog" || params.Target != "8080" || params.ExpiresMs != (24*time.Hour).Milliseconds() {
		t.Fatalf("the params: %+v, %v", params, err)
	}
}

// A raw link prints the client-certificate file's path; a target that does not answer yet prints the warning; an
// approval still pending when the wait runs out exits 1, naming it.
func TestUrBridgePublicTlsRawLinkAndTheWaitRunningOut(t *testing.T) {
	waits := setTestUrBridgeWait(t, &urBridgeSettings{ApprovalPollInterval: time.Second, ApprovalWaitTimeout: 3 * time.Second})
	daemon := &testUrBridgeDaemon{}
	approvalId := sidecar.NewId()
	pending := false
	cli, out, stderr := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodTlsPublish, false, func(callCount int) (any, error) {
		if pending {
			return &sidecar.DaemonTlsPublishReply{ApprovalId: &approvalId}, nil
		}
		return &sidecar.DaemonTlsPublishReply{Publish: &sidecar.DaemonTlsPublishStatus{
			Name: "tls/5671/db", Url: "db.abcdefghij.sidecar.example:5671", Audience: "link", AppMode: "raw",
			Passthrough: sidecar.TlsPublishPassthrough, ClientCertificateFile: "/synthetic/link-5671-db.pem",
		}}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "db:5432", "--port=5671", "--tcp", "--audience=link", "--alpn=postgresql", "--proxy-protocol"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	printed := out.String()
	for _, want := range []string{"client certificate and key  /synthetic/link-5671-db.pem", "audience   link", "expires    with its standing grant", "warning: nothing answers on the local port yet"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
	calls, _ := daemon.calls()
	params := &sidecar.DaemonTlsPublishParams{}
	if err := json.Unmarshal(calls[0], params); err != nil || !params.Tcp || !params.ProxyProtocol || params.Port != 5671 || params.Audience != "link" || !reflect.DeepEqual(params.Alpn, []string{"postgresql"}) {
		t.Fatalf("the params: %+v, %v", params, err)
	}
	pending = true
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "db:5432"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "approval "+approvalId.String()+" is still pending") || strings.Contains(out.String(), "published") {
		t.Fatalf("stdout %q, stderr %q", out.String(), stderr.String())
	}
	if *waits != 3 {
		t.Fatalf("%d waits", *waits)
	}
}

// --stop ends the publish unconfirmed, the subject's own filing, and exits 1 for a name this device does not publish;
// --status lists the publishes, the certificates and a degraded CT watch.
func TestUrBridgePublicTlsStopAndStatus(t *testing.T) {
	daemon := &testUrBridgeDaemon{}
	certId := sidecar.NewId()
	notAfter := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	cli, out, stderr := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodTlsUnpublish, false, func(callCount int) (any, error) {
			return &sidecar.DaemonTlsUnpublishReply{Unpublished: callCount == 1}, nil
		}),
		daemon.method(sidecar.DaemonMethodTlsStatus, false, func(callCount int) (any, error) {
			return &sidecar.DaemonTlsStatusReply{
				Publishes: []*sidecar.DaemonTlsPublishStatus{{
					Name: "tls/443/blog", Url: "https://blog.abcdefghij.sidecar.example", Audience: "public", Passthrough: sidecar.TlsPublishPassthrough, Serving: true,
				}},
				Certificates:    []*sidecar.DaemonTlsCertificateStatus{{CertId: certId, State: "issued", NotAfterMs: notAfter.UnixMilli(), Presented: true}},
				CtWatchDegraded: true,
			}, nil
		}))
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "--stop", "blog", "--port=8443", "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "unpublished  blog") {
		t.Fatalf("stdout %q", out.String())
	}
	calls, confirmed := daemon.calls()
	params := &sidecar.DaemonTlsUnpublishParams{}
	if err := json.Unmarshal(calls[0], params); err != nil || confirmed[0] || params.Host != "blog" || params.Port != 8443 || params.Network != "acme" {
		t.Fatalf("the params: %+v, confirmed %v, %v", params, confirmed, err)
	}
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "--stop", "blog"}); code != urExitFailed || !strings.Contains(stderr.String(), "does not publish blog") {
		t.Fatalf("a second stop: exit %d, stderr %q", code, stderr.String())
	}
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "public-tls", "--status"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	printed := out.String()
	for _, want := range []string{"published  https://blog.abcdefghij.sidecar.example", "audience   public", "certificate  " + certId.String() + "  network  issued until 2026-06-01T00:00:00Z, presented", "CT watch degraded"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
}
