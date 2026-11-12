//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// §22.5's §16 row at the core: §5.8's `.ur` rules. The flat form and nothing else; the search from the hello's cwd
// up, stopping at the git top level or $HOME; a call's network by argument, `.ur` or the only network, else
// FAILED_PRECONDITION naming the networks; a legacy network_name never from `.ur` (D-DNS-2).

// Writes content at path, making its directories.
func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The form §5.8 writes, comments and all, and each way out of it refused with a line and nothing of the file.
func TestDotUrForm(t *testing.T) {
	project, err := ParseSidecarProject([]byte("# the billing project\n" +
		"network = \"K7q2m9\"        # a label or alias\r\n" +
		"\tagent = \"api-refactor\"\n" +
		"claims = \"off\"\n" +
		"project = \"billing-api\"\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if project.Network != "k7q2m9" || project.Agent != "api-refactor" || project.Claims != "off" || project.Project != "billing-api" {
		t.Fatalf("%+v", project)
	}
	if empty, err := ParseSidecarProject(nil); err != nil || *empty != (SidecarProject{}) {
		t.Fatalf("an empty .ur: %+v %v", empty, err)
	}
	refused := map[string]int{
		"network = 'k7q2m9'\n":                         1,
		"network = \"k7q2m9\" extra\n":                 1,
		"network = \"k7q2m9\"\nnetwork = \"m3n4p5\"\n": 2,
		"[network]\nname = \"k7q2m9\"\n":               1,
		"network.name = \"k7q2m9\"\n":                  1,
		"\"network\" = \"k7q2m9\"\n":                   1,
		"network = \"k7\\u0071\"\n":                    1,
		"network = \"\"\n":                             1,
		"network = \"two words\"\n":                    1,
		"network = \"k7q2m9\n":                         1,
		"network = 7\n":                                1,
		"network = [\"k7q2m9\"]\n":                     1,
		"secret = \"synthetic-canary-value\"\n":        1,
		"\nagent = \"-starts-with-a-dash\"\n":          2,
		"claims = \"everything\"\n":                    1,
		"network = \"k7q2m9\"\x00\n":                   1,
		"agent = \"a\x1bb\"\n":                         1,
	}
	for content, line := range refused {
		_, err := ParseSidecarProject([]byte(content))
		if !errors.Is(err, ErrSidecarProjectMalformed) || !strings.HasSuffix(err.Error(), ": line "+string(rune('0'+line))) {
			t.Errorf("%q: %v", content, err)
		}
		if err != nil && (strings.Contains(err.Error(), "k7q2m9") || strings.Contains(err.Error(), "canary")) {
			t.Errorf("a refusal repeats the file: %v", err)
		}
	}
	for _, content := range [][]byte{
		[]byte("\xef\xbb\xbfnetwork = \"k7q2m9\"\n"),
		[]byte("network = \"\xff\"\n"),
		[]byte(strings.Repeat("#", DefaultSidecarProjectSettings().MaxByteCount+1)),
	} {
		if _, err := ParseSidecarProject(content); !errors.Is(err, ErrSidecarProjectMalformed) {
			t.Errorf("%q: %v", content, err)
		}
	}
}

// `.ur` is looked for from the cwd up, the nearest first, and not past the git top level, nor past $HOME outside a
// repository.
func TestUrSearchStopsAtGitTopLevel(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".ur"), "network = \"homenet\"\n")
	if err := os.MkdirAll(filepath.Join(home, "repo", ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(home, "repo", "sub", "deeper")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if project, err := FindSidecarProject(deep, home); err != nil || project != nil {
		t.Fatalf("the search passed the git top level: %+v %v", project, err)
	}
	writeTestFile(t, filepath.Join(home, "repo", ".ur"), "network = \"reponet\"\n")
	if project, err := FindSidecarProject(deep, home); err != nil || project == nil || project.Network != "reponet" ||
		project.Directory != filepath.Join(home, "repo") {
		t.Fatalf("the top level's .ur: %+v %v", project, err)
	}
	writeTestFile(t, filepath.Join(home, "repo", "sub", ".ur"), "network = \"subnet\"\n")
	if project, err := FindSidecarProject(deep, home); err != nil || project == nil || project.Network != "subnet" {
		t.Fatalf("the nearest .ur: %+v %v", project, err)
	}

	// a linked work tree's .git is a file, and stops the search the same
	linked := filepath.Join(home, "linked", "inner")
	writeTestFile(t, filepath.Join(home, "linked", ".git"), "gitdir: elsewhere\n")
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if project, err := FindSidecarProject(linked, home); err != nil || project != nil {
		t.Fatalf("a linked work tree's top level: %+v %v", project, err)
	}

	// outside a repository the search reaches $HOME and stops there
	plain := filepath.Join(home, "plain", "dir")
	if err := os.MkdirAll(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if project, err := FindSidecarProject(plain, home); err != nil || project == nil || project.Network != "homenet" {
		t.Fatalf("$HOME's .ur: %+v %v", project, err)
	}
	above := filepath.Dir(home)
	if project, err := FindSidecarProject(plain, filepath.Join(home, "plain")); err != nil || project != nil {
		t.Fatalf("the search passed $HOME toward %s: %+v %v", above, project, err)
	}

	// a .ur that is not a regular file, or does not parse, is refused rather than skipped
	writeTestFile(t, filepath.Join(home, "broken", ".ur"), "network = 'single'\n")
	if _, err := FindSidecarProject(filepath.Join(home, "broken"), home); !errors.Is(err, ErrSidecarProjectMalformed) {
		t.Errorf("a malformed .ur: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "dirur", ".ur"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := FindSidecarProject(filepath.Join(home, "dirur"), home); !errors.Is(err, ErrSidecarProjectMalformed) {
		t.Errorf("a directory named .ur: %v", err)
	}
	if project, err := FindSidecarProject("relative/path", home); err != nil || project != nil {
		t.Errorf("a relative cwd: %+v %v", project, err)
	}
}

// A daemon hosting networks whose rows the label table holds, with a zero Sidecar standing for each, enough for
// resolution, which reads only which networks are hosted.
func newProjectTestDaemon(t *testing.T, home string, rows ...NetworkLabelRow) *Daemon {
	t.Helper()
	daemon := newDispatchTestDaemon(t)
	table, _ := testNetworkLabelTable(t, rows...)
	daemon.settings.Labels = table
	daemon.settings.LabelRoot = testLabelRoot
	daemon.settings.Home = home
	for _, row := range rows {
		if err := daemon.AddSidecar(row.NetworkId, &Sidecar{}); err != nil {
			t.Fatal(err)
		}
	}
	return daemon
}

// Several networks and none chosen: FAILED_PRECONDITION naming each by its label, and one named by argument or `.ur`
// passes.
func TestAmbiguousNetworkNamesNetworks(t *testing.T) {
	home := t.TempDir()
	first, second := NewId(), NewId()
	daemon := newProjectTestDaemon(t, home,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: first, Label: "k7q2m9"},
		NetworkLabelRow{Root: testLabelRoot, NetworkId: second, Label: "m3n4p5", Alias: "acme-team"},
	)
	hello := &DaemonHello{UrLocal: 1, Mode: DaemonModeMcp, Version: "synthetic-version", Cwd: filepath.Join(home, "work")}
	_, err := daemon.ResolveNetwork(hello, "")
	var networkErr *DaemonNetworkError
	if !errors.As(err, &networkErr) || networkErr.Reason != "ambiguous" || !strings.Contains(err.Error(), "k7q2m9") ||
		!strings.Contains(err.Error(), "m3n4p5") {
		t.Fatalf("no network chosen: %v", err)
	}

	ran := 0
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.scoped", Network: true, Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		ran += 1
		if call.Sidecar == nil {
			t.Error("no Sidecar handed over")
		}
		return call.NetworkId.String(), nil
	}}); err != nil {
		t.Fatal(err)
	}
	response := dispatchTest(daemon, DaemonModeMcp, `{"jsonrpc":"2.0","id":1,"method":"synthetic.scoped"}`)
	if response.Error == nil || response.Error.Code != DaemonRpcFailedPrecondition || !strings.Contains(response.Error.Message, "m3n4p5") || ran != 0 {
		t.Fatalf("an unscoped call: %+v, ran %d", response.Error, ran)
	}
	response = dispatchTest(daemon, DaemonModeMcp, `{"jsonrpc":"2.0","id":2,"method":"synthetic.scoped","params":{"network":"acme-team"}}`)
	if response.Error != nil || string(response.Result) != `"`+second.String()+`"` {
		t.Fatalf("an alias argument: %+v %s", response.Error, response.Result)
	}
	response = dispatchTest(daemon, DaemonModeMcp, `{"jsonrpc":"2.0","id":3,"method":"synthetic.scoped","params":{"network":"`+first.String()+`"}}`)
	if response.Error != nil || string(response.Result) != `"`+first.String()+`"` {
		t.Fatalf("an id argument: %+v %s", response.Error, response.Result)
	}
	response = dispatchTest(daemon, DaemonModeMcp, `{"jsonrpc":"2.0","id":4,"method":"synthetic.scoped","params":{"network":"synthetic-canary"}}`)
	if response.Error == nil || response.Error.Code != DaemonRpcFailedPrecondition || strings.Contains(response.Error.Message, "canary") {
		t.Fatalf("an unknown name: %+v", response.Error)
	}

	writeTestFile(t, filepath.Join(home, ".ur"), "network = \"m3n4p5\"\n")
	if networkId, err := daemon.ResolveNetwork(hello, ""); err != nil || networkId != second {
		t.Fatalf(".ur's network: %s %v", networkId, err)
	}
	// the argument wins over .ur
	if networkId, err := daemon.ResolveNetwork(hello, "k7q2m9"); err != nil || networkId != first {
		t.Fatalf("the argument: %s %v", networkId, err)
	}

	// the only network needs no name, and none hosted names the way to enroll
	single := newProjectTestDaemon(t, t.TempDir(), NetworkLabelRow{Root: testLabelRoot, NetworkId: first, Label: "k7q2m9"})
	if networkId, err := single.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp}, ""); err != nil || networkId != first {
		t.Fatalf("the only network: %s %v", networkId, err)
	}
	empty := newProjectTestDaemon(t, t.TempDir())
	if _, err := empty.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "none" {
		t.Fatalf("no network: %v", err)
	}
	// a .ur that does not parse refuses rather than falling to the only network
	broken := t.TempDir()
	writeTestFile(t, filepath.Join(broken, ".ur"), "network = k7q2m9\n")
	if _, err := single.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: broken}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "project" {
		t.Fatalf("a broken .ur: %v", err)
	}
}

// D-DNS-2: `.ur` names a label or alias, never a legacy network_name, which only a person's typed argument may match;
// a .ur naming it is refused, never resolved, and never falls through to the only network.
func TestLegacyNetworkNameRefused(t *testing.T) {
	home := t.TempDir()
	networkId := NewId()
	daemon := newProjectTestDaemon(t, home, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9", LegacyName: "acme"})
	writeTestFile(t, filepath.Join(home, ".ur"), "network = \"acme\"\n")
	hello := &DaemonHello{Mode: DaemonModeControl, Cwd: home}
	var networkErr *DaemonNetworkError
	if _, err := daemon.ResolveNetwork(hello, ""); !errors.As(err, &networkErr) || networkErr.Reason != "unknown" {
		t.Fatalf(".ur's legacy name: %v", err)
	}
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp}, "acme"); !errors.As(err, &networkErr) {
		t.Fatalf("an agent's legacy name: %v", err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "acme"); err != nil || resolved != networkId {
		t.Fatalf("a person's typed legacy name: %s %v", resolved, err)
	}
	writeTestFile(t, filepath.Join(home, ".ur"), "network = \"k7q2m9\"\n")
	if resolved, err := daemon.ResolveNetwork(hello, ""); err != nil || resolved != networkId {
		t.Fatalf(".ur's label: %s %v", resolved, err)
	}
}
