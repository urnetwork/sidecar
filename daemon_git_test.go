//go:build !js && !ios && !android && !sdk_mobile_bind && !windows

package sidecar

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// §5.8's git mode: a hello naming any service but git-upload-pack or git-receive-pack is refused; <net> resolves by
// label or alias among the hosted networks; the raw bytes go to the git service and never to a control method.

// A git service that keeps what each session sent, until the client closes.
type testGitService struct {
	stateLock sync.Mutex
	sessions  []*DaemonGitSession
	received  []string
	done      chan struct{}
}

func newTestGitService() *testGitService {
	return &testGitService{done: make(chan struct{}, 8)}
}

func (self *testGitService) serve(ctx context.Context, session *DaemonGitSession) error {
	received, _ := io.ReadAll(session.Stream)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sessions = append(self.sessions, session)
		self.received = append(self.received, string(received))
	}()
	self.done <- struct{}{}
	return nil
}

// A daemon hosting one labelled network, with the git mode on service and one Confirm method that counts its runs.
func startGitTestDaemon(t *testing.T, service DaemonGitService) (*testDaemon, Id, *int) {
	t.Helper()
	networkId := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9", LegacyName: "acme"})
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Labels = table
		settings.LabelRoot = testLabelRoot
	})
	if err := started.daemon.AddSidecar(networkId, &Sidecar{}); err != nil {
		t.Fatal(err)
	}
	if err := started.daemon.RegisterMode(DaemonModeGit, NewDaemonGitMode(started.daemon, service)); err != nil {
		t.Fatal(err)
	}
	ran := new(int)
	for _, name := range []string{"synthetic.approve", "synthetic.read"} {
		if err := started.daemon.RegisterMethod(&DaemonMethod{Name: name, Confirm: name == "synthetic.approve", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			*ran += 1
			return "ran", nil
		}}); err != nil {
			t.Fatal(err)
		}
	}
	return started, networkId, ran
}

// A git session of repo and service.
func dialGitSession(t *testing.T, started *testDaemon, repo string, service string) (*DaemonClient, error) {
	t.Helper()
	return DialDaemon(context.Background(), started.socketPath, &DaemonHello{Mode: DaemonModeGit, Version: testDaemonVersion, Repo: repo, Service: service})
}

// The hello names one of git's two services, and nothing else gets a session or reaches the git service.
func TestGitHelloRefusesUnknownService(t *testing.T) {
	service := newTestGitService()
	started, _, _ := startGitTestDaemon(t, service.serve)
	for _, name := range []string{"git-upload-archive", "git-receive-pack ", "sh", ""} {
		_, err := dialGitSession(t, started, "k7q2m9/repo", name)
		var refusal *DaemonHelloRefusal
		if !errors.As(err, &refusal) || refusal.Code != DaemonHelloErrorMalformed {
			t.Errorf("service %q: %v", name, err)
		}
	}
	for _, name := range []string{daemonGitUploadPack, daemonGitReceivePack} {
		client, err := dialGitSession(t, started, "k7q2m9/repo", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		client.Close()
		<-service.done
	}
	service.stateLock.Lock()
	defer service.stateLock.Unlock()
	if len(service.sessions) != 2 || service.sessions[0].Service != daemonGitUploadPack || service.sessions[1].Service != daemonGitReceivePack ||
		service.sessions[0].Repo != "repo" || service.sessions[0].Sidecar == nil {
		t.Fatalf("sessions %+v", service.sessions)
	}
}

// D-CORE-9: the git mode selects a protocol and grants nothing. A JSON-RPC request sent down a git session is git
// bytes to the git service, and no control method, Confirm or not, runs or answers.
func TestGitModeGrantsNoControlMethod(t *testing.T) {
	service := newTestGitService()
	started, networkId, ran := startGitTestDaemon(t, service.serve)
	client, err := dialGitSession(t, started, "k7q2m9/repo", daemonGitReceivePack)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"synthetic.approve","ur_confirmed":true}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"synthetic.read"}` + "\n"
	if _, err := client.Stream().Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	client.conn.(interface{ CloseWrite() error }).CloseWrite()
	select {
	case <-service.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the git service did not end")
	}
	answer, _ := io.ReadAll(client.Stream())
	client.Close()
	if *ran != 0 || strings.Contains(string(answer), "jsonrpc") {
		t.Fatalf("a control method ran %d times, answer %q", *ran, answer)
	}
	service.stateLock.Lock()
	defer service.stateLock.Unlock()
	if len(service.received) != 1 || service.received[0] != request || service.sessions[0].NetworkId != networkId {
		t.Fatalf("the git service got %q", service.received)
	}
}

// Reads one pkt-line from the session.
func readGitPktLine(t *testing.T, client *DaemonClient) string {
	t.Helper()
	line, err := NewEvsPktLineReader(bufio.NewReader(client.Stream())).Next()
	if err != nil {
		t.Fatal(err)
	}
	return string(line.Payload)
}

// A <net> that is not a hosted network's label or alias, a legacy name included, and a daemon with no git service
// each answer git's ERR line, naming nothing the caller sent, and reach no service.
func TestGitSessionRefusals(t *testing.T) {
	service := newTestGitService()
	started, _, _ := startGitTestDaemon(t, service.serve)
	for _, repo := range []string{"acme/repo", "zz9zz9/repo", "synthetic-canary/repo"} {
		client, err := dialGitSession(t, started, repo, daemonGitUploadPack)
		if err != nil {
			t.Fatal(err)
		}
		line := readGitPktLine(t, client)
		client.Close()
		if !strings.HasPrefix(line, "ERR ur: ") || strings.Contains(line, "canary") || strings.Contains(line, "acme") {
			t.Errorf("%s: %q", repo, line)
		}
	}
	service.stateLock.Lock()
	served := len(service.sessions)
	service.stateLock.Unlock()
	if served != 0 {
		t.Errorf("%d refused sessions reached the service", served)
	}

	unserved, _, _ := startGitTestDaemon(t, nil)
	client, err := dialGitSession(t, unserved, "k7q2m9/repo", daemonGitUploadPack)
	if err != nil {
		t.Fatal(err)
	}
	if line := readGitPktLine(t, client); line != "ERR ur: git is not served by this daemon yet\n" {
		t.Errorf("no service: %q", line)
	}
	client.Close()
}
