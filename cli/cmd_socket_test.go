package main

// ur socket (SOCK-M5-14) against an in-process daemon whose socket methods a test stands in for: a pending approval
// prints ur approve <id>; an address's <net> rides the call's network argument; ls prints unsealed names and says what
// it dropped; and ur socket dial with no --listen relays stdin and stdout for an ssh-like exchange, its stdin's end a
// FIN, while the real daemon's refusal reaches stderr and leaves stdout empty.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon whose method name answers with answer, recording each call's params.
type testUrSocketDaemon struct {
	stateLock sync.Mutex
	params    []json.RawMessage
}

func (self *testUrSocketDaemon) method(name string, answer func(params json.RawMessage) (any, error)) *sidecar.DaemonMethod {
	return &sidecar.DaemonMethod{
		Name: name,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.stateLock.Lock()
			self.params = append(self.params, call.Params)
			self.stateLock.Unlock()
			return answer(call.Params)
		},
	}
}

func (self *testUrSocketDaemon) lastParams(t *testing.T, params any) {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.params) == 0 {
		t.Fatal("no call")
	}
	if err := json.Unmarshal(self.params[len(self.params)-1], params); err != nil {
		t.Fatal(err)
	}
}

// Starts a daemon with methods registered, and a ur on it.
func startTestUrSocketCli(t *testing.T, methods ...*sidecar.DaemonMethod) (*urCli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	started := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range methods {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	return newTestUrCli(started.socketPath)
}

// An outward listen whose gate waits prints the approval's id, for ur approve <id>, and exits 1 having listened on
// nothing; an address's <net> rides the call's network argument.
func TestUrSocketListenPrintsApprovalId(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	approvalId := sidecar.NewId()
	cli, out, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodSocketListen, func(params json.RawMessage) (any, error) {
		return &sidecar.DaemonSocketListenReply{ApprovalId: &approvalId}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "socket", "listen", "acme:tls/443/blog", "127.0.0.1:8443"}); code != urExitFailed {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), "ur approve "+approvalId.String()) {
		t.Errorf("stdout %q", out.String())
	}
	params := &sidecar.DaemonSocketListenParams{}
	daemon.lastParams(t, params)
	if params.Network != "acme" || params.Address != "acme:tls/443/blog" || params.Target != "127.0.0.1:8443" {
		t.Errorf("params %+v", params)
	}
}

// A listen that holds prints its forward and how it ends; a dial forward on every interface warns it is LAN-exposed.
func TestUrSocketListenAndDialForwardPrint(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	cli, out, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodSocketListen, func(params json.RawMessage) (any, error) {
			return &sidecar.DaemonSocketListenReply{Status: &sidecar.DaemonSocketStatus{Kind: sidecar.DaemonSocketKindListen, Name: "db/primary", Target: "127.0.0.1:5432"}}, nil
		}),
		daemon.method(sidecar.DaemonMethodSocketDial, func(params json.RawMessage) (any, error) {
			return &sidecar.DaemonSocketStatus{Kind: sidecar.DaemonSocketKindDial, Name: "db/primary", LocalAddresses: []string{"[::]:15432"}, LanExposed: true, Serving: true}, nil
		}),
	)
	if code := cli.main(context.Background(), []string{"ur", "socket", "listen", "db/primary", "5432"}); code != urExitOk {
		t.Fatalf("listen exit %d", code)
	}
	if !strings.Contains(out.String(), "listen  db/primary to 127.0.0.1:5432 (not serving: the local target refuses)") {
		t.Errorf("listen printed %q", out.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "socket", "dial", "db/primary", "--listen=15432"}); code != urExitOk {
		t.Fatalf("dial exit %d", code)
	}
	if !strings.Contains(out.String(), "LAN-exposed") || !strings.Contains(out.String(), "warning: hosts on the LAN") {
		t.Errorf("dial printed %q", out.String())
	}
	params := &sidecar.DaemonSocketDialParams{}
	daemon.lastParams(t, params)
	if params.Listen != "15432" || params.Address != "db/primary" || params.Network != "" {
		t.Errorf("params %+v", params)
	}
}

// ur socket ls prints each unsealed name, marks this daemon's, and says what did not open and that a listing stopped
// short.
func TestUrSocketLsPrintsUnsealedNames(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	cli, out, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodSocketList, func(params json.RawMessage) (any, error) {
		return &sidecar.DaemonSocketListReply{
			Names:        []*sidecar.DaemonSocketName{{Name: "db/primary", Local: true}, {Name: "tls/443/blog"}},
			DroppedCount: 1,
			Error:        &sidecar.SocketError{Code: sidecar.SocketErrorCodeUnavailable},
		}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "socket", "ls", "acme"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	want := "db/primary  (this daemon listens)\ntls/443/blog\n1 sealed names did not open on this device and are not shown\n" +
		"warning: the listing is incomplete, a page was refused: unavailable\n"
	if out.String() != want {
		t.Errorf("stdout %q", out.String())
	}
	params := &sidecar.DaemonSocketListParams{}
	daemon.lastParams(t, params)
	if params.Network != "acme" {
		t.Errorf("params %+v", params)
	}
}

// Two ends of a loopback TCP connection, each with its halves, as a Unix socket session has.
func testUrSocketPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	near, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	far := <-accepted
	t.Cleanup(func() {
		near.Close()
		far.Close()
	})
	return near.(*net.TCPConn), far.(*net.TCPConn)
}

// ur socket dial with no --listen relays stdin and stdout for an ssh-like exchange: the client's banner and packets
// reach the far side, its answers reach stdout alone, stdin's end arrives as io.EOF, and the far side's last bytes
// and end finish the relay.
func TestUrSocketDialRelaysStdio(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent")
	near, far := testUrSocketPair(t)
	var hello *sidecar.DaemonHello
	cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
		hello = opened
		return near, func() { near.Close() }, nil
	}
	stdinReader, stdinWriter := io.Pipe()
	cli.stdin = stdinReader
	farDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(far)
		banner, err := reader.ReadString('\n')
		if err != nil || banner != "SSH-2.0-synthetic_client\r\n" {
			farDone <- err
			return
		}
		far.Write([]byte("SSH-2.0-synthetic_server\r\n\x00\x00\x00\x0cbinary\x01\x02"))
		rest, err := io.ReadAll(reader)
		if err != nil || string(rest) != "\x00\x01packet" {
			farDone <- err
			return
		}
		far.Write([]byte("goodbye"))
		far.Close()
		farDone <- nil
	}()
	go func() {
		stdinWriter.Write([]byte("SSH-2.0-synthetic_client\r\n"))
		stdinWriter.Write([]byte("\x00\x01packet"))
		stdinWriter.Close()
	}()
	if code := cli.main(context.Background(), []string{"ur", "socket", "dial", "acme:ssh/host"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if err := <-farDone; err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "SSH-2.0-synthetic_server\r\n\x00\x00\x00\x0cbinary\x01\x02goodbye" {
		t.Errorf("stdout %q", stdout.String())
	}
	if hello == nil || hello.Mode != sidecar.DaemonModeSocket || hello.Socket != "acme:ssh/host" || hello.SocketSidecarId != nil {
		t.Errorf("hello %+v", hello)
	}
}

// Through the real daemon's socket mode a dial it cannot make is its status line's refusal: stderr names it and stdout
// stays empty, as ssh must see nothing of ur's own.
func TestUrSocketDialRefusalReachesStderr(t *testing.T) {
	started := startTestUrDaemon(t, shortTestDirectory(t), nil)
	cli, stdout, stderr := newTestUrCli(started.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "socket", "dial", "db/primary"}); code != urExitFailed {
		t.Errorf("exit %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "ur socket:") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}
