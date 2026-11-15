package main

// The daemon's events method in ur (QD-821): ur daemon registers it over its daemon's ring, and ur native-host relays it
// to the extension, a method off its list still refused; a stream that ends while a call runs ends that call's session,
// which is what ends an events wait at the daemon. Ids are synthetic, and every wait is on a channel.

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A source the daemon's ring is attached to, raising what a test gives it as a hosted network's sidecar.
type testUrEventSource struct {
	callbacks *sidecar.CallbackList[sidecar.SidecarEventFunction]
	networkId sidecar.Id
	sidecarId sidecar.Id
}

func newTestUrEventSource() *testUrEventSource {
	return &testUrEventSource{
		callbacks: sidecar.NewCallbackList[sidecar.SidecarEventFunction](),
		networkId: sidecar.NewId(),
		sidecarId: sidecar.NewId(),
	}
}

func (self *testUrEventSource) AddEventCallback(callback sidecar.SidecarEventFunction) func() {
	callbackId := self.callbacks.Add(callback)
	return func() {
		self.callbacks.Remove(callbackId)
	}
}

func (self *testUrEventSource) NetworkId() *sidecar.Id {
	networkId := self.networkId
	return &networkId
}

func (self *testUrEventSource) Identity() *sidecar.SidecarIdentity {
	return &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: self.sidecarId, Generation: 1}
}

// Raises event to every callback, as a Sidecar does.
func (self *testUrEventSource) raise(event sidecar.SidecarEvent) {
	for _, callback := range self.callbacks.Get() {
		callback(event)
	}
}

// ur daemon's target registers events over its daemon's ring, a method that confirms nothing and names no network; a
// target with no daemon registers none.
func TestDaemonRegistersTheEventsMethod(t *testing.T) {
	started := startTestUrDaemon(t, shortTestDirectory(t), nil)
	methods := urDaemonMethods("default", &urDaemonNetwork{daemon: started.daemon}, osKeyStoreKeyFile, nil)
	index := slices.IndexFunc(methods, func(method *sidecar.DaemonMethod) bool { return method.Name == sidecar.DaemonMethodEvents })
	if index < 0 {
		t.Fatal("ur daemon registers no events method")
	}
	if methods[index].Confirm || methods[index].Network {
		t.Errorf("events: Confirm %t, Network %t", methods[index].Confirm, methods[index].Network)
	}
	if len(urDaemonEventsMethods(&urDaemonNetwork{})) != 0 || len(urDaemonEventsMethods(&testUrDaemonTarget{})) != 0 {
		t.Error("a target with no daemon registered events")
	}
	// the native host's list is status and events, each a method that signs nothing and carries no secret
	if !slices.Equal(nativeHostRelayedMethods, []string{urMethodStatus, sidecar.DaemonMethodEvents}) {
		t.Errorf("the native host relays %v", nativeHostRelayedMethods)
	}
}

// ur native-host relays events on its own list, past a cursor and from none, while a method off the list is refused
// at the relay and never reaches the daemon.
func TestNativeHostRelaysEvents(t *testing.T) {
	calls := &testNativeHostCalls{}
	target := &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 4}}
	var events *sidecar.DaemonEvents
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := registerUrDaemonMethods(daemon, "default", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
		events = daemon.Events()
		if err := daemon.RegisterMethod(sidecar.DaemonEventsMethod(events)); err != nil {
			t.Fatal(err)
		}
		for _, method := range testNativeHostSyntheticMethods(calls) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	source := newTestUrEventSource()
	events.Attach(source)
	// the cursor before the events, from a session of the test's own
	ctx, cancel := context.WithTimeout(context.Background(), urTestTimeout)
	defer cancel()
	client, err := sidecar.DialDaemon(ctx, daemon.socketPath, &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl, Version: sidecar.Version})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	start := &sidecar.DaemonEventsReply{}
	if err := client.Call(ctx, sidecar.DaemonMethodEvents, &sidecar.DaemonEventsParams{}, false, start); err != nil {
		t.Fatal(err)
	}
	approvalId := sidecar.NewId()
	source.raise(sidecar.SidecarEvent{Kind: sidecar.SidecarEventState, Generation: 4, State: sidecar.SidecarStateOnline})
	source.raise(sidecar.SidecarEvent{Kind: sidecar.SidecarEventApprovalPending, Generation: 4, ApprovalId: &approvalId})

	stdout, stderr, code := runTestNativeHost(t, daemon.socketPath, nil, []string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"events","params":{"after":"`+start.Cursor+`","wait_ms":0}}`,
		`{"jsonrpc":"2.0","id":2,"method":"events"}`,
		`{"jsonrpc":"2.0","id":3,"method":"synthetic.read"}`,
		`{"jsonrpc":"2.0","id":4,"method":"status"}`,
	)
	if code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	replies := testNativeHostReplies(t, stdout)
	if len(replies) != 4 {
		t.Fatalf("%d replies: %v", len(replies), replies)
	}
	past, _ := replies[0]["result"].(map[string]any)
	pastEvents, _ := past["events"].([]any)
	if past == nil || len(pastEvents) != 2 || past["cursor"] == start.Cursor || past["gap"] != nil {
		t.Fatalf("events past the cursor: %v", replies[0])
	}
	first, _ := pastEvents[0].(map[string]any)
	second, _ := pastEvents[1].(map[string]any)
	if first["kind"] != "state" || first["state"] != "online" || first["network_id"] != source.networkId.String() ||
		first["origin_sidecar_id"] != source.sidecarId.String() || second["kind"] != "approval_pending" ||
		second["approval_id"] != approvalId.String() {
		t.Errorf("the relayed events: %v, %v", first, second)
	}
	now, _ := replies[1]["result"].(map[string]any)
	if nowEvents, _ := now["events"].([]any); now == nil || len(nowEvents) != 0 || now["cursor"] != past["cursor"] {
		t.Errorf("events from no cursor: %v", replies[1])
	}
	if code, _ := testNativeHostError(replies[2]); code != -32601 {
		t.Errorf("a method off the list: %v", replies[2])
	}
	if status, _ := replies[3]["result"].(map[string]any); status == nil || status["state"] != "online" {
		t.Errorf("status beside events: %v", replies[3])
	}
	if methods, confirmed := calls.snapshot(); len(methods) != 0 || slices.Contains(confirmed, true) {
		t.Errorf("the daemon saw %v", methods)
	}
}

// A stream that ends while a long poll runs ends that call's daemon session, which the poll's wait ends on, and the
// native host exits writing nothing more. events is the long poll the list names.
func TestNativeHostEndsALongPollWithTheStream(t *testing.T) {
	if !slices.Equal(nativeHostLongPollMethods, []string{sidecar.DaemonMethodEvents}) {
		t.Fatalf("the long polls %v", nativeHostLongPollMethods)
	}
	entered, ended := make(chan struct{}), make(chan struct{})
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := daemon.RegisterMethod(&sidecar.DaemonMethod{Name: "synthetic.wait", Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			close(entered)
			select {
			case <-call.SessionDone:
				close(ended)
				return nil, errors.New("the session ended")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}); err != nil {
			t.Fatal(err)
		}
	})
	reader, writer := io.Pipe()
	defer writer.Close()
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	cli.nativeHostIds = func() (*nativeHostIds, error) { return testNativeHostIds(), nil }
	cli.stdin = reader
	savedRelayed, savedLongPolls := nativeHostRelayedMethods, nativeHostLongPollMethods
	nativeHostRelayedMethods, nativeHostLongPollMethods = []string{"synthetic.wait"}, []string{"synthetic.wait"}
	defer func() {
		nativeHostRelayedMethods, nativeHostLongPollMethods = savedRelayed, savedLongPolls
	}()
	exited := make(chan int, 1)
	go func() {
		exited <- cli.main(context.Background(), []string{"ur", "native-host", "chrome-extension://" + testNativeHostChromeId + "/"})
	}()
	if err := writeNativeHostFrame(writer, []byte(`{"jsonrpc":"2.0","id":1,"method":"synthetic.wait"}`)); err != nil {
		t.Fatal(err)
	}
	awaitTestUrChannel(t, entered, "the call reached the daemon")
	writer.Close()
	awaitTestUrChannel(t, ended, "the call's session ended")
	select {
	case code := <-exited:
		if code != urExitOk {
			t.Errorf("exit %d: %s", code, stderr)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the native host did not exit")
	}
	if stdout.Len() != 0 {
		t.Errorf("an answer nobody reads went to stdout: %q", stdout.Bytes())
	}
}

// Waits for done to close, failing as what once urTestTimeout passes.
func awaitTestUrChannel(t *testing.T, done chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(urTestTimeout):
		t.Fatalf("waited for %s", what)
	}
}
