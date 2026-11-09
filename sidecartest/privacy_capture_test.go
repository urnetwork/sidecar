package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sidecar"
)

// A toy HttpEngine with a server's honest shape: it stores what it is given under an opaque id, logs
// the id, and counts by a fixed label. leak names where a bug puts the body instead.
type toyPrivacyEngine struct {
	host *sidecar.ServiceHost
	log  sidecar.Logger
	leak PrivacyClass
}

func (self *toyPrivacyEngine) Ready() bool {
	return true
}

func (self *toyPrivacyEngine) Drain() {
}

func (self *toyPrivacyEngine) Close() {
}

func (self *toyPrivacyEngine) Handler() http.Handler {
	counter := self.host.Metrics.Counter("urnetwork_toy_puts_total", "puts", "result")
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		objectId := request.URL.Query().Get("id")
		cluster, err := self.host.Blobs.FirstCluster()
		if err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if _, err := cluster.PutIfNoneMatch(request.Context(), "toy/"+objectId, body, nil); err != nil {
			writer.WriteHeader(http.StatusConflict)
			return
		}
		self.log.Infof("[toy]stored %s", objectId)
		counter.Add(1, "ok")
		switch self.leak {
		case PrivacyClassHandler:
			// the response echoes what it stored, which a client may then log or cache
			writer.Header().Set("X-Toy-Echo", string(body))
		case PrivacyClassLog:
			self.log.Infof("[toy]stored %s: %s", objectId, body)
		case PrivacyClassMetric:
			self.host.Metrics.Counter("urnetwork_toy_bodies_total", "bodies", "body").Add(1, string(body))
		case PrivacyClassRedis:
			self.host.Redis.Set(request.Context(), "{toy}last", body, 0)
		}
		writer.WriteHeader(http.StatusOK)
	})
}

func addToyPrivacyEngine(t *testing.T, net *Net, leak PrivacyClass) {
	t.Helper()
	if _, err := net.AddEngine("evs1", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return &toyPrivacyEngine{host: host, log: net.Capture().Logger("evs1"), leak: leak}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// What a sidecar uploads: sealed under a key it holds and the server never sees.
func toyPrivacySeal(t *testing.T, key []byte, plaintext []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}

func toyPut(ctx context.Context, net *Net, objectId string, body []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://evs1.example/toy/put?id="+objectId, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	response, err := net.EngineClient("evs1").Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response, fmt.Errorf("put %s: %d", objectId, response.StatusCode)
	}
	return response, nil
}

// Two sidecars exchange a message carrying a canary over Net, and one stores a sealed file with an
// engine: every class the harness captures through had something to read, and none holds a canary or
// the key.
func TestTwoSidecarsExchangingCanariesScanClean(t *testing.T) {
	net := newTestNet(t)
	capture := net.Capture()
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := net.AddSidecar("phone", nil)
	if err != nil {
		t.Fatal(err)
	}
	messages := make(chan *NetMessage, 16)
	defer phone.Client().ReceiveMessages(messages)()

	canary := capture.CanaryText("message body")
	if err := laptop.Client().SendMessage(phone.Client().ClientId, canary); err != nil {
		t.Fatal(err)
	}
	if message := awaitMessage(t, messages); message.Content != canary {
		t.Fatalf("message %+v", message)
	}

	addToyPrivacyEngine(t, net, "")
	key := []byte("synthetic-repo-key-for-this-test")
	capture.AddSecret("K_repo", key)
	contents := capture.Canary("file contents")
	if _, err := toyPut(t.Context(), net, "01JTOYOBJECT", toyPrivacySeal(t, key, contents)); err != nil {
		t.Fatal(err)
	}

	for _, class := range []PrivacyClass{PrivacyClassHandler, PrivacyClassFrame, PrivacyClassObject, PrivacyClassLog, PrivacyClassMetric, PrivacyClassEnv} {
		if capture.ItemCount(class) == 0 {
			t.Errorf("the capture holds no %s, so a clean scan proves nothing there", class)
		}
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("%v", findings)
	}
	if len(capture.FrameSizes(laptop.Client().ClientId, phone.Client().ClientId)) == 0 || len(capture.FrameSizes(phone.Client().ClientId, laptop.Client().ClientId)) == 0 {
		t.Error("no frame sizes for the pair")
	}
}

// A leak through each capture point, in turn, is found and named by its class.
func TestEachCaptureClassNamesItsLeak(t *testing.T) {
	leaks := map[PrivacyClass]func(t *testing.T, net *Net, canary string){
		PrivacyClassHandler: func(t *testing.T, net *Net, canary string) {
			addToyPrivacyEngine(t, net, PrivacyClassHandler)
			toyPutOrFail(t, net, canary)
		},
		PrivacyClassLog: func(t *testing.T, net *Net, canary string) {
			addToyPrivacyEngine(t, net, PrivacyClassLog)
			toyPutOrFail(t, net, canary)
		},
		PrivacyClassMetric: func(t *testing.T, net *Net, canary string) {
			addToyPrivacyEngine(t, net, PrivacyClassMetric)
			toyPutOrFail(t, net, canary)
		},
		PrivacyClassRedis: func(t *testing.T, net *Net, canary string) {
			addToyPrivacyEngine(t, net, PrivacyClassRedis)
			toyPutOrFail(t, net, canary)
		},
		PrivacyClassObject: func(t *testing.T, net *Net, canary string) {
			addToyPrivacyEngine(t, net, "")
			toyPutOrFail(t, net, canary)
		},
		PrivacyClassEnv: func(t *testing.T, net *Net, canary string) {
			t.Setenv("TOY_PRIVACY_LEAK", canary)
		},
		PrivacyClassFrame: func(t *testing.T, net *Net, canary string) {
			net.Capture().AddFrame(connect.NewId(), connect.NewId(), plaintextFrame(t, connect.NewId(), canary))
		},
		PrivacyClassHook: func(t *testing.T, net *Net, canary string) {
			fmt.Fprintf(net.Capture().Writer(PrivacyClassHook, "ur hook post-tool"), `{"tool_output":%q}`+"\n", canary)
		},
		PrivacyClassMcp: func(t *testing.T, net *Net, canary string) {
			fmt.Fprintf(net.Capture().Writer(PrivacyClassMcp, "mcp stdout"), `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":%q}]}}`+"\n", canary)
		},
		PrivacyClassHint: func(t *testing.T, net *Net, canary string) {
			net.Host().Push.Hint(t.Context(), []connect.Id{connect.NewId()}, &sidecar.ClientHint{Topic: "core", Body: []byte(canary)})
		},
		PrivacyClassUsage: func(t *testing.T, net *Net, canary string) {
			net.Host().Quota.ReportUsage(t.Context(), &sidecar.UsageBatch{BatchId: connect.NewId(), Producer: "evs", Events: []*sidecar.UsageEvent{{NetworkId: connect.NewId(), Meter: canary}}})
		},
		PrivacyClassTask: func(t *testing.T, net *Net, canary string) {
			net.Host().Tasks.Schedule(t.Context(), &sidecar.TaskRequest{Name: "job", OnceKey: canary})
		},
	}
	for _, class := range PrivacyClasses() {
		if _, ok := leaks[class]; !ok && class != PrivacyClassMx4Input {
			t.Errorf("no leak here for %s", class)
		}
	}
	for class, leak := range leaks {
		func() {
			// one open at a time: under sidecar_testhooks a Net holds the process's hooks
			net := NewNet(t.Context(), nil)
			defer net.Close()
			canary := net.Capture().CanaryText("leaked field")
			leak(t, net, canary)
			found := false
			for _, finding := range net.Capture().Scan() {
				found = found || (finding.Needle == "leaked field" && finding.Class == class)
			}
			if !found {
				t.Errorf("%s: the leak was not named: %v", class, net.Capture().Scan())
			}
		}()
	}
}

func toyPutOrFail(t *testing.T, net *Net, body string) {
	t.Helper()
	if _, err := toyPut(t.Context(), net, "01JTOYLEAK", []byte(body)); err != nil {
		t.Fatal(err)
	}
}

// A data frame in the clear, as a client that skipped its seal would send.
func plaintextFrame(t *testing.T, destinationId connect.Id, content string) []byte {
	t.Helper()
	frame, err := connect.ToFrame(&protocol.SimpleMessage{Content: content}, connect.DefaultProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	transferFrame, err := proto.Marshal(&protocol.TransferFrame{
		TransferPath: &protocol.TransferPath{DestinationId: destinationId.Bytes()},
		Pack:         &protocol.Pack{MessageId: connect.NewId().Bytes(), SequenceId: connect.NewId().Bytes(), Frames: []*protocol.Frame{frame}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return transferFrame
}

// CC2's rule, frame by frame: to a peer, only a seal, an ack or the handshake's carrier; to the
// platform, anything.
func TestCc2FailsAPlaintextFrameAndPassesControl(t *testing.T) {
	peerId := connect.NewId()
	marshal := func(transferFrame *protocol.TransferFrame) []byte {
		data, err := proto.Marshal(transferFrame)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	path := &protocol.TransferPath{DestinationId: peerId.Bytes()}
	handshake := &protocol.Frame{MessageType: protocol.MessageType_TransferEncryptedControl, MessageBytes: []byte{1, 2, 3}}
	for _, planted := range []struct {
		destination connect.Id
		frame       []byte
		want        string
	}{
		{destination: peerId, frame: plaintextFrame(t, peerId, "hello"), want: "a plaintext pack holding a TestSimpleMessage frame"},
		{destination: connect.ControlId, frame: plaintextFrame(t, connect.ControlId, "hello"), want: ""},
		{destination: peerId, frame: marshal(&protocol.TransferFrame{TransferPath: path, EncryptedTransferFrame: []byte("sealed bytes")}), want: ""},
		{destination: peerId, frame: marshal(&protocol.TransferFrame{TransferPath: path, EncryptedTransferFrame: []byte("sealed bytes"), Pack: &protocol.Pack{}}), want: "plaintext beside its seal"},
		{destination: peerId, frame: marshal(&protocol.TransferFrame{TransferPath: path, Ack: &protocol.Ack{MessageId: connect.NewId().Bytes()}}), want: ""},
		{destination: peerId, frame: marshal(&protocol.TransferFrame{TransferPath: path, Pack: &protocol.Pack{Frames: []*protocol.Frame{handshake}}}), want: ""},
		{destination: peerId, frame: []byte("\xff\xff not a frame"), want: "does not parse"},
	} {
		capture := NewPrivacyCapture()
		capture.AddFrame(connect.NewId(), planted.destination, planted.frame)
		findings := capture.Scan()
		switch {
		case planted.want == "" && len(findings) != 0:
			t.Errorf("a passing frame: %v", findings)
		case planted.want != "" && (len(findings) != 1 || findings[0].NeedleKind != "unsealed frame" || !strings.Contains(findings[0].Form, planted.want)):
			t.Errorf("want %q: %v", planted.want, findings)
		}
	}
}

// Each actor's requests, in order, with what a server learns of their shape and nothing a run draws
// fresh: two equal runs give equal logs, and actors stay apart.
func TestRequestLogIsIdenticalAcrossTwoEqualRuns(t *testing.T) {
	run := func() (daemonA []string, daemonB []string) {
		net := NewNet(t.Context(), nil)
		defer net.Close()
		addToyPrivacyEngine(t, net, "")
		key := []byte("synthetic-repo-key-for-this-test")
		for _, step := range []struct {
			actor    string
			objectId string
		}{
			{actor: "daemonA", objectId: "01JTOYA1"},
			{actor: "daemonB", objectId: "01JTOYB1"},
			{actor: "daemonA", objectId: "01JTOYA2"},
		} {
			actor := net.Actors().Actor(net.Context(), step.actor)
			// a fresh nonce each run, so the bodies differ and only their shape is logged
			if _, err := toyPut(actor.Context(), net, step.objectId, toyPrivacySeal(t, key, []byte("contents"))); err != nil {
				t.Fatal(err)
			}
		}
		return net.Capture().RequestLog("daemonA"), net.Capture().RequestLog("daemonB")
	}
	firstA, firstB := run()
	secondA, secondB := run()
	want := []string{"evs1 POST /toy/put?id=01JTOYA1 48", "evs1 POST /toy/put?id=01JTOYA2 48"}
	if !slices.Equal(firstA, want) || !slices.Equal(firstA, secondA) || !slices.Equal(firstB, secondB) || len(firstB) != 1 {
		t.Errorf("%q %q\n%q %q", firstA, secondA, firstB, secondB)
	}
}

// A listener made of pipes, so a stream engine's connections stay in process.
type pipeListener struct {
	stateLock sync.Mutex
	conns     chan net.Conn
	closed    bool
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 4)}
}

func (self *pipeListener) Dial() net.Conn {
	client, server := net.Pipe()
	self.conns <- server
	return client
}

func (self *pipeListener) Accept() (net.Conn, error) {
	conn, ok := <-self.conns
	if !ok {
		return nil, errors.New("closed")
	}
	return conn, nil
}

func (self *pipeListener) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.closed {
		self.closed = true
		close(self.conns)
	}
	return nil
}

func (self *pipeListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "pipe", Net: "unix"}
}

// A stream engine's connections, both ways: what it reads under the class given, what it writes as a
// handler's; mx-4's listener input is never scanned, and what the edge writes back still is.
func TestAStreamEnginesConnectionsAreCaptured(t *testing.T) {
	for _, inputClass := range []PrivacyClass{PrivacyClassHandler, PrivacyClassMx4Input} {
		capture := NewPrivacyCapture()
		report := capture.CanaryText("report body")
		pipes := newPipeListener()
		listener := capture.WrapListener("mxedge", pipes, inputClass)
		served := make(chan struct{})
		go func() {
			defer close(served)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			line := make([]byte, len(report))
			io.ReadFull(conn, line)
			conn.Write([]byte("250 ok\r\n"))
			conn.Close()
		}()
		client := pipes.Dial()
		client.Write([]byte(report))
		reply := make([]byte, 8)
		io.ReadFull(client, reply)
		client.Close()
		<-served
		pipes.Close()
		findings := capture.Scan()
		if inputClass == PrivacyClassMx4Input && len(findings) != 0 {
			t.Errorf("mx-4's input was scanned: %v", findings)
		}
		if inputClass == PrivacyClassHandler && (len(findings) != 1 || findings[0].Source != "mxedge input") {
			t.Errorf("%v", findings)
		}
		if capture.ItemCount(PrivacyClassHandler) == 0 || string(reply) != "250 ok\r\n" {
			t.Errorf("the edge's output was not captured or not passed on: %q", reply)
		}
	}
}

// An area's class registers once, and only as a capture point and path.
func TestAnAreasClassRegistersOnce(t *testing.T) {
	registry := &privacyClassRegistry{}
	if err := registry.register("CC4/toy-edge-record"); err != nil {
		t.Fatal(err)
	}
	if classes := registry.classes(); !slices.Contains(classes, "CC4/toy-edge-record") || !slices.Contains(classes, PrivacyClassLog) {
		t.Errorf("%v", classes)
	}
	for _, planted := range []PrivacyClass{"CC4/toy-edge-record", "CC4", "CC9/elsewhere", PrivacyClassLog} {
		if err := registry.register(planted); err == nil {
			t.Errorf("%q registered", planted)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("RegisterPrivacyClass of a built-in class passed")
			}
		}()
		RegisterPrivacyClass(PrivacyClassLog)
	}()
}
