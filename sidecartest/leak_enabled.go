//go:build sidecar_leaktest

// §22.7's self-test: "a sidecar_leaktest build leaks into each class, which must catch it". Each capture
// class has a leak here that puts a value through the path a real bug would take: an engine's handler,
// the exchange's routing of a frame in the clear, a store write, a logger an engine holds, a metric
// label, a hint, the process environment, an MCP server's output and a hook's payload. None goes through
// PrivacyCapture.Add, which would test nothing. An area adds its class's leak beside its capture with
// RegisterLeak, in a sidecar_leaktest file of its own, and TestEveryClassCatchesItsLeak fails a class
// with none, so a class cannot arrive untested.
//
// This file links only under the tag, which check/ fails on any release leg, and reaches no engine:
// its handler is a toy of its own.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sidecar"
)

// Whether this build links the leaks.
const LeaksLinked = true

var (
	leakLock    sync.Mutex
	leakClasses = map[PrivacyClass]*Leak{}
)

// Adds a class's leak. Two for one class panic.
func RegisterLeak(leak *Leak) *Leak {
	leakLock.Lock()
	defer leakLock.Unlock()
	if _, ok := leakClasses[leak.Class]; ok {
		panic(fmt.Sprintf("a second leak for %s", leak.Class))
	}
	leakClasses[leak.Class] = leak
	return leak
}

// Every leak this build links, by class.
func LeakClasses() map[PrivacyClass]*Leak {
	leakLock.Lock()
	defer leakLock.Unlock()
	classes := map[PrivacyClass]*Leak{}
	for class, leak := range leakClasses {
		classes[class] = leak
	}
	return classes
}

// An engine whose bug is to answer with what it was given: CC1's leak through a handler.
type leakEchoEngine struct{}

func (self *leakEchoEngine) Ready() bool {
	return true
}

func (self *leakEchoEngine) Drain() {
}

func (self *leakEchoEngine) Close() {
}

func (self *leakEchoEngine) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})
}

// The leak engine's instance name.
const leakEngineInstance = "leak1"

var _ = RegisterLeak(&Leak{Class: PrivacyClassHandler, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	if _, err := net.AddEngine(leakEngineInstance, func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return &leakEchoEngine{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://leak1.example/echo", bytes.NewReader(value))
	if err != nil {
		t.Fatal(err)
	}
	response, err := net.EngineClient(leakEngineInstance).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}})

// mxedge's report listener input: the leak arrives, and the scan must not count it (§2.8's mx-4).
var _ = RegisterLeak(&Leak{Class: PrivacyClassMx4Input, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	listener := newLeakPipeListener()
	wrapped := net.Capture().WrapListener("mxedge rpt", listener, PrivacyClassMx4Input)
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := wrapped.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, conn)
		conn.Close()
	}()
	client := listener.dial()
	client.Write(value)
	client.Close()
	<-served
}})

// A frame in the clear through the exchange's routing, as a client that skipped its seal would send.
var _ = RegisterLeak(&Leak{Class: PrivacyClassFrame, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	source := net.AddClient("leaky", nil)
	frame, err := leakPlaintextFrame(connect.NewId(), value)
	if err != nil {
		t.Fatal(err)
	}
	pooled := connect.MessagePoolGet(len(frame))
	copy(pooled, frame)
	net.exchange.forward(source, pooled)
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassObject, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(t.Context(), "head/leak/_", value, nil); err != nil {
		t.Fatal(err)
	}
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassRedis, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	if err := net.Host().Redis.Set(t.Context(), "{leak}k", value, 0); err != nil {
		t.Fatal(err)
	}
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassUsage, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	batch := &sidecar.UsageBatch{BatchId: connect.NewId(), Producer: "evs", Events: []*sidecar.UsageEvent{{NetworkId: connect.NewId(), Meter: string(value)}}}
	// api refuses a meter it does not know only once it has read the batch, and the read is the leak
	net.Host().Quota.ReportUsage(t.Context(), batch)
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassTask, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	if err := net.Host().Tasks.Schedule(t.Context(), &sidecar.TaskRequest{Name: "leak", OnceKey: "leak", Args: value}); err != nil {
		t.Fatal(err)
	}
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassLog, Binary: true, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	log := net.Capture().Logger("evs1")
	if log.V(2).Enabled() {
		log.Infof("[evs]push %s", value)
	}
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassMetric, Binary: false, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	net.Host().Metrics.Counter("urnetwork_leak_total", "leaks", "path").Add(1, string(value))
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassHint, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	if err := net.Host().Push.Hint(t.Context(), []connect.Id{connect.NewId()}, &sidecar.ClientHint{Topic: "core", Body: value}); err != nil {
		t.Fatal(err)
	}
}})

// What a sidecar hands a child process: text.
var _ = RegisterLeak(&Leak{Class: PrivacyClassEnv, Binary: false, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	t.Setenv("UR_LEAK_VALUE", string(value))
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassHook, Binary: true, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	net.Capture().Writer(PrivacyClassHook, "ur hook post-tool").Write(slices.Concat([]byte(`{"tool_output":"`), value, []byte("\"}\n")))
}})

var _ = RegisterLeak(&Leak{Class: PrivacyClassMcp, Binary: true, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	net.Capture().Writer(PrivacyClassMcp, "mcp stdout").Write(slices.Concat([]byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"`), value, []byte("\"}]}}\n")))
}})

// A frame in the clear to destinationId: a pack holding value as an application frame's bytes.
func leakPlaintextFrame(destinationId connect.Id, value []byte) ([]byte, error) {
	return proto.Marshal(&protocol.TransferFrame{
		TransferPath: &protocol.TransferPath{DestinationId: destinationId.Bytes()},
		Pack: &protocol.Pack{
			MessageId:  connect.NewId().Bytes(),
			SequenceId: connect.NewId().Bytes(),
			Frames:     []*protocol.Frame{{MessageType: protocol.MessageType_TestSimpleMessage, MessageBytes: value}},
		},
	})
}

// A listener made of pipes, so the mx-4 leak's connection stays in process.
type leakPipeListener struct {
	conns     chan net.Conn
	closeOnce sync.Once
}

func newLeakPipeListener() *leakPipeListener {
	return &leakPipeListener{conns: make(chan net.Conn, 1)}
}

func (self *leakPipeListener) dial() net.Conn {
	client, server := net.Pipe()
	self.conns <- server
	return client
}

func (self *leakPipeListener) Accept() (net.Conn, error) {
	conn, ok := <-self.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (self *leakPipeListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.conns)
	})
	return nil
}

func (self *leakPipeListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "leak", Net: "unix"}
}
