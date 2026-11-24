package computeservice

// Streams and the tunnel (CSRV-M12-01, §14.2's Host row, §6.6): an SSE comment after each 15 s of silence on a fake
// clock, a stream that outlives the status server's read and write bounds, the tunnel's hijack through the guard's
// writer, and Drain ending what is still open at its bound.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Returns once a timer at at is pending on clock, with no sleep: a goroutine has reached its wait.
func awaitComputeTimerAt(t testing.TB, ctx context.Context, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingAt time.Time) bool { return pendingAt.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("no timer at %v: %v", at, ctx.Err())
		}
	}
}

// A POST to the stream route through server with the fixture's token, its response open.
func openComputeStream(t testing.TB, fixture *computeFixture, server *httptest.Server, path string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(fixture.ctx, http.MethodPost, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fixture.token())
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != computeContentTypeEventStream ||
		response.Header.Get("X-Accel-Buffering") != "no" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("the stream answered %d %v %s", response.StatusCode, response.Header, body)
	}
	return response
}

// Reads one SSE block, the lines up to the blank line that ends it.
func readComputeStreamBlock(t testing.TB, reader *bufio.Reader) string {
	t.Helper()
	block := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("the stream ended after %q: %v", block, err)
		}
		if line == "\n" {
			return block
		}
		block += line
	}
}

// A stream with nothing to send writes a comment at each 15 s of silence, and a frame resets the silence: at 14 s
// nothing is written, and the frame sent then arrives before any comment.
func TestComputeStreamCommentsEvery15Seconds(t *testing.T) {
	opened := make(chan *ComputeStream, 1)
	release := make(chan struct{})
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteInfer: func(request *ComputeRequest) {
			stream, ok := request.Stream()
			if !ok {
				return
			}
			opened <- stream
			select {
			case <-release:
			case <-request.Ctx.Done():
			}
		},
	}})
	server := httptest.NewServer(fixture.engine.Handler())
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	start := fixture.clock.Now()
	response := openComputeStream(t, fixture, server, "/v1/infer")
	stream := <-opened
	reader := bufio.NewReader(response.Body)

	awaitComputeTimerAt(t, fixture.ctx, fixture.clock, start.Add(15*time.Second))
	fixture.clock.Advance(15 * time.Second)
	if block := readComputeStreamBlock(t, reader); block != ":\n" {
		t.Fatalf("at 15 s the stream wrote %q", block)
	}
	awaitComputeTimerAt(t, fixture.ctx, fixture.clock, start.Add(30*time.Second))
	fixture.clock.Advance(14 * time.Second)
	if err := stream.Send("chunk", []byte("a\nb")); err != nil {
		t.Fatal(err)
	}
	if block := readComputeStreamBlock(t, reader); block != "event: chunk\ndata: a\ndata: b\n" {
		t.Fatalf("the frame read %q", block)
	}
	// the silence starts again at the frame: its comment comes 15 s after it, not at 30 s
	sent := fixture.clock.Now()
	awaitComputeTimerAt(t, fixture.ctx, fixture.clock, sent.Add(15*time.Second))
	fixture.clock.Advance(15 * time.Second)
	if block := readComputeStreamBlock(t, reader); block != ":\n" {
		t.Fatalf("15 s after the frame the stream wrote %q", block)
	}
	if err := stream.Send("bad\nevent", nil); err == nil {
		t.Fatal("an event name with a line break was sent")
	}
}

// The net.Conn the status server's deadlines reach, recording the last of each it set, so a test can pass every bound
// still set: what the status server's ReadTimeout and WriteTimeout do once their time has come.
type computeDeadlineConn struct {
	net.Conn
	stateLock     sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (self *computeDeadlineConn) SetDeadline(deadline time.Time) error {
	self.stateLock.Lock()
	self.readDeadline, self.writeDeadline = deadline, deadline
	self.stateLock.Unlock()
	return self.Conn.SetDeadline(deadline)
}

func (self *computeDeadlineConn) SetReadDeadline(deadline time.Time) error {
	self.stateLock.Lock()
	self.readDeadline = deadline
	self.stateLock.Unlock()
	return self.Conn.SetReadDeadline(deadline)
}

func (self *computeDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	self.stateLock.Lock()
	self.writeDeadline = deadline
	self.stateLock.Unlock()
	return self.Conn.SetWriteDeadline(deadline)
}

// Moves every deadline still set into the past, as its time coming would, and says which it moved; a cleared one
// stays clear.
func (self *computeDeadlineConn) expire() []string {
	self.stateLock.Lock()
	read, write := self.readDeadline, self.writeDeadline
	self.stateLock.Unlock()
	past := time.Unix(1, 0)
	expired := []string{}
	if !read.IsZero() {
		self.Conn.SetReadDeadline(past)
		expired = append(expired, "read")
	}
	if !write.IsZero() {
		self.Conn.SetWriteDeadline(past)
		expired = append(expired, "write")
	}
	return expired
}

// A listener whose connections record their deadlines, each handed to the test as it is accepted.
type computeDeadlineListener struct {
	net.Listener
	conns chan *computeDeadlineConn
}

func (self *computeDeadlineListener) Accept() (net.Conn, error) {
	conn, err := self.Listener.Accept()
	if err != nil {
		return nil, err
	}
	deadlineConn := &computeDeadlineConn{Conn: conn}
	select {
	case self.conns <- deadlineConn:
	default:
	}
	return deadlineConn, nil
}

// sidecarhost.Run's status server bounds a request's read at 15 s and its writes at 30 s; a stream clears the write
// bound and net/http the read one once the body is read, so once both bounds' times have come its request's context
// still stands and its frames still arrive.
func TestComputeStreamOutlivesTheServerWriteTimeout(t *testing.T) {
	opened := make(chan struct{})
	proceed := make(chan struct{})
	sent := make(chan error, 1)
	release := make(chan struct{})
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteInfer: func(request *ComputeRequest) {
			stream, ok := request.Stream()
			if !ok {
				return
			}
			close(opened)
			<-proceed
			sent <- stream.Send("chunk", []byte("past the bound"))
			select {
			case <-release:
			case <-request.Ctx.Done():
			}
		},
	}})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadlineListener := &computeDeadlineListener{Listener: listener, conns: make(chan *computeDeadlineConn, 1)}
	server := httptest.NewUnstartedServer(fixture.engine.Handler())
	server.Listener = deadlineListener
	server.Config.ReadTimeout = 15 * time.Second
	server.Config.WriteTimeout = 30 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	response := openComputeStream(t, fixture, server, "/v1/infer")
	<-opened
	conn := <-deadlineListener.conns
	// a bound left set would end the stream: the write one its writes, the read one its context, through net/http's
	// background read
	if expired := conn.expire(); 0 < len(expired) {
		t.Errorf("the stream left the server's %v bounds set", expired)
	}
	close(proceed)
	if err := <-sent; err != nil {
		t.Fatalf("the frame after the bound: %v", err)
	}
	if block := readComputeStreamBlock(t, bufio.NewReader(response.Body)); block != "event: chunk\ndata: past the bound\n" {
		t.Fatalf("read %q", block)
	}
}

// The tunnel's handler hijacks its connection behind the guard's writer, answers 101 and relays bytes; its line
// records 101. A route the design does not give a hijack is refused one.
func TestComputeTunnelRouteCanHijack(t *testing.T) {
	hijackRefused := make(chan error, 1)
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteTunnel: func(request *ComputeRequest) {
			conn, readWriter, err := request.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			readWriter.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: compute-test\r\nConnection: Upgrade\r\n\r\n")
			readWriter.Flush()
			line, err := readWriter.ReadString('\n')
			if err != nil {
				return
			}
			readWriter.WriteString("echo " + line)
			readWriter.Flush()
		},
		ComputeRouteCatalog: func(request *ComputeRequest) {
			_, _, err := request.Hijack()
			hijackRefused <- err
			request.Reply(nil)
		},
	}})
	server := httptest.NewServer(fixture.engine.Handler())
	t.Cleanup(server.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /v1/tunnel?host=provider.example HTTP/1.1\r\nHost: compute.example\r\nAuthorization: Bearer "+
		fixture.token()+"\r\nConnection: Upgrade\r\nUpgrade: compute-test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("the upgrade answered %q: %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if echo, err := reader.ReadString('\n'); err != nil || echo != "echo ping\n" {
		t.Fatalf("the relay answered %q: %v", echo, err)
	}
	conn.Close()
	// the line comes once the handler has returned, after its relay ends
	lineFound := func() bool {
		for _, entry := range fixture.serviceLog.lines() {
			if entry.Route == ComputeRouteTunnel && entry.Status == http.StatusSwitchingProtocols {
				return true
			}
		}
		return false
	}
	for !lineFound() {
		count, changed := fixture.engine.inFlightCount.Get()
		if count == 0 {
			if !lineFound() {
				t.Fatal("the tunnel left no 101 line")
			}
			break
		}
		<-changed
	}
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("the catalog: %d", recorder.Code)
	}
	if err := <-hijackRefused; err == nil || fixture.metrics.Value("urnetwork_compute_alarms_total", "hijack_route") != 1 {
		t.Fatalf("a hijack on the catalog: %v", err)
	}
}

// Drain refuses a new request at once, lets an open stream run until DrainTimeout, then ends its context, and returns
// once its handler has; nothing ends before the bound.
func TestComputeDrainEndsStreamsWithinItsBound(t *testing.T) {
	opened := make(chan struct{})
	ended := make(chan time.Time, 1)
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteInfer: func(request *ComputeRequest) {
			if _, ok := request.Stream(); !ok {
				return
			}
			close(opened)
			<-request.Ctx.Done()
			ended <- request.Now()
		},
	}})
	server := httptest.NewServer(fixture.engine.Handler())
	t.Cleanup(server.Close)
	response := openComputeStream(t, fixture, server, "/v1/infer")
	<-opened
	start := fixture.clock.Now()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		fixture.engine.Drain()
	}()
	bound := start.Add(fixture.engine.settings.DrainTimeout)
	awaitComputeTimerAt(t, fixture.ctx, fixture.clock, bound)
	requireComputeRefusal(t, fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil), http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	if fixture.engine.Ready() {
		t.Fatal("a draining engine is ready")
	}
	fixture.clock.Advance(fixture.engine.settings.DrainTimeout - time.Second)
	select {
	case <-ended:
		t.Fatal("the stream ended before the drain's bound")
	case <-drained:
		t.Fatal("the drain returned before its bound with a stream open")
	default:
	}
	fixture.clock.Advance(time.Second)
	<-drained
	if at := <-ended; at.Before(bound) {
		t.Fatalf("the stream ended at %v, before the bound %v", at, bound)
	}
	// the client sees the stream end
	if _, err := io.ReadAll(response.Body); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("the stream's end read %v", err)
	}
	if count := fixture.engine.inFlightCount.Value(); count != 0 {
		t.Fatalf("%d requests in flight after the drain", count)
	}
}
