// CC1 (§22.7): what each engine's handler took and gave, request and response alike, and for a stream
// engine each connection's bytes both ways. A wrapper records as the bytes pass and forwards them
// unchanged, never reading ahead or holding a write, so a barrier inside the handler sees the timing it
// would see unwrapped. mx-4's listener input, §2.8's one exception, is captured under its own class,
// which the scan never reads.
//
// Each request is also kept in its caller's log, in order: what FI-23's and FI-24's equal-trace checks
// compare, so an entry holds what a server learns of a request's shape, its route, method and size,
// and nothing a run draws fresh.

package sidecartest

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/urnetwork/sidecar"
)

// One request an actor made of a server.
type privacyRequest struct {
	actor     string
	engine    string
	method    string
	target    string
	byteCount int
}

func (self *privacyRequest) String() string {
	return fmt.Sprintf("%s %s %s %d", self.engine, self.method, self.target, self.byteCount)
}

// CC1 for an HttpEngine: every request and response through handler, recorded under engineName and
// served unchanged. The calling actor is read from the request's ctx, so a client that serves in
// process (Net.EngineClient) keeps each actor's requests apart.
func (self *PrivacyCapture) WrapHandler(engineName string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestBody := &bytes.Buffer{}
		if request.Body != nil {
			request.Body = &privacyTeeBody{ReadCloser: request.Body, copy: requestBody}
		}
		recording := &privacyResponseWriter{ResponseWriter: writer}
		handler.ServeHTTP(recording, request)

		requestHead := &bytes.Buffer{}
		fmt.Fprintf(requestHead, "%s %s\n", request.Method, request.URL.RequestURI())
		request.Header.Write(requestHead)
		responseHead := &bytes.Buffer{}
		fmt.Fprintf(responseHead, "%d\n", recording.statusCode())
		recording.Header().Write(responseHead)
		// heads and bodies apart, so a body that is a compressed stream opens from its start
		self.AddItem(&PrivacyItem{Class: PrivacyClassHandler, Name: engineName + " request head", Body: requestHead.Bytes()})
		self.AddItem(&PrivacyItem{Class: PrivacyClassHandler, Name: engineName + " request body", Body: requestBody.Bytes()})
		self.AddItem(&PrivacyItem{Class: PrivacyClassHandler, Name: engineName + " response head", Body: responseHead.Bytes()})
		self.AddItem(&PrivacyItem{Class: PrivacyClassHandler, Name: engineName + " response body", Body: recording.body.Bytes()})

		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, &privacyRequest{
			actor:     ActorName(request.Context()),
			engine:    engineName,
			method:    request.Method,
			target:    request.URL.RequestURI(),
			byteCount: requestBody.Len(),
		})
	})
}

// actor's requests of servers, in the order the servers took them: "evs1 POST /evs/push 512".
func (self *PrivacyCapture) RequestLog(actor string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log := []string{}
	for _, request := range self.requests {
		if request.actor == actor {
			log = append(log, request.String())
		}
	}
	return log
}

// A request body that keeps a copy of what the handler reads, as it reads it.
type privacyTeeBody struct {
	io.ReadCloser
	copy *bytes.Buffer
}

func (self *privacyTeeBody) Read(buffer []byte) (int, error) {
	n, err := self.ReadCloser.Read(buffer)
	self.copy.Write(buffer[:n])
	return n, err
}

// A ResponseWriter that keeps a copy of each write and passes it on at once.
type privacyResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (self *privacyResponseWriter) WriteHeader(status int) {
	if self.status == 0 {
		self.status = status
	}
	self.ResponseWriter.WriteHeader(status)
}

func (self *privacyResponseWriter) Write(data []byte) (int, error) {
	if self.status == 0 {
		self.status = http.StatusOK
	}
	self.body.Write(data)
	return self.ResponseWriter.Write(data)
}

// Passes a flush on, for a handler that streams.
func (self *privacyResponseWriter) Flush() {
	if flusher, ok := self.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (self *privacyResponseWriter) statusCode() int {
	if self.status == 0 {
		return http.StatusOK
	}
	return self.status
}

// CC1 for a StreamEngine: a listener whose connections record what the engine read under inputClass
// and what it wrote as a handler's, each connection one item a direction once it closes. inputClass is
// PrivacyClassHandler, or PrivacyClassMx4Input for mxedge's report and role-mail listener alone.
func (self *PrivacyCapture) WrapListener(engineName string, listener net.Listener, inputClass PrivacyClass) net.Listener {
	return &privacyListener{Listener: listener, capture: self, engineName: engineName, inputClass: inputClass}
}

type privacyListener struct {
	net.Listener
	capture    *PrivacyCapture
	engineName string
	inputClass PrivacyClass
}

func (self *privacyListener) Accept() (net.Conn, error) {
	conn, err := self.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &privacyConn{Conn: conn, listener: self}, nil
}

// A connection that keeps a copy of each direction, added to the capture at its close.
type privacyConn struct {
	net.Conn
	listener *privacyListener

	stateLock sync.Mutex
	input     bytes.Buffer
	output    bytes.Buffer
	closeOnce sync.Once
}

func (self *privacyConn) Read(buffer []byte) (int, error) {
	n, err := self.Conn.Read(buffer)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.input.Write(buffer[:n])
	}()
	return n, err
}

func (self *privacyConn) Write(data []byte) (int, error) {
	n, err := self.Conn.Write(data)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.output.Write(data[:n])
	}()
	return n, err
}

func (self *privacyConn) Close() error {
	err := self.Conn.Close()
	self.closeOnce.Do(func() {
		var input, output []byte
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			input = bytes.Clone(self.input.Bytes())
			output = bytes.Clone(self.output.Bytes())
		}()
		capture := self.listener.capture
		capture.AddItem(&PrivacyItem{Class: self.listener.inputClass, Name: self.listener.engineName + " input", Body: input})
		capture.AddItem(&PrivacyItem{Class: PrivacyClassHandler, Name: self.listener.engineName + " output", Body: output})
	})
	return err
}

// CC4: a Logger whose every line, verbose ones included, is captured under source, so a log line
// that names a secret is found whatever level a production host runs at.
func (self *PrivacyCapture) Logger(source string) sidecar.Logger {
	return &privacyLogger{capture: self, source: source}
}

type privacyLogger struct {
	capture *PrivacyCapture
	source  string
}

func (self *privacyLogger) line(text string) {
	self.capture.Add(PrivacyClassLog, self.source, []byte(text))
}

func (self *privacyLogger) Info(args ...any) {
	self.line(fmt.Sprint(args...))
}

func (self *privacyLogger) Infof(format string, args ...any) {
	self.line(fmt.Sprintf(format, args...))
}

func (self *privacyLogger) Warningf(format string, args ...any) {
	self.line(fmt.Sprintf(format, args...))
}

func (self *privacyLogger) Errorf(format string, args ...any) {
	self.line(fmt.Sprintf(format, args...))
}

// Every level is on: a line a host keeps off still must not hold what it must not.
func (self *privacyLogger) V(level int32) sidecar.Verbose {
	return &privacyVerbose{logger: self}
}

type privacyVerbose struct {
	logger *privacyLogger
}

func (self *privacyVerbose) Enabled() bool {
	return true
}

func (self *privacyVerbose) Info(args ...any) {
	self.logger.Info(args...)
}

func (self *privacyVerbose) Infof(format string, args ...any) {
	self.logger.Infof(format, args...)
}
