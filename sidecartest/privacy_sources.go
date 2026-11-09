// CC4 (§22.7) and the classes the harness captures through. Logs come through PrivacyCapture.Logger,
// metrics through the fake ServiceHost.Metrics, the environment through AddEnvironment and the
// process's own at each scan, and hook payloads and MCP results through Add under their classes. An
// area adds its own records, edge records, report parse output, Find calls, dns edge queries, a fake
// upstream resolver, fake APNs and FCM, with AddSource and a class of its own, which it registers here
// with RegisterPrivacyClass, so sidecar_leaktest (leak_enabled.go) can hold it to a leak that takes its
// path: a class arrives tested or the self-test fails.

package sidecartest

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The capture classes: the built-in ones and those areas add.
type privacyClassRegistry struct {
	stateLock sync.Mutex
	added     []PrivacyClass
}

// What T2 captures through. PrivacyClassPostgres is T3's, and TEST-M2-09 registers it beside its
// capture and its leak.
var privacyBuiltInClasses = []PrivacyClass{
	PrivacyClassHandler, PrivacyClassMx4Input, PrivacyClassFrame,
	PrivacyClassObject, PrivacyClassRedis, PrivacyClassUsage, PrivacyClassTask,
	PrivacyClassLog, PrivacyClassMetric, PrivacyClassHint, PrivacyClassEnv, PrivacyClassHook, PrivacyClassMcp,
}

var privacyClassesRegistered = &privacyClassRegistry{}

func (self *privacyClassRegistry) register(class PrivacyClass) error {
	if !class.Valid() || !strings.Contains(string(class), "/") {
		return fmt.Errorf("%q names no capture point and path", class)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if slices.Contains(privacyBuiltInClasses, class) || slices.Contains(self.added, class) {
		return fmt.Errorf("%s is registered already", class)
	}
	self.added = append(self.added, class)
	return nil
}

func (self *privacyClassRegistry) classes() []PrivacyClass {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append(slices.Clone(privacyBuiltInClasses), self.added...)
}

// Adds an area's capture class, CC<n>/<what>, from a package-level var beside the source that captures
// under it. A class registered twice or naming no capture point and path panics.
func RegisterPrivacyClass(class PrivacyClass) PrivacyClass {
	if err := privacyClassesRegistered.register(class); err != nil {
		panic(err)
	}
	return class
}

// Every class the harness captures through: the built-in ones and those areas registered.
func PrivacyClasses() []PrivacyClass {
	return privacyClassesRegistered.classes()
}

// A writer whose every byte is captured under class and source: what a harness tees an MCP server's
// stdout through (PrivacyClassMcp), or a hook's payloads and answers (PrivacyClassHook), so a result or
// payload holding what it must not is found as the server or hook wrote it.
func (self *PrivacyCapture) Writer(class PrivacyClass, source string) io.Writer {
	writer := &privacyWriter{}
	self.AddSource(func() []*PrivacyItem {
		return []*PrivacyItem{{Class: class, Name: source, Body: writer.bytes()}}
	})
	return writer
}

type privacyWriter struct {
	stateLock sync.Mutex
	body      bytes.Buffer
}

func (self *privacyWriter) Write(data []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.body.Write(data)
}

func (self *privacyWriter) bytes() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.body.Bytes())
}

// A leak, for §22.7's self-test (leak_enabled.go): Put puts value into Class's real path on net, as a
// bug would. Leaks link only under sidecar_leaktest.
type Leak struct {
	Class PrivacyClass
	// The path holds any byte. One that holds text alone, an environment value or a metric label, is
	// leaked only the printable forms.
	Binary bool
	// The path puts the value inside text of its own, a log line's prefix, a metric's name and labels, a
	// JSON document, where a deflate or brotli stream, which carries no magic, is not opened
	// (privacy_decompress.go), so the self-test leaks those two forms through the other paths alone.
	Embeds bool
	Put    func(t testing.TB, net *Net, value []byte)
}

// CC4: an environment a process ran with, as os.Environ gives it, under source.
func (self *PrivacyCapture) AddEnvironment(source string, environ []string) {
	self.Add(PrivacyClassEnv, source, []byte(strings.Join(environ, "\n")))
}

// The test process's own environment, read at each scan: a value code under test put there with
// os.Setenv, for a child process or a hook, is found.
func processEnvironmentItems() []*PrivacyItem {
	return []*PrivacyItem{{Class: PrivacyClassEnv, Name: "process environment", Body: []byte(strings.Join(os.Environ(), "\n"))}}
}

// An http.Client that serves each request in process through instance's handler, captured as CC1,
// with the request's ctx, so the handler sees the calling actor and RequestLog keeps actors apart. An
// instance that is no HttpEngine answers 502.
func (self *Net) EngineClient(instance string) *http.Client {
	return &http.Client{Transport: &netEngineTransport{net: self, instance: instance}}
}

type netEngineTransport struct {
	net      *Net
	instance string
}

func (self *netEngineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var engine sidecar.Engine
	func() {
		self.net.stateLock.Lock()
		defer self.net.stateLock.Unlock()
		engine = self.net.engines[self.instance]
	}()
	httpEngine, ok := engine.(sidecar.HttpEngine)
	if !ok {
		return nil, fmt.Errorf("no HttpEngine runs as %s", self.instance)
	}
	recorder := httptest.NewRecorder()
	self.net.capture.WrapHandler(self.instance, httpEngine.Handler()).ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
