//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Fails unless call panics.
func testInferPanics(t *testing.T, why string, call func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", why)
		}
	}()
	call()
}

// A remote path registers once, for tee or direct, with a constructor: anything else is a build error.
func TestRegisterInferRemotePathRefusesABadRegistration(t *testing.T) {
	registrations := inferRemotePathRegistrations
	t.Cleanup(func() {
		inferRemotePathRegistrations = registrations
	})
	inferRemotePathRegistrations = []*inferRemotePathRegistration{}
	construct := func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error) {
		return &testInferPath{script: testInferAnswer("path")}, nil
	}
	testInferPanics(t, "a local registration", func() { registerInferRemotePath(InferCatalogKindLocal, construct) })
	testInferPanics(t, "a search registration", func() { registerInferRemotePath(InferCatalogKindSearch, construct) })
	testInferPanics(t, "a nil constructor", func() { registerInferRemotePath(InferCatalogKindTee, nil) })
	registerInferRemotePath(InferCatalogKindTee, construct)
	registerInferRemotePath(InferCatalogKindDirect, construct)
	testInferPanics(t, "a second tee registration", func() { registerInferRemotePath(InferCatalogKindTee, construct) })
	if len(inferRemotePathRegistrations) != 2 {
		t.Errorf("%d registrations", len(inferRemotePathRegistrations))
	}
}

// The remote catalog registers once, with a constructor.
func TestRegisterInferRemoteCatalogOnce(t *testing.T) {
	registration := inferRemoteCatalogRegistration
	t.Cleanup(func() {
		inferRemoteCatalogRegistration = registration
	})
	inferRemoteCatalogRegistration = nil
	testInferPanics(t, "a nil constructor", func() { registerInferRemoteCatalog(nil) })
	registerInferRemoteCatalog(func(sidecar *Sidecar, settings *InferSettings) (InferRemoteCatalog, error) {
		return &testInferRemoteCatalog{}, nil
	})
	testInferPanics(t, "a second registration", func() {
		registerInferRemoteCatalog(func(sidecar *Sidecar, settings *InferSettings) (InferRemoteCatalog, error) {
			return &testInferRemoteCatalog{}, nil
		})
	})
}

// Each registration constructs once for a router; one whose constructor fails or builds nothing leaves its kind
// refusing with why, and the others serve.
func TestInferRemotePathsConstructEachRegistration(t *testing.T) {
	tee := &testInferPath{script: testInferAnswer("tee")}
	failure := errors.New("planted: no broker client")
	constructed := 0
	paths := newInferRemotePaths(nil, DefaultInferSettings(), []*inferRemotePathRegistration{
		{kind: InferCatalogKindTee, construct: func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error) {
			constructed += 1
			return tee, nil
		}},
		{kind: InferCatalogKindDirect, construct: func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error) {
			constructed += 1
			return nil, failure
		}},
	})
	if constructed != 2 {
		t.Errorf("%d constructions", constructed)
	}
	if path, refused := paths.path(InferCatalogKindTee); refused != nil || path != tee {
		t.Errorf("the tee path: %v, %v", path, refused)
	}
	if _, refused := paths.path(InferCatalogKindDirect); refused == nil || refused.Code != InferErrorModelRefused || !strings.Contains(refused.Message, failure.Error()) {
		t.Errorf("a failed construction: %+v", refused)
	}
	empty := newInferRemotePaths(nil, DefaultInferSettings(), []*inferRemotePathRegistration{
		{kind: InferCatalogKindTee, construct: func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error) {
			return nil, nil
		}},
	})
	if _, refused := empty.path(InferCatalogKindTee); refused == nil || !strings.Contains(refused.Message, "built nothing") {
		t.Errorf("a constructor that built nothing: %+v", refused)
	}
	if _, refused := empty.path(InferCatalogKindDirect); refused == nil || !strings.Contains(refused.Message, "no direct path") {
		t.Errorf("an unregistered kind: %+v", refused)
	}
}

// A remote path gets the call the checks passed, the effort already one its model lists, and nothing but its own events
// and its returned error decide the stream.
func TestInferRemotePathGetsTheCheckedCall(t *testing.T) {
	world := newTestInferRouterWorld(t, func(world *testInferRouterWorld) {
		world.direct.script = func(ctx context.Context, call *InferCall, emit InferEmit) error {
			emit(&InferEvent{Kind: InferEventStart})
			emit(&InferEvent{Kind: InferEventText, Text: string(call.Effort)})
			return nil
		}
	})
	request := testInferRequest("engy-glm-5.2", "xhigh")
	events, err := world.router.Infer(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	all := testInferDrain(t, events)
	if testInferText(all) != "high" {
		t.Errorf("the path ran at %q", testInferText(all))
	}
	call := world.direct.called()[0]
	if call.Request != request || call.Entry.Provider != "engy" || call.Name != "engy-glm-5.2-high" {
		t.Errorf("the call: %+v", call)
	}
	if request.Model != "engy-glm-5.2" || request.Reasoning != "xhigh" {
		t.Errorf("the router changed the request: %+v", request)
	}
}
