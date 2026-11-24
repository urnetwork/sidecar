//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// On a running Sidecar: one router, the same for every caller (D-INFER-1), its registered remote paths built once for
// it, its local view following the engine the host sets; and once the Sidecar closes, no router.
func TestSidecarInferRouterIsShared(t *testing.T) {
	registrations := inferRemotePathRegistrations
	t.Cleanup(func() {
		inferRemotePathRegistrations = registrations
	})
	constructed := []*Sidecar{}
	inferRemotePathRegistrations = []*inferRemotePathRegistration{
		{kind: InferCatalogKindTee, construct: func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error) {
			constructed = append(constructed, sidecar)
			return &testInferPath{script: testInferAnswer("tee")}, nil
		}},
	}

	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, nil, testSidecarSettings(platform))
	if err != nil {
		t.Fatal(err)
	}
	first, err := sidecar.InferRouter()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sidecar.InferRouter()
	if err != nil || first != second {
		t.Errorf("two routers, or %v", err)
	}
	if !slices.Equal(constructed, []*Sidecar{sidecar}) {
		t.Errorf("the tee path constructed for %d sidecars", len(constructed))
	}

	catalog, err := first.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(catalog.LocalUnavailable(), "no local engine") {
		t.Errorf("before an engine: %q", catalog.LocalUnavailable())
	}
	engine := &testInferEngine{
		capabilities: testInferDevice("linux/amd64", InferDeviceClassDesktop, 32, false),
		script:       testInferAnswer("local"),
	}
	if err := sidecar.SetInferLocalEngine(engine); err != nil {
		t.Fatal(err)
	}
	catalog, err = first.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// a source build's manifest names no local model
	if strings.Contains(catalog.LocalUnavailable(), "no local engine") || catalog.LocalUnavailable() == "" {
		t.Errorf("with an engine: %q", catalog.LocalUnavailable())
	}

	ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
	defer cancel()
	if err := sidecar.CloseAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.InferRouter(); !errors.Is(err, ErrComputeComponentUnavailable) {
		t.Errorf("a router after the close: %v", err)
	}
	if err := sidecar.SetInferLocalEngine(engine); !errors.Is(err, ErrComputeComponentUnavailable) {
		t.Errorf("an engine set after the close: %v", err)
	}
}
