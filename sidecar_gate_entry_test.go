//go:build !sidecar_http && !js

// TestAuthorizeRunsFromEveryEntryPoint on a running sidecar: §5.4's one gate behind Sidecar.Authorize and each
// component's SidecarEnv.Authorize, which every outward entry point calls before its effect. The entry points
// themselves are other tracks' (MCP's tools, control mode's methods, the CLI, local SMTP submission, the sdk remote
// backend), so each is a stub here that calls what its owner's must, and with no gate installed every one is refused.

package sidecar_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A gate that counts what reaches it.
type entryTestGate struct {
	stateLock sync.Mutex
	kinds     []sidecar.SidecarActionKind
}

func (self *entryTestGate) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.kinds = append(self.kinds, action.Kind)
	return nil
}

func (self *entryTestGate) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.kinds)
}

// A component that hands its env to the test.
type entryTestComponent struct {
	envs chan *sidecar.SidecarEnv
}

func (self *entryTestComponent) Name() string {
	return "mail"
}

func (self *entryTestComponent) Attach(env *sidecar.SidecarEnv) error {
	select {
	case self.envs <- env:
	default:
	}
	return nil
}

func (self *entryTestComponent) Close() {}

func TestAuthorizeRunsFromEveryEntryPoint(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	running := laptop.Sidecar()
	component := &entryTestComponent{envs: make(chan *sidecar.SidecarEnv, 1)}
	removeComponent, err := running.AddComponent(component)
	if err != nil {
		t.Fatal(err)
	}
	defer removeComponent()
	var env *sidecar.SidecarEnv
	select {
	case env = <-component.envs:
	case <-time.After(30 * time.Second):
		t.Fatal("the component never attached")
	}

	canonical, err := proto.Marshal(&protocol.CanonicalAction{Kind: uint32(sidecar.SidecarActionMail), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	action := &sidecar.SidecarAction{Kind: sidecar.SidecarActionMail, Canonical: canonical, Risk: sidecar.SidecarRiskNormal}
	entryPoints := map[string]func(ctx context.Context) error{
		// what MCP's O tools, control mode's methods, the CLI and the sdk remote backend call
		"mcp":     func(ctx context.Context) error { return running.Authorize(ctx, action, nil) },
		"control": func(ctx context.Context) error { return running.Authorize(ctx, action, nil) },
		"cli":     func(ctx context.Context) error { return running.Authorize(ctx, action, nil) },
		"remote":  func(ctx context.Context) error { return running.Authorize(ctx, action, nil) },
		// what local SMTP submission's mail component calls, through its env
		"submission": func(ctx context.Context) error { return env.Authorize(ctx, action, nil) },
	}
	for name, entryPoint := range entryPoints {
		if err := entryPoint(t.Context()); !errors.Is(err, sidecar.ErrSidecarGateDenied) {
			t.Errorf("%s with no gate: %v", name, err)
		}
	}
	gate := &entryTestGate{}
	defer running.InstallGate(gate)()
	for name, entryPoint := range entryPoints {
		if err := entryPoint(t.Context()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if gate.count() != len(entryPoints) {
		t.Errorf("%d of %d entry points reached the gate", gate.count(), len(entryPoints))
	}
}
