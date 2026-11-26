//go:build !js && !ios && !android && !sdk_mobile_bind

// GET /sidecar/label read through a world's label refresh (fake_api_label.go; the core's dns_label_refresh.go): two
// networks hosted on one instance, each Sidecar's own refresh filing what the Net's api answers its network, and a
// daemon hosting both resolving each by its own names. The daemon builds where ur daemon does, as this file does.

package sidecartest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The world test's user root, synthetic.
const fakeApiLabelTestRoot = "users.example"

// Hands each client generation's env to the test, so the test attaches a label refresh at that generation itself and
// joins its read by Close.
type fakeApiLabelEnvComponent struct {
	envs chan *sidecar.SidecarEnv
}

func (self *fakeApiLabelEnvComponent) Name() string {
	return "label-env"
}

func (self *fakeApiLabelEnvComponent) Attach(env *sidecar.SidecarEnv) error {
	select {
	case self.envs <- env:
	default:
	}
	return nil
}

func (self *fakeApiLabelEnvComponent) Close() {
}

// Two networks hosted on one instance in a world, each Sidecar's own label refresh at its client generation reading
// the Net's api on that generation's token: one network's set label and alias, the other's label drawn at its read.
// Each files its own network's names under the user root in its own table, which resolves the other's names to
// nothing, and a daemon hosting both resolves each `.ur` by those names. On the code before, the Net's api served no
// GET /sidecar/label, so a refresh in a world was refused 404 for good and filed nothing.
func TestFakeApiLabelFilesEachHostedNetworksNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	net := NewNet(ctx, nil)
	t.Cleanup(net.Close)
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := net.StartInstance("labels", &TestInstanceArgs{Settings: func() *sidecar.SidecarSettings {
		settings := sidecar.DefaultSidecarSettings()
		settings.UserRoot = fakeApiLabelTestRoot
		return settings
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	alphaId, bravoId := sidecar.NewId(), sidecar.NewId()
	if err := api.SetNetworkLabel(alphaId, &FakeApiNetworkLabel{Label: "a7q2m9x4k1", Alias: "team-alpha"}); err != nil {
		t.Fatal(err)
	}

	// enrolls a Sidecar of networkId and runs its label refresh once at its client generation, joined by Close: a
	// read that lands is the generation's last
	refreshed := func(networkId sidecar.Id) *sidecar.Sidecar {
		t.Helper()
		running, err := instance.AddSidecarIn(networkId, nil)
		if err != nil {
			t.Fatal(err)
		}
		capture := &fakeApiLabelEnvComponent{envs: make(chan *sidecar.SidecarEnv, 1)}
		remove, err := running.AddComponent(capture)
		if err != nil {
			t.Fatal(err)
		}
		defer remove()
		var env *sidecar.SidecarEnv
		select {
		case env = <-capture.envs:
		case <-ctx.Done():
			t.Fatalf("network %s's Sidecar attached no generation", networkId)
		}
		// the generation's env, its reads ending with the test's bound too: a read refused for later would wait on the
		// Net's clock, which nothing moves here, and Close would wait with it
		readCtx, stopRead := context.WithCancel(env.Ctx)
		defer stopRead()
		stopAtBound := context.AfterFunc(ctx, stopRead)
		defer stopAtBound()
		readEnv := *env
		readEnv.Ctx = readCtx
		refresh := running.NewNetworkLabelRefreshComponent(nil)
		if err := refresh.Attach(&readEnv); err != nil {
			t.Fatal(err)
		}
		refresh.Close()
		if err := ctx.Err(); err != nil {
			t.Fatalf("network %s's label refresh landed no read: %v", networkId, err)
		}
		return running
	}
	alpha, bravo := refreshed(alphaId), refreshed(bravoId)
	bravoLabel, ok := api.NetworkLabel(bravoId)
	if !ok {
		t.Fatal("bravo's read drew no label")
	}

	for _, c := range []struct {
		running   *sidecar.Sidecar
		networkId sidecar.Id
		names     map[string]sidecar.NetworkLabelKind
		other     string
	}{
		{running: alpha, networkId: alphaId, names: map[string]sidecar.NetworkLabelKind{"a7q2m9x4k1": sidecar.NetworkLabelKindLabel, "team-alpha": sidecar.NetworkLabelKindAlias}, other: bravoLabel.Label},
		{running: bravo, networkId: bravoId, names: map[string]sidecar.NetworkLabelKind{bravoLabel.Label: sidecar.NetworkLabelKindLabel}, other: "a7q2m9x4k1"},
	} {
		table, err := c.running.NetworkLabels()
		if err != nil {
			t.Fatal(err)
		}
		for name, kind := range c.names {
			if resolved, resolvedKind, err := table.ResolveNetworkLabel(fakeApiLabelTestRoot, name, false); err != nil || resolved != c.networkId || resolvedKind != kind {
				t.Errorf("network %s's table resolves %q to %s %s %v", c.networkId, name, resolved, resolvedKind, err)
			}
		}
		if resolved, _, err := table.ResolveNetworkLabel(fakeApiLabelTestRoot, c.other, false); !errors.Is(err, sidecar.ErrNetworkLabelUnknown) {
			t.Errorf("network %s's table resolves the other network's label to %s %v", c.networkId, resolved, err)
		}
	}

	// a short path, since a Unix socket's name is bounded
	directory, err := os.MkdirTemp("/tmp", "ur-labels-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	home := t.TempDir()
	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     filepath.Join(directory, "s"),
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
		LabelRoot:      fakeApiLabelTestRoot,
		Home:           home,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	t.Cleanup(func() {
		daemon.Close()
		<-done
	})
	for networkId, running := range map[sidecar.Id]*sidecar.Sidecar{alphaId: alpha, bravoId: bravo} {
		if err := daemon.AddSidecar(networkId, running); err != nil {
			t.Fatal(err)
		}
	}
	for index, c := range []struct {
		name      string
		networkId sidecar.Id
	}{
		{name: "a7q2m9x4k1", networkId: alphaId},
		{name: "team-alpha", networkId: alphaId},
		{name: bravoLabel.Label, networkId: bravoId},
	} {
		project := filepath.Join(home, "project-"+string(rune('a'+index)))
		if err := os.MkdirAll(project, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, ".ur"), []byte("network = \""+c.name+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if resolved, err := daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Cwd: project}, ""); err != nil || resolved != c.networkId {
			t.Errorf(".ur naming %q resolves to %s %v", c.name, resolved, err)
		}
	}
}
