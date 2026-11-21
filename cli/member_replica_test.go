//go:build !ios_extension && !sidecar_http && !js

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A signed-in app opens a previously provisioned network through its stock replica.
// The config and application readers must both decrypt the real EVS head with the
// generation kept by the enrolled instance, including after a full process restart.
func TestMemberReplicaReadsTheEnrolledNetworksEncryptedHeadAfterRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("member", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	networkId := sidecar.NewId()
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	provisioned, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: keys, OwnerMemberId: sidecar.NewId()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	running = instance.Sidecar(networkId)
	open := func(running *sidecar.Sidecar) *sidecar.MemberReplica {
		t.Helper()
		replica, err := running.OpenMemberReplica(ctx)
		if err != nil {
			t.Fatal(err)
		}
		again, err := running.OpenMemberReplica(ctx)
		if err != nil || again != replica {
			t.Fatalf("the enrolled host opened a second replica: %v", err)
		}
		if _, err := running.ConfigFollower().WaitStanding(ctx); err != nil {
			t.Fatalf("the enrolled config head: %v (%+v)", err, running.ConfigFollower().Status())
		}
		config, evs := replica.Config(), replica.Evs()
		if config == nil || evs == nil || !bytes.Equal(config.Pin().GetChain(), provisioned.Bootstrap.Pin.GetChain()) {
			t.Fatal("the public clients did not open on the verified pin")
		}
		var content bytes.Buffer
		_, err = evs.Repo(provisioned.ConfigRepoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: sidecar.ConfigHeadGenesisPath}, &content)
		if err != nil || !bytes.Equal(content.Bytes(), provisioned.Bootstrap.SignedGenesis) {
			t.Fatalf("the public file read: %v", err)
		}
		return replica
	}
	first := open(running)
	instance.Instance().Lock()
	if first.Config() != nil || first.Evs() != nil {
		t.Fatal("the locked instance still served member data")
	}
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	if first.Config() != nil || first.Evs() != nil || running.MemberReplica() != nil {
		t.Fatal("the closed host still publishes the old replica")
	}
	restarted := instance.Sidecar(networkId)
	second := open(restarted)
	restarted.Close()
	if second.Config() != nil || second.Evs() != nil || restarted.MemberReplica() != nil {
		t.Fatal("the host still serves its replica after Close")
	}
}

// The daemon writes a versionless file under its network's rollout. After rollback and a full restart, the
// app replica still verifies that file while the same explicit versionless write is refused.
func TestHostedEvsRolloutWritesAndReadsAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.EvsInstanceFormat = sidecar.EvsRepoFormat2
	engines := enginenet.NewEngines(t, net, settings)
	instance, err := net.StartInstance("member", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	networkId := sidecar.NewId()
	setRollout := func(on bool) {
		t.Helper()
		text := fmt.Sprintf("sidecar:\n  evs:\n    enabled: true\n    networks: [%s]\n  gkm:\n    enabled: true\n    networks: [%s]\n  format2:\n    enabled: %t\n    networks: [%s]\n", networkId, networkId, on, networkId)
		if err := net.Fakes().Gates.Set(text); err != nil {
			t.Fatal(err)
		}
	}
	setRollout(true)
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: keys, OwnerMemberId: sidecar.NewId()}, nil); err != nil {
		t.Fatal(err)
	}
	startUrConfigFollower(running, sidecar.NewNoopLogger())
	if _, err := running.ConfigFollower().WaitStanding(ctx); err != nil {
		t.Fatal(err)
	}
	daemon, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	waitRollout := func(client *sidecar.EvsClient, want bool) {
		t.Helper()
		for {
			// The reader arms its next fetch after publishing its result.
			_, changed := net.Clock().WatchTimers()
			if on, known := client.Format2Gate(); known && on == want {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("host never observed the authenticated rollout %t: %v", want, ctx.Err())
			case <-changed:
			}
		}
	}
	waitRollout(daemon, true)
	repoId, err := engines.CreateRepo(ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	const content = "versionless member data"
	write := func(client *sidecar.EvsClient) error {
		_, err := client.Repo(repoId).Write(ctx, &sidecar.EvsWriteArgs{
			Path: "note", Content: strings.NewReader(content), Size: int64(len(content)), Versioning: sidecar.EvsVersioningOff,
		})
		return err
	}
	if err := write(daemon); err != nil {
		t.Fatalf("daemon's format-2 write: %v", err)
	}
	setRollout(false)
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	if _, known := daemon.Format2Gate(); known {
		t.Fatal("the old daemon retained authenticated rollout after restart")
	}
	running = instance.Sidecar(networkId)
	replica, err := running.OpenMemberReplica(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := running.ConfigFollower().WaitStanding(ctx); err != nil {
		t.Fatal(err)
	}
	member := replica.Evs()
	if member == nil {
		t.Fatal("member did not open its signed network")
	}
	waitRollout(member, false)
	var read bytes.Buffer
	if _, err := member.Repo(repoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: "note"}, &read); err != nil || read.String() != content {
		t.Fatalf("member's verified read after rollback: %q, %v", read.String(), err)
	}
	if err := write(member); !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		t.Fatalf("member's explicit format-2 write outside rollout: %v", err)
	}
}
