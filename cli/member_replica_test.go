//go:build !ios_extension && !sidecar_http && !js

package main

import (
	"bytes"
	"context"
	"io"
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
	// Provision a normal shared file before the app joins. Its own EVS reader must establish the searchable name.
	startUrConfigFollower(running, sidecar.NewNoopLogger())
	initial, err := running.ConfigFollower().WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fileRepo, err := engines.CreateRepo(ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	tip := initial.Pin()
	evs, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	const path = "app-orchard.txt"
	content := []byte("the enrolled member's file")
	if _, err := evs.Repo(fileRepo).Write(ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(content), Size: int64(len(content))}); err != nil {
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
		client, err := running.ConfigFollower().WaitStanding(ctx)
		if err != nil {
			t.Fatalf("the enrolled config head: %v (%+v)", err, running.ConfigFollower().Status())
		}
		if _, err := client.WaitFor(ctx, tip.GetVersion()); err != nil {
			t.Fatal(err)
		}
		config, evs := replica.Config(), replica.Evs()
		if config == nil || evs == nil || !bytes.Equal(config.Pin().GetChain(), tip.GetChain()) {
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
	fileRequest := &sidecar.SearchRequest{Text: "orchard", Repos: []sidecar.Id{fileRepo}}
	if _, err := first.Evs().Repo(fileRepo).ReadHead(ctx, &sidecar.EvsReadArgs{Path: path}, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertFile := func(running *sidecar.Sidecar) {
		t.Helper()
		hits := hostedSearchHits(t, ctx, running, fileRequest)
		if len(hits) != 1 || hits[0].Path != path || hits[0].Signer != running.Identity().SidecarId {
			t.Fatalf("the app's verified file: %+v", hits)
		}
	}
	assertFile(running)
	request := &sidecar.SearchRequest{Text: "genesis", Repos: []sidecar.Id{provisioned.ConfigRepoId}}
	if hits := hostedSearchHits(t, ctx, running, request); len(hits) != 0 {
		t.Fatal("an app search exposed its config repository")
	}
	instance.Instance().Lock()
	if _, err := running.Search(ctx, request); err == nil {
		t.Fatal("the locked app opened a search")
	}
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
	assertFile(restarted)
	if hits := hostedSearchHits(t, ctx, restarted, request); len(hits) != 0 {
		t.Fatal("a restarted app search exposed its config repository")
	}
	restarted.Close()
	if second.Config() != nil || second.Evs() != nil || restarted.MemberReplica() != nil {
		t.Fatal("the host still serves its replica after Close")
	}
}
