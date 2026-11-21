// The desktop daemon publishes owned refs from live mounts and from the sealed journal after restart.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// Stock git receives the local acknowledgement from the daemon. Clock and store barriers separate receipt,
// an ordinary background publication, and the restart's publication without a further request to the daemon.
func TestDaemonPublishesOwnedGitRefsAcrossRestart(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	networkId := network.NetworkId()
	engines.OpenNetwork(networkId)
	// The other device has its own instance, keychain and sealed store. Only the writer gets a local Git tier.
	readerInstance, err := world.net.StartInstance("reader", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readerInstance.Close)
	reader, err := readerInstance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	network.AdmitSidecar(network.Owner(), reader.Identity(), network.Owner().MemberId, 0)
	if startUrConfigFollower(reader, sidecar.NewNoopLogger()) == nil {
		t.Fatal("the reader's config follower did not start")
	}
	world.standing(reader, network)
	git := newTestUrGit(t, world.ctx)
	running := world.host(network, nil)
	world.standing(running, network)
	if running.Identity().SidecarId == reader.Identity().SidecarId {
		t.Fatal("the reader and writer have the same device identity")
	}
	if err := engines.Sync(world.ctx, networkId); err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	repoId, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	readerClient := testDaemonGitReader(t, world, engines, running, reader, repoId)
	git.daemon(networkId, running)
	url := "ur://" + testUrGitNetworkLabel + "/id:" + repoId.String()
	clone := filepath.Join(t.TempDir(), "clone")
	git.must("", "clone", "-q", url, clone)
	git.must(clone, "config", "user.name", "git writer")
	git.must(clone, "config", "user.email", running.Identity().ClientId.String()+"@ur.invalid")
	const content = "committed by the publication worker\n"
	if err := os.WriteFile(filepath.Join(clone, "README"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	git.must(clone, "add", "README")
	git.must(clone, "commit", "-q", "-m", "publish an owned ref")
	client, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	repo := client.Repo(repoId)
	for _, branch := range []string{"live", "restart"} {
		name := sidecar.EvsOwnedRefName(running.Identity().SidecarId, branch)
		refId, err := repo.RefIdOf(world.ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		headKey := "head/" + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId)
		parked, err := world.net.Faults().Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpPut, KeyPrefix: headKey, Result: sidecartest.Delay, Delay: sidecartest.DelayInNetwork,
		})
		if err != nil {
			t.Fatal(err)
		}
		git.must(clone, "push", "-q", "origin", "HEAD:refs/heads/"+string(name))
		mounts, err := client.Mounts()
		if err != nil {
			t.Fatal(err)
		}
		mount, ok := mounts.Get(repoId)
		if !ok {
			t.Fatal("no mount after the successful push")
		}
		journals, err := mount.Receiver().JournalStatus()
		if err != nil {
			t.Fatal(err)
		}
		queued := false
		for _, journal := range journals {
			if journal.RefId == refId && journal.Queued == 1 {
				queued = true
			}
		}
		if !queued {
			t.Fatalf("the acknowledged %s push is absent from the durable queue", branch)
		}
		if branch == "restart" {
			if err := world.instance.Restart(); err != nil {
				t.Fatal(err)
			}
			running = world.instance.Sidecar(networkId)
			world.standing(running, network)
		} else {
			world.net.Clock().Advance(sidecar.DefaultEvsSettings().QueueFirstDelay)
		}
		select {
		case <-parked:
		case <-world.ctx.Done():
			t.Fatalf("the %s worker never reached EVS for its acknowledged push", branch)
		}
		blobs := world.net.Fakes().Blobs
		delivered := 0
		for _, clusterId := range blobs.MetadataClusterIds() {
			delivered += blobs.DeliverDelayed(clusterId, headKey)
		}
		if delivered != 1 {
			t.Fatalf("the store received %d writes of the %s head", delivered, branch)
		}
		client, err = urDaemonEvsClient(running)
		if err != nil {
			t.Fatal(err)
		}
		mounts, err = client.Mounts()
		if err != nil {
			t.Fatal(err)
		}
		mount, ok = mounts.Get(repoId)
		if !ok {
			t.Fatal("the mounted repo was lost")
		}
		// The worker holds this lock from before the observed head write through its replay.
		release, err := mount.Locks().LockPublish(world.ctx, refId)
		if err != nil {
			t.Fatal(err)
		}
		journals, err = mount.Receiver().JournalStatus()
		release()
		if err != nil {
			t.Fatal(err)
		}
		for _, journal := range journals {
			if journal.RefId == refId {
				t.Fatalf("the %s worker left its committed push in the journal: %+v", branch, journal)
			}
		}
		// The other device opens the committed head using the repo key delivered to its own group client.
		args := &sidecar.EvsReadArgs{RefName: name, Path: "README", Fresh: true}
		out := &bytes.Buffer{}
		info, err := readerClient.Repo(repoId).ReadHead(world.ctx, args, out)
		if err != nil || info == nil || info.RefId != refId || info.HeadVersion != 1 || out.String() != content {
			t.Fatalf("the other device read %q from the %s ref: %+v, %v", out, branch, info, err)
		}
	}
}

// Grants the second device read access through the signed log and delivers its key over the real repo group.
func testDaemonGitReader(t *testing.T, world *testUrFollowWorld, engines *enginenet.Engines, writer *sidecar.Sidecar, reader *sidecar.Sidecar, repoId sidecar.Id) *sidecar.EvsClient {
	t.Helper()
	pin, err := engines.PostStatement(world.ctx, writer, bridge.SignedType_SIGNED_REPO_GRANT, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.RepoGrant{Header: header, RepoId: repoId.Bytes(), Subject: reader.Identity().SidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ConfigFollower().Client().WaitFor(world.ctx, pin.GetVersion()); err != nil {
		t.Fatal(err)
	}
	clients := testUrClientsOf(reader)
	readerGroup, err := clients.groupClient()
	if err != nil {
		t.Fatal(err)
	}
	clients.stateLock.Lock()
	upkeep := clients.upkeep
	clients.stateLock.Unlock()
	if upkeep == nil {
		t.Fatal("the reader has no key upkeep")
	}
	passes, _ := upkeep.Passes()
	upkeep.RefillKeyPackages()
	for {
		count, changed := upkeep.Passes()
		if passes < count {
			break
		}
		select {
		case <-changed:
		case <-world.ctx.Done():
			t.Fatal("the reader posted no KeyPackages")
		}
	}
	writerGroup, err := testUrClientsOf(writer).groupClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := writerGroup.RunPending(world.ctx, repoId); err != nil {
		t.Fatal(err)
	}
	if _, err := readerGroup.JoinWelcomes(world.ctx); err != nil {
		t.Fatal(err)
	}
	client, err := urDaemonEvsClient(reader)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
