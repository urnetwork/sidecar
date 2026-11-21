// The stock daemon and member search bindings use each hosted network's own verified keys and view.
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A local search can name an observed file only on the network and ref that actually verified it.
func TestDaemonSearchReadsVerifiedFilesOnlyInTheirHostedNetwork(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	engines := enginenet.NewEngines(t, world.net, nil)
	var hosted []*sidecar.Sidecar
	var repoId sidecar.Id
	path := "review-orchard.txt"
	for index, network := range world.networks {
		engines.OpenNetwork(network.NetworkId())
		running := world.host(network, nil)
		world.standing(running, network)
		hosted = append(hosted, running)
		if err := engines.Sync(world.ctx, network.NetworkId()); err != nil {
			t.Fatal(err)
		}
		if index != 0 {
			continue
		}
		gkm, err := urDaemonGkmClient(running)
		if err != nil {
			t.Fatal(err)
		}
		repoId, err = engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
		if err != nil {
			t.Fatal(err)
		}
		evs, err := urDaemonEvsClient(running)
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("plain local content")
		repo := evs.Repo(repoId)
		if _, err := repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(data), Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path, Provenance: true}, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	request := &sidecar.SearchRequest{Text: "orchard", Repos: []sidecar.Id{repoId}}
	hits := hostedSearchHits(t, world.ctx, hosted[0], request)
	if len(hits) != 1 || hits[0].Path != path || hits[0].Repo != repoId || hits[0].Signer != hosted[0].Identity().SidecarId {
		t.Fatalf("local observation: %+v", hits)
	}
	if hits := hostedSearchHits(t, world.ctx, hosted[1], request); len(hits) != 0 {
		t.Fatalf("another network returned the observation: %+v", hits)
	}
	if hits := hostedSearchHits(t, world.ctx, hosted[0], &sidecar.SearchRequest{Text: "orchard", Repos: []sidecar.Id{repoId}, Ref: "unverified-ref"}); len(hits) != 0 {
		t.Fatalf("another ref returned the observation: %+v", hits)
	}
	evs, err := urDaemonEvsClient(hosted[0])
	if err != nil {
		t.Fatal(err)
	}
	repo := evs.Repo(repoId)
	if _, err := repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: path, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, io.Discard); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("expected the signed removal: %v", err)
	}
	if hits := hostedSearchHits(t, world.ctx, hosted[0], request); len(hits) != 0 {
		t.Fatalf("removed observation: %+v", hits)
	}
}

// Each result enters through the public Sidecar method without installing a test engine.
func hostedSearchHits(t *testing.T, ctx context.Context, running *sidecar.Sidecar, r *sidecar.SearchRequest) []sidecar.SearchHit {
	t.Helper()
	stream, err := running.Search(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var hits []sidecar.SearchHit
	for {
		page, _, done, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, page...)
		if done {
			return hits
		}
	}
}

// The actual signed record reader and its governing class policy drive the fallback view.
func TestDaemonSearchOpensSignedVaultDocumentsOnTheirWriterRef(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	engines.OpenNetwork(network.NetworkId())
	running := world.host(network, nil)
	world.standing(running, network)
	if err := engines.Sync(world.ctx, network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	owner := network.Owner().MemberId
	vault, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &owner})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	record, err := running.Record()
	if err != nil {
		t.Fatal(err)
	}
	if err := record.BindMemberReplica(running.ConfigFollower().Client(), evs); err != nil {
		t.Fatal(err)
	}
	if err := record.PrepareDirectWrites(world.ctx); err != nil {
		t.Fatal(err)
	}
	refs, err := record.Writer().Append(&sidecar.RecordDraft{Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent, NoSession: true, Body: &protocol.CoordinationBody{Text: "orchard record"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Land(world.ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := record.Reader().Sync(world.ctx, vault); err != nil {
		t.Fatal(err)
	}
	request := &sidecar.SearchRequest{Text: "orchard", Repos: []sidecar.Id{vault}, Ref: string(sidecar.RecordStreamRefName(running.Identity().SidecarId))}
	hits := hostedSearchHits(t, world.ctx, running, request)
	if len(hits) != 1 || hits[0].Repo != vault || hits[0].Signer != running.Identity().SidecarId {
		t.Fatalf("signed vault search: %+v", hits)
	}
}
