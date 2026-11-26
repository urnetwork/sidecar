// The stock daemon and member search bindings use each hosted network's own verified keys and view.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A local search can name an observed file only on the network and ref that actually verified it.
func TestDaemonSearchReadsVerifiedFilesOnlyInTheirHostedNetwork(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	engines := enginenet.NewEngines(t, world.net, nil)
	// each opening keeps evs and gkm open to the networks opened before it, so both hosted networks stay admitted
	for _, network := range world.networks {
		engines.OpenNetwork(network.NetworkId())
	}
	var hosted []*sidecar.Sidecar
	var repoId sidecar.Id
	path := "review-orchard.txt"
	for index, network := range world.networks {
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
	if err := world.instance.Restart(); err != nil {
		t.Fatal(err)
	}
	for index, network := range world.networks {
		hosted[index] = world.instance.Sidecar(network.NetworkId())
		world.standing(hosted[index], network)
	}
	if hits := hostedSearchHits(t, world.ctx, hosted[0], request); len(hits) != 1 || hits[0].Path != path {
		t.Fatalf("restored verified file: %+v", hits)
	}
	if err := engines.Sync(world.ctx, world.networks[0].NetworkId()); err != nil {
		t.Fatal(err)
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
	hits, _ := hostedSearchPage(t, ctx, running, r)
	return hits
}

func hostedSearchPage(t *testing.T, ctx context.Context, running *sidecar.Sidecar, r *sidecar.SearchRequest) ([]sidecar.SearchHit, sidecar.SearchProgress) {
	t.Helper()
	hits, progress, err := readHostedSearchPage(ctx, running, r)
	if err != nil {
		t.Fatal(err)
	}
	return hits, progress
}

// Opens the public stream and releases it even when a concurrent read invalidates the page.
func readHostedSearchPage(ctx context.Context, running *sidecar.Sidecar, r *sidecar.SearchRequest) ([]sidecar.SearchHit, sidecar.SearchProgress, error) {
	stream, err := running.Search(ctx, r)
	if err != nil {
		return nil, sidecar.SearchProgress{}, err
	}
	defer stream.Close()
	var hits []sidecar.SearchHit
	for {
		page, progress, done, err := stream.Next()
		if err != nil {
			return nil, progress, err
		}
		hits = append(hits, page...)
		if done {
			return hits, progress, nil
		}
	}
}

// Startup ingestion can advance the signed reader's revision between opening a scan and consuming its page.
func hostedRecordSearchPage(t *testing.T, ctx context.Context, running *sidecar.Sidecar, r *sidecar.SearchRequest) ([]sidecar.SearchHit, sidecar.SearchProgress) {
	t.Helper()
	for range 8 {
		runtime.Gosched()
		hits, progress, err := readHostedSearchPage(ctx, running, r)
		if errors.Is(err, sidecar.ErrSearchCursorExpired) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(progress.Coverage) == 0 && slices.ContainsFunc(progress.Excluded, func(row sidecar.SearchExclusion) bool { return row.Reason == sidecar.SearchExcludedUnbuilt }) {
			continue
		}
		return hits, progress
	}
	t.Fatal("signed reader did not hold one revision through the search")
	return nil, sidecar.SearchProgress{}
}

// The actual signed record reader and its governing class policy drive the fallback view.
func TestDaemonSearchOpensSignedVaultDocumentsOnTheirWriterRef(t *testing.T) {
	world, running, _, record, vault, _ := hostedRecordNote(t, false)
	if err := record.Reader().Sync(world.ctx, vault); err != nil {
		t.Fatal(err)
	}
	request := &sidecar.SearchRequest{Text: "first vault note", Repos: []sidecar.Id{vault}, Ref: string(sidecar.RecordStreamRefName(running.Identity().SidecarId))}
	hits, _ := hostedRecordSearchPage(t, world.ctx, running, request)
	if len(hits) != 1 || hits[0].Repo != vault || hits[0].Signer != running.Identity().SidecarId {
		t.Fatalf("signed vault search: %+v", hits)
	}
	policy, err := record.Retention().Set(world.ctx, &sidecar.RecordRetentionSetArgs{LogId: vault, Class: sidecar.RecordClassCoordination, SearchableDays: 1, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Land(world.ctx, []*sidecar.RecordEntryRef{policy}); err != nil {
		t.Fatal(err)
	}
	if err := record.Reader().Sync(world.ctx, vault); err != nil {
		t.Fatal(err)
	}
	if d := record.Retention().SearchableDays(vault, sidecar.RecordClassCoordination); d != 1 {
		t.Fatalf("signed retention policy: %d days", d)
	}
	world.net.Clock().Advance(24*time.Hour + time.Second)
	if hits, _ := hostedRecordSearchPage(t, world.ctx, running, request); len(hits) != 0 {
		t.Fatalf("signed searchable age still exposed: %+v", hits)
	}
}

// A signed context reaches its own stream's derived card through the stock member binding, including its sync control.
func TestDaemonSearchFollowsSignedRecordCompanionAndScansItsRun(t *testing.T) {
	world, running, evs, record, vault, _ := hostedRecordNote(t, true)
	run := sidecar.NewId()
	refs, err := record.Writer().Append(&sidecar.RecordDraft{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook,
		RunId: &run, NoSession: true, Body: &protocol.ContextBody{Stage: 1, Harness: "claude-code", Title: "Orchard run"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].LogId != vault || refs[0].Spooled {
		t.Fatalf("signed context did not reach the vault: %+v", refs)
	}
	if err := record.Land(world.ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := record.Reader().Sync(world.ctx, vault); err != nil {
		t.Fatal(err)
	}
	streamName := sidecar.RecordStreamRefName(running.Identity().SidecarId)
	entry, ok := record.Reader().Entry(vault, refs[0].EntryId)
	if !ok || entry.State != sidecar.RecordEntryLive || entry.BodyInvalid {
		t.Fatalf("signed context is unavailable: %+v", entry)
	}
	hits, progress := hostedRecordSearchPage(t, world.ctx, running, &sidecar.SearchRequest{Text: "orchard", Repos: []sidecar.Id{vault}, Ref: string(streamName)})
	stream, err := evs.Repo(vault).RefIdOf(world.ctx, streamName)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Path != fmt.Sprintf("run/%x", run.Bytes()) || hits[0].Repo != vault || hits[0].Ref != stream ||
		hits[0].DocKind != int(sidecar.IndexDocDerived) {
		t.Fatalf("signed stream's run card: %+v; progress %+v", hits, progress)
	}
	params, err := json.Marshal(&sidecar.DaemonSearchSyncParams{Repo: vault.String()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sidecar.DaemonSearchSyncMethods()[0].Handler(world.ctx, &sidecar.DaemonCall{Sidecar: running, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	reply := raw.(*sidecar.DaemonSearchSyncReply)
	if reply.Synced != 1 || len(reply.Failed) != 0 {
		t.Fatalf("expected one physical index for the signed stream: %+v, failures %+v", reply, reply.Failed)
	}
}

// A normal format-2 write creates a real encrypted index. An unscoped cached query cannot use the named-repo scan.
func TestDaemonSearchSyncsTheRealEncryptedIndex(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	cfg := enginenet.DefaultEnginesSettings()
	cfg.EvsInstanceFormat = sidecar.EvsRepoFormat2
	cfg.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, world.net, cfg)
	network := world.networks[0]
	engines.OpenNetwork(network.NetworkId())
	gates := world.net.Fakes().Gates
	id := connect.Id(network.NetworkId()).String()
	if err := gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  gkm: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q]}\n", id, id, id)); err != nil {
		t.Fatal(err)
	}
	running := world.host(network, nil)
	world.standing(running, network)
	keys, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	repoId, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: keys, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, changed := world.net.Clock().WatchTimers()
		if on, known := evs.Format2Gate(); on && known {
			break
		}
		select {
		case <-changed:
		case <-world.ctx.Done():
			t.Fatalf("waiting for authenticated format-2 admission: %v", world.ctx.Err())
		}
	}
	path := "orchard-catalog.txt"
	content := []byte("very local catalog")
	repo := evs.Repo(repoId)
	if _, err := repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(content), Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	info, err := repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(&sidecar.DaemonSearchSyncParams{Repo: repoId.String()})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := sidecar.DaemonSearchSyncMethods()[0].Handler(world.ctx, &sidecar.DaemonCall{Sidecar: running, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	synced := reply.(*sidecar.DaemonSearchSyncReply)
	if synced.Synced != 1 || len(synced.Failed) != 0 {
		for _, f := range synced.Failed {
			t.Logf("%s %s", f.RefId, f.Error)
		}
		t.Fatalf("synced %d refs", synced.Synced)
	}
	request := &sidecar.SearchRequest{Text: "orchard", Scope: sidecar.SearchCached}
	hits, progress := hostedSearchPage(t, world.ctx, running, request)
	if len(hits) != 1 || hits[0].Path != path || hits[0].Repo != repoId {
		t.Fatalf("ordinary network search of cache: %+v", hits)
	}
	cache, err := running.SearchCache()
	if err != nil {
		t.Fatal(err)
	}
	refId, err := repo.RefIdOf(world.ctx, sidecar.EvsMainRefName)
	if err != nil {
		t.Fatal(err)
	}
	var covered bool
	for _, ref := range progress.Coverage {
		if ref.RepoId == repoId && ref.RefId == refId && ref.State == "searched" && ref.PinVersion == info.HeadVersion &&
			ref.IndexedThrough == info.CommitVersion && ref.IndexedThrough > 0 {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("coverage at the signed file commit %d (head %d): %+v", info.CommitVersion, info.HeadVersion, progress.Coverage)
	}
	held, err := cache.Ref(repoId, refId)
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	if held != nil {
		for _, f := range held.Files {
			ready = ready || f.KeysKept
		}
	}
	if !ready {
		t.Fatal("the hosted cache must retain an actual reopenable EVS record")
	}
	if err := world.instance.Restart(); err != nil {
		t.Fatal(err)
	}
	restored := world.instance.Sidecar(network.NetworkId())
	world.standing(restored, network)
	if hits := hostedSearchHits(t, world.ctx, restored, request); len(hits) != 1 || hits[0].Repo != repoId || hits[0].Path != path {
		t.Fatalf("the restarted host could not reopen the encrypted search cache: %+v", hits)
	}
}
