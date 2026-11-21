//go:build !sidecar_http

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Discovery lags the writer's own ref. A failed direct read can still return a prefix along with its error.
type testRecordLaggedListing struct {
	sidecar.RecordStreams
	listing []*sidecar.RecordStreamHead
	readErr error
}

func (self *testRecordLaggedListing) Streams(ctx context.Context, repoId sidecar.Id) ([]*sidecar.RecordStreamHead, error) {
	return self.listing, nil
}

func (self *testRecordLaggedListing) ReadStream(ctx context.Context, repoId sidecar.Id, writerId sidecar.Id, after uint64) ([]*sidecar.RecordStreamVersion, error) {
	versions, err := self.RecordStreams.ReadStream(ctx, repoId, writerId, after)
	if err == nil && self.readErr != nil {
		return versions[:min(1, len(versions))], self.readErr
	}
	return versions, err
}

func TestRecordWriterRestoredCaptureUsesOwnRefThroughItsFreshHead(t *testing.T) {
	for _, omitted := range []bool{true, false} {
		world := newTestRecordWorld(t)
		device := world.device(true)
		record := device.open()
		var newest *sidecar.RecordEntryRef
		for _, note := range []string{"first", "second"} {
			newest = testRecordAppend(t, record, testRecordNote(nil, note))
			if err := record.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		lagged := &testRecordLaggedListing{RecordStreams: device.tap.RecordStreams, readErr: io.ErrUnexpectedEOF}
		if !omitted {
			lagged.listing = []*sidecar.RecordStreamHead{{SidecarId: device.sidecarId, Version: 1}}
		}
		device.tap.RecordStreams = lagged
		device.files = sidecartest.NewFakeStore()
		var err error
		device.store, err = device.files.Root().Directory("record", "record")
		if err != nil {
			t.Fatal(err)
		}
		record = device.cold()
		if err := record.PrepareDirectWrites(t.Context()); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("omitted=%t: incomplete read allowed startup: %v", omitted, err)
		}
		if ref := testRecordAppend(t, record, testRecordNote(nil, "after restore")); !ref.Spooled {
			t.Fatalf("omitted=%t: capture signed on an incomplete read", omitted)
		}
		chain := sidecar.NewRecordChainStore(device.store, device.sidecarId)
		if head, err := chain.Head(world.vaultId); err != nil || head.Seq != 0 {
			t.Fatalf("omitted=%t: local chain after incomplete read: %+v, %v", omitted, head, err)
		}
		lagged.readErr = nil
		if err := record.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
		entries := world.storedEntries(device.sidecarId)
		if len(entries) != 3 || entries[2].path != "e/0/0/3" || entries[2].header.GetSeq() != newest.Seq+1 ||
			!bytes.Equal(entries[2].header.GetPrevSha256(), newest.Leaf[:]) {
			t.Fatalf("omitted=%t: restored entry failed to extend the second record at the next path: %+v", omitted, entries)
		}
	}
}

type testRecordHeadTransport func(*http.Request) (*http.Response, error)

func (self testRecordHeadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

func TestRecordEvsOwnStreamRecoveryVerifiesTheFreshRefAndWholeLog(t *testing.T) {
	world := newRecordEvsWorld(t)
	ctx := t.Context()
	repoId, err := world.NewRepo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writerId := world.ownerId
	signer := world.signer(writerId)
	env := &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(sidecartest.NewFakeStore().Root(), writerId), Sign: signer.Sign}
	var newest *sidecar.RecordSealedEntry
	for _, path := range []string{"e/0/0/1", "e/0/0/2"} {
		newest, err = sidecar.RecordSeal(env, testChainNote(repoId, path))
		if err != nil {
			t.Fatal(err)
		}
		push := recordEvsWorldPush(world, writerId, path)
		push.Entries[0].Entry = newest.EntryBytes(&push.SlotId, 0)
		push.SlotRows[0] = newest.SlotRow(0)
		if _, err := world.For(writerId).Append(ctx, repoId, push); err != nil {
			t.Fatal(err)
		}
	}

	refId, err := world.evsRepo(writerId, repoId).RefIdOf(ctx, sidecar.RecordStreamRefName(writerId))
	if err != nil {
		t.Fatal(err)
	}
	listing := &protocol.EvsRefsReply{Format: 1}
	listed, fresh := 0, 0
	partialLog := false
	answer := func(message proto.Message) *http.Response {
		encoded, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		response.Write(encoded)
		return response.Result()
	}
	client := world.newClient(writerId, sidecartest.NewFakeStore().Root(), func(args *sidecar.EvsClientArgs) {
		args.Transport = testRecordHeadTransport(func(request *http.Request) (*http.Response, error) {
			switch {
			case strings.HasSuffix(request.URL.Path, "/refs"):
				listed++
				return answer(listing), nil
			case strings.HasSuffix(request.URL.Path, "/log") && partialLog:
				return answer(&protocol.EvsLogReply{}), nil
			case strings.HasSuffix(request.URL.Path, "/read"):
				data, err := io.ReadAll(request.Body)
				if err != nil {
					return nil, err
				}
				request.Body.Close()
				request.Body = io.NopCloser(bytes.NewReader(data))
				read := &protocol.EvsReadRequest{}
				if err := proto.Unmarshal(data, read); err != nil {
					return nil, err
				}
				if read.GetFresh() && bytes.Equal(read.GetRefId(), refId[:]) {
					fresh++
				}
			}
			return world.RoundTrip(request)
		})
	})
	streams := world.streamsOn(writerId, client, sidecartest.NewFakeStore().Root())
	if heads, err := streams.Streams(ctx, repoId); !errors.Is(err, sidecar.ErrEvsReplyInvalid) || heads != nil {
		t.Fatalf("partial listing reported streams: %+v, %v", heads, err)
	}
	partialLog = true
	if head, found, err := sidecar.RecordStreamChainHead(ctx, streams, repoId, writerId, signer.PublicKey()); !errors.Is(err, sidecar.ErrEvsChainBroken) || found || head != nil {
		t.Fatalf("partial signed log supplied a writer head: %+v, %t, %v", head, found, err)
	}
	partialLog = false
	if head, found, err := sidecar.RecordStreamChainHead(ctx, streams, repoId, writerId, signer.PublicKey()); err != nil || !found || head.Seq != 2 || head.Leaf != newest.Leaf {
		t.Fatalf("writer head with a partial listing: %+v, %t, %v", head, found, err)
	}
	if n, err := sidecar.RecordStreamCounter(ctx, streams, repoId, writerId); err != nil || n != 2 {
		t.Fatalf("counter with a partial listing: %d, %v", n, err)
	}
	if listed != 1 || fresh < 3 {
		t.Fatalf("writer recovery used %d listings and %d fresh reads of its ref", listed-1, fresh)
	}
	listing.All = true
	listing.Refs = []*protocol.EvsHeadSummary{{RefId: refId[:], OwnerSidecarId: writerId[:], RefKind: protocol.EvsRefKind_EVS_REF_OWNED, Version: 1}}
	if heads, err := streams.Streams(ctx, repoId); err != nil || len(heads) != 1 || heads[0].Version != 2 {
		t.Fatalf("stale discovery version reached the reader: %+v, %v", heads, err)
	}
}

type testRecordEvsPinnedAuth struct {
	sidecar.RecordAuthView
	world *recordEvsWorld
}

func (self testRecordEvsPinnedAuth) Pin() *bridge.AuthPin {
	return self.world.Pin()
}

// Expiry can destroy the file carrying a header. A current writer holds its committed head and path, whereas a
// backup taken before that file was written can resume only once a later signed header proves the continuation.
func TestRecordWriterRestoredBeforeRemovedTailWaitsForCoverage(t *testing.T) {
	world := newRecordEvsWorld(t)
	ctx := t.Context()
	repoId, err := world.NewRepo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writerId := world.ownerId
	signer := world.signer(writerId)
	view := sidecartest.NewFakeRecordAuth().Append(&sidecartest.FakeRecordAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{writerId: signer.PublicKey()},
		Members:      map[sidecar.Id]sidecar.Id{writerId: world.memberId},
		Vaults:       map[sidecar.Id]sidecar.Id{world.memberId: repoId},
		Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{repoId: {Readers: []sidecar.Id{writerId}, Writers: []sidecar.Id{writerId}, Consented: []sidecar.Id{writerId}}},
	})
	streams := world.For(writerId)
	open := func(store sidecar.SidecarStore) (*sidecar.SidecarRecord, error) {
		return sidecar.OpenSidecarRecord(ctx, &sidecar.SidecarRecordArgs{
			SidecarId: writerId, IdentityPublicKey: signer.PublicKey(), Sign: signer.Sign,
			Store: store, Spool: newTestRecordSpool(), Clock: world.clock, Streams: streams,
			Auth:     func() sidecar.RecordAuthView { return testRecordEvsPinnedAuth{RecordAuthView: view, world: world} },
			Settings: sidecar.DefaultSidecarSettings().Record,
		})
	}
	old := sidecartest.NewFakeStore().Root()
	current := sidecartest.NewFakeStore().Root()
	var latest *sidecar.RecordEntryRef
	for _, store := range []sidecar.SidecarStore{old, current} {
		record, err := open(store)
		if err != nil {
			t.Fatal(err)
		}
		latest = testRecordAppend(t, record, testRecordNote(nil, "before expiry"))
		if err := record.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	admin := world.evsRepo(writerId, repoId)
	keys, err := admin.SlotKeysOf(ctx, sidecar.RecordStreamRefName(writerId), []string{"e/0/0/2"})
	if err != nil || len(keys) == 0 {
		t.Fatalf("tail file keys: %v, %v", keys, err)
	}
	if _, err := admin.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil {
		t.Fatal(err)
	}
	if n, err := sidecar.RecordStreamCounter(ctx, streams, repoId, writerId); err != nil || n != 2 {
		t.Fatalf("counter after expiry: %d, %v", n, err)
	}
	if _, err := open(old); !errors.Is(err, sidecar.ErrRecordStreamsUnavailable) {
		t.Fatalf("older backup with a removed tail: %v", err)
	}
	// Mixing the newer counter with the old chain, or restoring that number from the legacy format, cannot
	// establish the identity of the missing entry.
	files, err := current.List("stream/")
	if err != nil || len(files) != 1 {
		t.Fatalf("persisted stream counters: %+v, %v", files, err)
	}
	source, err := current.Open(files[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	latestCounter, err := io.ReadAll(source)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]json.RawMessage{}
	if err := json.Unmarshal(latestCounter, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "chain")
	legacyCounter, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{latestCounter, legacyCounter} {
		file, err := old.Create(files[0].Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(content); err == nil {
			err = file.Commit()
		}
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := open(old); !errors.Is(err, sidecar.ErrRecordStreamsUnavailable) {
			t.Fatalf("older chain with an unmatched counter signed over a removed tail: %v", err)
		}
	}
	record, err := open(current)
	if err != nil {
		t.Fatal(err)
	}
	next := testRecordAppend(t, record, testRecordNote(nil, "after expiry"))
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if next.Seq != latest.Seq+1 {
		t.Fatalf("signed sequence %d after removed sequence %d", next.Seq, latest.Seq)
	}
	head, found, err := sidecar.RecordStreamChainHead(ctx, streams, repoId, writerId, signer.PublicKey())
	if err != nil || !found || head.Seq != next.Seq || head.Leaf != next.Leaf {
		t.Fatalf("writer head after a later signed record: %+v, %t, %v", head, found, err)
	}
	if _, err := open(old); err != nil {
		t.Fatalf("legacy counter with a later signed record: %v", err)
	}
}

func TestRecordChainChecksLocalLeafBelowHigherStreamHead(t *testing.T) {
	writer := newTestRecordWriter(t)
	world, logId := testChainWorld(t, writer.sidecarId)
	streams := world.For(writer.sidecarId)
	local := writer.open()
	own := writer.seal(local, logId, 1)
	other := newTestRecordWriter(t)
	other.sidecarId, other.key = writer.sidecarId, writer.key
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(other.seal(other.open(), logId, 2)))
	if adopted, err := local.Chain.AdoptStream(t.Context(), streams, logId, writer.publicKey()); !errors.Is(err, sidecar.ErrRecordChainForked) || adopted {
		t.Fatalf("adopted a higher head with a conflicting local ancestor: %t, %v", adopted, err)
	}
	head, err := local.Chain.Head(logId)
	if err != nil || head.Seq != own[0].Seq || head.Leaf != own[0].Leaf {
		t.Fatalf("local head after a conflict: %+v, %v", head, err)
	}
}
