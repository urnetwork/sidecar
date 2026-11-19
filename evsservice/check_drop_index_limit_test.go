package evsservice

// A DROP at the storage limit against this engine and its real storage gate (QD-1088; §11.14's limit row, §20.7): the
// repo admin's sidecar.EvsClient of check_drop_index_client_test.go drops a.txt's history while its network is over
// its storage limit, or spent. A hook whose rewrite of a standing index shard is an upload has that upload refused 403
// QUOTA_LIMIT (402 QUOTA_PAYMENT while spent), and the client sends the DROP again once without it, which commits,
// the shard left as it stood for the backfill. A hook whose rewrite is staged rides the DROP at the limit, which
// uploads nothing. A DROP whose kept head needs an upload is refused with its rewrites and again without them, the
// QuotaRefusal going back to the person and nothing dropped, and lands with its rewrites once the limit lifts.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The length of a shard, and of a head, past what a push stages or holds inline, so writing it is an upload.
const dropIndexLimitUploadByteCount = 40000

// length bytes that do not compress, a function of label.
func dropIndexLimitBytes(label string, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	for counter := uint64(0); len(out) < length; counter += 1 {
		sum := sha256.Sum256(binary.BigEndian.AppendUint64([]byte(label), counter))
		out = append(out, sum[:]...)
	}
	return out[:length]
}

// Writes a.txt three times, each version versionBytes long, and shard at the index's shard path, then files the drop's
// dry run of a.txt.
func (self *dropIndexClientWorld) limitHistoryAndPreview(versionByteCount int, shard []byte) *sidecar.EvsDropPreview {
	t := self.t
	t.Helper()
	for _, label := range []string{"alpha", "beta", "gamma"} {
		content := dropIndexLimitBytes(label, versionByteCount)
		if _, err := self.repo.WritePaths(self.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{Path: "a.txt", Content: bytes.NewReader(content)}}}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := self.repo.WritePaths(self.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{
		Path: dropIndexClientShardPath, Content: bytes.NewReader(shard), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	self.resolver.preview = &DropPreviewResolveResult{
		Paths:           []*protocol.EvsDropPreviewPath{{ListMatch: true, Count: 3, Linked: true}},
		SnapshotVersion: 4,
	}
	preview, err := self.repo.DropHistoryPreview(self.ctx, &sidecar.EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

// Puts the world's network over its storage limit, or spent, or with nil under it again, as the gate's next reread
// finds it, and rereads.
func (self *dropIndexClientWorld) setLimit(storage *sidecar.QuotaRefusal, spent *sidecar.QuotaRefusal) {
	self.host.Quota.SetStorageRefusal(connect.Id(self.networkId), storage)
	self.host.Quota.SetSpentRefusal(connect.Id(self.networkId), spent)
	self.quota.refresh(self.ctx)
	if over := self.quota.Over(connect.Id(self.networkId)); over != (storage != nil || spent != nil) {
		self.t.Fatalf("the gate reads the network over its limit: %v", over)
	}
}

// The storage limit's refusal, and a spent network's.
func dropIndexLimitStorageRefusal() *sidecar.QuotaRefusal {
	return &sidecar.QuotaRefusal{LimitKey: "evs_storage_bytes", Limit: 1 << 30, Used: 1<<30 + 1}
}

func dropIndexLimitSpentRefusal() *sidecar.QuotaRefusal {
	return &sidecar.QuotaRefusal{LimitKey: "balance", Upgrade: true}
}

// A DROP whose hook rewrites a standing shard that is an upload, while the network is refused new payload: the first
// send stops at the shard's upload, before any DROP is posted, and the second, the hook not asked again, commits
// without the rewrite; the shard stands as it did, and a.txt reads its kept head.
func testDropIndexLimitGoesWithoutAnUploadedRewrite(t *testing.T, storage *sidecar.QuotaRefusal, spent *sidecar.QuotaRefusal) {
	t.Helper()
	world := newDropIndexClientWorld(t)
	standing := dropIndexLimitBytes("the shard", dropIndexLimitUploadByteCount)
	preview := world.limitHistoryAndPreview(5, standing)
	_, before := world.read(dropIndexClientShardPath)
	calls := 0
	world.client.SetDropIndexHook(func(ctx context.Context, repo *sidecar.EvsRepo, args *sidecar.EvsDropIndexArgs) (*sidecar.EvsDropIndexRewrites, error) {
		calls += 1
		return &sidecar.EvsDropIndexRewrites{Writes: []*sidecar.EvsPathWrite{{
			Path: dropIndexClientShardPath, Content: bytes.NewReader(dropIndexLimitBytes("the shard rewritten", dropIndexLimitUploadByteCount)),
			Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}}}, nil
	})
	world.setLimit(storage, spent)
	result, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten {
		t.Fatalf("hook calls %d, pushes %+v", calls, result.Pushes)
	}
	if statuses := world.dropStatusesPosted(); len(statuses) != 1 || statuses[0] != http.StatusOK {
		t.Fatalf("evs answered the DROPs %v", statuses)
	}
	shard, after := world.read(dropIndexClientShardPath)
	if !bytes.Equal(shard, standing) || after.CommitVersion != before.CommitVersion {
		t.Fatal("the shard moved with a DROP sent without its rewrite")
	}
	head, headInfo := world.read("a.txt")
	if !bytes.Equal(head, dropIndexLimitBytes("gamma", 5)) || headInfo.Version != 4 || headInfo.CommitVersion != result.Pushes[0].Version {
		t.Fatalf("a.txt after the DROP: version %d, committed at %d", headInfo.Version, headInfo.CommitVersion)
	}
}

func TestDropIndexAtTheLimitGoesWithoutAnUploadedRewrite(t *testing.T) {
	testDropIndexLimitGoesWithoutAnUploadedRewrite(t, dropIndexLimitStorageRefusal(), nil)
}

func TestDropIndexWhileSpentGoesWithoutAnUploadedRewrite(t *testing.T) {
	testDropIndexLimitGoesWithoutAnUploadedRewrite(t, nil, dropIndexLimitSpentRefusal())
}

// At the storage limit a DROP whose rewrite is staged uploads nothing, and evs takes it whole at once: the shard reads
// back rewritten at the DROP's own version. What the limit refuses stays refused: a content write there gets 403
// QUOTA_LIMIT.
func TestDropIndexAtTheLimitTakesAStagedRewrite(t *testing.T) {
	world := newDropIndexClientWorld(t)
	preview := world.historyAndPreview()
	kept := dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 3 gamma")
	world.client.SetDropIndexHook(func(ctx context.Context, repo *sidecar.EvsRepo, args *sidecar.EvsDropIndexArgs) (*sidecar.EvsDropIndexRewrites, error) {
		return &sidecar.EvsDropIndexRewrites{Writes: []*sidecar.EvsPathWrite{{
			Path: dropIndexClientShardPath, Content: bytes.NewReader(kept), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}}}, nil
	})
	world.setLimit(dropIndexLimitStorageRefusal(), nil)
	_, err := world.repo.WritePaths(world.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{Path: "b.txt", Content: bytes.NewReader([]byte("payload"))}}})
	if !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT) {
		t.Fatalf("a content write at the limit: %v", err)
	}
	result, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP's pushes %+v", result.Pushes)
	}
	if statuses := world.dropStatusesPosted(); len(statuses) != 1 || statuses[0] != http.StatusOK {
		t.Fatalf("evs answered the DROPs %v", statuses)
	}
	shard, info := world.read(dropIndexClientShardPath)
	if !bytes.Equal(shard, kept) || info.CommitVersion != result.Pushes[0].Version {
		t.Fatalf("the shard after the DROP, committed at %d", info.CommitVersion)
	}
}

// At the storage limit a DROP whose kept head needs an upload is refused: sent with its staged rewrite, then once
// without it, and the second QuotaRefusal goes back to the person, no DROP ever posted, a.txt and the shard as they
// stood. Under the limit again the same dry run's command lands, its rewrite with it.
func TestDropIndexAtTheLimitRefusedForItsKeptHead(t *testing.T) {
	world := newDropIndexClientWorld(t)
	standing := dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 1 alpha", "a.txt 2 beta", "a.txt 3 gamma")
	preview := world.limitHistoryAndPreview(dropIndexLimitUploadByteCount, standing)
	_, before := world.read(dropIndexClientShardPath)
	kept := dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 3 gamma")
	calls := 0
	world.client.SetDropIndexHook(func(ctx context.Context, repo *sidecar.EvsRepo, args *sidecar.EvsDropIndexArgs) (*sidecar.EvsDropIndexRewrites, error) {
		calls += 1
		return &sidecar.EvsDropIndexRewrites{Writes: []*sidecar.EvsPathWrite{{
			Path: dropIndexClientShardPath, Content: bytes.NewReader(kept), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}}}, nil
	})
	world.setLimit(dropIndexLimitStorageRefusal(), nil)
	_, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	refusal, ok := sidecar.EvsErrorOf(err)
	if !ok || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT || refusal.Quota.GetLimitKey() != "evs_storage_bytes" {
		t.Fatalf("a DROP whose kept head needs an upload, at the limit: %v", err)
	}
	if statuses := world.dropStatusesPosted(); calls != 1 || len(statuses) != 0 {
		t.Fatalf("hook calls %d, evs answered the DROPs %v", calls, statuses)
	}
	if _, headInfo := world.read("a.txt"); headInfo.Version != 3 {
		t.Fatalf("a.txt after a refused DROP: version %d", headInfo.Version)
	}
	if shard, after := world.read(dropIndexClientShardPath); !bytes.Equal(shard, standing) || after.CommitVersion != before.CommitVersion {
		t.Fatal("the shard moved with a refused DROP")
	}

	world.setLimit(nil, nil)
	result, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("hook calls %d, pushes %+v", calls, result.Pushes)
	}
	if statuses := world.dropStatusesPosted(); len(statuses) != 1 || statuses[0] != http.StatusOK {
		t.Fatalf("evs answered the DROPs %v", statuses)
	}
	if shard, _ := world.read(dropIndexClientShardPath); !bytes.Equal(shard, kept) {
		t.Fatal("the shard after the DROP under the limit")
	}
	if head, headInfo := world.read("a.txt"); !bytes.Equal(head, dropIndexLimitBytes("gamma", dropIndexLimitUploadByteCount)) || headInfo.Version != 4 {
		t.Fatalf("a.txt after the DROP: version %d", headInfo.Version)
	}
}
