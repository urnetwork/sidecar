package gkmschedule

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// Reconfigure's change goes into a copy of gkm's settings, its nested settings included, which the new instance runs
// under, and the standing instance keeps its own as they were: its probe loop reads them until it has closed, so a
// change written into them raced that read wherever the instance's first probe had not yet ended, as the race detector
// found under load at TestLateAskFollowUpsEndOnceTheFirstAskIsAResyncIntervalOld's probeStoresOnce.
func TestReconfigureLeavesTheStandingInstanceItsSettings(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	standing := world.Engine.Settings()
	probeInterval := standing.StoreProbeInterval
	notFoundTtl := standing.Place.NotFoundTtl
	shardCount := standing.Prices.ShardCount
	bucket := standing.CommitSecondsBuckets[0]
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) {
		settings.StoreProbeInterval = probeInterval + time.Second
		settings.Place.NotFoundTtl = notFoundTtl + time.Second
		settings.Prices.ShardCount = shardCount + 1
		settings.CommitSecondsBuckets[0] = bucket + 1
	})
	settings := world.Engine.Settings()
	if settings == standing {
		t.Fatal("the new instance runs under the standing instance's settings")
	}
	if standing.StoreProbeInterval != probeInterval || standing.Place.NotFoundTtl != notFoundTtl ||
		standing.Prices.ShardCount != shardCount || standing.CommitSecondsBuckets[0] != bucket {
		t.Error("the change was written into the standing instance's settings")
	}
	if settings.StoreProbeInterval != probeInterval+time.Second || settings.Place.NotFoundTtl != notFoundTtl+time.Second ||
		settings.Prices.ShardCount != shardCount+1 || settings.CommitSecondsBuckets[0] != bucket+1 {
		t.Error("the new instance runs without the change")
	}
}
