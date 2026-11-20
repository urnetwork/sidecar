//go:build sidecar_testhooks

// The hold cases on T2 (ABUSE-M10-01): FS-92's (fs92_hold.go) and FS-69's, FS-66's and FS-6's (hold_cases.go), each
// hold placed and ended through the Net's api for holds, which on T2 is the fixture (sidecartest.FixtureHoldApi),
// writing the bytes and keeping the deadlines server's api does. Server's abuse_fs92_t3_test.go and
// abuse_hold_format2_t3_test.go run the same builders on T3 with api's own placement and pass. The schedules hold the
// drop job, the sweep and the shred at barriers, so this needs the sidecar_testhooks tag.

package fault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs92(t *testing.T) {
	RunRow(t, "FS-92", "", nil)
}

func TestFs92HoldBetweenVerifyAndDelete(t *testing.T) {
	RunClause(t, "FS-92", "between verify and delete", Fs92HoldBetweenVerifyAndDelete, nil)
}

func TestFs92HoldBetweenDeletes(t *testing.T) {
	RunClause(t, "FS-92", "between deletes", Fs92HoldBetweenDeletes, nil)
}

func TestFs92DeleteInFlight(t *testing.T) {
	RunClause(t, "FS-92", "a delete in flight", Fs92DeleteInFlight, nil)
}

// (a) with a 90-day §2703(f) order, which outlasts the 30 days the drop table keeps an ended drop's entry: the held
// entry stays, unlisted past them as its twin's would be, and the job deletes what it held once the order ends (owner
// decision 643; QD-1113).
func TestFs92HoldOutlastsTheDropTable(t *testing.T) {
	RunClause(t, "FS-92", "a hold that outlasts the drop table", Fs92HoldOutlastsTheDropTable, nil)
}

func TestFs69(t *testing.T) {
	RunRow(t, "FS-69", "", nil)
}

func TestFs69HoldBetweenSweepDeletes(t *testing.T) {
	RunClause(t, "FS-69", "between sweep deletes", Fs69HoldBetweenSweepDeletes, nil)
}

func TestFs69EraseUnderTheHold(t *testing.T) {
	RunClause(t, "FS-69", "an erase under the hold", Fs69EraseUnderTheHold, nil)
}

func TestFs66Hold(t *testing.T) {
	RunRow(t, "FS-66", "hold", nil)
}

func TestFs6NowShredUnderAHold(t *testing.T) {
	RunClause(t, "FS-6", "a --now shred under a hold", Fs6NowShredUnderAHold, nil)
}

// FS-92 (c): a sealed hold's network takes the answers its no-hold twin takes, listing and bill included, while the
// held world keeps what the twin's job deletes.
func TestFs92SealedHoldAnswersEqualANoHoldTwin(t *testing.T) {
	twins, err := Fs92SealedHoldTwins(t.Context(), func() *Net {
		return sidecartest.NewNet(t.Context(), sidecartest.DefaultNetSettings())
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := twins.HeldAnswers.Lines()
	listed, billed := false, false
	for _, line := range lines {
		listed = listed || strings.HasPrefix(line, "listing: ")
		billed = billed || strings.HasPrefix(line, "bill: ")
	}
	if len(lines) < 10 || !listed || !billed {
		t.Fatalf("the comparison held %d answers, listing %t, bill %t", len(lines), listed, billed)
	}
}

// The comparison fails a held network whose one answer differs from its twin's, and ids normalize by their first
// appearance alone.
func TestHoldAnswersEqualCatchesOneDifferentAnswer(t *testing.T) {
	held, twin := NewHoldAnswers(), NewHoldAnswers()
	for _, answers := range []*HoldAnswers{held, twin} {
		answers.Add("admin GET /evs/v1/repos/00112233445566778899aabbccddeeff/drops: 200, 120 bytes, headers Content-Type")
	}
	held.Add("reader GET /evs/v1/repos/ffeeddccbbaa99887766554433221100/x: 404, 0 bytes, headers")
	twin.Add("reader GET /evs/v1/repos/0123456789abcdef0123456789abcdef/x: 404, 0 bytes, headers")
	if err := HoldAnswersEqual(held, twin); err != nil {
		t.Fatalf("answers alike but for their ids: %v", err)
	}
	held.Add("bill: the stored count fell 2000 bytes")
	twin.Add("bill: the stored count fell 0 bytes")
	if err := HoldAnswersEqual(held, twin); err == nil {
		t.Fatal("a bill that tells the hold apart passed")
	}
	if err := HoldAnswersEqual(NewHoldAnswers(), NewHoldAnswers()); err == nil {
		t.Fatal("two empty answer lists compared as equal")
	}
}

// What a fixture's pass queued.
type testHoldTasks struct {
	requests []*sidecar.TaskRequest
}

func (self *testHoldTasks) Register(name string, function sidecar.TaskFunction) {
}

func (self *testHoldTasks) Schedule(ctx context.Context, request *sidecar.TaskRequest) error {
	self.requests = append(self.requests, request)
	return nil
}

// T2's api keeps api's deadlines and order: a preserve_2703f hold renewed once to 180 days and refused a second
// renewal, a report_2258a hold a year from its report and never renewed, a missing object put back while the hold
// stands, and at the end the hold-end sweep queued before the object goes.
func TestFixtureHoldApiKeepsApisDeadlinesAndOrder(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	api := sidecartest.NewFixtureHoldApi(blobs, clock, evsservice.EvsSweepHoldEndTaskRequest, nil)
	networkId := sidecar.NewId()
	placeTime := clock.Now()

	preserve, err := api.PlaceHold(ctx, &sidecartest.HoldPlacement{NetworkId: networkId, Kind: sidecar.HoldKindPreserve2703f})
	if err != nil || !preserve.PlaceTime.Equal(placeTime) || !preserve.ExpireTime.Equal(placeTime.AddDate(0, 0, 90)) {
		t.Fatalf("the §2703(f) hold: %+v %v", preserve, err)
	}
	reportTime := placeTime.Add(-30 * 24 * time.Hour)
	report, err := api.PlaceHold(ctx, &sidecartest.HoldPlacement{NetworkId: networkId, Kind: sidecar.HoldKindReport2258a, ReportTime: reportTime})
	if err != nil || !report.ExpireTime.Equal(reportTime.AddDate(1, 0, 0)) {
		t.Fatalf("the §2258A hold: %+v %v", report, err)
	}
	if _, err := api.PlaceHold(ctx, &sidecartest.HoldPlacement{NetworkId: networkId, Kind: sidecar.HoldKindReport2258a}); err == nil {
		t.Fatal("a §2258A hold with no report time was placed")
	}
	if _, err := api.RenewHold(ctx, networkId, report.CaseId); err == nil {
		t.Fatal("a §2258A hold was renewed")
	}
	clock.Advance(80 * 24 * time.Hour)
	renewed, err := api.RenewHold(ctx, networkId, preserve.CaseId)
	if err != nil || !renewed.ExpireTime.Equal(placeTime.AddDate(0, 0, 180)) || !renewed.PlaceTime.Equal(placeTime) {
		t.Fatalf("the renewal: %+v %v", renewed, err)
	}
	if _, err := api.RenewHold(ctx, networkId, preserve.CaseId); err == nil {
		t.Fatal("a second renewal was taken")
	}
	cover, err := sidecar.NewHoldSet(blobs, clock, nil).Covering(ctx, networkId, sidecar.Id{})
	if err != nil || !cover.Covered() || len(cover.Holds) != 2 {
		t.Fatalf("the readers' cover: %+v %v", cover, err)
	}

	// a lost object comes back while its hold stands
	if err := sidecartest.RemoveHold(ctx, blobs, networkId, preserve.CaseId); err != nil {
		t.Fatal(err)
	}
	tasks := &testHoldTasks{}
	if ended, err := api.RunHoldPass(ctx, tasks); err != nil || len(ended) != 0 || len(tasks.requests) != 0 {
		t.Fatalf("a pass before any expiry: %d ended, %d queued, %v", len(ended), len(tasks.requests), err)
	}
	first, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Head(ctx, sidecar.HoldObjectKey(networkId, preserve.CaseId)); err != nil {
		t.Fatalf("the lost object was not put back: %v", err)
	}

	// day 335, a year from the report, ends both holds, the renewed one having ended at day 180: each one's sweep
	// queued, then its object gone
	clock.AdvanceTo(reportTime.AddDate(1, 0, 0))
	ended, err := api.RunHoldPass(ctx, tasks)
	if err != nil || len(ended) != 2 || len(tasks.requests) != 2 {
		t.Fatalf("the pass at the year's end: %d ended, %d queued, %v", len(ended), len(tasks.requests), err)
	}
	for _, request := range tasks.requests {
		if request.Name != evsservice.EvsSweepTaskName {
			t.Fatalf("the pass queued %q", request.Name)
		}
	}
	listed, _, err := first.List(ctx, "hold/", "", 10)
	if err != nil || len(listed) != 0 {
		t.Fatalf("hold/ after the pass: %d objects, %v", len(listed), err)
	}
}
