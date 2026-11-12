//go:build !ios_extension

package sidecar

// EVS2-M10-15 through PlanWrite: a new path written versionless plans one kind-5 checkpoint, staged when it pads to
// 16 KiB, with content_sha256 in its sealed fields and never inline; a 20 MiB one five 4 MiB kind-5 chunks, none
// staged; a versioned write plans as format 1 did; the run's tainted bit rides the plan; and a write past 2 GiB is
// refused by name before anything is read.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A plan of writes on the test world's main ref, at its writable generation.
func (self *evsTestWriter) plan(t *testing.T, tainted bool, writes ...*EvsPathWrite) *EvsWritePlan {
	t.Helper()
	ctx := context.Background()
	for _, write := range writes {
		self.server.know(write.Path)
	}
	refId, err := self.repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := self.gkm.EnsureWritable(ctx, self.world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := self.repo.PlanWrite(ctx, &EvsPlanArgs{RefName: EvsMainRefName, RefId: refId, Writes: writes, Generation: repoKey.Generation(), Tainted: tainted})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestEvsPlanWriteVersionlessNewPaths(t *testing.T) {
	writer := newEvsTestWriter(t)
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	small := evsTestContent("plan small versionless", 5000)
	big := evsTestContent("plan big versionless", 20*1024*1024)
	plain := evsTestContent("plan versioned", 5000)
	plan := writer.plan(t, true,
		&EvsPathWrite{Path: "small.bin", Content: bytes.NewReader(small), Versioning: versionless},
		&EvsPathWrite{Path: "big.bin", Content: bytes.NewReader(big), Versioning: versionless},
		&EvsPathWrite{Path: "plain.txt", Content: bytes.NewReader(plain)},
	)
	if !plan.Tainted {
		t.Error("the run's tainted bit left the plan")
	}
	paths := map[string]*EvsPlannedPath{}
	for _, planned := range plan.Paths {
		paths[planned.Path] = planned
	}
	smallPlan, bigPlan, plainPlan := paths["small.bin"], paths["big.bin"], paths["plain.txt"]
	if smallPlan == nil || bigPlan == nil || plainPlan == nil {
		t.Fatalf("planned %v", paths)
	}
	smallSum, bigSum := sha256.Sum256(small), sha256.Sum256(big)
	if smallPlan.Versioning != versionless || smallPlan.Inline || len(smallPlan.Chain) != 1 || !smallPlan.Chain[0].Staged ||
		smallPlan.Chain[0].Kind != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT || !bytes.Equal(smallPlan.Fields.GetContentSha256(), smallSum[:]) {
		t.Errorf("a small versionless file: %+v", smallPlan)
	}
	if bigPlan.Versioning != versionless || len(bigPlan.Chain) != 5 || !bytes.Equal(bigPlan.Fields.GetContentSha256(), bigSum[:]) {
		t.Fatalf("a 20 MiB versionless file: %d links", len(bigPlan.Chain))
	}
	for i, link := range bigPlan.Chain {
		if link.Staged || link.Kind != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT || link.Record == nil || link.Record.Kind != protocol.EvsRecordKind_EVS_RECORD_CHUNK {
			t.Errorf("chunk %d: %+v", i, link)
		}
	}
	if plainPlan.Versioning != 0 || len(plainPlan.Fields.GetContentSha256()) != 0 || !plainPlan.Inline || plainPlan.Chain[0].Kind != 0 {
		t.Errorf("a versioned file planned as format 2: %+v", plainPlan)
	}
	// past 2 GiB: refused by name
	_, err := writer.repo.PlanWrite(context.Background(), &EvsPlanArgs{
		RefName: EvsMainRefName, RefId: plan.RefId, Generation: plan.Generation,
		Writes: []*EvsPathWrite{{Path: "huge.bin", Content: &evsTestSizedSource{Reader: bytes.NewReader(nil), size: EvsFileMaxByteCount + 1}, Versioning: versionless}},
	})
	if !errors.Is(err, ErrEvsFileTooLarge) {
		t.Errorf("a file past 2 GiB: %v", err)
	}
}
