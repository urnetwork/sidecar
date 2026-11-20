// §21.9's holds as a test places them: the hold/<network_id>/<case_id>/_ object api writes from
// abuse_legal_hold (ABUSE-M5-14), written through sidecar.EncodeHoldRecord, the codec api uses, so a
// fixture cannot drift from what readers parse. evs's, gkm's and taskworker's hold cases (EVSB-M2-11,
// KEYS-M2-16, EVS1-M2-19, FS-66, FS-69, FS-76, FS-78, FS-92) place holds here long before api writes
// one.
//
// HoldApi is the seam ABUSE-M10-01 swaps the fixture across: what places, renews and ends a schedule's holds. A
// schedule asks its Net's (NetHoldApi). On T3, server's tests give each Net api's own: model.PlaceLegalHold behind
// controller.PlaceLegalHold for a placement and controller.RunAbuseHoldPass for an end, over the Net's first
// metadata cluster and server's Postgres, so the readers' hold cases run against api's real hold/ writes. On T2 a
// Net has no api, and FixtureHoldApi stands in: it writes the bytes api writes, on api's deadlines, and ends a hold
// in the order api's pass does, evs's hold-end sweep queued before the object goes. Readers see hold/ alone, so a
// schedule that holds on one holds on the other.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Writes record's object on the first metadata cluster, as api places a hold, or rewrites it If-Match
// when it exists, as api renews one. blobs is any BlobStore that holds the first cluster, a FakeBlobs
// among them.
func PlaceHold(ctx context.Context, blobs sidecar.BlobStore, record *sidecar.HoldRecord) error {
	body, err := sidecar.EncodeHoldRecord(record)
	if err != nil {
		return err
	}
	return PlaceHoldBytes(ctx, blobs, sidecar.HoldObjectKey(record.NetworkId, record.CaseId), body)
}

// Writes body at key on the first metadata cluster, created or rewritten If-Match: how a test plants
// an object no codec would write, such as a malformed body or a newer version.
func PlaceHoldBytes(ctx context.Context, blobs sidecar.BlobStore, key string, body []byte) error {
	cluster, err := blobs.FirstCluster()
	if err != nil {
		return err
	}
	_, err = cluster.PutIfNoneMatch(ctx, key, body, nil)
	if !errors.Is(err, sidecar.ErrBlobPrecondition) {
		return err
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	_, err = cluster.PutIfMatch(ctx, key, info.Etag, body, nil)
	return err
}

// Deletes a hold's object, as api's sweep does once the hold has ended.
func RemoveHold(ctx context.Context, blobs sidecar.BlobStore, networkId sidecar.Id, caseId sidecar.Id) error {
	cluster, err := blobs.FirstCluster()
	if err != nil {
		return err
	}
	return cluster.Delete(ctx, sidecar.HoldObjectKey(networkId, caseId))
}

// ----- the api seam -----

// One hold a schedule asks api to place: what counsel's order, or a report to NCMEC, gives (§21.9).
type HoldPlacement struct {
	NetworkId sidecar.Id
	Kind      sidecar.HoldKind
	// The network, or 1 to sidecar.HoldScopeMaxRepoCount of its repos.
	Scope sidecar.HoldScope
	// report_2258a: when the report reached NCMEC, at or before the placement. Zero for preserve_2703f.
	ReportTime time.Time
	// Under a sealing or nondisclosure order (18 U.S.C. §2705(b)), or a CSAM report: api bars the hold's case, so
	// nothing tells the network of it (owner decision 93). No reader of hold/ can tell a sealed hold from another.
	Sealed bool
}

// What places, renews and ends a schedule's holds: §21.9's api. See the file header.
type HoldApi interface {
	// Places a hold at api's now, answering the terms its hold/ object holds once api acknowledged the placement. A
	// deleter is bound from §11.13's cache bound after that acknowledgement, 5 s (owner decision 629).
	PlaceHold(ctx context.Context, placement *HoldPlacement) (*sidecar.HoldRecord, error)
	// Renews a preserve_2703f hold once (§2703(f)(2)), answering its renewed terms.
	RenewHold(ctx context.Context, networkId sidecar.Id, caseId sidecar.Id) (*sidecar.HoldRecord, error)
	// api's hold pass at its now: each hold past its expiry has evs's hold-end sweep queued in tasks before its
	// object is deleted, and a live hold whose object is gone gets it back. Answers the holds it ended. The caller
	// runs what tasks took, as taskworker would.
	RunHoldPass(ctx context.Context, tasks sidecar.Tasks) ([]*sidecar.HoldRecord, error)
}

// The request that starts evs's hold-end sweep for a hold api ends at endTime: evsservice.EvsSweepHoldEndTaskRequest,
// which this package cannot name, since evsservice's own tests import it.
type HoldEndRequest func(record *sidecar.HoldRecord, endTime time.Time) (*sidecar.TaskRequest, error)

// The deadlines FixtureHoldApi gives: api's (server/model/abuse_hold_model.go), the statutes' periods in calendar
// days and years, as api adds them.
type FixtureHoldApiSettings struct {
	// 18 U.S.C. §2703(f)(1): 90 days from placement.
	PreserveDayCount int
	// §2703(f)(2): one renewal of 90 days more, so 180 days from placement.
	PreserveRenewDayCount int
	// §2258A(h)(1): a year from the report to NCMEC.
	ReportYearCount int
}

func DefaultFixtureHoldApiSettings() *FixtureHoldApiSettings {
	return &FixtureHoldApiSettings{
		PreserveDayCount:      90,
		PreserveRenewDayCount: 90,
		ReportYearCount:       1,
	}
}

// T2's api for holds (see the file header): its rows are this memory, its hold/ objects real writes through blobs.
// Safe for concurrent use.
type FixtureHoldApi struct {
	blobs    sidecar.BlobStore
	clock    Clock
	holdEnd  HoldEndRequest
	settings *FixtureHoldApiSettings

	stateLock sync.Mutex
	// the holds placed and not yet ended, as api's part-0 rows hold them, by their object's key
	holds map[string]*sidecar.HoldRecord
}

// The fixture on blobs' first metadata cluster, its now clock's; holdEnd is what its pass queues for a hold it ends.
// settings nil takes the defaults.
func NewFixtureHoldApi(blobs sidecar.BlobStore, clock Clock, holdEnd HoldEndRequest, settings *FixtureHoldApiSettings) *FixtureHoldApi {
	if settings == nil {
		settings = DefaultFixtureHoldApiSettings()
	}
	return &FixtureHoldApi{blobs: blobs, clock: clock, holdEnd: holdEnd, settings: settings, holds: map[string]*sidecar.HoldRecord{}}
}

// A time as api keeps it, to the millisecond, so the row and the object agree.
func fixtureHoldTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Millisecond)
}

// api's deadline for kind, before any renewal.
func (self *FixtureHoldApi) deadline(kind sidecar.HoldKind, placeTime time.Time, reportTime time.Time) (time.Time, error) {
	switch kind {
	case sidecar.HoldKindPreserve2703f:
		if !reportTime.IsZero() {
			return time.Time{}, fmt.Errorf("%w: a §2703(f) hold names a report time", sidecar.ErrHoldRecordInvalid)
		}
		return placeTime.AddDate(0, 0, self.settings.PreserveDayCount), nil
	case sidecar.HoldKindReport2258a:
		if reportTime.IsZero() || placeTime.Before(reportTime) {
			return time.Time{}, fmt.Errorf("%w: a §2258A hold whose report time is not at or before its placement", sidecar.ErrHoldRecordInvalid)
		}
		return fixtureHoldTime(reportTime).AddDate(self.settings.ReportYearCount, 0, 0), nil
	}
	return time.Time{}, fmt.Errorf("%w: an unknown kind", sidecar.ErrHoldRecordInvalid)
}

// Writes the object If-None-Match under a case of its own, as api's placement does, then keeps the row.
func (self *FixtureHoldApi) PlaceHold(ctx context.Context, placement *HoldPlacement) (*sidecar.HoldRecord, error) {
	now := fixtureHoldTime(self.clock.Now())
	expireTime, err := self.deadline(placement.Kind, now, placement.ReportTime)
	if err != nil {
		return nil, err
	}
	if !now.Before(expireTime) {
		return nil, fmt.Errorf("%w: a hold past its deadline at its placement", sidecar.ErrHoldRecordInvalid)
	}
	record := &sidecar.HoldRecord{
		NetworkId:  placement.NetworkId,
		CaseId:     sidecar.NewId(),
		Kind:       placement.Kind,
		Scope:      sidecar.HoldScopeRepos(placement.Scope.RepoIds...),
		PlaceTime:  now,
		ExpireTime: expireTime,
	}
	body, err := sidecar.EncodeHoldRecord(record)
	if err != nil {
		return nil, err
	}
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	key := sidecar.HoldObjectKey(record.NetworkId, record.CaseId)
	if _, err := cluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holds[key] = record
	return record, nil
}

// Rewrites a standing preserve_2703f hold's object with its renewed expiry, keeping its placement, as api's renewal
// does; a second renewal, a report_2258a hold and one past its expiry are refused.
func (self *FixtureHoldApi) RenewHold(ctx context.Context, networkId sidecar.Id, caseId sidecar.Id) (*sidecar.HoldRecord, error) {
	key := sidecar.HoldObjectKey(networkId, caseId)
	now := fixtureHoldTime(self.clock.Now())
	self.stateLock.Lock()
	held := self.holds[key]
	self.stateLock.Unlock()
	switch {
	case held == nil:
		return nil, fmt.Errorf("%w: no hold of the case stands", sidecar.ErrHoldRecordInvalid)
	case held.Kind != sidecar.HoldKindPreserve2703f || !held.Live(now):
		return nil, fmt.Errorf("%w: the hold is not renewable", sidecar.ErrHoldRecordInvalid)
	}
	renewed := *held
	renewed.ExpireTime = held.PlaceTime.AddDate(0, 0, self.settings.PreserveDayCount+self.settings.PreserveRenewDayCount)
	if !renewed.ExpireTime.After(held.ExpireTime) {
		return nil, fmt.Errorf("%w: renewed once already", sidecar.ErrHoldRecordInvalid)
	}
	if err := PlaceHold(ctx, self.blobs, &renewed); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holds[key] = &renewed
	return &renewed, nil
}

// api's pass at the clock's now: each hold past its expiry has its hold-end sweep queued, then its object deleted,
// then its row; each live hold whose object is gone gets it back. Holds are taken in key order, as api's cursor takes
// rows in order.
func (self *FixtureHoldApi) RunHoldPass(ctx context.Context, tasks sidecar.Tasks) ([]*sidecar.HoldRecord, error) {
	now := fixtureHoldTime(self.clock.Now())
	self.stateLock.Lock()
	keys := []string{}
	for key := range self.holds {
		keys = append(keys, key)
	}
	holds := map[string]*sidecar.HoldRecord{}
	for _, key := range keys {
		holds[key] = self.holds[key]
	}
	self.stateLock.Unlock()
	slices.SortFunc(keys, strings.Compare)
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	ended := []*sidecar.HoldRecord{}
	for _, key := range keys {
		record := holds[key]
		if record.Live(now) {
			_, err := cluster.Head(ctx, key)
			if errors.Is(err, sidecar.ErrBlobNotFound) {
				err = PlaceHold(ctx, self.blobs, record)
			}
			if err != nil {
				return ended, err
			}
			continue
		}
		if self.holdEnd == nil || tasks == nil {
			return ended, errors.New("the fixture's pass has no hold-end request or no task queue, so it ends no hold")
		}
		request, err := self.holdEnd(record, record.ExpireTime)
		if err != nil {
			return ended, err
		}
		if err := tasks.Schedule(ctx, request); err != nil {
			return ended, err
		}
		if err := cluster.Delete(ctx, key); err != nil {
			return ended, err
		}
		self.stateLock.Lock()
		delete(self.holds, key)
		self.stateLock.Unlock()
		ended = append(ended, record)
	}
	return ended, nil
}

// Each open Net's api for holds, where its tier gave one.
var netHoldApis sync.Map

// Gives net's schedules api's placement in place of the fixture until net closes: server's T3 tests set server's own
// on each Net they build (ABUSE-M10-01).
func SetNetHoldApi(net *Net, api HoldApi) {
	netHoldApis.Store(net, api)
	context.AfterFunc(net.Context(), func() {
		netHoldApis.Delete(net)
	})
}

// The api net's tier gave its schedules, nil where it gave none, as on T2, where a schedule places its holds through
// a FixtureHoldApi on the Net's own stores.
func NetHoldApi(net *Net) HoldApi {
	api, ok := netHoldApis.Load(net)
	if !ok {
		return nil
	}
	return api.(HoldApi)
}
