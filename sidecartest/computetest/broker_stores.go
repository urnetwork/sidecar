// The stores computetest.Broker's guard and handlers read on T2 (CTEST-M12-01), each standing in for a table or a
// database a block reads, which no sidecar test reaches (pgx stays out of this module, DESIGN §4.5):
//
//	FakeComputeAbuseHolds       compute_abuse_hold's rows (§17.2, CARCH-M12-01), which every admission reads after
//	                            the hold's projection misses: none held until a test sets one
//	FakeComputeRegions          the host's GeoLite2 lookup (§17.2's refused regions): every address placed nowhere
//	                            until a test places one, and a fault that makes it unreadable
//	FakeComputeCatalogVersions  compute_catalog_version's rows (§6.3, INFER-M12-01): versions published in order,
//	                            a publish of any number but one past the newest refused as another broker's race
//
// Each answers what a test set, or the store's own refusal: a failing store answers an error, which the broker
// answers 503, never an admission. Safe for concurrent use: one lock each, no call out while holding it.

package computetest

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A store a test made fail did not answer.
	ErrFakeComputeStoreDown = errors.New("computetest: the fake store does not answer")
)

// compute_abuse_hold's rows as a test sets them (see the file header).
type FakeComputeAbuseHolds struct {
	stateLock    sync.Mutex
	networkHolds map[sidecar.Id]*model.ComputeAbuseHold
	failing      bool
	readCount    int
}

// No network held.
func NewFakeComputeAbuseHolds() *FakeComputeAbuseHolds {
	return &FakeComputeAbuseHolds{networkHolds: map[sidecar.Id]*model.ComputeAbuseHold{}}
}

// Sets networkId's row to hold, its version raised past the row's before as each staff act raises it; nil clears the
// row, as a network never held.
func (self *FakeComputeAbuseHolds) Set(networkId sidecar.Id, hold *model.ComputeAbuseHold) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if hold == nil {
		delete(self.networkHolds, networkId)
		return
	}
	copied := *hold
	copied.NetworkId = networkId
	if before, ok := self.networkHolds[networkId]; ok && copied.Version <= before.Version {
		copied.Version = before.Version + 1
	}
	if copied.Version <= 0 {
		copied.Version = 1
	}
	self.networkHolds[networkId] = &copied
}

// Makes the store fail, or answer again.
func (self *FakeComputeAbuseHolds) SetFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

// How many rows were read.
func (self *FakeComputeAbuseHolds) ReadCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// The network's row, nil for a network never held (computeservice.ComputeAbuseHoldStoreForTest's shape).
func (self *FakeComputeAbuseHolds) Hold(ctx context.Context, networkId sidecar.Id) (*model.ComputeAbuseHold, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, ErrFakeComputeStoreDown
	}
	self.readCount += 1
	hold, ok := self.networkHolds[networkId]
	if !ok {
		return nil, nil
	}
	copied := *hold
	return &copied, nil
}

// The host's region lookup as a test sets it (see the file header).
type FakeComputeRegions struct {
	stateLock   sync.Mutex
	addrRegions map[netip.Addr]*computeservice.ComputeRegion
	failing     bool
	askedCount  int
}

var _ computeservice.ComputeRegionLookup = (*FakeComputeRegions)(nil)

// Every address placed nowhere.
func NewFakeComputeRegions() *FakeComputeRegions {
	return &FakeComputeRegions{addrRegions: map[netip.Addr]*computeservice.ComputeRegion{}}
}

// Places addr in region; nil places it nowhere again.
func (self *FakeComputeRegions) Place(addr netip.Addr, region *computeservice.ComputeRegion) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if region == nil {
		delete(self.addrRegions, addr.Unmap())
		return
	}
	copied := *region
	self.addrRegions[addr.Unmap()] = &copied
}

// Makes the lookup fail, or answer again.
func (self *FakeComputeRegions) SetFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

// How many addresses were asked.
func (self *FakeComputeRegions) AskedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askedCount
}

// See computeservice.ComputeRegionLookup: a zero region for an address placed nowhere. The error names no address.
func (self *FakeComputeRegions) Region(addr netip.Addr) (*computeservice.ComputeRegion, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askedCount += 1
	if self.failing {
		return nil, ErrFakeComputeStoreDown
	}
	if region, ok := self.addrRegions[addr.Unmap()]; ok {
		copied := *region
		return &copied, nil
	}
	return &computeservice.ComputeRegion{}, nil
}

// compute_catalog_version's rows as the broker's catalog writes and reads them (see the file header).
type FakeComputeCatalogVersions struct {
	stateLock sync.Mutex
	// oldest first
	versions []*computeservice.ComputeCatalogVersion
	failing  bool
}

// No version published.
func NewFakeComputeCatalogVersions() *FakeComputeCatalogVersions {
	return &FakeComputeCatalogVersions{}
}

// A deep copy of version, so neither side's later change reaches the other.
func fakeCatalogVersionCopy(version *computeservice.ComputeCatalogVersion) *computeservice.ComputeCatalogVersion {
	copied := *version
	if version.Answer != nil {
		copied.Answer = proto.Clone(version.Answer).(*protocol.InferCatalogAnswer)
	}
	copied.Exposures = make([]*computeservice.ComputeDirectExposure, 0, len(version.Exposures))
	for _, exposure := range version.Exposures {
		exposureCopy := *exposure
		copied.Exposures = append(copied.Exposures, &exposureCopy)
	}
	return &copied
}

// Makes the store fail, or answer again.
func (self *FakeComputeCatalogVersions) SetFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

// The newest count versions, newest first; none where none was published (computeservice's
// ComputeCatalogVersionStoreForTest shape).
func (self *FakeComputeCatalogVersions) Newest(ctx context.Context, count int) ([]*computeservice.ComputeCatalogVersion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, ErrFakeComputeStoreDown
	}
	newest := []*computeservice.ComputeCatalogVersion{}
	for i := len(self.versions) - 1; 0 <= i && len(newest) < count; i -= 1 {
		newest = append(newest, fakeCatalogVersionCopy(self.versions[i]))
	}
	return newest, nil
}

// Publishes version, whose number must be one past the newest, or 1 for the first: computeservice.ErrComputeCatalogRace
// otherwise, as the table's insert refuses another publisher's number.
func (self *FakeComputeCatalogVersions) Publish(ctx context.Context, version *computeservice.ComputeCatalogVersion) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if version == nil {
		return errors.New("computetest: no catalog version to publish")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return ErrFakeComputeStoreDown
	}
	newest := uint64(0)
	if 0 < len(self.versions) {
		newest = self.versions[len(self.versions)-1].Version
	}
	if version.Version != newest+1 {
		return computeservice.ErrComputeCatalogRace
	}
	self.versions = append(self.versions, fakeCatalogVersionCopy(version))
	return nil
}

// Sets version's exposures as of at, unless an exposure as new or newer stands, as the table's update keeps the newest.
func (self *FakeComputeCatalogVersions) SetExposure(ctx context.Context, version uint64, exposures []*computeservice.ComputeDirectExposure, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return ErrFakeComputeStoreDown
	}
	index := slices.IndexFunc(self.versions, func(stored *computeservice.ComputeCatalogVersion) bool {
		return stored.Version == version
	})
	if index < 0 || at.Before(self.versions[index].ExposureTime) {
		return nil
	}
	updated := fakeCatalogVersionCopy(self.versions[index])
	updated.Exposures = updated.Exposures[:0]
	for _, exposure := range exposures {
		exposureCopy := *exposure
		updated.Exposures = append(updated.Exposures, &exposureCopy)
	}
	updated.ExposureTime = at.UTC()
	self.versions[index] = updated
	return nil
}
