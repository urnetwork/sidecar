// Ties schedules to the catalog's rows. A row's schedule is one exported Builder in a non-test file of
// this package (fs<n>.go), registered from a package-level var, so the T2 test beside it and server's
// T3 test run the same builder, never two hand copies (plan-TEST-small-readings reading 1):
//
//	var Fs2 = Register("FS-2", "", []Tier{TierT2, TierT3}, Twin(Fs2Refusal, Fs2Disjoint))
//
// A registration names a row and a case the catalog holds and tiers the case runs on, or it fails,
// and the first registration of a (row, case, tier) is the only one. Missing lists what no builder
// covers, which a gate reports as missing and never as passing. What a test binary does not link it
// does not see, so a gate sweep links this package, where every builder lives.
//
// Safe for concurrent use.

package fault

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// One builder for one case of a row, on the tiers it names.
type Registration struct {
	Row   string
	Case  string
	Tiers []Tier
	Build Builder
}

// FS-19's config-read on T2+T3.
func (self *Registration) String() string {
	tiers := []string{}
	for _, tier := range self.Tiers {
		tiers = append(tiers, string(tier))
	}
	name := self.Row
	if self.Case != "" {
		name += "'s " + self.Case
	}
	return name + " on " + strings.Join(tiers, "+")
}

type registry struct {
	catalog *Catalog

	stateLock     sync.Mutex
	registrations []*Registration
}

func newRegistry(catalog *Catalog) *registry {
	return &registry{catalog: catalog}
}

var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *registry
)

func theRegistry() *registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = newRegistry(DefaultCatalog())
	})
	return defaultRegistry
}

// Ties builder to a case of a row on tiers. caseName is empty for the row's main part. A row, case or
// tier the catalog does not hold, a nil builder, and a case already registered on one of the tiers
// each panic, since a registration runs from a package-level var and a test binary that cannot link
// its rows must not pass.
func Register(rowId string, caseName string, tiers []Tier, builder Builder) *Registration {
	registration, err := theRegistry().register(rowId, caseName, tiers, builder)
	if err != nil {
		panic(err)
	}
	return registration
}

func (self *registry) register(rowId string, caseName string, tiers []Tier, builder Builder) (*Registration, error) {
	if self.catalog.Row(rowId) == nil {
		return nil, fmt.Errorf("register %s: no such row in §22.8", rowId)
	}
	testCase := self.catalog.Case(rowId, caseName)
	if testCase == nil {
		return nil, fmt.Errorf("register %s: no case %q", rowId, caseName)
	}
	if builder == nil {
		return nil, fmt.Errorf("register %s: no builder", testCase)
	}
	if len(tiers) == 0 {
		return nil, fmt.Errorf("register %s: no tier", testCase)
	}
	for _, tier := range tiers {
		if !slices.Contains(testCase.TwinTiers(), tier) {
			return nil, fmt.Errorf("register %s on %s: the case runs on %v", testCase, tier, testCase.Tiers())
		}
	}
	registration := &Registration{Row: rowId, Case: caseName, Tiers: slices.Clone(tiers), Build: builder}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, other := range self.registrations {
		if other.Row != rowId || other.Case != caseName {
			continue
		}
		for _, tier := range tiers {
			if slices.Contains(other.Tiers, tier) {
				return nil, fmt.Errorf("register %s: %s on %s is registered already", registration, testCase, tier)
			}
		}
	}
	self.registrations = append(self.registrations, registration)
	return registration, nil
}

// Every registration this binary links, in row and case order.
func Registered() []*Registration {
	return theRegistry().registered()
}

func (self *registry) registered() []*Registration {
	self.stateLock.Lock()
	registrations := slices.Clone(self.registrations)
	self.stateLock.Unlock()
	order := func(registration *Registration) (int, int) {
		row := self.catalog.Row(registration.Row)
		return row.Number, slices.IndexFunc(row.Cases, func(testCase *Case) bool { return testCase.Name == registration.Case })
	}
	slices.SortStableFunc(registrations, func(a *Registration, b *Registration) int {
		rowA, caseA := order(a)
		rowB, caseB := order(b)
		if rowA != rowB {
			return rowA - rowB
		}
		return caseA - caseB
	})
	return registrations
}

// The registration covering a case on tier, or nil.
func Lookup(rowId string, caseName string, tier Tier) *Registration {
	return theRegistry().lookup(rowId, caseName, tier)
}

func (self *registry) lookup(rowId string, caseName string, tier Tier) *Registration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, registration := range self.registrations {
		if registration.Row == rowId && registration.Case == caseName && slices.Contains(registration.Tiers, tier) {
			return registration
		}
	}
	return nil
}

// The cases that must pass at gate on tier and that no builder covers on tier, in row order. Missing is
// never pass: a gate reports each of these missing. A case that waits on production, hardware or people
// (Case.Open) is not here, since what it waits on is no builder: a gate reports it open.
func Missing(gate string, tier Tier) []*Case {
	return theRegistry().missing(gate, tier)
}

func (self *registry) missing(gate string, tier Tier) []*Case {
	missing := []*Case{}
	for _, testCase := range self.catalog.GateCases(gate) {
		if !slices.Contains(testCase.Tiers(), tier) || testCase.Open != "" {
			continue
		}
		if self.lookup(testCase.Row.Id, testCase.Name, tier) == nil {
			missing = append(missing, testCase)
		}
	}
	return missing
}
