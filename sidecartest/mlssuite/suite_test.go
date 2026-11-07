package mlssuite

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FakeMls keeps the seam's behavior, so what builds on it keeps working on the real engine, which KEYS-M2-08 runs
// this suite against.
func TestFakeMlsPassesTheEngineSuite(t *testing.T) {
	Run(t, func(t *testing.T, count int) []sidecar.MlsEngine {
		world := sidecartest.NewFakeMlsWorld()
		engines := []sidecar.MlsEngine{}
		for index := 0; index < count; index += 1 {
			engines = append(engines, world.Engine(sidecar.NewId(), []byte(fmt.Sprintf("credential %d", index))))
		}
		return engines
	})
}

// FakeMls engines for one test, each its own sidecar.
func fakeEngines(t *testing.T, count int) []sidecar.MlsEngine {
	world := sidecartest.NewFakeMlsWorld()
	engines := []sidecar.MlsEngine{}
	for index := 0; index < count; index += 1 {
		engines = append(engines, world.Engine(sidecar.NewId(), []byte(fmt.Sprintf("credential %d", index))))
	}
	return engines
}

// A planted engine wraps FakeMls's and breaks one behavior.
type plantedEngine struct {
	sidecar.MlsEngine
	breakGroup   func(group sidecar.MlsGroup) sidecar.MlsGroup
	breakPending func(pending sidecar.MlsPendingJoin) sidecar.MlsPendingJoin
}

func (self *plantedEngine) CreateGroup(groupId sidecar.Id, urGroup *sidecar.MlsUrGroup) (sidecar.MlsGroup, error) {
	group, err := self.MlsEngine.CreateGroup(groupId, urGroup)
	if err != nil {
		return nil, err
	}
	return self.group(group), nil
}

func (self *plantedEngine) JoinWelcome(welcome []byte) (sidecar.MlsPendingJoin, error) {
	pending, err := self.MlsEngine.JoinWelcome(welcome)
	if err != nil {
		return nil, err
	}
	pending = &plantedPending{MlsPendingJoin: pending, engine: self}
	if self.breakPending != nil {
		return self.breakPending(pending), nil
	}
	return pending, nil
}

// The group, broken as planted, and its staged commits' groups after them.
func (self *plantedEngine) group(group sidecar.MlsGroup) sidecar.MlsGroup {
	wrapped := &plantedGroup{MlsGroup: group, engine: self}
	if self.breakGroup != nil {
		return self.breakGroup(wrapped)
	}
	return wrapped
}

// A pending join whose group is planted.
type plantedPending struct {
	sidecar.MlsPendingJoin
	engine *plantedEngine
}

func (self *plantedPending) Complete(groupInfo []byte) (sidecar.MlsGroup, error) {
	group, err := self.MlsPendingJoin.Complete(groupInfo)
	if err != nil {
		return nil, err
	}
	return self.engine.group(group), nil
}

// A group whose adopted successors are planted too.
type plantedGroup struct {
	sidecar.MlsGroup
	engine *plantedEngine
}

func (self *plantedGroup) Commit(args *sidecar.MlsCommitArgs) (sidecar.MlsStagedCommit, error) {
	staged, err := self.MlsGroup.Commit(args)
	if err != nil {
		return nil, err
	}
	return &plantedStaged{MlsStagedCommit: staged, engine: self.engine}, nil
}

func (self *plantedGroup) Process(message []byte) (sidecar.MlsStagedCommit, error) {
	staged, err := self.MlsGroup.Process(message)
	if err != nil {
		return nil, err
	}
	return &plantedStaged{MlsStagedCommit: staged, engine: self.engine}, nil
}

// A staged commit whose adopted group is planted.
type plantedStaged struct {
	sidecar.MlsStagedCommit
	engine *plantedEngine
}

func (self *plantedStaged) Adopt() (sidecar.MlsGroup, error) {
	group, err := self.MlsStagedCommit.Adopt()
	if err != nil {
		return nil, err
	}
	return self.engine.group(group), nil
}

// Planted engines for one test.
func plantedEngines(breakGroup func(group sidecar.MlsGroup) sidecar.MlsGroup, breakPending func(pending sidecar.MlsPendingJoin) sidecar.MlsPendingJoin) NewEngines {
	return func(t *testing.T, count int) []sidecar.MlsEngine {
		engines := []sidecar.MlsEngine{}
		for _, engine := range fakeEngines(t, count) {
			engines = append(engines, &plantedEngine{MlsEngine: engine, breakGroup: breakGroup, breakPending: breakPending})
		}
		return engines
	}
}

// A group whose staged commits export for anyone, a removed leaf included.
type leakyGroup struct {
	*plantedGroup
}

func (self *leakyGroup) Process(message []byte) (sidecar.MlsStagedCommit, error) {
	staged, err := self.plantedGroup.Process(message)
	if err != nil {
		return nil, err
	}
	return &leakyStaged{MlsStagedCommit: staged, group: self}, nil
}

// A staged commit exporting the old epoch's secrets when the new one's are out of reach.
type leakyStaged struct {
	sidecar.MlsStagedCommit
	group *leakyGroup
}

func (self *leakyStaged) Exporter(label string, context []byte, length int) ([]byte, error) {
	exported, err := self.MlsStagedCommit.Exporter(label, context, length)
	if err != nil {
		return self.group.Exporter(label, context, length)
	}
	return exported, nil
}

// A group whose Process stages any message, refused frames included.
type lenientGroup struct {
	*plantedGroup
}

func (self *lenientGroup) Process(message []byte) (sidecar.MlsStagedCommit, error) {
	staged, err := self.plantedGroup.Process(message)
	if err != nil {
		return nopStaged{}, nil
	}
	return staged, nil
}

// A staged commit of nothing, which a lenient group hands back for what it should have refused.
type nopStaged struct{}

func (self nopStaged) Exporter(label string, context []byte, length int) ([]byte, error) {
	return make([]byte, length), nil
}
func (self nopStaged) Message() []byte                  { return nil }
func (self nopStaged) Epoch() uint64                    { return 0 }
func (self nopStaged) EpochAuthenticator() []byte       { return nil }
func (self nopStaged) Committer() sidecar.MlsMember     { return sidecar.MlsMember{} }
func (self nopStaged) Added() []sidecar.MlsMember       { return nil }
func (self nopStaged) Removed() []sidecar.MlsMember     { return nil }
func (self nopStaged) AuthenticatedData() []byte        { return nil }
func (self nopStaged) Welcome() []byte                  { return nil }
func (self nopStaged) GroupInfo() ([]byte, error)       { return nil, nil }
func (self nopStaged) Adopt() (sidecar.MlsGroup, error) { return nil, errors.New("nothing staged") }
func (self nopStaged) Discard()                         {}

// A pending join that checks a GroupInfo's signature but its last byte: a refused one is tried again with that byte
// flipped back.
type sloppyPending struct {
	sidecar.MlsPendingJoin
}

func (self *sloppyPending) Complete(groupInfo []byte) (sidecar.MlsGroup, error) {
	group, err := self.MlsPendingJoin.Complete(groupInfo)
	if err == nil || len(groupInfo) == 0 {
		return group, err
	}
	again := bytes.Clone(groupInfo)
	again[len(again)-1] ^= 1
	return self.MlsPendingJoin.Complete(again)
}

// Each planted break is caught by the case that holds its behavior, so a passing run says something.
func TestTheSuiteCatchesPlantedBreaks(t *testing.T) {
	planted := []struct {
		name       string
		newEngines NewEngines
		catches    func(t *testing.T, newEngines NewEngines) error
	}{
		{
			name: "a removed leaf deriving the new epoch's KEK",
			newEngines: plantedEngines(func(group sidecar.MlsGroup) sidecar.MlsGroup {
				return &leakyGroup{plantedGroup: group.(*plantedGroup)}
			}, nil),
			catches: caseRemove,
		},
		{
			name: "standalone proposals and application data staged",
			newEngines: plantedEngines(func(group sidecar.MlsGroup) sidecar.MlsGroup {
				return &lenientGroup{plantedGroup: group.(*plantedGroup)}
			}, nil),
			catches: caseRefusedMessages,
		},
		{
			name: "a GroupInfo's signature checked but its last byte",
			newEngines: plantedEngines(nil, func(pending sidecar.MlsPendingJoin) sidecar.MlsPendingJoin {
				return &sloppyPending{MlsPendingJoin: pending}
			}),
			catches: caseForgedGroupInfo,
		},
		{
			name: "a commit of another epoch staged",
			newEngines: plantedEngines(func(group sidecar.MlsGroup) sidecar.MlsGroup {
				return &lenientGroup{plantedGroup: group.(*plantedGroup)}
			}, nil),
			catches: caseOtherEpoch,
		},
	}
	for _, c := range planted {
		if err := c.catches(t, c.newEngines); err == nil {
			t.Errorf("%s: the suite passed it", c.name)
		}
		if err := c.catches(t, fakeEngines); err != nil {
			t.Errorf("%s: FakeMls itself fails: %v", c.name, err)
		}
	}
}
