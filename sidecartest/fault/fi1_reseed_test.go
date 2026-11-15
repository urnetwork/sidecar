package fault

// FI-1 and FI-6 over a re-seeded push in parts (QD-818, QD-836), on fi1_test.go's fiWorld: the writer, the repo's
// admin, writes 1,100 files in one push, which goes in parts, and the world's transport turns that push into a
// re-seed, as an admin's device re-seeds a push in parts its mirror kept: each part goes to POST .../reseed as its part
// call, under an admin token, while sidecar.yml's reseed is on, and the device gets that call's answer, its
// EVS_BATCH_RESEED record's place; the seal goes there as the seal call naming those places. evs commits it as a seal
// naming an EVS_BATCH_RESEED record per part, and both oracles read the store clean after every step: the re-seed,
// writes after it that reach its paths through the newest rule, an evacuation 26 h on that moves the parts with their
// seal, and a write after that.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The transport's re-seed of the device's pushes in parts: the part calls and seal calls it sent, and the slot bodies a
// seal carried, which a re-seed returns by slot calls this world does not make.
type fiReseed struct {
	world         *fiWorld
	partCallCount int
	sealCallCount int
	slotBodyCount int
}

// Turns the device's pushes in parts into re-seeds from here on, with sidecar.yml's reseed on.
func (self *fiWorld) reseedPushesInParts() (*fiReseed, error) {
	network := connect.Id(self.networkId).String()
	if err := self.host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  reseed: true\n", network)); err != nil {
		return nil, err
	}
	reseed := &fiReseed{world: self}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.intercept = reseed.serve
	return reseed, nil
}

// Ends the re-seed: the device's requests go to the engine as they are.
func (self *fiWorld) stopReseeding() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.intercept = nil
}

// A part goes to POST .../reseed as its part call (QD-836), and a seal as its seal call naming the places the parts'
// calls answered, each under an admin token, the engine's answer going to the device; everything else to the engine as
// it is. Called on the device call's goroutines: the world's state lock guards the counts.
func (self *fiReseed) serve(request *http.Request, recorder *httptest.ResponseRecorder) bool {
	if request.Method != http.MethodPost || !strings.Contains(request.URL.Path, "/push") {
		return false
	}
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	segments := strings.Split(strings.TrimSuffix(request.URL.Path, "/"), "/")
	var reseed *protocol.EvsReseedRequest
	var repoPath string
	switch {
	case 3 <= len(segments) && segments[len(segments)-3] == "push":
		number, err := strconv.ParseUint(segments[len(segments)-1], 10, 32)
		if err != nil {
			return false
		}
		part := &protocol.EvsPartRequest{}
		if err := proto.Unmarshal(body, part); err != nil {
			return false
		}
		reseed = &protocol.EvsReseedRequest{Statement: part.GetStatement(), Parts: [][]byte{part.GetPart()}, PartNumber: uint32(number)}
		repoPath = strings.Join(segments[:len(segments)-3], "/")
		func() {
			self.world.stateLock.Lock()
			defer self.world.stateLock.Unlock()
			self.partCallCount += 1
		}()
	case segments[len(segments)-1] == "push":
		seal := &protocol.EvsPushRequest{}
		if err := proto.Unmarshal(body, seal); err != nil || len(seal.GetPartPlaces()) == 0 {
			// a one-part push goes to evs as it is
			return false
		}
		reseed = &protocol.EvsReseedRequest{Statement: seal.GetStatement(), PartPlaces: seal.GetPartPlaces()}
		repoPath = strings.Join(segments[:len(segments)-1], "/")
		func() {
			self.world.stateLock.Lock()
			defer self.world.stateLock.Unlock()
			self.sealCallCount += 1
			if 0 < len(seal.GetSlotBodies()) {
				self.slotBodyCount += 1
			}
		}()
	default:
		return false
	}
	reseedBytes, err := proto.Marshal(reseed)
	if err != nil {
		return false
	}
	reseedRequest := httptest.NewRequestWithContext(request.Context(), http.MethodPost, repoPath+"/reseed", bytes.NewReader(reseedBytes))
	reseedRequest.Header.Set("Authorization", "Bearer "+self.world.token([]string{"repo:" + self.world.repoId.String() + ":admin"}))
	self.world.engine.Handler().ServeHTTP(recorder, reseedRequest)
	return true
}

// The part and seal calls sent, and the seals that carried slot bodies.
func (self *fiReseed) counts() (int, int, int) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return self.partCallCount, self.sealCallCount, self.slotBodyCount
}

// The record at place on the repo's cluster, from its batch or, once evacuated, its container.
func (self *fiWorld) recordAt(ctx context.Context, place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
	return evsservice.ReadRecordLocated(ctx, evsservice.NewRecordCache(evsservice.DefaultEvsSettings()), evsservice.NewRecordLocator(self.net.Host().Blobs, nil),
		self.cluster(), self.repoId, self.refId, place)
}

// The re-seeded push at version: a seal whose every part is an EVS_BATCH_RESEED record holding a part's body, and
// how many parts it names.
func (self *fiWorld) requireReseededSeal(ctx context.Context, version uint64) (int, error) {
	head, err := self.head(ctx)
	if err != nil {
		return 0, err
	}
	window, err := evsservice.EvsHeadWindow(head.Head)
	if err != nil {
		return 0, err
	}
	index := int(version - evsservice.EvsHeadWindowFirstVersion(head.Head))
	if index < 0 || len(window) <= index {
		return 0, fmt.Errorf("version %d is not in the window", version)
	}
	seal, err := self.recordAt(ctx, window[index].Place)
	if err != nil {
		return 0, err
	}
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || len(sealParts) < 2 {
		return 0, fmt.Errorf("version %d's record is type %s with %d parts: %v", version, seal.Type, len(sealParts), err)
	}
	for i, sealPart := range sealParts {
		part, err := self.recordAt(ctx, sealPart.Place)
		if err != nil {
			return 0, err
		}
		if !sidecar.EvsReseedRecordHoldsPart(part) {
			return 0, fmt.Errorf("part %d of version %d is type %s", i+1, version, part.Type)
		}
	}
	return len(sealParts), nil
}

// See the file header.
func TestFi1AndFi6ReadAReseededPushInPartsClean(t *testing.T) {
	world := newFiWorld(t)
	var reseed *fiReseed
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			if reseed, err = world.reseedPushesInParts(); err != nil {
				return err
			}
			defer world.stopReseeding()
			writes := []*sidecar.EvsPathWrite{}
			for i := 0; i < 1100; i += 1 {
				content := []byte(fmt.Sprintf("bulk file %d", i))
				writes = append(writes, &sidecar.EvsPathWrite{Path: fmt.Sprintf("bulk/f-%04d", i), Content: bytes.NewReader(content)})
			}
			if err := world.call(ctx, func(ctx context.Context) error {
				_, err := world.device.Repo(world.repoId).WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: writes})
				return err
			}); err != nil {
				return err
			}
			partCount, err := world.requireReseededSeal(ctx, 2)
			if err != nil {
				return err
			}
			partCalls, sealCalls, slotBodies := reseed.counts()
			if partCalls != partCount || sealCalls != 1 || slotBodies != 0 {
				return fmt.Errorf("%d part calls and %d seal calls, %d carrying slot bodies, for %d parts: want a call a part and one seal with none",
					partCalls, sealCalls, slotBodies, partCount)
			}
			return nil
		}},
		{Actor: "writerA", Action: world.write("n/after.txt", 40)},
		{Actor: "writerA", Action: world.write("bulk/f-0007", 30)},
		{Actor: "clock", Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.evacuate},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			if _, err := world.requireReseededSeal(ctx, 2); err != nil {
				return fmt.Errorf("after evacuation: %w", err)
			}
			return world.write("e.txt", 60)(ctx, net)
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi-reseed-parts", Steps: steps, Check: fiChecks()}, world.net)
	fiRequirePass(t, result)
	head, err := world.head(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if head.Version() != 5 {
		t.Fatalf("the run ended at version %d, want 5", head.Version())
	}
	if batches, err := fiKeys(t.Context(), world.cluster(), "pb/"); err != nil || len(batches) != 1 {
		t.Fatalf("evacuation left %d batches but the last write's, %v", len(batches), err)
	}
	if sidecartest.HooksLinked && !fiDecryptRan(world) {
		t.Fatal("with the hooks linked, no named actor held the repo's keys, so the decrypt clause never ran")
	}
}
