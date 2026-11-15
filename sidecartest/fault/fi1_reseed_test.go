package fault

// FI-1 and FI-6 over a re-seeded push in parts (QD-818), on fi1_test.go's fiWorld: the writer, the repo's admin,
// writes 1,100 files in one push, which goes in parts, and the world's transport turns that push into a re-seed, as an
// admin's device re-seeds a push in parts its mirror kept: each part is held rather than posted, and the seal goes to
// POST .../reseed with the parts held, under an admin token, while sidecar.yml's reseed is on. evs commits it as a seal
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

// The transport's re-seed of the device's pushes in parts: each part held by push and part, and the reseed calls sent.
type fiReseed struct {
	world *fiWorld
	// by push id, each part held, by part number less one
	parts       map[sidecar.Id][][]byte
	reseedCount int
}

// Turns the device's pushes in parts into re-seeds from here on, with sidecar.yml's reseed on.
func (self *fiWorld) reseedPushesInParts() (*fiReseed, error) {
	network := connect.Id(self.networkId).String()
	if err := self.host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  reseed: true\n", network)); err != nil {
		return nil, err
	}
	reseed := &fiReseed{world: self, parts: map[sidecar.Id][][]byte{}}
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

// A part is held and answered a place no record has, which the device's seal names and evs never reads; a seal goes
// to POST .../reseed with the parts held, in part order; everything else to the engine as it is. Called on the device
// call's goroutines: the world's state lock guards what it holds.
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
	answer := func(message proto.Message) {
		replyBytes, err := proto.Marshal(message)
		if err != nil {
			recorder.WriteHeader(http.StatusInternalServerError)
			return
		}
		recorder.WriteHeader(http.StatusOK)
		recorder.Write(replyBytes)
	}
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
		statement, err := sidecar.ParseEvsStatement(part.GetStatement())
		if err != nil {
			return false
		}
		pushId := sidecar.Id(statement.Push.GetPushId())
		func() {
			self.world.stateLock.Lock()
			defer self.world.stateLock.Unlock()
			held := self.parts[pushId]
			for len(held) < int(statement.Push.GetPartCount()) {
				held = append(held, nil)
			}
			if 0 < number && int(number) <= len(held) {
				held[number-1] = part.GetPart()
			}
			self.parts[pushId] = held
		}()
		answer(&protocol.EvsPushReply{Place: &protocol.EvsPlace{Minute: uint32(number)}})
		return true
	case segments[len(segments)-1] == "push":
		seal := &protocol.EvsPushRequest{}
		if err := proto.Unmarshal(body, seal); err != nil || len(seal.GetPartPlaces()) == 0 {
			// a one-part push goes to evs as it is
			return false
		}
		statement, err := sidecar.ParseEvsStatement(seal.GetStatement())
		if err != nil {
			return false
		}
		var parts [][]byte
		func() {
			self.world.stateLock.Lock()
			defer self.world.stateLock.Unlock()
			parts = self.parts[sidecar.Id(statement.Push.GetPushId())]
			self.reseedCount += 1
		}()
		reseedBytes, err := proto.Marshal(&protocol.EvsReseedRequest{Statement: seal.GetStatement(), Parts: parts})
		if err != nil {
			return false
		}
		path := strings.TrimSuffix(request.URL.Path, "/push") + "/reseed"
		reseedRequest := httptest.NewRequestWithContext(request.Context(), http.MethodPost, path, bytes.NewReader(reseedBytes))
		reseedRequest.Header.Set("Authorization", "Bearer "+self.world.token([]string{"repo:" + self.world.repoId.String() + ":admin"}))
		self.world.engine.Handler().ServeHTTP(recorder, reseedRequest)
		return true
	}
	return false
}

// The record at place on the repo's cluster, from its batch or, once evacuated, its container.
func (self *fiWorld) recordAt(ctx context.Context, place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
	return evsservice.ReadRecordLocated(ctx, evsservice.NewRecordCache(evsservice.DefaultEvsSettings()), evsservice.NewRecordLocator(self.net.Host().Blobs, nil),
		self.cluster(), self.repoId, self.refId, place)
}

// The re-seeded push at version: a seal whose every part is an EVS_BATCH_RESEED record holding a part's body.
func (self *fiWorld) requireReseededSeal(ctx context.Context, version uint64) error {
	head, err := self.head(ctx)
	if err != nil {
		return err
	}
	window, err := evsservice.EvsHeadWindow(head.Head)
	if err != nil {
		return err
	}
	index := int(version - evsservice.EvsHeadWindowFirstVersion(head.Head))
	if index < 0 || len(window) <= index {
		return fmt.Errorf("version %d is not in the window", version)
	}
	seal, err := self.recordAt(ctx, window[index].Place)
	if err != nil {
		return err
	}
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || len(sealParts) < 2 {
		return fmt.Errorf("version %d's record is type %s with %d parts: %v", version, seal.Type, len(sealParts), err)
	}
	for i, sealPart := range sealParts {
		part, err := self.recordAt(ctx, sealPart.Place)
		if err != nil {
			return err
		}
		if !sidecar.EvsReseedRecordHoldsPart(part) {
			return fmt.Errorf("part %d of version %d is type %s", i+1, version, part.Type)
		}
	}
	return nil
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
			if reseed.reseedCount != 1 {
				return fmt.Errorf("%d reseed calls, want the push in parts' one", reseed.reseedCount)
			}
			return world.requireReseededSeal(ctx, 2)
		}},
		{Actor: "writerA", Action: world.write("n/after.txt", 40)},
		{Actor: "writerA", Action: world.write("bulk/f-0007", 30)},
		{Actor: "clock", Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.evacuate},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			if err := world.requireReseededSeal(ctx, 2); err != nil {
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
