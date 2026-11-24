//go:build !sidecar_http

// The team directory's cards read holds this device's reads to its own pushes as every evs read does
// (directory_evs.go's cards row; evs_read.go's own pushes row), on T2: what a fresh reply shows of them is noted only
// once the read's own walk reaches its head and pins it, or the head is the version the copy verified. Before this
// change the reply was noted as it arrived, so one evs forged below the device's push lowered the floor though the
// read refused it.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// evs as a misbehaving one answers one client's fresh reads: armed, a fresh POST .../read is answered with the forged
// head alone, and never reaches evs; every other request goes on through transport. It counts the fresh reads it saw.
type directoryEvsFreshForger struct {
	transport http.RoundTripper

	stateLock  sync.Mutex
	forged     *protocol.EvsHeadSummary
	freshCount int
}

// Answers every fresh read from now on with head; nil lets them through again.
func (self *directoryEvsFreshForger) arm(head *protocol.EvsHeadSummary) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forged = head
}

// How many fresh reads the forger has seen.
func (self *directoryEvsFreshForger) fresh() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.freshCount
}

func (self *directoryEvsFreshForger) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") {
		return self.transport.RoundTrip(request)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	read := &protocol.EvsReadRequest{}
	if err := proto.Unmarshal(body, read); err != nil {
		return nil, err
	}
	forged := func() *protocol.EvsHeadSummary {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !read.GetFresh() {
			return nil
		}
		self.freshCount += 1
		return self.forged
	}()
	if forged == nil {
		return self.transport.RoundTrip(request)
	}
	answer := httptest.NewRecorder()
	answer.WriteHeader(http.StatusOK)
	for _, frame := range []*protocol.EvsReadFrame{{Head: forged}, {End: true}} {
		encoded, err := sidecar.EncodeEvsReadFrame(frame)
		if err != nil {
			return nil, err
		}
		answer.Write(encoded)
	}
	return answer.Result(), nil
}

// A card writer whose push committed above what evs's cluster holds of the cards ref, as a site loss leaves it before
// its reseed: a fresh reply evs forged below the push, a head past the copy's that no statement chains to, is refused
// and leaves the floor at the push. evs answering truly, a read from before the head walks to it and pins it, which
// lowers the floor to it; after another push the cluster lost, a read from the head the copy holds finds that head
// again, which lowers it once more; and the reads after it go through the cache, none fresh. It fails with the reply
// noted as it arrived (the floor falls to the forged head), and with the cards read noting nothing (the floor stays at
// the push).
func TestDirectoryEvsCardsOwnFloorMovesOnlyOnAVerifiedHead(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	client := directory.client(directory.writers[0])
	forger := &directoryEvsFreshForger{}
	client.WrapTransportForTest(func(transport http.RoundTripper) http.RoundTripper {
		forger.transport = transport
		return forger
	})
	cards := directory.binding(t, client, nil)
	notices := directoryEvsNoticePaths(t, 1)
	write := &sidecar.DirectoryCardWrite{PushId: sidecar.NewId(), Path: notices[0], Content: []byte("a"), AuthPin: directory.world.Pin()}
	if _, err := cards.PutCard(ctx, directory.directoryId, write); err != nil {
		t.Fatal(err)
	}
	held, err := cards.ReadCards(ctx, directory.directoryId, 0)
	if err != nil || len(held.Files) != 1 {
		t.Fatalf("the first read: %+v %v", held, err)
	}
	head := held.HeadVersion
	refId, err := client.Repo(directory.directoryId).RefIdOf(ctx, sidecar.DirectoryCardsRefName())
	if err != nil {
		t.Fatal(err)
	}
	client.NoteCommittedForTest(directory.directoryId, refId, head+8)
	chain := sha256.Sum256([]byte("a chain evs forged"))
	forger.arm(&protocol.EvsHeadSummary{RefId: refId.Bytes(), Version: head + 4, Chain: chain[:]})
	if _, err := cards.ReadCards(ctx, directory.directoryId, head); !errors.Is(err, sidecar.ErrEvsChainBroken) {
		t.Fatalf("the read of a forged reply: %v", err)
	}
	if floor := client.OwnFloorForTest(directory.directoryId, refId); floor != head+8 {
		t.Errorf("held to %d after the forged reply, not the push's %d", floor, head+8)
	}
	forger.arm(nil)
	// from before the head: walked to it and pinned
	fresh := forger.fresh()
	changes, err := cards.ReadCards(ctx, directory.directoryId, 0)
	if err != nil || changes.HeadVersion != head || len(changes.Files) != 1 {
		t.Fatalf("the true read from before the head: %+v %v", changes, err)
	}
	if got := forger.fresh() - fresh; got != 1 {
		t.Errorf("the true read from before the head went fresh %d times, not once", got)
	}
	if floor := client.OwnFloorForTest(directory.directoryId, refId); floor != head {
		t.Errorf("held to %d after the head walked to, not %d", floor, head)
	}
	// from the head the copy holds, after another push the cluster lost
	client.NoteCommittedForTest(directory.directoryId, refId, head+16)
	fresh = forger.fresh()
	if changes, err := cards.ReadCards(ctx, directory.directoryId, head); err != nil || changes.HeadVersion != head || len(changes.Files) != 0 {
		t.Fatalf("the true read from the head: %+v %v", changes, err)
	}
	if got := forger.fresh() - fresh; got != 1 {
		t.Errorf("the true read from the head went fresh %d times, not once", got)
	}
	if floor := client.OwnFloorForTest(directory.directoryId, refId); floor != head {
		t.Errorf("held to %d after the head the copy holds, not %d", floor, head)
	}
	fresh = forger.fresh()
	if changes, err := cards.ReadCards(ctx, directory.directoryId, head); err != nil || changes.HeadVersion != head {
		t.Fatalf("a later read: %+v %v", changes, err)
	}
	if got := forger.fresh() - fresh; got != 0 {
		t.Errorf("a later read went fresh %d times", got)
	}
}
