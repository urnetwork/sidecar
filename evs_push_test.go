// EVS1-M2-26's tests: FS-1's client side, a dropped answer's retry returning the original version; each refusal
// retried with the same statement, rebuilt under a new push id, or returned to the caller; a push in parts, a kill
// between its parts committing nothing, and PARTS_MISSING's repost; and EVS_GIT_REF on a git-mode ref (§22.5).

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The push ids of the statements posted, in order.
func (self *evsTestPushServer) postedPushIds(t *testing.T) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pushIds := []Id{}
	for _, statementBytes := range self.postedStatements {
		statement, err := ParseEvsStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		pushIds = append(pushIds, Id(statement.Push.GetPushId()))
	}
	return pushIds
}

// FS-1's client side: the commit's answer is lost as a 503 of unknown outcome, the client retries the same statement,
// and evs's 5a answers the original version; one commit.
func TestEvsPushRetryAfterALostAnswerReturnsTheOriginalVersion(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.dropAnswers = 1
	result, err := writer.write(t, "a.txt", []byte("content a"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || len(writer.world.commits) != 1 {
		t.Fatalf("version %d after %d commits", result.Version, len(writer.world.commits))
	}
	posted := writer.server.postedStatements
	if len(posted) != 2 || !bytes.Equal(posted[0], posted[1]) {
		t.Fatalf("%d posts, the retry's bytes the first's: %t", len(posted), len(posted) == 2 && bytes.Equal(posted[0], posted[1]))
	}
	if result.PushId != writer.server.postedPushIds(t)[0] {
		t.Error("the result names another push")
	}
}

// A 429 (TIME_AHEAD's among them) and a 503 refuse nothing: the same statement goes again after each one's wait.
func TestEvsPushRetriesWhatRefusesNothingWithTheSameStatement(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.pushRefusals = []*evsTestRefusal{
		{status: http.StatusTooManyRequests, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD, RetryAfterMs: 1500}},
		{status: http.StatusTooManyRequests, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BUSY, RetryAfterMs: 20}},
		{status: http.StatusServiceUnavailable, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE}},
	}
	if _, err := writer.write(t, "a.txt", []byte("content a")); err != nil {
		t.Fatal(err)
	}
	posted := writer.server.postedStatements
	if len(posted) != 4 {
		t.Fatalf("%d posts", len(posted))
	}
	for _, statement := range posted[1:] {
		if !bytes.Equal(statement, posted[0]) {
			t.Fatal("a retry under another statement")
		}
	}
	waits := writer.test.clock.waited()
	if len(waits) < 3 || waits[len(waits)-3] != 1500*time.Millisecond || waits[len(waits)-2] != 20*time.Millisecond {
		t.Errorf("waits %v", waits)
	}
}

// Each refusal that asks for a rebuild builds the push again under a new push id, from a fresh read, its segments
// uploaded again; GATE_CLOSED asks gkm for a writable generation again first. 412 PATH_EPOCH is a retoken's
// (evs_epoch_test.go).
func TestEvsPushRebuildsUnderANewPushId(t *testing.T) {
	cases := []struct {
		status int
		code   protocol.EvsRefusalCode
	}{
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE},
		{status: http.StatusPreconditionFailed, code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED},
	}
	for _, c := range cases {
		writer := newEvsTestWriter(t)
		writer.server.pushRefusals = []*evsTestRefusal{{status: c.status, reply: &protocol.EvsRefusalReply{Code: c.code, Recorded: true}}}
		result, err := writer.write(t, "big.txt", evsTestContent("rebuild", 64*1024))
		if err != nil {
			t.Errorf("%s: %v", c.code, err)
			continue
		}
		pushIds := writer.server.postedPushIds(t)
		if len(pushIds) != 2 || pushIds[0] == pushIds[1] || result.PushId != pushIds[1] {
			t.Errorf("%s: push ids %v", c.code, pushIds)
		}
		if len(writer.server.uploads) != 2 {
			t.Errorf("%s: %d uploads", c.code, len(writer.server.uploads))
		}
		if writer.gkm.ensured != 2 {
			t.Errorf("%s: EnsureWritable %d times", c.code, writer.gkm.ensured)
		}
		if read, _, err := writer.read(t, "big.txt"); err != nil || !bytes.Equal(read, evsTestContent("rebuild", 64*1024)) {
			t.Errorf("%s: read back: %v", c.code, err)
		}
	}
	// past PushRebuildCount the refusal goes back
	writer := newEvsTestWriter(t)
	for range writer.test.client.settings.PushRebuildCount + 1 {
		writer.server.pushRefusals = append(writer.server.pushRefusals, &evsTestRefusal{status: http.StatusConflict,
			reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE}})
	}
	if _, err := writer.write(t, "a.txt", []byte("a")); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE) {
		t.Errorf("past the rebuild bound: %v", err)
	}
}

// A file-mode 409 with paths, and every other refusal a rebuild does not answer, goes back to the caller after one
// post; a creation's 409 is planned once more from a fresh read, which a standing path does not survive.
func TestEvsPushReturnsOtherRefusals(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "a.txt", []byte("a")); err != nil {
		t.Fatal(err)
	}
	conflictPath := writer.world.tokens("a.txt")
	cases := []struct {
		status int
		code   protocol.EvsRefusalCode
	}{
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE},
		{status: http.StatusForbidden, code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE},
		{status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL},
	}
	for _, c := range cases {
		posted := len(writer.server.postedStatements)
		writer.server.pushRefusals = []*evsTestRefusal{{status: c.status, reply: &protocol.EvsRefusalReply{
			Code: c.code, Paths: []*protocol.EvsTokenPath{conflictPath.Proto()},
		}}}
		_, err := writer.write(t, "a.txt", []byte(fmt.Sprint("a ", c.code)))
		evsError, ok := EvsErrorOf(err)
		if !ok || evsError.Code != c.code {
			t.Errorf("%s: %v", c.code, err)
			continue
		}
		if c.code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT && (len(evsError.Paths) != 1 || !evsError.Paths[0].Equal(conflictPath)) {
			t.Errorf("the 409 names %v", evsError.Paths)
		}
		if got := len(writer.server.postedStatements) - posted; got != 1 {
			t.Errorf("%s: %d posts", c.code, got)
		}
	}
	// a creation's 409: planned again, and committed, while the path still does not stand
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}}}
	posted := len(writer.server.postedStatements)
	if _, err := writer.write(t, "new.txt", []byte("new")); err != nil {
		t.Errorf("a creation's 409 planned again: %v", err)
	}
	if got := len(writer.server.postedStatements) - posted; got != 2 {
		t.Errorf("a creation's 409: %d posts", got)
	}
}

// A push past 1,024 entry writes goes in parts and a seal; a kill between its parts commits nothing, and the next
// write commits every file; a seal answered PARTS_MISSING posts the parts again and seals the same push id again.
func TestEvsPushInPartsWithAKillBetweenParts(t *testing.T) {
	writer := newEvsTestWriter(t)
	const fileCount = 1100
	writes := []*EvsPathWrite{}
	for i := 0; i < fileCount; i += 1 {
		path := fmt.Sprintf("file-%04d.txt", i)
		writer.server.know(path)
		writes = append(writes, &EvsPathWrite{Path: path, Content: bytes.NewReader([]byte(path))})
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer.server.onPart = func(k uint32) {
		if k == 2 {
			cancel()
		}
	}
	if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: writes}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a write killed between its parts: %v", err)
	}
	if len(writer.world.commits) != 0 || len(writer.server.postedStatements) != 0 {
		t.Fatal("a killed push committed or sealed")
	}
	writer.server.onPart = nil
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING}}}
	parts := len(writer.server.postedParts)
	result, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: writes})
	if err != nil {
		t.Fatal(err)
	}
	pushIds := writer.server.postedPushIds(t)
	if len(pushIds) != 2 || pushIds[0] != pushIds[1] || result.Version != 1 || len(result.PathVersions) != fileCount {
		t.Fatalf("seals %v, version %d", pushIds, result.Version)
	}
	if got := len(writer.server.postedParts) - parts; got != 4 {
		t.Errorf("%d parts posted for two parts sealed twice", got)
	}
	statement, err := ParseEvsStatement(writer.server.postedStatements[1])
	if err != nil || statement.Push.GetPartCount() != 2 {
		t.Fatalf("the statement's parts: %v", err)
	}
	for _, i := range []int{0, 1023, 1024, fileCount - 1} {
		path := fmt.Sprintf("file-%04d.txt", i)
		if read, _, err := writer.read(t, path); err != nil || string(read) != path {
			t.Errorf("%s read back: %v", path, err)
		}
	}
}

// §22.5: a head-mode write to a git-mode ref is EVS_GIT_REF, and nothing is posted.
func TestEvsWriteGitModeRefIsEvsGitRef(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	writer.world.push(&evsTestChange{path: "tree.txt", content: []byte("tree")})
	if _, err := writer.write(t, "tree.txt", []byte("head mode")); !errors.Is(err, ErrEvsGitRef) {
		t.Fatalf("a git-mode ref: %v", err)
	}
	if len(writer.server.postedStatements) != 0 || len(writer.server.uploads) != 0 {
		t.Error("a git-mode write sent something")
	}
}

// Cuts the world over to each epoch of epochs in turn, one at each push that arrives, the old current epoch listed
// first among its sources, as a PATH_EPOCH commit lists it.
func (self *evsTestWriter) cutOverAtPushes(epochs ...uint64) {
	next := 0
	self.server.onPush = func(statement *EvsStatement) {
		if len(epochs) <= next {
			return
		}
		world := self.world
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.sourceEpochs = append([]uint64{max(1, world.currentEpoch)}, world.sourceEpochs...)
		world.currentEpoch = epochs[next]
		next += 1
	}
}

// The checked payload of a committed version.
func (self *evsTestWriter) committedPayload(t *testing.T, version uint64) (*EvsStatement, *EvsCheckedPayload) {
	t.Helper()
	commit := self.world.commits[version-1]
	checked, err := EvsCheckPayload(commit.parsed, commit.built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return commit.parsed, checked
}

// The epochs and token paths a change's source paths name.
func evsTestSourcePaths(t *testing.T, change *EvsCheckedChange) map[uint64]EvsTokenPath {
	t.Helper()
	sources := map[uint64]EvsTokenPath{}
	for _, encoded := range change.SourcePaths {
		sourcePath := &protocol.EvsSourcePath{}
		if err := proto.Unmarshal(encoded, sourcePath); err != nil {
			t.Fatal(err)
		}
		tokenPath, err := ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		sources[sourcePath.GetEpoch()] = tokenPath
	}
	return sources
}

// A push refused 412 PATH_EPOCH is re-tokenized on the new head and sent again under a new push id with every sealed
// byte kept: one upload, one EnsureWritable, the chain naming the one segment; its change names the path in the new
// epoch and, as a source, in the epoch the refused push showed it in, and the root's row is sealed in the new epoch
// (DESIGN-DETAILS 9.2.5; 9.6's K and C).
func TestEvsPushRetokenKeepsWhatItSealed(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.gkm.newest = 2
	writer.world.generation = 2
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	writer.cutOverAtPushes(2)
	content := evsTestContent("retoken", 64*1024)
	result, err := writer.write(t, "big.txt", content)
	if err != nil {
		t.Fatal(err)
	}
	pushIds := writer.server.postedPushIds(t)
	if len(pushIds) != 2 || pushIds[0] == pushIds[1] || result.PushId != pushIds[1] {
		t.Fatalf("push ids %v, the result's %v", pushIds, result.PushId)
	}
	if len(writer.server.uploads) != 1 || writer.gkm.ensured != 1 {
		t.Fatalf("%d uploads and %d EnsureWritable calls for one retoken", len(writer.server.uploads), writer.gkm.ensured)
	}
	refused, err := ParseEvsStatement(writer.server.postedStatements[0])
	if err != nil {
		t.Fatal(err)
	}
	statement, checked := writer.committedPayload(t, result.Version)
	if refused.Push.GetPathEpoch() != 1 || statement.Push.GetPathEpoch() != 2 || statement.Push.GetGeneration() != 2 {
		t.Fatalf("epochs %d then %d", refused.Push.GetPathEpoch(), statement.Push.GetPathEpoch())
	}
	keys := evsTestKeys(t, writer.world.repoId, 2)
	for _, change := range checked.Changes {
		sources := evsTestSourcePaths(t, change)
		switch {
		case change.TokenPath.Equal(writer.world.tokensAt("big.txt", 2)):
			if len(sources) != 1 || !sources[1].Equal(writer.world.tokensAt("big.txt", 1)) {
				t.Errorf("the file's source paths %v", sources)
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
				t.Fatal(err)
			}
			if entry.GetVersion() != 1 || entry.GetBaseVersion() != 0 || len(entry.GetChain()) != 1 ||
				hex.EncodeToString(entry.GetChain()[0].GetId()) != writer.server.uploads[0] {
				t.Errorf("the entry: version %d on %d, its chain %v", entry.GetVersion(), entry.GetBaseVersion(), entry.GetChain())
			}
		case len(change.TokenPath) == 0:
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
				t.Fatal(err)
			}
			opened, err := EvsOpenNameTable(entry.GetNames(), 2, func(epoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
				return keys.manifest, evsTestPathKey(t, writer.world.repoId, epoch), EvsRootToken, nil
			})
			if err != nil || len(opened) != 1 || string(opened[0].Name) != "big.txt" || opened[0].Token != writer.world.tokensAt("big.txt", 2).Last() {
				t.Errorf("the root's row in epoch 2: %v", err)
			}
		default:
			t.Errorf("a change of another path")
		}
	}
	if read, _, err := writer.read(t, "big.txt"); err != nil || !bytes.Equal(read, content) {
		t.Fatalf("read back: %v", err)
	}
}

// A retoken that meets a second cut-over is re-tokenized again, each time by the floors the refusals lowered: the
// path names both listed sources the third time.
func TestEvsPushRetokenAcrossTwoCutOvers(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.gkm.newest = 3
	writer.world.generation = 3
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	writer.cutOverAtPushes(2, 3)
	result, err := writer.write(t, "big.txt", evsTestContent("two cut-overs", 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	if posted := writer.server.postedPushIds(t); len(posted) != 3 || len(writer.server.uploads) != 1 {
		t.Fatalf("%d posts and %d uploads", len(posted), len(writer.server.uploads))
	}
	statement, checked := writer.committedPayload(t, result.Version)
	if statement.Push.GetPathEpoch() != 3 {
		t.Fatalf("committed in epoch %d", statement.Push.GetPathEpoch())
	}
	for _, change := range checked.Changes {
		if !change.TokenPath.Equal(writer.world.tokensAt("big.txt", 3)) {
			continue
		}
		sources := evsTestSourcePaths(t, change)
		if len(sources) != 2 || !sources[2].Equal(writer.world.tokensAt("big.txt", 2)) || !sources[1].Equal(writer.world.tokensAt("big.txt", 1)) {
			t.Errorf("source paths %v", sources)
		}
	}
}

// A retoken keeps a segment's receipt only under RetokenReceiptMaxAge and uploads the segment again past it, since evs
// adopts an upload only under 24 h old.
func TestEvsPushRetokenUploadsAgainPastTheReceiptAge(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.gkm.newest = 2
	writer.world.generation = 2
	writer.server.uploadMs = writer.test.clock.Now().Add(-23 * time.Hour).UnixMilli()
	writer.cutOverAtPushes(2)
	if _, err := writer.write(t, "big.txt", evsTestContent("old receipt", 64*1024)); err != nil {
		t.Fatal(err)
	}
	if uploads := writer.server.uploads; len(uploads) != 2 || uploads[0] != uploads[1] {
		t.Fatalf("uploads %v", uploads)
	}
}

// Retokens count against PushRebuildCount with rebuilds: past it, 412 PATH_EPOCH goes back to the caller.
func TestEvsPushRetokenBound(t *testing.T) {
	writer := newEvsTestWriter(t)
	count := writer.test.client.settings.PushRebuildCount
	epochs := []uint64{}
	for i := range count + 1 {
		epochs = append(epochs, uint64(i+2))
	}
	writer.gkm.newest = uint64(count + 2)
	writer.world.generation = uint64(count + 2)
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	writer.cutOverAtPushes(epochs...)
	if _, err := writer.write(t, "a.txt", []byte("a")); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH) {
		t.Fatalf("past the bound: %v", err)
	}
	if posted := writer.server.postedPushIds(t); len(posted) != count+1 {
		t.Fatalf("%d posts for a bound of %d", len(posted), count)
	}
}
