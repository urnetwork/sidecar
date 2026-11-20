// FS-91's races (a), (b) and (c)'s cached head (§22.8; §11.7's fence row, §11.8's step 4 and 5h, §11.9's cache row,
// §11.13's mark row, FI-2, FI-27; EVS2-M10-31, QD-1146) on the evs world with its drop wiring (evs_world_drop.go): a
// reuse copy racing the DROP that lists its source. x.txt has three versions on main, each its own segment; a
// writer's push on ref r2 creates a file as a copy of x.txt's first version, naming it as its reuse source and citing
// its segment, and in (a) and (b) is held on its instance after step 4 validated it (evs.push.step4.after), the DROP
// of x.txt's history going through the other instance.
//
//	(a)  Fs91ReleasedBeforeTheDrop: the copy is released before the DROP commits, and commits. The DROP then commits
//	     and its job runs: mark finds r2's version and keeps the segment it shares with x.txt's first version, while
//	     the segments only x.txt's second and third versions name go (the drop writes its kept head again)
//	(b)  Fs91ReleasedAfterTheDrop, the registered case: the DROP commits while the copy is held; released more than
//	     §11.8's 5 s after its validation, the copy's step 7 reruns 5h and is refused 409 DROPPED. Nothing names the
//	     listed versions' segments beyond the drop's list, and the job deletes both. Its twin is (a)
//	     Fs91ReleasedWithinTheWindow: the DROP commits while the copy is held; released 2 s on, within the window, its
//	     step 7 reruns nothing and it commits after the DROP, naming a listed version as its reuse source (QD-1105).
//	     mark, run past evacuation's horizon, finds r2's version and keeps the shared segment, as in (a), and FI-27
//	     lets the copy through on its arrival before the DROP's head write and its own within the window; read with a
//	     window of 1 s the same run is a violation, and so is it with the ledger's record of the copy's push moved
//	     past the DROP's head write, a push validated after the fence (fs91_test.go)
//	(c)  Fs91ValidatedOnACachedHead: the DROP's write of main's {evsh_} entry fails (a Redis write refused before it
//	     applies), so the cache keeps main's head from before the DROP; 2 min on, within the cache's 10 min of that
//	     head's write, the copy is posted, and its step 4 takes main's head from the cache (QD-701), validates on it
//	     after the DROP committed and commits, naming a listed version as its reuse source. FI-27 lets it through on
//	     the Net's record of that cached read (QD-1146), and mark, run past evacuation's horizon, finds r2's version
//	     and keeps the shared segment, as in (a); read with a cache age of 1 min the same run is a violation where
//	     the copy commits, and so is it with the ledger's record of the copy's arrival moved past its reads, a push
//	     validated on the cluster's head, which shows the DROP (fs91_test.go)
//
// Where the copy committed, (a), the within-window order and (c), the reader then reads its version through evs's read
// route after evacuation and the drop's deletes (fs91ReadsTheCopy): the entry, citing x.txt's first version's
// segment, and that segment's bytes, which the route withholds for anything a drop's job deleted or holds.
//
// The copy is a hand-built push (EvsWorld.PostPlan, ReuseFill): the client's planner writes a reuse list only from a
// git tier's publish. Not built: (c)'s copy creating its ref with its head write held at the store past 26 h, and its
// cache entry put 11 min after its head's write, never served (evsservice's TestHeadCacheStampsTheHeadsWrittenMs holds
// that on the engine, and fi27_test.go holds FI-27's side of it); a push in parts sealed after the drop, (d)
// (evsservice's TestPushDroppedRefusesASealAfterTheDrop holds the seal's refusal on the engine); a re-upload adopting a
// young candidate's receipt, (e); and a git-mode push carrying a candidate's bytes, (f).

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs91Case = Register("FS-91", "", []Tier{TierT2, TierT3}, Fs91ReleasedAfterTheDrop)

// The ref the copy is pushed on.
var fs91CopyRef = []byte("r2")

// The label of the copy's hand-built path (evsWorldHandPath).
const fs91CopyLabel = "copy of x.txt"

// When the held copy is released, against the DROP that lists its source, or, for fs91ValidatedOnACachedHead, that
// it is posted after the DROP committed and is held nowhere.
type fs91Release int

const (
	fs91ReleaseBeforeTheDrop fs91Release = iota + 1
	fs91ReleaseWithinTheWindow
	fs91ReleasePastTheWindow
	fs91ValidatedOnACachedHead
)

// See the file header.
func Fs91ReleasedAfterTheDrop(net *Net) *Schedule {
	schedule := fs91Schedule(net, fs91ReleasePastTheWindow, nil)
	schedule.Refuses = "a reuse copy of a version a DROP lists, released past 5 s after the DROP committed"
	schedule.Twin = Fs91ReleasedBeforeTheDrop
	return schedule
}

// See the file header.
func Fs91ReleasedBeforeTheDrop(net *Net) *Schedule {
	return fs91Schedule(net, fs91ReleaseBeforeTheDrop, nil)
}

// See the file header.
func Fs91ReleasedWithinTheWindow(net *Net) *Schedule {
	return fs91Schedule(net, fs91ReleaseWithinTheWindow, nil)
}

// See the file header.
func Fs91ValidatedOnACachedHead(net *Net) *Schedule {
	return fs91Schedule(net, fs91ValidatedOnACachedHead, nil)
}

// The schedule of the order released, with the steps afterCommit gives, when it is not nil, run right after the check
// of a committed copy's 200: a test's own steps, given the world and the copy's answer.
func fs91Schedule(net *Net, released fs91Release, afterCommit func(world *EvsWorld, posted *EvsWorldPosted) []*Step) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	posted := &EvsWorldPosted{}
	// x.txt's versions as each write committed them, kept for the segments they name
	versions := []*EvsWorldCommittedEntry{}
	keep := func(ctx context.Context, net *Net) error {
		entry, err := world.CommittedEntry("admin", "x.txt")
		if err != nil {
			return err
		}
		versions = append(versions, entry)
		return nil
	}
	version := func(ordinal int) func() (*EvsWorldCommittedEntry, error) {
		return func() (*EvsWorldCommittedEntry, error) {
			if len(versions) < ordinal {
				return nil, errors.New("x.txt's writes did not all commit")
			}
			return versions[ordinal-1], nil
		}
	}
	segments := func(ordinal int) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			entry, err := version(ordinal)()
			if err != nil {
				return nil, err
			}
			return entry.SegmentIds(), nil
		}
	}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	for ordinal := 1; ordinal <= 3; ordinal += 1 {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropWritten("x.txt", ordinal, fsDropUploadContent))},
			{Actor: "check", Action: keep},
		}...)
	}
	release := &Step{Release: []string{sidecartest.ActorBarrierSite("evs2", evsservice.BarrierPushStep4After)}}
	join := &Step{Actor: "writer", Join: true}
	drop := &Step{Actor: "admin", Action: world.Drop("admin", "x.txt", true)}
	post := world.PostPlan("writer", fs91CopyRef, posted, world.ReuseFill(fs91CopyLabel, version(1)))
	committed := []*Step{{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusOK, 0)}}
	if afterCommit != nil {
		committed = append(committed, afterCommit(world, posted)...)
	}
	// r2's first write, which in (a) and (b) passes evs2's step 4 first
	steps = append(steps, &Step{Actor: "writer", Action: world.WriteRef("writer", fs91CopyRef, "seed.txt", fsDropUploadContent("fs91 seed"))})
	if released != fs91ValidatedOnACachedHead {
		steps = append(steps, []*Step{
			{Actor: "writer", Action: post, Background: true},
			{Actor: "evs2", Await: evsservice.BarrierPushStep4After, AwaitSkip: 1},
		}...)
	}
	switch released {
	case fs91ValidatedOnACachedHead:
		steps = append(steps, []*Step{
			// the DROP's step 8 fails its write of main's {evsh_} entry, so the cache keeps x.txt's third version's head
			{Fault: &FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: evsservice.HeadCacheKey(world.RepoId), Result: FailBeforeApply, Actor: "evs1", WritesOnly: true}},
			drop,
			// within §11.9's 10 min of the cached head's write, so the cache serves it, and past the 1 min age
			// fs91_test.go reads the run with to hold the cached read to its age
			{Advance: 2 * time.Minute},
			// validated after the DROP committed, against the cached head below it
			{Actor: "writer", Action: post},
		}...)
		steps = append(steps, committed...)
	case fs91ReleaseBeforeTheDrop:
		steps = append(steps, release, join)
		steps = append(steps, committed...)
		steps = append(steps, drop)
	case fs91ReleaseWithinTheWindow:
		steps = append(steps, drop, &Step{Advance: 2 * time.Second}, release, join)
		steps = append(steps, committed...)
	default:
		steps = append(steps, drop, &Step{Advance: 6 * time.Second}, release, join,
			&Step{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED)})
	}
	// a copy that committed keeps the segment it shares with x.txt's first version
	copied := released != fs91ReleasePastTheWindow
	steps = append(steps, &Step{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})})
	executed := []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		// what r2's copy names stays; what only listed versions name goes
		{Actor: "check", Action: world.ExpectSegments("x.txt's first version, which r2's copy cites", copied, segments(1))},
		{Actor: "check", Action: world.ExpectSegments("x.txt's second version", false, segments(2))},
		// the head the drop keeps is its own rewrite, uploaded again: the version it replaced is listed, and goes
		{Actor: "check", Action: world.ExpectSegments("x.txt's third version", false, segments(3))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
	}
	if copied {
		// the copy's version reads after evacuation and the drop's deletes, the segment it shares included
		executed = append(executed, &Step{Actor: "reader", Action: fs91ReadsTheCopy(world, "reader", posted, version(1))})
	}
	executed = append(executed, []*Step{
		// the evacuation fenced r2's head for a refused copy's record: a push arriving within the fence's margin of
		// it ends unknown, so the ref's next write comes after it
		{Advance: time.Hour},
		{Actor: "writer", Action: world.WriteRef("writer", fs91CopyRef, "after.txt", fsDropUploadContent("fs91 after"))},
	}...)
	steps = append(steps, fsDropExecute(net, world, executed...)...)
	return &Schedule{Id: "FS-91", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: device reads the copy on r2 through evs's read route by its token path, which names nothing a reader
// can open (evsWorldHandPath), with ranges of the segments source's entry names: the path must answer the version
// posted's 200 committed, its entry naming those segments, and each range must come back whole as the segment
// cluster holds it, never missing, as the route answers a segment a drop's job deleted or holds.
func fs91ReadsTheCopy(world *EvsWorld, device string, posted *EvsWorldPosted, source func() (*EvsWorldCommittedEntry, error)) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		cited, err := source()
		if err != nil {
			return err
		}
		worldDevice := world.Device(device)
		refId, err := worldDevice.Repo.RefIdOf(ctx, fs91CopyRef)
		if err != nil {
			return err
		}
		head, _, _, err := world.newestStatement(ctx, refId)
		if err != nil {
			return err
		}
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		segmentIds := cited.SegmentIds()
		stored := map[string][]byte{}
		ranges := []*protocol.EvsReadRange{}
		for _, segmentId := range segmentIds {
			object, err := cluster.Get(sidecartest.InspectContext(ctx), evsservice.SegmentKey(world.RepoId, [32]byte(segmentId)))
			if err != nil {
				return fmt.Errorf("the copy's segment %x: %w", segmentId, err)
			}
			segmentBytes, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			stored[string(segmentId)] = segmentBytes
			ranges = append(ranges, &protocol.EvsReadRange{SegmentId: segmentId, Length: uint32(len(segmentBytes))})
		}
		tokenPath := evsWorldHandPath(fs91CopyLabel)
		frames, err := fs91Read(ctx, world, worldDevice, &protocol.EvsReadRequest{
			RefId: refId.Bytes(), Fresh: true, Ranges: ranges,
			Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: evsservice.EvsHeadCurrentEpoch(head), TokenPath: tokenPath.Components()}}}},
		})
		if err != nil {
			return fmt.Errorf("%s's read of the copy: %w", device, err)
		}
		var version *protocol.EvsIndexVersion
		read := map[string][]byte{}
		for _, frame := range frames {
			if path := frame.GetPath(); path != nil {
				version = path.GetVersion()
			}
			object := frame.GetObject()
			if object == nil || object.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT {
				continue
			}
			if object.GetMissing() {
				return fmt.Errorf("%s's read of the copy found its segment %x missing", device, object.GetId())
			}
			read[string(object.GetId())] = append(read[string(object.GetId())], object.GetBody()...)
		}
		if version == nil || version.GetCommitVersion() != posted.Version {
			// a nil version reads as 0, no version at all
			return fmt.Errorf("%s's read of the copy on r2 answered its version at %d, not %d", device, version.GetCommitVersion(), posted.Version)
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(version.GetEntryVersion(), entry); err != nil {
			return err
		}
		if named := (&EvsWorldCommittedEntry{Entry: entry}).SegmentIds(); !slices.EqualFunc(named, segmentIds, bytes.Equal) {
			return fmt.Errorf("the copy's entry names segments %x, not x.txt's first version's %x", named, segmentIds)
		}
		for _, segmentId := range segmentIds {
			if !bytes.Equal(read[string(segmentId)], stored[string(segmentId)]) {
				return fmt.Errorf("%s's read of the copy's segment %x came back as %d bytes, not the %d stored", device, segmentId, len(read[string(segmentId)]), len(stored[string(segmentId)]))
			}
		}
		return nil
	}
}

// One POST .../read of request through the world's lb under device's read token: every frame of a 200, or the status
// it answered instead.
func fs91Read(ctx context.Context, world *EvsWorld, device *EvsWorldDevice, request *protocol.EvsReadRequest) ([]*protocol.EvsReadFrame, error) {
	token, err := world.issueToken(device, []string{"repo:" + world.RepoId.String() + ":r"})
	if err != nil {
		return nil, err
	}
	body, err := proto.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://evs.example/evs/v1/repos/"+sidecar.EvsKeyId(world.RepoId)+"/read", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Content-Type", "application/x-protobuf")
	response, err := device.transport.RoundTrip(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %d", response.StatusCode)
	}
	frames := []*protocol.EvsReadFrame{}
	reader := sidecar.NewEvsReadFrames(response.Body)
	for {
		frame, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return frames, nil
		}
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
}
