package fault

// FS-93 on T2 (EVSB-M10-04; DESIGN-DETAILS 10.6): rename chains and lineages across path epochs, through the drop job
// over the real resolve, mark, verify and deletes. A rename is one push removing a path and creating another from its
// chain, so the segments a chain shares stay while any live version names them; a lineage is checked link by link in
// the committed map part or tail it names, and one no map or tail links is refused {mismatch}, deleting nothing.

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The rename chain: on ref A, Z written twice, renamed to Y from Z's chain, Y renamed to X, X edited; on ref R2, a copy
// of an old X. Every listed version's entry bytes, by path.
type fs93Chain struct {
	world       *fsDropWorld
	refA, refR2 sidecar.Id
	x, y, z     sidecar.EvsTokenPath
	z1, z2, x2  [32]byte
	zv, yv, xv  [][]byte
	removeZ     uint64
	removeY     uint64
}

func newFs93Chain(t *testing.T) *fs93Chain {
	world := newFsDropWorld(t)
	chain := &fs93Chain{
		world: world, refA: fsDropId16("ref a"), refR2: fsDropId16("ref r2"), x: fsDropPath("x"), y: fsDropPath("y"), z: fsDropPath("z"),
		z1: fsDropSegment("z1"), z2: fsDropSegment("z2"), x2: fsDropSegment("x2"),
	}
	chain.zv = append(chain.zv, world.write(chain.refA, chain.z, 0, &fsDropEntry{segments: [][32]byte{chain.z1}}))
	chain.zv = append(chain.zv, world.write(chain.refA, chain.z, 1, &fsDropEntry{segments: [][32]byte{chain.z2}}))
	// Z to Y: Y's creation at max(b, m) + 1 = 3 names Z's chain
	createY := &fsDropChange{path: chain.y, spec: &fsDropEntry{version: 3, segments: [][32]byte{chain.z2}}}
	world.commit(chain.refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{{path: chain.z, base: 2}, createY}})
	chain.yv, chain.removeZ = [][]byte{createY.entry}, 3
	createX := &fsDropChange{path: chain.x, spec: &fsDropEntry{version: 4, segments: [][32]byte{chain.z2}}}
	world.commit(chain.refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{{path: chain.y, base: 3}, createX}})
	chain.xv, chain.removeY = [][]byte{createX.entry}, 4
	chain.xv = append(chain.xv, world.write(chain.refA, chain.x, 4, &fsDropEntry{segments: [][32]byte{chain.x2}}))
	world.write(chain.refR2, chain.x, 0, &fsDropEntry{segments: [][32]byte{chain.z2}})
	return chain
}

// Dropping X keeps what Z's, Y's and R2's versions name: only the segment X's own edit introduced goes.
func TestFs93DroppingXKeepsWhatTheChainAndACopyName(t *testing.T) {
	chain := newFs93Chain(t)
	world := chain.world
	dropId := fsDropId16("drop x")
	world.drop(chain.refA, dropId, []*protocol.EvsDropPath{fsDropPathOf(6, 1, nil, fsDropSource(1, chain.x))}, [][][]byte{chain.xv})
	world.ripen(50 * time.Hour)
	if result := world.runToEnd(world.job("a"), 8); !result.Ended || world.dropState(dropId) != evsservice.DropStateDone {
		t.Fatalf("the job: %+v, state %d", result, world.dropState(dropId))
	}
	if world.stored(chain.x2) || !world.stored(chain.z2) || !world.stored(chain.z1) {
		t.Fatalf("x2 %t, z2 %t, z1 %t", world.stored(chain.x2), world.stored(chain.z2), world.stored(chain.z1))
	}
}

// --follow drops X, Y and Z in one push and one job, freeing what only they name, R2's copy keeping its segments.
func TestFs93FollowFreesWhatOnlyTheChainNames(t *testing.T) {
	chain := newFs93Chain(t)
	world := chain.world
	dropId := fsDropId16("drop chain")
	world.drop(chain.refA, dropId, []*protocol.EvsDropPath{
		fsDropPathOf(6, 1, nil, fsDropSource(1, chain.x)),
		fsDropPathOf(chain.removeY, 2, nil, fsDropSource(1, chain.y)),
		fsDropPathOf(chain.removeZ, 2, nil, fsDropSource(1, chain.z)),
	}, [][][]byte{chain.xv, chain.yv, chain.zv})
	world.ripen(50 * time.Hour)
	if result := world.runToEnd(world.job("a"), 8); !result.Ended || world.dropState(dropId) != evsservice.DropStateDone {
		t.Fatalf("the job: %+v, state %d", result, world.dropState(dropId))
	}
	if world.stored(chain.x2) || world.stored(chain.z1) || !world.stored(chain.z2) {
		t.Fatalf("x2 %t, z1 %t, z2 %t", world.stored(chain.x2), world.stored(chain.z1), world.stored(chain.z2))
	}
}

// X live through three epochs, its link into epoch 2 in the second part of epoch 2's map and its link into epoch 3 in
// epoch 3's tail, since X was removed and created again after that map's source: one lineage, every version it lists
// freed; the same lineage naming the wrong part is refused {mismatch}, deleting nothing.
func TestFs93ALineageThroughThreeEpochs(t *testing.T) {
	for _, wrongPart := range []bool{false, true} {
		world := newFsDropWorld(t)
		refA := fsDropId16("ref a")
		x1, x2, x3 := fsDropPath("x"), fsDropPath("e2", "x"), fsDropPath("e3", "x")
		w1, w2, w3 := fsDropPath("w"), fsDropPath("e2", "w"), fsDropPath("e3", "w")
		segments := [][32]byte{fsDropSegment("a1"), fsDropSegment("a2"), fsDropSegment("a6"), fsDropSegment("a7")}
		listed := [][]byte{world.write(refA, x1, 0, &fsDropEntry{segments: segments[0:1]})}
		world.write(refA, w1, 0, &fsDropEntry{inline: true})
		world.pathEpoch(refA, 2, [][]*protocol.EvsPathMove{{fsDropMove(w2, fsDropSource(1, w1))}, {fsDropMove(x2, fsDropSource(1, x1))}}, nil)
		listed = append(listed, world.write(refA, x2, 1, &fsDropEntry{segments: segments[1:2]}))
		world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{{path: x2, base: 2}}})
		// created again at max(b, m) + 1, after epoch 3's map took its source
		created := &fsDropChange{path: x2, spec: &fsDropEntry{version: 6, segments: segments[2:3]}}
		world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{created}})
		listed = append(listed, created.entry)
		world.pathEpoch(refA, 3, [][]*protocol.EvsPathMove{{fsDropMove(w3, fsDropSource(2, w2))}}, []*protocol.EvsPathMove{fsDropMove(x3, fsDropSource(2, x2))})
		listed = append(listed, world.write(refA, x3, 6, &fsDropEntry{segments: segments[3:4]}))
		// the map's parts ascend, so X's move is in the second part when its path sorts after W's
		part := uint32(1)
		if 0 < x2.Compare(w2) {
			part = 2
		}
		if wrongPart {
			part = 3 - part
		}
		dropId := fsDropId16("drop x")
		world.drop(refA, dropId, []*protocol.EvsDropPath{fsDropPathOf(8, 1, []uint32{0, part}, fsDropSource(3, x3), fsDropSource(2, x2), fsDropSource(1, x1))}, [][][]byte{listed})
		world.ripen(50 * time.Hour)
		world.runToEnd(world.job("a"), 8)
		state := world.dropState(dropId)
		if wrongPart {
			if state != evsservice.DropStateRefusedMismatch {
				t.Fatalf("a link in the wrong part: state %d", state)
			}
			for _, segment := range segments {
				if !world.stored(segment) {
					t.Fatal("a refused drop deleted a segment")
				}
			}
			continue
		}
		if state != evsservice.DropStateDone {
			t.Fatalf("the lineage: state %d", state)
		}
		for _, segment := range segments {
			if world.stored(segment) {
				t.Fatalf("a listed version's segment %x stayed", segment[:4])
			}
		}
	}
}

// X removed before a cut-over and created again after: no map or tail links its two lives, so one lineage across them
// is refused {mismatch}; two lineages, the old life at its standing removal, drop both.
func TestFs93ARemovalBeforeACutOverMakesTwoLineages(t *testing.T) {
	for _, twoLineages := range []bool{false, true} {
		world := newFsDropWorld(t)
		refA := fsDropId16("ref a")
		x1, x2, w1, w2 := fsDropPath("x"), fsDropPath("e2", "x"), fsDropPath("w"), fsDropPath("e2", "w")
		b1, b2, b3 := fsDropSegment("b1"), fsDropSegment("b2"), fsDropSegment("b3")
		world.write(refA, w1, 0, &fsDropEntry{inline: true})
		old := world.write(refA, x1, 0, &fsDropEntry{segments: [][32]byte{b1}})
		world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{{path: x1, base: 1}}})
		world.pathEpoch(refA, 2, [][]*protocol.EvsPathMove{{fsDropMove(w2, fsDropSource(1, w1))}}, nil)
		created := &fsDropChange{path: x2, spec: &fsDropEntry{version: 5, segments: [][32]byte{b2}}}
		world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{created}})
		edited := world.write(refA, x2, 5, &fsDropEntry{segments: [][32]byte{b3}})
		dropId := fsDropId16("drop x")
		if twoLineages {
			world.drop(refA, dropId, []*protocol.EvsDropPath{
				fsDropPathOf(7, 1, nil, fsDropSource(2, x2)),
				fsDropPathOf(2, 2, nil, fsDropSource(1, x1)),
			}, [][][]byte{{created.entry, edited}, {old}})
		} else {
			world.drop(refA, dropId, []*protocol.EvsDropPath{fsDropPathOf(7, 1, []uint32{1}, fsDropSource(2, x2), fsDropSource(1, x1))},
				[][][]byte{{created.entry, edited, old}})
		}
		world.ripen(50 * time.Hour)
		world.runToEnd(world.job("a"), 8)
		state := world.dropState(dropId)
		if !twoLineages {
			if state != evsservice.DropStateRefusedMismatch || !world.stored(b1) || !world.stored(b2) || !world.stored(b3) {
				t.Fatalf("one lineage across a removal: state %d", state)
			}
			continue
		}
		if state != evsservice.DropStateDone || world.stored(b1) || world.stored(b2) || world.stored(b3) {
			t.Fatalf("two lineages: state %d, stored %t %t %t", state, world.stored(b1), world.stored(b2), world.stored(b3))
		}
	}
}
