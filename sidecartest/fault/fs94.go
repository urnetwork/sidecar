// FS-94 (§22.8; §11.7's states and inline rows, §11.13's delete row, FI-1, FI-27; EVS2-M10-31) on the evs world with
// its drop wiring (evs_world_drop.go): a shared inline record. One push writes small x.txt and y.txt with the same
// bytes, so one batch record holds both entry versions; x.txt is written again and its history dropped.
//
//	general       Fs94, the registered case, a general repo: in the drop's window x.txt's listed version reads on,
//	              shown drop pending; after not_before it is withheld (dropped, nothing fetched), while y.txt is served
//	              and verifies at its newest and at the version the shared record holds, and the record's other entry
//	              versions keep their hashes (FI-1 opens every committed version after every step). The job then
//	              executes: nothing of a general repo's inline bytes is deleted, x.txt's listed versions stay withheld
//	              and y.txt reads on, a later write of y.txt verifying over the shared record. x.txt's path is then
//	              removed: its listed versions still read dropped, with no alarm
//	compaction    in the general case, once x.txt's version is withheld: compaction's stub, Fs94CompactionKeeps, a pure
//	              function over the shared record with x.txt's listed version not live, keeps the statement and y.txt's
//	              entry version whole, its inline bytes within it and its hash its change's, and leaves x.txt's entry
//	              version out; it reads no store and deletes nothing, compaction being Later (owner decision 247;
//	              RESOLUTIONS plan-EVSB-fs94-compaction-clause #1)
//	record class  Fs94RecordClass, a record repo, where each path's versions name their own slots: x.txt's listed
//	              versions are unreadable from the DROP's commit, the job deletes their slots, and y.txt, whose slot
//	              no listed version names, is served and verifies at both versions
//
// Not here, each a deferral in EVS2-M10-31's report: x.txt's marker collected and its epoch drained after its removal;
// and the inline bytes unserved by push id, which no route of the world's client asks for.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs94Case = Register("FS-94", "", []Tier{TierT2, TierT3}, Fs94)

// The bytes x.txt and y.txt share: small enough that one record holds both versions inline.
var fs94SharedContent = []byte("fs94: the bytes x.txt and y.txt both hold")

// See the file header.
func Fs94(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	mark := &EvsWorldStoreMark{}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WritePair("admin", "x.txt", "y.txt", fs94SharedContent)},
		{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropInlineContent("fs94 x second"))},
		{Actor: "check", Action: world.MarkStore(mark)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", false)},
		// in the window: pending, and still read
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropPending})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		// after not_before: withheld, y.txt served and verifying
		{Advance: 7*24*time.Hour + time.Minute},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		// compaction's stub over the shared record keeps every byte y.txt needs
		{Actor: "check", Action: fs94CompactionKeepsTheLive(world, "x.txt", "y.txt")},
	}
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		// a general repo's inline bytes are in its packs, which a drop never rewrites
		{Actor: "check", Action: world.NoSegmentDeletesSince(mark)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		{Actor: "admin", Action: world.Write("admin", "y.txt", fsDropInlineContent("fs94 y second"))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		// the path removed: its listed versions still read dropped
		{Actor: "admin", Action: world.Remove("admin", "x.txt")},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)...)
	return &Schedule{Id: "FS-94", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs94RecordClass(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_RECORD, false))
	mark := &EvsWorldStoreMark{}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WritePair("admin", "x.txt", "y.txt", fs94SharedContent)},
		{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropInlineContent("fs94 x second"))},
		{Actor: "check", Action: world.MarkStore(mark)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		// unreadable at once, y.txt read on
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
	}
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: fs94SlotDeletes(mark, 2)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		{Actor: "admin", Action: world.Write("admin", "y.txt", fsDropInlineContent("fs94 y second"))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
	}...)...)
	return &Schedule{Id: "FS-94 record class", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: taskworker deleted count slots since mark, the listed versions' own: x.txt's two versions below the
// drop's rewrite of its head, and none of y.txt's, whose reads the steps beside this hold.
func fs94SlotDeletes(mark *EvsWorldStoreMark, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		index := mark.index
		mark.stateLock.Unlock()
		history := net.BlobHistory()
		deleted := map[string]bool{}
		for _, entry := range history[min(index, len(history)):] {
			if entry.Op == sidecartest.BlobHistoryDelete && entry.Outcome == sidecartest.BlobOutcomeOk && strings.HasPrefix(entry.Key, "slot/") {
				deleted[entry.Key] = true
			}
		}
		if len(deleted) != count {
			return fmt.Errorf("%d slots were deleted since the drop, not the %d its listed versions name", len(deleted), count)
		}
		return nil
	}
}

// What compaction's stub keeps of one push's record: see Fs94CompactionKeeps.
type Fs94CompactionKept struct {
	// The record's statement, whole, and its change list where the push's changes ride under changes_root: every
	// change's token path and entry hash, those of a version that is not live too, so each entry version of the record
	// keeps its hash.
	Statement  []byte
	ChangeList []byte
	// The entry version bytes of each change a live version needs, by the change's place in the push. A version the
	// record holds inline has its content's ciphertext within them.
	EntryVersions map[int][]byte
}

// Compaction's stub (§22.8's FS-94; RESOLUTIONS plan-EVSB-fs94-compaction-clause #1): a pure function that, given a
// one-part push's record, its statement and its payload as stored, and which of the entry versions it wrote are live,
// returns the bytes of the record a live version needs: the statement and change list whole, and each live change's
// entry version exactly as committed. It reads no store and deletes nothing, since compaction is Later (owner
// decision 247): what it leaves out is what a compaction could drop from the record, never what one did.
func Fs94CompactionKeeps(statement *sidecar.EvsStatement, payloadBytes []byte, live func(tokenPath sidecar.EvsTokenPath, entry *protocol.EvsEntryVersion) bool) (*Fs94CompactionKept, error) {
	sections, err := sidecar.ParseEvsPayloadFormat2(payloadBytes)
	if err != nil {
		return nil, err
	}
	checked, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
	if err != nil {
		return nil, err
	}
	kept := &Fs94CompactionKept{
		Statement:     bytes.Clone(statement.Bytes),
		ChangeList:    bytes.Clone(sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST)),
		EntryVersions: map[int][]byte{},
	}
	for index, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return nil, err
		}
		if live(change.TokenPath, entry) {
			kept.EntryVersions[index] = bytes.Clone(change.EntryVersion)
		}
	}
	return kept, nil
}

// A step action: compaction's stub over the record of the push that first wrote livePath, which wrote droppedPath
// beside it, with droppedPath's version there not live, as a drop past its not_before lists it: the stub keeps the
// statement and change list whole and, of the push's file versions, livePath's alone, its bytes hashing to its
// change's entry hash and every locator it names inline, so nothing livePath's version needs lies outside what was
// kept; droppedPath's entry version is left out, its hash staying under the statement.
func fs94CompactionKeepsTheLive(world *EvsWorld, droppedPath string, livePath string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		// droppedPath's newest write is a push of its own, which names its token path
		dropped, err := world.CommittedEntry("admin", droppedPath)
		if err != nil {
			return err
		}
		statement, payloadBytes, err := world.FirstPush(livePath)
		if err != nil {
			return err
		}
		kept, err := Fs94CompactionKeeps(statement, payloadBytes, func(tokenPath sidecar.EvsTokenPath, entry *protocol.EvsEntryVersion) bool {
			return !tokenPath.Equal(dropped.TokenPath)
		})
		if err != nil {
			return err
		}
		sections, err := sidecar.ParseEvsPayloadFormat2(payloadBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(kept.Statement, statement.Bytes) || !bytes.Equal(kept.ChangeList, sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST)) {
			return errors.New("the stub did not keep the record's statement and change list whole")
		}
		checked, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return err
		}
		liveCount, droppedCount := 0, 0
		for index, change := range checked.Changes {
			if !change.WritesEntry() {
				continue
			}
			keptBytes, isKept := kept.EntryVersions[index]
			if change.TokenPath.Equal(dropped.TokenPath) {
				droppedCount += 1
				if isKept {
					return fmt.Errorf("the stub kept %s's listed version's bytes, which no live version needs", droppedPath)
				}
				continue
			}
			if !isKept {
				return fmt.Errorf("the stub left out change %d's entry version, which is live", index)
			}
			digest := sha256.Sum256(keptBytes)
			if !bytes.Equal(digest[:], change.Change.GetEntrySha256()) {
				return fmt.Errorf("change %d's entry version as the stub kept it does not hash to its change's entry hash", index)
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(keptBytes, entry); err != nil {
				return err
			}
			if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
				continue
			}
			liveCount += 1
			if len(entry.GetChain()) == 0 {
				return fmt.Errorf("%s's version in the shared record names no locator", livePath)
			}
			for _, locator := range entry.GetChain() {
				if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_INLINE || len(locator.GetInline()) == 0 {
					return fmt.Errorf("%s's version in the shared record names a locator of kind %d: its bytes are not all in the record", livePath, locator.GetKind())
				}
			}
		}
		if liveCount != 1 || droppedCount != 1 {
			return fmt.Errorf("the shared record writes %d live files and %d dropped, not one of each", liveCount, droppedCount)
		}
		return nil
	}
}
