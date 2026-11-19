//go:build sidecar_testhooks

// FS-99's cards case (§22.8, meta review F01; §16.11's revoke row and Erasure and removal block, §11.12's cut,
// closure and directory rows, I-EVS-16, owner decision 181; RECORD-M10-06), format 2's, at the later of M6-out and
// M10-out, on real engines: the directory world on evs (fs_directory_evs.go), so every card, repo file, index entry,
// CUT, CLOSURE and ERASE goes through evsservice's engine on T2's fakes, and through server's evshost on T3's stores
// (server's sidecar_directory_format2_t3_test.go). It extends RECORD-M6-25's schedules: the entries case's legs stay
// in the authorship world (fs99_test.go) and the evs clause's on format 1 (fs99_evs.go).
//
//	world     directory admins D and D2, repo owner R (P's admin, no directory admin), writers A and B, an ordinary
//	          agent X with rw and a fresh member device F. R announces P, whose r/ file is the directory's first
//	          format-2 push; A's card holds a run in P and one elsewhere, B's and X's a run each, every push carrying
//	          its index entries (the in-ref index writer)
//	refused   X's CUT listing A's run on the cards ref's index, its ERASE naming A's card's keys, its list mixing its
//	          own card's key with A's and its CLOSURE of its own card each answer 403 SCOPE, with every slot's ETag,
//	          every key, the cards ref's head and index epoch as they were, and no ERASE or CLOSURE committed
//	revoke    R revokes P with no directory admin's daemon running: the marker hides P's name from A and B at once,
//	          nothing is erased, and R reads the erasure pending
//	runner    D's daemon then starts. Its first pass cuts the documents naming P, rewrites the index files and P's
//	          r/ file by CLOSURE and erases their old keys, each ERASE and CLOSURE naming the request, and leaves A's
//	          card, which still names P, waiting for its writer (question record-m10-05-card-closure-content, option 1)
//	killed    A reads the marker and writes its run private. D's next pass is killed between its CLOSURE of A's
//	          card and the ERASE: the CLOSURE stands with its keys orphaned. D restarts from its stores, erases
//	          those keys first and finishes; D2's pass after it sends nothing
//	after     no key a version naming P was stored under remains in any slot object, B's and X's cards keep theirs
//	          in slots never rewritten, R reads the erasure done by D, and F, with an empty cache, syncs with no alarm
//	          and holds no P name, with A's other run, B's and X's shown
//
// Fs99CardsOnEvsOf's mutant mints X what its client asks for, as an exchange without §7.8's directory rule would,
// and must fail at X's first ERASE.
//
// Not here: the 24 h directory_erasure raise and the lapsed request, which the entries case runs (fs99_test.go) and
// format 2 does not change; two runners truly racing a CLOSURE (D2 passes after D here); a preservation hold over the
// cards ref; X's ?closure=1 upload, which a card's inline CLOSURE never makes (the evs clause holds the route).

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs99Cards = Register("FS-99", "cards", []Tier{TierT2, TierT3}, Fs99CardsOnEvs)

const (
	fs99CardsAdmin   = "daemonD"
	fs99CardsSecond  = "daemonD2"
	fs99CardsOwner   = "ownerR"
	fs99CardsWriterA = "writerA"
	fs99CardsWriterB = "writerB"
	fs99CardsAgentX  = "agentX"
	fs99CardsFresh   = "daemonF"
	fs99CardsRepo    = "P"
	// P's name and the project A's run names in it: what no readable copy may hold once the erasure ran
	fs99CardsRepoTitle = "launch plans"
	fs99CardsProject   = "example.org/team/launch-plans"
)

// FS-99's cards case's sizes.
type Fs99CardsSettings struct {
	// X's tokens carry what its client asks for, admin among it: the mutant, which must fail.
	Mutant bool
	// The time between X's attempts, past the wait evs holds between the refusals it records on one ref.
	RefusalSpacing time.Duration
	// The time between a card's writes, past a card's write interval.
	WriteSpacing time.Duration
}

func DefaultFs99CardsSettings() *Fs99CardsSettings {
	return &Fs99CardsSettings{
		RefusalSpacing: 2 * time.Minute,
		WriteSpacing:   time.Minute,
	}
}

// The case's world and what its steps keep.
type fs99Cards struct {
	world    *DirEvsWorld
	settings *Fs99CardsSettings
	runInP   *DirEvsRun
	runOfA   *DirEvsRun
	runOfB   *DirEvsRun
	runOfX   *DirEvsRun

	noted      *DirEvsNoted
	revocation *sidecar.DirectoryRevocation
}

func (self *fs99Cards) repoPath() string {
	return sidecar.DirectoryRepoPath(self.world.Repo(fs99CardsRepo))
}

func (self *fs99Cards) cardPath(device string) string {
	return sidecar.DirectoryCardPath(self.world.Device(device).SidecarId)
}

// A's card: its run in P, private once it read the marker, and its run elsewhere.
func (self *fs99Cards) cardOfA(net *Net, private bool) []*protocol.Announcement {
	repoId := self.world.Repo(fs99CardsRepo)
	inP := self.world.RunItem(net, fs99CardsWriterA, self.runInP, 1, &DirEvsWhere{RepoId: &repoId, Project: fs99CardsProject, Branch: "main"})
	if private {
		inP = self.world.RunItem(net, fs99CardsWriterA, self.runInP, 2, &DirEvsWhere{RepoId: &repoId, Private: true})
	}
	return []*protocol.Announcement{inP, self.world.RunItem(net, fs99CardsWriterA, self.runOfA, 1, &DirEvsWhere{Project: "example.org/team/app", Branch: "main"})}
}

// A step action: the repo's erasure state and the four files' keys are noted through the admin's reads.
func (self *fs99Cards) note() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		noted, err := self.world.Note(ctx, net, fs99CardsAdmin, []string{
			self.repoPath(), self.cardPath(fs99CardsWriterA), self.cardPath(fs99CardsWriterB), self.cardPath(fs99CardsAgentX),
		})
		if err != nil {
			return err
		}
		self.noted = noted
		return nil
	}
}

// Whether err is evs's 403 SCOPE, as a push's refusal or a stream call's.
func fs99CardsScopeRefused(err error) bool {
	if code, refused := sidecar.RecordStreamRefusalCode(err); refused {
		return code == protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE
	}
	return sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

// A step action: one of X's erasure calls, which must answer 403 SCOPE and leave everything noted as it was.
func (self *fs99Cards) refused(what string, attempt func(ctx context.Context, erasure *sidecar.DirectoryEvsErasure) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		erasure, err := self.world.Erasure(fs99CardsAgentX)
		if err != nil {
			return err
		}
		err = attempt(ctx, erasure)
		if err == nil {
			return fmt.Errorf("X's %s was not refused", what)
		}
		if !fs99CardsScopeRefused(err) {
			return fmt.Errorf("X's %s: %w, not 403 SCOPE", what, err)
		}
		if err := self.world.Unchanged(ctx, net, fs99CardsAdmin, self.noted); err != nil {
			return fmt.Errorf("after X's refused %s: %w", what, err)
		}
		return nil
	}
}

// The ERASEs and the cards ref's CLOSUREs after the noted ones, as reader reads them, are the request's, by D, and
// each ERASE's note that carries a body names the request as a revocation.
func (self *fs99Cards) erasuresNameRequest(ctx context.Context, reader string) error {
	requestId := self.revocation.RequestId
	eraserId := self.world.Device(fs99CardsAdmin).SidecarId
	erasures, err := self.world.Erasures(ctx, reader)
	if err != nil {
		return err
	}
	for _, erasure := range erasures[self.noted.EraseCount:] {
		if erasure.ErasureId != requestId || erasure.EraserSidecarId != eraserId {
			return fmt.Errorf("an ERASE of %s by %s: not the request's by its runner", erasure.ErasureId, erasure.EraserSidecarId)
		}
		// an index pair's ERASE short of the completing one carries no caller bytes
		if 0 < len(erasure.Note) {
			body := &protocol.ErasureBody{}
			if err := proto.Unmarshal(erasure.Note, body); err != nil {
				return fmt.Errorf("an ERASE's note: %w", err)
			}
			if !bytes.Equal(body.GetRequestId(), requestId[:]) || sidecar.RecordErasureReason(body.GetReason()) != sidecar.RecordErasureReasonRevocation {
				return fmt.Errorf("an ERASE's note names reason %d and another request", body.GetReason())
			}
		}
	}
	closures, err := self.world.CardClosures(ctx, reader)
	if err != nil {
		return err
	}
	for _, closure := range closures[self.noted.ClosureCount:] {
		if closure.ErasureId != requestId || closure.EraserSidecarId != eraserId {
			return fmt.Errorf("a CLOSURE of %s by %s: not the request's by its runner", closure.ErasureId, closure.EraserSidecarId)
		}
	}
	return nil
}

// How many of the documents naming P the cards ref's index holds live at the versions that named it, as device reads
// the index.
func (self *fs99Cards) liveNamingP(ctx context.Context, device string) (int, error) {
	erasure, err := self.world.Erasure(device)
	if err != nil {
		return 0, err
	}
	index, err := erasure.CardsIndex(ctx, self.world.DirectoryId)
	if err != nil {
		return 0, err
	}
	held, err := self.world.CardsIndex(ctx, device)
	if err != nil {
		return 0, err
	}
	writerId := self.world.Device(fs99CardsWriterA).SidecarId
	count := 0
	for _, name := range [][]byte{
		DirEvsDocumentName(nil, sidecar.DirectoryRepoAnnouncementId(self.world.Repo(fs99CardsRepo))),
		DirEvsDocumentName(&writerId, self.runInP.AnnouncementId),
	} {
		key, err := index.DocKey(name)
		if err != nil {
			return 0, err
		}
		// version 1 of each named P; the marker and the private run are their version 2
		if held.Live[key] == 1 {
			count += 1
		}
	}
	return count, nil
}

// The device's copy shows P as its private marker, with no name.
func (self *fs99Cards) markerShown(device string) error {
	item, ok := self.world.Device(device).Client.RepoItem(self.world.Repo(fs99CardsRepo))
	if !ok || !item.Announcement.GetWhere().GetPrivate() || item.Announcement.GetWhat().GetTitle() != "" {
		return fmt.Errorf("%s does not show P as its private marker", device)
	}
	return nil
}

// FS-99's cards case: see the file header.
func Fs99CardsOnEvs(net *Net) *Schedule {
	return Fs99CardsOnEvsOf(net, nil)
}

// FS-99's cards case under settings, nil for the defaults.
func Fs99CardsOnEvsOf(net *Net, settings *Fs99CardsSettings) *Schedule {
	if settings == nil {
		settings = DefaultFs99CardsSettings()
	}
	devices := []string{fs99CardsAdmin, fs99CardsSecond, fs99CardsOwner, fs99CardsWriterA, fs99CardsWriterB, fs99CardsAgentX, fs99CardsFresh}
	world := NewDirEvsWorld(net, &DirEvsWorldSettings{
		Devices: []*DirEvsDeviceSettings{
			{Name: fs99CardsAdmin, Admin: true}, {Name: fs99CardsSecond, Admin: true}, {Name: fs99CardsOwner},
			{Name: fs99CardsWriterA}, {Name: fs99CardsWriterB}, {Name: fs99CardsAgentX, MintsAsked: settings.Mutant}, {Name: fs99CardsFresh},
		},
		RepoAdmins: map[string][]string{fs99CardsRepo: {fs99CardsOwner}},
	})
	state := &fs99Cards{
		world: world, settings: settings,
		runInP: NewDirEvsRun("launcher", "draft the launch plan"), runOfA: NewDirEvsRun("builder", "refactor the settings loader"),
		runOfB: NewDirEvsRun("reviewer", "review the changelog"), runOfX: NewDirEvsRun("scout", "survey the open issues"),
	}
	card := func(device string, items func(net *Net) []*protocol.Announcement) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			_, err := world.WriteCard(ctx, device, items(net)...)
			return err
		}
	}
	steps := []*Step{
		{Actor: fs99CardsAdmin, Action: world.Setup},
		{Actor: fs99CardsAdmin, Action: world.InstallIndexWriters(devices...)},
		{Actor: fs99CardsOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(fs99CardsOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			if _, err := owner.Client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.Repo(fs99CardsRepo), DisplayName: fs99CardsRepoTitle, Confirmed: true}); err != nil {
				return fmt.Errorf("R's announcement of P: %w", err)
			}
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			if !owner.Client.Format2() || world.CopyFile(fs99CardsOwner, state.repoPath()) == nil {
				return errors.New("P's announcement is not its r/ file on a format-2 directory")
			}
			return nil
		}},
		{Actor: fs99CardsWriterA, Action: card(fs99CardsWriterA, func(net *Net) []*protocol.Announcement { return state.cardOfA(net, false) })},
		{Actor: fs99CardsWriterB, Action: card(fs99CardsWriterB, func(net *Net) []*protocol.Announcement {
			return []*protocol.Announcement{world.RunItem(net, fs99CardsWriterB, state.runOfB, 1, &DirEvsWhere{Project: "example.org/team/app", Branch: "review"})}
		})},
		{Actor: fs99CardsAgentX, Action: card(fs99CardsAgentX, func(net *Net) []*protocol.Announcement {
			return []*protocol.Announcement{world.RunItem(net, fs99CardsAgentX, state.runOfX, 1, &DirEvsWhere{Project: "example.org/team/issues", Branch: "main"})}
		})},
		{Actor: "check", Action: state.note()},

		// X, an ordinary agent with rw, erases nothing
		{Advance: settings.RefusalSpacing},
		{Actor: fs99CardsAgentX, Action: state.refused("CUT of A's run on the cards ref's index", func(ctx context.Context, erasure *sidecar.DirectoryEvsErasure) error {
			index, err := erasure.CardsIndex(ctx, world.DirectoryId)
			if err != nil {
				return err
			}
			writerId := world.Device(fs99CardsWriterA).SidecarId
			key, err := index.DocKey(DirEvsDocumentName(&writerId, state.runInP.AnnouncementId))
			if err != nil {
				return err
			}
			_, err = index.Cut(ctx, &sidecar.IndexCutArgs{ErasureId: sidecar.NewId(), Documents: []*sidecar.IndexCutDocument{{Key: key, Version: 1}}})
			return err
		})},
		{Advance: settings.RefusalSpacing},
		{Actor: fs99CardsAgentX, Action: state.refused("ERASE naming A's card's keys", func(ctx context.Context, erasure *sidecar.DirectoryEvsErasure) error {
			return erasure.EraseCardKeys(ctx, world.DirectoryId, &sidecar.EvsEraseArgs{
				ErasureId: sidecar.NewId(), Keys: state.noted.Keys[state.cardPath(fs99CardsWriterA)], Complete: true,
			})
		})},
		{Advance: settings.RefusalSpacing},
		{Actor: fs99CardsAgentX, Action: state.refused("ERASE mixing its own card's key with A's", func(ctx context.Context, erasure *sidecar.DirectoryEvsErasure) error {
			keys := slices.Concat(state.noted.Keys[state.cardPath(fs99CardsAgentX)], state.noted.Keys[state.cardPath(fs99CardsWriterA)])
			return erasure.EraseCardKeys(ctx, world.DirectoryId, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true})
		})},
		{Advance: settings.RefusalSpacing},
		{Actor: fs99CardsAgentX, Action: func(ctx context.Context, net *Net) error {
			// X's own card, rewritten as an eraser rewrites one: the path is X's, the CLOSURE is not
			if err := world.Device(fs99CardsAgentX).Client.Sync(ctx); err != nil {
				return err
			}
			path := state.cardPath(fs99CardsAgentX)
			file := world.CopyFile(fs99CardsAgentX, path)
			if file == nil || file.Content == nil {
				return errors.New("X's copy does not hold its own card")
			}
			return state.refused("CLOSURE of its own card", func(ctx context.Context, erasure *sidecar.DirectoryEvsErasure) error {
				_, err := erasure.CloseCard(ctx, world.DirectoryId, sidecar.NewId(), &sidecar.DirectoryCardWrite{
					PushId: sidecar.NewId(), Path: path, IfVersion: file.Version, Content: file.Content, AuthPin: file.AuthPin,
				}, state.noted.Keys[path])
				return err
			})(ctx, net)
		}},

		// R revokes P with no directory admin's daemon running
		{Actor: fs99CardsOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(fs99CardsOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			revocation, err := owner.Client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.Repo(fs99CardsRepo), Confirmed: true})
			if err != nil {
				return fmt.Errorf("R's revocation: %w", err)
			}
			if revocation.State != sidecar.DirectoryRevocationPending {
				return fmt.Errorf("the revocation with no runner: %+v", revocation)
			}
			state.revocation = revocation
			return owner.Record.Flush(ctx)
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			// the marker hides P's name from every honest reader at once, and nothing is erased
			for _, device := range []string{fs99CardsWriterA, fs99CardsWriterB} {
				if err := world.Device(device).Client.Sync(ctx); err != nil {
					return err
				}
				if err := state.markerShown(device); err != nil {
					return err
				}
			}
			erasures, err := world.Erasures(ctx, fs99CardsWriterB)
			if err != nil || len(erasures) != state.noted.EraseCount {
				return fmt.Errorf("%d ERASEs with no runner: %v", len(erasures), err)
			}
			for path := range state.noted.Keys {
				if held, err := world.KeysHeld(ctx, net, state.noted, path); err != nil || held != len(state.noted.Keys[path]) {
					return fmt.Errorf("a key went with no runner: %v", err)
				}
			}
			owner := world.Device(fs99CardsOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			revocations, err := owner.Client.Revocations()
			if err != nil || len(revocations) != 1 || revocations[0].State != sidecar.DirectoryRevocationPending {
				return fmt.Errorf("the revoker's view with no runner: %+v, %v", revocations, err)
			}
			return nil
		}},

		// D's daemon starts: the first pass takes what no longer needs a writer
		{Actor: fs99CardsAdmin, Action: func(ctx context.Context, net *Net) error {
			pass, err := world.Pass(ctx, fs99CardsAdmin)
			if err != nil {
				return fmt.Errorf("D's first pass: %w", err)
			}
			files := pass.Files[state.revocation.RequestId]
			if !pass.Runs || files == nil || files.CutCount == 0 || !slices.Equal(files.ClosedPaths, []string{state.repoPath()}) ||
				!slices.Equal(files.WaitingPaths, []string{state.cardPath(fs99CardsWriterA)}) || len(files.RemovedPaths) != 0 {
				return fmt.Errorf("D's first pass: %+v, files %+v", pass, files)
			}
			if err := state.erasuresNameRequest(ctx, fs99CardsAdmin); err != nil {
				return err
			}
			if held, err := world.KeysHeld(ctx, net, state.noted, state.repoPath()); err != nil || held != 0 {
				return fmt.Errorf("%d keys of P's file's old versions remain: %v", held, err)
			}
			// the card that still names P keeps its key until its writer wrote it again
			if held, err := world.KeysHeld(ctx, net, state.noted, state.cardPath(fs99CardsWriterA)); err != nil || held == 0 {
				return fmt.Errorf("A's card's key went before its writer dropped P: %v", err)
			}
			if live, err := state.liveNamingP(ctx, fs99CardsAdmin); err != nil || live != 0 {
				return fmt.Errorf("the cards ref's index holds %d documents naming P after the CUT: %v", live, err)
			}
			return nil
		}},

		// A reads the marker and writes its run private; D's next pass dies between its CLOSURE and its ERASE
		{Advance: settings.WriteSpacing},
		{Actor: fs99CardsWriterA, Action: card(fs99CardsWriterA, func(net *Net) []*protocol.Announcement { return state.cardOfA(net, true) })},
		{Actor: fs99CardsAdmin, Action: func(ctx context.Context, net *Net) error {
			_, err := world.Pass(ctx, fs99CardsAdmin)
			return err
		}, Background: true},
		// the barrier's second arrival: the first pass's CLOSURE of P's file passed it
		{Actor: fs99CardsAdmin, Await: "directory.erasure.closure.after", AwaitSkip: 1},
		{Actor: fs99CardsAdmin, Kill: true},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			// the CLOSURE stands and no ERASE followed: its keys are orphaned, and still in their slots
			erasure, err := world.Erasure(fs99CardsSecond)
			if err != nil {
				return err
			}
			orphans, err := erasure.OrphanCardKeys(ctx, world.DirectoryId, state.revocation.RequestId)
			if err != nil || len(orphans) == 0 {
				return fmt.Errorf("the killed runner's CLOSURE left %d orphaned keys: %v", len(orphans), err)
			}
			if held, err := world.KeysHeld(ctx, net, state.noted, state.cardPath(fs99CardsWriterA)); err != nil || held == 0 {
				return fmt.Errorf("A's card's old key went with no ERASE: %v", err)
			}
			return nil
		}},
		{Actor: fs99CardsAdmin, Restart: fs99CardsAdmin},
		{Actor: fs99CardsAdmin, Action: world.Reopen(fs99CardsAdmin)},
		{Actor: fs99CardsAdmin, Action: func(ctx context.Context, net *Net) error {
			if _, err := world.Pass(ctx, fs99CardsAdmin); err != nil {
				return fmt.Errorf("D's pass after its restart: %w", err)
			}
			erasure, err := world.Erasure(fs99CardsAdmin)
			if err != nil {
				return err
			}
			if orphans, err := erasure.OrphanCardKeys(ctx, world.DirectoryId, state.revocation.RequestId); err != nil || len(orphans) != 0 {
				return fmt.Errorf("%d keys stay orphaned after the resume: %v", len(orphans), err)
			}
			return nil
		}},
		{Actor: fs99CardsSecond, Action: func(ctx context.Context, net *Net) error {
			// the second runner finds the work done and sends nothing
			erasures, err := world.Erasures(ctx, fs99CardsSecond)
			if err != nil {
				return err
			}
			closures, err := world.CardClosures(ctx, fs99CardsSecond)
			if err != nil {
				return err
			}
			if _, err := world.Pass(ctx, fs99CardsSecond); err != nil {
				return fmt.Errorf("D2's pass: %w", err)
			}
			erasuresAfter, err := world.Erasures(ctx, fs99CardsSecond)
			if err != nil {
				return err
			}
			closuresAfter, err := world.CardClosures(ctx, fs99CardsSecond)
			if err != nil {
				return err
			}
			if len(erasuresAfter) != len(erasures) || len(closuresAfter) != len(closures) {
				return fmt.Errorf("D2's pass after D's sent %d ERASEs and %d CLOSUREs", len(erasuresAfter)-len(erasures), len(closuresAfter)-len(closures))
			}
			return nil
		}},

		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			// exactly the copies naming P: no key a version naming it was stored under remains
			for _, path := range []string{state.repoPath(), state.cardPath(fs99CardsWriterA)} {
				if held, err := world.KeysHeld(ctx, net, state.noted, path); err != nil || held != 0 {
					return fmt.Errorf("%d keys of versions naming P remain: %v", held, err)
				}
			}
			for _, device := range []string{fs99CardsWriterB, fs99CardsAgentX} {
				path := state.cardPath(device)
				for _, key := range state.noted.Keys[path] {
					if held, err := world.KeyHeld(ctx, net, key); err != nil || !held {
						return fmt.Errorf("%s's card lost a key to P's erasure: %v", device, err)
					}
					if etag, err := world.SlotEtag(ctx, net, key.SlotId); err != nil || etag != state.noted.Etags[key.SlotId] {
						return fmt.Errorf("%s's card's slot was rewritten: %v", device, err)
					}
				}
			}
			if err := state.erasuresNameRequest(ctx, fs99CardsSecond); err != nil {
				return err
			}
			if live, err := state.liveNamingP(ctx, fs99CardsSecond); err != nil || live != 0 {
				return fmt.Errorf("the cards ref's index holds %d documents naming P: %v", live, err)
			}
			// the revoker reads the erasure done, by D
			owner := world.Device(fs99CardsOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			revocations, err := owner.Client.Revocations()
			if err != nil {
				return err
			}
			adminId := world.Device(fs99CardsAdmin).SidecarId
			if len(revocations) != 1 || revocations[0].State != sidecar.DirectoryRevocationDone || revocations[0].EraserSidecarId == nil || *revocations[0].EraserSidecarId != adminId {
				return fmt.Errorf("the revocation at its revoker: %+v", revocations)
			}
			return nil
		}},
		{Actor: fs99CardsFresh, Action: func(ctx context.Context, net *Net) error {
			// a fresh member device with an empty cache
			fresh := world.Device(fs99CardsFresh)
			if err := fresh.Client.Sync(ctx); err != nil {
				return fmt.Errorf("the fresh device's sync: %w", err)
			}
			if alarms := fresh.Alarms(); len(alarms) != 0 {
				return fmt.Errorf("the fresh device alarmed: %v", alarms)
			}
			if alarms := world.EvsAlarms(fs99CardsFresh); len(alarms) != 0 {
				return fmt.Errorf("the fresh device's evs alarmed: %v", alarms)
			}
			if err := state.markerShown(fs99CardsFresh); err != nil {
				return err
			}
			for _, file := range fresh.Client.Cards() {
				if bytes.Contains(file.Content, []byte(fs99CardsRepoTitle)) || bytes.Contains(file.Content, []byte(fs99CardsProject)) {
					return fmt.Errorf("the fresh device's copy holds P's name at %s version %d", file.Path, file.Version)
				}
			}
			items, err := fresh.Client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun, IncludePrivate: true})
			if err != nil {
				return err
			}
			shown := map[sidecar.Id]*protocol.Announcement{}
			for _, item := range items {
				shown[item.Key.AnnouncementId] = item.Announcement
			}
			inP := shown[state.runInP.AnnouncementId]
			if inP == nil || !inP.GetWhere().GetPrivate() || inP.GetWhere().GetProject() != "" {
				return fmt.Errorf("A's run in P at the fresh device: %v", inP)
			}
			for _, run := range []*DirEvsRun{state.runOfA, state.runOfB, state.runOfX} {
				if item := shown[run.AnnouncementId]; item == nil || item.GetWhat().GetTitle() != run.Title {
					return fmt.Errorf("the fresh device does not show %q, which names no P", run.Title)
				}
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-99", Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
