//go:build !ios_extension

// A mailbox's or group inbox's first search-index build (§15.7's search index row, §11.14's on and Documents rows,
// §15.17's v1; R-MAIL-17, R-CTX-35, D-MAIL-16, I-19; MAIL-M10-01). Mail a repo took before its index existed, under
// storage format 1 or before the index was on, is in no index, and one full build on a device that holds the mail
// writes it (§11.14; owner decision 169). From then on ingest's own pushes carry each message's delta (mail_ingest.go).
//
//	build     the index's builder (IndexBuilder, through EvsRepo.IndexRebuild) writes the ref's root whole under its
//	          lock, from the text at its pin, each document in the window of its content push's signed time or in
//	          all, leaving out what the ref's erasure set lists; this file gives it the mail as the repo's one
//	          content ref, mailIndexContent
//	messages  read from i/, the message list, a month at a time: each IndexEntry names its m/ path, its receive
//	          time's month and its id. A message an erasure took is in no segment once its part commits (§15.7), and
//	          before that its CUT lists it, which the builder leaves out, and its keys are gone, which leaves it
//	          unopenable below
//	versions  each m/ path's verified entry, EntryReadCount a round, gives the version, the ref version and the signed
//	          time of the push that wrote it, and its size; a message is written once, create-only, so the version at
//	          the head is the one at the build's pin, and one written after the pin stands at none
//	text      State reads one message at a time through evs's verifying reader into a spill, which the next State or
//	          the build's end closes; a message whose content is gone (its keys erased, its object missing, its seal
//	          broken) is unopenable and left out, as the builder leaves out every unopenable version, and so is one
//	          past MessageMaxByteCount, which no writer makes; any other failure fails the build, which a later call
//	          runs again
//	trust     the outside bit from the entry's label (MailEntryUntrusted), as ingest marks its write; tainted false for
//	          a message ingest wrote, since ingest is no run, and for a sent copy, which has no label, from its push's
//	          provenance, a provenance the read cannot show reading tainted, never as an untainted run's word
//
// Only m/ is read here, so vault/, o/, forward, ra/, s/model, f/ and i/ never reach the build: an index covers only
// documents every reader of its ref can open, and a mailbox's vault/ entries are its owner's devices' alone (§15.7's
// trap). The builder's never row (indexExcluded) holds the same line.
//
// The pushes the content ref gives are those that wrote the messages' versions, each with its signed time, which is
// what a build reads of pushes (QD-689's reading 5); it is no coverage reader, and no other caller takes it. Who builds
// and when is the composition's: a device holding the mail, at the end of the migration to format 2 (FS-72), or for a
// mailbox an older index never covered. Paths are this device's plaintext and go into no log or error (I-13). Not safe
// for concurrent use: one build at a time.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A first build asked of no repo.
var ErrMailIndexBuildArgs = errors.New("mail index build without its repo")

// What a first build is tuned by.
type MailIndexBuildSettings struct {
	// The most bytes of one m/ file a build reads: a message at pro.yml's highest mail_inbound_message_bytes with
	// ingest's headers, which ingest's own deposit bound holds. A file past it, which no writer makes, is left out.
	// Non-positive reads none.
	MessageMaxByteCount int64
	// The m/ entries one verified read names: evs's ReadMaxPathCount, the read format's (§11.9). Non-positive takes 1.
	EntryReadCount int
	// How the message list is read; nil takes DefaultMailStoreSettings.
	Store *MailStoreSettings
}

// The one default.
func DefaultMailIndexBuildSettings() *MailIndexBuildSettings {
	return &MailIndexBuildSettings{
		MessageMaxByteCount: DefaultMailIngestSettings().DepositMaxByteCount,
		EntryReadCount:      DefaultEvsFormatSettings().ReadMaxPathCount,
	}
}

// What a first build builds.
type MailIndexBuildArgs struct {
	// The mailbox or the group repo, whose main ref holds both its mail and its index.
	Repo *EvsRepo
	// A group repo laid out as an inbox (§15.7), rather than a mailbox.
	GroupInbox bool
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailIndexBuildSettings.
	Settings *MailIndexBuildSettings
}

// What a first build did.
type MailIndexBuildResult struct {
	// The ref whose index the build wrote, and the ref version it committed at, 0 where it was skipped.
	RefId   Id
	Version uint64
	// EvsIndexStateOff where an admin turned the index off, so nothing was built; empty otherwise.
	Skipped string
	// The documents the build wrote, the messages the list named at its pin, and those it left out unopenable.
	EntryCount   int
	MessageCount int
	LeftOutCount int
}

// The first build of a mailbox's or group inbox's index: see the file header. ErrEvsIndexLocked where another device
// holds the index's lock, ErrEvsIndexExcluded for a repo that holds no index, ErrEvsIndexNewerFormat for an index a
// newer build wrote.
func MailIndexFirstBuild(ctx context.Context, args *MailIndexBuildArgs) (*MailIndexBuildResult, error) {
	if args == nil || args.Repo == nil {
		return nil, ErrMailIndexBuildArgs
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailIndexBuildSettings()
	}
	refId, err := args.Repo.RefIdOf(ctx, EvsMainRefName)
	if err != nil {
		return nil, err
	}
	content := &mailIndexContent{
		repo:     args.Repo,
		store:    newMailEvsStore(args.Repo, nil, settings.Store),
		refId:    refId,
		settings: settings,
		log:      loggerOrDefault(args.Log),
	}
	defer content.close()
	rebuilt, err := args.Repo.IndexRebuild(ctx, &EvsIndexRebuildArgs{contents: []indexContentRef{content}, groupInbox: args.GroupInbox})
	result := &MailIndexBuildResult{RefId: refId, MessageCount: len(content.messages), LeftOutCount: content.leftOut}
	if rebuilt != nil {
		result.Version, result.Skipped, result.EntryCount = rebuilt.Version, rebuilt.Skipped, rebuilt.EntryCount
	}
	return result, err
}

// One message of the list, as its m/ entry stands.
type mailIndexMessage struct {
	id Id
	// Its m/ path's version, and the ref version, signed time and signer of the push that wrote it.
	version       uint64
	commitVersion uint64
	signedTimeMs  int64
	signer        Id
	// Its plaintext's bytes, from the entry's sealed fields.
	byteCount uint64
	// Mail from outside the network, by its label (MailEntryUntrusted).
	outside bool
	// A message ingest wrote, whose label it set: no run wrote it.
	ingested bool
}

// The mail of one repo's main ref as an index build reads it (indexContentRef): see the file header.
type mailIndexContent struct {
	repo     *EvsRepo
	store    mailStore
	refId    Id
	settings *MailIndexBuildSettings
	log      Logger

	// The messages as the last load read them, by m/ path, at pin.
	pin      uint64
	loaded   bool
	messages map[string]*mailIndexMessage
	// The content State gave last, closed at the next State or close.
	open *evsSpill
	// Messages State left out unopenable since the last load.
	leftOut int
}

// See indexContentRef.
func (self *mailIndexContent) RefId() Id {
	return self.refId
}

// The ref's head read from evs now, the content ref's own (indexContentRef). A build of a file-mode ref's own index
// pins its view's base and never asks.
func (self *mailIndexContent) Head(ctx context.Context) (*indexContentHead, error) {
	result, err := self.repo.read(ctx, self.refId, []string{""}, 0, true)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	head := indexHeadOfEvs(result.head)
	return &indexContentHead{version: head.version, signedTimeMs: head.signedTimeMs}, nil
}

// The pushes in (afterVersion, throughVersion] that wrote a message's version, each with its signed time and signer,
// oldest first: what a build reads of pushes.
func (self *mailIndexContent) Pushes(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentPush, error) {
	if err := self.load(ctx, throughVersion); err != nil {
		return nil, err
	}
	byVersion := map[uint64]*indexContentPush{}
	for _, message := range self.messages {
		if message.commitVersion <= afterVersion || throughVersion < message.commitVersion {
			continue
		}
		byVersion[message.commitVersion] = &indexContentPush{version: message.commitVersion, signedTimeMs: message.signedTimeMs, signer: message.signer}
	}
	pushes := make([]*indexContentPush, 0, len(byVersion))
	for _, push := range byVersion {
		pushes = append(pushes, push)
	}
	slices.SortFunc(pushes, func(a *indexContentPush, b *indexContentPush) int { return cmp.Compare(a.version, b.version) })
	return pushes, nil
}

// Each message's m/ path standing at refVersion, in path order, with its plaintext's bytes.
func (self *mailIndexContent) Paths(ctx context.Context, refVersion uint64, visit func(path string, byteCount uint64) error) error {
	if err := self.load(ctx, refVersion); err != nil {
		return err
	}
	paths := make([]string, 0, len(self.messages))
	for path, message := range self.messages {
		if message.commitVersion <= refVersion {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := visit(path, self.messages[path].byteCount); err != nil {
			return err
		}
	}
	return nil
}

// A message's state at refVersion: its version and text, unopenable where its content is gone, or no version where
// the list names no such message standing at refVersion. The text stays readable until the next State or close.
func (self *mailIndexContent) State(ctx context.Context, path string, refVersion uint64) (*indexContentState, error) {
	self.closeOpen()
	if err := self.load(ctx, refVersion); err != nil {
		return nil, err
	}
	message := self.messages[path]
	if message == nil || refVersion < message.commitVersion {
		return &indexContentState{}, nil
	}
	state := &indexContentState{
		version: message.version, commitVersion: message.commitVersion, outside: message.outside, tainted: !message.ingested,
	}
	unopenable := func() (*indexContentState, error) {
		self.leftOut += 1
		state.unopenable = true
		return state, nil
	}
	if uint64(max(self.settings.MessageMaxByteCount, 0)) < message.byteCount {
		self.log.Warningf("[mail]index build %s: a message past the build's bound left out", self.repo.repoId)
		return unopenable()
	}
	spill := newEvsSpill(self.repo.client.args.Store, self.repo.client.settings.DeltaBaseMemoryByteCount)
	out := &mailIndexBoundedSpill{spill: spill, maxByteCount: max(self.settings.MessageMaxByteCount, 0)}
	info, err := self.repo.ReadHead(ctx, &EvsReadArgs{Path: path, Provenance: !message.ingested}, out)
	switch {
	case errors.Is(err, ErrEvsPathAbsent):
		spill.close()
		return &indexContentState{}, nil
	case errors.Is(err, ErrMailStoreTooLarge), errors.Is(err, ErrEvsObjectMissing), errors.Is(err, ErrEvsSealInvalid),
		errors.Is(err, ErrEvsEntryRefused):
		spill.close()
		return unopenable()
	case err != nil:
		spill.close()
		return nil, err
	}
	if info.Version != message.version || refVersion < info.CommitVersion {
		// a version the list's read did not show: not the one at the pin, which the next attempt reads again
		spill.close()
		return nil, fmt.Errorf("%w: a message's version moved under the build", errIndexCollected)
	}
	if !message.ingested {
		// a sent copy: its push's provenance, unknown read as tainted
		state.tainted = info.Provenance == nil || info.Provenance.Tainted
	}
	self.open = spill
	state.content, state.byteCount = spill, uint64(spill.Size())
	return state, nil
}

// Closes the text State gave last.
func (self *mailIndexContent) closeOpen() {
	if self.open != nil {
		self.open.close()
		self.open = nil
	}
}

// Closes what the build left open.
func (self *mailIndexContent) close() {
	self.closeOpen()
}

// Reads the message list and each message's entry, once a pin: see the file header.
func (self *mailIndexContent) load(ctx context.Context, pin uint64) error {
	if self.loaded && self.pin == pin {
		return nil
	}
	listed, err := self.listMessages(ctx)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(listed))
	for path := range listed {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	messages := map[string]*mailIndexMessage{}
	for start := 0; start < len(paths); start += max(self.settings.EntryReadCount, 1) {
		batch := paths[start:min(len(paths), start+max(self.settings.EntryReadCount, 1))]
		if err := self.readEntries(ctx, batch, listed, messages); err != nil {
			return err
		}
	}
	self.pin, self.loaded, self.messages, self.leftOut = pin, true, messages, 0
	return nil
}

// Every message i/ lists, by its m/ path, with what its entry says: the first entry of an id wins, as the view keeps
// it (mail_view.go). An entry that does not parse, or whose time is not its segment's month, names no path.
func (self *mailIndexContent) listMessages(ctx context.Context) (map[string]*mailIndexMessage, error) {
	names, err := self.store.List(ctx, mailIndexFamily)
	if errors.Is(err, ErrEvsPathAbsent) {
		return map[string]*mailIndexMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	months := []MailYearMonth{}
	for _, name := range names {
		if month, ok := ParseMailYearMonth(name); ok {
			months = append(months, month)
		}
	}
	slices.Sort(months)
	months = slices.Compact(months)
	listed := map[string]*mailIndexMessage{}
	for _, month := range months {
		numbers, err := mailListSegments(ctx, self.store, MailIndexDirectory(month))
		if err != nil {
			return nil, err
		}
		for _, n := range numbers {
			segment, _, err := self.store.Read(ctx, MailIndexPath(month, n), mailIndexSegmentReadMaxByteCount)
			if errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrMailStoreTooLarge) {
				continue
			}
			if err != nil {
				return nil, err
			}
			// a segment that stops parsing keeps what came before
			mailSegmentRecords(segment, func(index int, record []byte) error {
				entry := &protocol.IndexEntry{}
				if proto.Unmarshal(record, entry) != nil {
					return nil
				}
				id, err := IdFromBytes(entry.GetId())
				if err != nil || entry.GetTime() == 0 || MailYearMonthOf(entry.GetTime()) != month {
					return nil
				}
				path := MailMessagePath(month, id)
				if _, ok := listed[path]; !ok {
					listed[path] = &mailIndexMessage{
						id: id, outside: MailEntryUntrusted(entry),
						ingested: entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_LABEL_UNSPECIFIED,
					}
				}
				return nil
			})
		}
	}
	return listed, nil
}

// The verified entries of one batch of listed m/ paths, at the head: each standing message's version, its push and
// its size, into messages. A path with no file standing is no message.
func (self *mailIndexContent) readEntries(ctx context.Context, paths []string, listed map[string]*mailIndexMessage, messages map[string]*mailIndexMessage) error {
	result, err := self.repo.read(ctx, self.refId, paths, 0, false)
	if err != nil {
		return err
	}
	defer result.objects.close()
	for index, verified := range result.replies {
		if verified.Entry == nil || verified.Removal != nil || verified.Absent || verified.Base != nil ||
			verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) || verified.Statement == nil {
			continue
		}
		push := verified.Statement.Push
		manifest, err := result.keys.manifest(ctx, push.GetGeneration())
		if err != nil {
			return err
		}
		var fields *protocol.EvsSealedFields
		if verified.Entry.GetVersioning() == 0 {
			fields, err = EvsOpenFields(manifest, verified.Entry.GetSealedFields())
		} else {
			fields, err = EvsOpenFieldsFormat2(manifest, verified.Entry.GetSealedFields(), verified.Entry.GetVersioning())
		}
		if err != nil {
			return err
		}
		signer, err := IdFromBytes(push.GetSignerSidecarId())
		if err != nil {
			return fmt.Errorf("%w: a statement's signer", ErrEvsSealInvalid)
		}
		message := *listed[paths[index]]
		message.version, message.commitVersion = verified.Entry.GetVersion(), verified.CommitVersion
		message.signedTimeMs, message.signer, message.byteCount = push.GetTimeMs(), signer, fields.GetSize()
		messages[paths[index]] = &message
	}
	return nil
}

// A spill that refuses bytes past its bound with ErrMailStoreTooLarge.
type mailIndexBoundedSpill struct {
	spill        *evsSpill
	maxByteCount int64
}

// Keeps data, or refuses all of it where it would pass the bound.
func (self *mailIndexBoundedSpill) Write(data []byte) (int, error) {
	if self.maxByteCount < self.spill.Size()+int64(len(data)) {
		return 0, ErrMailStoreTooLarge
	}
	return self.spill.Write(data)
}
