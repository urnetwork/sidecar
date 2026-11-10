// POST /evs/v1/repos/<id>/read (§11.9; EVS1-M2-14): one request, one framed reply (read_frame.go), two store
// rounds, three with an uncached head (R-EVS-8):
//
//	head     from {evsh_} when §11.9's cache row allows it: within 10 min of its cache time, at least pin_version,
//	         and the request not fresh (a client reads fresh past a hinted version); else the cluster's. Nothing is
//	         served above this head: a folded version above its v sends evs to a newer head from the cluster
//	round 1  every path's entry by §11.6's read rule (its source copies while the head lists sources), and the
//	         records of the window versions after folded_through whose digest may touch a path, which §11.7's newest
//	         rule and a directory's listing then read from this process's cache
//	round 2  the statements after pin_version from the window's places, any statement that wrote a served version
//	         below the pin, the records the proofs need, the log page an older version's statement sits in, and the
//	         slots, maps, log pages, push records and segment ranges the request names
//	reply    the head summary; every statement after pin_version, or `behind` with the first missing version when
//	         the pin is older than the window, beside those the window holds; per path the newest version by the
//	         newest rule (an older one by number from its entry or the window), the statement that wrote it when not
//	         among those returned, its Merkle proof when the list is not inline, and the adjacent-leaf proofs of
//	         each later statement whose list is not inline and whose prefixes reach the path; a removed path its
//	         removal's push id, version and path version from its marker or the window; an overlay's path it holds
//	         no version of `base`; a directory its folded table, names_through and the deltas after it; then the
//	         objects (read_frame.go)
//
// Path epochs (DESIGN-DETAILS 9.2.4; EVS1-M2-45). A path names its token path in each epoch it names, at most 8, one
// an epoch, and evs matches them to the head by their epoch field, never by position: the head's current epoch's
// and the listed sources' are read by §11.6's read rule, and a path naming none in the current epoch is answered
// stale_epoch, nothing read for it. entry_epoch names the epoch whose copy served. Every statement is worked in its
// own epoch, e(w), which it declares:
//
//	served   the version, removal or delta at names_through a reply speaks for, committed at u: in the current epoch
//	         (after the newest cut-over) found by the current token path; else by the leaf place the fold recorded
//	         for it (leaf_part, leaf_index), else by the path's token path in e(u) when the request names one; the
//	         proof's leaf is the change itself, which the reader checks against its own token path in e(u)
//	absent   each statement w after max(u, pin_version) whose list is under changes_root: the adjacent-leaf proofs
//	         under the path's token path in e(w) when the request names one, nothing for w when it names none
//	history  an older version by number from the entry's folded versions by their leaf places, or with
//	         commit_version from that push's record by the path's token path in its epoch
//
// When evs can locate a version's change by neither, an inline list of an epoch the request names no token path in
// or a place left unrecorded, it answers the path with the statement alone, as 9.2.4's history does: the reader,
// finding its own token path in it, may name that epoch and ask again (question evs1-m2-45-inline-leaf-place). An
// elided version in an inline list is restored from the one write of its push whose bytes elide to its own. Window
// versions after folded_through are all the current epoch's (9.3's W1) and keep the current token path. evs never
// asks a client for a token.
//
// A placeholder head reads as absent (§11.8's first row). The route takes r, so a deposit-only principal is refused
// at the guard (FS-23). The {refs} streams form and moved_after are M6's (EVS1-M6-01) and answer 400 until then.
// A request whose reads fail before the first frame answers 503; one that fails after it ends the stream short,
// which the client reads as invalid and retries.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route templates.
const (
	evsReadRouteTemplate = "POST /evs/v1/repos/{repo_id}/read"
	evsRefsRouteTemplate = "GET /evs/v1/repos/{repo_id}/refs"
	evsLogRouteTemplate  = "GET /evs/v1/repos/{repo_id}/log"
)

// Every read route takes r, which rw and admin imply; deposit alone is refused.
const evsReadRights = sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin

// The read routes: the read, GET .../refs (refs.go) and GET .../log (log.go).
func (self *EvsEngine) readRoutes() []*EvsRoute {
	pattern := evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}"
	return []*EvsRoute{
		{Method: http.MethodPost, Pattern: pattern + "/read", Name: evsReadRouteTemplate, Rights: evsReadRights, Placed: true, Serve: self.serveRead},
		{Method: http.MethodGet, Pattern: pattern + "/refs", Name: evsRefsRouteTemplate, Rights: evsReadRights, Placed: true, Serve: self.serveRefs},
		{Method: http.MethodGet, Pattern: pattern + "/log", Name: evsLogRouteTemplate, Rights: evsReadRights, Placed: true, Serve: self.serveLog},
	}
}

// See the file header.
func (self *EvsEngine) serveRead(request *EvsRequest) {
	body := &protocol.EvsReadRequest{}
	if !request.ReadMessage(body, self.settings.RequestBodyMaxByteCount) {
		return
	}
	if len(body.GetRefs()) != 0 {
		// the streams form is M6's
		request.Note("streams")
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	refId, err := sidecar.IdFromBytes(body.GetRefId())
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	request.NoteRefIds(refId)
	read, err := self.newReadAttempt(request, body, refId)
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	reply, err := read.read()
	if err != nil {
		read.unavailableOn(err)
		return
	}
	read.stream(reply)
}

// One path as the request names it, with what the read found.
type readPath struct {
	// every token path the request names, by epoch, and the first it names, which a stale reply carries
	named map[uint64]sidecar.EvsTokenPath
	first sidecar.EvsTokenPath
	// named matched to the head served; stale when it names none in the head's current epoch
	tokens *EvsPathTokens
	stale  bool
	// 0 for the newest version, else the path version asked for, and the ref version its push committed at when
	// the request knows it
	version       uint64
	commitVersion uint64
	read          *EvsPathRead
	newest        *EvsNewest
	listing       *EvsListing
	reply         *protocol.EvsReadPathReply
}

// What one read gives before it streams.
type readReply struct {
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	behind     uint64
	paths      []*protocol.EvsReadPathReply
}

// One read request on its way: what it asked and what it read.
type readAttempt struct {
	engine   *EvsEngine
	request  *EvsRequest
	settings *EvsSettings
	ctx      context.Context
	cluster  sidecar.BlobCluster
	repoId   sidecar.Id
	refId    sidecar.Id
	body     *protocol.EvsReadRequest
	paths    []*readPath

	// the head served, and the pushes read against it
	head   *EvsStoredHead
	pushes *readPushes
	source *RecordPushSource
}

// The attempt for body, its paths parsed and its bounds held.
func (self *EvsEngine) newReadAttempt(request *EvsRequest, body *protocol.EvsReadRequest, refId sidecar.Id) (*readAttempt, error) {
	settings := self.settings
	if settings.ReadPathMaxCount < len(body.GetPaths()) || settings.ReadRangeMaxCount < len(body.GetRanges()) ||
		settings.ReadObjectMaxCount < len(body.GetSlotIds()) || settings.ReadObjectMaxCount < len(body.GetMaps()) ||
		settings.ReadObjectMaxCount < len(body.GetLogPages()) || settings.ReadObjectMaxCount < len(body.GetPushes()) {
		return nil, fmt.Errorf("%w: a read past its bounds", sidecar.ErrEvsPushInvalid)
	}
	rangeByteCount := int64(0)
	for _, readRange := range body.GetRanges() {
		if len(readRange.GetSegmentId()) != 32 || readRange.GetLength() == 0 {
			return nil, fmt.Errorf("%w: a range of no segment or no length", sidecar.ErrEvsPushInvalid)
		}
		rangeByteCount += int64(readRange.GetLength())
	}
	if settings.ReadRangeMaxByteCount < rangeByteCount {
		return nil, fmt.Errorf("%w: ranges past %d bytes", sidecar.ErrEvsPushInvalid, settings.ReadRangeMaxByteCount)
	}
	for _, slotId := range body.GetSlotIds() {
		if len(slotId) != 16 {
			return nil, fmt.Errorf("%w: a slot id of %d bytes", sidecar.ErrEvsPushInvalid, len(slotId))
		}
	}
	read := &readAttempt{
		engine:   self,
		request:  request,
		settings: settings,
		ctx:      request.Ctx,
		cluster:  request.Cluster,
		repoId:   request.RepoId,
		refId:    refId,
		body:     body,
	}
	for _, path := range body.GetPaths() {
		tokenPaths := path.GetTokenPaths()
		if len(tokenPaths) == 0 || sidecar.EvsReadPathMaxEpochCount < len(tokenPaths) {
			return nil, fmt.Errorf("%w: a path of %d token paths", sidecar.ErrEvsPushInvalid, len(tokenPaths))
		}
		readPath := &readPath{named: map[uint64]sidecar.EvsTokenPath{}, version: path.GetVersion(), commitVersion: path.GetCommitVersion()}
		for _, sourcePath := range tokenPaths {
			tokenPath, err := sidecar.ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
			if err != nil {
				return nil, err
			}
			epoch := sourcePath.GetEpoch()
			if _, named := readPath.named[epoch]; named || epoch == 0 {
				return nil, fmt.Errorf("%w: a token path of epoch %d named twice or of no epoch", sidecar.ErrEvsPushInvalid, epoch)
			}
			readPath.named[epoch] = tokenPath
			if readPath.first == nil {
				readPath.first = tokenPath
			}
		}
		if readPath.commitVersion != 0 && readPath.version == 0 {
			return nil, fmt.Errorf("%w: a commit version with no version", sidecar.ErrEvsPushInvalid)
		}
		read.paths = append(read.paths, readPath)
	}
	return read, nil
}

// 503 for a read that failed before the first frame; a head or record that breaks its shape alarms. A batch or
// record of a layout past this instance's is neither: the read needs format 2, answered 409 FORMAT_UNSUPPORTED
// {needs_format: 2}, so the reader waits on no retry and sees no outage (FS-72).
func (self *readAttempt) unavailableOn(err error) {
	if errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		self.request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED, NeedsFormat: sidecar.EvsRepoFormat2})
		return
	}
	if errors.Is(err, ErrEvsHeadInvalid) || errors.Is(err, ErrEvsStatementMismatch) || errors.Is(err, ErrEvsIndexEntryInvalid) {
		self.engine.log.Errorf("[evs] alarm read: repo %s ref %s: %v", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.refId), err)
		self.engine.metrics.alarms.Add(1, "read")
	}
	self.request.Unavailable(nil)
}

// The head and both rounds, against a newer head from the cluster when an entry sends evs there.
func (self *readAttempt) read() (*readReply, error) {
	engine := self.engine
	body := self.body
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierReadHeadBefore, barrierKey)
	head, err := engine.heads.ReadCached(self.ctx, self.cluster, self.repoId, self.refId, body.GetPinVersion(), body.GetFresh())
	testHookBarrier(BarrierReadHeadAfter, barrierKey)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt += 1 {
		self.head = head
		self.pushes = newReadPushes(engine, self.ctx, self.cluster, self.repoId, self.refId, head.Head)
		self.source = NewRecordPushSource(engine.records, self.cluster, self.repoId, self.refId)
		reply, err := self.readAt()
		switch {
		case errors.Is(err, ErrEvsEntryAheadOfHead), errors.Is(err, ErrEvsHorizonAhead):
			if self.settings.ReadHeadRetryCount <= attempt {
				return nil, err
			}
			// a folded version above the head's v: the newer head, from the cluster (§11.9's newest row)
			head, err = engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
			if err != nil {
				return nil, err
			}
			continue
		case err != nil:
			return nil, err
		}
		return reply, nil
	}
}

// Both rounds against self.head.
func (self *readAttempt) readAt() (*readReply, error) {
	head := self.head.Head
	for _, path := range self.paths {
		path.tokens = EvsPathTokensAt(path.named, head)
		path.stale = path.tokens.Current == nil
	}
	reply := &readReply{head: self.headSummary()}
	if self.head.Absent() || !evsHeadExists(head) {
		// no commit yet: every path is absent, and nothing is after any pin
		for _, path := range self.paths {
			if path.stale {
				reply.paths = append(reply.paths, staleReply(path))
				continue
			}
			reply.paths = append(reply.paths, &protocol.EvsReadPathReply{TokenPath: path.tokens.Current.Components()})
		}
		return reply, nil
	}
	if err := self.readEntries(); err != nil {
		return nil, err
	}
	for _, path := range self.paths {
		if path.stale {
			continue
		}
		if err := self.resolvePath(path); err != nil {
			return nil, err
		}
	}
	statements, behind, err := self.statementsAfterPin()
	if err != nil {
		return nil, err
	}
	reply.statements = statements
	reply.behind = behind
	for _, path := range self.paths {
		pathReply, err := self.pathReply(path)
		if err != nil {
			return nil, err
		}
		reply.paths = append(reply.paths, pathReply)
	}
	return reply, nil
}

// Whether the head is one some push committed, rather than a placeholder.
func evsHeadExists(head *protocol.EvsHead) bool {
	return head != nil && (0 < head.GetVersion() || head.GetRefKind() != 0 || head.GetRefMode() != 0)
}

// §11.8's fill row as a reader sees it, with the push sequence its last commit raised where {evsh_} holds it.
func (self *readAttempt) headSummary() *protocol.EvsHeadSummary {
	head := self.head.Head
	summary := &protocol.EvsHeadSummary{RefId: self.refId.Bytes()}
	if !evsHeadExists(head) {
		chain := sidecar.EvsChainStart(self.repoId, self.refId)
		summary.Chain = chain[:]
		return summary
	}
	summary.Version = head.GetVersion()
	summary.Chain = head.GetChain()
	summary.PushId = head.GetPushId()
	summary.RefKind = protocol.EvsRefKind(head.GetRefKind())
	summary.RefMode = protocol.EvsRefMode(head.GetRefMode())
	summary.OwnerSidecarId = head.GetOwnerSidecarId()
	summary.SealedRefName = head.GetSealedRefName()
	summary.Base = head.GetBase()
	summary.Auth = head.GetAuth()
	summary.GroupId = head.GetGroupId()
	summary.Generation = head.GetGeneration()
	summary.GenerationCommitment = head.GetGenerationCommitment()
	summary.PathEpoch = head.GetPathEpoch()
	summary.IndexEpoch = head.GetIndexEpoch()
	summary.Deleted = head.GetDeleted()
	summary.PushSequence = self.head.PushSequence
	if head.GetVersion() == 0 {
		chain := sidecar.EvsChainStart(self.repoId, self.refId)
		summary.Chain = chain[:]
	}
	return summary
}

// Round 1: every path's entry and the window records the newest rule may read, together.
func (self *readAttempt) readEntries() error {
	head := self.head.Head
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierReadEntriesBefore, barrierKey)
	defer testHookBarrier(BarrierReadEntriesAfter, barrierKey)
	var waitGroup sync.WaitGroup
	var errLock sync.Mutex
	var firstErr error
	note := func(err error) {
		errLock.Lock()
		defer errLock.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, path := range self.paths {
		if path.stale {
			continue
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			read, err := ReadPathEntry(self.ctx, self.cluster, self.repoId, self.refId, head, path.tokens)
			if err != nil {
				note(err)
				return
			}
			path.read = read
		}()
	}
	for _, place := range self.windowPlacesTouching() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			// a failure here only costs the newest rule its own read
			ReadRecord(self.ctx, self.engine.records, self.cluster, place)
		}()
	}
	waitGroup.Wait()
	return firstErr
}

// The places of the window versions after folded_through whose digest may touch a path or a prefix holding it.
func (self *readAttempt) windowPlacesTouching() []*protocol.EvsPlace {
	head := self.head.Head
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil
	}
	first := EvsHeadWindowFirstVersion(head)
	places := []*protocol.EvsPlace{}
	for i, entry := range window {
		if first+uint64(i) <= head.GetFoldedThrough() {
			continue
		}
		for _, path := range self.paths {
			if !path.stale && entry.PathsDigest.MayChange(path.tokens.Current) {
				places = append(places, entry.Place)
				break
			}
		}
	}
	return places
}

// §11.7's newest for one path at the head, and a standing directory's listing. An entry the head's window does not
// reach past is read again after the head.
func (self *readAttempt) resolvePath(path *readPath) error {
	head := self.head.Head
	for attempt := 0; attempt < 2; attempt += 1 {
		newest, err := Newest(self.ctx, path.read.EvsEntryRead, head, self.source)
		if errors.Is(err, ErrEvsEntryBehindWindow) && attempt == 0 {
			reread, readErr := ReadPathEntry(self.ctx, self.cluster, self.repoId, self.refId, head, path.tokens)
			if readErr != nil {
				return readErr
			}
			path.read = reread
			continue
		}
		if err != nil {
			return err
		}
		path.newest = newest
		if newest.Exists && newest.Directory {
			listing, err := Listing(self.ctx, path.read.EvsEntryRead, head, self.source)
			if err != nil {
				return err
			}
			path.listing = listing
		}
		return nil
	}
	return ErrEvsEntryBehindWindow
}

// The statements after pin_version, from the window's places, and `behind` when the pin is older than the window.
func (self *readAttempt) statementsAfterPin() ([]*protocol.EvsReadStatement, uint64, error) {
	head := self.head.Head
	pin := self.body.GetPinVersion()
	if head.GetVersion() <= pin {
		return nil, 0, nil
	}
	first := EvsHeadWindowFirstVersion(head)
	behind := uint64(0)
	if pin+1 < first {
		behind = pin + 1
	}
	versions := []uint64{}
	for version := max(pin+1, first); version <= head.GetVersion(); version += 1 {
		versions = append(versions, version)
	}
	statements := make([]*protocol.EvsReadStatement, len(versions))
	var waitGroup sync.WaitGroup
	var errLock sync.Mutex
	var firstErr error
	for i, version := range versions {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			entry := windowEntryAt(head, version)
			record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.repoId, self.refId, entry.Place)
			if err == nil {
				var statementBytes []byte
				statementBytes, err = recordStatementBytes(record)
				if err == nil && record.PushId == entry.PushId {
					statements[i] = &protocol.EvsReadStatement{Version: version, Statement: statementBytes}
					return
				}
				if err == nil {
					err = fmt.Errorf("%w: another push's record", ErrEvsStatementMismatch)
				}
			}
			errLock.Lock()
			defer errLock.Unlock()
			if firstErr == nil {
				firstErr = err
			}
		}()
	}
	waitGroup.Wait()
	if firstErr != nil {
		return nil, 0, firstErr
	}
	return statements, behind, nil
}

// A record's statement bytes, by its type.
func recordStatementBytes(record *sidecar.EvsBatchRecord) ([]byte, error) {
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, _, err := sidecar.ParseEvsPushRecordBody(record.Body)
		return statementBytes, err
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, _, err := sidecar.ParseEvsSealRecordBody(record.Body)
		return statementBytes, err
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		statementBytes, _, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		return statementBytes, err
	}
	return nil, fmt.Errorf("%w: a record of type %d", sidecar.ErrEvsPushInvalid, record.Type)
}

// A stale_epoch path's reply: the request named no token path in the head's current epoch, so nothing was read for
// it, and the reader asks again on this head (DESIGN-DETAILS 9.2.4).
func staleReply(path *readPath) *protocol.EvsReadPathReply {
	return &protocol.EvsReadPathReply{TokenPath: path.first.Components(), StaleEpoch: true}
}

// One path's reply: see the file header.
func (self *readAttempt) pathReply(path *readPath) (*protocol.EvsReadPathReply, error) {
	if path.stale {
		return staleReply(path), nil
	}
	head := self.head.Head
	newest := path.newest
	reply := &protocol.EvsReadPathReply{TokenPath: path.tokens.Current.Components(), EntryEpoch: path.read.SourceEpoch}
	since := uint64(0)
	deltaVersions := map[uint64]bool{}
	switch {
	case newest.Exists && !newest.Directory && path.version != 0 && newest.Version != path.version:
		// an older version by number: from its entry's folded versions, each of which its own push committed
		if err := self.olderVersion(path, reply); err != nil {
			return nil, err
		}
		return reply, nil
	case newest.Exists:
		version, located, err := self.versionReply(path, newest)
		if err != nil {
			return nil, err
		}
		if !located {
			return reply, self.statementAlone(reply, newest.CommitVersion)
		}
		reply.Version = version
		since = newest.CommitVersion
		if located, err := self.attachStatement(reply, path, newest.CommitVersion, evsLeafPlaceOfVersion(version), false); err != nil || !located {
			if err != nil {
				return nil, err
			}
			return reply, self.statementAlone(reply, newest.CommitVersion)
		}
		if listing := path.listing; listing != nil {
			reply.Names = &protocol.EvsNameTable{Names: listing.Names}
			reply.NamesThrough = listing.TableThrough
			for _, deltaVersion := range listing.DeltaVersions {
				deltaVersions[deltaVersion] = true
				// a delta after the table is an unfolded window version, of the current epoch (9.3's W1)
				delta, err := self.deltaReply(deltaVersion, path.tokens.Current)
				if err != nil {
					return nil, err
				}
				reply.Deltas = append(reply.Deltas, delta)
			}
		}
	case newest.RemovalVersion != 0:
		removal := &protocol.EvsRemovalMarker{
			PushId:         newest.PushId.Bytes(),
			RemovalVersion: newest.CommitVersion,
			PathVersion:    newest.RemovalVersion,
		}
		if marker := newest.Marker; marker != nil {
			removal.LeafPart, removal.LeafIndex = marker.GetLeafPart(), marker.GetLeafIndex()
		}
		reply.Removal = removal
		since = newest.CommitVersion
		if located, err := self.attachStatement(reply, path, newest.CommitVersion, evsLeafPlaceOfMarker(removal), true); err != nil || !located {
			if err != nil {
				return nil, err
			}
			return reply, self.statementAlone(reply, newest.CommitVersion)
		}
	case head.GetBase() != nil:
		reply.Base = head.GetBase()
	}
	absences, err := self.absences(path, since, deltaVersions)
	if err != nil {
		return nil, err
	}
	reply.Absences = absences
	return reply, nil
}

// A path's reply as the statement committed at commitVersion alone: what evs answers for a version or removal whose
// change it can locate in that statement by neither its leaf place nor a token path the request names (see the file
// header). The reader asks again naming that statement's epoch once it finds its own token path there.
func (self *readAttempt) statementAlone(reply *protocol.EvsReadPathReply, commitVersion uint64) error {
	push, err := self.pushes.at(commitVersion)
	if err != nil {
		return err
	}
	reply.Version = nil
	reply.Removal = nil
	reply.Proof = nil
	reply.Names = nil
	reply.NamesThrough = 0
	reply.Deltas = nil
	reply.Absences = nil
	reply.Statement = push.statement.Bytes
	return nil
}

// The newest version as an EvsIndexVersion, never elided, with its leaf place: from the window's change, or from the
// entry, with its bodies restored from its push record when elided or when a directory's table carries none, its
// change located in the push's own epoch. located false when that change cannot be (see the file header).
func (self *readAttempt) versionReply(path *readPath, newest *EvsNewest) (*protocol.EvsIndexVersion, bool, error) {
	version := &protocol.EvsIndexVersion{PushId: newest.PushId.Bytes(), CommitVersion: newest.CommitVersion}
	place := evsLeafPlace{}
	switch {
	case newest.Change != nil:
		// a window version after folded_through, of the current epoch
		version.EntryVersion = newest.Change.EntryVersion
		return version, true, nil
	case newest.IndexVersion != nil:
		place = evsLeafPlaceOfVersion(newest.IndexVersion)
		if !newest.IndexVersion.GetElided() {
			version.EntryVersion = newest.IndexVersion.GetEntryVersion()
			version.LeafPart, version.LeafIndex = place.part, place.index
			return version, true, nil
		}
	case path.read.Entry != nil:
		// a directory's folded table: its delta at names_through
		place = evsLeafPlaceOfTable(path.read.Entry)
	}
	push, err := self.pushes.at(newest.CommitVersion)
	if err != nil {
		return nil, false, err
	}
	entryVersion, err := self.entryVersionIn(push, path, place, newest.IndexVersion)
	if err != nil || entryVersion == nil {
		return nil, false, err
	}
	version.PushId = push.statement.Push.GetPushId()
	version.EntryVersion = entryVersion
	version.LeafPart, version.LeafIndex = place.part, place.index
	return version, true, nil
}

// The EvsEntryVersion bytes the push wrote for the path, its change located in the push's own epoch, or for an elided
// version of an inline list matched by its elided bytes; nil when neither finds it.
func (self *readAttempt) entryVersionIn(push *readPush, path *readPath, place evsLeafPlace, elided *protocol.EvsIndexVersion) ([]byte, error) {
	change, _, _, err := self.locate(push, path, place, false)
	if err != nil {
		return nil, err
	}
	if change != nil {
		if !change.WritesEntry() {
			return nil, fmt.Errorf("%w: version %d's change for the path writes nothing", ErrEvsIndexEntryInvalid, push.version)
		}
		return change.EntryVersion, nil
	}
	if elided == nil || push.rooted() {
		return nil, nil
	}
	return self.pushes.inlineEntryVersionEliding(push, elided)
}

// A directory's delta at version: its entry version as its push carried it.
func (self *readAttempt) deltaReply(version uint64, tokenPath sidecar.EvsTokenPath) (*protocol.EvsIndexVersion, error) {
	push, err := self.pushes.at(version)
	if err != nil {
		return nil, err
	}
	entryVersion, err := self.pushes.entryVersionOf(push, tokenPath)
	if err != nil {
		return nil, err
	}
	if len(entryVersion) == 0 {
		return nil, fmt.Errorf("%w: version %d does not write the directory its listing names it for", ErrEvsStatementMismatch, version)
	}
	return &protocol.EvsIndexVersion{PushId: push.statement.Push.GetPushId(), CommitVersion: version, EntryVersion: entryVersion}, nil
}

// Where the change of the path a reply speaks for sits in push, worked in the push's own epoch (see the file header):
// its part and index, and nil when it cannot be located. A change of the current epoch's push that its token path
// does not find, or a leaf place the push does not have, is a fault.
func (self *readAttempt) locate(push *readPush, path *readPath, place evsLeafPlace, removal bool) (*sidecar.EvsCheckedChange, int, int, error) {
	epoch := push.statement.Push.GetPathEpoch()
	current := EvsHeadCurrentEpoch(self.head.Head)
	byTokenPath := func(tokenPath sidecar.EvsTokenPath) (*sidecar.EvsCheckedChange, int, int, error) {
		if removal {
			return self.pushes.removalOf(push, tokenPath)
		}
		return self.pushes.changeOf(push, tokenPath)
	}
	if epoch == current {
		change, part, index, err := byTokenPath(path.tokens.Current)
		if err == nil && change == nil {
			err = fmt.Errorf("%w: version %d does not change the path its entry names it for", ErrEvsStatementMismatch, push.version)
		}
		return change, part, index, err
	}
	if push.rooted() && place.index != 0 {
		change, part, index, err := self.pushes.changeAt(push, place)
		if err == nil && removal == change.WritesEntry() {
			err = fmt.Errorf("%w: version %d's change at the place recorded is not what the entry holds", ErrEvsIndexEntryInvalid, push.version)
		}
		return change, part, index, err
	}
	if tokenPath := path.tokens.In(epoch, current); tokenPath != nil {
		return byTokenPath(tokenPath)
	}
	return nil, 0, 0, nil
}

// The statement that wrote the version or removal at commitVersion, when the reply does not return it among those
// after the pin, and its proof to changes_root when the list is not inline: the path's own change, or for a removal
// the change removing it or a prefix holding it, located in the statement's own epoch. located false when it cannot
// be, and the reply then carries no proof.
func (self *readAttempt) attachStatement(reply *protocol.EvsReadPathReply, path *readPath, commitVersion uint64, place evsLeafPlace, removal bool) (bool, error) {
	push, err := self.pushes.at(commitVersion)
	if err != nil {
		return false, err
	}
	if commitVersion <= self.body.GetPinVersion() || commitVersion < EvsHeadWindowFirstVersion(self.head.Head) {
		reply.Statement = push.statement.Bytes
	}
	if !push.rooted() {
		// the statement holds the list, which the reader reads under its own token path in the statement's epoch
		return true, nil
	}
	change, part, index, err := self.locate(push, path, place, removal)
	if err != nil || change == nil {
		return false, err
	}
	reply.Proof, err = self.pushes.inclusionProof(push, part, index)
	return err == nil, err
}

// For each statement after since among those the reply returns whose list is not inline and whose covering
// prefixes reach the path or a prefix holding it, the adjacent-leaf proofs for each such path the push did not
// change, under the path's token path in that statement's epoch, and nothing for a statement of an epoch the request
// names none in; a directory's own deltas are its reply's, and a prefix the push changed is shown by nothing here.
func (self *readAttempt) absences(path *readPath, since uint64, deltaVersions map[uint64]bool) ([]*protocol.EvsAbsenceProof, error) {
	head := self.head.Head
	current := EvsHeadCurrentEpoch(head)
	absences := []*protocol.EvsAbsenceProof{}
	for version := max(since, self.body.GetPinVersion()) + 1; version <= head.GetVersion(); version += 1 {
		if deltaVersions[version] {
			continue
		}
		// a version below the window is read with its log page, which a reader behind the window walks too
		entry := windowEntryAt(head, version)
		if entry == nil {
			push, err := self.pushes.at(version)
			if err != nil {
				return nil, err
			}
			entry = push.entry
		}
		if !entry.ChangesInPayload() || !path.tokens.MayChangeIn(entry.PathsDigest) {
			continue
		}
		push, err := self.pushes.at(version)
		if err != nil {
			return nil, err
		}
		tokenPath := path.tokens.In(push.statement.Push.GetPathEpoch(), current)
		if tokenPath == nil || !entry.PathsDigest.MayChange(tokenPath) {
			continue
		}
		for _, absentPath := range sidecar.EvsAbsencePaths(push.statement.ChangedPrefixes, tokenPath) {
			absence, err := self.pushes.absenceProof(push, absentPath)
			if err != nil {
				return nil, err
			}
			if absence != nil {
				absences = append(absences, absence)
			}
		}
	}
	return absences, nil
}

// An older version by number (§11.9's "older ones on request"; DESIGN-DETAILS 9.2.4's history): from the entry's
// folded versions, by their leaf places, with the statement that wrote it and its proof; else from the window; else,
// with commit_version, from that push's record by the path's token path in its epoch, or the statement alone when the
// request names none there. One none of these holds answers the path with no version, which a reader takes as absent
// at that number.
func (self *readAttempt) olderVersion(path *readPath, reply *protocol.EvsReadPathReply) error {
	tokenPath := path.tokens.Current
	if entry := path.read.Entry; entry != nil {
		for _, version := range entry.GetVersions() {
			entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
			if err != nil || entryVersion.GetVersion() != path.version {
				continue
			}
			place := evsLeafPlaceOfVersion(version)
			served := &protocol.EvsIndexVersion{
				PushId: version.GetPushId(), CommitVersion: version.GetCommitVersion(), EntryVersion: version.GetEntryVersion(),
				LeafPart: place.part, LeafIndex: place.index,
			}
			if version.GetElided() {
				push, err := self.pushes.at(version.GetCommitVersion())
				if err != nil {
					return err
				}
				if served.EntryVersion, err = self.entryVersionIn(push, path, place, version); err != nil {
					return err
				}
				if served.EntryVersion == nil {
					return self.statementAlone(reply, version.GetCommitVersion())
				}
			}
			reply.Version = served
			located, err := self.attachStatement(reply, path, version.GetCommitVersion(), place, false)
			if err != nil {
				return err
			}
			if !located {
				return self.statementAlone(reply, version.GetCommitVersion())
			}
			return nil
		}
	}
	// the window's versions of the path after the entry's horizon, the current epoch's, newest first
	head := self.head.Head
	for version := head.GetVersion(); EvsHeadWindowFirstVersion(head) <= version && path.read.FoldedThrough < version; version -= 1 {
		entry := windowEntryAt(head, version)
		if !entry.PathsDigest.MayChange(tokenPath) {
			continue
		}
		push, err := self.pushes.at(version)
		if err != nil {
			return err
		}
		change, _, _, err := self.pushes.changeOf(push, tokenPath)
		if err != nil {
			return err
		}
		if change == nil || !change.WritesEntry() {
			continue
		}
		entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil || entryVersion.GetVersion() != path.version {
			continue
		}
		reply.Version = &protocol.EvsIndexVersion{PushId: push.statement.Push.GetPushId(), CommitVersion: version, EntryVersion: change.EntryVersion}
		_, err = self.attachStatement(reply, path, version, evsLeafPlace{}, false)
		return err
	}
	return self.versionAtCommit(path, reply)
}

// History by commit_version (DESIGN-DETAILS 9.2.4): the version asked for, from the push the request says committed
// it, located by the path's token path in that push's epoch; the statement alone when the request names none there,
// and nothing when the push did not write that version of the path.
func (self *readAttempt) versionAtCommit(path *readPath, reply *protocol.EvsReadPathReply) error {
	commitVersion := path.commitVersion
	if commitVersion == 0 || self.head.Head.GetVersion() < commitVersion {
		return nil
	}
	push, err := self.pushes.at(commitVersion)
	if err != nil {
		return err
	}
	tokenPath := path.tokens.In(push.statement.Push.GetPathEpoch(), EvsHeadCurrentEpoch(self.head.Head))
	if tokenPath == nil {
		return self.statementAlone(reply, commitVersion)
	}
	change, _, _, err := self.pushes.changeOf(push, tokenPath)
	if err != nil || change == nil || !change.WritesEntry() {
		return err
	}
	entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
	if err != nil || entryVersion.GetVersion() != path.version {
		return nil
	}
	reply.Version = &protocol.EvsIndexVersion{PushId: push.statement.Push.GetPushId(), CommitVersion: commitVersion, EntryVersion: change.EntryVersion}
	_, err = self.attachStatement(reply, path, commitVersion, evsLeafPlace{}, false)
	return err
}
