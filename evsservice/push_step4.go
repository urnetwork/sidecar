// Step 4 (§11.8): what a push reads before step 5 checks it, and the view check.go's functions run over.
//
//	head    the verified cache entry when its version is at least the push's base, else a cluster GET; a refusal on
//	        a cached head runs step 4 again from the cluster (push.go)
//	state   the authorization state: the gate view of the repo's network, read from memory again at the start of
//	        each run, before the head, so step 7, issued within PushStepSevenWindow of step 4's reads, is within it
//	        of the state it validated against (§11.8's timing row; QD-660); bind's read at arrival judges only
//	        bind's own 5b
//	round   one round on the repo's cluster after it, issued together: repo/ (cached at most 5 s), the generation
//	        record, its signer's key from that state, every changed path's entry by §11.6's read rule (its source
//	        copies included while the head lists sources), each reuse source's ref head and entry, and the records
//	        of the window versions after folded_through whose digest may touch a changed path, which the newest rule
//	        then reads from this process's cache
//	view    §11.7's newest per changed path, each entry combined only with the head read before it; a directory's
//	        listing where the push writes its table; the flags of the head's push (IMMUTABLE); C at the push's base
//
// After a 412 (outcome.go) the entries stay as read, keeping the folded_through they were read after, and the gate
// view is read again and the view built again on the reread head: an entry the reread head's window no longer
// reaches past is read again after that head (ErrEvsEntryBehindWindow), and an entry holding a version past the head
// sends the attempt back to step 4 (ErrEvsEntryAheadOfHead).

package evsservice

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What step 4 read for one attempt. See the file header.
type pushReads struct {
	// when step 4's reads were issued, by the engine's clock: step 7 issues within PushStepSevenWindow of it
	readAt time.Time
	repo   *EvsRepoRead
	// gen/<g> of the push's group and generation; nil when gkm holds none
	generation          *protocol.GenRotate
	overlayBaseVersions []uint64
	// the head of the ref a creating push's section 16 names, nil for none (DESIGN-DETAILS 8.2.2)
	overlayBase *protocol.EvsHead
	// each changed path's entry, by its token path's KeyString
	entries map[string]*EvsPathRead
	reuses  []*ReuseRead
	// what step 5 checks
	view *PushView
}

// Step 4, from the cache when cached allows it. A nil outcome with rerun false has built the view; rerun true asks
// for step 4 again from the cluster.
func (self *pushAttempt) step4(cached bool) *pushOutcome {
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushStep4Before, barrierKey)
	defer testHookBarrier(BarrierPushStep4After, barrierKey)
	for rerun := 0; rerun <= self.settings.PushRerunCount; rerun += 1 {
		outcome, again := self.readStep4(cached)
		if !again {
			return outcome
		}
		cached = false
	}
	return self.busy()
}

// One run of step 4. again asks for another from the cluster.
func (self *pushAttempt) readStep4(cached bool) (*pushOutcome, bool) {
	engine := self.engine
	push := self.statement.Push
	readAt := engine.clock.Now()
	if outcome := self.readGateView(); outcome != nil {
		return outcome, false
	}
	var head *EvsStoredHead
	var err error
	switch {
	case self.seal != nil && self.seal.head != nil:
		// the cluster's head the seal read in its parts' round (push_seal.go), used once
		head, self.seal.head = self.seal.head, nil
	case cached:
		head, err = engine.heads.ReadCached(self.ctx, self.cluster, self.repoId, self.refId, push.GetBaseVersion(), false)
	default:
		head, err = engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	}
	if err != nil {
		return self.unavailableOn(err), false
	}
	self.head = head
	reads := &pushReads{readAt: readAt, entries: map[string]*EvsPathRead{}}

	// the round after the head, issued together
	var waitGroup sync.WaitGroup
	var repoErr, generationErr, overlayErr error
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		reads.repo, repoErr = engine.repos.Read(self.ctx, self.cluster, self.repoId)
	}()
	go func() {
		defer waitGroup.Done()
		groupId, idErr := sidecar.IdFromBytes(push.GetGroupId())
		if idErr != nil {
			return
		}
		reads.generation, generationErr = engine.generations.Read(self.ctx, self.cluster, groupId, push.GetGeneration(), self.gateView)
	}()
	go func() {
		defer waitGroup.Done()
		if self.payload == nil || self.payload.Base == nil || (!head.Absent() && head.Head.GetVersion() != 0 && !head.Head.GetDeleted()) {
			reads.overlayBaseVersions, overlayErr = engine.overlays.BaseVersions(self.ctx, self.cluster, self.repoId, self.refId, head)
			return
		}
		// a creating push of an overlay: its chain starts at the base section 16 names, whose head is read here for
		// 5c's base rule and for the chain past it
		reads.overlayBase, reads.overlayBaseVersions, overlayErr = self.readOverlayBase(self.payload.Base)
	}()
	var entryLock sync.Mutex
	entryErrs := []error{}
	if self.payload != nil {
		for _, change := range self.payload.Changes {
			tokens, tokensErr := evsPathTokensOf(change)
			if tokensErr != nil {
				return refusedOutcome(newEvsCheckRefusal(EvsCheckReasonInvalid, "a source path that does not parse").Reply(self.pushId)), false
			}
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				read, readErr := ReadPathEntry(self.ctx, self.cluster, self.repoId, self.refId, head.Head, tokens)
				entryLock.Lock()
				defer entryLock.Unlock()
				if readErr != nil {
					entryErrs = append(entryErrs, readErr)
					return
				}
				reads.entries[change.TokenPath.KeyString()] = read
			}()
		}
		// the window records the newest rule will read, into this process's cache, in the same round
		for _, place := range self.windowPlacesTouching(head.Head) {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				// a failure here only costs the newest rule its own read
				ReadRecord(self.ctx, engine.records, self.cluster, place)
			}()
		}
		reads.reuses = make([]*ReuseRead, len(self.payload.ReuseList))
		for i, reuse := range self.payload.ReuseList {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				read, readErr := self.readReuse(reuse)
				entryLock.Lock()
				defer entryLock.Unlock()
				if readErr != nil {
					entryErrs = append(entryErrs, readErr)
					return
				}
				reads.reuses[i] = read
			}()
		}
	}
	waitGroup.Wait()
	switch {
	case errors.Is(repoErr, sidecar.ErrEvsRepoNotFound):
		// a placed repo whose repo/ was never written: nothing to push to
		return refusedOutcome(&protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND}), false
	case repoErr != nil:
		return self.unavailableOn(repoErr), false
	case generationErr != nil, overlayErr != nil:
		return self.unavailableOn(errors.Join(generationErr, overlayErr)), false
	case 0 < len(entryErrs):
		return self.unavailableOn(errors.Join(entryErrs...)), false
	}
	if !reads.repo.FormatWithin(self.settings.InstanceFormat) {
		// a repo of a format past this instance's, a format-2 repo on a format-1 binary: 503 before anything is
		// written, refusing nothing (plan-EVS1-format-unsupported#4)
		return self.unavailable(), false
	}
	if networkId, err := sidecar.IdFromBytes(reads.repo.Object.GetNetworkId()); err == nil {
		self.networkId = networkId
	}
	self.reads = reads
	return self.buildView()
}

// The newest gate view of the repo's network into self.gateView, at each run of step 4 and at each rerun of 5 (b-h)
// on a head a 412 or a lost answer made the attempt reread (QD-660): what 5 judges, 5d's predicate above all, so a
// rerun after step 7's window passed meets the removals evs has learned since. One map read, no I/O. A state no
// longer loaded answers 503, refusing nothing.
func (self *pushAttempt) readGateView() *pushOutcome {
	views := self.engine.deps.GateViews
	if views == nil {
		return self.unavailable()
	}
	view, answer := views.View(self.networkId)
	if answer != EvsAuthAllowed || view == nil {
		return self.unavailable()
	}
	self.gateView = view
	return nil
}

// The places of the window versions after the head's folded_through whose digest may touch a changed path or a
// prefix holding it: what the newest rule reads for this push (§11.8 step 4's statements).
func (self *pushAttempt) windowPlacesTouching(head *protocol.EvsHead) []*protocol.EvsPlace {
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
		for _, change := range self.payload.Changes {
			if entry.PathsDigest.MayChange(change.TokenPath) {
				places = append(places, entry.Place)
				break
			}
		}
	}
	return places
}

// A change's token paths as §11.6's read rule takes them: its path in the current epoch and in each source its
// payload names.
func evsPathTokensOf(change *sidecar.EvsCheckedChange) (*EvsPathTokens, error) {
	tokens := &EvsPathTokens{Current: change.TokenPath}
	for _, encoded := range change.SourcePaths {
		sourcePath := &protocol.EvsSourcePath{}
		if err := proto.Unmarshal(encoded, sourcePath); err != nil {
			return nil, fmt.Errorf("%w: a source path that does not parse", sidecar.ErrEvsPushInvalid)
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
		if err != nil {
			return nil, err
		}
		tokens.Sources = append(tokens.Sources, &EvsSourceTokenPath{Epoch: sourcePath.GetEpoch(), TokenPath: tokenPath})
	}
	return tokens, nil
}

// A creating push's overlay base: the head of the ref section 16 names, at least at the version it names when it has
// one, and the base versions of the chain from it, k first then the base ref's own chain. A base ref with no head
// answers a placeholder and no chain, which 5c refuses.
func (self *pushAttempt) readOverlayBase(base *protocol.EvsOverlay) (*protocol.EvsHead, []uint64, error) {
	engine := self.engine
	baseRefId, err := sidecar.IdFromBytes(base.GetRefId())
	if err != nil {
		return nil, nil, err
	}
	// the cluster's head, whose current epoch and block an overlay's first push is held to (DESIGN-DETAILS 9.2.6)
	baseHead, err := engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, baseRefId)
	if err != nil {
		return nil, nil, err
	}
	if baseHead.Absent() {
		return &protocol.EvsHead{}, nil, nil
	}
	chain, err := engine.overlays.BaseVersions(self.ctx, self.cluster, self.repoId, baseRefId, baseHead)
	if err != nil {
		return nil, nil, err
	}
	return baseHead.Head, append([]uint64{base.GetVersion()}, chain...), nil
}

// One reuse source: its ref's head, then the version committed in that ref's entry or, with its statement, in its
// window (§11.8 step 4's reuse). A ref or version step 4 finds none of leaves EntryVersion nil, which 5h refuses.
func (self *pushAttempt) readReuse(reuse *sidecar.EvsReuse) (*ReuseRead, error) {
	engine := self.engine
	read := &ReuseRead{Reuse: reuse}
	refHead, err := engine.heads.ReadCached(self.ctx, self.cluster, self.repoId, reuse.RefId, 0, false)
	if err != nil {
		return nil, err
	}
	if refHead.Absent() || refHead.Version() == 0 {
		return read, nil
	}
	entryRead, err := ReadEntry(self.ctx, self.cluster, self.repoId, reuse.RefId, EvsHeadCurrentEpoch(refHead.Head), reuse.TokenPath, refHead.Head.GetFoldedThrough())
	if err != nil {
		return nil, err
	}
	for _, version := range entryRead.Entry.GetVersions() {
		entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
		if err == nil && entryVersion.GetVersion() == reuse.EntryVersion && !version.GetElided() {
			read.EntryVersion = entryVersion
			return read, nil
		}
	}
	window, err := EvsHeadWindow(refHead.Head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	pushes := NewRecordPushSource(engine.records, engine.locator, self.cluster, self.repoId, reuse.RefId)
	first := EvsHeadWindowFirstVersion(refHead.Head)
	for i := len(window) - 1; 0 <= i; i -= 1 {
		if !window[i].PathsDigest.MayChange(reuse.TokenPath) {
			continue
		}
		changes, err := pushes.ChangesAt(self.ctx, first+uint64(i), window[i], reuse.TokenPath)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			if !change.TokenPath.Equal(reuse.TokenPath) || change.Removes() {
				continue
			}
			entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
			if err == nil && entryVersion.GetVersion() == reuse.EntryVersion {
				read.EntryVersion = entryVersion
				return read, nil
			}
		}
	}
	return read, nil
}

// The view step 5 checks, over self.head and what step 4 read. again asks for step 4 again from the cluster.
func (self *pushAttempt) buildView() (*pushOutcome, bool) {
	engine := self.engine
	reads := self.reads
	head := self.head
	push := self.statement.Push
	request := self.request
	view := &PushView{
		Stage:               self.stage(),
		RepoId:              self.repoId,
		Statement:           self.statement,
		Payload:             self.payload,
		TokenSidecarId:      request.SidecarId,
		TokenClientId:       sidecar.Id(request.Principal.ClientId),
		Rights:              request.Rights,
		Repo:                reads.repo.Object,
		Head:                head.Head,
		Now:                 engine.clock.Now(),
		TimeBound:           self.timeBound(),
		Auth:                self.gateView,
		Generation:          reads.generation,
		Paths:               map[string]*PathRead{},
		OverlayBaseVersions: reads.overlayBaseVersions,
		OverlayBase:         reads.overlayBase,
		Receipts:            self.receipts,
		Reuses:              reads.reuses,
		NetworkId:           self.networkId,
		InstanceFormat:      self.settings.InstanceFormat,
		NeedsFormat2:        self.needsFormat2,
		Format2Rules:        engine.deps.Format2Rules,
	}
	if self.needsFormat2 {
		// the gate, read once per round of steps 4 and 5, so a rerun meets a gate that moved
		view.Format2Admitted = engine.format2.Admits(self.networkId)
	}
	if self.payload == nil {
		// a format-2 payload at a format-1 instance, or a seal's before its parts: only 5a and its refusal run
		reads.view = view
		return nil, false
	}
	if uploads := engine.deps.Uploads; uploads != nil {
		view.ReceiptKeys = uploads.Keys
		if uploads.Quota != nil {
			view.Quota = uploads.Quota
		}
		// §19.9's cohort limit, read once per round of steps 4 and 5 from the cluster's last allowance
		view.ClusterFull = uploads.ClusterLimit.Full(self.cluster.ClusterId())
		view.ClusterFullRetryAfter = uploads.ClusterLimit.RetryAfter()
	}
	flags, err := self.headFlags(head.Head)
	if err != nil {
		return self.unavailableOn(err), false
	}
	view.HeadFlags = flags
	baseChain, err := self.baseChainAt(head.Head, push.GetBaseVersion())
	if err != nil {
		return self.unavailableOn(err), false
	}
	view.BaseChain = baseChain

	for _, change := range self.payload.Changes {
		key := change.TokenPath.KeyString()
		read := reads.entries[key]
		if read == nil {
			return self.unavailableOn(fmt.Errorf("a changed path step 4 did not read")), false
		}
		pathRead, again, err := self.newestOf(change, read)
		if err != nil {
			return self.unavailableOn(err), false
		}
		if again {
			return nil, true
		}
		view.Paths[key] = pathRead
	}
	due, err := self.pathEpochDueOver(head.Head)
	if err != nil {
		return self.unavailableOn(err), false
	}
	self.due = due
	view.CrossingDue = due
	self.pathEpoch = nil
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		pathEpoch, err := self.readPathEpoch(head.Head)
		if err != nil {
			return self.unavailableOn(err), false
		}
		self.pathEpoch = pathEpoch
	}
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) != 0 && self.erasureSlots == nil {
		if err := self.readErasureSlots(); err != nil {
			return self.unavailableOn(err), false
		}
	}
	view.PathEpochRules = self.pathEpochRules
	view.ErasureRules = self.erasureRules
	reads.view = view
	return nil, false
}

// §11.7's newest for one changed path at self.head, and its listing where the push writes a directory's table. An
// entry the head's window does not reach past is read again after it; again asks for step 4 again.
func (self *pushAttempt) newestOf(change *sidecar.EvsCheckedChange, read *EvsPathRead) (*PathRead, bool, error) {
	head := self.head.Head
	for attempt := 0; attempt < 2; attempt += 1 {
		newest, err := Newest(self.ctx, read.EvsEntryRead, head, self.pushes)
		switch {
		case errors.Is(err, ErrEvsEntryBehindWindow) && attempt == 0:
			// the head moved past the entry's horizon: the entry again, after this head
			tokens, tokensErr := evsPathTokensOf(change)
			if tokensErr != nil {
				return nil, false, tokensErr
			}
			reread, readErr := ReadPathEntry(self.ctx, self.cluster, self.repoId, self.refId, head, tokens)
			if readErr != nil {
				return nil, false, readErr
			}
			self.reads.entries[change.TokenPath.KeyString()] = reread
			read = reread
			continue
		case errors.Is(err, ErrEvsEntryAheadOfHead), errors.Is(err, ErrEvsHorizonAhead):
			return nil, true, nil
		case err != nil:
			return nil, false, err
		}
		pathRead := &PathRead{Newest: newest}
		if self.writesDirectoryTable(change) {
			listing, err := Listing(self.ctx, read.EvsEntryRead, head, self.pushes)
			if err != nil {
				return nil, false, err
			}
			pathRead.Listing = listing
		}
		return pathRead, false, nil
	}
	return nil, true, nil
}

// Whether change writes a directory's entry version, whose bound 5g checks against its listing.
func (self *pushAttempt) writesDirectoryTable(change *sidecar.EvsCheckedChange) bool {
	if !change.WritesEntry() {
		return false
	}
	entry, err := parseEvsEntryVersion(change.EntryVersion)
	return err == nil && protocol.EvsEntryKind(entry.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
}

// The flags of the push committed at the head's version, which say whether a git-mode ref is IMMUTABLE. 0 for a
// file-mode ref, which takes no IMMUTABLE, and for a ref with no committed head.
func (self *pushAttempt) headFlags(head *protocol.EvsHead) (uint32, error) {
	if head == nil || head.GetVersion() == 0 || protocol.EvsRefMode(head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
		return 0, nil
	}
	window, err := EvsHeadWindow(head)
	if err != nil || len(window) == 0 {
		return 0, fmt.Errorf("%w: a committed head with no window", ErrEvsHeadInvalid)
	}
	statement, err := self.pushes.statementAt(self.ctx, head.GetVersion(), window[len(window)-1])
	if err != nil {
		return 0, err
	}
	return statement.Push.GetFlags(), nil
}

// C at version b as the head establishes it: its chain at v, its window from window_base_chain forward through
// each version's statement, or C_0 at 0. nil when b lies before the window, which 5f refuses on its own.
func (self *pushAttempt) baseChainAt(head *protocol.EvsHead, baseVersion uint64) (*[32]byte, error) {
	start := sidecar.EvsChainStart(self.repoId, self.refId)
	if head == nil || head.GetVersion() == 0 {
		if baseVersion == 0 {
			return &start, nil
		}
		return nil, nil
	}
	if baseVersion == 0 {
		return &start, nil
	}
	version := head.GetVersion()
	if version < baseVersion {
		return nil, nil
	}
	if baseVersion == version {
		chain, err := sidecar.EvsChainFromBytes(head.GetChain())
		if err != nil {
			return nil, fmt.Errorf("%w: a head chain of %d bytes", ErrEvsHeadInvalid, len(head.GetChain()))
		}
		return &chain, nil
	}
	first := EvsHeadWindowFirstVersion(head)
	if baseVersion+1 < first {
		return nil, nil
	}
	chain, err := sidecar.EvsChainFromBytes(head.GetWindowBaseChain())
	if err != nil {
		return nil, fmt.Errorf("%w: a window base chain of %d bytes", ErrEvsHeadInvalid, len(head.GetWindowBaseChain()))
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	for version := first; version <= baseVersion; version += 1 {
		entry := window[version-first]
		statement, err := self.pushes.statementAt(self.ctx, version, entry)
		if err != nil {
			return nil, err
		}
		chain = sidecar.EvsChainNext(chain, entry.PushId, statement.Sha256)
	}
	return &chain, nil
}

// §11.8's fence row: whether head carries an evacuation or GC fence whose fence_ms is later than this attempt's
// arrival less PushFenceMargin. Only those fences set fence_ms, and no push writes one, so every fence_ms is from a
// write this attempt did not make.
func (self *pushAttempt) fenced(head *protocol.EvsHead) bool {
	fenceMs := head.GetFenceMs()
	return fenceMs != 0 && self.arrival.Add(-self.settings.PushFenceMargin).UnixMilli() < fenceMs
}

// 503 for a read or write that failed before anything could settle the push: unknown once a step 7 may have been
// issued. A context that ended stops the attempt the same way.
func (self *pushAttempt) unavailableOn(err error) *pushOutcome {
	if errors.Is(err, ErrEvsHeadInvalid) || errors.Is(err, ErrEvsStatementMismatch) || errors.Is(err, sidecar.ErrEvsRepoInvalid) {
		self.engine.log.Errorf("[evs] alarm push_read: repo %s ref %s: %v", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.refId), err)
		self.engine.metrics.alarms.Add(1, "push_read")
	}
	return self.unavailable()
}

// The window entry naming version in head, nil when the window does not hold it.
func windowEntryAt(head *protocol.EvsHead, version uint64) *sidecar.EvsWindowEntry {
	first := EvsHeadWindowFirstVersion(head)
	if version < first || head.GetVersion() < version {
		return nil
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil
	}
	return window[version-first]
}
