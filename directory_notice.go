//go:build !ios_extension

// §16.11's notices (RECORD-M6-18; the repo table's q/ rows, its path rules and repair row, D-MCP-30): one file
// q/<h>/<tgt>/<rid> on the cards ref for each request, at most 256 B, written by path CAS. A notice names the request,
// its requester and the request entry's seq, never an approver: readers compute the target's approvers from their own
// state.
//
//	accept    a reader takes a notice version only by its push's signer and auth pin (I-EVS-14): pending with no
//	          decision, written by the requester whose stream holds the request; pending with the first approval of a
//	          rule that asks two, or decided, written by a decider the notice names who is eligible for the target at
//	          that pin; a version that names another request, requester, seq or expiry than the request entry's is
//	          none. A breach is ignored with a path_rule alarm, once a version, and the reader shows the version it
//	          last accepted meanwhile
//	repair    every file here is current state its rightful writer reproduces: the requester's daemon re-creates a
//	          pending notice from its request entry when the path holds none or a version no rule takes, which is also
//	          how a crash between the entry and the notice is repaired
//	leases    an approver's device leases q/<h>/<tgt>/ for every target it approves, and a requester's each pending
//	          notice's own path (§11.10), never the cards ref
//
// The copy keeps the newest file of a path and nothing of a removal, so a removal is taken as it comes: who removed a
// notice is not judged here, and the request's entries then say its state (directory_request.go).
//
// Barriers: directory.notice.before and .after around each write and removal, keyed by the request's id.

package sidecar

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A notice version this reader accepted.
type directoryNoticeAccepted struct {
	version uint64
	notice  *protocol.DirectoryNotice
	// the push's signer and pin
	signerSidecarId Id
	authPin         *bridge.AuthPin
}

// The pending notice of a request, as its requester writes it at creation and in repair.
func directoryPendingNotice(view *DirectoryRequestView) *protocol.DirectoryNotice {
	return &protocol.DirectoryNotice{
		RequestId:          view.RequestId.Bytes(),
		RequesterSidecarId: view.RequesterSidecarId.Bytes(),
		EntrySeq:           view.EntrySeq,
		NotAfterMillis:     view.Request.GetNotAfterMillis(),
		State:              uint32(DirectoryNoticeStatePending),
	}
}

// Whether a notice names a decider.
func directoryNoticeNames(notice *protocol.DirectoryNotice, deciderSidecarId Id) bool {
	return slices.ContainsFunc(notice.GetDecisions(), func(ref *protocol.DecisionRef) bool {
		return Id(ref.GetDeciderSidecarId()) == deciderSidecarId
	})
}

// Whether file is a version of view's notice the path rules take, and the notice it holds. unknown is true when the
// state at the file's pin could not be asked, which neither takes the version nor calls it a breach.
func (self *DirectoryAccessRequests) judgeNotice(auth DirectoryAuthView, view *DirectoryRequestView, file *DirectoryCardFile) (notice *protocol.DirectoryNotice, taken bool, unknown bool) {
	notice, err := DirectoryDecodeNotice(file.Content)
	if err != nil {
		return nil, false, false
	}
	if Id(notice.GetRequestId()) != view.RequestId || Id(notice.GetRequesterSidecarId()) != view.RequesterSidecarId ||
		notice.GetEntrySeq() != view.EntrySeq || notice.GetNotAfterMillis() != view.Request.GetNotAfterMillis() {
		return nil, false, false
	}
	pending := DirectoryNoticeState(notice.GetState()) == DirectoryNoticeStatePending
	if pending && len(notice.GetDecisions()) == 0 {
		return notice, file.SignerSidecarId == view.RequesterSidecarId, false
	}
	// a rewrite: by a decider it names, eligible for the target at the push's pin
	if !directoryNoticeNames(notice, file.SignerSidecarId) {
		return nil, false, false
	}
	decides, err := auth.Decides(view.Request, view.RequesterSidecarId, file.SignerSidecarId, file.AuthPin)
	if err != nil {
		return nil, false, true
	}
	if !decides {
		return nil, false, false
	}
	approvers, err := auth.EligibleApprovers(view.Request, view.RequesterSidecarId, file.AuthPin)
	if err != nil {
		return nil, false, true
	}
	approved := DirectoryOutcome(notice.GetOutcome()) == DirectoryOutcomeApproved
	switch {
	case pending && approvers.Count < 2:
		// the first approval of a rule that asks one decides it
		return nil, false, false
	case !pending && approved && len(notice.GetDecisions()) < approvers.Count:
		return nil, false, false
	}
	return notice, true, false
}

// The version of view's notice this reader shows: file's when the path rules take it, else the one it last accepted,
// nil for none. A breach alarms once a version.
func (self *DirectoryAccessRequests) acceptNotice(auth DirectoryAuthView, view *DirectoryRequestView, file *DirectoryCardFile) *directoryNoticeAccepted {
	path := view.NoticePath
	if file == nil {
		// removed, or never written
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.accepted, path)
		}()
		return nil
	}
	held := func() *directoryNoticeAccepted {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.accepted[path]
	}()
	if held != nil && held.version == file.Version {
		return held
	}
	notice, taken, unknown := self.judgeNotice(auth, view, file)
	if taken {
		accepted := &directoryNoticeAccepted{version: file.Version, notice: notice, signerSidecarId: file.SignerSidecarId, authPin: file.AuthPin}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.accepted[path] = accepted
		return accepted
	}
	if !unknown {
		alarm := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.breached[path] == file.Version {
				return false
			}
			self.breached[path] = file.Version
			return true
		}()
		if alarm {
			signerSidecarId := file.SignerSidecarId
			directoryId, _ := self.client.DirectoryId()
			self.client.raise(SidecarRecordAlarmPathRule, directoryId, &signerSidecarId)
		}
	}
	return held
}

// Writes a notice at path from the version read, by path CAS, under pushId: the path's new version.
func (self *DirectoryAccessRequests) putNotice(ctx context.Context, path string, ifVersion uint64, notice *protocol.DirectoryNotice, pushId Id) (uint64, error) {
	if err := DirectoryCheckNotice(notice); err != nil {
		return 0, err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
	if err != nil {
		return 0, err
	}
	hookKey := recordChainIdText(Id(notice.GetRequestId()))
	testHookBarrier("directory.notice.before", hookKey)
	version, err := self.client.PutCard(ctx, &DirectoryCardWrite{
		PushId: pushId, Path: path, IfVersion: ifVersion, Content: content, AuthPin: self.client.auth().Pin(),
	})
	testHookBarrier("directory.notice.after", hookKey)
	return version, err
}

// Removes the notice at path from the version read, by path CAS, under pushId.
func (self *DirectoryAccessRequests) removeNotice(ctx context.Context, requestId Id, path string, ifVersion uint64, pushId Id) error {
	hookKey := recordChainIdText(requestId)
	testHookBarrier("directory.notice.before", hookKey)
	err := self.client.RemoveCard(ctx, &DirectoryCardWrite{PushId: pushId, Path: path, IfVersion: ifVersion, AuthPin: self.client.auth().Pin()})
	testHookBarrier("directory.notice.after", hookKey)
	return err
}

// Whether err is a path CAS's conflict: another write, or a removal, landed since the version read.
func directoryPathConflict(err error) bool {
	code, ok := RecordStreamRefusalCode(err)
	return ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT
}

// The requester's repair (the path rules' repair row): each of this sidecar's own requests still pending by its
// entries and before not_after, whose path holds no notice or a version no rule takes, gets its pending notice again,
// from the version the path holds. Answers how many were written. A conflict means another write landed, which the
// next sync reads.
func (self *DirectoryAccessRequests) repairNotices(ctx context.Context, fold *directoryRequestFold) (int, error) {
	written := 0
	var firstErr error
	for _, view := range fold.views {
		if !view.Mine || view.State != DirectoryRequestPending || view.Notice != nil || view.cancelEntry != nil {
			continue
		}
		ifVersion := uint64(0)
		if view.noticeFile != nil {
			ifVersion = view.noticeFile.Version
		}
		pushId, err := self.newId()
		if err != nil {
			return written, err
		}
		if _, err := self.putNotice(ctx, view.NoticePath, ifVersion, directoryPendingNotice(view), pushId); err != nil {
			if !directoryPathConflict(err) && firstErr == nil {
				firstErr = fmt.Errorf("directory notice: repair: %w", err)
			}
			continue
		}
		written += 1
	}
	return written, firstErr
}

// Holds the leases the fold calls for and releases the rest: q/<h>/<tgt>/ for every target this device decides, and
// the path of each of its own pending requests' notices.
func (self *DirectoryAccessRequests) maintainLeases(fold *directoryRequestFold) {
	wanted := map[string]bool{}
	for _, prefix := range self.approverPrefixes() {
		wanted[prefix] = true
	}
	for _, view := range fold.views {
		if view.Mine && (view.State == DirectoryRequestPending || view.State == DirectoryRequestDenied) {
			// a denied one is still leased until it is closed, so a repo approval that a denial beat still arrives
			wanted[view.NoticePath] = true
		}
	}
	releases := []func(){}
	missing := []string{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for prefix, release := range self.leases {
			if !wanted[prefix] {
				releases = append(releases, release)
				delete(self.leases, prefix)
			}
		}
		for prefix := range wanted {
			if _, ok := self.leases[prefix]; !ok {
				missing = append(missing, prefix)
			}
		}
	}()
	for _, release := range releases {
		release()
	}
	slices.Sort(missing)
	for _, prefix := range missing {
		release, err := self.client.Lease(prefix)
		if err != nil {
			continue
		}
		kept := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if _, ok := self.leases[prefix]; ok || self.closed {
				return false
			}
			self.leases[prefix] = release
			return true
		}()
		if !kept {
			release()
		}
	}
}

// The notice prefixes of the targets this device decides now (§16.11's notify row): each live repo whose requests it
// decides, an admin's for its repos and an owner's consented device for an owner-bound one, and each worker of its own
// member's or sponsored by it, itself among them. Sockets' prefixes wait on §9's listeners, which name a socket's
// owner.
func (self *DirectoryAccessRequests) approverPrefixes() []string {
	auth := self.client.auth()
	sidecarId := self.client.sidecarId
	prefixes := []string{}
	for _, repo := range auth.Repos() {
		if repo == nil || !repo.Live {
			continue
		}
		target := &protocol.RequestTarget{RepoId: repo.RepoId.Bytes()}
		probe := &protocol.DirectoryRequest{Target: target}
		if decides, err := auth.Decides(probe, sidecarId, sidecarId, auth.Pin()); err != nil || !decides {
			continue
		}
		if prefix, err := DirectoryNoticePrefix(target); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	memberId, isMember := auth.MemberOf(sidecarId)
	if !isMember {
		return prefixes
	}
	workerIds := []Id{sidecarId}
	if items, err := self.client.List(&DirectoryFilter{Kind: DirectoryAnnouncementKindWorker, MemberId: &memberId}); err == nil {
		for _, item := range items {
			workerIds = append(workerIds, item.SignerSidecarId)
		}
	}
	slices.SortFunc(workerIds, Id.Cmp)
	for _, workerId := range slices.Compact(workerIds) {
		if prefix, err := DirectoryNoticePrefix(&protocol.RequestTarget{SidecarId: workerId.Bytes()}); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}
