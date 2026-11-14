//go:build !ios_extension

// The requester's receipt (RECORD-M6-19; §16.11's Requests table, its receipt and close rows; D-MCP-34): what this
// sidecar does once the notice of one of its own requests turns decided.
//
//	read     that notice version and, by its DecisionRefs, the one or two decision entries it names, each by its
//	         decider's stream and seq (DirectoryReceiptSource: a head read of the path the seq names; the default
//	         reads this copy's synced, verified entries). No stream is scanned and no index is asked
//	accept   only if each entry's writer and header hash are the ref's, each binds this request (request_id and
//	         request_entry_sha256), each outcome is the notice's, and each decider is eligible for the target at its
//	         push's pin; else they are ignored with a bad_decision alarm and nothing is acted on
//	act      an approved repo's statement is checked in the authorization log; approved reach runs §16.6's spend check
//	         and files the GrantActivate (DirectoryReceipts); then access_decided is raised with the outcome, once,
//	         and the outcome is recorded in the member's vault. With no receipts bound an approval is not taken: fail
//	         closed
//	close    the requester removes an approved notice once the vault recorded the outcome, and a denied one only past
//	         not_after + 1 d, still leasing it, so a repo approval that a denial beat still arrives by the rewrite to
//	         approved
//	others   a request that expired or that this sidecar cancelled raises access_decided once, with no entry read
//
// What was received is kept in the directory's store, receipts, so an event is raised once across restarts.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// The store's name for what this sidecar received, and its format.
const (
	directoryReceiptsStoreName    = "receipts"
	directoryReceiptsStoreVersion = 1
)

var (
	// A decided notice whose decisions do not hold: nothing is acted on.
	ErrDirectoryReceiptRefused = errors.New("the notice's decisions do not hold")
	// Nothing here checks an approval's statement or spends a reach decision, so no approval is taken.
	ErrDirectoryReceiptsUnbound = errors.New("nothing receives a directory approval here")
)

// Where a receipt reads a decision entry: its decider's stream at the path its seq names.
type DirectoryReceiptSource interface {
	// The verified entry at seq in deciderSidecarId's stream as a decision, nil with no error while none is there.
	DecisionEntry(ctx context.Context, deciderSidecarId Id, seq uint64) (*DirectoryDecisionView, error)
}

// What a requester's daemon does with an approval, which it binds to its authorization log, its gate and its vault.
type DirectoryReceipts interface {
	// Whether the authorization log holds the statement of that hash at position (§7.9): a repo approval's receipt.
	StatementHeld(ctx context.Context, statementSha256 []byte, position uint64) (bool, error)
	// Runs §16.6's spend check on a reach approval's decisions and files its GrantActivate, once.
	ActivateReach(ctx context.Context, request *StoredApprovalRequest, decisions [][]byte) error
	// Records the outcome in the member's vault.
	Record(ctx context.Context, receipt *DirectoryReceipt) error
}

// One of this sidecar's requests as received.
type DirectoryReceipt struct {
	RequestId Id
	// approved, denied, cancelled or expired: access_decided's outcomes.
	Outcome string
	// The decision entries the notice named, as accepted.
	Decisions []*DirectoryDecisionView
	// The vault recorded it.
	Recorded bool
}

// One kept receipt.
type directoryReceiptRow struct {
	Outcome  string `json:"outcome"`
	Millis   int64  `json:"millis"`
	Recorded bool   `json:"recorded,omitempty"`
	Closed   bool   `json:"closed,omitempty"`
}

// The store's document of receipts, by the request's id in hex.
type directoryReceiptsDocument struct {
	Version  int                             `json:"version"`
	Receipts map[string]*directoryReceiptRow `json:"receipts"`
}

// The receipts kept.
func (self *DirectoryAccessRequests) loadReceipts() (*directoryReceiptsDocument, error) {
	document := &directoryReceiptsDocument{Version: directoryReceiptsStoreVersion, Receipts: map[string]*directoryReceiptRow{}}
	store := self.client.store
	if store == nil || store.store == nil {
		return document, nil
	}
	content, err := store.readFile(directoryReceiptsStoreName)
	if err != nil || content == nil {
		return document, err
	}
	kept := &directoryReceiptsDocument{}
	if err := json.Unmarshal(content, kept); err != nil || kept.Version != directoryReceiptsStoreVersion {
		return nil, fmt.Errorf("%w: the kept receipts do not read", ErrDirectoryStoreCorrupt)
	}
	if kept.Receipts == nil {
		kept.Receipts = map[string]*directoryReceiptRow{}
	}
	return kept, nil
}

// Keeps the receipts.
func (self *DirectoryAccessRequests) keepReceipts(document *directoryReceiptsDocument) error {
	store := self.client.store
	if store == nil || store.store == nil {
		return nil
	}
	return store.writeDocument(directoryReceiptsStoreName, document)
}

// The default source: this copy's synced, verified entries.
type directoryCopyReceiptSource struct {
	client *DirectoryClient
}

// The decision entry at seq in the decider's stream, from the copy.
func (self *directoryCopyReceiptSource) DecisionEntry(ctx context.Context, deciderSidecarId Id, seq uint64) (*DirectoryDecisionView, error) {
	for _, entry := range self.client.entriesOfKinds(RecordKindDecision) {
		writerId, pushPin, pushTimeMillis, ok := directoryEntryPush(entry)
		if !ok || writerId != deciderSidecarId || entry.Header.Header.GetSeq() != seq {
			continue
		}
		stored, err := DirectoryDecodeDecision(entry.Body)
		if err != nil {
			return nil, nil
		}
		return &DirectoryDecisionView{
			DeciderSidecarId: writerId,
			EntryId:          entry.EntryId,
			Seq:              seq,
			HeaderSha256:     DirectoryEntryHeaderSha256(entry.SignedBytes),
			Decision:         stored.Decision,
			Stored:           stored,
			PushPin:          pushPin,
			PushTimeMillis:   pushTimeMillis,
		}, nil
	}
	return nil, nil
}

// Receives one of this sidecar's requests whose accepted notice is decided: see the file's header's read, accept and
// act rows. source nil reads this copy. nil with no error while an entry it names, or its statement, is not there yet;
// ErrDirectoryReceiptRefused, with a bad_decision alarm, when the decisions do not hold.
func (self *DirectoryAccessRequests) Receive(ctx context.Context, view *DirectoryRequestView, source DirectoryReceiptSource) (*DirectoryReceipt, error) {
	client := self.client
	if view == nil || !view.Mine || view.Notice == nil || DirectoryNoticeState(view.Notice.GetState()) != DirectoryNoticeStateDecided {
		return nil, fmt.Errorf("%w: no decided notice of this sidecar's request", ErrDirectoryRequestUnknown)
	}
	if source == nil {
		source = &directoryCopyReceiptSource{client: client}
	}
	auth := client.auth()
	outcome := DirectoryOutcome(view.Notice.GetOutcome())
	refuse := func(why string) (*DirectoryReceipt, error) {
		if self.raiseOnce(fmt.Sprintf("receipt/%s/%d", recordChainIdText(view.RequestId), view.NoticeVersion)) {
			directoryId, _ := client.DirectoryId()
			client.raise(SidecarRecordAlarmBadDecision, directoryId, nil)
		}
		return nil, fmt.Errorf("%w: %s", ErrDirectoryReceiptRefused, why)
	}
	receipt := &DirectoryReceipt{RequestId: view.RequestId, Outcome: SidecarAccessDecidedDenied}
	if outcome == DirectoryOutcomeApproved {
		receipt.Outcome = SidecarAccessDecidedApproved
	}
	for _, ref := range view.Notice.GetDecisions() {
		deciderId := Id(ref.GetDeciderSidecarId())
		decision, err := source.DecisionEntry(ctx, deciderId, ref.GetSeq())
		if err != nil {
			return nil, err
		}
		if decision == nil {
			return nil, nil
		}
		switch {
		case decision.DeciderSidecarId != deciderId || decision.Seq != ref.GetSeq():
			return refuse("an entry of another writer or seq")
		case !bytes.Equal(decision.HeaderSha256[:], ref.GetHeaderSha256()):
			return refuse("an entry whose header is not the one named")
		case Id(decision.Decision.GetRequestId()) != view.RequestId || !bytes.Equal(decision.Decision.GetRequestEntrySha256(), view.EntrySha256[:]):
			return refuse("a decision that binds another request")
		case DirectoryOutcome(decision.Decision.GetOutcome()) != outcome:
			return refuse("a decision of another outcome than the notice's")
		}
		decides, err := auth.Decides(view.Request, view.RequesterSidecarId, deciderId, decision.PushPin)
		if err != nil {
			return nil, err
		}
		if !decides {
			return refuse("a decider not eligible at its push's pin")
		}
		decision.Eligible = true
		receipt.Decisions = append(receipt.Decisions, decision)
	}
	receipts := self.bound().Receipts
	if outcome == DirectoryOutcomeApproved {
		if receipts == nil {
			return nil, ErrDirectoryReceiptsUnbound
		}
		if view.TargetKind == DirectoryTargetKindRepo {
			for _, decision := range receipt.Decisions {
				held, err := receipts.StatementHeld(ctx, decision.Decision.GetStatementSha256(), decision.Decision.GetStatementPosition())
				if err != nil {
					return nil, err
				}
				if !held {
					// the log has not reached the statement's position yet
					return nil, nil
				}
			}
		} else {
			approval, err := view.Stored.Approval()
			if err != nil {
				return refuse("a reach request with no approval")
			}
			signed := [][]byte{}
			for _, decision := range receipt.Decisions {
				signed = append(signed, decision.Decision.GetApprovalDecision())
			}
			if err := receipts.ActivateReach(ctx, approval, signed); err != nil {
				return nil, err
			}
		}
	}
	if receipts != nil {
		if err := receipts.Record(ctx, receipt); err != nil {
			client.log.Infof("[directory]a request's outcome is not in the vault yet: %s", err)
		} else {
			receipt.Recorded = true
		}
	}
	return receipt, nil
}

// Receives each of this sidecar's own requests that left pending, raises access_decided once an outcome, and closes
// what the close row lets it. The caller holds writeLock.
func (self *DirectoryAccessRequests) receiveWithLock(ctx context.Context, fold *directoryRequestFold) error {
	kept, err := self.loadReceipts()
	if err != nil {
		return err
	}
	events := self.bound().Events
	grace := self.settings().NoticeGrace.Milliseconds()
	changed := false
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, view := range fold.views {
		if !view.Mine || view.State == DirectoryRequestPending {
			continue
		}
		key := recordChainIdText(view.RequestId)
		row := kept.Receipts[key]
		outcome := ""
		recorded := false
		switch view.State {
		case DirectoryRequestExpired:
			outcome = SidecarAccessDecidedExpired
		case DirectoryRequestCancelled:
			outcome = SidecarAccessDecidedCancelled
		default:
			if view.Notice == nil || DirectoryNoticeState(view.Notice.GetState()) != DirectoryNoticeStateDecided {
				// closed already, or decided by entries alone: nothing more to read
				continue
			}
			outcome = SidecarAccessDecidedDenied
			if DirectoryOutcome(view.Notice.GetOutcome()) == DirectoryOutcomeApproved {
				outcome = SidecarAccessDecidedApproved
			}
			if row == nil || row.Outcome != outcome || !row.Recorded {
				receipt, err := self.Receive(ctx, view, nil)
				if err != nil {
					note(err)
					continue
				}
				if receipt == nil {
					continue
				}
				recorded = receipt.Recorded
			} else {
				recorded = row.Recorded
			}
		}
		if row == nil || row.Outcome != outcome {
			// a denial that an approval's rewrite beat is received again as the approval
			row = &directoryReceiptRow{Outcome: outcome, Millis: fold.nowMillis}
			kept.Receipts[key] = row
			changed = true
			if events != nil {
				note(events.RaiseAccessDecided(view.RequestId, outcome))
			}
		}
		if recorded && !row.Recorded {
			row.Recorded = true
			changed = true
		}
		// close
		if row.Closed || view.noticeFile == nil || view.Notice == nil || view.NoticeVersion != view.noticeFile.Version {
			continue
		}
		closes := false
		switch outcome {
		case SidecarAccessDecidedApproved:
			closes = row.Recorded
		case SidecarAccessDecidedDenied:
			closes = view.Request.GetNotAfterMillis()+grace < fold.nowMillis
		}
		if !closes {
			continue
		}
		pushId, err := self.newId()
		if err != nil {
			note(err)
			continue
		}
		if err := self.removeNotice(ctx, view.RequestId, view.NoticePath, view.NoticeVersion, pushId); err != nil {
			if !directoryPathConflict(err) {
				note(err)
			}
			continue
		}
		row.Closed = true
		changed = true
	}
	if changed {
		note(self.keepReceipts(kept))
	}
	return firstErr
}
