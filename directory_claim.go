//go:build !ios_extension

// record_append's team routes (RECORD-M6-16; §16.11's claims and end rows, its coordination paragraph; RECORD.md
// sections 6.4 and 7.3; R-MCP-13, R-MCP-15, Q-MCP-7, FS-88): in a team network a claim or a handoff is state of the
// calling run's item in the directory, never a coordination entry, and an ask, answer, check or note is an entry in the
// caller's own directory stream, which the record writer routes there (record_team.go); no network coordination log is
// created.
//
//	claim      adds a Claim to the run's item: a random claim_id, the agent's text and path prefixes, state active, its
//	           expiry capped by the run's when the item is written; at most DirectoryClaimCount (4) in all, a fifth
//	           refused; raises the item's version, source agent; under prompt the first claim announces the run
//	release    a claim whose one target is claim:<claim_id> with expires at or before now sets that claim released
//	           (RECORD.md reading 11), raising the version; an id no claim of the run holds is refused
//	handoff    sets the item's Handoff (at most one member, one agent, and the note), its named claims handed_off,
//	           raising the version; the run's end then reads handed_off where it names a member or an agent
//	off        a run whose claims value is off refuses both, naming the setting, and announces nothing
//	unbound    a session no run binds, or a run that ended or was withdrawn, has no item to change: refused
//
// Text and targets arrive normalized and redacted by RecordProjection.Append; the item is redacted again whole and
// checked before it is written. Safe for concurrent use, as DirectoryRuns.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The run's item holds DirectoryClaimCount claims already: one is released or handed off first.
	ErrDirectoryRunClaimsFull = errors.New("directory run holds its most claims")
)

// A claim or a handoff on the calling run's item, args and its parsed targets and body as RecordProjection.Append
// made them: the item's announcement id and the version written.
func (self *DirectoryRuns) Coordinate(ctx context.Context, args *RecordAppendArgs, targets *RecordTargets, body *protocol.CoordinationBody) (*RecordAppendResult, error) {
	if args == nil || targets == nil || body == nil || (args.Kind != RecordKindClaim && args.Kind != RecordKindHandoff) {
		return nil, ErrRecordAppendKind
	}
	if args.RunId == nil {
		return nil, fmt.Errorf("%w: no run binds the session", ErrDirectoryRunUnknown)
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	nowMillis := self.clock.Now().UnixMilli()
	claimId, err := self.newId()
	if err != nil {
		return nil, err
	}
	result := &RecordAppendResult{}
	ref, err := self.update(*args.RunId, RecordSourceAgent, func(run *directoryRun) (bool, error) {
		if run.Claims.effective() == DirectoryRunClaimsOff {
			return false, ErrDirectoryRunsClaimsOff
		}
		if 0 < run.Version && !run.open() {
			return false, fmt.Errorf("%w: its item ended", ErrDirectoryRunUnknown)
		}
		claims := run.claims()
		switch {
		case args.Kind == RecordKindClaim && targets.Release:
			released := false
			for _, claim := range claims {
				if bytes.Equal(claim.GetClaimId(), targets.ClaimIds[0].Bytes()) {
					claim.State = uint32(DirectoryClaimStateReleased)
					released = true
				}
			}
			if !released {
				return false, fmt.Errorf("%w: no claim of this run has that id", ErrRecordTargetsInvalid)
			}
		case args.Kind == RecordKindClaim:
			if DirectoryClaimCount <= len(claims) {
				return false, ErrDirectoryRunClaimsFull
			}
			// an opening claim's targets are path prefixes alone, as the body holds them redacted
			claims = append(claims, &protocol.Claim{
				ClaimId:       claimId.Bytes(),
				Text:          body.GetText(),
				Targets:       body.GetTargets(),
				ExpiresMillis: args.ExpiresMillis,
				State:         uint32(DirectoryClaimStateActive),
			})
		default:
			for _, handedId := range targets.ClaimIds {
				found := false
				for _, claim := range claims {
					if bytes.Equal(claim.GetClaimId(), handedId.Bytes()) {
						claim.State = uint32(DirectoryClaimStateHandedOff)
						found = true
					}
				}
				if !found {
					return false, fmt.Errorf("%w: no claim of this run has that id", ErrRecordTargetsInvalid)
				}
			}
			handoff := &protocol.Handoff{Note: body.GetText(), Millis: nowMillis}
			if 0 < len(targets.MemberIds) {
				handoff.ToMemberId = targets.MemberIds[0].Bytes()
			}
			if 0 < len(targets.AgentLabels) {
				handoff.ToAgentLabel = targets.AgentLabels[0]
			}
			handoffBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(handoff)
			if err != nil {
				return false, err
			}
			run.HandoffBody = handoffBody
		}
		if err := run.setClaims(claims); err != nil {
			return false, err
		}
		// a content change: a raised version, the first when a claim announces a run under prompt
		run.Version += 1
		run.startDue = false
		result.Version = run.Version
		announcementId := run.AnnouncementId
		result.AnnouncementId = &announcementId
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if ref != nil {
		result.EntryId, result.LogId, result.Spooled = ref.EntryId, ref.LogId, ref.Spooled
	}
	return result, nil
}
