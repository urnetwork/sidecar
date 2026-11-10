// Which storage format a push needs (§11.6's format row, EVS-FORMAT.md's format 2 chapter; EVS2-M10-05): the
// classifier evs runs at 5c against §19.11's format2 gate, and a format-2 client runs before it sends, so it knows
// whether the push will raise a format-1 repo. A push carries format 2 when an entry version has versioning 1 or 2, a
// locator is kind 5 or staged, a new-objects item is a staged segment, the push stages bytes, or the statement sets
// flag 256 or 512, field 33 or field 34. The provenance's tainted bit, which format 1 ignores, does not count.
//
// Each function reads what the format-2 parsers left (ParseEvsStatementFormat2, EvsCheckPayloadFormat2 and
// EvsCheckPartFormat2), so a format-1 parse, which refuses every one of these as ErrEvsFormatUnsupported, never
// reaches them with a format-2 value. An entry version that does not parse counts as format 1: the parse that held
// it refused it already, and the classifier decides only the gate's question.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether statement and payload carry a format-2 value: the statement's flags and fields, each change's entry
// version, the new-objects list and the staged bytes. A nil payload, a seal's before its parts are read, answers for
// the statement alone.
func EvsPushNeedsFormat2(statement *EvsStatement, payload *EvsCheckedPayload) bool {
	if statement != nil && EvsStatementNeedsFormat2(statement.Push) {
		return true
	}
	if payload == nil {
		return false
	}
	if 0 < len(payload.Staged) || payload.Drop != nil {
		return true
	}
	for _, object := range payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT {
			return true
		}
	}
	return EvsChangesNeedFormat2(payload.Changes)
}

// Whether the statement itself carries format 2: flag 256 (DROP) or 512 (CUT), field 33 (drop_sha256) or field 34
// (index_epoch).
func EvsStatementNeedsFormat2(push *protocol.EvsPush) bool {
	if push == nil {
		return false
	}
	return push.GetFlags()&evsFormat2PushFlags != 0 || len(push.GetDropSha256()) != 0 || push.GetIndexEpoch() != 0
}

// Whether any change's entry version carries format 2: a part's own changes, or a payload's.
func EvsChangesNeedFormat2(changes []*EvsCheckedChange) bool {
	for _, change := range changes {
		if change == nil || len(change.EntryVersion) == 0 {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			continue
		}
		if EvsEntryVersionNeedsFormat2(entry) {
			return true
		}
	}
	return false
}

// Whether an entry version carries format 2: versioning 1 or 2, or a kind-5 or staged locator in its chain.
func EvsEntryVersionNeedsFormat2(entry *protocol.EvsEntryVersion) bool {
	if entry == nil {
		return false
	}
	if entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return true
	}
	for _, locator := range entry.GetChain() {
		if EvsLocatorNeedsFormat2(locator) {
			return true
		}
	}
	return false
}

// Whether a locator carries format 2: kind 5, or the staged mark.
func EvsLocatorNeedsFormat2(locator *protocol.EvsLocator) bool {
	if locator == nil {
		return false
	}
	return protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT || locator.GetStaged()
}
