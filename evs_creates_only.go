// The creates-only rule (§11.8's refs table; QD-722), which evs's 5c (evsservice/check_refs.go's checkCreatesOnly) and
// readers (evsCheckRefRules, and a record stream's replay in record_evs.go) apply alike to each change of a ref that
// takes only creations from its writers: a record-class stream, a deposit ref and the erasure ref.
//
//	creation  a change on base 0 writing an entry, which every such ref takes
//	delta     on a record-class stream alone, a directory's add-only delta (QD-722): its entry a directory's at its
//	          base + 1 (§11.7's versions row) whose table removes no token, on the directory's newest version, the
//	          path standing as a directory, so §16.8's 2,048-entry directories grow one push after another
//	refused   every other change: a removal, a file's write on a base, a delta removing a token or off the newest
//	          version, and a change of kind; evs answers 409 PATH_CONFLICT, final, and a reader refuses the statement
//
// A checker judges what it holds. Without a change's entry version, as a statement read alone gives it, a write on a
// base cannot be told from a directory's delta, so on a stream it is left to the checker that holds the push's payload:
// evs, or the replaying reader. Without the path's own state, the newest version and the standing kind are left to the
// checker that holds it: evs's newest rule, or a reader's replay.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A path a creates-only change lands on, as its checker holds it.
type EvsCreatesOnlyPath struct {
	// The path stands, and as a directory, its newest version Version.
	Exists    bool
	Directory bool
	Version   uint64
}

// Why change breaks the creates-only rule, empty when it keeps it: see the file header. deltas is whether the ref takes
// a directory's add-only delta, a record-class stream's. path is the path's state as the checker holds it, nil when it
// holds none.
func EvsCreatesOnlyRefusal(change *EvsCheckedChange, deltas bool, path *EvsCreatesOnlyPath) string {
	baseEntryVersion := change.Change.GetBaseEntryVersion()
	switch {
	case !change.WritesEntry():
		return "a removal"
	case baseEntryVersion == 0:
		return ""
	case !deltas:
		return "a write on a base"
	case change.EntryVersion == nil:
		// a statement read alone: the checker holding its payload judges it
		return ""
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return "an entry version that does not parse"
	}
	switch {
	case entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY):
		return "a file's write on a base"
	case 0 < len(entry.GetNames().GetRemovedTokens()):
		return "a directory delta removing a name"
	case entry.GetVersion() != baseEntryVersion+1:
		return "a directory delta not at its base + 1"
	case path == nil:
		return ""
	case !path.Exists || !path.Directory:
		return "a directory delta on a path that does not stand as a directory"
	case path.Version != baseEntryVersion:
		return "a directory delta off the directory's newest version"
	}
	return ""
}
