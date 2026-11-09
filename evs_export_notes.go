// Export's signed provenance (§11.12's export row): refs/notes/ur, one note per exported commit that ends a push,
// naming the push, its signer, its client, the ref version it committed at and its Signed EvsPush as received, so
// anyone holding the export can check the statement against the network's keys without evs. The notes commit is
// deterministic: its tree is git's notes layout, one blob per annotated commit named by that commit's 40-hex oid,
// and its author and committer are fixed at the newest push's time.
//
// On every leg; only a desktop host runs it. Not safe for concurrent use.

package sidecar

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
)

// The notes ref export writes.
const evsExportNotesRef = "refs/notes/ur"

// One commit's provenance.
type evsExportNote struct {
	commit    EvsGitOid
	statement *EvsVerifiedStatement
}

// The note blob of one push.
func evsExportNoteBody(statement *EvsVerifiedStatement) []byte {
	push := statement.Statement.Push
	return fmt.Appendf(nil, "ur push %s\nsigner %s\nclient %s\nversion %d\nstatement %s\n",
		hex.EncodeToString(push.GetPushId()),
		hex.EncodeToString(push.GetSignerSidecarId()),
		hex.EncodeToString(push.GetClientId()),
		statement.Version,
		base64.StdEncoding.EncodeToString(statement.Statement.Bytes),
	)
}

// Writes the notes and points refs/notes/ur at their commit. No notes write nothing.
func (self *evsGitObjectWriter) writeNotes(notes []*evsExportNote) error {
	if len(notes) == 0 {
		return nil
	}
	tree := &EvsGitTree{}
	newestMs := int64(0)
	seen := map[EvsGitOid]bool{}
	for _, note := range notes {
		if seen[note.commit] {
			continue
		}
		seen[note.commit] = true
		blob, err := self.write("blob", evsExportNoteBody(note.statement))
		if err != nil {
			return err
		}
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: 0o100644, Name: []byte(hex.EncodeToString(note.commit[:])), Oid: blob})
		newestMs = max(newestMs, note.statement.Statement.Push.GetTimeMs())
	}
	slices.SortFunc(tree.Entries, func(a EvsGitTreeEntry, b EvsGitTreeEntry) int { return evsGitTreeEntryCompare(a, b) })
	encoded, err := tree.Encode()
	if err != nil {
		return err
	}
	treeOid, err := self.write("tree", encoded)
	if err != nil {
		return err
	}
	ident := &EvsGitIdent{Name: []byte("ur export"), Email: []byte("export" + evsCommitterDomain), TimeSeconds: max(0, newestMs/1000), TimeZone: "+0000"}
	identBytes, err := ident.Encode()
	if err != nil {
		return err
	}
	commit := &EvsGitCommit{TreeOid: treeOid, Author: identBytes, Committer: identBytes, Message: []byte("ur export provenance\n")}
	commitBytes, err := commit.Encode()
	if err != nil {
		return err
	}
	commitOid, err := self.write("commit", commitBytes)
	if err != nil {
		return err
	}
	return self.setRef(evsExportNotesRef, commitOid)
}
