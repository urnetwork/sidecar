//go:build !ios_extension

// The field registry (§11.14's fields row): 1 subject, 2 from, 3 to (to and cc), 4 title and 5 body are every
// document's, and 6-15 are registered per document class, §16.8's record entries and run cards and §16.11's directory
// documents, each holding what its class says at the numbers it says. One posting set covers every field, and a
// field-scoped query is confirmed against the doc table row, so a class registers which field holds what and the
// names its derived documents take, and nothing else.
//
// A class gives its documents through IndexDocumentSource, so a build, a rebuild, a backfill and a host checking
// another writer's head by rebuild read a log's or directory's documents through one seam, never its formats.

package sidecar

import (
	"bytes"
	"context"
)

// The first registered field.
const indexFieldFirstRegistered = indexFieldBody + 1

// What a class holds in fields 6-15 and the names its derived documents take. Immutable once made.
type IndexFieldRegistry struct {
	// What field n holds, at n - 6, empty for a field the class leaves empty.
	FieldNames [indexFieldLast - indexFieldBody]string
	// The prefixes of the class's derived documents' names, such as "run/" and "a/". A record entry is named by its
	// path, a derived document by one of these and its id.
	DerivedPrefixes [][]byte
}

// A class of documents beyond files and mail: §16.8's record logs and §16.11's directory implement it.
type IndexDocumentSource interface {
	// The class's fields and derived names.
	IndexRegistry() *IndexFieldRegistry
	// Visits every document the class holds in the ref at refVersion, each at its newest version, for a build, a
	// rebuild, a backfill or a check by rebuild (§11.14's on and coverage rows). A document the class has dropped,
	// such as an item past its end on its card, is not visited; a visit's error stops the walk and is returned.
	IndexDocuments(ctx context.Context, refVersion uint64, visit func(document *IndexDocument) error) error
}

// §16.8's registry for record entries and run cards: 6 kind, 7 writer sidecar_id, 8 agent_id, 9 agent label, 10
// run_id, 11 session ids (at most 4), 12 tools (at most 32 names), 13 claim expires, 14 claim state, 15 reserved; a
// run card is named run/ || run_id.
func indexRecordFieldRegistry() *IndexFieldRegistry {
	return &IndexFieldRegistry{
		FieldNames: [indexFieldLast - indexFieldBody]string{
			"kind", "writer", "agent_id", "agent", "run_id", "session_ids", "tools", "claim_expires", "claim_state", "",
		},
		DerivedPrefixes: [][]byte{[]byte("run/")},
	}
}

// §16.11's registry for the team directory's documents: 6 announcement or entry kind, 7 sidecar_id, 8 agent_id, 9
// agent label, 10 run_id, 11 member_id, 12 project, 13 branch, 14 repo_id, 15 state; an announcement is named a/ ||
// announcement_id.
func indexDirectoryFieldRegistry() *IndexFieldRegistry {
	return &IndexFieldRegistry{
		FieldNames: [indexFieldLast - indexFieldBody]string{
			"kind", "sidecar_id", "agent_id", "agent", "run_id", "member_id", "project", "branch", "repo_id", "state",
		},
		DerivedPrefixes: [][]byte{[]byte("a/")},
	}
}

// The registered field of this name, or 0 when the class registers none: what a field-scoped filter confirms
// against the row (§16.10's agent, run and kind filters).
func (self *IndexFieldRegistry) field(name string) int {
	if name == "" {
		return 0
	}
	for index, fieldName := range self.FieldNames {
		if fieldName == name {
			return indexFieldFirstRegistered + index
		}
	}
	return 0
}

// Refuses a document its class could not give: a file or message, a value in a field it leaves empty or in fields 1
// to 3, which records and derived documents do not use, a derived document whose name is under none of its prefixes,
// or a record entry's under one.
func (self *IndexFieldRegistry) check(document *IndexDocument) error {
	if err := document.check(); err != nil {
		return err
	}
	if !document.Kind.hasRegisteredFields() {
		return indexMalformed("a registered class giving a file or message")
	}
	for number := indexFieldSubject; number < indexFieldTitle; number += 1 {
		if len(document.Fields[number]) != 0 {
			return indexMalformed("a registered document with a subject, from or to")
		}
	}
	for number := indexFieldFirstRegistered; number <= indexFieldLast; number += 1 {
		if len(document.Fields[number]) != 0 && self.FieldNames[number-indexFieldFirstRegistered] == "" {
			return indexMalformed("a value in a field the class leaves empty")
		}
	}
	derivedName := false
	for _, prefix := range self.DerivedPrefixes {
		if bytes.HasPrefix(document.Name, prefix) && len(prefix) < len(document.Name) {
			derivedName = true
		}
	}
	if (document.Kind == IndexDocDerived) != derivedName {
		return indexMalformed("a name that is not its kind's")
	}
	return nil
}
