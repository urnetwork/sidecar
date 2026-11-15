//go:build sidecar_testhooks && !ios_extension

// SEARCH-M10-43's cross-implementation check (DESIGN-DETAILS 11.6; D-TEST-14, FI-22): the oracle's extractor and the
// index's, written apart from the same rules, give equal documents on any bytes, read as a message and as a file:
// the same count, chunk numbers and fields before normalization, and the same rows. The index is reached through
// sidecar.TestHookIndexExtract, called here and never from an oracle file, so TestSearchOracleImportsNoIndexCode
// keeps holding.
//
// What is not compared yet: which documents D6 skips past KeySetMax and lone(d). The oracle's half of QD-760's
// shard test is not built, so a document the index skips is compared by its fields alone, and only the oracle's own
// KeySetMax verdict is held against the index's skip.

package sidecartest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// How the index's documents for content at path differ from the oracle's, read as mail when mail is set and else as
// a file; empty when they are equal.
func searchExtractDifferences(mail bool, path []byte, content []byte) []string {
	settings := DefaultSearchOracleExtractSettings()
	var oracleDocuments []*searchOracleDocument
	if mail {
		oracleDocuments = searchOracleMailDocuments(string(path), content, settings)
	} else {
		oracleDocuments = searchOracleFileDocuments(string(path), content, settings)
	}
	indexDocuments, ok := sidecar.TestHookIndexExtract(mail, path, content)
	switch {
	case !ok && mail:
		return []string{"the index refused a message"}
	case !ok && oracleDocuments != nil:
		return []string{fmt.Sprintf("the index read a binary, the oracle %d documents", len(oracleDocuments))}
	case !ok:
		return nil
	case !mail && oracleDocuments == nil:
		return []string{fmt.Sprintf("the oracle read a binary, the index %d documents", len(indexDocuments))}
	case len(indexDocuments) != len(oracleDocuments):
		return []string{fmt.Sprintf("the index gave %d documents, the oracle %d", len(indexDocuments), len(oracleDocuments))}
	}
	differences := []string{}
	for i, indexDocument := range indexDocuments {
		oracleDocument := oracleDocuments[i]
		if indexDocument.Chunk != oracleDocument.chunk {
			differences = append(differences, fmt.Sprintf("document %d: chunk %d, the oracle's %d", i, indexDocument.Chunk, oracleDocument.chunk))
		}
		for field := 1; field <= 5; field += 1 {
			if !bytes.Equal(indexDocument.Fields[field-1], oracleDocument.fields[field]) {
				differences = append(differences, fmt.Sprintf("document %d: field %d %q, the oracle's %q", i, field,
					searchConformanceShow(indexDocument.Fields[field-1]), searchConformanceShow(oracleDocument.fields[field])))
			}
		}
		if searchOracleKeySetTooLarge(oracleDocument.text) && !indexDocument.Skipped {
			differences = append(differences, fmt.Sprintf("document %d: kept, though its key set passes KeySetMax", i))
		}
		if indexDocument.Skipped {
			// its row is empty; D6's lone(d) on the oracle's side is QD-760's second track
			continue
		}
		indexRow := [5]string{indexDocument.Locator, indexDocument.Subject, indexDocument.From, indexDocument.To, indexDocument.Title}
		for k, name := range []string{"locator", "subject", "from", "to", "title"} {
			if indexRow[k] != oracleDocument.row[k] {
				differences = append(differences, fmt.Sprintf("document %d: row %s %q, the oracle's %q", i, name, indexRow[k], oracleDocument.row[k]))
			}
		}
		if indexDocument.ByteCount != oracleDocument.byteCount {
			differences = append(differences, fmt.Sprintf("document %d: row size %d, the oracle's %d", i, indexDocument.ByteCount, oracleDocument.byteCount))
		}
	}
	return differences
}

// Any bytes, as a message and as a file at any path, give equal documents. Seeds: every vector of mail.json and
// file.json under 64 KiB, each read both ways.
func FuzzExtractOracleEqualsIndex(f *testing.F) {
	if err := searchOracleTablesErr(); err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"mail.json", "file.json"} {
		file := searchConformanceLoad(f, name)
		for _, vector := range file.Vectors {
			path, input, err := vector.bytes()
			if err != nil {
				f.Fatalf("%s: %v", vector.Name, err)
			}
			if len(input) < 64*1024 {
				f.Add([]byte(path), input)
			}
		}
	}
	f.Fuzz(func(t *testing.T, path []byte, content []byte) {
		// a bound on one execution's work, far past every seed
		if 4*1024*1024 < len(content) {
			return
		}
		for _, mail := range []bool{true, false} {
			if differences := searchExtractDifferences(mail, path, content); len(differences) != 0 {
				t.Fatalf("mail %v, path %q: %s", mail, path, strings.Join(differences, "; "))
			}
		}
	})
}

// SearchCorpus's generated mail and notes, and every conformance vector whatever its size, give equal documents in
// the two extractors.
func TestExtractOracleEqualsIndexOnCorpus(t *testing.T) {
	if err := searchOracleTablesErr(); err != nil {
		t.Fatal(err)
	}
	corpus := NewSearchCorpus(DefaultSearchCorpusSettings())
	messageCount, noteCount := 0, 0
	for _, step := range corpus.Steps {
		if step.Commit == nil {
			continue
		}
		for _, change := range step.Commit.Changes {
			if change.Content == nil || strings.HasPrefix(change.Path, searchOracleIndexPrefix) {
				continue
			}
			mail := false
			switch {
			case step.Commit.RepoId == corpus.Mailbox.RepoId && strings.HasPrefix(change.Path, searchOracleMailboxPrefix):
				mail = true
				messageCount += 1
			case step.Commit.RepoId == corpus.Mailbox.RepoId:
				continue
			default:
				noteCount += 1
			}
			if differences := searchExtractDifferences(mail, []byte(change.Path), change.Content); len(differences) != 0 {
				t.Errorf("%s version %d: %s", change.Path, change.Version, strings.Join(differences, "; "))
			}
		}
	}
	if messageCount == 0 || noteCount == 0 {
		t.Fatalf("the corpus gave %d messages and %d notes: the check would pass vacuously", messageCount, noteCount)
	}
	for _, name := range []string{"mail.json", "file.json"} {
		file := searchConformanceLoad(t, name)
		for _, vector := range file.Vectors {
			path, input, err := vector.bytes()
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			for _, mail := range []bool{true, false} {
				if differences := searchExtractDifferences(mail, []byte(path), input); len(differences) != 0 {
					t.Errorf("%s as mail %v: %s", vector.Name, mail, strings.Join(differences, "; "))
				}
			}
		}
	}
}
