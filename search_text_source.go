//go:build !ios_extension

// A host's own plaintext and display fields, as search confirms against them (§11.14's confirm, coverage and off
// rows; §16.10's match row; owner decision 155; SEARCH-M10-24). A text source is what a desktop or indexer mirroring a
// ref, a mounted working tree, an indexer answering a remote search, or a device that already caches a body, holds of a
// document's text. It answers only from what this host already holds, at the exact version the index names, and never
// fetches: a fetch a query chose would show evs what was searched (I-19, D-MCP-20), so a document whose text is not
// here stays as its display fields confirm it. A display source is what a host without the text may still confirm a
// hit from beyond the row: a mailbox's i/ entry, its address and its 200 B snippet (§15.7).
//
// Neither is told the query. A request names a document by the row the index holds for it: its kind, its locator (a
// path, or a derived document's registered name) and its version, so a row whose locator is not the exact path (cut,
// or a path that was not UTF-8: the row's inexact flag) names no text, and its hit stays as the fields confirm it.
//
// SearchContentTextSource reads a version's bytes through whatever local store holds them and extracts them with
// extractor 1, so a confirmation reads a document exactly as the index's writer did (DESIGN-DETAILS section 11).
// SearchMailDisplay reads a mailbox's i/ entries through MailView. The mirrors' and working trees' own byte readers are
// their areas' (EvsMirror holds sealed records and no plaintext read yet; EvsLocalRepo's trees are git's, keyed by
// blob, not by entry version), so each joins through SearchContentTextSource.Content when it has one.

package sidecar

import (
	"context"
	"errors"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// One document version a search asks a host about, named by its row.
type SearchTextRequest struct {
	RepoId Id
	// The ref the document is on: a ur/index row's ref_id, else the ref whose index holds it.
	RefId Id
	Kind  IndexDocKind
	// The row's locator, the exact path or registered name.
	Name []byte
	// The entry version the index holds; a source answers for this version alone.
	Version uint64
}

// A host's own plaintext. Implementations are safe for concurrent use.
type SearchTextSource interface {
	// The version's documents, one a chunk in chunk order, as extractor 1 or the document's class gives them; false
	// where this host holds no plaintext of that version. Never a fetch.
	SearchDocuments(ctx context.Context, request *SearchTextRequest) ([]*IndexDocument, bool, error)
}

// What a host holds of a document beyond its row without holding its text.
type SearchDisplay struct {
	// A mailbox message's i/ entry: the address it was delivered to, and the start of its first text part, at most
	// 200 B (§15.7).
	Address string
	Snippet string
}

// A host's display fields beyond the row. Implementations are safe for concurrent use.
type SearchDisplaySource interface {
	// What this host holds of the document's display fields, or false where it holds none. Never a fetch.
	SearchDisplay(ctx context.Context, request *SearchTextRequest) (*SearchDisplay, bool, error)
}

// A text source over a local store of version bytes: extractor 1 on the bytes this host holds of a path at a version.
type SearchContentTextSource struct {
	// The version's bytes from this host's own store, or false where it holds none: a mirror's decrypted records, a
	// working tree, a bare repository. Never a fetch.
	Content func(ctx context.Context, repoId Id, refId Id, path []byte, version uint64) ([]byte, bool, error)
	// The repo's kind, and whether it is a general repo laid out as a group inbox, which decide its extractor and what
	// the never row keeps out (§11.14).
	Place func(repoId Id) (protocol.RepoKind, bool)
	// Extractor 1's bounds; nil takes DefaultIndexFormatSettings.
	Settings *IndexFormatSettings
}

// Extracts the bytes Content holds as the index's writer would: mail for a mailbox's or group inbox's m/ messages,
// files for the rest, nothing for what §11.14's never row keeps out or a binary.
func (self *SearchContentTextSource) SearchDocuments(ctx context.Context, request *SearchTextRequest) ([]*IndexDocument, bool, error) {
	if self.Content == nil || self.Place == nil {
		return nil, false, nil
	}
	if request.Kind != IndexDocFile && request.Kind != IndexDocMail {
		// record entries and derived documents are their class's (IndexDocumentSource)
		return nil, false, nil
	}
	repoKind, groupInbox := self.Place(request.RepoId)
	place := indexPlace{repoKind: repoKind, groupInbox: groupInbox, path: string(request.Name)}
	if indexExcluded(place) || indexExtractorKind(place) != request.Kind {
		return nil, false, nil
	}
	content, ok, err := self.Content(ctx, request.RepoId, request.RefId, request.Name, request.Version)
	if err != nil || !ok {
		return nil, false, err
	}
	settings := self.Settings
	if settings == nil {
		settings = DefaultIndexFormatSettings()
	}
	var documents []*IndexDocument
	switch request.Kind {
	case IndexDocMail:
		documents = indexExtractMail(request.Name, content, settings)
	default:
		documents, ok = indexExtractFile(request.Name, content, settings)
		if !ok {
			return nil, false, nil
		}
	}
	for _, document := range documents {
		document.Version = request.Version
	}
	return documents, true, nil
}

// A display source over the i/ entries this device mirrors (§15.7), through MailView.
type SearchMailDisplay struct {
	// The view of the mailbox whose i/ holds the entries of a repo's m/ messages: the mailbox itself, or for a group
	// inbox a member's mailbox whose r/ names them. nil where this device mirrors none.
	View func(repoId Id) *MailView
}

// The i/ entry of a mail document, found by its m/ path's month and id.
func (self *SearchMailDisplay) SearchDisplay(ctx context.Context, request *SearchTextRequest) (*SearchDisplay, bool, error) {
	if self.View == nil || request.Kind != IndexDocMail {
		return nil, false, nil
	}
	month, messageId, ok := searchMailMessageOf(request.Name)
	if !ok {
		return nil, false, nil
	}
	view := self.View(request.RepoId)
	if view == nil {
		return nil, false, nil
	}
	entry, err := view.Entry(ctx, month, messageId)
	switch {
	case errors.Is(err, ErrMailViewEntryAbsent):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return &SearchDisplay{Address: entry.Entry.GetAddress(), Snippet: entry.Entry.GetSnippet()}, true, nil
}

// The month and message id an m/ path names: m/<yyyymm>/<h>/<id>, exactly as MailMessagePath spells it, or false.
func searchMailMessageOf(name []byte) (MailYearMonth, Id, bool) {
	parts := strings.Split(string(name), "/")
	if len(parts) != 4 || parts[0]+"/" != indexMailMessagePrefix {
		return 0, Id{}, false
	}
	month, ok := ParseMailYearMonth(parts[1])
	if !ok {
		return 0, Id{}, false
	}
	raw, err := evsTokenEncoding.DecodeString(parts[3])
	if err != nil || len(raw) != len(Id{}) {
		return 0, Id{}, false
	}
	messageId := Id(raw)
	if MailMessagePath(month, messageId) != string(name) {
		return 0, Id{}, false
	}
	return month, messageId, true
}
