//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// IMAP SEARCH on the search engine (RFC 9051 §6.4.4; §15.7's IMAP row, §16.10; R-MAIL-17, I-19; MAIL-M10-03), which
// replaces MAIL-M8-07's scan of i/ for a command's BODY and TEXT terms.
//
//	terms     each distinct BODY or TEXT string of the command, nested NOT and OR included, is one engine search of the
//	          string as a quoted phrase, a required substring by the engine's normalization, over the repos the
//	          selected folder's messages are in: scope all, Remote off, so the query stays on this device (I-19). At
//	          most SearchTermMaxCount of them a command
//	verified  a message holds a term where the engine gave it as a hit it verified against the message's text or
//	          confirmed against i/'s subject, address and snippet; a possible or near hit is no match, since SEARCH has
//	          no way to label one. BODY and TEXT both read the message as the index holds it, its subject, sender,
//	          recipient and text
//	folders   the folder's own listing decides which messages are in it, as before; the request asks the join for
//	          spam outside INBOX and for trash inside Trash, so a search inside either finds its messages (QD-898)
//	fallback  a message of a repo the engine left out of the search, its index off or not yet readable, is matched
//	          against its i/ entry, as is every message while no engine is bound or installed (M10's engine is a
//	          host's to install; until then SEARCH answers what MAIL-M8-07's did). Either way a client is told no more
//	          than this device checked
//	refusals  more terms than the bound, a term past the grammar's 512 B, a search the engine calls too broad or
//	          busy, and one past SearchHitMaxCount hits or SearchPageMaxCount pages answer NO, never a part of the
//	          answer given as the whole
//	the rest  sequence and UID sets, dates, sizes, flags and the Subject, From, To and Message-Id header terms are
//	          answered from the snapshot's entries, which hold them exactly
//
// Nothing here logs a term (I-13).

package sidecar

import (
	"context"
	"errors"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

var (
	errMailImapSearchLimit = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeLimit, Text: "The search has too many text terms, or one that matches too much"}
	errMailImapSearchBusy  = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "The mailbox's text cannot be searched now"}
)

// What the engine answered for one text term.
type mailImapSearchTerm struct {
	// the grammar reads the string as no term, which every message holds
	every bool
	// the messages the engine verified or confirmed holding it
	keys map[MailImapKey]bool
	// the repos the engine left out of the search, whose messages fall back to their entries
	excluded map[Id]bool
}

// A command's text terms as the engine answered them; nil terms where no engine answers, and every term falls back.
type mailImapSearchAnswer struct {
	terms map[string]*mailImapSearchTerm
}

// Whether message holds term.
func (self *mailImapSearchAnswer) holds(message *MailImapMessage, term string) bool {
	if self != nil && self.terms != nil {
		if found := self.terms[term]; found != nil {
			if found.every {
				return true
			}
			if !found.excluded[message.Key.RepoId] {
				return found.keys[message.Key]
			}
		}
	}
	return mailImapEntryHolds(message, term)
}

// Whether the message's i/ entry holds term: its subject, sender and snippet, as MAIL-M8-07's scan read them.
func mailImapEntryHolds(message *MailImapMessage, term string) bool {
	term = strings.ToLower(term)
	return strings.Contains(strings.ToLower(message.Entry.GetSubject()), term) ||
		strings.Contains(strings.ToLower(message.Entry.GetFrom()), term) ||
		strings.Contains(strings.ToLower(message.Entry.GetSnippet()), term)
}

// The distinct BODY and TEXT strings of criteria, nested ones to maxDepth, in the order met.
func mailImapSearchTexts(criteria *imap.SearchCriteria, maxDepth int, depth int, texts []string) []string {
	if maxDepth < depth {
		return texts
	}
	for _, text := range append(slices.Clone(criteria.Body), criteria.Text...) {
		if !slices.Contains(texts, text) {
			texts = append(texts, text)
		}
	}
	for index := range criteria.Not {
		texts = mailImapSearchTexts(&criteria.Not[index], maxDepth, depth+1, texts)
	}
	for index := range criteria.Or {
		texts = mailImapSearchTexts(&criteria.Or[index][0], maxDepth, depth+1, texts)
		texts = mailImapSearchTexts(&criteria.Or[index][1], maxDepth, depth+1, texts)
	}
	return texts
}

// A text term as the engine's grammar takes it: one quoted phrase. A quote inside it would end the phrase, and
// normalizes to a space anyway.
func mailImapSearchQuery(text string) string {
	return "\"" + strings.ReplaceAll(text, "\"", " ") + "\""
}

// The engine's answer for the command's text terms over the snapshot's repos; a nil answer's terms where none answers.
func (self *mailImapSession) searchTextsWithLock(criteria *imap.SearchCriteria) (*mailImapSearchAnswer, error) {
	settings := self.server.settings
	texts := mailImapSearchTexts(criteria, settings.SearchMaxDepth, 0, nil)
	answer := &mailImapSearchAnswer{}
	if len(texts) == 0 || self.account == nil || self.account.Search == nil {
		return answer, nil
	}
	if settings.SearchTermMaxCount < len(texts) {
		return nil, errMailImapSearchLimit
	}
	repoIds := []Id{}
	for _, message := range self.snapshot.Messages {
		if !slices.Contains(repoIds, message.Key.RepoId) {
			repoIds = append(repoIds, message.Key.RepoId)
		}
	}
	if len(repoIds) == 0 {
		return answer, nil
	}
	ctx, done := self.server.commandContext()
	defer done()
	var folder *MailListArgs
	if self.store != nil {
		folder, _ = self.store.folderArgs(self.snapshot.Folder)
	}
	terms := map[string]*mailImapSearchTerm{}
	for _, text := range texts {
		query := mailImapSearchQuery(text)
		parsed, err := ParseSearchQuery(query)
		if err != nil {
			return nil, errMailImapSearchLimit
		}
		if parsed.Empty() {
			terms[text] = &mailImapSearchTerm{every: true}
			continue
		}
		request := &SearchRequest{
			Text: query, Repos: slices.Clone(repoIds), Scope: SearchAll, Remote: SearchRemoteOff,
			IncludeSpam:  folder == nil || folder.Folder != MailFolderInbox,
			IncludeTrash: folder == nil || folder.Folder == MailFolderTrash,
		}
		found, err := self.searchTermWithLock(ctx, request)
		switch {
		case errors.Is(err, ErrSidecarSearchUnavailable), errors.Is(err, ErrMailSearchUnavailable):
			// no engine on this host: every term falls back to the entries
			return answer, nil
		case err != nil:
			return nil, err
		}
		terms[text] = found
	}
	answer.terms = terms
	return answer, nil
}

// One term's search, read to its end.
func (self *mailImapSession) searchTermWithLock(ctx context.Context, request *SearchRequest) (*mailImapSearchTerm, error) {
	settings := self.server.settings
	stream, err := self.account.Search(ctx, request)
	if err != nil {
		if errors.Is(err, ErrSidecarSearchUnavailable) || errors.Is(err, ErrMailSearchUnavailable) {
			return nil, err
		}
		if errors.Is(err, ErrSearchQueryTooLong) {
			return nil, errMailImapSearchLimit
		}
		return nil, errMailImapSearchBusy
	}
	defer stream.Close()
	found := &mailImapSearchTerm{keys: map[MailImapKey]bool{}, excluded: map[Id]bool{}}
	for range settings.SearchPageMaxCount {
		page, progress, done, err := stream.Next()
		if err != nil {
			return nil, errMailImapSearchBusy
		}
		if progress.TooBroad {
			return nil, errMailImapSearchLimit
		}
		for _, hit := range page {
			if hit.DocKind != int(IndexDocMail) || (hit.State != SearchVerified && hit.State != SearchConfirmed) {
				continue
			}
			month, messageId, ok := searchJoinMailPath(hit.Path)
			if !ok {
				continue
			}
			found.keys[MailImapKey{RepoId: hit.Repo, Month: month, Id: messageId}] = true
			if settings.SearchHitMaxCount < len(found.keys) {
				return nil, errMailImapSearchLimit
			}
		}
		if done {
			for _, exclusion := range progress.Excluded {
				found.excluded[exclusion.RepoId] = true
			}
			return found, nil
		}
	}
	return nil, errMailImapSearchLimit
}

// SEARCH: the snapshot's messages that match criteria, their text terms answered by the engine. See the file header.
func (self *mailImapSession) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	data := &imap.SearchData{}
	if self.snapshot == nil {
		return data, nil
	}
	answer, err := self.searchTextsWithLock(criteria)
	if err != nil {
		return nil, err
	}
	var seqSet imap.SeqSet
	var uidSet imap.UIDSet
	for index, message := range self.snapshot.Messages {
		if !self.matchesWithLock(uint32(index+1), message, criteria, answer, 0) {
			continue
		}
		data.Count += 1
		if kind == imapserver.NumKindUID {
			uidSet.AddNum(imap.UID(message.Uid))
		} else {
			seqSet.AddNum(uint32(index + 1))
		}
	}
	if kind == imapserver.NumKindUID {
		data.All = uidSet
	} else {
		data.All = seqSet
	}
	return data, nil
}

// Whether message matches criteria: its text terms by answer, the rest on what its entry holds. Past SearchMaxDepth a
// nested criterion matches nothing.
func (self *mailImapSession) matchesWithLock(seqNum uint32, message *MailImapMessage, criteria *imap.SearchCriteria, answer *mailImapSearchAnswer, depth int) bool {
	if self.server.settings.SearchMaxDepth < depth {
		return false
	}
	for _, seqSet := range criteria.SeqNum {
		if seqNums, _ := self.selectedWithLock(seqSet); !slices.Contains(seqNums, seqNum) {
			return false
		}
	}
	for _, uidSet := range criteria.UID {
		if _, messages := self.selectedWithLock(uidSet); !slices.Contains(messages, message) {
			return false
		}
	}
	date := message.InternalDate()
	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	if !criteria.Since.IsZero() && day.Before(criteria.Since) {
		return false
	}
	if !criteria.Before.IsZero() && !day.Before(criteria.Before) {
		return false
	}
	flags := message.ImapFlags()
	for _, flag := range criteria.Flag {
		if !slices.Contains(flags, string(flag)) {
			return false
		}
	}
	for _, flag := range criteria.NotFlag {
		if slices.Contains(flags, string(flag)) {
			return false
		}
	}
	if 0 < criteria.Larger && int64(message.Size()) <= criteria.Larger {
		return false
	}
	if 0 < criteria.Smaller && criteria.Smaller <= int64(message.Size()) {
		return false
	}
	contains := func(text string, term string) bool {
		return strings.Contains(strings.ToLower(text), strings.ToLower(term))
	}
	for _, field := range criteria.Header {
		value := ""
		switch textproto.CanonicalMIMEHeaderKey(field.Key) {
		case "Subject":
			value = message.Entry.GetSubject()
		case "From":
			value = message.Entry.GetFrom()
		case "To":
			value = message.Entry.GetAddress()
		case "Message-Id":
			value = message.Entry.GetMessageId()
		default:
			return false
		}
		if !contains(value, field.Value) {
			return false
		}
	}
	for _, term := range append(slices.Clone(criteria.Body), criteria.Text...) {
		if !answer.holds(message, term) {
			return false
		}
	}
	for index := range criteria.Not {
		if self.matchesWithLock(seqNum, message, &criteria.Not[index], answer, depth+1) {
			return false
		}
	}
	for index := range criteria.Or {
		if !self.matchesWithLock(seqNum, message, &criteria.Or[index][0], answer, depth+1) && !self.matchesWithLock(seqNum, message, &criteria.Or[index][1], answer, depth+1) {
			return false
		}
	}
	return true
}
