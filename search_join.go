//go:build !ios_extension

// Mail's joins (§15.7's search index row and Reads; D-MAIL-16; SEARCH-M10-28): a mail hit's seen, flagged, labels and
// trash come from f/, and spam from a person's verdict, else i/'s spam_score against the mailbox's threshold, joined on
// the device and never stored in the index, whose rows hold a message's subject, from, to and date alone. A member's
// mail search leaves out spam and trash unless asked.
//
// Mail implements SearchJoinSource over its message list (MailView; MAIL-M10-03), and the engine asks it of each mail
// hit before giving the hit (search_engine.go). A join answers from what the device already holds of i/ and f/: it
// never reads evs because a query chose a message, which would show evs a candidate (I-19). A message it holds no i/
// entry for joins as unknown, and stays: a join only ever leaves out what it knows to be spam or trash. Nothing here is
// logged (I-13). Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"strings"
)

// One message's flags as the device joins them.
type SearchMailFlags struct {
	Seen    bool
	Flagged bool
	Trash   bool
	// A person's spam verdict, else spam_score at or past the mailbox's threshold (§15.9).
	Spam bool
	// The labels set, sorted.
	Labels []string
}

// Joins mail's flags to a hit on the device. Safe for concurrent use.
type SearchJoinSource interface {
	// The flags of message messageId of repo repoId, a mailbox or a group inbox, received in month, as this device's
	// copy of the member's message list holds them (a group message through the mailbox's r/ reference); false where it
	// holds no i/ entry for it. Never a read a query chose (I-19).
	MailFlags(ctx context.Context, repoId Id, month MailYearMonth, messageId Id) (*SearchMailFlags, bool, error)
}

// What a search asks of the join. The zero value is the default: spam and trash left out.
type SearchJoinAsk struct {
	Spam  bool
	Trash bool
}

// What a request asks of the join: its explicit include of spam and of trash (QD-898), which IMAP SEARCH sets from the
// selected folder and a member's mail search from what the person asked (MAIL-M10-03).
func searchJoinAskOf(request *SearchRequest) SearchJoinAsk {
	return SearchJoinAsk{Spam: request.IncludeSpam, Trash: request.IncludeTrash}
}

// A mail document's locator read back as its month and message id: m/<yyyymm>/<h>/<id>, as MailMessagePath writes
// it; false for any other path.
func searchJoinMailPath(locator string) (MailYearMonth, Id, bool) {
	parts := strings.Split(locator, "/")
	if len(parts) != 4 || parts[0]+"/" != indexMailMessagePrefix {
		return 0, Id{}, false
	}
	month, ok := ParseMailYearMonth(parts[1])
	if !ok {
		return 0, Id{}, false
	}
	idBytes, err := evsTokenEncoding.DecodeString(parts[3])
	if err != nil || len(idBytes) != len(Id{}) {
		return 0, Id{}, false
	}
	messageId := Id(idBytes)
	if MailMessagePath(month, messageId) != locator {
		return 0, Id{}, false
	}
	return month, messageId, true
}

// The join of one hit of repoId whose row is row: whether it stays, and the message's flags, nil for a hit that is no
// message, or one the device holds no i/ entry for, which stays.
func searchJoinMailHit(ctx context.Context, source SearchJoinSource, ask SearchJoinAsk, repoId Id, row *indexRow) (bool, *SearchMailFlags, error) {
	if source == nil || row == nil || row.docKind != indexDocMail {
		return true, nil, nil
	}
	month, messageId, ok := searchJoinMailPath(row.locator)
	if !ok {
		return true, nil, nil
	}
	flags, held, err := source.MailFlags(ctx, repoId, month, messageId)
	if err != nil {
		return false, nil, err
	}
	if !held || flags == nil {
		return true, nil, nil
	}
	if (flags.Spam && !ask.Spam) || (flags.Trash && !ask.Trash) {
		return false, flags, nil
	}
	return true, flags, nil
}
