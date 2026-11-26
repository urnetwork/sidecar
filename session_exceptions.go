//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.9's exceptions, what the session journal keeps in another form than the model read it
// (CTXH-M11-03; D-CTXH-7, D-CTXH-11; Q-CTXH-2, Q-CTXH-3, Q-CTXH-10, Q-CTXH-15):
//
//	secrets    DESIGN §16.7's secret rules on every string of every node and part before it is sealed, a marker where
//	           a match was, counted in redactions (Q-CTXH-10); record.redact.pii's hashing is not applied to kinds 54
//	           and 55 (Redactor.RedactKind), so a resumed run keeps the addresses the person typed (Q-CTXH-15)
//	search     a built-in's keep: false result, today web search's alone, kept as §21.6's stub, counted in stubs: SRCH's
//	           stub where it gives one, and until it does a stub of the call alone, never the result's text or details
//	           (CO-26, Q-CTXH-3); keep: false from any other tool is ignored, the result kept whole
//	mail       mail_list's and mail_read's results as §23.11's reference, the mailbox, the messages, the call's start
//	           and max_chars, the sign-in flag and the SHA-256 of the text the model read, a form the journal takes from
//	           the mail tools alone; one with no reference is refused, never kept as text (D-MAILCAL-8)
//	whole      every other result, a calendar's and a fetched page's among them, whole up to the part caps (Q-CTXH-2)
//
// A tool result sits in a Pi message entry's message, role toolResult, its content and details; nothing is kept for
// the safety classifier's sake (§24.9's last paragraph).
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// The mail tools whose results the record keeps by reference alone (§23.11).
const (
	sessionMailListTool = "mail_list"
	sessionMailReadTool = "mail_read"
)

// MAILCAL's reference to what a mail tool read (§23.11), which the journal keeps in place of the text: the mailbox or
// group repo, each message's id, the call's start and max_chars, and whether sign-in mail was withheld. The journal
// adds the SHA-256 of the text the model read, so a rebuild that re-renders it from the mailbox checks it.
type SessionMailReference struct {
	RepoId         Id
	MessageIds     []string
	Start          int
	MaxChars       int
	SignInWithheld bool
}

// What the record keeps of a mail tool's result, under details' mail_reference.
type sessionMailReferenceRecord struct {
	RepoId         string   `json:"repo_id"`
	MessageIds     []string `json:"message_ids"`
	Start          int      `json:"start"`
	MaxChars       int      `json:"max_chars"`
	SignInWithheld bool     `json:"sign_in_withheld"`
	// SHA-256 of the text the model read, its text content in order, lowercase hex
	TextSha256 string `json:"text_sha256"`
}

// What applying the exceptions counted.
type sessionExceptionCounts struct {
	redactions int
	stubs      int
	form       SessionItemForm
}

// Whether a tool's result goes by reference: the mail tools' alone.
func sessionMailTool(name string) bool {
	return name == sessionMailListTool || name == sessionMailReadTool
}

// The object a tool result's content and details sit in: a Pi message entry's message, role toolResult, or the
// item itself where it holds content directly. Nil for an item that holds no result.
func sessionToolResultObject(value any) map[string]any {
	item, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if message, ok := item["message"].(map[string]any); ok {
		if role, _ := message["role"].(string); role == "toolResult" {
			return message
		}
		return nil
	}
	if _, ok := item["content"]; ok {
		return item
	}
	return nil
}

// The text a result's content holds, as the model read it: each text part's text in order.
func sessionResultText(result map[string]any) string {
	builder := strings.Builder{}
	switch content := result["content"].(type) {
	case string:
		builder.WriteString(content)
	case []any:
		for _, part := range content {
			if object, ok := part.(map[string]any); ok {
				if text, ok := object["text"].(string); ok {
					builder.WriteString(text)
				}
			}
		}
	}
	return builder.String()
}

// Applies §24.9's exceptions to value, a decoded item, in place: the tool result's form, then the secret rules over
// every string left (see the file header). ErrSessionMailAsText for a mail tool's result with no reference.
func sessionApplyExceptions(value any, tool *SessionToolResult, redactor *Redactor) (any, *sessionExceptionCounts, error) {
	counts := &sessionExceptionCounts{form: SessionItemWhole}
	if tool != nil {
		result := sessionToolResultObject(value)
		switch {
		case sessionMailTool(tool.Name) && tool.BuiltIn:
			if tool.MailReference == nil || result == nil {
				return nil, nil, fmt.Errorf("%w: %s", ErrSessionMailAsText, tool.Name)
			}
			textSha256 := sha256.Sum256([]byte(sessionResultText(result)))
			reference := tool.MailReference
			messageIds := append([]string{}, reference.MessageIds...)
			result["content"] = []any{map[string]any{"type": "text", "text": fmt.Sprintf("[mail reference: %d messages]", len(messageIds))}}
			result["details"] = map[string]any{"mail_reference": &sessionMailReferenceRecord{
				RepoId: hex.EncodeToString(reference.RepoId[:]), MessageIds: messageIds, Start: reference.Start, MaxChars: reference.MaxChars,
				SignInWithheld: reference.SignInWithheld, TextSha256: hex.EncodeToString(textSha256[:]),
			}}
			// a reference keeps the call exact while the message stands, so it is no stub (§24.6's check row)
			counts.form = SessionItemMailReference
		case tool.BuiltIn && tool.KeepFalse:
			if result == nil {
				return nil, nil, fmt.Errorf("%w: a keep: false result the item does not hold", ErrSessionNodeRefused)
			}
			stub := map[string]any{"tool": tool.Name}
			if callId, ok := result["toolCallId"].(string); ok {
				stub["toolCallId"] = callId
			}
			if tool.SearchStub != nil {
				searchStub, err := sessionDecodeJson(tool.SearchStub)
				if err != nil {
					return nil, nil, fmt.Errorf("%w: a search stub: %v", ErrSessionNodeRefused, err)
				}
				stub["search"] = searchStub
			}
			result["content"] = []any{map[string]any{"type": "text", "text": "[" + tool.Name + " result not kept]"}}
			result["details"] = map[string]any{"stub": stub}
			counts.form = SessionItemStub
			counts.stubs += 1
		}
		// keep: false from any other tool is ignored: the result is kept whole
	}
	if redactor == nil {
		return nil, nil, fmt.Errorf("%w: no redactor", ErrSessionNodeRefused)
	}
	redacted, matches := sessionRedactStrings(value, redactor)
	counts.redactions = matches
	return redacted, counts, nil
}

// value with every string redacted under the secret rules, kinds 54 and 55's exemption from PII hashing applied, and
// how many matches were marked. Object keys are the item's schema and are left as they are.
func sessionRedactStrings(value any, redactor *Redactor) (any, int) {
	switch typed := value.(type) {
	case string:
		redacted, matches := redactor.RedactKind(RecordKindSessionEntry, []byte(typed))
		return string(redacted), len(matches)
	case map[string]any:
		total := 0
		for key, member := range typed {
			redacted, count := sessionRedactStrings(member, redactor)
			typed[key] = redacted
			total += count
		}
		return typed, total
	case []any:
		total := 0
		for index, element := range typed {
			redacted, count := sessionRedactStrings(element, redactor)
			typed[index] = redacted
			total += count
		}
		return typed, total
	}
	// a SessionPartRef or a mail reference the exceptions placed, and numbers, booleans and null
	return value, 0
}

// JSON decoded for a walk, numbers kept as written.
func sessionDecodeJson(data []byte) (any, error) {
	value, err := sessionItemDecode(data)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// value's RFC 8785 form.
func sessionCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return CanonicalJson(encoded)
}
