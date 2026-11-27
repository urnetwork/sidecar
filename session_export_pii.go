//go:build !ios_extension

// DESIGN-COMPUTE §24.9's hashing where history leaves the member's devices (CTXH-M11-05; Q-CTXH-15, D-CTXH-11): kinds 54
// and 55 keep email addresses and phone numbers as written in the author's vault, so a resumed or continued run has the
// addresses the person typed, and every export of their bodies hashes them under the harness config's
// record.redact.pii: each match becomes §16.7's marker under the network redactor's key, [REDACTED:<rule>:<8 hex>], so
// equal addresses read as one marker in an export and no reader of it learns them. Where record.redact.pii is off the
// person chose to keep them, and nothing is hashed.
//
// A node's item is JSON, so each string in it is hashed apart, never the encoded text, whose escapes a match could
// break; a blob's content is a part's text, hashed where it is UTF-8 and left as it is where it is bytes, an image's.
// A disclosure packet, which proves each body by its commitment, carries them as sealed instead, its confirmation
// counting them (RECORD.md section 11).
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Every export of a session body hashes it here.
func init() {
	recordExportSessionPii = sessionExportPii
}

// The rules that find PII, by id: the ones record.redact.pii governs.
var sessionPiiRuleIds = sync.OnceValue(func() map[string]bool {
	ids := map[string]bool{}
	for _, compiled := range redactCompiledRules() {
		if compiled.rule.pii {
			ids[compiled.rule.id] = true
		}
	}
	return ids
})

// text with each email address and phone number replaced by its marker under redactor's key while its
// record.redact.pii hashes, and how many; text as it is where hashing is off. Secrets are left to the seal's own
// redaction, which ran before.
func SessionHashPii(redactor *Redactor, text []byte) ([]byte, int) {
	key, pii := redactor.state()
	defer clear(key)
	if !pii {
		return text, 0
	}
	matches, _ := findRedactMatches(text, true)
	piiMatches := []RedactMatch{}
	ruleIds := sessionPiiRuleIds()
	for _, match := range matches {
		if ruleIds[match.Rule] {
			piiMatches = append(piiMatches, match)
		}
	}
	if len(piiMatches) == 0 {
		return text, 0
	}
	return applyRedactMatches(text, piiMatches, func(match RedactMatch) string {
		mac := hmac.New(sha256.New, key)
		mac.Write(text[match.Start:match.End])
		sum := mac.Sum(nil)
		return fmt.Sprintf("[REDACTED:%s:%s]", match.Rule, hex.EncodeToString(sum[:redactMarkerHashByteCount]))
	}), len(piiMatches)
}

// A JSON value with each string's PII hashed, walking objects and arrays; and how many.
func sessionHashPiiValue(redactor *Redactor, value any) (any, int) {
	switch typed := value.(type) {
	case string:
		hashed, count := SessionHashPii(redactor, []byte(typed))
		return string(hashed), count
	case map[string]any:
		total := 0
		for key, member := range typed {
			hashed, count := sessionHashPiiValue(redactor, member)
			typed[key] = hashed
			total += count
		}
		return typed, total
	case []any:
		total := 0
		for i, member := range typed {
			hashed, count := sessionHashPiiValue(redactor, member)
			typed[i] = hashed
			total += count
		}
		return typed, total
	}
	return value, 0
}

// A JSON item, a node's recorded item or a Pi entry, with every string's PII hashed, as RFC 8785; and how many. An
// item with none comes back as it was.
func SessionHashPiiJson(redactor *Redactor, item []byte) ([]byte, int, error) {
	value, err := sessionItemDecode(item)
	if err != nil {
		return nil, 0, err
	}
	hashed, count := sessionHashPiiValue(redactor, value)
	if count == 0 {
		return item, 0, nil
	}
	encoded, err := json.Marshal(hashed)
	if err != nil {
		return nil, 0, err
	}
	canonical, err := CanonicalJson(encoded)
	if err != nil {
		return nil, 0, err
	}
	return canonical, count, nil
}

// A session entry's or blob's stored body with its PII hashed (record_export.go's hook), and how many: the node's item,
// or the blob's content where it is text. A body with none, or of another kind, comes back as it was.
func sessionExportPii(redactor *Redactor, kind RecordKind, body []byte) ([]byte, int, error) {
	switch kind {
	case RecordKindSessionEntry:
		node := &protocol.SessionEntryBody{}
		if err := proto.Unmarshal(body, node); err != nil {
			return nil, 0, fmt.Errorf("%w: a session entry's body: %v", ErrRecordExportArgs, err)
		}
		if len(node.GetItem()) == 0 {
			return body, 0, nil
		}
		item, count, err := SessionHashPiiJson(redactor, node.GetItem())
		if err != nil || count == 0 {
			return body, 0, err
		}
		node.Item = item
		hashed, err := proto.MarshalOptions{Deterministic: true}.Marshal(node)
		return hashed, count, err
	case RecordKindSessionBlob:
		blob := &protocol.SessionBlobBody{}
		if err := proto.Unmarshal(body, blob); err != nil {
			return nil, 0, fmt.Errorf("%w: a session blob's body: %v", ErrRecordExportArgs, err)
		}
		if !utf8.Valid(blob.GetContent()) {
			// a part's bytes, an image's: no text to hash
			return body, 0, nil
		}
		content, count := SessionHashPii(redactor, blob.GetContent())
		if count == 0 {
			return body, 0, nil
		}
		blob.Content = content
		hashed, err := proto.MarshalOptions{Deterministic: true}.Marshal(blob)
		return hashed, count, err
	}
	return body, 0, nil
}
