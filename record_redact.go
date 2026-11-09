// §16.7's redactor (R-MCP-5, D-MCP-5, I-7): before anything capture holds is sealed, every secret a rule
// (record_redact_rules.go, record_redact_entropy.go) finds becomes
//
//	[REDACTED:<rule>:<8 hex of HMAC(key, value)>]
//
// so equal secrets in one key's epoch read as one marker and no reader learns the value. The key is the redactor's
// own, 32 random bytes drawn at each unlock and kept in memory through a lock, so redaction goes on while the daemon
// is Locked and holds no R_n (MCP.md's reading 5): equal secrets in two epochs do not correlate, which costs nothing
// the marker promises. Text a network's members share takes RedactShared's [REDACTED:<rule>] instead, since no HMAC
// of a shared secret may travel (RECORD-M6-11); shared writes that refuse on a secret call Scan, which rewrites
// nothing and reports PII as no secret.
//
// Each rule runs only when one of its keywords is in the lowercased text, and every rule is RE2, so a 1 MiB payload
// costs time linear in its length. A redaction is itself a coverage gap: Redact answers what it covered, by rule and
// offset, never by value, and no error here carries a value. A marker already in the text is left alone, so
// redacting twice changes nothing. The restore point is never redacted (§16.7): restore needs exact bytes, and they
// never leave the device.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The marker's format values.
const (
	// The redaction key's bytes.
	redactKeyByteCount = 32
	// The HMAC bytes a local marker shows, as 8 hex characters.
	redactMarkerHashByteCount = 4
)

// A marker either form leaves, which a later pass leaves alone.
var redactMarkerPattern = regexp.MustCompile(`\[REDACTED:[a-z0-9-]+(?::[0-9a-f]{8})?\]`)

// One rule's compiled form.
type redactCompiledRule struct {
	rule         *redactRule
	pattern      *regexp.Regexp
	allow        []*regexp.Regexp
	allowMatch   []*regexp.Regexp
	keywordBytes [][]byte
}

// The rules, compiled once. A rule that does not compile is a bug the tests catch, so it panics at first use.
var redactCompiledRules = sync.OnceValue(func() []*redactCompiledRule {
	compiled := []*redactCompiledRule{}
	for _, rule := range append(slices.Clone(redactRules), redactEntropyRule) {
		compiledRule := &redactCompiledRule{rule: rule, pattern: regexp.MustCompile(rule.pattern)}
		for _, allow := range rule.allow {
			compiledRule.allow = append(compiledRule.allow, regexp.MustCompile(allow))
		}
		for _, allow := range rule.allowMatch {
			compiledRule.allowMatch = append(compiledRule.allowMatch, regexp.MustCompile(allow))
		}
		for _, keyword := range rule.keywords {
			compiledRule.keywordBytes = append(compiledRule.keywordBytes, []byte(keyword))
		}
		compiled = append(compiled, compiledRule)
	}
	return compiled
})

// Whether a keyword of the rule is in lowered, the text lowercased: the prefilter that keeps most rules from running.
func (self *redactCompiledRule) prefilter(lowered []byte) bool {
	if len(self.keywordBytes) == 0 {
		return true
	}
	for _, keyword := range self.keywordBytes {
		if bytes.Contains(lowered, keyword) {
			return true
		}
	}
	return false
}

// One secret a rule found: text[Start:End], by rule. Never the value.
type RedactMatch struct {
	Rule  string
	Start int
	End   int
}

// The secrets in text, sorted by start and merged where they overlap, the earlier rule naming a merged span. Spans
// inside a marker already there are left out. work counts the bytes the rules' regexes were handed, which is the
// redactor's cost: at most one pass of the text per rule.
func findRedactMatches(text []byte, withPii bool) (matches []RedactMatch, work int) {
	lowered := bytes.ToLower(text)
	// markers do not overlap and come in order, so the first that ends past start is the only one that can meet it
	markers := redactMarkerPattern.FindAllIndex(text, -1)
	insideMarker := func(start int, end int) bool {
		at, _ := slices.BinarySearchFunc(markers, start, func(marker []int, start int) int {
			if marker[1] <= start {
				return -1
			}
			return 1
		})
		return at < len(markers) && markers[at][0] < end
	}
	type ruleSpan struct {
		match RedactMatch
		order int
	}
	spans := []ruleSpan{}
	for order, compiled := range redactCompiledRules() {
		if compiled.rule.pii && !withPii {
			continue
		}
		if !compiled.prefilter(lowered) {
			continue
		}
		work += len(text)
		for _, groups := range compiled.pattern.FindAllSubmatchIndex(text, -1) {
			start, end := redactSecretSpan(compiled.rule, groups)
			if start < 0 || start == end {
				continue
			}
			secret := text[start:end]
			if 0 < compiled.rule.entropy && redactShannonEntropy(secret) <= compiled.rule.entropy {
				continue
			}
			if slices.ContainsFunc(compiled.allow, func(allow *regexp.Regexp) bool { return allow.Match(secret) }) {
				continue
			}
			whole := text[groups[0]:groups[1]]
			if slices.ContainsFunc(compiled.allowMatch, func(allow *regexp.Regexp) bool { return allow.Match(whole) }) {
				continue
			}
			if insideMarker(start, end) {
				continue
			}
			spans = append(spans, ruleSpan{match: RedactMatch{Rule: compiled.rule.id, Start: start, End: end}, order: order})
		}
	}
	slices.SortFunc(spans, func(a ruleSpan, b ruleSpan) int {
		if a.match.Start != b.match.Start {
			return a.match.Start - b.match.Start
		}
		return a.order - b.order
	})
	for _, span := range spans {
		if last := len(matches) - 1; 0 <= last && span.match.Start < matches[last].End {
			matches[last].End = max(matches[last].End, span.match.End)
			continue
		}
		matches = append(matches, span.match)
	}
	return matches, work
}

// Where a match's secret is: the rule's group, else the first non-empty group, else the whole match. -1 for none.
func redactSecretSpan(rule *redactRule, groups []int) (int, int) {
	if rule.secretGroup != 0 {
		if len(groups) <= 2*rule.secretGroup+1 {
			return -1, -1
		}
		return groups[2*rule.secretGroup], groups[2*rule.secretGroup+1]
	}
	for group := 1; 2*group+1 < len(groups); group += 1 {
		if start, end := groups[2*group], groups[2*group+1]; 0 <= start && start < end {
			return start, end
		}
	}
	return groups[0], groups[1]
}

// text with each match replaced by the marker marker answers for it.
func applyRedactMatches(text []byte, matches []RedactMatch, marker func(match RedactMatch) string) []byte {
	if len(matches) == 0 {
		return bytes.Clone(text)
	}
	out := make([]byte, 0, len(text))
	at := 0
	for _, match := range matches {
		out = append(out, text[at:match.Start]...)
		out = append(out, marker(match)...)
		at = match.End
	}
	return append(out, text[at:]...)
}

// The redactor of one network's capture. Its key is drawn at construction and at each Rotate.
type Redactor struct {
	stateLock sync.Mutex
	key       []byte
	// whether PII is hashed, the harness config's record.redact.pii (QD-116): hash by default
	pii bool
}

// A redactor with a fresh key from random, hashing PII.
func NewRedactor(random io.Reader) (*Redactor, error) {
	self := &Redactor{pii: true}
	if err := self.Rotate(random); err != nil {
		return nil, err
	}
	return self, nil
}

// Draws a new key from random, starting a new epoch: what the spool calls at each unlock. The old key is zeroed.
func (self *Redactor) Rotate(random io.Reader) error {
	key := make([]byte, redactKeyByteCount)
	if _, err := io.ReadFull(random, key); err != nil {
		return errors.New("no randomness for a redaction key")
	}
	testHookSecret("K_redact", key)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.key)
	self.key = key
	return nil
}

// Sets whether PII is hashed, from the harness config's record.redact.pii: true for hash, false for off.
func (self *Redactor) SetPiiHashing(hash bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pii = hash
}

// A copy of the key and the PII setting.
func (self *Redactor) state() ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.key), self.pii
}

// text with every secret, and PII while it is hashed, replaced by §16.7's marker under this epoch's key, and what was
// covered, by rule and offset in text. A match is a coverage gap for the caller to record.
func (self *Redactor) Redact(text []byte) ([]byte, []RedactMatch) {
	key, pii := self.state()
	defer clear(key)
	matches, _ := findRedactMatches(text, pii)
	return applyRedactMatches(text, matches, func(match RedactMatch) string {
		mac := hmac.New(sha256.New, key)
		mac.Write(text[match.Start:match.End])
		sum := mac.Sum(nil)
		return fmt.Sprintf("[REDACTED:%s:%s]", match.Rule, hex.EncodeToString(sum[:redactMarkerHashByteCount]))
	}), matches
}

// text with every secret, and PII while it is hashed, replaced by [REDACTED:<rule>], with no HMAC: for text a
// network's members share, such as the directory's (RECORD-M6-11).
func (self *Redactor) RedactShared(text []byte) ([]byte, []RedactMatch) {
	_, pii := self.state()
	matches, _ := findRedactMatches(text, pii)
	return applyRedactMatches(text, matches, func(match RedactMatch) string {
		return "[REDACTED:" + match.Rule + "]"
	}), matches
}

// The secrets in text, rewriting nothing: what a shared write refuses on, and what Sidecar.SecretMatcher takes as
// the redactor's token forms. PII is no credential, so it is never reported here.
func (self *Redactor) Scan(text []byte) []RedactMatch {
	matches, _ := findRedactMatches(text, false)
	return matches
}

// The rule names a marker may carry, sorted, each once: for a reader that counts redactions by rule.
func RedactRuleIds() []string {
	ids := []string{}
	for _, compiled := range redactCompiledRules() {
		if !slices.Contains(ids, compiled.rule.id) {
			ids = append(ids, compiled.rule.id)
		}
	}
	slices.SortFunc(ids, strings.Compare)
	return ids
}
