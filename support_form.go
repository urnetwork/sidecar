//go:build !ios_extension && !sidecar_http

// A support message's form and secret checks (DESIGN-COMPUTE §28.6), run on the device before anything is queued:
//
//	form     at most the format's 16 KiB of UTF-8 text; control characters other than newline and tab dropped; tag
//	         characters, variation selectors not attached to an emoji and bidirectional controls refused, hidden_text,
//	         since they hide text from the operator and from any model triage runs
//	secrets  the record's redaction patterns and every credential the daemon holds (Sidecar.SecretMatcher), with any a
//	         host adds (SupportSecretSource), in the text and each text file: a match refuses an agent's message,
//	         secret_in_message, naming the pattern's class and where it starts, never the match; a person's own
//	         message is warned and the person decides (FB section 10.1)
//	files    at most 3, each at most 10 MiB, UTF-8 text, which the scan reads whole, PNG or JPEG, which it cannot;
//	         anything else is refused (§28.7)
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The refusals that fail only their call (§28.14): a Harness run goes on, and support is never a reason to stop work.
type SupportRefusal string

const (
	SupportRefusalDisclosureRequired SupportRefusal = "disclosure_required"
	SupportRefusalSecretInMessage    SupportRefusal = "secret_in_message"
	SupportRefusalHiddenText         SupportRefusal = "hidden_text"
	SupportRefusalSupportOff         SupportRefusal = "support_off"
	SupportRefusalRateLimited        SupportRefusal = "rate_limited"
	SupportRefusalQueueFull          SupportRefusal = "support_queue_full"
	SupportRefusalPaused             SupportRefusal = "support_paused"
	// The text is past its bound, empty, or no UTF-8 (§28.6's form row).
	SupportRefusalTooLong SupportRefusal = "too_long"
	SupportRefusalNotText SupportRefusal = "not_text"
	// A file of a type §28.7 does not take, past its size or count, or one no reader opens.
	SupportRefusalFileRefused SupportRefusal = "file_refused"
	// No item of the member's has that id, or this caller may not read it.
	SupportRefusalNotFound SupportRefusal = "not_found"
	// No verified policy names the feedback service's host yet (§28.10).
	SupportRefusalNoHost SupportRefusal = "no_host"
	// A person's message the scan warned on, which the person has not confirmed.
	SupportRefusalSecretWarned SupportRefusal = "secret_warned"
	// An agent's enumerated report, which needs FB section 5's feedback.auto grant, a person's per network or per agent,
	// that nothing builds yet (FB's G3): refused until it is (support_report.go).
	SupportRefusalGrantRequired SupportRefusal = "grant_required"
)

// The support log's word for each refusal, which its registry enumerates.
var supportRefusalLogValues = map[SupportRefusal]SupportLogRefusal{
	SupportRefusalDisclosureRequired: SupportLogRefusalDisclosureRequired,
	SupportRefusalSecretInMessage:    SupportLogRefusalSecretInMessage,
	SupportRefusalSecretWarned:       SupportLogRefusalSecretInMessage,
	SupportRefusalHiddenText:         SupportLogRefusalHiddenText,
	SupportRefusalSupportOff:         SupportLogRefusalSupportOff,
	SupportRefusalRateLimited:        SupportLogRefusalRateLimited,
	SupportRefusalQueueFull:          SupportLogRefusalSupportQueueFull,
	SupportRefusalPaused:             SupportLogRefusalSupportPaused,
	SupportRefusalTooLong:            SupportLogRefusalTooLong,
	SupportRefusalNotText:            SupportLogRefusalNotText,
	SupportRefusalFileRefused:        SupportLogRefusalFileRefused,
	SupportRefusalNotFound:           SupportLogRefusalNotFound,
	SupportRefusalNoHost:             SupportLogRefusalNoHost,
	SupportRefusalGrantRequired:      SupportLogRefusalGrantRequired,
}

// What a refused call answers: the refusal, and where it applies the secret's class and where it starts, the file it
// is in, or when to try again. Never the matched bytes, nor any of the message's text.
type SupportRefusalError struct {
	Refusal SupportRefusal
	// secret_in_message: the pattern's class (SecretMatch.Class), its offset in the text or the file, and which file,
	// -1 for the text.
	SecretClass  string
	SecretOffset int
	FileIndex    int
	// rate_limited: when the next message may go.
	RetryAfter time.Duration
	// disclosure_required: the disclosure's id, and the fix the person runs.
	DisclosureId string
}

// The refusal and its class or offset, never the message.
func (self *SupportRefusalError) Error() string {
	switch self.Refusal {
	case SupportRefusalSecretInMessage, SupportRefusalSecretWarned:
		where := "the text"
		if 0 <= self.FileIndex {
			where = fmt.Sprintf("file %d", self.FileIndex+1)
		}
		return fmt.Sprintf("%s: %s at byte %d of %s", self.Refusal, self.SecretClass, self.SecretOffset, where)
	case SupportRefusalRateLimited:
		return fmt.Sprintf("%s: retry after %s", self.Refusal, self.RetryAfter.Round(time.Second))
	case SupportRefusalDisclosureRequired:
		return fmt.Sprintf("%s: %s; the person reads it in the app's settings or with ur disclosures ack %s", self.Refusal, self.DisclosureId, self.DisclosureId)
	}
	return string(self.Refusal)
}

// A refusal of code alone.
func supportRefused(refusal SupportRefusal) *SupportRefusalError {
	return &SupportRefusalError{Refusal: refusal, FileIndex: -1}
}

// The refusal err holds, or "" for an error that is no refusal.
func SupportRefusalOf(err error) SupportRefusal {
	var refusal *SupportRefusalError
	if errors.As(err, &refusal) {
		return refusal.Refusal
	}
	return ""
}

// Whether r is a bidirectional control: the embeddings, overrides and isolates, and the marks.
func supportBidiControl(r rune) bool {
	return (0x202A <= r && r <= 0x202E) || (0x2066 <= r && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// Whether r is a tag character, which hides ASCII text in plain sight.
func supportTagCharacter(r rune) bool {
	return 0xE0000 <= r && r <= 0xE007F
}

// Whether r is a variation selector: the 16 standard ones and the 240 ideographic ones.
func supportVariationSelector(r rune) bool {
	return (0xFE00 <= r && r <= 0xFE0F) || (0xE0100 <= r && r <= 0xE01EF)
}

// Whether r takes an emoji presentation selector: the blocks emoji are drawn from, and the keycap bases. A reading of
// Unicode's emoji data, which Go's tables do not carry: wider than it, never narrower for an emoji in common use.
func supportEmojiBase(r rune) bool {
	switch {
	case 0x1F000 <= r && r <= 0x1FAFF, 0x2600 <= r && r <= 0x27BF, 0x2190 <= r && r <= 0x21FF, 0x2300 <= r && r <= 0x23FF,
		0x2B00 <= r && r <= 0x2BFF, 0x2900 <= r && r <= 0x297F, 0x25A0 <= r && r <= 0x25FF:
		return true
	}
	switch r {
	case 0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299, '#', '*':
		return true
	}
	return '0' <= r && r <= '9'
}

// The text as it goes, or the refusal: UTF-8 within maxByteCount after control characters other than newline and tab
// are dropped, refused for a tag character, a bidirectional control, or a variation selector that follows no emoji
// (VS15 and VS16 after an emoji base are presentation, the rest hide). Empty text is refused too.
func supportFormText(text string, maxByteCount int) (string, error) {
	if !utf8.ValidString(text) {
		return "", supportRefused(SupportRefusalNotText)
	}
	out := strings.Builder{}
	previous := rune(-1)
	for _, r := range text {
		switch {
		case supportTagCharacter(r) || supportBidiControl(r):
			return "", supportRefused(SupportRefusalHiddenText)
		case supportVariationSelector(r):
			if !((r == 0xFE0E || r == 0xFE0F) && 0 <= previous && supportEmojiBase(previous)) {
				return "", supportRefused(SupportRefusalHiddenText)
			}
		case r == '\n' || r == '\t':
		case unicode.IsControl(r):
			// dropped, as §28.6 has it
			continue
		}
		out.WriteRune(r)
		previous = r
	}
	formed := out.String()
	if strings.TrimSpace(formed) == "" {
		return "", supportRefused(SupportRefusalNotText)
	}
	if maxByteCount < len(formed) {
		return "", supportRefused(SupportRefusalTooLong)
	}
	return formed, nil
}

// A file a message names, as its caller read it: under the run's root for an agent, by the person's choice in an app or
// on /dev/tty.
type SupportFile struct {
	// Its base name, which the body and the card show.
	Name string
	Data []byte
}

// A file's type by its bytes, or the refusal: PNG and JPEG by their signatures, else UTF-8 text with no NUL, which the
// scan reads whole, else refused.
func supportFileType(file *SupportFile, maxByteCount int64) (uint32, error) {
	if file == nil || file.Name == "" || strings.ContainsAny(file.Name, "/\\\x00") || maxByteCount < int64(len(file.Data)) {
		return 0, supportRefused(SupportRefusalFileRefused)
	}
	switch {
	case bytes.HasPrefix(file.Data, []byte("\x89PNG\r\n\x1a\n")):
		return supportFileTypePng, nil
	case bytes.HasPrefix(file.Data, []byte{0xFF, 0xD8, 0xFF}):
		return supportFileTypeJpeg, nil
	case utf8.Valid(file.Data) && !bytes.ContainsRune(file.Data, 0):
		return supportFileTypeText, nil
	}
	return 0, supportRefused(SupportRefusalFileRefused)
}

// A file type's word, as a body and a card name it.
var supportFileTypeNames = map[uint32]string{
	supportFileTypeText: "text",
	supportFileTypePng:  "png",
	supportFileTypeJpeg: "jpeg",
}

// What the scan matches beyond Sidecar.SecretMatcher's: the credentials a host holds for compute (DESIGN §16.6's secrets
// row: gateway and service tokens, connections' tokens and calendar links' secrets) and every sign-in code or link the
// mail component withheld (§23.4). Their owners register them as they land (CONTRACTS C-41); until then a host gives
// none, and the matcher's own patterns still hold.
type SupportSecretSource interface {
	// Each value to refuse, raw; a caller zeroes nothing it is given.
	SupportSecrets() [][]byte
}

// The first secret in text and in each text file, by matcher and extra's forms: its class, its offset and which file,
// -1 for the text; nil for none.
func supportScan(matcher *SecretMatcher, extra *SecretMatcher, text string, files []*SupportFile, fileTypes []uint32) *SupportRefusalError {
	scan := func(data []byte, fileIndex int) *SupportRefusalError {
		for _, each := range []*SecretMatcher{matcher, extra} {
			if each == nil {
				continue
			}
			if match := each.Match(data); match != nil {
				return &SupportRefusalError{Refusal: SupportRefusalSecretInMessage, SecretClass: match.Class, SecretOffset: match.Offset, FileIndex: fileIndex}
			}
		}
		return nil
	}
	if refused := scan([]byte(text), -1); refused != nil {
		return refused
	}
	for i, file := range files {
		if fileTypes[i] != supportFileTypeText {
			// an image the scan cannot read, which is why a file always asks the person (§28.7)
			continue
		}
		if refused := scan(file.Data, i); refused != nil {
			return refused
		}
	}
	return nil
}
