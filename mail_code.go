// One-time codes (§15.9's GetOneTimeCodes; R-MAIL-6; MAIL-M7-12): the sign-up or login code a message carries, for
// IndexEntry.one_time_code, found in its subject, else its first text part, by a small pattern set: a code is a
// standalone run of 4 to 8 digits, which may be split once into two halves by a space or a hyphen ("123 456",
// "123-456"), or of 6 to 10 capital letters and digits holding both, which sits within a short distance after a code
// word ("code", "passcode", "verification", "OTP", and a few other languages'), or just before one ("123456 is your
// code"). Every value is the sender's, so it is only ever text to show; nothing here acts on it.
//
// What looks like a code and is not: a ZIP, postal, area, promo, coupon or gift code; an order, invoice, ticket,
// reference, tracking or account number (a "#" before the run, or one of those words just before); a price (a
// currency sign or code beside it); a year from 1900 to 2099 standing alone as four digits, or a date as yyyymmdd; a
// date or a time (a run that touches "/", ":", "." or "," to another digit); a run longer than 8 digits, and one a
// space or hyphen joins to another digit run, as a phone number's groups are. Those are refused before a code is
// taken, so a false code costs a missing one rather than a wrong one shown.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// How far around a code word a code may sit, in bytes: after it ("your verification code for Example is 123456"),
// and before it ("123456 is your code"). Pattern values, as the set is.
const (
	mailCodeAfterByteCount  = 64
	mailCodeBeforeByteCount = 24
)

// The words that say a code follows or precedes, lowercase, matched where no letter touches them. "code" covers
// "verification code", "security code", "login code" and the rest.
var mailCodeWords = []string{
	"code", "passcode", "otp", "one-time", "one time", "verification", "verify", "pin",
	"código", "codigo", "codice", "kod", "kode", "koodi", "vérification", "bestätigungscode",
	"код", "验证码", "認証コード", "確認コード", "인증번호",
}

// Words that, just before a code word, make it no code: "zip code" and the like.
var mailCodeNotWords = []string{"zip", "postal", "post", "area", "promo", "promotional", "coupon", "discount", "gift", "referral", "voucher", "source", "country", "dial"}

// Words that, just before a run, make it a number of another kind.
var mailCodeNumberWords = []string{
	"order", "invoice", "ticket", "reference", "ref", "tracking", "account", "case", "booking", "reservation",
	"confirmation number", "no", "number", "phone", "tel", "fax", "id", "room", "suite", "unit", "apt", "flight",
	"seat", "gate", "page", "version", "build", "item", "sku", "part", "serial",
}

// Currency signs and codes that, beside a run, make it a price.
var mailCodeCurrencies = []string{"$", "€", "£", "¥", "₹", "usd", "eur", "gbp", "jpy", "cad", "aud"}

// The first one-time code in subject, else in text, or "" where neither holds one MAIL-FORMAT.md's 32 bytes can
// carry.
func MailExtractOneTimeCode(subject string, text string) string {
	for _, source := range []string{subject, text} {
		if code := mailCodeIn(source); code != "" && len(code) <= mailIndexOneTimeCodeMaxByteCount {
			return code
		}
	}
	return ""
}

// A run of characters that might be a code: where it starts and ends in the text, and the code it gives.
type mailCodeCandidate struct {
	start int
	end   int
	code  string
}

// text lowercased rune by rune where that keeps each rune's byte length, so an offset in one is the same offset in the
// other.
func mailCodeLower(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, character := range text {
		lowered := unicode.ToLower(character)
		if utf8.RuneLen(lowered) != utf8.RuneLen(character) {
			lowered = character
		}
		builder.WriteRune(lowered)
	}
	return builder.String()
}

// The first code in text: the first candidate, in text order, near a code word and refused by no rule.
func mailCodeIn(text string) string {
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	lower := mailCodeLower(text)
	wordSpans := mailCodeWordSpans(lower)
	if len(wordSpans) == 0 {
		return ""
	}
	for _, candidate := range mailCodeCandidates(text) {
		near := false
		for _, span := range wordSpans {
			after := span[1] <= candidate.start && candidate.start-span[1] <= mailCodeAfterByteCount
			before := candidate.end <= span[0] && span[0]-candidate.end <= mailCodeBeforeByteCount
			if after || before {
				near = true
				break
			}
		}
		if near && !mailCodeRefused(lower, candidate) {
			return candidate.code
		}
	}
	return ""
}

// Where each code word sits in lower, as [start, end), but a word that a "not" word comes just before.
func mailCodeWordSpans(lower string) [][2]int {
	spans := [][2]int{}
	for _, word := range mailCodeWords {
		for offset := 0; offset < len(lower); {
			index := strings.Index(lower[offset:], word)
			if index < 0 {
				break
			}
			start, end := offset+index, offset+index+len(word)
			offset = end
			// a script written without spaces sets its words beside other letters
			if !mailCodeUnspaced(word) && (mailCodeLetterAt(lower, start, -1) || mailCodeLetterAt(lower, end, 1)) {
				continue
			}
			if mailCodePrecededBy(lower, start, mailCodeNotWords) {
				continue
			}
			spans = append(spans, [2]int{start, end})
		}
	}
	return spans
}

// Whether word is written in a script that sets no space between words: Han, kana or Hangul.
func mailCodeUnspaced(word string) bool {
	for _, character := range word {
		if unicode.In(character, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) {
			return true
		}
	}
	return false
}

// Whether a letter touches index from the side direction says: -1 the rune before it, 1 the rune at it.
func mailCodeLetterAt(text string, index int, direction int) bool {
	var character rune
	if direction < 0 {
		if index == 0 {
			return false
		}
		character, _ = utf8.DecodeLastRuneInString(text[:index])
	} else {
		if len(text) <= index {
			return false
		}
		character, _ = utf8.DecodeRuneInString(text[index:])
	}
	return unicode.IsLetter(character)
}

// Whether one of words ends just before index, past spaces and a colon or "#", as a whole word.
func mailCodePrecededBy(lower string, index int, words []string) bool {
	before := strings.TrimRight(lower[:index], " \t\r\n:#.")
	for _, word := range words {
		if strings.HasSuffix(before, word) && !mailCodeLetterAt(before, len(before)-len(word), -1) {
			return true
		}
	}
	return false
}

// Each run that has a code's shape, in text order: digits, possibly split once, or capitals and digits holding both.
func mailCodeCandidates(text string) []mailCodeCandidate {
	candidates := []mailCodeCandidate{}
	isAlphanumeric := func(character rune) bool {
		return ('0' <= character && character <= '9') || ('A' <= character && character <= 'Z') || ('a' <= character && character <= 'z')
	}
	for index := 0; index < len(text); {
		character, width := utf8.DecodeRuneInString(text[index:])
		if !isAlphanumeric(character) {
			index += width
			continue
		}
		start := index
		for index < len(text) && isAlphanumeric(rune(text[index])) {
			index += 1
		}
		run := text[start:index]
		// a letter or digit of another script touching the run makes it part of a longer word
		if mailCodeTouchesWord(text, start, index) {
			continue
		}
		switch {
		case mailCodeAllDigits(run):
			// one split into halves: 123 456, 123-456
			if index+1 < len(text) && (text[index] == ' ' || text[index] == '-') {
				end := index + 1
				for end < len(text) && '0' <= text[end] && text[end] <= '9' {
					end += 1
				}
				second := text[index+1 : end]
				if len(run) == 3 && len(second) == 3 && !mailCodeTouchesWord(text, index+1, end) &&
					(end == len(text) || !isAlphanumeric(rune(text[end]))) {
					candidates = append(candidates, mailCodeCandidate{start: start, end: end, code: run + second})
					index = end
					continue
				}
			}
			if 4 <= len(run) && len(run) <= 8 {
				candidates = append(candidates, mailCodeCandidate{start: start, end: index, code: run})
			}
		case 6 <= len(run) && len(run) <= 10 && strings.ToUpper(run) == run && strings.ContainsAny(run, "0123456789") &&
			strings.ContainsAny(run, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
			candidates = append(candidates, mailCodeCandidate{start: start, end: index, code: run})
		}
	}
	return candidates
}

// Whether a letter or digit outside ASCII touches [start, end), which joins the run to a word of another script.
func mailCodeTouchesWord(text string, start int, end int) bool {
	if 0 < start {
		character, _ := utf8.DecodeLastRuneInString(text[:start])
		if character >= utf8.RuneSelf && (unicode.IsLetter(character) || unicode.IsDigit(character)) {
			return true
		}
	}
	if end < len(text) {
		character, _ := utf8.DecodeRuneInString(text[end:])
		if character >= utf8.RuneSelf && (unicode.IsLetter(character) || unicode.IsDigit(character)) {
			return true
		}
	}
	return false
}

// Whether run is ASCII digits only, and not empty.
func mailCodeAllDigits(run string) bool {
	for index := range len(run) {
		if run[index] < '0' || '9' < run[index] {
			return false
		}
	}
	return run != ""
}

// Whether a rule makes a candidate no code: see the file header.
func mailCodeRefused(lower string, candidate mailCodeCandidate) bool {
	start, end := candidate.start, candidate.end
	// a year standing alone, or a date written yyyymmdd
	code := candidate.code
	if mailCodeAllDigits(code) && (strings.HasPrefix(code, "19") || strings.HasPrefix(code, "20")) &&
		((len(code) == 4 && end-start == 4) ||
			(len(code) == 8 && "01" <= code[4:6] && code[4:6] <= "12" && "01" <= code[6:8] && code[6:8] <= "31")) {
		return true
	}
	// a date, a time or a decimal: a separator joining the run to another digit
	joined := func(index int, direction int) bool {
		if direction < 0 {
			return 2 <= index && strings.ContainsRune("/:.,", rune(lower[index-1])) && '0' <= lower[index-2] && lower[index-2] <= '9'
		}
		return index+1 < len(lower) && strings.ContainsRune("/:.,", rune(lower[index])) && '0' <= lower[index+1] && lower[index+1] <= '9'
	}
	if joined(start, -1) || joined(end, 1) {
		return true
	}
	// part of a longer number, as a phone number's groups are: another digit run a space or a hyphen away
	digit := func(index int) bool { return '0' <= lower[index] && lower[index] <= '9' }
	if (2 <= start && strings.ContainsRune(" -", rune(lower[start-1])) && digit(start-2)) ||
		(end+1 < len(lower) && strings.ContainsRune(" -", rune(lower[end])) && digit(end+1)) {
		return true
	}
	// a number of another kind, or a price
	if 0 < start && lower[start-1] == '#' {
		return true
	}
	if mailCodePrecededBy(lower, start, mailCodeNumberWords) {
		return true
	}
	beforeRun := strings.TrimRight(lower[:start], " ")
	afterRun := strings.TrimLeft(lower[end:], " ")
	for _, currency := range mailCodeCurrencies {
		if strings.HasSuffix(beforeRun, currency) || strings.HasPrefix(afterRun, currency) {
			return true
		}
	}
	return false
}
