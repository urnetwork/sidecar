//go:build !ios_extension && !sidecar_http

// The classifier's two views and hidden text (DESIGN-COMPUTE §27.6, §27.7; SAFE-M13-02). Each text is scored as it was
// read and in a normalized view, and the higher score counts (SAFE-M13-04), against §27.3's character attacks: letters
// spaced out, zero-width and format characters, homoglyphs and fullwidth forms. The normalized view never replaces the
// raw one.
//
// SafetyNormalize's view, in §27.6's order, each pass:
//
//  1. NFKC (x/text), fullwidth and compatibility forms to their plain ones; invalid UTF-8 to U+FFFD;
//  2. Unicode's format characters (Cf: zero-width joiners and spaces, bidirectional controls, soft hyphens),
//     variation selectors and tag characters (U+E0000-U+E007F) removed;
//  3. confusables mapped to their TS #39 skeletons: the text decomposed (NFD), each code point the table holds
//     replaced by its prototype, decomposed again, as TS #39's skeleton is built; every code point the table maps,
//     the table's own reach, ASCII's few among them (m to rn, I to l, 0 to O);
//  4. letters standing alone, each separated from the next by exactly one space or one punctuation character, joined:
//     "i g n o r e" and "i.g.n.o.r.e" to "ignore"; a letter is one with its combining marks, and it stands alone when no
//     letter, digit or mark touches it, so prose keeps its spaces and a word its punctuation;
//  5. NFKC again, so the view is composed.
//
// The view is the text the passes leave unchanged: a second pass checks the first, and up to NormalizeMaxPassCount run
// before a text that keeps changing is refused, so the view is idempotent by construction, whatever table a release
// pins. Each step's output is held to NormalizeGrowthMaxFactor times the text's size; past it, and past the input
// bound, the text is refused, matching ErrSafetyUnavailable, so it asks. Without a verified table there is no view:
// SafetyNormalize answers unavailable, never a view without skeletons (QD-1368).
//
// SafetyHiddenText reads the raw text for what no reader sees: tag characters, a variation selector not attached to an
// emoji, and bidirectional controls. Any of them, in an input or in the action, makes the verdict ask, reason
// hidden_text, whatever the scores (§27.7). A variation selector is attached only where it is U+FE0E or U+FE0F right
// after an emoji, as emoji presentation writes it; any other selector, or a second one, can carry a hidden byte
// (emoji smuggling, §27.3), so it counts.
//
// Safe for concurrent use: nothing here holds state.

package sidecar

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The view of text (see the file comment) under confusables, or ErrSafetyUnavailable: no table, a text past the input
// bound, one that grows past its bound, or one whose view does not settle.
func SafetyNormalize(text string, confusables *SafetyConfusables, settings *SafetySettings) (string, error) {
	if confusables == nil {
		return "", safetyUnavailable("no verified confusables table, so no normalized view")
	}
	if settings.InputMaxByteCount < len(text) {
		return "", safetyUnavailable("a text of %d bytes, past %d", len(text), settings.InputMaxByteCount)
	}
	// a character the table grows the most from leaves room for one of its prototypes on any text
	maxByteCount := settings.NormalizeGrowthMaxFactor*len(text) + utf8.UTFMax*settings.ConfusablesTargetMaxCodePointCount
	current := text
	for range settings.NormalizeMaxPassCount {
		next, err := safetyNormalizePass(current, confusables, maxByteCount)
		if err != nil {
			return "", err
		}
		if next == current {
			return current, nil
		}
		current = next
	}
	return "", safetyUnavailable("a text whose normalized view does not settle in %d passes", settings.NormalizeMaxPassCount)
}

// One pass of the view's five steps, each output held to maxByteCount bytes.
func safetyNormalizePass(text string, confusables *SafetyConfusables, maxByteCount int) (string, error) {
	held := func(step string) error {
		if maxByteCount < len(step) {
			return safetyUnavailable("a text whose normalized view grows past %d bytes", maxByteCount)
		}
		return nil
	}
	text = strings.ToValidUTF8(norm.NFKC.String(text), safetyReplacementCharacter)
	if err := held(text); err != nil {
		return "", err
	}
	stripped := strings.Builder{}
	for _, character := range text {
		if !safetyRemovedRune(character) {
			stripped.WriteRune(character)
		}
	}
	skeleton := strings.Builder{}
	for _, character := range norm.NFD.String(stripped.String()) {
		if prototype, ok := confusables.prototypes[character]; ok {
			skeleton.WriteString(prototype)
		} else {
			skeleton.WriteRune(character)
		}
		if err := held(skeleton.String()); err != nil {
			return "", err
		}
	}
	decomposed := norm.NFD.String(skeleton.String())
	if err := held(decomposed); err != nil {
		return "", err
	}
	joined := norm.NFKC.String(safetyJoinLetters(decomposed))
	if err := held(joined); err != nil {
		return "", err
	}
	return joined, nil
}

// Whether the view drops character: a format character, a variation selector or a tag character.
func safetyRemovedRune(character rune) bool {
	return unicode.Is(unicode.Cf, character) || safetyVariationSelector(character) || safetyTagCharacter(character)
}

// Unicode's Variation_Selector: Mongolian's free variation selectors, the standardized and the ideographic ones.
func safetyVariationSelector(character rune) bool {
	switch {
	case 0x180b <= character && character <= 0x180d, character == 0x180f:
		return true
	case 0xfe00 <= character && character <= 0xfe0f:
		return true
	case 0xe0100 <= character && character <= 0xe01ef:
		return true
	}
	return false
}

// The tag block, U+E0000-U+E007F.
func safetyTagCharacter(character rune) bool {
	return 0xe0000 <= character && character <= 0xe007f
}

// The bidirectional controls §27.6 names: the embeddings and overrides, the isolates, and the marks.
func safetyBidiControl(character rune) bool {
	switch {
	case 0x202a <= character && character <= 0x202e, 0x2066 <= character && character <= 0x2069:
		return true
	case character == 0x200e, character == 0x200f, character == 0x061c:
		return true
	}
	return false
}

// What an emoji presentation selector may follow: Unicode's Extended_Pictographic, as emoji-data.txt gives it, and
// the keycap bases. Generous where the blocks are mostly pictographs, which only lets one more bit pass after each.
var safetyEmojiBases = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x0023, Hi: 0x0023, Stride: 1},
		{Lo: 0x002a, Hi: 0x002a, Stride: 1},
		{Lo: 0x0030, Hi: 0x0039, Stride: 1},
		{Lo: 0x00a9, Hi: 0x00a9, Stride: 1},
		{Lo: 0x00ae, Hi: 0x00ae, Stride: 1},
		{Lo: 0x203c, Hi: 0x203c, Stride: 1},
		{Lo: 0x2049, Hi: 0x2049, Stride: 1},
		{Lo: 0x2122, Hi: 0x2122, Stride: 1},
		{Lo: 0x2139, Hi: 0x2139, Stride: 1},
		{Lo: 0x2194, Hi: 0x2199, Stride: 1},
		{Lo: 0x21a9, Hi: 0x21aa, Stride: 1},
		{Lo: 0x231a, Hi: 0x231b, Stride: 1},
		{Lo: 0x2328, Hi: 0x2328, Stride: 1},
		{Lo: 0x2388, Hi: 0x2388, Stride: 1},
		{Lo: 0x23cf, Hi: 0x23cf, Stride: 1},
		{Lo: 0x23e9, Hi: 0x23f3, Stride: 1},
		{Lo: 0x23f8, Hi: 0x23fa, Stride: 1},
		{Lo: 0x24c2, Hi: 0x24c2, Stride: 1},
		{Lo: 0x25aa, Hi: 0x25ab, Stride: 1},
		{Lo: 0x25b6, Hi: 0x25b6, Stride: 1},
		{Lo: 0x25c0, Hi: 0x25c0, Stride: 1},
		{Lo: 0x25fb, Hi: 0x25fe, Stride: 1},
		{Lo: 0x2600, Hi: 0x27bf, Stride: 1},
		{Lo: 0x2934, Hi: 0x2935, Stride: 1},
		{Lo: 0x2b05, Hi: 0x2b07, Stride: 1},
		{Lo: 0x2b1b, Hi: 0x2b1c, Stride: 1},
		{Lo: 0x2b50, Hi: 0x2b50, Stride: 1},
		{Lo: 0x2b55, Hi: 0x2b55, Stride: 1},
		{Lo: 0x3030, Hi: 0x3030, Stride: 1},
		{Lo: 0x303d, Hi: 0x303d, Stride: 1},
		{Lo: 0x3297, Hi: 0x3297, Stride: 1},
		{Lo: 0x3299, Hi: 0x3299, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1f000, Hi: 0x1faff, Stride: 1},
		{Lo: 0x1fc00, Hi: 0x1fffd, Stride: 1},
	},
}

// Whether text holds characters no reader sees (see the file comment): a tag character, a variation selector not
// attached to an emoji, or a bidirectional control.
func SafetyHiddenText(text string) bool {
	previous := rune(-1)
	for _, character := range text {
		switch {
		case safetyTagCharacter(character), safetyBidiControl(character):
			return true
		case safetyVariationSelector(character):
			attached := (character == 0xfe0e || character == 0xfe0f) && 0 <= previous && unicode.Is(safetyEmojiBases, previous)
			if !attached {
				return true
			}
		}
		previous = character
	}
	return false
}

// Whether character is a letter, by Unicode's L categories.
func safetyLetter(character rune) bool {
	return unicode.IsLetter(character)
}

// Whether character touches a letter so that it is no letter standing alone: a letter, a digit or a mark.
func safetyWordRune(character rune) bool {
	return unicode.IsLetter(character) || unicode.IsNumber(character) || unicode.IsMark(character)
}

// Whether character may stand between two letters of a run: one space or one punctuation character.
func safetyJoinSeparator(character rune) bool {
	return character == ' ' || unicode.IsPunct(character)
}

// text, decomposed, with each run of letters standing alone, separated from the next by one space or punctuation
// character, joined (see the file comment's step 4).
func safetyJoinLetters(text string) string {
	characters := []rune(text)
	// the end of the letter at start with its marks, and whether it stands alone
	letterEnd := func(start int) (int, bool) {
		if !safetyLetter(characters[start]) || (0 < start && safetyWordRune(characters[start-1])) {
			return start, false
		}
		end := start + 1
		for end < len(characters) && unicode.IsMark(characters[end]) {
			end += 1
		}
		alone := end == len(characters) || !safetyWordRune(characters[end])
		return end, alone
	}
	joined := make([]rune, 0, len(characters))
	for index := 0; index < len(characters); {
		end, alone := letterEnd(index)
		if !alone {
			joined = append(joined, characters[index])
			index += 1
			continue
		}
		// the run: letters alone, each next one after exactly one separator
		letters := [][2]int{{index, end}}
		for end+1 < len(characters) && safetyJoinSeparator(characters[end]) {
			nextEnd, nextAlone := letterEnd(end + 1)
			if !nextAlone {
				break
			}
			letters = append(letters, [2]int{end + 1, nextEnd})
			end = nextEnd
		}
		if len(letters) < 2 {
			joined = append(joined, characters[index:end]...)
			index = end
			continue
		}
		for _, letter := range letters {
			joined = append(joined, characters[letter[0]:letter[1]]...)
		}
		index = end
	}
	return string(joined)
}
