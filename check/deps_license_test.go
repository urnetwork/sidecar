//go:build sidecar_check

// A license file's words, and the texts of §4.7's licenses they are read against. A file passes under
// its row only when every word in it is one of the row's licenses' own words, in that license's
// order, or one of the module's notes (checkSettings.licenseNotes). So a familiar license with any
// clause added is the custom license §4.7 refuses, however the clause is worded: BSD-4-Clause's
// advertising clause under a BSD-3-Clause row, or a use restriction beside MIT's text. A list of
// refused phrases could only catch the clauses someone thought of.
//
// The comparison follows SPDX's matching guidelines where copies of one license differ: case,
// punctuation, whitespace, list markers, copyright notices and the parts a license leaves to each
// copy, such as its holder's name.

package check

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// §4.7's licenses' texts, a directory for each SPDX id. text.txt is the license itself; notice.txt
// the notice a file may carry in its place, such as Apache-2.0's header or MPL-2.0's Exhibit A; and
// excerpt-*.txt a part of the license a module may quote on its own. A text or a notice shows a module
// is under its id, and an excerpt only covers the words it quotes. In each, <<...>> stands for the
// words a license leaves to each copy, such as its holder's name, and what it says inside is not read;
// [[...]] is a part a copy may leave out, such as a heading or a list marker, and may nest.
// TestEveryAllowedLicenseHasItsText holds the directories to §4.7's list.
const licenseTextsDirectory = "testdata/licenses"

// One word of a license's text, a part left to each copy, or a part a copy may leave out.
type licenseTemplateItem struct {
	word     string
	variable bool
	optional []licenseTemplateItem
}

// One of §4.7's licenses' texts, or a module's note.
type licenseText struct {
	id string
	// text, notice, excerpt-..., or note
	name string
	// true for a text or a notice, which show that a module is under id
	backs bool
	items []licenseTemplateItem
}

// A copyright notice's line, which each copy writes for itself: Copyright with a year, (c) or ©, or
// (c) with a year. Copyright with any other word after it is the license's own, as in "copyright
// license" or "copyright notice".
var copyrightNoticePattern = regexp.MustCompile(`(?i)^\W*(copyright|\(c\)|©)\s*(\(c\)|©|[0-9]{4})`)

// A word that a hyphen breaks across a line, and a hyphenated word, which copies spell either way.
var (
	hyphenBreakPattern = regexp.MustCompile(`(\pL)-[ \t]*\r?\n\s*(\pL)`)
	hyphenPattern      = regexp.MustCompile(`([\pL\pN])-([\pL\pN])`)
)

// A text's words, as license files and §4.7's texts are compared: lowercased runs of letters and
// digits, with copyright notices and "all rights reserved" left out, hyphenated words joined, and
// https read as http.
func licenseWords(text string) []string {
	keptLines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if !copyrightNoticePattern.MatchString(line) {
			keptLines = append(keptLines, line)
		}
	}
	joined := strings.ToLower(strings.Join(keptLines, "\n"))
	joined = hyphenBreakPattern.ReplaceAllString(joined, "$1$2")
	// a word of several hyphens needs a pass for each, since one pass's matches cannot overlap
	for {
		next := hyphenPattern.ReplaceAllString(joined, "$1$2")
		if next == joined {
			break
		}
		joined = next
	}
	fields := strings.FieldsFunc(joined, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	words := make([]string, 0, len(fields))
	for index := 0; index < len(fields); index++ {
		if index+2 < len(fields) && fields[index] == "all" && fields[index+1] == "rights" && fields[index+2] == "reserved" {
			index += 2
			continue
		}
		if fields[index] == "https" {
			words = append(words, "http")
			continue
		}
		words = append(words, fields[index])
	}
	return words
}

// A license's text as items, its <<...>> and [[...]] marks read. A <<...>> part ends at the word
// after it, so one with no word after it, last in the text or in a [[...]] part, is refused: it could
// only end at an arbitrary count, which would let it take an added clause's first words.
func parseLicenseTemplate(text string) ([]licenseTemplateItem, error) {
	items, rest, err := parseLicenseTemplateUntil(text, false)
	if err != nil {
		return nil, err
	}
	if rest != "" {
		return nil, errors.New("a ]] closes no [[")
	}
	var unended func(items []licenseTemplateItem) bool
	unended = func(items []licenseTemplateItem) bool {
		for index, item := range items {
			if item.variable && (index+1 == len(items) || items[index+1].word == "") {
				return true
			}
			if item.optional != nil && unended(item.optional) {
				return true
			}
		}
		return false
	}
	if unended(items) {
		return nil, errors.New("a <<...>> part has no word after it to end it")
	}
	return items, nil
}

// Items up to the ]] that closes an open [[, when one is open, and what follows it.
func parseLicenseTemplateUntil(text string, open bool) ([]licenseTemplateItem, string, error) {
	items := []licenseTemplateItem{}
	for {
		next := len(text)
		for _, mark := range []string{"<<", "[[", "]]"} {
			if index := strings.Index(text, mark); index >= 0 && index < next {
				next = index
			}
		}
		for _, word := range licenseWords(text[:next]) {
			items = append(items, licenseTemplateItem{word: word})
		}
		if next == len(text) {
			if open {
				return nil, "", errors.New("a [[ is never closed")
			}
			return items, "", nil
		}
		switch text[next : next+2] {
		case "<<":
			end := strings.Index(text[next:], ">>")
			if end < 0 {
				return nil, "", errors.New("a << is never closed")
			}
			items = append(items, licenseTemplateItem{variable: true})
			text = text[next+end+2:]
		case "[[":
			inner, rest, err := parseLicenseTemplateUntil(text[next+2:], true)
			if err != nil {
				return nil, "", err
			}
			items = append(items, licenseTemplateItem{optional: inner})
			text = rest
		case "]]":
			if !open {
				return items, text[next:], nil
			}
			return items, text[next+2:], nil
		}
	}
}

// True for a word of digits alone, which a text may use to number its clauses.
func isNumberWord(word string) bool {
	return word != "" && strings.IndexFunc(word, func(r rune) bool { return !unicode.IsDigit(r) }) < 0
}

// Matches items against words from at, and returns where the match ends. A number the items do not
// expect is a list marker and is passed over, since copies number their clauses or do not; a number
// the items name must be there. A variable part takes one to licenseVariableMaxWordCount words, the
// fewest that let the rest match.
func (self *checkSettings) matchLicenseItems(items []licenseTemplateItem, words []string, at int) (int, bool) {
	if len(items) == 0 {
		return at, true
	}
	first := items[0]
	switch {
	case first.optional != nil:
		if end, ok := self.matchLicenseItems(first.optional, words, at); ok && end > at {
			if final, ok := self.matchLicenseItems(items[1:], words, end); ok {
				return final, true
			}
		}
		return self.matchLicenseItems(items[1:], words, at)
	case first.variable:
		for count := 1; count <= self.licenseVariableMaxWordCount && at+count <= len(words); count++ {
			if final, ok := self.matchLicenseItems(items[1:], words, at+count); ok {
				return final, true
			}
		}
		return 0, false
	default:
		for at < len(words) && words[at] != first.word && isNumberWord(words[at]) {
			at += 1
		}
		if at < len(words) && words[at] == first.word {
			return self.matchLicenseItems(items[1:], words, at+1)
		}
		return 0, false
	}
}

// Marks covered every word that an occurrence of one of the texts covers, and returns the ids that a
// text or notice among them showed.
func (self *checkSettings) coverLicenseWords(words []string, covered []bool, texts []*licenseText) map[string]bool {
	shownIds := map[string]bool{}
	for _, text := range texts {
		for start := 0; start < len(words); start++ {
			end, ok := self.matchLicenseItems(text.items, words, start)
			if !ok || end == start {
				continue
			}
			for index := start; index < end; index++ {
				covered[index] = true
			}
			if text.backs {
				shownIds[text.id] = true
			}
			start = end - 1
		}
	}
	return shownIds
}

// How far items reach into words from at before they stop matching, for a finding: a variable part
// runs to the next word the items name, and a part a copy may leave out is taken when it matches.
func (self *checkSettings) reachLicenseItems(items []licenseTemplateItem, words []string, at int) int {
	for index, item := range items {
		switch {
		case item.optional != nil:
			if end, ok := self.matchLicenseItems(item.optional, words, at); ok {
				at = end
			}
		case item.variable:
			at += 1
			if index+1 < len(items) && items[index+1].word != "" {
				for count := 0; count < self.licenseVariableMaxWordCount && at < len(words) && words[at] != items[index+1].word; count++ {
					at += 1
				}
			}
		default:
			for at < len(words) && words[at] != item.word && isNumberWord(words[at]) {
				at += 1
			}
			if at >= len(words) || words[at] != item.word {
				return at
			}
			at += 1
		}
	}
	return at
}

// Where a file's words first leave every text that could cover them, for a finding: the words from
// the first one no text covers, or from as far as one text reaches into them from there, or the end
// of the file when a text goes on past it.
func (self *checkSettings) licenseDeparture(words []string, covered []bool, texts []*licenseText) string {
	first := slices.Index(covered, false)
	if first < 0 {
		return "nowhere"
	}
	departure := first
	for _, text := range texts {
		departure = max(departure, self.reachLicenseItems(text.items, words, first))
	}
	if departure >= len(words) {
		return "the end of the file"
	}
	return fmt.Sprintf("%q", strings.Join(words[departure:min(departure+self.licenseDepartureWordCount, len(words))], " "))
}

// §4.7's licenses' texts by id, read once from licenseTextsDirectory, which go test runs beside.
var licenseTexts = sync.OnceValues(func() (map[string][]*licenseText, error) {
	idEntries, err := os.ReadDir(licenseTextsDirectory)
	if err != nil {
		return nil, err
	}
	texts := map[string][]*licenseText{}
	for _, idEntry := range idEntries {
		if !idEntry.IsDir() {
			return nil, fmt.Errorf("%s holds %s, which is no license's directory", licenseTextsDirectory, idEntry.Name())
		}
		id := idEntry.Name()
		entries, err := os.ReadDir(filepath.Join(licenseTextsDirectory, id))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name, isText := strings.CutSuffix(entry.Name(), ".txt")
			if !isText || !(name == "text" || name == "notice" || strings.HasPrefix(name, "excerpt-")) {
				return nil, fmt.Errorf("%s/%s is no text, notice or excerpt", id, entry.Name())
			}
			data, err := os.ReadFile(filepath.Join(licenseTextsDirectory, id, entry.Name()))
			if err != nil {
				return nil, err
			}
			items, err := parseLicenseTemplate(string(data))
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", id, entry.Name(), err)
			}
			texts[id] = append(texts[id], &licenseText{id: id, name: name, backs: name == "text" || name == "notice", items: items})
		}
	}
	return texts, nil
})
