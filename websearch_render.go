//go:build !ios_extension && !sidecar_http

// What a served search becomes (DESIGN-COMPUTE §21.6's To the model, To the UI and Recorded rows, D-SRCH-7, CO-26,
// Q-SRCH-9; SRCH-M13-10):
//
//	model    between the untrusted-data markers, from a whitelist: "[n] title — url (publish_date)" and the result's
//	         excerpts, each result's excerpts cut at ResultExcerptMaxCharacterCount and the whole at
//	         ExcerptTotalMaxCharacterCount; the warnings as one line; never search_id, session_id or usage; every
//	         control character stripped, a line's newlines too, an excerpt's kept as newlines
//	details  kind web_search and keep: false, which the Harness holds in memory only and an app shows until a reload:
//	         the objective, the queries and the mode, each result's title, URL, site, date and first excerpt, the price
//	         and the transaction hash as text (never a link to an explorer), and the disclosure's id, version and
//	         one-line summary, read from the newest verified policy alone
//	stub     what the record, the session entries and the apps' storage keep in place of the results and details: the
//	         call (objective, queries, mode), the number of results, the SHA-256 of the gateway's answer, the
//	         payment's nonce and transaction, the price, and the text "[web_search: n results; not kept]"
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The sender the untrusted-data markers name, and the details' kind: identifiers.
const (
	webSearchUntrustedSender = "Parallel web search"
	webSearchDetailsKind     = "web_search"
)

// text on one line: every control character, line and paragraph separator a space, runs of spaces kept.
func webSearchCleanLine(text string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 || r == utf8.RuneError {
			return ' '
		}
		return r
	}, text))
}

// text with every control character stripped but newlines, and separators read as newlines.
func webSearchCleanText(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == 0x2028 || r == 0x2029:
			return '\n'
		case unicode.IsControl(r) || r == utf8.RuneError:
			return -1
		}
		return r
	}, text)
}

// text cut to at most count characters.
func webSearchCut(text string, count int) string {
	if count <= 0 {
		return ""
	}
	if utf8.RuneCountInString(text) <= count {
		return text
	}
	runes := []rune(text)
	return string(runes[:count])
}

// The text the model reads of answer, fenced (see the file header's model row).
func WebSearchRenderText(answer *WebSearchAnswer, settings *WebSearchSettings) string {
	builder := strings.Builder{}
	left := settings.ExcerptTotalMaxCharacterCount
	take := func(text string) {
		text = webSearchCut(text, left)
		left -= utf8.RuneCountInString(text)
		builder.WriteString(text)
	}
	if len(answer.Results) == 0 {
		take("No results.\n")
	}
	for i, result := range answer.Results {
		if left <= 0 {
			break
		}
		heading := fmt.Sprintf("[%d] %s — %s", i+1, webSearchCleanLine(result.Title), webSearchCleanLine(result.Url))
		if date := webSearchCleanLine(result.PublishDate); date != "" {
			heading += " (" + date + ")"
		}
		take(heading + "\n")
		excerpts := []string{}
		for _, excerpt := range result.Excerpts {
			excerpts = append(excerpts, strings.TrimSpace(webSearchCleanText(excerpt)))
		}
		excerpt := webSearchCut(strings.Join(excerpts, "\n"), settings.ResultExcerptMaxCharacterCount)
		if excerpt != "" {
			take(excerpt + "\n")
		}
		take("\n")
	}
	if 0 < len(answer.Warnings) && 0 < left {
		warnings := []string{}
		for _, warning := range answer.Warnings {
			warnings = append(warnings, webSearchCleanLine(warning))
		}
		take("Warnings: " + strings.Join(warnings, "; ") + "\n")
	}
	return HarnessUntrustedText(webSearchUntrustedSender, strings.TrimRight(builder.String(), "\n"))
}

// One result as the UI shows it.
type WebSearchDetailsResult struct {
	Title   string `json:"title"`
	Url     string `json:"url"`
	Site    string `json:"site"`
	Date    string `json:"date,omitempty"`
	Excerpt string `json:"excerpt,omitempty"`
}

// The disclosure a search's card shows, from the newest verified policy.
type WebSearchDetailsDisclosure struct {
	Id      string `json:"id"`
	Version uint32 `json:"version"`
	Summary string `json:"summary"`
}

// The details the UI shows of a search (see the file header's details row). Never kept.
type WebSearchDetails struct {
	Kind         string                      `json:"kind"`
	Keep         bool                        `json:"keep"`
	Objective    string                      `json:"objective,omitempty"`
	Queries      []string                    `json:"queries"`
	Mode         string                      `json:"mode"`
	Results      []*WebSearchDetailsResult   `json:"results"`
	PriceNanoUsd int64                       `json:"price_nano_usd"`
	Transaction  string                      `json:"transaction,omitempty"`
	Disclosure   *WebSearchDetailsDisclosure `json:"disclosure,omitempty"`
}

// The details of a search of objective, queries and mode that answered answer, with its disclosure's line.
func NewWebSearchDetails(objective string, queries []string, answer *WebSearchAnswer, disclosure *WebSearchDetailsDisclosure, settings *WebSearchSettings) *WebSearchDetails {
	details := &WebSearchDetails{
		Kind:         webSearchDetailsKind,
		Keep:         false,
		Objective:    objective,
		Queries:      append([]string{}, queries...),
		Mode:         answer.Mode,
		Results:      []*WebSearchDetailsResult{},
		PriceNanoUsd: answer.PriceNanoUsd,
		Disclosure:   disclosure,
	}
	if 0 < len(answer.Transaction) {
		details.Transaction = "0x" + hex.EncodeToString(answer.Transaction)
	}
	for _, result := range answer.Results {
		shown := &WebSearchDetailsResult{
			Title: webSearchCleanLine(result.Title),
			Url:   webSearchCleanLine(result.Url),
			Date:  webSearchCleanLine(result.PublishDate),
		}
		if parsed, err := url.Parse(result.Url); err == nil {
			shown.Site = parsed.Hostname()
		}
		if 0 < len(result.Excerpts) {
			shown.Excerpt = webSearchCut(strings.TrimSpace(webSearchCleanText(result.Excerpts[0])), settings.DetailsExcerptMaxCharacterCount)
		}
		details.Results = append(details.Results, shown)
	}
	return details
}

// The call a stub keeps.
type WebSearchStubCall struct {
	Objective string   `json:"objective,omitempty"`
	Queries   []string `json:"queries"`
	Mode      string   `json:"mode"`
}

// What the record keeps of a search (see the file header's stub row).
type WebSearchStub struct {
	Call         *WebSearchStubCall `json:"call"`
	Results      int                `json:"results"`
	AnswerSha256 string             `json:"answer_sha256"`
	Nonce        string             `json:"nonce"`
	Transaction  string             `json:"transaction,omitempty"`
	PriceNanoUsd int64              `json:"price_nano_usd"`
	Text         string             `json:"text"`
}

// The stub of a search of objective, queries and mode that answered answer.
func NewWebSearchStub(objective string, queries []string, answer *WebSearchAnswer) *WebSearchStub {
	stub := &WebSearchStub{
		Call:         &WebSearchStubCall{Objective: objective, Queries: append([]string{}, queries...), Mode: answer.Mode},
		Results:      len(answer.Results),
		AnswerSha256: hex.EncodeToString(answer.AnswerSha256[:]),
		Nonce:        hex.EncodeToString(answer.Nonce),
		PriceNanoUsd: answer.PriceNanoUsd,
	}
	if 0 < len(answer.Transaction) {
		stub.Transaction = hex.EncodeToString(answer.Transaction)
	}
	stub.Text = WebSearchStubText(stub.Results)
	return stub
}

// The text a stub's result reads (§21.6).
func WebSearchStubText(results int) string {
	return fmt.Sprintf("[web_search: %d results; not kept]", results)
}

// The stub as the journal takes it.
func (self *WebSearchStub) Json() ([]byte, error) {
	return json.Marshal(self)
}
