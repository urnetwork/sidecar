// What ur search and ur agents print (§16.10's CLI block: format, explain and exit rows, and the cli row's control
// characters; SEARCH-M10-30).
//
//	text   a line a hit: its time, its network and repo, = confirmed, ~ possible or ? near, its kind, its display
//	       fields (subject, from, to, title, then the class's registered names in name order), its path where the hit
//	       opens as a file, and its snippet; a stub's text reads [untrusted: withheld]; group headers above their
//	       hits; then one coverage line: repos searched and excluded with each reason, the counts, and complete or
//	       partial with why
//	json   the MCP result as the daemon answered it, one document
//	jsonl  a line a hit as each page lands, then one summary line {counts, coverage, status}
//	ids    a hit reference a line: <repo_id>:<path>@<version> for a file, else <repo_id>:<doc type>/<doc key>@<version>
//
// Text and ids output drops C0 and C1 controls and bidi overrides, embeddings, isolates and marks, so a hit's text
// cannot move the cursor, rewrite a line or reorder what a terminal shows (Trojan Source); json and jsonl keep every
// character, writing those as \u escapes, which no terminal acts on.
//
// Exit codes, as grep's: 0 a hit, 1 none, 2 an error, 3 partial (the wait elapsed, the query too broad, or a coverage
// gap: a ref whose index is not built, a receipt that did not land, or an index this build cannot read).

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar"
)

// ur search's exit codes beyond ur's own.
const (
	urSearchExitNone    = 1
	urSearchExitError   = 2
	urSearchExitPartial = 3
)

// The formats ur search prints.
const (
	urSearchFormatText  = "text"
	urSearchFormatJson  = "json"
	urSearchFormatJsonl = "jsonl"
	urSearchFormatIds   = "ids"
)

// The exclusion reasons that are coverage gaps, which make a search partial, rather than the scope's own rules.
var urSearchGapReasons = []string{sidecar.SearchExcludedUnbuilt, sidecar.SearchExcludedReceipt, sidecar.SearchExcludedUpdate}

// Whether r is a control or a bidi control a terminal acts on: C0 (U+0000-U+001F), DEL, C1 (U+0080-U+009F), the
// embeddings and overrides U+202A-U+202E, the isolates U+2066-U+2069, and the marks U+200E, U+200F and U+061C.
func urSearchUnsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, 0x80 <= r && r <= 0x9f:
		return true
	case 0x202a <= r && r <= 0x202e, 0x2066 <= r && r <= 0x2069:
		return true
	case r == 0x200e, r == 0x200f, r == 0x061c:
		return true
	}
	return false
}

// text with every unsafe rune dropped and invalid UTF-8 as U+FFFD, one line.
func urSearchSafe(text string) string {
	var builder strings.Builder
	for _, r := range text {
		if r == utf8.RuneError || !urSearchUnsafeRune(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// JSON of value with every unsafe rune that encoding/json leaves as it is written as a \u escape, then a newline.
func urSearchJson(value any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	escaped := &bytes.Buffer{}
	for _, r := range buffer.String() {
		// encoding/json escapes C0 within strings itself; C1 and the bidi controls stay as they are
		if r != '\n' && urSearchUnsafeRune(r) {
			fmt.Fprintf(escaped, "\\u%04x", r)
			continue
		}
		escaped.WriteRune(r)
	}
	return escaped.Bytes(), nil
}

// The mark a hit's match takes.
func urSearchMark(match string) string {
	switch match {
	case "confirmed":
		return "="
	case "near":
		return "?"
	}
	return "~"
}

// The display fields of a hit, in their order: the header fields, then the rest in name order.
func urSearchFieldOrder(fields map[string]string) []string {
	order := []string{}
	for _, name := range []string{"subject", "from", "to", "title"} {
		if _, ok := fields[name]; ok {
			order = append(order, name)
		}
	}
	rest := []string{}
	for name := range fields {
		if !slices.Contains(order, name) {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)
	return append(order, rest...)
}

// The path a hit opens at, where it opens as a file.
func urSearchHitPath(hit *sidecar.SearchToolHit) string {
	if hit.Open == nil {
		return ""
	}
	if path, ok := hit.Open.Arguments["path"].(string); ok {
		return path
	}
	return ""
}

// One hit as a text line.
func urSearchTextLine(hit *sidecar.SearchToolHit) string {
	parts := []string{hit.Time, hit.Network + "/" + hit.RepoId, urSearchMark(hit.Match)}
	if hit.Kind != "" {
		parts = append(parts, hit.Kind)
	} else {
		parts = append(parts, hit.Doc.Type)
	}
	if hit.Stub {
		parts = append(parts, "[untrusted: withheld]")
	} else {
		for _, name := range urSearchFieldOrder(hit.Fields) {
			parts = append(parts, name+": "+hit.Fields[name])
		}
		if path := urSearchHitPath(hit); path != "" {
			parts = append(parts, path)
		}
		if hit.Snippet != "" {
			parts = append(parts, "| "+hit.Snippet)
		}
	}
	return urSearchSafe(strings.Join(parts, "  "))
}

// One hit as an ids line.
func urSearchIdLine(hit *sidecar.SearchToolHit) string {
	if path := urSearchHitPath(hit); path != "" {
		return urSearchSafe(fmt.Sprintf("%s:%s@%d", hit.RepoId, path, hit.Version))
	}
	return urSearchSafe(fmt.Sprintf("%s:%s/%s@%d", hit.RepoId, hit.Doc.Type, hit.Doc.Key, hit.Version))
}

// A group's header line.
func urSearchGroupLine(group *sidecar.SearchToolGroup) string {
	label := group.Key
	if group.AgentLabel != "" {
		label = group.AgentLabel
	}
	where := []string{}
	if group.Device != "" {
		where = append(where, "on "+group.Device)
	}
	if group.Member != "" {
		where = append(where, "("+group.Member+")")
	}
	state := "idle"
	if group.Active {
		state = "active"
	}
	if group.Stub {
		label += " [untrusted: withheld]"
	}
	line := "## " + label
	if 0 < len(where) {
		line += " " + strings.Join(where, " ")
	}
	line += fmt.Sprintf(", %s, %d hits", state, group.HitCount)
	if group.LastActivity != "" {
		line += ", last " + group.LastActivity
	}
	return urSearchSafe(line)
}

// Why a result is partial, empty where it is not: the wait elapsed, too broad, or a coverage gap.
func urSearchPartialReasons(result *sidecar.SearchToolResult) []string {
	reasons := []string{}
	if !result.Status.Complete {
		reasons = append(reasons, "the wait elapsed")
	}
	if result.Status.TooBroad {
		reasons = append(reasons, "the query is too broad")
	}
	for _, coverage := range result.Coverage {
		if slices.Contains(urSearchGapReasons, coverage.State) {
			reasons = append(reasons, "a coverage gap")
			break
		}
	}
	return reasons
}

// The coverage line.
func urSearchCoverageLine(result *sidecar.SearchToolResult) string {
	searched := map[string]bool{}
	reasons := map[string]int{}
	for _, coverage := range result.Coverage {
		if coverage.State == "searched" {
			searched[coverage.RepoId] = true
			continue
		}
		reasons[coverage.State] += 1
	}
	line := fmt.Sprintf("-- searched %d repos", len(searched))
	if 0 < len(reasons) {
		names := []string{}
		for reason, count := range reasons {
			names = append(names, fmt.Sprintf("%s %d", reason, count))
		}
		slices.Sort(names)
		line += " (left out: " + strings.Join(names, ", ") + ")"
	}
	counts := result.Counts
	line += fmt.Sprintf("; %d confirmed, %d possible, %d near, %d untrusted withheld, %d masked", counts.Confirmed, counts.Possible, counts.Near, counts.UntrustedWithheld, counts.Masked)
	if partial := urSearchPartialReasons(result); 0 < len(partial) {
		line += "; partial: " + strings.Join(partial, ", ")
	} else {
		line += "; complete"
	}
	return urSearchSafe(line)
}

// Writes result in format. jsonl writes the hits alone; its summary is urSearchWriteSummary's.
func urSearchWrite(out io.Writer, format string, result *sidecar.SearchToolResult) error {
	switch format {
	case urSearchFormatJson:
		encoded, err := urSearchJson(result)
		if err != nil {
			return err
		}
		_, err = out.Write(encoded)
		return err
	case urSearchFormatJsonl:
		for _, hit := range result.Hits {
			encoded, err := urSearchJson(hit)
			if err != nil {
				return err
			}
			if _, err := out.Write(encoded); err != nil {
				return err
			}
		}
		return nil
	case urSearchFormatIds:
		for _, hit := range result.Hits {
			fmt.Fprintln(out, urSearchIdLine(hit))
		}
		return nil
	}
	shown := map[string]bool{}
	for _, group := range result.Groups {
		fmt.Fprintln(out, urSearchGroupLine(group))
		for _, hit := range group.Top {
			shown[hit.HitId] = true
			fmt.Fprintln(out, urSearchTextLine(hit))
		}
	}
	for _, hit := range result.Hits {
		if !shown[hit.HitId] {
			fmt.Fprintln(out, urSearchTextLine(hit))
		}
	}
	fmt.Fprintln(out, urSearchCoverageLine(result))
	return nil
}

// jsonl's summary line.
type urSearchSummary struct {
	Summary  bool                          `json:"summary"`
	Counts   sidecar.SearchToolCounts      `json:"counts"`
	Coverage []*sidecar.SearchToolCoverage `json:"coverage"`
	Status   sidecar.SearchToolStatus      `json:"status"`
}

// Writes jsonl's summary line.
func urSearchWriteSummary(out io.Writer, result *sidecar.SearchToolResult) error {
	encoded, err := urSearchJson(&urSearchSummary{Summary: true, Counts: result.Counts, Coverage: result.Coverage, Status: result.Status})
	if err != nil {
		return err
	}
	_, err = out.Write(encoded)
	return err
}

// What a search exits with, its last page result and shownCount the hits and groups its pages printed: 3 where it is
// partial, 0 with a hit or a group, 1 with none.
func urSearchExit(result *sidecar.SearchToolResult, shownCount int) error {
	if partial := urSearchPartialReasons(result); 0 < len(partial) {
		return &urExitError{code: urSearchExitPartial, err: errors.New("partial: " + strings.Join(partial, ", "))}
	}
	if shownCount == 0 {
		return &urExitError{code: urSearchExitNone, err: errors.New("no match")}
	}
	return nil
}

// An error as ur search exits with it: 2, as grep's, whatever ur's own code would be.
func urSearchError(err error) error {
	if err == nil {
		return nil
	}
	var exit *urExitError
	if errors.As(err, &exit) {
		return err
	}
	return &urExitError{code: urSearchExitError, err: err}
}
