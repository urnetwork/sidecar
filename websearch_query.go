//go:build !ios_extension && !sidecar_http

// The query check (DESIGN-COMPUTE §21.6's Before sending row, D-SRCH-4, §22.5; SRCH-M13-10): a search leaves for
// Parallel in plaintext, so before any byte does, its objective and each query are read for what must not leave.
//
//	secrets   the record's secret rules (DESIGN §16.7), by findRedactMatches, which the record's Redactor uses too: a
//	          match refuses the search and tells the model which kind of secret, never the value
//	personal  the record's personal-data rules, pii-email and pii-phone, read whatever the harness config's hashing
//	          says (Redactor.Scan leaves PII out, so the check calls findRedactMatches itself): the tool asks the
//	          person to confirm in a run they are attached to, and refuses otherwise
//	urls      every URL and bare host named, which a tainted run may send only where its fetches may reach them
//	          (FETCH-M13-04's FetchRunUrls: a URL listed itself, a bare host the host of a listed URL, the plan's
//	          reading); until that rule lands, every URL or host in a tainted run's query is refused
//	          unlisted_url_in_query, until G-SRCH-parallel settles whether the gateway fetches a URL it is given
//
// What the check reports names fields and rules, never the text that matched. Package-level functions are safe for
// concurrent use.

package sidecar

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The personal-data rules' ids: identifiers of record_redact_rules.go's list.
var webSearchPersonalRules = []string{"pii-email", "pii-phone"}

// A URL, or a bare host of labels ending in a letters-only top-level label.
var webSearchUrlPattern = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'\x60]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)

// One finding: the field it was in and the rule that matched.
type WebSearchQueryFinding struct {
	// objective, or queries[n].
	Field string
	Rule  string
}

// What a search's text holds that the tool must act on before it sends.
type WebSearchQueryCheck struct {
	Secrets  []*WebSearchQueryFinding
	Personal []*WebSearchQueryFinding
	// Each URL named, as written, and each bare host, lowercase.
	Urls  []string
	Hosts []string
}

// The fields of a search and their names.
func webSearchQueryFields(objective string, queries []string) ([]string, []string) {
	names := []string{"objective"}
	texts := []string{objective}
	for i, query := range queries {
		names = append(names, fmt.Sprintf("queries[%d]", i))
		texts = append(texts, query)
	}
	return names, texts
}

// The check of objective and queries (see the file header).
func CheckWebSearchQuery(objective string, queries []string) *WebSearchQueryCheck {
	check := &WebSearchQueryCheck{}
	names, texts := webSearchQueryFields(objective, queries)
	seenUrls, seenHosts := map[string]bool{}, map[string]bool{}
	for i, text := range texts {
		if text == "" {
			continue
		}
		matches, _ := findRedactMatches([]byte(text), true)
		for _, match := range matches {
			finding := &WebSearchQueryFinding{Field: names[i], Rule: match.Rule}
			personal := false
			for _, rule := range webSearchPersonalRules {
				personal = personal || rule == match.Rule
			}
			if personal {
				check.Personal = append(check.Personal, finding)
			} else {
				check.Secrets = append(check.Secrets, finding)
			}
		}
		for _, named := range webSearchUrlPattern.FindAllString(text, -1) {
			if strings.Contains(strings.ToLower(named), "://") {
				if !seenUrls[named] {
					seenUrls[named] = true
					check.Urls = append(check.Urls, named)
				}
				continue
			}
			host := strings.ToLower(named)
			if !seenHosts[host] {
				seenHosts[host] = true
				check.Hosts = append(check.Hosts, host)
			}
		}
	}
	return check
}

// The URLs and hosts a tainted run may name in a search: FETCH-M13-04's FetchRunUrls. Safe for concurrent use.
type WebSearchRunUrls interface {
	// Whether runId's fetches may reach rawUrl: listed itself.
	UrlListed(runId Id, rawUrl string) bool
	// Whether host is the host of a URL listed for runId.
	HostListed(runId Id, host string) bool
	// The search's results' URLs, runId's latest search results (§22.5).
	AddSearchResults(runId Id, urls []string)
}

// The first URL or host of check a tainted run runId may not name, and true; false where every one is listed. With no
// list (urls nil), every one is refused.
func (self *WebSearchQueryCheck) unlisted(urls WebSearchRunUrls, runId Id) (string, bool) {
	for _, named := range self.Urls {
		if urls == nil || !urls.UrlListed(runId, named) {
			parsed, err := url.Parse(named)
			if err == nil && parsed.Hostname() != "" {
				return parsed.Hostname(), true
			}
			return "a URL", true
		}
	}
	for _, host := range self.Hosts {
		if urls == nil || !urls.HostListed(runId, host) {
			return host, true
		}
	}
	return "", false
}

// The kind of what a finding matched, as the model and the person are told it.
func webSearchRuleKind(rule string) string {
	switch rule {
	case "pii-email":
		return "an email address"
	case "pii-phone":
		return "a phone number"
	}
	return "a secret (" + rule + ")"
}
