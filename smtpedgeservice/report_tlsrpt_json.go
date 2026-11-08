// TLS-RPT aggregate reports' JSON (RFC 8460), for §15's inbound policy: each policy's type, domain and
// session totals are kept, and the failure details, which name sending MTAs' addresses, are skipped
// unread into no field. Nesting is held to ReportNestingDepth by a scan before decoding, so the
// decoder never descends past it.

package smtpedgeservice

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RFC 8460 §4.3's policy types.
var smtpTlsRptPolicyTypes = map[string]bool{"sts": true, "tlsa": true, "no-policy-found": true}

// The fields of a TLS-RPT report this parser keeps; the rest are skipped by the decoder.
type smtpTlsRptReport struct {
	ReportId  string `json:"report-id"`
	DateRange struct {
		Start string `json:"start-datetime"`
		End   string `json:"end-datetime"`
	} `json:"date-range"`
	Policies []struct {
		Policy struct {
			PolicyType   string `json:"policy-type"`
			PolicyDomain string `json:"policy-domain"`
		} `json:"policy"`
		Summary struct {
			SuccessCount uint64 `json:"total-successful-session-count"`
			FailureCount uint64 `json:"total-failure-session-count"`
		} `json:"summary"`
	} `json:"policies"`
}

// The deepest nesting of objects and arrays in data, read outside strings.
func smtpJsonDepth(data []byte) int {
	depth := 0
	deepest := 0
	inString := false
	escaped := false
	for _, c := range data {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			depth += 1
			deepest = max(deepest, depth)
		case c == '}' || c == ']':
			depth -= 1
		}
	}
	return deepest
}

// The policies of a TLS-RPT report, refusing what §14.8's bounds refuse.
func parseSmtpTlsRptJson(data []byte, settings *SmtpEdgeSettings) (*SmtpAggregateRows, error) {
	if settings.ReportNestingDepth < smtpJsonDepth(data) {
		return nil, fmt.Errorf("%w: JSON nesting past the bound", ErrSmtpReportRefused)
	}
	var report smtpTlsRptReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("%w: JSON that does not parse as TLS-RPT", ErrSmtpReportRefused)
	}
	reportId := strings.TrimSpace(report.ReportId)
	if reportId == "" || smtpAggregateValueMaxByteCount < len(reportId) {
		return nil, fmt.Errorf("%w: a report with no usable report-id", ErrSmtpReportRefused)
	}
	rows := &SmtpAggregateRows{Kind: SmtpAggregateKindTlsRpt, ReportId: reportId}
	if begin, err := time.Parse(time.RFC3339, report.DateRange.Start); err == nil {
		rows.Begin = begin.UTC()
	}
	if end, err := time.Parse(time.RFC3339, report.DateRange.End); err == nil {
		rows.End = end.UTC()
	}
	for _, policy := range report.Policies {
		policyType := strings.ToLower(strings.TrimSpace(policy.Policy.PolicyType))
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(policy.Policy.PolicyDomain)), ".")
		if !smtpTlsRptPolicyTypes[policyType] || !smtpLdhName(domain) {
			rows.DroppedRowCount += 1
			continue
		}
		rows.Rows = append(rows.Rows, &SmtpAggregateRow{
			Domain:       domain,
			PolicyType:   policyType,
			SuccessCount: policy.Summary.SuccessCount,
			FailureCount: policy.Summary.FailureCount,
		})
	}
	return rows, nil
}
