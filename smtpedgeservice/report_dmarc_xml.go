// DMARC aggregate reports' XML (RFC 9990, and RFC 7489's appendix C before it), machine data rather
// than user content (D-SMTP-23). Parsed with encoding/xml in strict mode and no entity map, after a
// scan that refuses any DOCTYPE or ENTITY declaration outright, so no DTD and no external entity is
// ever read; any other directive is refused as it is met. Nesting is held to ReportNestingDepth, and
// each kept value to smtpAggregateValueMaxByteCount. Elements are matched by local name, so RFC 9990's
// namespace and RFC 7489's lack of one parse alike.
//
// Rows whose source_ip is not a sending address are dropped here, at parse: third-party IPs are never
// stored (§2.8 smtp-5), and only URnetwork's own sends are counted.

package smtpedgeservice

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// The longest value an aggregate field may hold: every field kept is an identifier, a name, a word or
// a number, and RFC 1035 bounds a name at 253 octets.
const smtpAggregateValueMaxByteCount = 1024

// What an aggregate report says of URnetwork's sends.
type SmtpAggregateRows struct {
	// SmtpAggregateKind*.
	Kind string
	// As the reporter wrote it.
	ReportId string
	// The range the report covers. Zero when it gives none that parses.
	Begin time.Time
	End   time.Time
	// The rows kept.
	Rows []*SmtpAggregateRow
	// DMARC rows dropped for a source IP outside the sending set.
	DroppedRowCount int
}

// One row kept: a DMARC record from a sending address, or a TLS-RPT policy.
type SmtpAggregateRow struct {
	// DMARC: identifiers' header_from. TLS-RPT: the policy domain. Lowercased.
	Domain string
	// DMARC's count.
	MessageCount uint64
	// policy_evaluated's disposition, dkim and spf.
	Disposition string
	DkimAligned string
	SpfAligned  string
	// auth_results' first dkim, and its spf result.
	DkimDomain   string
	DkimSelector string
	DkimResult   string
	SpfResult    string
	// TLS-RPT: sts, tlsa or no-policy-found, and the session totals.
	PolicyType   string
	SuccessCount uint64
	FailureCount uint64
}

// Whether data declares a DTD or an entity, in any case.
func smtpXmlDeclaresDtd(data []byte) bool {
	upper := bytes.ToUpper(data)
	return bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY"))
}

// One record's values as they are met.
type smtpDmarcRecord struct {
	sourceIp     string
	count        string
	disposition  string
	dkimAligned  string
	spfAligned   string
	headerFrom   string
	dkimDomain   string
	dkimSelector string
	dkimResult   string
	spfResult    string
	// Whether the first auth_results dkim and spf have closed, so later ones are skipped.
	dkimClosed bool
	spfClosed  bool
}

// The rows of a DMARC aggregate report, refusing what §14.8's bounds refuse.
func parseSmtpDmarcXml(data []byte, settings *SmtpEdgeSettings) (*SmtpAggregateRows, error) {
	if smtpXmlDeclaresDtd(data) {
		return nil, fmt.Errorf("%w: a report that declares a DTD or entity", ErrSmtpReportRefused)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	// no entity map: only XML's five predefined entities, and an unknown one fails
	decoder.Entity = nil
	rows := &SmtpAggregateRows{Kind: SmtpAggregateKindDmarc}
	path := []string{}
	var record *smtpDmarcRecord
	var begin, end string
	// the value of the element now open, when it is one this parser keeps
	var value *string
	finishRecord := func() {
		address, err := netip.ParseAddr(strings.TrimSpace(record.sourceIp))
		if err != nil || !settings.isSendingAddress(address) {
			rows.DroppedRowCount += 1
			return
		}
		count, err := strconv.ParseUint(strings.TrimSpace(record.count), 10, 64)
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.headerFrom)), ".")
		if err != nil || !smtpLdhName(domain) {
			rows.DroppedRowCount += 1
			return
		}
		rows.Rows = append(rows.Rows, &SmtpAggregateRow{
			Domain:       domain,
			MessageCount: count,
			Disposition:  strings.ToLower(strings.TrimSpace(record.disposition)),
			DkimAligned:  strings.ToLower(strings.TrimSpace(record.dkimAligned)),
			SpfAligned:   strings.ToLower(strings.TrimSpace(record.spfAligned)),
			DkimDomain:   strings.ToLower(strings.TrimSpace(record.dkimDomain)),
			DkimSelector: strings.ToLower(strings.TrimSpace(record.dkimSelector)),
			DkimResult:   strings.ToLower(strings.TrimSpace(record.dkimResult)),
			SpfResult:    strings.ToLower(strings.TrimSpace(record.spfResult)),
		})
	}
	// the field a path names, inside a record or the metadata. A path joins its local names with ">"
	target := func() *string {
		joined := strings.Join(path, ">")
		switch joined {
		case "feedback>report_metadata>report_id":
			return &rows.ReportId
		case "feedback>report_metadata>date_range>begin":
			return &begin
		case "feedback>report_metadata>date_range>end":
			return &end
		}
		if record == nil {
			return nil
		}
		switch joined {
		case "feedback>record>row>source_ip":
			return &record.sourceIp
		case "feedback>record>row>count":
			return &record.count
		case "feedback>record>row>policy_evaluated>disposition":
			return &record.disposition
		case "feedback>record>row>policy_evaluated>dkim":
			return &record.dkimAligned
		case "feedback>record>row>policy_evaluated>spf":
			return &record.spfAligned
		case "feedback>record>identifiers>header_from":
			return &record.headerFrom
		}
		if !record.dkimClosed {
			switch joined {
			case "feedback>record>auth_results>dkim>domain":
				return &record.dkimDomain
			case "feedback>record>auth_results>dkim>selector":
				return &record.dkimSelector
			case "feedback>record>auth_results>dkim>result":
				return &record.dkimResult
			}
		}
		if !record.spfClosed && joined == "feedback>record>auth_results>spf>result" {
			return &record.spfResult
		}
		return nil
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: XML that does not parse", ErrSmtpReportRefused)
		}
		switch element := token.(type) {
		case xml.StartElement:
			if settings.ReportNestingDepth <= len(path) {
				return nil, fmt.Errorf("%w: XML nesting past the bound", ErrSmtpReportRefused)
			}
			path = append(path, element.Name.Local)
			if len(path) == 1 && element.Name.Local != "feedback" {
				return nil, fmt.Errorf("%w: XML that is not a DMARC report", ErrSmtpReportRefused)
			}
			if len(path) == 2 && element.Name.Local == "record" {
				record = &smtpDmarcRecord{}
			}
			value = target()
		case xml.EndElement:
			joined := strings.Join(path, ">")
			switch joined {
			case "feedback>record":
				if record != nil {
					finishRecord()
				}
				record = nil
			case "feedback>record>auth_results>dkim":
				if record != nil {
					record.dkimClosed = true
				}
			case "feedback>record>auth_results>spf":
				if record != nil {
					record.spfClosed = true
				}
			}
			path = path[:len(path)-1]
			value = nil
		case xml.CharData:
			if value != nil {
				if smtpAggregateValueMaxByteCount < len(*value)+len(element) {
					return nil, fmt.Errorf("%w: an XML value past the bound", ErrSmtpReportRefused)
				}
				*value += string(element)
			}
		case xml.Directive:
			return nil, fmt.Errorf("%w: an XML directive", ErrSmtpReportRefused)
		}
	}
	rows.ReportId = strings.TrimSpace(rows.ReportId)
	if rows.ReportId == "" {
		return nil, fmt.Errorf("%w: a report with no report_id", ErrSmtpReportRefused)
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(begin), 10, 64); err == nil {
		rows.Begin = time.Unix(seconds, 0).UTC()
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(end), 10, 64); err == nil {
		rows.End = time.Unix(seconds, 0).UTC()
	}
	return rows, nil
}
