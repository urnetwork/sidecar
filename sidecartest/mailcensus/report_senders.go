// The report senders a census lists (ABUSE-M7-01; D-MAIL-9, D-ABUSE-5, QD-118): the mailbox providers whose reports
// are how §21 hears of a network's mail, each a sender of the census list with kind report, so the owner sees, beside
// the sign-up bar, which of them would be lost if they reached a receiver without SNI. A report of theirs goes to
// rpt.bringyour.com, which takes it SNI or not (D-SMTP-19), so they stay out of the bar, as BuildCensus keeps every
// report sender out of it; the census lists them so a provider's move to another path shows here first.
//
// They add no metadata (plan-MAIL-census, option 1): a report sender's row is a census row like any other, its ASN from
// the census's own list, never from an address. Names are the list's names, never an address or a host.

package main

import (
	"slices"
)

// One report sender: the census list's name for it and what it sends §21.
type CensusReportSender struct {
	// the census list's name
	Sender string
	// what it reports: CensusReportArf, a complaint feed of one message each, or CensusReportDmarc, aggregate
	// reports
	Reports string
}

// What a report sender sends.
const (
	CensusReportArf   = "arf"
	CensusReportDmarc = "dmarc"
)

// The report senders a census lists, by name: Microsoft's JMRP and Yahoo's complaint feedback loop, which send §14.8's
// ARF complaints, and the large receivers' DMARC aggregate reports, Gmail's first among them.
func CensusReportSenders() []*CensusReportSender {
	return []*CensusReportSender{
		{Sender: "microsoft-jmrp", Reports: CensusReportArf},
		{Sender: "yahoo-cfl", Reports: CensusReportArf},
		{Sender: "gmail-dmarc", Reports: CensusReportDmarc},
		{Sender: "microsoft-dmarc", Reports: CensusReportDmarc},
		{Sender: "yahoo-dmarc", Reports: CensusReportDmarc},
	}
}

// The report senders sends lacks, by name and sorted: a census whose list leaves one out says nothing of whether
// §21 would hear it. A send of another kind under a report sender's name does not count as listing it.
func MissingCensusReportSenders(sends []*CensusSend) []string {
	missing := []string{}
	for _, reportSender := range CensusReportSenders() {
		listed := slices.ContainsFunc(sends, func(send *CensusSend) bool {
			return send != nil && send.Sender == reportSender.Sender && send.Kind == CensusKindReport
		})
		if !listed {
			missing = append(missing, reportSender.Sender)
		}
	}
	slices.Sort(missing)
	return missing
}

// The table's report senders' rows, in the table's order.
func (self *CensusTable) ReportSenderRows() []*CensusRow {
	rows := []*CensusRow{}
	for _, row := range self.Rows {
		if row.Kind == CensusKindReport {
			rows = append(rows, row)
		}
	}
	return rows
}
