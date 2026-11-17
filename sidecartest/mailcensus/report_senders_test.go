// The census's report senders (ABUSE-M7-01): a census list carrying them is whole, one missing says which, and their
// rows, with SNI or without, are listed and leave the bar as the sign-up senders set it.

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

// A census list of two sign-up senders and every report sender, each in a window of its own, an hour apart, the
// report senders' ASNs from the documentation range.
func testCensusReportSends(start time.Time) []*CensusSend {
	sends := []*CensusSend{
		{Sender: "signup-alpha", Kind: CensusKindSignup, Rank: 1, Asn: 64500, Recipient: "census-1@census.example"},
		{Sender: "signup-bravo", Kind: CensusKindSignup, Rank: 2, Asn: 64501, Recipient: "census-2@census.example"},
	}
	for index, reportSender := range CensusReportSenders() {
		sends = append(sends, &CensusSend{
			Sender:    reportSender.Sender,
			Kind:      CensusKindReport,
			Asn:       uint32(64502 + index),
			Recipient: "census-report-" + reportSender.Sender + "@census.example",
		})
	}
	for index, send := range sends {
		send.Start = start.Add(time.Duration(index) * time.Hour)
		send.End = send.Start.Add(time.Minute)
	}
	return sends
}

// Every report sender has a row; a report sender without SNI changes neither share; and the text lists them by name
// with no address.
func TestCensusListsTheReportSenders(t *testing.T) {
	start := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	sends := testCensusReportSends(start)
	if missing := MissingCensusReportSenders(sends); len(missing) != 0 {
		t.Fatalf("a whole list misses %v", missing)
	}
	// the sign-up senders deliver with SNI; of the report senders, the ARF feeds deliver with SNI and the DMARC
	// reporters reach the router without it
	received := []*CensusReceived{}
	snapshots := []*CensusCounterSnapshot{}
	settings := DefaultCensusSettings()
	noSni := 0.0
	for _, send := range sends {
		snapshots = append(snapshots, &CensusCounterSnapshot{Time: send.Start, Series: map[string]float64{censusSeriesName(settings.SessionsSeries, censusNoSniResult): noSni}})
		if send.Kind == CensusKindReport && strings.HasSuffix(send.Sender, "-dmarc") {
			noSni += 1
		} else {
			received = append(received, &CensusReceived{Recipient: send.Recipient, Time: send.Start.Add(time.Second), Sni: "mx.census.example", TlsVersion: 0x0304})
		}
		snapshots = append(snapshots, &CensusCounterSnapshot{Time: send.End, Series: map[string]float64{censusSeriesName(settings.SessionsSeries, censusNoSniResult): noSni}})
	}
	table, err := BuildCensus(settings, sends, snapshots, received)
	if err != nil {
		t.Fatal(err)
	}
	reportRows := table.ReportSenderRows()
	if len(reportRows) != len(CensusReportSenders()) {
		t.Fatalf("%d report rows", len(reportRows))
	}
	for _, row := range reportRows {
		wantSni := CensusYes
		if strings.HasSuffix(row.Sender, "-dmarc") {
			wantSni = CensusNo
		}
		if row.Sni != wantSni || row.Rank != 0 || row.Asn == 0 {
			t.Errorf("%s: %+v", row.Sender, row)
		}
	}
	if table.SignupAnswered != 2 || table.SignupWithoutSni != 0 || table.WeightedLoss != 0 || !table.Pass {
		t.Fatalf("report senders moved the bar: %+v", table)
	}
	var text bytes.Buffer
	if err := table.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, reportSender := range CensusReportSenders() {
		if !strings.Contains(text.String(), reportSender.Sender+"\treport") {
			t.Errorf("the table leaves out %s", reportSender.Sender)
		}
	}
	if strings.Contains(text.String(), "@") {
		t.Fatalf("the table holds an address:\n%s", text.String())
	}
}

// A list missing a report sender, or carrying one under another kind, names it.
func TestCensusNamesAMissingReportSender(t *testing.T) {
	sends := testCensusReportSends(time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC))
	trimmed := slices.DeleteFunc(slices.Clone(sends), func(send *CensusSend) bool {
		return send.Sender == "yahoo-cfl"
	})
	for _, send := range trimmed {
		if send.Sender == "gmail-dmarc" {
			relabeled := *send
			relabeled.Kind = CensusKindProvider
			trimmed = slices.DeleteFunc(trimmed, func(other *CensusSend) bool { return other == send })
			trimmed = append(trimmed, &relabeled)
			break
		}
	}
	if missing := MissingCensusReportSenders(trimmed); !slices.Equal(missing, []string{"gmail-dmarc", "yahoo-cfl"}) {
		t.Fatalf("missing %v", missing)
	}
	if missing := MissingCensusReportSenders(nil); len(missing) != len(CensusReportSenders()) {
		t.Fatalf("an empty list misses %v", missing)
	}
}
