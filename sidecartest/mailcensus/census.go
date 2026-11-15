// The census table (D-MAIL-9's inbound half, R-TEST-8, QD-118; MAIL-M7-26): what a scripted census run
// learned of each sender, joined from three records it keeps apart, so the owner can accept or refuse the
// SNI loss D-MAIL-9 proposes as burners' launch bar.
//
//	sends     the census's own list: each sender by name, its kind (provider, esp, signup or report), its
//	          rank in the top-100 sign-up list, its ASN from that list, the test address it was sent to, and
//	          the window it sent in. The census sends one sender at a time, so a window is that sender's alone
//	counters  snapshots of the router's urnetwork_mxedge_* counters, scraped across the run; a window reads
//	          the change between the last snapshot at or before its start and the first at or after its end
//	received  the test network's receiver's own view: each message it took, by test address and time, with
//	          the SNI it was reached on, its TLS version and whether the SNI host's TLSA held its key
//
// One row a sender: SNI (yes, no or unknown), DANE (the receiver's TLSA evidence, which a DANE sender
// needs, and no proof the sender checked it), TLS version, a plaintext fallback (a closed handshake and a
// plaintext try in its window, counted once however often it retried), and whether the mail arrived. The
// ASN comes from the list and never from a sender's address, which no record here holds, so mx-1, mx-2 and
// ops-1 stay as written. The bar is QD-118's restatement of "by volume": the share of sign-up senders
// without SNI, each weighted 1/rank, under Bar, shown beside the unweighted share; report senders are listed
// and left out, since rpt.bringyour.com takes them SNI or not, and senders with no answer are listed and
// counted apart.
//
// The tool sends nothing: SMTP-M7-01's mxprobe supplies the outbound half, and the run needs real senders.
// No address, of a sender or a test inbox, is ever written out.

package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// What a census run is judged by.
type CensusSettings struct {
	// D-MAIL-9's proposed bar: the weighted share of sign-up senders without SNI must stay under this. 0.05.
	Bar float64
	// The counter families a window reads, the router's.
	SessionsSeries  string
	PlaintextSeries string
}

// The proposal's values, the only source of their defaults.
func DefaultCensusSettings() *CensusSettings {
	return &CensusSettings{
		Bar:             0.05,
		SessionsSeries:  "urnetwork_mxedge_sessions_total",
		PlaintextSeries: "urnetwork_mxedge_plaintext_sessions_total",
	}
}

// A sender's kind in the census list.
const (
	CensusKindProvider = "provider"
	CensusKindEsp      = "esp"
	CensusKindSignup   = "signup"
	CensusKindReport   = "report"
)

// The router's session results that mean the sender reached TLS and the handshake closed, a temporary
// failure, and the one among them that means it named no SNI (mxedgeservice's metrics.go).
var (
	censusClosedHandshakeResults = []string{
		"closed_handshake", "hello_failed", "gate_closed", "not_ready", "no_sni", "unknown_name", "route_unavailable",
		"network_cap", "spent", "no_receiver", "receiver_busy", "receiver_denied", "sockets_unavailable", "setup_failed",
	}
	censusNoSniResult       = "no_sni"
	censusSplicePrefix      = "splice_"
	censusPlaintextResults  = []string{"451", "530"}
	errCensusInputRefused   = errors.New("census input refused")
	censusAnswerWords       = map[CensusAnswer]string{CensusUnknown: "unknown", CensusYes: "yes", CensusNo: "no"}
	censusTlsVersionWords   = map[uint16]string{0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
	censusTableColumnTitles = []string{"sender", "kind", "rank", "asn", "delivered", "sni", "dane", "tls", "plaintext_fallback"}
)

// One send of the census list.
type CensusSend struct {
	// The sender's name in the list, never an address.
	Sender string `json:"sender"`
	Kind   string `json:"kind"`
	// A sign-up sender's place in the top-100 list, 1 first; 0 for any other kind.
	Rank int `json:"rank"`
	// From the list, never from the sender's address.
	Asn uint32 `json:"asn"`
	// The test address the send went to: read to match what arrived, and never written out.
	Recipient string    `json:"recipient"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
}

// One scrape of the router's counters: series, as name{label="value"}, to value.
type CensusCounterSnapshot struct {
	Time   time.Time          `json:"time"`
	Series map[string]float64 `json:"series"`
}

// One message the test receiver took.
type CensusReceived struct {
	// The test address it was for: matched, never written out.
	Recipient string    `json:"recipient"`
	Time      time.Time `json:"time"`
	// The SNI the router routed it by, "" for none.
	Sni string `json:"sni"`
	// IANA's TLS version number, as MailDeposit.tls_version holds it.
	TlsVersion uint16 `json:"tls_version"`
	// MailAuthEvidence.sni_tlsa_live: the SNI host's TLSA held the receiver's key.
	TlsaLive bool `json:"tlsa_live"`
}

// A yes, a no, or no way to tell.
type CensusAnswer int

const (
	CensusUnknown CensusAnswer = iota
	CensusYes
	CensusNo
)

func (self CensusAnswer) String() string {
	return censusAnswerWords[self]
}

// One sender's row.
type CensusRow struct {
	Sender            string
	Kind              string
	Rank              int
	Asn               uint32
	Delivered         bool
	Sni               CensusAnswer
	Dane              CensusAnswer
	TlsVersion        string
	PlaintextFallback bool
}

// The table and the bar.
type CensusTable struct {
	Rows []*CensusRow
	// Sign-up senders with an SNI answer, and those whose answer was no.
	SignupAnswered   int
	SignupWithoutSni int
	// Sign-up senders with no answer either way, listed but in neither share.
	SignupUnknown int
	// Σ 1/rank of sign-up senders without SNI over Σ 1/rank of those answered, and the plain share.
	WeightedLoss   float64
	UnweightedLoss float64
	Bar            float64
	// Whether the weighted loss stayed under the bar. No answered sign-up sender is no pass.
	Pass bool
}

// The change of series between the snapshot at or before start and the one at or after end, false when
// either is missing.
func censusWindowDelta(snapshots []*CensusCounterSnapshot, start time.Time, end time.Time) (map[string]float64, bool) {
	var before, after *CensusCounterSnapshot
	for _, snapshot := range snapshots {
		if !snapshot.Time.After(start) && (before == nil || before.Time.Before(snapshot.Time)) {
			before = snapshot
		}
		if !snapshot.Time.Before(end) && (after == nil || snapshot.Time.Before(after.Time)) {
			after = snapshot
		}
	}
	if before == nil || after == nil {
		return nil, false
	}
	delta := map[string]float64{}
	for series, value := range after.Series {
		delta[series] = value - before.Series[series]
	}
	return delta, true
}

// series{result="result"}, the name a scrape gives one result's counter.
func censusSeriesName(name string, result string) string {
	return name + `{result="` + result + `"}`
}

// The table over sends, snapshots and received, as the file header says. A send with no sender, a kind
// not in the list's four, a window that ends before it starts or a sign-up sender with no rank is refused.
func BuildCensus(settings *CensusSettings, sends []*CensusSend, snapshots []*CensusCounterSnapshot, received []*CensusReceived) (*CensusTable, error) {
	if settings == nil {
		settings = DefaultCensusSettings()
	}
	table := &CensusTable{Bar: settings.Bar}
	weightedAnswered, weightedLoss := 0.0, 0.0
	for _, send := range sends {
		if send == nil || send.Sender == "" || send.End.Before(send.Start) ||
			!slices.Contains([]string{CensusKindProvider, CensusKindEsp, CensusKindSignup, CensusKindReport}, send.Kind) ||
			(send.Kind == CensusKindSignup && send.Rank < 1) {
			return nil, fmt.Errorf("%w: a send with no sender, kind, window or sign-up rank", errCensusInputRefused)
		}
		row := &CensusRow{Sender: send.Sender, Kind: send.Kind, Rank: send.Rank, Asn: send.Asn}
		highestVersion := uint16(0)
		for _, message := range received {
			if message == nil || message.Recipient != send.Recipient || message.Time.Before(send.Start) || message.Time.After(send.End) {
				continue
			}
			row.Delivered = true
			if message.Sni != "" {
				row.Sni = CensusYes
			}
			if message.TlsaLive {
				row.Dane = CensusYes
			} else if row.Dane == CensusUnknown {
				row.Dane = CensusNo
			}
			highestVersion = max(highestVersion, message.TlsVersion)
		}
		if 0 < highestVersion {
			row.TlsVersion = censusTlsVersionWords[highestVersion]
			if row.TlsVersion == "" {
				row.TlsVersion = "0x" + strconv.FormatUint(uint64(highestVersion), 16)
			}
		}
		if delta, ok := censusWindowDelta(snapshots, send.Start, send.End); ok {
			closed := 0.0
			for _, result := range censusClosedHandshakeResults {
				closed += delta[censusSeriesName(settings.SessionsSeries, result)]
			}
			spliced := 0.0
			for series, value := range delta {
				if strings.HasPrefix(series, settings.SessionsSeries+`{result="`+censusSplicePrefix) {
					spliced += value
				}
			}
			plaintext := 0.0
			for _, result := range censusPlaintextResults {
				plaintext += delta[censusSeriesName(settings.PlaintextSeries, result)]
			}
			if row.Sni == CensusUnknown {
				switch {
				case 0 < delta[censusSeriesName(settings.SessionsSeries, censusNoSniResult)]:
					row.Sni = CensusNo
				case 0 < spliced:
					// a splice routed by SNI: the receiver's record of it may lag the window
					row.Sni = CensusYes
				}
			}
			// once, whatever the count: a sender that fell back did so in this window
			row.PlaintextFallback = 0 < closed && 0 < plaintext
		}
		if send.Kind == CensusKindSignup {
			switch row.Sni {
			case CensusUnknown:
				table.SignupUnknown += 1
			case CensusNo:
				table.SignupAnswered += 1
				table.SignupWithoutSni += 1
				weightedAnswered += 1 / float64(send.Rank)
				weightedLoss += 1 / float64(send.Rank)
			case CensusYes:
				table.SignupAnswered += 1
				weightedAnswered += 1 / float64(send.Rank)
			}
		}
		table.Rows = append(table.Rows, row)
	}
	if 0 < table.SignupAnswered {
		table.WeightedLoss = weightedLoss / weightedAnswered
		table.UnweightedLoss = float64(table.SignupWithoutSni) / float64(table.SignupAnswered)
		table.Pass = table.WeightedLoss < table.Bar
	}
	return table, nil
}

// The table as text: a header, one tab-separated row a sender, then the bar's lines. It names senders by
// their list names and holds no address.
func (self *CensusTable) WriteText(writer io.Writer) error {
	lines := []string{strings.Join(censusTableColumnTitles, "\t")}
	for _, row := range self.Rows {
		rank := ""
		if 0 < row.Rank {
			rank = strconv.Itoa(row.Rank)
		}
		tlsVersion := row.TlsVersion
		if tlsVersion == "" {
			tlsVersion = "unknown"
		}
		lines = append(lines, strings.Join([]string{
			censusCell(row.Sender), row.Kind, rank, strconv.FormatUint(uint64(row.Asn), 10), strconv.FormatBool(row.Delivered),
			row.Sni.String(), row.Dane.String(), tlsVersion, strconv.FormatBool(row.PlaintextFallback),
		}, "\t"))
	}
	verdict := "fail"
	if self.Pass {
		verdict = "pass"
	}
	lines = append(lines,
		"",
		fmt.Sprintf("sign-up senders answered\t%d, of which %d without SNI; %d with no answer, in neither share", self.SignupAnswered, self.SignupWithoutSni, self.SignupUnknown),
		fmt.Sprintf("SNI loss, weighted 1/rank\t%s against the bar %s: %s", censusPercent(self.WeightedLoss), censusPercent(self.Bar), verdict),
		fmt.Sprintf("SNI loss, unweighted\t%s", censusPercent(self.UnweightedLoss)),
		"report senders\tlisted, left out of the bar: rpt.bringyour.com takes them with or without SNI",
	)
	_, err := io.WriteString(writer, strings.Join(lines, "\n")+"\n")
	return err
}

// A list name as one cell: tabs and line breaks become spaces, so a name cannot add a column or a row.
func censusCell(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, text)
}

// A share as a percentage to two places.
func censusPercent(share float64) string {
	return strconv.FormatFloat(math.Round(share*10000)/100, 'f', 2, 64) + "%"
}

// The urnetwork_mxedge_* series of a Prometheus text exposition, as a snapshot's: a scrape's lines
// name{labels} value, comments and other families skipped.
func ParseCensusCounterText(text string, scrapeTime time.Time) (*CensusCounterSnapshot, error) {
	snapshot := &CensusCounterSnapshot{Time: scrapeTime, Series: map[string]float64{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "urnetwork_mxedge_") {
			continue
		}
		end := strings.LastIndexAny(line, " \t")
		if end < 0 {
			return nil, fmt.Errorf("%w: a series with no value", errCensusInputRefused)
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(line[end+1:]), 64)
		if err != nil {
			return nil, fmt.Errorf("%w: a value that is no number", errCensusInputRefused)
		}
		snapshot.Series[strings.TrimSpace(line[:end])] = value
	}
	return snapshot, nil
}
