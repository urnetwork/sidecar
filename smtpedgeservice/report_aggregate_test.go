// FS-39's parser half: gzip and zip XML and JSON aggregates to rows, bombs stopped at the bound, and
// DTDs, external entities and deep nesting refused (§14.8, D-SMTP-23).

package smtpedgeservice

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"
	"time"
)

// data gzipped.
func gzipBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// Each name's data as files of one zip.
func zipBytes(t testing.TB, files ...[2]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, file := range files {
		entry, err := writer.Create(file[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(file[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// An aggregate message carrying attachment.
func aggregateMessage(mediaType string, fileName string, attachment []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(attachment)
	var lines strings.Builder
	for 0 < len(encoded) {
		take := min(76, len(encoded))
		lines.WriteString(encoded[:take] + "\r\n")
		encoded = encoded[take:]
	}
	return []byte("From: noreply-dmarc@reporter.example\r\nContent-Type: multipart/mixed; boundary=agg\r\n\r\n" +
		"--agg\r\nContent-Type: text/plain\r\n\r\nreport attached\r\n" +
		"--agg\r\nContent-Type: " + mediaType + "; name=\"" + fileName + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + lines.String() + "--agg--\r\n")
}

// The aggregate a message carries.
func parseAggregateMessage(t *testing.T, raw []byte) (*SmtpAggregateRows, error) {
	t.Helper()
	settings := reportTestSettings()
	parts, err := parseSmtpReportMime(raw, settings)
	if err != nil {
		t.Fatal(err)
	}
	return parseSmtpAggregate(parts, settings)
}

// The rows dmarc.xml must give.
func assertDmarcFixtureRows(t *testing.T, rows *SmtpAggregateRows) {
	t.Helper()
	if rows.Kind != SmtpAggregateKindDmarc || rows.ReportId != "17265234567890123456" {
		t.Fatalf("kind %q, report id %q", rows.Kind, rows.ReportId)
	}
	if !rows.Begin.Equal(time.Unix(1793664000, 0)) || !rows.End.Equal(time.Unix(1793750399, 0)) {
		t.Fatalf("range %v to %v", rows.Begin, rows.End)
	}
	if rows.DroppedRowCount != 1 || len(rows.Rows) != 2 {
		t.Fatalf("%d rows kept, %d dropped", len(rows.Rows), rows.DroppedRowCount)
	}
	first := rows.Rows[0]
	if first.Domain != "quietnet.root.example" || first.MessageCount != 5 || first.Disposition != "none" || first.DkimAligned != "pass" ||
		first.SpfAligned != "fail" || first.DkimDomain != "quietnet.root.example" || first.DkimSelector != "abcdefghijklmnopqrstuvwxyz" ||
		first.DkimResult != "pass" || first.SpfResult != "pass" {
		t.Fatalf("first row %+v", first)
	}
	second := rows.Rows[1]
	if second.Domain != "quiet-otter.quietnet.root.example" || second.MessageCount != 2 || second.Disposition != "reject" {
		t.Fatalf("second row %+v", second)
	}
}

func TestAggregateGzipXmlParsesToRows(t *testing.T) {
	data := readCrlfFixture(t, "aggregate/dmarc.xml")
	rows, err := parseAggregateMessage(t, aggregateMessage("application/gzip", "reporter.example!root.example!1!2.xml.gz", gzipBytes(t, data)))
	if err != nil {
		t.Fatal(err)
	}
	assertDmarcFixtureRows(t, rows)
}

func TestAggregateOneFileZipXmlParsesToRows(t *testing.T) {
	data := readCrlfFixture(t, "aggregate/dmarc.xml")
	rows, err := parseAggregateMessage(t, aggregateMessage("application/octet-stream", "report.zip", zipBytes(t, [2]string{"report.xml", string(data)})))
	if err != nil {
		t.Fatal(err)
	}
	assertDmarcFixtureRows(t, rows)
}

func TestAggregatePlainXmlParsesToRows(t *testing.T) {
	rows, err := parseAggregateMessage(t, aggregateMessage("text/xml", "report.xml", readCrlfFixture(t, "aggregate/dmarc.xml")))
	if err != nil {
		t.Fatal(err)
	}
	assertDmarcFixtureRows(t, rows)
}

func TestAggregateGzipTlsRptJsonParsesToRows(t *testing.T) {
	data := readCrlfFixture(t, "aggregate/tlsrpt.json")
	rows, err := parseAggregateMessage(t, aggregateMessage("application/tlsrpt+gzip", "report.json.gz", gzipBytes(t, data)))
	if err != nil {
		t.Fatal(err)
	}
	if rows.Kind != SmtpAggregateKindTlsRpt || rows.ReportId != "2026-11-02T00:00:00Z_quietnet.root.example" || len(rows.Rows) != 2 {
		t.Fatalf("%+v", rows)
	}
	if !rows.Begin.Equal(time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("begin %v", rows.Begin)
	}
	if row := rows.Rows[0]; row.Domain != "quietnet.root.example" || row.PolicyType != "sts" || row.SuccessCount != 120 || row.FailureCount != 3 {
		t.Fatalf("first policy %+v", row)
	}
	if row := rows.Rows[1]; row.Domain != "quiet-otter.quietnet.root.example" || row.PolicyType != "no-policy-found" || row.SuccessCount != 4 {
		t.Fatalf("second policy %+v", row)
	}
	for _, row := range rows.Rows {
		for _, value := range []string{row.Domain, row.PolicyType, row.Disposition, row.DkimDomain} {
			if strings.Contains(value, "198.51.100.33") {
				t.Fatal("a failure detail's sending MTA reached a row")
			}
		}
	}
}

func TestAggregateNonSendingSourceIpDroppedAtParse(t *testing.T) {
	xml := `<feedback><report_metadata><report_id>r</report_id></report_metadata>` +
		`<record><row><source_ip>198.51.100.7</source_ip><count>9</count></row><identifiers><header_from>quietnet.root.example</header_from></identifiers></record>` +
		`<record><row><source_ip>2001:db8::7</source_ip><count>1</count></row><identifiers><header_from>quietnet.root.example</header_from></identifiers></record>` +
		`</feedback>`
	rows, err := parseSmtpDmarcXml([]byte(xml), reportTestSettings())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 0 || rows.DroppedRowCount != 2 {
		t.Fatalf("%d kept, %d dropped", len(rows.Rows), rows.DroppedRowCount)
	}
}

// The bytes this goroutine's work allocates, which bounds what a parse can hold at once.
func allocatedBytes(work func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	work()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestAggregateGzipBombStopsAtTheBound(t *testing.T) {
	settings := reportTestSettings()
	// zeros compress past 100:1, so the ratio bound stops this one
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 1024*1024)
	for range 64 {
		writer.Write(zeros)
	}
	writer.Close()
	bomb := buffer.Bytes()
	var inflateErr error
	allocated := allocatedBytes(func() {
		_, inflateErr = inflateSmtpReport(bomb, smtpPackingGzip, settings)
	})
	if !errors.Is(inflateErr, ErrSmtpReportRefused) {
		t.Fatalf("a gzip bomb: %v", inflateErr)
	}
	if bound := uint64(4 * min(settings.ReportInflateByteCount, settings.ReportInflateRatio*len(bomb))); bound < allocated {
		t.Fatalf("a gzip bomb allocated %d bytes past %d", allocated, bound)
	}
	// incompressible data stays under 100:1, so the absolute bound stops this one
	random := rand.New(rand.NewPCG(1, 2))
	noise := make([]byte, settings.ReportInflateByteCount+1024)
	for i := range noise {
		noise[i] = byte(random.Uint32())
	}
	packed := gzipBytes(t, noise)
	allocated = allocatedBytes(func() {
		_, inflateErr = inflateSmtpReport(packed, smtpPackingGzip, settings)
	})
	if !errors.Is(inflateErr, ErrSmtpReportRefused) {
		t.Fatalf("an 8 MiB gzip: %v", inflateErr)
	}
	if bound := uint64(4 * settings.ReportInflateByteCount); bound < allocated {
		t.Fatalf("an 8 MiB gzip allocated %d bytes past %d", allocated, bound)
	}
}

func TestAggregateZipBombStopsAtTheBound(t *testing.T) {
	settings := reportTestSettings()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 1024*1024)
	for range 64 {
		entry.Write(zeros)
	}
	writer.Close()
	bomb := buffer.Bytes()
	var inflateErr error
	allocated := allocatedBytes(func() {
		_, inflateErr = inflateSmtpReport(bomb, smtpPackingZip, settings)
	})
	if !errors.Is(inflateErr, ErrSmtpReportRefused) {
		t.Fatalf("a zip bomb: %v", inflateErr)
	}
	if bound := uint64(4*min(settings.ReportInflateByteCount, settings.ReportInflateRatio*len(bomb)) + 1024*1024); bound < allocated {
		t.Fatalf("a zip bomb allocated %d bytes past %d", allocated, bound)
	}
}

func TestAggregateZipOfTwoFilesRefused(t *testing.T) {
	packed := zipBytes(t, [2]string{"a.xml", "<feedback/>"}, [2]string{"b.xml", "<feedback/>"})
	if _, err := inflateSmtpReport(packed, smtpPackingZip, reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("a zip of two files: %v", err)
	}
}

func TestAggregateDoctypeRefused(t *testing.T) {
	for _, xml := range []string{
		`<?xml version="1.0"?><!DOCTYPE feedback [<!ELEMENT feedback ANY>]><feedback><report_metadata><report_id>r</report_id></report_metadata></feedback>`,
		`<?xml version="1.0"?><!doctype feedback><feedback/>`,
	} {
		if _, err := parseSmtpDmarcXml([]byte(xml), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
			t.Errorf("%q: %v", xml, err)
		}
	}
}

func TestAggregateExternalEntityRefused(t *testing.T) {
	for _, xml := range []string{
		`<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback><report_metadata><report_id>&x;</report_id></report_metadata></feedback>`,
		`<feedback><report_metadata><report_id>&x;</report_id></report_metadata></feedback>`,
	} {
		if _, err := parseSmtpDmarcXml([]byte(xml), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
			t.Errorf("%q: %v", xml, err)
		}
	}
}

func TestAggregateNestingPastTheBoundRefused(t *testing.T) {
	settings := reportTestSettings()
	nest := func(depth int) []byte {
		// feedback, report_metadata, report_id, then filler down to depth
		inner := strings.Repeat("<x>", depth-3) + strings.Repeat("</x>", depth-3)
		return []byte("<feedback><report_metadata><report_id>r" + inner + "</report_id></report_metadata></feedback>")
	}
	if _, err := parseSmtpDmarcXml(nest(settings.ReportNestingDepth), settings); err != nil {
		t.Fatalf("nesting 32: %v", err)
	}
	if _, err := parseSmtpDmarcXml(nest(settings.ReportNestingDepth+1), settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("nesting 33: %v", err)
	}
	jsonNest := func(depth int) []byte {
		return []byte(`{"report-id":"r","x":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`)
	}
	if _, err := parseSmtpTlsRptJson(jsonNest(settings.ReportNestingDepth), settings); err != nil {
		t.Fatalf("JSON nesting 32: %v", err)
	}
	if _, err := parseSmtpTlsRptJson(jsonNest(settings.ReportNestingDepth+1), settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("JSON nesting 33: %v", err)
	}
}

func TestAggregateWithoutAReportIdRefused(t *testing.T) {
	if _, err := parseSmtpDmarcXml([]byte(`<feedback><record/></feedback>`), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("XML: %v", err)
	}
	if _, err := parseSmtpTlsRptJson([]byte(`{"policies":[]}`), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("JSON: %v", err)
	}
}

func TestAggregateOtherRootElementRefused(t *testing.T) {
	if _, err := parseSmtpDmarcXml([]byte(`<other><report_id>r</report_id></other>`), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("%v", err)
	}
}

func TestAggregateLongValueRefused(t *testing.T) {
	xml := "<feedback><report_metadata><report_id>" + strings.Repeat("a", smtpAggregateValueMaxByteCount+1) + "</report_id></report_metadata></feedback>"
	if _, err := parseSmtpDmarcXml([]byte(xml), reportTestSettings()); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("%v", err)
	}
}

func TestAggregateMessageWithoutAnAttachmentFindsNone(t *testing.T) {
	rows, err := parseAggregateMessage(t, []byte("From: a@reporter.example\r\nContent-Type: text/plain\r\n\r\nno report here"))
	if err != nil || rows != nil {
		t.Fatalf("%v, %v", rows, err)
	}
}

func TestAggregateReadBoundedStopsOneOctetPast(t *testing.T) {
	reader := &countingReader{reader: bytes.NewReader(make([]byte, 1024))}
	if _, err := smtpReadBounded(reader, 100); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("%v", err)
	}
	if reader.count != 101 {
		t.Fatalf("read %d octets for a bound of 100", reader.count)
	}
}

// Counts what is read through it.
type countingReader struct {
	reader io.Reader
	count  int
}

// Counts and passes on.
func (self *countingReader) Read(buffer []byte) (int, error) {
	n, err := self.reader.Read(buffer)
	self.count += n
	return n, err
}
