// §22.6's report rows: bounded expansion, and no enclosed ARF body octet in any output. A plain go test
// runs the seeds, testdata/fuzz's included; a campaign is go test -fuzz.

package smtpedgeservice

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// What a canary in an enclosed body reads as. No input may hold it, which the fuzz bodies check.
const fuzzBodyCanary = "BODY-OCTET-CANARY-6e1f"

// The bytes work allocates, read without a collection, so a fuzz iteration stays cheap.
func fuzzAllocatedBytes(work func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	work()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A testdata file's bytes with LF made CRLF, for a seed.
func fuzzSeed(f *testing.F, name string) []byte {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "smtp", name))
	if err != nil {
		f.Fatal(err)
	}
	return bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
}

func FuzzSmtpArf(f *testing.F) {
	settings := reportTestSettings()
	for _, name := range []string{"arf/rfc5965.eml", "arf/jmrp.eml", "arf/cfl.eml"} {
		raw := fuzzSeed(f, name)
		f.Add([]byte(arfEnclosedHeaders("seed")), raw)
	}
	f.Add([]byte("From: a@quietnet.root.example\r\nDKIM-Signature: v=1; d=quietnet.root.example; s=sel\r\n"), []byte("Content-Type: multipart/report; boundary=x\r\n\r\n--x\r\n\r\n--x--"))
	f.Add([]byte("Received: from x ([192.0.2.10]) by y; Tue, 03 Nov 2026 10:00:01 +0000\r\n"), []byte("\r\n"))
	f.Fuzz(func(t *testing.T, enclosed []byte, raw []byte) {
		// an enclosed header block, then the canary as its body: whatever the block holds, no output may
		// hold an octet past its blank line
		if !bytes.Contains(enclosed, []byte("b-1")) && !bytes.Contains(enclosed, []byte(fuzzBodyCanary)) {
			report := arfReport("Feedback-Type: abuse", "message/rfc822", "", append(append(bytes.Clone(enclosed), "\r\n\r\n"...), fuzzBodyCanary...))
			parts, err := parseSmtpReportMime(report, settings)
			if err == nil {
				if arf, err := parseSmtpArf(parts, settings); err == nil {
					if bytes.Contains(arf.headerBlock, []byte(fuzzBodyCanary)) {
						t.Fatal("the header block holds a body octet")
					}
					for _, field := range arfFields(arf) {
						if bytes.Contains(field, []byte(fuzzBodyCanary)) {
							t.Fatal("a field holds a body octet")
						}
					}
				}
			}
		}
		// any report: no panic, the bounds held, and memory in proportion to the input
		var arf *SmtpArfReport
		allocated := fuzzAllocatedBytes(func() {
			parts, err := parseSmtpReportMime(raw, settings)
			if err != nil {
				return
			}
			if settings.ReportMimePartCount < len(parts.Parts) {
				t.Fatalf("%d parts", len(parts.Parts))
			}
			arf, _ = parseSmtpArf(parts, settings)
		})
		if arf != nil && settings.ReportHeaderByteCount < len(arf.headerBlock) {
			t.Fatalf("a header block of %d bytes", len(arf.headerBlock))
		}
		if bound := uint64(16*len(raw) + 4*1024*1024); bound < allocated {
			t.Fatalf("%d bytes allocated for %d of input", allocated, len(raw))
		}
	})
}

func FuzzSmtpAggregate(f *testing.F) {
	settings := reportTestSettings()
	// a smaller bound keeps each iteration fast; the property is the same at any bound
	settings.ReportInflateByteCount = 256 * 1024
	xml := fuzzSeed(f, "aggregate/dmarc.xml")
	json := fuzzSeed(f, "aggregate/tlsrpt.json")
	var zeros bytes.Buffer
	writer := gzip.NewWriter(&zeros)
	writer.Write(make([]byte, 1024*1024))
	writer.Close()
	f.Add(xml, uint8(0))
	f.Add(json, uint8(0))
	f.Add(gzipBytes(f, xml), uint8(1))
	f.Add(gzipBytes(f, json), uint8(1))
	f.Add(zeros.Bytes(), uint8(1))
	f.Add(zipBytes(f, [2]string{"r.xml", string(xml)}), uint8(2))
	f.Add([]byte(`<!DOCTYPE feedback><feedback/>`), uint8(0))
	f.Add([]byte(`{"report-id":"r","policies":[[[[]]]]}`), uint8(0))
	f.Fuzz(func(t *testing.T, packed []byte, packingChoice uint8) {
		packing := []string{smtpPackingNone, smtpPackingGzip, smtpPackingZip}[int(packingChoice)%3]
		var data []byte
		var rows *SmtpAggregateRows
		allocated := fuzzAllocatedBytes(func() {
			var err error
			data, err = inflateSmtpReport(packed, packing, settings)
			if err != nil {
				return
			}
			trimmed := bytes.TrimLeft(data, " \t\r\n")
			switch {
			case bytes.HasPrefix(trimmed, []byte("<")):
				rows, _ = parseSmtpDmarcXml(data, settings)
			case bytes.HasPrefix(trimmed, []byte("{")):
				rows, _ = parseSmtpTlsRptJson(data, settings)
			}
		})
		if data != nil && packing != smtpPackingNone && settings.ReportInflateRatio*len(packed) < len(data) {
			t.Fatalf("%d bytes from %d packed, past the ratio", len(data), len(packed))
		}
		if settings.ReportInflateByteCount < len(data) {
			t.Fatalf("%d bytes inflated, past the bound", len(data))
		}
		if rows != nil {
			for _, row := range rows.Rows {
				if !smtpLdhName(row.Domain) {
					t.Fatalf("a row kept the domain %q", row.Domain)
				}
			}
		}
		// what inflating may hold, twice the bound, and what parsing what it holds may allocate
		if bound := uint64(2*settings.ReportInflateByteCount + 32*settings.ReportInflateByteCount + 16*len(packed) + 4*1024*1024); bound < allocated {
			t.Fatalf("%d bytes allocated for %d packed", allocated, len(packed))
		}
	})
}
