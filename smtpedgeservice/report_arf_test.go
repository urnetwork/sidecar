// §22.5's §14 header-only parse: the MIME walk and ARF, on testdata/smtp/arf's shapes and on reports
// built here around canaries.

package smtpedgeservice

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Settings with one RFC 5737 sending address, as every report test uses.
func reportTestSettings() *SmtpEdgeSettings {
	settings := DefaultSmtpEdgeSettings()
	settings.Root = "root.example"
	settings.ReportHostName = "rpt.report.example"
	settings.SendingAddresses = []SmtpSendingAddress{{Address: netip.MustParseAddr("192.0.2.10"), HeloName: "o1.out.report.example"}}
	settings.LoopAllowlist = []string{"loop.example"}
	return settings
}

// A testdata file with every LF made CRLF.
func readCrlfFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "smtp", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
}

// A report's ARF, through the walk.
func parseArfFixture(t *testing.T, raw []byte) *SmtpArfReport {
	t.Helper()
	settings := reportTestSettings()
	parts, err := parseSmtpReportMime(raw, settings)
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseSmtpArf(parts, settings)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// Every string and byte slice a report's exported fields hold, reached by reflection, so a field added
// later is scanned too. The header block is not among them: it stays in memory for VerifyHeaders, and
// holds the enclosed Received lines as written.
func arfFields(report *SmtpArfReport) [][]byte {
	outputs := [][]byte{}
	var walk func(value reflect.Value)
	walk = func(value reflect.Value) {
		switch value.Kind() {
		case reflect.Pointer:
			if !value.IsNil() {
				walk(value.Elem())
			}
		case reflect.Struct:
			if value.Type() == reflect.TypeOf(netip.Addr{}) {
				outputs = append(outputs, []byte(value.Interface().(netip.Addr).String()))
				return
			}
			if value.Type() == reflect.TypeOf(time.Time{}) {
				return
			}
			for i := range value.NumField() {
				if value.Type().Field(i).IsExported() {
					walk(value.Field(i))
				}
			}
		case reflect.Slice:
			if value.Type().Elem().Kind() == reflect.Uint8 {
				outputs = append(outputs, value.Bytes())
				return
			}
			for i := range value.Len() {
				walk(value.Index(i))
			}
		case reflect.String:
			outputs = append(outputs, []byte(value.String()))
		}
	}
	walk(reflect.ValueOf(report))
	return outputs
}

// Fails when any exported field holds a needle: what may leave the parser, as a third-party address
// must not.
func assertNoFieldHolds(t *testing.T, report *SmtpArfReport, needles ...string) {
	t.Helper()
	for _, output := range arfFields(report) {
		for _, needle := range needles {
			if bytes.Contains(output, []byte(needle)) {
				t.Errorf("a field holds %q", needle)
			}
		}
	}
}

// Fails when any field or the header block holds a needle: what the parser must never have read, as
// an enclosed body must not.
func assertNoOutputHolds(t *testing.T, report *SmtpArfReport, needles ...string) {
	t.Helper()
	assertNoFieldHolds(t, report, needles...)
	for _, needle := range needles {
		if bytes.Contains(report.headerBlock, []byte(needle)) {
			t.Errorf("the header block holds %q", needle)
		}
	}
}

// The fields every fixture's enclosed headers carry.
func assertFixtureHeaders(t *testing.T, headers *SmtpReportHeaders, wantSignatures int, wantXUrRef bool, wantFeedbackId bool) {
	t.Helper()
	if headers == nil {
		t.Fatal("no headers")
	}
	if len(headers.DkimSignatures) != wantSignatures {
		t.Fatalf("%d signatures, want %d", len(headers.DkimSignatures), wantSignatures)
	}
	for _, signature := range headers.DkimSignatures {
		if signature.Domain != "quietnet.root.example" || signature.Selector != "abcdefghijklmnopqrstuvwxyz" {
			t.Fatalf("signature %+v", signature)
		}
	}
	if headers.MessageId != "<aaaabbbbccccddddeeeeffffgg@quietnet.root.example>" {
		t.Fatalf("message id %q", headers.MessageId)
	}
	if (headers.XUrRef == "1.abcdefghijklmnopqrstuvwxyz234567ab") != wantXUrRef || (headers.XUrRef == "") == wantXUrRef {
		t.Fatalf("x-ur-ref %q", headers.XUrRef)
	}
	if (headers.FeedbackId == "n:c:abcdefghijklmnopqrstuvwxyz:urnetwork") != wantFeedbackId || (headers.FeedbackId == "") == wantFeedbackId {
		t.Fatalf("feedback-id %q", headers.FeedbackId)
	}
	if headers.FromDomain != "quietnet.root.example" {
		t.Fatalf("from domain %q", headers.FromDomain)
	}
	if headers.ReceivedAddress != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("received address %v", headers.ReceivedAddress)
	}
	if !headers.ReceivedTime.Equal(time.Date(2026, time.November, 3, 10, 0, 1, 0, time.UTC)) {
		t.Fatalf("received time %v", headers.ReceivedTime)
	}
}

func TestArfParsesThePlainRfc5965Shape(t *testing.T) {
	report := parseArfFixture(t, readCrlfFixture(t, "arf/rfc5965.eml"))
	if report.FeedbackType != SmtpComplaintTypeAbuse {
		t.Fatalf("feedback type %q", report.FeedbackType)
	}
	assertFixtureHeaders(t, report.Headers, 2, true, true)
	assertNoOutputHolds(t, report, "BODY-CANARY", "virus")
	assertNoFieldHolds(t, report, "198.51.100.20")
}

func TestArfParsesTheJmrpShape(t *testing.T) {
	report := parseArfFixture(t, readCrlfFixture(t, "arf/jmrp.eml"))
	if report.FeedbackType != SmtpComplaintTypeAbuse {
		t.Fatalf("feedback type %q", report.FeedbackType)
	}
	assertFixtureHeaders(t, report.Headers, 1, true, false)
	assertNoOutputHolds(t, report, "BODY-CANARY", "Qk9EWS1DQU5BUlk")
	assertNoFieldHolds(t, report, "198.51.100.20", "2001:db8:10::5")
}

func TestArfParsesARedactedJmrpReport(t *testing.T) {
	report := parseArfFixture(t, readCrlfFixture(t, "arf/jmrp-redacted.eml"))
	assertFixtureHeaders(t, report.Headers, 1, true, false)
	if !bytes.Contains(report.headerBlock, []byte("To: <redacted>")) {
		t.Fatal("the masked recipient is not in the header block VerifyHeaders reads")
	}
}

func TestArfParsesTheCflHeadersOnlyShape(t *testing.T) {
	report := parseArfFixture(t, readCrlfFixture(t, "arf/cfl.eml"))
	if report.FeedbackType != SmtpComplaintTypeAbuse {
		t.Fatalf("feedback type %q", report.FeedbackType)
	}
	assertFixtureHeaders(t, report.Headers, 1, false, true)
}

// A fresh canary: random hex, so no fixture text can hold it by chance.
func arfCanary(label string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return label + "-" + hex.EncodeToString(value)
}

// A report whose enclosed message is header, then body.
func arfReport(feedbackPart string, enclosedType string, transferEncoding string, enclosed []byte) []byte {
	var builder strings.Builder
	builder.WriteString("From: fbl@loop.example\r\nContent-Type: multipart/report; report-type=feedback-report; boundary=\"b-1\"\r\n\r\n")
	builder.WriteString("--b-1\r\nContent-Type: text/plain\r\n\r\nhuman text\r\n")
	if feedbackPart != "" {
		builder.WriteString("--b-1\r\nContent-Type: message/feedback-report\r\n\r\n" + feedbackPart + "\r\n")
	}
	builder.WriteString("--b-1\r\nContent-Type: " + enclosedType + "\r\n")
	if transferEncoding != "" {
		builder.WriteString("Content-Transfer-Encoding: " + transferEncoding + "\r\n")
	}
	builder.WriteString("\r\n")
	builder.Write(enclosed)
	builder.WriteString("\r\n--b-1--\r\n")
	return []byte(builder.String())
}

// An enclosed message's header block.
func arfEnclosedHeaders(subject string) string {
	return "Received: from o1.out.report.example (o1.out.report.example [192.0.2.10]) by mx.receiver.example; Tue, 03 Nov 2026 10:00:01 +0000\r\n" +
		"From: sender@quietnet.root.example\r\nSubject: " + subject + "\r\nMessage-ID: <m1@quietnet.root.example>\r\n\r\n"
}

func TestArfBodyCanaryUntouched(t *testing.T) {
	bodyCanary := arfCanary("BODY")
	attachmentCanary := arfCanary("ATTACHMENT")
	enclosed := arfEnclosedHeaders("hello") +
		"Content-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\n" + bodyCanary +
		"\r\nFeedback-Type: virus\r\n--inner\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(attachmentCanary)) + "\r\n--inner--\r\n"
	for _, transferEncoding := range []string{"", "7bit", "base64", "quoted-printable"} {
		body := []byte(enclosed)
		switch transferEncoding {
		case "base64":
			body = []byte(base64.StdEncoding.EncodeToString(body))
		case "quoted-printable":
			body = []byte(strings.ReplaceAll(enclosed, "=", "=3D"))
		}
		report := parseArfFixture(t, arfReport("Feedback-Type: fraud", "message/rfc822", transferEncoding, body))
		if report.FeedbackType != SmtpComplaintTypeFraud {
			t.Fatalf("%q: feedback type %q", transferEncoding, report.FeedbackType)
		}
		if !bytes.HasSuffix(report.headerBlock, []byte("<m1@quietnet.root.example>\r\n\r\n")) {
			t.Fatalf("%q: the header block runs past its blank line", transferEncoding)
		}
		assertNoOutputHolds(t, report, bodyCanary, attachmentCanary, base64.StdEncoding.EncodeToString([]byte(attachmentCanary)))
	}
}

func TestArfHeaderBlockCutAtTheBound(t *testing.T) {
	settings := reportTestSettings()
	// a 65 KiB header block of short fields, then a body
	var header strings.Builder
	header.WriteString(arfEnclosedHeaders("first")[:len(arfEnclosedHeaders("first"))-2])
	for header.Len() < 65*1024 {
		header.WriteString("X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	header.WriteString("X-Ur-Ref: 1.abcdefghijklmnopqrstuvwxyz234567ab\r\n\r\nbody")
	report := parseArfFixture(t, arfReport("Feedback-Type: abuse", "text/rfc822-headers", "", []byte(header.String())))
	if settings.ReportHeaderByteCount < len(report.headerBlock) {
		t.Fatalf("a header block of %d bytes passed the bound", len(report.headerBlock))
	}
	if !bytes.HasSuffix(report.headerBlock, []byte("\r\n")) || bytes.HasSuffix(report.headerBlock, []byte("\r\n\r\n")) {
		t.Fatal("the cut is not at a line's end")
	}
	if report.Headers.XUrRef != "" {
		t.Fatal("a field past the bound was read")
	}
	if report.Headers.FromDomain != "quietnet.root.example" {
		t.Fatal("a field inside the bound was lost")
	}
}

func TestArfNestedMultipartPastTheDepthRefused(t *testing.T) {
	settings := reportTestSettings()
	nest := func(depth int) []byte {
		inner := "Content-Type: text/plain\r\n\r\nleaf\r\n"
		for level := depth - 1; 0 <= level; level -= 1 {
			boundary := fmt.Sprintf("n%d", level)
			inner = "Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n--" + boundary + "\r\n" + inner + "--" + boundary + "--\r\n"
		}
		return []byte("From: a@loop.example\r\n" + inner)
	}
	if _, err := parseSmtpReportMime(nest(settings.ReportMimeDepth-1), settings); err != nil {
		t.Fatalf("nesting at the bound: %v", err)
	}
	if _, err := parseSmtpReportMime(nest(settings.ReportMimeDepth), settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("nesting past the bound: %v", err)
	}
}

func TestArfPartCountBounded(t *testing.T) {
	settings := reportTestSettings()
	build := func(count int) []byte {
		var builder strings.Builder
		builder.WriteString("Content-Type: multipart/mixed; boundary=p\r\n\r\n")
		for range count {
			builder.WriteString("--p\r\nContent-Type: text/plain\r\n\r\nx\r\n")
		}
		builder.WriteString("--p--\r\n")
		return []byte(builder.String())
	}
	if parts, err := parseSmtpReportMime(build(settings.ReportMimePartCount), settings); err != nil || len(parts.Parts) != settings.ReportMimePartCount {
		t.Fatalf("parts at the bound: %v", err)
	}
	if _, err := parseSmtpReportMime(build(settings.ReportMimePartCount+1), settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("parts past the bound: %v", err)
	}
}

func TestArfReportHeaderBlockPastTheBoundRefused(t *testing.T) {
	settings := reportTestSettings()
	raw := []byte("From: a@loop.example\r\nX-Long: " + strings.Repeat("a", settings.ReportHeaderByteCount) + "\r\n\r\nbody")
	if _, err := parseSmtpReportMime(raw, settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("an endless header block: %v", err)
	}
}

func TestArfEncodedWordsAndCharsetsStayRaw(t *testing.T) {
	enclosed := "From: =?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte("Sender")) + "?= <sender@quietnet.root.example>\r\n" +
		"Subject: =?x-unknown?q?caf=E9?=\r\nMessage-ID: <m2@quietnet.root.example>\r\n\r\nbody"
	report := parseArfFixture(t, arfReport("Feedback-Type: abuse", "message/rfc822", "", []byte(enclosed)))
	if report.Headers.FromDomain != "quietnet.root.example" {
		t.Fatalf("from domain %q", report.Headers.FromDomain)
	}
	if !bytes.Contains(report.headerBlock, []byte("=?x-unknown?q?caf=E9?=")) {
		t.Fatal("an encoded word was rewritten")
	}
	assertNoFieldHolds(t, report, "Sender <", "café")
}

func TestArfKeepsOnlyASendingAddressFromReceived(t *testing.T) {
	enclosed := "Received: from relay.receiver.example (relay.receiver.example [198.51.100.40]) by mx.receiver.example; Tue, 03 Nov 2026 10:00:01 +0000\r\n" +
		"Received: from other.example ([IPv6:2001:db8::40]) by relay.receiver.example; Tue, 03 Nov 2026 10:00:00 +0000\r\n" +
		"From: sender@quietnet.root.example\r\n\r\nbody"
	report := parseArfFixture(t, arfReport("Feedback-Type: abuse", "text/rfc822-headers", "", []byte(enclosed)))
	if report.Headers.ReceivedAddress.IsValid() || !report.Headers.ReceivedTime.IsZero() {
		t.Fatal("a hop naming no sending address was kept")
	}
	assertNoFieldHolds(t, report, "198.51.100.40", "2001:db8::40")
}

func TestArfHoldsEachFieldToItsShape(t *testing.T) {
	enclosed := "From: =?utf-8?q?x?= <sender@bad_domain!>\r\nMessage-ID: no-at-sign\r\nX-UR-Ref: 1.TOO-SHORT\r\n" +
		"Feedback-ID: n:c:free text here:urnetwork\r\nDKIM-Signature: v=1; d=quietnet.root.example\r\n\r\nbody"
	report := parseArfFixture(t, arfReport("Feedback-Type: abuse", "text/rfc822-headers", "", []byte(enclosed)))
	headers := report.Headers
	if headers.FromDomain != "" || headers.MessageId != "" || headers.XUrRef != "" || headers.FeedbackId != "" || len(headers.DkimSignatures) != 0 {
		t.Fatalf("a field off its shape was kept: %+v", headers)
	}
}

func TestArfNotSpamIsKeptAsACancel(t *testing.T) {
	report := parseArfFixture(t, arfReport("Feedback-Type: not-spam\r\nVersion: 1", "text/rfc822-headers", "", []byte(arfEnclosedHeaders("x"))))
	if report.FeedbackType != SmtpComplaintTypeNotSpam {
		t.Fatalf("feedback type %q", report.FeedbackType)
	}
}

func TestArfFeedbackReportWithoutATypeRefused(t *testing.T) {
	settings := reportTestSettings()
	for _, feedback := range []string{"Version: 1", "Feedback-Type: abuse; text", "Feedback-Type: " + strings.Repeat("a", 33)} {
		parts, err := parseSmtpReportMime(arfReport(feedback, "text/rfc822-headers", "", []byte(arfEnclosedHeaders("x"))), settings)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseSmtpArf(parts, settings); !errors.Is(err, ErrSmtpReportRefused) {
			t.Errorf("%q: %v", feedback, err)
		}
	}
}

func TestArfRoleMailWithOnlyAnEnclosedMessage(t *testing.T) {
	report := parseArfFixture(t, arfReport("", "message/rfc822", "", []byte(arfEnclosedHeaders("spam about"))))
	if report.FeedbackType != "" || report.Headers == nil || report.Headers.FromDomain != "quietnet.root.example" {
		t.Fatalf("a role mail's enclosed message: %+v", report)
	}
}

func TestArfReportWithNeitherPartRefused(t *testing.T) {
	settings := reportTestSettings()
	parts, err := parseSmtpReportMime([]byte("From: someone@person.example\r\nContent-Type: text/plain\r\n\r\nplease stop the spam"), settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSmtpArf(parts, settings); !errors.Is(err, ErrSmtpReportRefused) {
		t.Fatalf("a bare message: %v", err)
	}
}

func TestParseHeaderBlockForTheAbuseForm(t *testing.T) {
	headers, err := ParseHeaderBlock([]byte(arfEnclosedHeaders("pasted")), reportTestSettings())
	if err != nil {
		t.Fatal(err)
	}
	if headers.FromDomain != "quietnet.root.example" || headers.MessageId != "<m1@quietnet.root.example>" || headers.ReceivedAddress != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("%+v", headers)
	}
	if _, err := ParseHeaderBlock(nil, &SmtpEdgeSettings{}); !errors.Is(err, ErrSmtpEdgeSettingsRefused) {
		t.Fatalf("unvalidated settings: %v", err)
	}
}

func TestMimeSkipsABoundaryInsideContent(t *testing.T) {
	settings := reportTestSettings()
	raw := []byte("Content-Type: multipart/mixed; boundary=xx\r\n\r\npreamble --xx not a delimiter\r\n--xx\r\nContent-Type: text/plain\r\n\r\nline --xxy still content\r\n--xxtail\r\n--xx--\r\nepilogue")
	parts, err := parseSmtpReportMime(raw, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts.Parts) != 1 || string(parts.Parts[0].Body) != "line --xxy still content\r\n--xxtail" {
		t.Fatalf("parts %q", parts.Parts[0].Body)
	}
}

func TestArfReceivedWithInvalidUtf8KeepsItsIndexes(t *testing.T) {
	// FuzzSmtpArf's crasher: lowering invalid UTF-8 changes its length, which once moved " by "'s index
	// past the end of the field
	for _, value := range []string{"\xbb\xbb\xbb BY ", "from x \xbb([192.0.2.10]) \xff by y; Tue, 03 Nov 2026 10:00:01 +0000"} {
		address, _, ok := smtpReceivedHop(value)
		if strings.HasPrefix(value, "from") && (!ok || address != netip.MustParseAddr("192.0.2.10")) {
			t.Errorf("%q: %v, %v", value, address, ok)
		}
	}
	if got := smtpAsciiLower("A\xbbB Ä"); got != "a\xbbb Ä" {
		t.Fatalf("%q", got)
	}
}
