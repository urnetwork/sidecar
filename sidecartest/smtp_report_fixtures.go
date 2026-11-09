// Fixtures for smtpedgeservice's report intake (§14.8): DNS for reporters' keys, a DKIM signer,
// builders of ARF and aggregate reports, and fakes of the intake's seams: tokens, labels, mail keys,
// SMTP-M9-15's join and §21's abuse sink. The signer canonicalizes with code of its own, written apart
// from smtpedgeservice's, so a canonicalization slip in either fails the verifier's tests rather than
// cancelling out. Names are .example, addresses RFC 5737's, and keys are made per process, never kept
// in the repository. Safe for concurrent use.

package sidecartest

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

var _ smtpedgeservice.SmtpDnsTxtSource = (*FakeSmtpDnsTxt)(nil)

// What a FakeSmtpDnsTxt answers for a name set to fail: DNS that did not answer.
var ErrFakeSmtpDnsTimeout = errors.New("fake dns: no answer")

// TXT records in memory, and names that fail as a timeout would.
type FakeSmtpDnsTxt struct {
	stateLock sync.Mutex
	records   map[string][]string
	failing   map[string]bool
	lookups   []string
}

// No records.
func NewFakeSmtpDnsTxt() *FakeSmtpDnsTxt {
	return &FakeSmtpDnsTxt{records: map[string][]string{}, failing: map[string]bool{}}
}

// Sets name's records, replacing any.
func (self *FakeSmtpDnsTxt) Set(name string, records ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.records[strings.ToLower(name)] = records
}

// Makes name fail, or answer again.
func (self *FakeSmtpDnsTxt) SetFailing(name string, failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing[strings.ToLower(name)] = failing
}

// Every name looked up, in order.
func (self *FakeSmtpDnsTxt) Lookups() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lookups...)
}

// See SmtpDnsTxtSource.
func (self *FakeSmtpDnsTxt) LookupTxt(ctx context.Context, name string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name = strings.ToLower(name)
	self.lookups = append(self.lookups, name)
	if self.failing[name] {
		return nil, ErrFakeSmtpDnsTimeout
	}
	return append([]string{}, self.records[name]...), nil
}

// The fixture RSA key, made once per process.
var smtpFixtureRsa = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// A DKIM signing key under one selector and domain.
type SmtpDkimFixtureKey struct {
	// rsa-sha256 or ed25519-sha256.
	Algorithm string
	Selector  string
	Domain    string
	rsaKey    *rsa.PrivateKey
	edKey     ed25519.PrivateKey
}

// The process's RSA-2048 fixture key under selector at domain.
func NewSmtpDkimFixtureRsaKey(selector string, domain string) *SmtpDkimFixtureKey {
	return &SmtpDkimFixtureKey{Algorithm: "rsa-sha256", Selector: selector, Domain: domain, rsaKey: smtpFixtureRsa()}
}

// An Ed25519 key derived from name, so the same name gives the same key.
func NewSmtpDkimFixtureEd25519Key(name string, selector string, domain string) *SmtpDkimFixtureKey {
	seed := sha256.Sum256([]byte("smtp dkim fixture " + name))
	return &SmtpDkimFixtureKey{Algorithm: "ed25519-sha256", Selector: selector, Domain: domain, edKey: ed25519.NewKeyFromSeed(seed[:])}
}

// The public key as a key record's p= carries it: DER SubjectPublicKeyInfo, or Ed25519's 32 octets.
func (self *SmtpDkimFixtureKey) PublicKeyBytes() []byte {
	if self.rsaKey != nil {
		der, err := x509.MarshalPKIXPublicKey(&self.rsaKey.PublicKey)
		if err != nil {
			panic(err)
		}
		return der
	}
	return []byte(self.edKey.Public().(ed25519.PublicKey))
}

// The name the key record sits at.
func (self *SmtpDkimFixtureKey) RecordName() string {
	return self.Selector + "._domainkey." + self.Domain
}

// The key record, as DNS would hold it.
func (self *SmtpDkimFixtureKey) TxtRecord() string {
	keyType := "rsa"
	if self.edKey != nil {
		keyType = "ed25519"
	}
	return fmt.Sprintf("v=DKIM1; k=%s; p=%s", keyType, base64.StdEncoding.EncodeToString(self.PublicKeyBytes()))
}

// The key as smtp_dkim_key would hold it for networkId.
func (self *SmtpDkimFixtureKey) StoredKey(networkId sidecar.Id) *smtpedgeservice.SmtpDkimKey {
	return &smtpedgeservice.SmtpDkimKey{
		Selector:  self.Selector,
		Domain:    self.Domain,
		NetworkId: networkId,
		SidecarId: sidecar.NewId(),
		Algorithm: self.Algorithm,
		PublicKey: self.PublicKeyBytes(),
	}
}

// How SignSmtpDkimFixture signs.
type SmtpDkimFixtureOptions struct {
	// h=, in order. Default: from, to, subject, date, message-id, and from again, oversigned.
	Headers       []string
	HeaderRelaxed bool
	BodyRelaxed   bool
	// t=. Zero leaves t= out.
	SignTime time.Time
	// x=. Zero leaves x= out.
	ExpireTime time.Time
}

// One header field as the fixture signer reads it.
type fixtureHeaderField struct {
	name string
	// The whole field, its folding and final CRLF included.
	raw string
	// After the colon, folding included, without the final CRLF.
	value string
}

// The fields of a header block: lines on CRLF, a line opening with a space or tab continuing the last.
func fixtureHeaderFields(header string) []*fixtureHeaderField {
	fields := []*fixtureHeaderField{}
	for _, line := range strings.Split(strings.TrimSuffix(header, "\r\n"), "\r\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && 0 < len(fields) {
			last := fields[len(fields)-1]
			last.raw += line + "\r\n"
			last.value += "\r\n" + line
			continue
		}
		name, value, _ := strings.Cut(line, ":")
		fields = append(fields, &fixtureHeaderField{name: name, raw: line + "\r\n", value: value})
	}
	return fields
}

// RFC 6376 §3.4.2, written apart from smtpedgeservice's: unfold, split on WSP, rejoin with one space.
func fixtureRelaxedHeader(name string, value string) string {
	value = strings.ReplaceAll(value, "\r\n", "")
	words := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' })
	return strings.ToLower(strings.TrimSpace(name)) + ":" + strings.Join(words, " ") + "\r\n"
}

// RFC 6376 §3.4.3: every trailing CRLF goes, then one is added.
func fixtureSimpleBody(body string) string {
	for strings.HasSuffix(body, "\r\n") {
		body = strings.TrimSuffix(body, "\r\n")
	}
	return body + "\r\n"
}

// RFC 6376 §3.4.4 line by line: each run of WSP one space, none at a line's end, no trailing empty
// line, an empty body empty.
func fixtureRelaxedBody(body string) string {
	lines := strings.Split(body, "\r\n")
	for i, line := range lines {
		var builder strings.Builder
		space := false
		for j := range len(line) {
			if line[j] == ' ' || line[j] == '\t' {
				space = true
				continue
			}
			if space {
				builder.WriteByte(' ')
			}
			space = false
			builder.WriteByte(line[j])
		}
		lines[i] = builder.String()
	}
	for 0 < len(lines) && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// message, a header block, CRLF CRLF and a body, with a DKIM-Signature under key added at its top.
// The b= value is folded, so a verifier has to unfold it.
func SignSmtpDkimFixture(message []byte, key *SmtpDkimFixtureKey, options *SmtpDkimFixtureOptions) []byte {
	if options == nil {
		options = &SmtpDkimFixtureOptions{}
	}
	headerNames := options.Headers
	if len(headerNames) == 0 {
		headerNames = []string{"from", "to", "subject", "date", "message-id", "from"}
	}
	text := string(message)
	header, body, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		panic("a fixture message with no blank line")
	}
	header += "\r\n"
	canonicalBody := fixtureSimpleBody(body)
	if options.BodyRelaxed {
		canonicalBody = fixtureRelaxedBody(body)
	}
	bodyHash := sha256.Sum256([]byte(canonicalBody))
	canon := func(relaxed bool) string {
		if relaxed {
			return "relaxed"
		}
		return "simple"
	}
	tags := []string{
		"v=1",
		"a=" + key.Algorithm,
		"c=" + canon(options.HeaderRelaxed) + "/" + canon(options.BodyRelaxed),
		"d=" + key.Domain,
		"s=" + key.Selector,
	}
	if !options.SignTime.IsZero() {
		tags = append(tags, fmt.Sprintf("t=%d", options.SignTime.Unix()))
	}
	if !options.ExpireTime.IsZero() {
		tags = append(tags, fmt.Sprintf("x=%d", options.ExpireTime.Unix()))
	}
	tags = append(tags, "h="+strings.Join(headerNames, ":"), "bh="+base64.StdEncoding.EncodeToString(bodyHash[:]), "b=")
	unsigned := "DKIM-Signature: " + strings.Join(tags, "; ")
	fields := fixtureHeaderFields(header)
	taken := make([]bool, len(fields))
	var input strings.Builder
	for _, name := range headerNames {
		for i := len(fields) - 1; 0 <= i; i -= 1 {
			if taken[i] || !strings.EqualFold(fields[i].name, name) {
				continue
			}
			taken[i] = true
			if options.HeaderRelaxed {
				input.WriteString(fixtureRelaxedHeader(fields[i].name, fields[i].value))
			} else {
				input.WriteString(fields[i].raw)
			}
			break
		}
	}
	if options.HeaderRelaxed {
		name, value, _ := strings.Cut(unsigned, ":")
		input.WriteString(strings.TrimSuffix(fixtureRelaxedHeader(name, value), "\r\n"))
	} else {
		input.WriteString(unsigned)
	}
	digest := sha256.Sum256([]byte(input.String()))
	var signature []byte
	var err error
	if key.rsaKey != nil {
		signature, err = rsa.SignPKCS1v15(nil, key.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
	} else {
		signature = ed25519.Sign(key.edKey, digest[:])
	}
	encoded := base64.StdEncoding.EncodeToString(signature)
	var folded strings.Builder
	for 0 < len(encoded) {
		take := min(len(encoded), 60)
		if folded.Len() != 0 {
			folded.WriteString("\r\n\t")
		}
		folded.WriteString(encoded[:take])
		encoded = encoded[take:]
	}
	return []byte(unsigned + folded.String() + "\r\n" + text)
}

// A text message under From at fromDomain, with the headers §14.6 adds, ready to sign.
type SmtpFixtureMessage struct {
	FromDomain string
	// Extra fields, each a whole line without CRLF, placed after the standard ones.
	ExtraFields []string
	MessageId   string
	XUrRef      string
	FeedbackId  string
	Subject     string
	Body        string
	Date        time.Time
}

// The message's bytes, CRLF throughout.
func (self *SmtpFixtureMessage) Bytes() []byte {
	date := self.Date
	if date.IsZero() {
		date = time.Date(2026, time.November, 3, 10, 0, 0, 0, time.UTC)
	}
	lines := []string{
		"From: Sender <sender@" + self.FromDomain + ">",
		"To: recipient@receiver.example",
		"Subject: " + self.Subject,
		"Date: " + date.Format(time.RFC1123Z),
		"Message-ID: " + self.MessageId,
	}
	if self.XUrRef != "" {
		lines = append(lines, "X-UR-Ref: "+self.XUrRef)
	}
	if self.FeedbackId != "" {
		lines = append(lines, "Feedback-ID: "+self.FeedbackId)
	}
	lines = append(lines, self.ExtraFields...)
	lines = append(lines, "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8")
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n" + strings.ReplaceAll(self.Body, "\n", "\r\n"))
}

// The boundary every fixture multipart uses: no fixture body may hold it.
const SmtpFixtureBoundary = "fixture-boundary-7f3a"

// An RFC 5965 feedback report from reporter at reporterDomain about enclosed, whose whole bytes go in
// a message/rfc822 part, or only its header block in a text/rfc822-headers part when headersOnly.
func BuildSmtpArfReport(reporterDomain string, feedbackType string, enclosed []byte, headersOnly bool) []byte {
	enclosedType := "message/rfc822"
	if headersOnly {
		enclosedType = "text/rfc822-headers"
		if end := bytes.Index(enclosed, []byte("\r\n\r\n")); 0 <= end {
			enclosed = enclosed[:end+4]
		}
	}
	lines := []string{
		"From: Feedback Loop <fbl@" + reporterDomain + ">",
		"To: root@rpt.report.example",
		"Subject: complaint about message",
		"Date: Tue, 03 Nov 2026 11:00:00 +0000",
		"Message-ID: <report-1@" + reporterDomain + ">",
		"MIME-Version: 1.0",
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"" + SmtpFixtureBoundary + "\"",
		"",
		"--" + SmtpFixtureBoundary,
		"Content-Type: text/plain",
		"",
		"This is an abuse report for a message received from 192.0.2.10.",
		"--" + SmtpFixtureBoundary,
		"Content-Type: message/feedback-report",
		"",
		"Feedback-Type: " + feedbackType,
		"User-Agent: FixtureLoop/1.0",
		"Version: 1",
		"",
		"--" + SmtpFixtureBoundary,
		"Content-Type: " + enclosedType,
		"Content-Disposition: inline",
		"",
	}
	report := strings.Join(lines, "\r\n") + "\r\n" + string(enclosed) + "\r\n--" + SmtpFixtureBoundary + "--\r\n"
	return []byte(report)
}

// data gzipped.
func SmtpFixtureGzip(data []byte) []byte {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

// data as the one file of a zip, named name.
func SmtpFixtureZip(name string, data []byte) []byte {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create(name)
	if err != nil {
		panic(err)
	}
	if _, err := entry.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

// One record of a DMARC aggregate.
type SmtpFixtureDmarcRecord struct {
	SourceIp     string
	Count        int
	HeaderFrom   string
	Disposition  string
	DkimAligned  string
	SpfAligned   string
	DkimDomain   string
	DkimSelector string
	DkimResult   string
}

// An RFC 9990 aggregate report's XML.
func BuildSmtpDmarcXml(orgName string, reportId string, begin time.Time, records []*SmtpFixtureDmarcRecord) []byte {
	var builder strings.Builder
	builder.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<feedback xmlns=\"urn:ietf:params:xml:ns:dmarc-2.0\">\n")
	fmt.Fprintf(&builder, "  <report_metadata>\n    <org_name>%s</org_name>\n    <email>noreply@%s</email>\n    <report_id>%s</report_id>\n", orgName, orgName, reportId)
	fmt.Fprintf(&builder, "    <date_range>\n      <begin>%d</begin>\n      <end>%d</end>\n    </date_range>\n  </report_metadata>\n", begin.Unix(), begin.Add(24*time.Hour).Unix())
	builder.WriteString("  <policy_published>\n    <domain>root.example</domain>\n    <adkim>s</adkim>\n    <aspf>s</aspf>\n    <p>reject</p>\n  </policy_published>\n")
	for _, record := range records {
		fmt.Fprintf(&builder, "  <record>\n    <row>\n      <source_ip>%s</source_ip>\n      <count>%d</count>\n", record.SourceIp, record.Count)
		fmt.Fprintf(&builder, "      <policy_evaluated>\n        <disposition>%s</disposition>\n        <dkim>%s</dkim>\n        <spf>%s</spf>\n      </policy_evaluated>\n    </row>\n", record.Disposition, record.DkimAligned, record.SpfAligned)
		fmt.Fprintf(&builder, "    <identifiers>\n      <header_from>%s</header_from>\n      <envelope_to>receiver.example</envelope_to>\n    </identifiers>\n", record.HeaderFrom)
		fmt.Fprintf(&builder, "    <auth_results>\n      <dkim>\n        <domain>%s</domain>\n        <selector>%s</selector>\n        <result>%s</result>\n      </dkim>\n", record.DkimDomain, record.DkimSelector, record.DkimResult)
		builder.WriteString("      <spf>\n        <domain>b.root.example</domain>\n        <result>pass</result>\n      </spf>\n    </auth_results>\n  </record>\n")
	}
	builder.WriteString("</feedback>\n")
	return []byte(builder.String())
}

// One policy of a TLS-RPT report.
type SmtpFixtureTlsRptPolicy struct {
	PolicyType   string
	PolicyDomain string
	SuccessCount int
	FailureCount int
	// A failure detail's sending MTA, which the parser must keep out of every field.
	SendingMtaIp string
}

// An RFC 8460 report's JSON.
func BuildSmtpTlsRptJson(orgName string, reportId string, begin time.Time, policies []*SmtpFixtureTlsRptPolicy) []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "{\"organization-name\":%q,\"date-range\":{\"start-datetime\":%q,\"end-datetime\":%q},\"contact-info\":\"tlsrpt@%s\",\"report-id\":%q,\"policies\":[",
		orgName, begin.Format(time.RFC3339), begin.Add(24*time.Hour).Format(time.RFC3339), orgName, reportId)
	for i, policy := range policies {
		if 0 < i {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, "{\"policy\":{\"policy-type\":%q,\"policy-string\":[\"version: STSv1\"],\"policy-domain\":%q,\"mx-host\":[\"mx.%s\"]},", policy.PolicyType, policy.PolicyDomain, policy.PolicyDomain)
		fmt.Fprintf(&builder, "\"summary\":{\"total-successful-session-count\":%d,\"total-failure-session-count\":%d},", policy.SuccessCount, policy.FailureCount)
		fmt.Fprintf(&builder, "\"failure-details\":[{\"result-type\":\"certificate-expired\",\"sending-mta-ip\":%q,\"receiving-mx-hostname\":\"mx.%s\",\"failed-session-count\":%d}]}", policy.SendingMtaIp, policy.PolicyDomain, policy.FailureCount)
	}
	builder.WriteString("]}")
	return []byte(builder.String())
}

// An aggregate report message from reporterDomain carrying attachment, base64 in a part of mediaType
// named fileName.
func BuildSmtpAggregateMessage(reporterDomain string, recipient string, mediaType string, fileName string, attachment []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(attachment)
	var wrapped strings.Builder
	for 0 < len(encoded) {
		take := min(len(encoded), 76)
		wrapped.WriteString(encoded[:take] + "\r\n")
		encoded = encoded[take:]
	}
	lines := []string{
		"From: Reports <noreply-dmarc@" + reporterDomain + ">",
		"To: " + recipient,
		"Subject: Report Domain: root.example Submitter: " + reporterDomain,
		"Date: Tue, 03 Nov 2026 12:00:00 +0000",
		"Message-ID: <aggregate-1@" + reporterDomain + ">",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=\"" + SmtpFixtureBoundary + "\"",
		"",
		"--" + SmtpFixtureBoundary,
		"Content-Type: text/plain",
		"",
		"This is an aggregate report.",
		"--" + SmtpFixtureBoundary,
		"Content-Type: " + mediaType + "; name=\"" + fileName + "\"",
		"Content-Disposition: attachment; filename=\"" + fileName + "\"",
		"Content-Transfer-Encoding: base64",
		"",
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n" + wrapped.String() + "--" + SmtpFixtureBoundary + "--\r\n")
}

var _ smtpedgeservice.SmtpAbuseSink = (*FakeSmtpAbuseSink)(nil)
var _ smtpedgeservice.SmtpNetTokenSource = (*FakeSmtpNetTokens)(nil)
var _ smtpedgeservice.SmtpLabelSource = (*FakeSmtpLabels)(nil)
var _ smtpedgeservice.SmtpReportKeySource = (*FakeSmtpReportKeys)(nil)
var _ smtpedgeservice.SmtpReportJoin = (*FakeSmtpReportJoin)(nil)

// §21's case flow, recording each report it is handed: what ABUSE-M5-09's real sink stands in for.
type FakeSmtpAbuseSink struct {
	stateLock sync.Mutex
	reports   []*smtpedgeservice.SmtpAbuseReport
	// The error the next calls answer, until cleared.
	failure error
}

// Records everything.
func NewFakeSmtpAbuseSink() *FakeSmtpAbuseSink {
	return &FakeSmtpAbuseSink{}
}

// Makes the sink fail with err, or answer again with nil.
func (self *FakeSmtpAbuseSink) SetFailure(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failure = err
}

// See SmtpAbuseSink.
func (self *FakeSmtpAbuseSink) OpenSmtpCase(ctx context.Context, report *smtpedgeservice.SmtpAbuseReport) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failure != nil {
		return self.failure
	}
	kept := *report
	self.reports = append(self.reports, &kept)
	return nil
}

// Every report handed over, in order, as copies.
func (self *FakeSmtpAbuseSink) Reports() []*smtpedgeservice.SmtpAbuseReport {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reports := []*smtpedgeservice.SmtpAbuseReport{}
	for _, report := range self.reports {
		kept := *report
		reports = append(reports, &kept)
	}
	return reports
}

// network_dns_zone.report_token in memory.
type FakeSmtpNetTokens struct {
	stateLock sync.Mutex
	networks  map[string]sidecar.Id
	lookups   []string
}

// No tokens.
func NewFakeSmtpNetTokens() *FakeSmtpNetTokens {
	return &FakeSmtpNetTokens{networks: map[string]sidecar.Id{}}
}

// A fresh token for networkId, as zone creation draws one: 26 lowercase base32 characters.
func (self *FakeSmtpNetTokens) Add(networkId sidecar.Id) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networks[token] = networkId
	return token
}

// Every token looked up, in order.
func (self *FakeSmtpNetTokens) Lookups() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lookups...)
}

// See SmtpNetTokenSource.
func (self *FakeSmtpNetTokens) NetworkForReportToken(ctx context.Context, token string) (sidecar.Id, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookups = append(self.lookups, token)
	networkId, ok := self.networks[token]
	return networkId, ok, nil
}

// §12's label map in memory.
type FakeSmtpLabels struct {
	stateLock sync.Mutex
	networks  map[string]sidecar.Id
}

// No labels.
func NewFakeSmtpLabels() *FakeSmtpLabels {
	return &FakeSmtpLabels{networks: map[string]sidecar.Id{}}
}

// Maps label to networkId.
func (self *FakeSmtpLabels) Set(label string, networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networks[label] = networkId
}

// See SmtpLabelSource.
func (self *FakeSmtpLabels) NetworkForLabel(ctx context.Context, label string) (sidecar.Id, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkId, ok := self.networks[label]
	return networkId, ok, nil
}

// Network mail keys in memory, each made here with its private half kept for the test to open copies.
type FakeSmtpReportKeys struct {
	stateLock   sync.Mutex
	publicKeys  map[sidecar.Id][]byte
	privateKeys map[sidecar.Id]hpke.PrivateKey
}

// No keys: what every network has before M7.
func NewFakeSmtpReportKeys() *FakeSmtpReportKeys {
	return &FakeSmtpReportKeys{publicKeys: map[sidecar.Id][]byte{}, privateKeys: map[sidecar.Id]hpke.PrivateKey{}}
}

// Makes networkId an X-Wing mail key and returns its private half.
func (self *FakeSmtpReportKeys) Add(networkId sidecar.Id) hpke.PrivateKey {
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		panic(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.publicKeys[networkId] = privateKey.PublicKey().Bytes()
	self.privateKeys[networkId] = privateKey
	return privateKey
}

// See SmtpReportKeySource.
func (self *FakeSmtpReportKeys) ReportSealKey(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.publicKeys[networkId]), nil
}

// SMTP-M9-15's attribution, faked: a report attributes when its enclosed From domain was set here, and
// to what was set.
type FakeSmtpReportJoin struct {
	stateLock     sync.Mutex
	byFromDomain  map[string]*smtpedgeservice.SmtpComplaint
	joinedReports int
}

// Attributes nothing.
func NewFakeSmtpReportJoin() *FakeSmtpReportJoin {
	return &FakeSmtpReportJoin{byFromDomain: map[string]*smtpedgeservice.SmtpComplaint{}}
}

// Reports from fromDomain attribute to networkId, at confidence joinResult.
func (self *FakeSmtpReportJoin) Attribute(fromDomain string, networkId sidecar.Id, joinResult string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.byFromDomain[fromDomain] = &smtpedgeservice.SmtpComplaint{NetworkId: networkId, Domain: fromDomain, JoinResult: joinResult}
}

// How many reports reached the join.
func (self *FakeSmtpReportJoin) JoinedReports() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.joinedReports
}

// See SmtpReportJoin.
func (self *FakeSmtpReportJoin) JoinReport(ctx context.Context, report *smtpedgeservice.SmtpArfReport) (*smtpedgeservice.SmtpComplaint, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.joinedReports += 1
	if report.Headers == nil {
		return nil, nil
	}
	complaint, ok := self.byFromDomain[report.Headers.FromDomain]
	if !ok {
		return nil, nil
	}
	kept := *complaint
	if 0 < len(report.Headers.DkimSignatures) {
		kept.DkimDomain = report.Headers.DkimSignatures[0].Domain
		kept.DkimSelector = report.Headers.DkimSignatures[0].Selector
	}
	kept.MessageIdHash = smtpedgeservice.SmtpMessageIdHash(report.Headers.MessageId)
	kept.XUrRef = report.Headers.XUrRef
	kept.FeedbackId = report.Headers.FeedbackId
	return &kept, nil
}
