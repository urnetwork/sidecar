// The mail test kit (MAIL-M7-03), checked against the RFCs and crypto alone, never through a receiver's
// verifiers: RFC 6376's canonicalization example and RFC 8463's signed message reproduced to the byte,
// every signer's signature verified with crypto/rsa and crypto/ed25519, ARC seals over their sets, the
// fake zone's answers and delays on a fake clock, the scripted MTA against a stub server, and FS-121's
// corpus as FS-121 describes it.
package sidecartest

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// RFC 6376 §3.4.5's example, both canonicalizations.
func TestMailCanonicalizationMatchesRfc6376(t *testing.T) {
	if got := mailCanonHeaderRelaxed("A: X\r\n") + mailCanonHeaderRelaxed("B : Y\t\r\n\tZ  \r\n"); got != "a:X\r\nb:Y Z\r\n" {
		t.Errorf("relaxed headers %q", got)
	}
	body := []byte(" C \r\nD \t E\r\n\r\n\r\n")
	if got := string(mailCanonBodyRelaxed(body)); got != " C\r\nD E\r\n" {
		t.Errorf("relaxed body %q", got)
	}
	if got := string(mailCanonBodySimple(body)); got != " C \r\nD \t E\r\n" {
		t.Errorf("simple body %q", got)
	}
	// an empty body: nothing relaxed, one CRLF simple (§3.4.3, §3.4.4)
	if got := mailCanonBodyRelaxed(nil); len(got) != 0 {
		t.Errorf("relaxed empty body %q", got)
	}
	if got := string(mailCanonBodySimple(nil)); got != "\r\n" {
		t.Errorf("simple empty body %q", got)
	}
	// a last line with no CRLF gains one
	if got := string(mailCanonBodyRelaxed([]byte("last"))); got != "last\r\n" {
		t.Errorf("relaxed unterminated %q", got)
	}
}

// RFC 8463 Appendix A, reproduced: the secret key of A.1 derives the public key A.2 publishes, the body
// hashes to the bh= of A.3, and signing the RFC's own field, its b= emptied, gives A.3's b=, which
// Ed25519 makes deterministically.
func TestMailDkimReproducesRfc8463(t *testing.T) {
	read := func(name string) string {
		bytes, err := os.ReadFile("../testdata/smtp/dkim/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(bytes), "\n", "\r\n")
	}
	message := []byte(read("rfc8463.eml"))
	record := strings.TrimSpace(read("rfc8463.txt"))
	seed, err := base64.StdEncoding.DecodeString("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
	if err != nil {
		t.Fatal(err)
	}
	key := MailDkimEd25519Key(seed)
	if got := MailDkimKeyRecord(key); got != record {
		t.Fatalf("A.1's key publishes %q, not A.2's %q", got, record)
	}
	fields, body, err := mailSplitMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if got := mailBodyHash(body, true, MailDkimEd25519Sha256); got != "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=" {
		t.Fatalf("body hash %s", got)
	}
	field := fields[0]
	bIndex := testMailBTagIndex(field)
	unsigned := field[:bIndex+2]
	want := strings.Join(strings.Fields(field[bIndex+2:]), "")
	names := []string{"from", "to", "subject", "date", "message-id", "from", "subject", "date"}
	got, err := MailDkimSignOver(message, unsigned, MailDkimEd25519Sha256, key, names, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("b= %s, A.3 shows %s", got, want)
	}
}

// A field's tags, its value unfolded, by name.
func testMailTags(t testing.TB, field string) map[string]string {
	t.Helper()
	_, value, _ := strings.Cut(strings.ReplaceAll(field, "\r\n", ""), ":")
	tags := map[string]string{}
	for tag := range strings.SplitSeq(value, ";") {
		name, tagValue, found := strings.Cut(tag, "=")
		if found {
			tags[strings.TrimSpace(name)] = strings.TrimSpace(tagValue)
		}
	}
	return tags
}

// Where a field's b= tag starts: a "b=" whose last non-whitespace byte before it is the separator
// ending the tag before, so a "b=" inside a base64 value never counts.
func testMailBTagIndex(field string) int {
	for index := strings.Index(field, "b="); 0 <= index; {
		before := strings.TrimRight(field[:index], " \t\r\n")
		if strings.HasSuffix(before, ";") || strings.HasSuffix(before, ":") {
			return index
		}
		next := strings.Index(field[index+1:], "b=")
		if next < 0 {
			return -1
		}
		index += 1 + next
	}
	return -1
}

// The field with its b= value removed, as RFC 6376 §3.7 signs it.
func testMailUnsigned(field string) string {
	field = strings.TrimSuffix(field, "\r\n")
	return field[:testMailBTagIndex(field)+2]
}

// Verifies one signature field over message's fields with crypto alone: the canonical bytes recomputed
// from the field's own h= and c=, its b= removed, and checked under publicKey.
func testMailVerify(t testing.TB, fields []string, signatureField string, selectedFields []string, publicKey crypto.PublicKey, relaxed bool) error {
	t.Helper()
	tags := testMailTags(t, signatureField)
	signature, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(tags["b"]), ""))
	if err != nil {
		return err
	}
	data := mailSignedData(selectedFields, testMailUnsigned(signatureField), relaxed)
	switch tags["a"] {
	case string(MailDkimEd25519Sha256):
		sum := sha256.Sum256(data)
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), sum[:], signature) {
			return errors.New("ed25519 signature does not verify")
		}
		return nil
	case string(MailDkimRsaSha1):
		sum := sha1.Sum(data)
		return rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA1, sum[:], signature)
	default:
		sum := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], signature)
	}
}

// Verifies the DKIM-Signature on top of message.
func testMailVerifyTop(t testing.TB, message []byte, publicKey crypto.PublicKey) error {
	t.Helper()
	fields, body, err := mailSplitMessage(message)
	if err != nil {
		return err
	}
	tags := testMailTags(t, fields[0])
	headerCanon, bodyCanon, _ := strings.Cut(tags["c"], "/")
	if got := mailBodyHash(body, bodyCanon == "relaxed", MailDkimAlgorithm(tags["a"])); got != tags["bh"] {
		return fmt.Errorf("bh= %s, the body hashes to %s", tags["bh"], got)
	}
	return testMailVerify(t, fields, fields[0], mailSelectFields(fields, strings.Split(tags["h"], ":")), publicKey, headerCanon == "relaxed")
}

var testMailMessage = mailCorpusBase("sender.example", "kit")

// Every algorithm and size the kit signs with, both canonicalizations, verifies under crypto; a changed
// header or body does not.
func TestMailDkimSignaturesVerifyUnderCrypto(t *testing.T) {
	for _, test := range []struct {
		algorithm MailDkimAlgorithm
		key       crypto.Signer
	}{
		{MailDkimRsaSha256, MailDkimRsaKey(1024)},
		{MailDkimRsaSha256, MailDkimRsaKey(2048)},
		{MailDkimRsaSha256, MailDkimRsaKey(8192)},
		{MailDkimRsaSha1, MailDkimRsaKey(1024)},
		{MailDkimEd25519Sha256, MailDkimEd25519Key(make([]byte, ed25519.SeedSize))},
	} {
		for _, canonicalization := range []string{"relaxed/relaxed", "simple/simple"} {
			signer, err := NewMailDkimSigner("sender.example", "kit", test.algorithm, test.key)
			if err != nil {
				t.Fatal(err)
			}
			signer.Canonicalization = canonicalization
			signer.SignTime = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
			signed, err := signer.Sign(testMailMessage)
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("%s %d bits %s", test.algorithm, testMailKeyBits(test.key), canonicalization)
			if err := testMailVerifyTop(t, signed, test.key.Public()); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			for _, line := range strings.Split(string(signed), "\r\n") {
				if 998 < len(line) {
					t.Errorf("%s: a line of %d bytes", name, len(line))
				}
			}
			tampered := []byte(strings.Replace(string(signed), "Subject: kit", "Subject: kit!", 1))
			if err := testMailVerifyTop(t, tampered, test.key.Public()); err == nil {
				t.Errorf("%s: a changed subject verifies", name)
			}
			tampered = []byte(strings.Replace(string(signed), "A synthetic body", "A changed body", 1))
			if err := testMailVerifyTop(t, tampered, test.key.Public()); err == nil {
				t.Errorf("%s: a changed body verifies", name)
			}
		}
	}
	if _, err := NewMailDkimSigner("sender.example", "kit", MailDkimEd25519Sha256, MailDkimRsaKey(1024)); err == nil {
		t.Error("an RSA key signs ed25519-sha256")
	}
	if key := MailDkimRsaKey(8192); key.N.BitLen() != 8192 || key.PublicKey.E != 65537 {
		t.Errorf("an 8,192-bit key of %d bits, e %d", key.N.BitLen(), key.PublicKey.E)
	}
}

func testMailKeyBits(key crypto.Signer) int {
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return rsaKey.N.BitLen()
	}
	return 256
}

// The ARC fields of message by instance and name.
func testMailArcSets(t *testing.T, message []byte) map[int]map[string]string {
	t.Helper()
	fields, _, err := mailSplitMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	sets := map[int]map[string]string{}
	for _, field := range fields {
		name := mailFieldName(field)
		if name != mailArcSealName && name != mailArcMessageSignatureName && name != mailArcResultsName {
			continue
		}
		instance := mailArcInstance(field)
		if sets[instance] == nil {
			sets[instance] = map[string]string{}
		}
		sets[instance][name] = field
	}
	return sets
}

// Each set's message signature and seal verify under crypto, the seal over every set up to its own in
// instance order; cv runs none, then pass, and the newest fail when asked; a gap leaves its instance out.
func TestMailArcSealsVerifyUnderCrypto(t *testing.T) {
	sealer := &MailArcSealer{Domain: "forwarder.example", Selector: "arc", Key: MailDkimRsaKey(1024), AuthServId: "mx.forwarder.example"}
	for _, options := range []*MailArcChainOptions{
		{SetCount: 3},
		{SetCount: 5, GapAt: 3},
		{SetCount: 4, FailNewest: true},
	} {
		message, err := sealer.Chain(testMailMessage, options)
		if err != nil {
			t.Fatal(err)
		}
		fields, _, err := mailSplitMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		sets := testMailArcSets(t, message)
		instances := slices.Sorted(maps.Keys(sets))
		if len(instances) != options.SetCount || (options.GapAt != 0 && slices.Contains(instances, options.GapAt)) {
			t.Fatalf("%+v: instances %v", options, instances)
		}
		var sealed []string
		for index, instance := range instances {
			set := sets[instance]
			if len(set) != 3 {
				t.Fatalf("%+v: instance %d has %d fields", options, instance, len(set))
			}
			messageSignature := set[mailArcMessageSignatureName]
			if err := testMailVerify(t, fields, messageSignature, mailSelectFields(fields, mailDkimDefaultHeaders), &sealer.Key.PublicKey, true); err != nil {
				t.Errorf("%+v: instance %d's AMS: %v", options, instance, err)
			}
			seal := set[mailArcSealName]
			sealed = append(sealed, set[mailArcResultsName], messageSignature)
			if err := testMailVerify(t, fields, seal, sealed, &sealer.Key.PublicKey, true); err != nil {
				t.Errorf("%+v: instance %d's seal: %v", options, instance, err)
			}
			sealed = append(sealed, seal)
			cv := testMailTags(t, seal)["cv"]
			want := "pass"
			switch {
			case index == len(instances)-1 && options.FailNewest:
				want = "fail"
			case index == 0:
				want = "none"
			}
			if cv != want {
				t.Errorf("%+v: instance %d cv=%s, want %s", options, instance, cv, want)
			}
		}
	}
}

// Parses a response to one question.
func testMailZoneAnswer(t *testing.T, response []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	return header, answers
}

// A selector answering 4.9 s late answers at 4.9 s on the zone's clock and not a nanosecond before; each
// record type answers as wire; each failure answers as scripted; and every query is logged.
func TestFakeMailZoneAnswersOnItsClock(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	zone := NewFakeMailZone(clock)
	selector := MailDkimKeyName("slow", "sender.example")
	zone.AddTxt(selector, strings.Repeat("k", 300))
	zone.SetDelay(selector, 4900*time.Millisecond)
	answered := make(chan []byte, 1)
	go func() {
		response, usable := zone.Forward(ctx, dnsmessage.TypeTXT, selector+".")
		if !usable {
			response = nil
		}
		answered <- response
	}()
	if err := zone.AwaitInFlight(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(4900*time.Millisecond - time.Nanosecond)
	select {
	case <-answered:
		t.Fatal("answered before its delay")
	default:
	}
	clock.Advance(time.Nanosecond)
	response := <-answered
	_, answers := testMailZoneAnswer(t, response)
	if len(answers) != 1 || strings.Join(answers[0].Body.(*dnsmessage.TXTResource).TXT, "") != strings.Repeat("k", 300) {
		t.Fatalf("answers %+v", answers)
	}
	queries := zone.Queries()
	if len(queries) != 1 || queries[0].End.Sub(queries[0].Start) != 4900*time.Millisecond {
		t.Fatalf("queries %+v", queries)
	}

	zone.AddAddress("mail.sender.example", netip.MustParseAddr("192.0.2.25"))
	zone.AddAddress("mail.sender.example", netip.MustParseAddr("2001:db8::25"))
	zone.AddMx("sender.example", 10, "mail.sender.example")
	zone.AddPtr(netip.MustParseAddr("192.0.2.25"), "mail.sender.example")
	zone.AddTlsa("_25._tcp.mx.network.root.example", 3, 1, 1, make([]byte, 32))
	for _, test := range []struct {
		name  string
		qType dnsmessage.Type
	}{
		{"mail.sender.example", dnsmessage.TypeA},
		{"mail.sender.example", dnsmessage.TypeAAAA},
		{"sender.example", dnsmessage.TypeMX},
		{"25.2.0.192.in-addr.arpa", dnsmessage.TypePTR},
		{"_25._tcp.mx.network.root.example", MailZoneTypeTlsa},
	} {
		response, usable := zone.Forward(ctx, test.qType, test.name)
		if !usable {
			t.Fatalf("%s %s unusable", test.name, test.qType)
		}
		header, answers := testMailZoneAnswer(t, response)
		if header.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 || answers[0].Header.Type != test.qType {
			t.Errorf("%s %s: %v %+v", test.name, test.qType, header.RCode, answers)
		}
	}
	if got := MailZoneReverseName(netip.MustParseAddr("2001:db8::25")); !strings.HasPrefix(got, "5.2.0.0.") || !strings.HasSuffix(got, ".8.b.d.0.1.0.0.2.ip6.arpa") {
		t.Errorf("reverse name %s", got)
	}

	if response, usable := zone.Forward(ctx, dnsmessage.TypeTXT, "absent.example"); !usable || testMailZoneRcode(t, response) != dnsmessage.RCodeNameError {
		t.Error("an absent name is not NXDOMAIN")
	}
	if response, usable := zone.Forward(ctx, dnsmessage.TypeMX, "mail.sender.example"); !usable || testMailZoneRcode(t, response) != dnsmessage.RCodeSuccess {
		t.Error("another type of a known name is not NODATA")
	}
	zone.Fail("sender.example", dnsmessage.TypeMX, FakeMailZoneServFail)
	if response, _ := zone.Forward(ctx, dnsmessage.TypeMX, "sender.example"); testMailZoneRcode(t, response) != dnsmessage.RCodeServerFailure {
		t.Error("a scripted SERVFAIL")
	}
	zone.Fail("sender.example", dnsmessage.TypeMX, FakeMailZoneTruncated)
	if response, _ := zone.Forward(ctx, dnsmessage.TypeMX, "sender.example"); !testMailZoneTruncated(t, response) {
		t.Error("a scripted truncation")
	}
	zone.Fail("sender.example", dnsmessage.TypeMX, FakeMailZoneUnusable)
	if _, usable := zone.Forward(ctx, dnsmessage.TypeMX, "sender.example"); usable {
		t.Error("a scripted unusable answer")
	}
	zone.Fail("sender.example", dnsmessage.TypeMX, FakeMailZoneMalformed)
	if response, usable := zone.Forward(ctx, dnsmessage.TypeMX, "sender.example"); !usable || testMailZoneParses(response) {
		t.Error("a scripted malformed answer parses")
	}
	zone.Fail("sender.example", dnsmessage.TypeMX, FakeMailZoneHang)
	hangCtx, cancel := context.WithCancel(ctx)
	hung := make(chan bool, 1)
	go func() {
		_, usable := zone.Forward(hangCtx, dnsmessage.TypeMX, "sender.example")
		hung <- usable
	}()
	if err := zone.AwaitInFlight(ctx, 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	if <-hung {
		t.Error("a hung lookup answered once its caller left")
	}
}

func testMailZoneRcode(t *testing.T, response []byte) dnsmessage.RCode {
	t.Helper()
	header, _ := testMailZoneAnswer(t, response)
	return header.RCode
}

func testMailZoneTruncated(t *testing.T, response []byte) bool {
	t.Helper()
	header, _ := testMailZoneAnswer(t, response)
	return header.Truncated
}

func testMailZoneParses(response []byte) bool {
	var parser dnsmessage.Parser
	if _, err := parser.Start(response); err != nil {
		return false
	}
	return parser.SkipAllQuestions() == nil
}

// Nine lookups at once all wait at the zone, which counts them: the zone limits nothing, so a budget's
// own limit is what a test sees.
func TestFakeMailZoneCountsWhatWaitsAtOnce(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	zone := NewFakeMailZone(clock)
	done := make(chan struct{}, 9)
	for index := range 9 {
		name := fmt.Sprintf("s%d._domainkey.sender.example", index)
		zone.AddTxt(name, "v=DKIM1")
		zone.SetDelay(name, time.Second)
		go func() {
			zone.Forward(ctx, dnsmessage.TypeTXT, name)
			done <- struct{}{}
		}()
	}
	if err := zone.AwaitInFlight(ctx, 9); err != nil {
		t.Fatal(err)
	}
	if err := clock.AwaitTimers(ctx, 9); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	for range 9 {
		<-done
	}
	if zone.MaxInFlight() != 9 || len(zone.Queries()) != 9 {
		t.Fatalf("%d at once of %d", zone.MaxInFlight(), len(zone.Queries()))
	}
}

// A self-signed certificate for a stub server.
func testMailServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.network.root.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"mx.network.root.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// What a stub server saw.
type testMailStubSession struct {
	proxyLine  string
	commands   []string
	serverName string
	version    uint16
	messages   [][]byte
	cut        bool
}

// A stub SMTP server on one connection, enough of RFC 5321, 3207 and 3030 for the MTA's steps: it answers
// 530 to MAIL before STARTTLS, reads DATA to its end and BDAT by size, and notes a close mid-message.
func testMailStubServe(t *testing.T, conn net.Conn, certificate tls.Certificate, expectProxy bool, session *testMailStubSession, done chan<- struct{}) {
	defer close(done)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(text string) { conn.Write([]byte(text)) }
	if expectProxy {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		session.proxyLine = line
	}
	write("220 mx.network.root.example ESMTP\r\n")
	secured := false
	// a BDAT message under way, its LAST not yet seen
	bdatOpen := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimRight(line, "\r\n")
		session.commands = append(session.commands, command)
		verb := strings.ToUpper(strings.SplitN(command, " ", 2)[0])
		switch verb {
		case "EHLO":
			write("250-mx.network.root.example\r\n250-STARTTLS\r\n250-CHUNKING\r\n250 ENHANCEDSTATUSCODES\r\n")
		case "STARTTLS":
			write("220 2.0.0 Ready to start TLS\r\n")
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					session.serverName = hello.ServerName
					return nil, nil
				},
			})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			session.version = tlsConn.ConnectionState().Version
			conn = tlsConn
			reader = bufio.NewReader(tlsConn)
			secured = true
		case "MAIL":
			if !secured {
				write("530 5.7.0 Must issue a STARTTLS command first\r\n")
				continue
			}
			write("250 2.1.0 OK\r\n")
		case "RCPT":
			write("250 2.1.5 OK\r\n")
		case "DATA":
			write("354 Go ahead\r\n")
			var message strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					session.cut = true
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				message.WriteString(strings.TrimPrefix(dataLine, "."))
			}
			session.messages = append(session.messages, []byte(message.String()))
			write("250 2.0.0 Queued\r\n")
		case "BDAT":
			parts := strings.Fields(command)
			size := 0
			fmt.Sscanf(parts[1], "%d", &size)
			chunk := make([]byte, size)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				session.cut = true
				return
			}
			if !bdatOpen {
				session.messages = append(session.messages, nil)
				bdatOpen = true
			}
			last := len(session.messages) - 1
			session.messages[last] = append(session.messages[last], chunk...)
			if 2 < len(parts) && strings.EqualFold(parts[2], "LAST") {
				bdatOpen = false
			}
			write("250 2.0.0 Chunk OK\r\n")
		case "QUIT":
			write("221 2.0.0 Bye\r\n")
			return
		default:
			write("502 5.5.1 Unrecognized\r\n")
		}
	}
}

// The MTA's whole path against the stub, on TLS 1.2 without SNI and TLS 1.3 with it, by DATA and by
// BDAT: the PROXY line, a multi-line EHLO, STARTTLS, a transaction, QUIT.
func TestScriptedMtaAgainstAStubServer(t *testing.T) {
	certificate := testMailServerCertificate(t)
	for _, test := range []struct {
		serverName string
		version    uint16
		bdat       bool
	}{
		{"", tls.VersionTLS12, false},
		{"mx.network.root.example", tls.VersionTLS13, true},
	} {
		serverConn, clientConn := net.Pipe()
		session := &testMailStubSession{}
		done := make(chan struct{})
		go testMailStubServe(t, serverConn, certificate, true, session, done)
		mta := NewScriptedMta(clientConn)
		source := netip.MustParseAddrPort("198.51.100.7:40000")
		if err := mta.WriteProxyV1(source, netip.MustParseAddrPort("203.0.113.1:25")); err != nil {
			t.Fatal(err)
		}
		if banner, err := mta.Banner(); err != nil || !banner.Is(220) {
			t.Fatalf("banner %s, %v", banner, err)
		}
		ehlo, err := mta.Ehlo("relay.sender.example")
		if err != nil || !ehlo.Is(250) || len(ehlo.Lines) != 4 || ehlo.Lines[1] != "STARTTLS" {
			t.Fatalf("EHLO %s, %v", ehlo, err)
		}
		state, err := mta.StartTls(MailMtaTlsConfig(test.serverName, test.version))
		if err != nil || state.Version != test.version {
			t.Fatalf("STARTTLS %+v, %v", state, err)
		}
		if reply, err := mta.Ehlo("relay.sender.example"); err != nil || !reply.Is(250) {
			t.Fatalf("EHLO after TLS %s, %v", reply, err)
		}
		if reply, err := mta.MailFrom("sender@sender.example"); err != nil || !reply.Is(250) {
			t.Fatalf("MAIL %s, %v", reply, err)
		}
		if reply, err := mta.RcptTo("receiver@mx.network.root.example"); err != nil || !reply.Is(250) {
			t.Fatalf("RCPT %s, %v", reply, err)
		}
		message := append(slices.Clone(testMailMessage), []byte(".a line that starts with a dot\r\n")...)
		var reply *MailReply
		if test.bdat {
			reply, err = mta.Bdat(message, 64)
		} else {
			reply, err = mta.Data(message)
		}
		if err != nil || !reply.Is(250) {
			t.Fatalf("the message %s, %v", reply, err)
		}
		if reply, err := mta.Quit(); err != nil || !reply.Is(221) {
			t.Fatalf("QUIT %s, %v", reply, err)
		}
		<-done
		if session.proxyLine != "PROXY TCP4 198.51.100.7 203.0.113.1 40000 25\r\n" {
			t.Errorf("PROXY %q", session.proxyLine)
		}
		if session.serverName != test.serverName || session.version != test.version {
			t.Errorf("the stub saw SNI %q on %x", session.serverName, session.version)
		}
		if len(session.messages) != 1 || string(session.messages[0]) != string(message) {
			t.Errorf("the stub got %q", session.messages)
		}
	}
}

// A plaintext transaction gets the stub's 530, pipelined bytes arrive in one write, and a close in
// mid-message leaves the stub with no message.
func TestScriptedMtaPlaintextPipeliningAndACut(t *testing.T) {
	certificate := testMailServerCertificate(t)
	serverConn, clientConn := net.Pipe()
	session := &testMailStubSession{}
	done := make(chan struct{})
	go testMailStubServe(t, serverConn, certificate, false, session, done)
	mta := NewScriptedMta(clientConn)
	if _, err := mta.Banner(); err != nil {
		t.Fatal(err)
	}
	if reply, err := mta.PlaintextTransaction("sender@sender.example"); err != nil || !reply.Is(530) {
		t.Fatalf("plaintext MAIL %s, %v", reply, err)
	}
	if err := mta.Write("NOOP\r\nNOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if reply, err := mta.ReadReply(); err != nil || !reply.Is(502) {
			t.Fatalf("a pipelined command %s, %v", reply, err)
		}
	}
	if _, err := mta.StartTls(MailMtaTlsConfig("", tls.VersionTLS13)); err != nil {
		t.Fatal(err)
	}
	if _, err := mta.MailFrom("sender@sender.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := mta.RcptTo("receiver@mx.network.root.example"); err != nil {
		t.Fatal(err)
	}
	if err := mta.DataCutAt(testMailMessage, 40); err != nil {
		t.Fatal(err)
	}
	<-done
	if !session.cut || len(session.messages) != 0 {
		t.Fatalf("cut %t, messages %d", session.cut, len(session.messages))
	}
}

// The published key of a selector, read back from the zone as a verifier would read it.
func testMailZoneKey(t *testing.T, zone *FakeMailZone, selector string, domain string) crypto.PublicKey {
	t.Helper()
	response, usable := zone.Forward(context.Background(), dnsmessage.TypeTXT, MailDkimKeyName(selector, domain))
	if !usable {
		t.Fatalf("no key for %s", selector)
	}
	_, answers := testMailZoneAnswer(t, response)
	if len(answers) != 1 {
		t.Fatalf("%d records for %s", len(answers), selector)
	}
	record := strings.Join(answers[0].Body.(*dnsmessage.TXTResource).TXT, "")
	_, encoded, _ := strings.Cut(record, "p=")
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(record, "k=ed25519") {
		return ed25519.PublicKey(der)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Verifies each DKIM signature of a corpus message against its published key, as FS-121 says it
// verifies or does not.
func testMailCheckCorpus(t *testing.T, zone *FakeMailZone, corpus *MailCorpusMessage) {
	t.Helper()
	fields, body, err := mailSplitMessage(corpus.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signatureFields := []string{}
	for _, field := range fields {
		if mailFieldName(field) == "dkim-signature" {
			signatureFields = append(signatureFields, field)
		}
	}
	if len(signatureFields) != len(corpus.Signatures) {
		t.Fatalf("%s: %d fields for %d signatures", corpus.Name, len(signatureFields), len(corpus.Signatures))
	}
	for index, field := range signatureFields {
		signature := corpus.Signatures[index]
		tags := testMailTags(t, field)
		if tags["d"] != signature.Domain || tags["s"] != signature.Selector {
			t.Fatalf("%s: signature %d is %s/%s, said %s/%s", corpus.Name, index, tags["d"], tags["s"], signature.Domain, signature.Selector)
		}
		if got := mailBodyHash(body, true, MailDkimRsaSha256); got != tags["bh"] {
			t.Fatalf("%s: signature %d's bh=", corpus.Name, index)
		}
		key := testMailZoneKey(t, zone, signature.Selector, signature.Domain)
		err := testMailVerify(t, fields, field, mailSelectFields(fields, strings.Split(tags["h"], ":")), key, true)
		if signature.Valid != (err == nil) {
			t.Errorf("%s: signature %d valid %t, verified %v", corpus.Name, index, signature.Valid, err)
		}
		aligned := signature.Domain == corpus.FromDomain || strings.HasSuffix(signature.Domain, "."+corpus.FromDomain)
		if signature.Aligned != aligned {
			t.Errorf("%s: signature %d aligned %t", corpus.Name, index, signature.Aligned)
		}
	}
}

// FS-121's corpus as FS-121 describes it: 64 signatures with distinct maximal identifiers, every key
// name at 253 bytes and every selector at 63; chains of 8, 12 and 51 sets and one missing instance 3; a
// valid aligned signature above 3 invalid ones; a spoofed From with 9 aligned bogus signatures.
func TestMailCorpusIsFs121s(t *testing.T) {
	zone := NewFakeMailZone(NewFakeClock(DefaultClockStart()))
	corpus := NewMailCorpus(zone, time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC))
	maximal, err := corpus.MaximalSignatures(64)
	if err != nil {
		t.Fatal(err)
	}
	domains, selectors := map[string]bool{}, map[string]bool{}
	for _, signature := range maximal.Signatures {
		domains[signature.Domain] = true
		selectors[signature.Selector] = true
		if len(signature.Selector) != 63 || len(MailDkimKeyName(signature.Selector, signature.Domain)) != 253 {
			t.Fatalf("selector %d bytes, key name %d bytes", len(signature.Selector), len(MailDkimKeyName(signature.Selector, signature.Domain)))
		}
		for label := range strings.SplitSeq(signature.Domain, ".") {
			if label == "" || 63 < len(label) {
				t.Fatalf("a label of %d bytes in %s", len(label), signature.Domain)
			}
		}
	}
	if len(maximal.Signatures) != 64 || len(domains) != 64 || len(selectors) != 64 {
		t.Fatalf("%d signatures, %d domains, %d selectors", len(maximal.Signatures), len(domains), len(selectors))
	}
	testMailCheckCorpus(t, zone, maximal)

	for _, test := range []struct {
		setCount   int
		gapAt      int
		failNewest bool
	}{{8, 0, false}, {12, 0, false}, {51, 0, false}, {8, 3, false}, {8, 0, true}} {
		chain, err := corpus.ArcChain(test.setCount, test.gapAt, test.failNewest)
		if err != nil {
			t.Fatal(err)
		}
		sets := testMailArcSets(t, chain.Bytes)
		if len(sets) != test.setCount || (test.gapAt != 0 && sets[test.gapAt] != nil) {
			t.Errorf("%s: %d sets", chain.Name, len(sets))
		}
		testMailCheckCorpus(t, zone, chain)
	}

	aligned, err := corpus.AlignedAfterInvalid(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(aligned.Signatures) != 4 || !aligned.Signatures[0].Valid || aligned.Signatures[1].Valid || aligned.Signatures[3].Valid {
		t.Fatalf("aligned after invalid: %+v", aligned.Signatures)
	}
	testMailCheckCorpus(t, zone, aligned)

	spoofed, err := corpus.SpoofedFrom(9)
	if err != nil {
		t.Fatal(err)
	}
	if len(spoofed.Signatures) != 9 {
		t.Fatalf("%d bogus signatures", len(spoofed.Signatures))
	}
	for _, signature := range spoofed.Signatures {
		if signature.Valid || !signature.Aligned {
			t.Fatalf("spoofed %+v", signature)
		}
	}
	testMailCheckCorpus(t, zone, spoofed)
	if response, usable := zone.Forward(context.Background(), dnsmessage.TypeTXT, "_dmarc.bank.example"); !usable || testMailZoneRcode(t, response) != dnsmessage.RCodeSuccess {
		t.Fatal("no DMARC record for the spoofed domain")
	}
}
