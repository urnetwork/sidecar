// The planner on fixed inputs (DESIGN-DETAILS 3.2.4, 3.2.6, 3.6's SMTP-M9-39 row): whole sends through the
// prover, the real gate and the scripted MX, counted in units, the parts the gate verified; the envelope in
// groups, a group's replies overflowing the msg part into an env part, a reply record no shape holds ending
// in EnvelopeRetry, groups that follow public values alone, and the message's parts proven several at once
// and submitted in index order. The MX writes each reply in a record of its own, 3.2.6's worst packing.

package smtpproof

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A header block of exactly byteCount octets: testHeaderBlock's fields, where the first record holds them
// (SMTP-M9-04's order), then filler lines to the length.
func testHeaderBlockOf(t *testing.T, byteCount int) string {
	t.Helper()
	base := strings.TrimSuffix(testHeaderBlock(), "\r\n")
	fill := byteCount - len(base) - len("\r\n")
	const prefix = "X-Padding: "
	lineMin := len(prefix) + 1 + len("\r\n")
	if fill != 0 && fill < lineMin {
		t.Fatalf("a header block of %d octets has no room for a filler line", byteCount)
	}
	var block strings.Builder
	block.WriteString(base)
	lineCount := (fill + 77) / 78
	for i := range lineCount {
		size := fill / lineCount
		if i < fill%lineCount {
			size += 1
		}
		block.WriteString(prefix + strings.Repeat("a", size-lineMin+1) + "\r\n")
	}
	block.WriteString("\r\n")
	if block.Len() != byteCount {
		t.Fatalf("a header block of %d octets, want %d", block.Len(), byteCount)
	}
	return block.String()
}

// recipientCount recipients whose RCPT records are each 47 octets, as 3.2.6's table counts them.
func testPlanRecipients(recipientCount int) []string {
	recipients := make([]string, 0, recipientCount)
	for i := range recipientCount {
		recipients = append(recipients, fmt.Sprintf("recipient-%07d", i))
	}
	return recipients
}

// A job of a header block of headerBytes octets, a body, and recipientCount recipients.
func testPlanJob(t *testing.T, recipientCount int, headerBytes int, body string) *sidecar.SmtpProofJob {
	t.Helper()
	job := testJob("", testPlanRecipients(recipientCount)...)
	job.Message = []byte(testHeaderBlockOf(t, headerBytes) + body)
	job.Preamble.MessageByteCount = uint64(len(job.Message))
	return job
}

func TestRcptRecordsAreTheTablesLength(t *testing.T) {
	command := literalRcptPrefix + testPlanRecipients(1)[0] + "@" + testRecipientDomain + ">" + literalCrlf
	if len(command) != 47 {
		t.Fatalf("an RCPT record of %d octets, want 3.2.6's 47", len(command))
	}
}

// A send's units on a leg, BDAT unless data.
type testPlanCase struct {
	recipientCount int
	headerBytes    int
	// By leg: tls13 aes, tls13 chacha, tls12 aes.
	units [3]int
}

// 3.2.6's unit counts for the landed catalog: 1 for the key part, the envelope's groups (AES 13 commands a
// group, MAIL among the first; ChaCha20 19), 1 when the last group's replies overflow the msg part, and one
// a header record by split, whose first is the msg part's. Two rows differ from 3.2.6's table, whose
// msg-chacha20 shape holds 12 server blocks where the landed one holds 13 (SMTP-M9-37's fill): 12
// recipients under ChaCha20 fit three units, and 50 recipients' last group of 13 replies fits the msg part.
var testPlanCases = []*testPlanCase{
	{recipientCount: 1, headerBytes: 831, units: [3]int{3, 3, 3}},
	{recipientCount: 1, headerBytes: 832, units: [3]int{4, 3, 3}},
	{recipientCount: 1, headerBytes: 4095, units: [3]int{6, 5, 6}},
	{recipientCount: 1, headerBytes: 16383, units: [3]int{16, 10, 16}},
	{recipientCount: 10, headerBytes: 831, units: [3]int{3, 3, 3}},
	{recipientCount: 10, headerBytes: 832, units: [3]int{4, 3, 3}},
	{recipientCount: 10, headerBytes: 4095, units: [3]int{6, 5, 6}},
	{recipientCount: 10, headerBytes: 16383, units: [3]int{16, 10, 16}},
	{recipientCount: 12, headerBytes: 831, units: [3]int{3, 3, 3}},
	{recipientCount: 12, headerBytes: 832, units: [3]int{4, 3, 3}},
	{recipientCount: 12, headerBytes: 4095, units: [3]int{6, 5, 6}},
	{recipientCount: 12, headerBytes: 16383, units: [3]int{16, 10, 16}},
	{recipientCount: 13, headerBytes: 831, units: [3]int{4, 4, 4}},
	{recipientCount: 13, headerBytes: 832, units: [3]int{5, 4, 4}},
	{recipientCount: 13, headerBytes: 4095, units: [3]int{7, 6, 7}},
	{recipientCount: 13, headerBytes: 16383, units: [3]int{17, 11, 17}},
	{recipientCount: 50, headerBytes: 831, units: [3]int{6, 5, 6}},
	{recipientCount: 50, headerBytes: 832, units: [3]int{7, 5, 6}},
	{recipientCount: 50, headerBytes: 4095, units: [3]int{9, 7, 9}},
	{recipientCount: 50, headerBytes: 16383, units: [3]int{19, 12, 19}},
	{recipientCount: 100, headerBytes: 831, units: [3]int{10, 8, 10}},
	{recipientCount: 100, headerBytes: 832, units: [3]int{11, 8, 10}},
	{recipientCount: 100, headerBytes: 4095, units: [3]int{13, 10, 13}},
	{recipientCount: 100, headerBytes: 16383, units: [3]int{23, 15, 23}},
}

// Every part the gate verified finds a production shape, and the MX took the message whole.
func testExpectPlannedSend(t *testing.T, name string, leg *testTlsLeg, send *testSend, job *sidecar.SmtpProofJob) {
	t.Helper()
	testExpectOneTransaction(t, leg, send, job)
	for _, statement := range send.backend.statements {
		if _, err := partShapeFor(DefaultProofSettings(), statement); err != nil {
			t.Errorf("%s: part %d: %v", name, statement.index, err)
		}
	}
}

func TestThePlannersUnitsFollowTheSend(t *testing.T) {
	for i, leg := range testTlsLegs() {
		for _, c := range testPlanCases {
			name := fmt.Sprintf("%s, %d recipients, a header block of %d octets", leg.name, c.recipientCount, c.headerBytes)
			job := testPlanJob(t, c.recipientCount, c.headerBytes, "a body line\r\n")
			send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
			testExpectPlannedSend(t, name, leg, send, job)
			if got := len(send.edge.parts); got != c.units[i] {
				t.Errorf("%s: %d units, want %d", name, got, c.units[i])
			}
		}
	}
}

func TestThePlannersUnitsFollowADataSend(t *testing.T) {
	// 3.2.6's DATA row: the gate's header block, 10 recipients, 100 KiB in all; one unit a body record of
	// the body shape, 1,295 octets under AES-128-GCM (1,296 in 1.2) and 2,559 under ChaCha20
	settings := DefaultProverSettings()
	settings.ForceData = true
	for i, leg := range testTlsLegs() {
		job := testPlanJob(t, 10, 4095, "")
		// whole lines to 100 KiB, the last one shorter
		const line = "a line of the body, whole, no dot first, ending CRLF as DATA's lines do\r\n"
		left := 100*1024 - len(job.Message)
		body := strings.Repeat(line, left/len(line)-1)
		body += strings.Repeat("b", left-len(body)-len("\r\n")) + "\r\n"
		job.Message = append(job.Message, body...)
		job.Preamble.MessageByteCount = uint64(len(job.Message))
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectPlannedSend(t, leg.name+" DATA", leg, send, job)
		if want := [3]int{82, 44, 82}[i]; len(send.edge.parts) != want {
			t.Errorf("%s: %d units, want %d", leg.name, len(send.edge.parts), want)
		}
	}
}

func TestTheLastGroupsRepliesOverflowTheMsgPartIntoAnEnvPart(t *testing.T) {
	// replies of 33 octets take 3 AES blocks each, and the msg shape holds 17, so the last group's 13
	// replies go in an env part that opens no client record, and the msg part covers none (X = 1)
	mxSettings := testMxDefaults()
	mxSettings.rcptTaken = "250 2.1.5 Ok, the recipient is taken"
	leg := testTlsLegs()[0]
	job := testPlanJob(t, 12, 831, "a body line\r\n")
	send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
	testExpectPlannedSend(t, "overflow", leg, send, job)
	parts := send.edge.parts
	if len(parts) != 4 {
		t.Fatalf("%d parts, want key, env, the env over the replies, msg", len(parts))
	}
	cover, message := parts[2], parts[3]
	if len(cover.Records) != 0 || cover.ReplyCount != 13 || cover.ServerRecordCount <= parts[1].ServerRecordCount {
		t.Errorf("the env part over the replies: %+v", cover)
	}
	if message.ReplyCount != 0 || message.ServerRecordCount != cover.ServerRecordCount || message.HeaderRecordCount != 1 {
		t.Errorf("the msg part: %+v", message)
	}
}

func TestAReplyRecordThatFitsNoShapeEndsInEnvelopeRetry(t *testing.T) {
	// one RCPT reply in one record longer than an env part's server blocks hold, on every leg: no part can
	// cover it, so the connection ends before any message record and the sender retries (3.5)
	mxSettings := testMxDefaults()
	mxSettings.rcptTaken = "250 2.1.5 " + strings.Repeat("x", 1300)
	for _, leg := range testTlsLegs() {
		job := testPlanJob(t, 1, 831, "a body line\r\n")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if !send.result.EnvelopeRetry || send.result.Accepted || send.result.Mode != partModeBdat {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
		for _, command := range send.mx.seen() {
			if strings.HasPrefix(command, "BDAT") || strings.HasPrefix(command, "From:") {
				t.Errorf("%s: %q reached the MX", leg.name, command)
			}
		}
		if !slices.Equal(send.result.RecipientReplyCodes, []uint32{250}) {
			t.Errorf("%s: recipient codes %v", leg.name, send.result.RecipientReplyCodes)
		}
	}
}

func TestTheEnvelopeGroupMaxBoundsEachGroup(t *testing.T) {
	// the sender's retry after EnvelopeRetry names one command a group: each env part opens one, and
	// covers the reply to the one before
	leg := testTlsLegs()[0]
	job := testPlanJob(t, 3, 831, "a body line\r\n")
	job.EnvelopeGroupMaxCount = 1
	send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
	testExpectPlannedSend(t, "one a group", leg, send, job)
	parts := send.edge.parts
	if len(parts) != 6 {
		t.Fatalf("%d parts, want key, four env parts and msg", len(parts))
	}
	for i, part := range parts[1:5] {
		want := uint32(1)
		if len(part.Records) != 1 || part.ReplyCount != want {
			t.Errorf("env part %d: %d records, %d replies", i+2, len(part.Records), part.ReplyCount)
		}
	}
	if parts[5].ReplyCount != 1 {
		t.Errorf("the msg part covers %d replies", parts[5].ReplyCount)
	}

	// the settings' bound, where the job names none, does the same at two
	settings := DefaultProverSettings()
	settings.EnvelopeGroupMaxCount = 2
	job = testPlanJob(t, 3, 831, "a body line\r\n")
	send = testRunSend(t, leg, testMxDefaults(), settings, job)
	testExpectPlannedSend(t, "two a group", leg, send, job)
	if len(send.edge.parts) != 4 || len(send.edge.parts[1].Records) != 2 || len(send.edge.parts[2].Records) != 2 {
		t.Errorf("%d parts", len(send.edge.parts))
	}
}

// What the edge sees of a send's parts: every public field, and each record's length.
func testPublicParts(parts []*sidecar.SmtpProofPart) []string {
	var publics []string
	for _, part := range parts {
		var lengths []int
		for _, record := range part.Records {
			lengths = append(lengths, len(record))
		}
		publics = append(publics, fmt.Sprintf("index %d mode %d records %d-%d %v last %t server %d replies %d k %d key %d carry %d",
			part.Index, part.Mode, part.FirstRecord, part.LastRecord, lengths, part.Last, part.ServerRecordCount,
			part.ReplyCount, part.HeaderRecordCount, len(part.KeyCommitment), len(part.Carry)))
	}
	return publics
}

func TestEnvelopeGroupsAreAFunctionOfPublicValues(t *testing.T) {
	// 3.3's K3: two sends whose addresses and replies differ in every octet the edge cannot read, and in no
	// length, take the same parts; a send whose replies are longer takes other groups, by the lengths alone
	recipients := func(letter string) []string {
		var locals []string
		for i := range 40 {
			locals = append(locals, fmt.Sprintf("%s-%015d", letter, i))
		}
		return locals
	}
	legs := testTlsLegs()
	for _, leg := range []*testTlsLeg{legs[0], legs[2]} {
		var structures [][]string
		for _, c := range []struct {
			letter string
			taken  string
		}{
			{letter: "a", taken: "250 2.1.5 Ok, taken: alpha"},
			{letter: "b", taken: "250 2.1.5 Ok, taken: bravo"},
			{letter: "c", taken: "250 2.1.5 Ok, the recipient is taken, and this reply is long"},
		} {
			mxSettings := testMxDefaults()
			mxSettings.rcptTaken = c.taken
			job := testJob("", recipients(c.letter)...)
			job.Message = []byte(testHeaderBlockOf(t, 2000) + "a body line\r\n")
			job.Preamble.MessageByteCount = uint64(len(job.Message))
			send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
			testExpectPlannedSend(t, leg.name+" "+c.letter, leg, send, job)
			structures = append(structures, testPublicParts(send.edge.parts))
		}
		if !slices.Equal(structures[0], structures[1]) {
			t.Errorf("%s: equal lengths, other parts:\n%s\n%s", leg.name, strings.Join(structures[0], "\n"), strings.Join(structures[1], "\n"))
		}
		if slices.Equal(structures[0], structures[2]) {
			t.Errorf("%s: longer replies, the same parts", leg.name)
		}
	}
}

func TestTheResultCarriesEveryReplyCode(t *testing.T) {
	leg := testTlsLegs()[0]
	job := testJob("one line\r\n", "bob", "carol")
	send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
	testExpectOneTransaction(t, leg, send, job)
	// EHLO's, MAIL's, each RCPT's and the message's, in the order read
	if !slices.Equal(send.result.ReplyCodes, []uint32{250, 250, 250, 250, 250}) || !slices.Equal(send.result.RecipientReplyCodes, []uint32{250, 250}) {
		t.Errorf("codes %v, recipients %v", send.result.ReplyCodes, send.result.RecipientReplyCodes)
	}

	// a refused recipient is named beside the one taken
	mxSettings := testMxDefaults()
	mxSettings.rcptReplies["carol"] = "550 5.1.1 No such user"
	job = testJob("one line\r\n", "bob", "carol", "dave")
	send = testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
	if send.err != nil || send.result.RefusedCode != "550" {
		t.Fatalf("%+v, %v", send.result, send.err)
	}
	if !slices.Equal(send.result.RecipientReplyCodes, []uint32{250, 550, 250}) || !slices.Equal(send.result.ReplyCodes, []uint32{250, 250, 250, 550, 250}) {
		t.Errorf("codes %v, recipients %v", send.result.ReplyCodes, send.result.RecipientReplyCodes)
	}

	// without PIPELINING the first refusal sends no more, and a recipient no reply named is 0
	mxSettings.keywords = []string{"CHUNKING"}
	job = testJob("one line\r\n", "bob", "carol", "dave")
	send = testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
	if send.err != nil || send.result.RefusedCode != "550" {
		t.Fatalf("%+v, %v", send.result, send.err)
	}
	if !slices.Equal(send.result.RecipientReplyCodes, []uint32{250, 550, 0}) {
		t.Errorf("recipients %v", send.result.RecipientReplyCodes)
	}

	// a refused MAIL: with PIPELINING the RCPT went with it and has the MX's answer, and without it the
	// RCPT never went and no recipient is named
	mxSettings = testMxDefaults()
	mxSettings.mailReply = "550 5.7.1 Refused"
	send = testRunSend(t, leg, mxSettings, DefaultProverSettings(), testJob("one line\r\n", "bob"))
	if send.err != nil || send.result.RefusedCode != "550" || !slices.Equal(send.result.RecipientReplyCodes, []uint32{503}) {
		t.Errorf("%+v, %v", send.result, send.err)
	}
	mxSettings.keywords = []string{"CHUNKING"}
	send = testRunSend(t, leg, mxSettings, DefaultProverSettings(), testJob("one line\r\n", "bob"))
	if send.err != nil || send.result.RefusedCode != "550" || send.result.RecipientReplyCodes != nil || !slices.Equal(send.result.ReplyCodes, []uint32{250, 550}) {
		t.Errorf("%+v, %v", send.result, send.err)
	}
}

// Holds the message's proofs until released, and counts how many run at once.
type testConcurrentBackend struct {
	inner   *testWitnessBackend
	target  int
	reached chan struct{}
	release chan struct{}

	stateLock   sync.Mutex
	inFlight    int
	maxInFlight int
}

func (self *testConcurrentBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	kind, err := partKindOf(statement, roles)
	if err != nil {
		return nil, err
	}
	if kind == partKindMessage || kind == partKindHeader || kind == partKindBody {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.inFlight += 1
			self.maxInFlight = max(self.maxInFlight, self.inFlight)
			if self.inFlight == self.target {
				close(self.reached)
			}
		}()
		select {
		case <-self.release:
		case <-ctx.Done():
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.inFlight -= 1
		}()
	}
	return self.inner.provePart(ctx, statement, witness)
}

func TestTheMessagesPartsProveTogetherAndGoInIndexOrder(t *testing.T) {
	// a header block of four records is the msg part and three hdr parts, whose statements are complete
	// once their records are sealed, so three prove at once; the gate takes them only in index order, so a
	// send it accepts went in that order
	leg := testTlsLegs()[0]
	settings := DefaultProverSettings()
	settings.ProveConcurrency = 3
	backend := &testConcurrentBackend{inner: newTestWitnessBackend(), target: 3, reached: make(chan struct{}), release: make(chan struct{})}
	job := testPlanJob(t, 2, 4095, "a body line\r\n")
	sent := make(chan *testSend, 1)
	go func() {
		sent <- testRunSendWith(t, leg, testMxDefaults(), settings, job, backend, backend.inner)
	}()
	select {
	case <-backend.reached:
	case <-time.After(time.Minute):
		t.Fatal("three of the message's parts never proved at once")
	}
	close(backend.release)
	send := <-sent
	send.backend = backend.inner
	testExpectPlannedSend(t, "three at once", leg, send, job)
	if backend.maxInFlight != 3 {
		t.Errorf("%d proofs at once, want 3", backend.maxInFlight)
	}
	for i, part := range send.edge.parts {
		if part.Index != uint32(i+1) {
			t.Errorf("part %d went in as %d", i+1, part.Index)
		}
	}
}

func TestEnvelopeGroupSizeFollowsTheRule(t *testing.T) {
	proof := DefaultProofSettings()
	aes := proof.shape(ShapeKindEnvelope, ShapeFamilyAes128Gcm, 0)
	chacha := proof.shape(ShapeKindEnvelope, ShapeFamilyChacha20, 0)
	rcpts := func(count int, byteCount int) []int {
		sizes := make([]int, count)
		for i := range sizes {
			sizes[i] = byteCount
		}
		return sizes
	}
	for _, c := range []struct {
		name     string
		shape    *ShapeSettings
		version  uint16
		commands []int
		estimate int
		groupMax int
		want     int
	}{
		// 47-octet records take 3 AES blocks: 13 fill 40; 40-octet replies take 3, 13 fill 40
		{name: "aes 1.3 table", shape: aes, version: tlsVersion13, commands: rcpts(100, 47), estimate: 40, want: 13},
		{name: "aes 1.2 table", shape: aes, version: tlsVersion12, commands: rcpts(100, 47), estimate: 40, want: 13},
		// short records: the server blocks bind, 40 / ceil(41 / 16)
		{name: "aes short", shape: aes, version: tlsVersion13, commands: rcpts(100, 20), estimate: 40, want: 13},
		// a later group's estimate of 22 takes 2 blocks: 20 by the server, 20 by 2-block records
		{name: "aes later", shape: aes, version: tlsVersion13, commands: rcpts(100, 20), estimate: 22, want: 20},
		// ChaCha20: one 64-octet block a record either way; 19 server blocks bind
		{name: "chacha table", shape: chacha, version: tlsVersion13, commands: rcpts(100, 47), estimate: 40, want: 19},
		{name: "chacha long", shape: chacha, version: tlsVersion13, commands: rcpts(100, 64), estimate: 40, want: 10},
		{name: "fewer left", shape: aes, version: tlsVersion13, commands: rcpts(4, 47), estimate: 40, want: 4},
		{name: "the bound", shape: aes, version: tlsVersion13, commands: rcpts(100, 47), estimate: 40, groupMax: 5, want: 5},
		// the longest RCPT, 332 octets, takes 21 AES blocks, so one goes a group
		{name: "the longest", shape: aes, version: tlsVersion13, commands: rcpts(3, 332), estimate: 40, want: 1},
		// a reply estimate no server pool holds lets no command go
		{name: "no room", shape: aes, version: tlsVersion13, commands: rcpts(3, 47), estimate: 40 * 16, want: 0},
	} {
		if got := envelopeGroupSize(c.shape, c.version, c.commands, c.estimate, c.groupMax); got != c.want {
			t.Errorf("%s: %d commands, want %d", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		settingsMax int
		jobMax      int
		want        int
	}{
		{want: 0}, {settingsMax: 4, want: 4}, {jobMax: 1, want: 1}, {settingsMax: 4, jobMax: 1, want: 1}, {settingsMax: 2, jobMax: 5, want: 2},
	} {
		if got := envelopeGroupMax(c.settingsMax, c.jobMax); got != c.want {
			t.Errorf("max of %d and %d: %d, want %d", c.settingsMax, c.jobMax, got, c.want)
		}
	}
}

func TestTheReplyEstimateReadsLengthsAlone(t *testing.T) {
	settings := DefaultProverSettings()
	record := func(version uint16, contentBytes int) *partRecord {
		overhead := tlsAeadTagBytes + tlsInnerTypeBytes
		if version == tlsVersion12 {
			overhead = tlsAeadTagBytes + tlsExplicitNonceBytes
		}
		return &partRecord{raw: tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, contentBytes+overhead))}
	}
	for _, version := range []uint16{tlsVersion13, tlsVersion12} {
		records := []*partRecord{record(version, 14), record(version, 14), record(version, 15)}
		// 43 octets over 3 replies, rounded up, and the margin
		if got := replyEstimate(settings, version, records, 3); got != 15+8 {
			t.Errorf("version %x: estimate %d", version, got)
		}
		if got := replyEstimate(settings, version, records, 0); got != settings.ReplyEstimateByteCount {
			t.Errorf("version %x: no replies, estimate %d", version, got)
		}
	}
}

func TestReplyCutsFallAtRepliesEnds(t *testing.T) {
	plaintext := func(content string) []byte {
		return append([]byte(content), tlsRecordApplicationData)
	}
	ticket := []byte{tlsHandshakeNewSessionTicket, 0, 0, 0, tlsRecordHandshake}
	plaintexts := [][]byte{
		plaintext("250 2.1.0 Ok\r\n"),
		ticket,
		plaintext("250-first line\r\n"),
		plaintext("250 last line\r\n250 2.1.5 Ok\r\n"),
		plaintext("250 2.1.5"),
		plaintext(" Ok\r\n"),
	}
	want := []int{0, 1, 1, -1, 3, -1, 4}
	if got := replyCuts(tlsVersion13, plaintexts); !slices.Equal(got, want) {
		t.Errorf("cuts %v, want %v", got, want)
	}
}
