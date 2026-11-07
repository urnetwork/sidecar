// §15.4's dialog at the state machine: every row a sender can reach before TLS. service_test.go runs
// the same rows through Serve.

package mxedgeservice_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/mxedgeservice"
)

const (
	testReply530  = "530 5.7.0 Must issue a STARTTLS command first, see " + testDeviationUrl + "\r\n"
	testReply451  = "451 4.7.0 TLS required, try again later\r\n"
	testReply220  = "220 2.0.0 Ready to start TLS\r\n"
	testReplyEhlo = "250-" + testBannerHostName + "\r\n250-ENHANCEDSTATUSCODES\r\n250 STARTTLS\r\n"
)

// A dialog whose memory answers recent, and a count of how often it was asked.
func testDialog(recent bool) (*mxedgeservice.Dialog, *int) {
	asked := 0
	return mxedgeservice.NewDialog(testSettings(), func() bool {
		asked += 1
		return recent
	}, false), &asked
}

// Feeds input as one read and checks what comes back.
func expectReceive(t *testing.T, dialog *mxedgeservice.Dialog, input string, wantReply string, wantStep mxedgeservice.DialogStep) {
	t.Helper()
	reply, step := dialog.Receive([]byte(input))
	if string(reply) != wantReply || step != wantStep {
		t.Fatalf("%q answered %q and step %d, want %q and step %d", input, reply, step, wantReply, wantStep)
	}
}

func TestBannerNamesTheHost(t *testing.T) {
	dialog, _ := testDialog(false)
	if banner := string(dialog.Banner()); banner != "220 "+testBannerHostName+" ESMTP\r\n" {
		t.Errorf("banner %q", banner)
	}
}

func TestEhloOffersStartTlsAndStatusCodes(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO relay.example\r\n", testReplyEhlo, mxedgeservice.DialogStepRead)
	if dialog.EhloName() != "relay.example" {
		t.Errorf("kept %q", dialog.EhloName())
	}
}

func TestEhloNeverOffersPipelining(t *testing.T) {
	dialog, _ := testDialog(false)
	reply, _ := dialog.Receive([]byte("EHLO relay.example\r\n"))
	if bytes.Contains(bytes.ToUpper(reply), []byte("PIPELINING")) {
		t.Errorf("reply %q", reply)
	}
}

func TestHeloAnswersWithNoExtensions(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "HELO relay.example\r\n", "250 "+testBannerHostName+"\r\n", mxedgeservice.DialogStepRead)
	if dialog.EhloName() != "relay.example" {
		t.Errorf("kept %q", dialog.EhloName())
	}
}

func TestLaterEhloReplacesTheName(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "HELO first.example\r\n", "250 "+testBannerHostName+"\r\n", mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "EHLO second.example\r\n", testReplyEhlo, mxedgeservice.DialogStepRead)
	if dialog.EhloName() != "second.example" {
		t.Errorf("kept %q", dialog.EhloName())
	}
}

func TestEhloTakesAnAddressLiteralAndIgnoresWhatFollows(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO   [192.0.2.1] trailing words\r\n", testReplyEhlo, mxedgeservice.DialogStepRead)
	if dialog.EhloName() != "[192.0.2.1]" {
		t.Errorf("kept %q", dialog.EhloName())
	}
}

// A name goes on to MailIngress, where a proto string must be valid UTF-8, and within 1,024 B.
func TestEhloRefusesWhatCannotBeAName(t *testing.T) {
	for _, line := range []string{
		"EHLO\r\n",
		"EHLO \t \r\n",
		"HELO\r\n",
		"EHLO \xff\xfe.example\r\n",
		"EHLO a\x00b\r\n",
		"EHLO \x7f\r\n",
		"EHLO " + strings.Repeat("a", mxedgeservice.EhloNameMaxByteCount+1) + "\r\n",
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, line, "501 5.5.4 Syntax error\r\n", mxedgeservice.DialogStepRead)
		if dialog.EhloName() != "" {
			t.Errorf("%q kept %q", line, dialog.EhloName())
		}
	}
}

func TestEhloTakesANameAtItsLimit(t *testing.T) {
	dialog, _ := testDialog(false)
	name := strings.Repeat("a", mxedgeservice.EhloNameMaxByteCount)
	expectReceive(t, dialog, "EHLO "+name+"\r\n", testReplyEhlo, mxedgeservice.DialogStepRead)
	if dialog.EhloName() != name {
		t.Errorf("kept %q", dialog.EhloName())
	}
}

func TestQuitSaysGoodbyeAndEnds(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "QUIT\r\n", "221 2.0.0 Bye\r\n", mxedgeservice.DialogStepQuit)
}

func TestCommandsReadInAnyCase(t *testing.T) {
	for _, c := range []struct {
		line      string
		wantReply string
		wantStep  mxedgeservice.DialogStep
	}{
		{line: "ehlo a.example\r\n", wantReply: testReplyEhlo, wantStep: mxedgeservice.DialogStepRead},
		{line: "eHlO\ta.example\r\n", wantReply: testReplyEhlo, wantStep: mxedgeservice.DialogStepRead},
		{line: "helo a.example\r\n", wantReply: "250 " + testBannerHostName + "\r\n", wantStep: mxedgeservice.DialogStepRead},
		{line: "quit\r\n", wantReply: "221 2.0.0 Bye\r\n", wantStep: mxedgeservice.DialogStepQuit},
		{line: "starttls\r\n", wantReply: testReply220, wantStep: mxedgeservice.DialogStepTls},
		{line: "StartTLS \t \r\n", wantReply: testReply220, wantStep: mxedgeservice.DialogStepTls},
		{line: "mail from:<a@b.example>\r\n", wantReply: testReply530, wantStep: mxedgeservice.DialogStepRead},
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, c.line, c.wantReply, c.wantStep)
	}
}

func TestStartTlsAnswersAndHandsOver(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO relay.example\r\n", testReplyEhlo, mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
}

func TestStartTlsNeedsNoEhloFirst(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
}

// A sender that writes both at once still gets each answer, in order.
func TestEhloAndStartTlsInOneReadBothAnswer(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO relay.example\r\nSTARTTLS\r\n", testReplyEhlo+testReply220, mxedgeservice.DialogStepTls)
}

func TestStartTlsTakesNoParameter(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "STARTTLS now\r\n", "501 5.5.4 Syntax error\r\n", mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
}

func TestQuitTakesNoParameter(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "QUIT now\r\n", "501 5.5.4 Syntax error\r\n", mxedgeservice.DialogStepRead)
}

// §15.4's plaintext row, each command, with no closed handshake.
func TestPlaintextTransactionGets530LinkingTheDeviation(t *testing.T) {
	for _, line := range []string{
		"MAIL FROM:<a@b.example>\r\n",
		"RCPT TO:<c@d.example>\r\n",
		"DATA\r\n",
		"BDAT 512 LAST\r\n",
		"MAIL\r\n",
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, line, testReply530, mxedgeservice.DialogStepRead)
	}
}

// The same row after a closed handshake.
func TestPlaintextTransactionGets451AfterAClosedHandshake(t *testing.T) {
	for _, line := range []string{
		"MAIL FROM:<a@b.example>\r\n",
		"RCPT TO:<c@d.example>\r\n",
		"DATA\r\n",
		"BDAT 512 LAST\r\n",
	} {
		dialog, _ := testDialog(true)
		expectReceive(t, dialog, line, testReply451, mxedgeservice.DialogStepRead)
	}
}

// Only a transaction reaches the memory, and one session asks once however many it tries.
func TestDialogAsksTheMemoryOncePerSession(t *testing.T) {
	dialog, asked := testDialog(true)
	expectReceive(t, dialog, "EHLO relay.example\r\nNOOP\r\n", testReplyEhlo+"502 5.5.1 Command not implemented\r\n", mxedgeservice.DialogStepRead)
	if *asked != 0 {
		t.Fatalf("asked %d times before a transaction", *asked)
	}
	expectReceive(t, dialog, "MAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\n", testReply451+testReply451, mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "DATA\r\n", testReply451, mxedgeservice.DialogStepRead)
	if *asked != 1 {
		t.Errorf("asked %d times", *asked)
	}
}

// A sender told 530 may still do it properly.
func TestStartTlsStillWorksAfterARefusal(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "MAIL FROM:<a@b.example>\r\n", testReply530, mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
}

// Reading 6.
func TestAnythingElseGets502(t *testing.T) {
	for _, line := range []string{
		"NOOP\r\n",
		"RSET\r\n",
		"VRFY a\r\n",
		"EXPN a\r\n",
		"HELP\r\n",
		"AUTH PLAIN AHRlc3QAdGVzdA==\r\n",
		"\r\n",
		" EHLO a.example\r\n",
		"EHLOX a.example\r\n",
		"MAILFROM:<a@b.example>\r\n",
		"\x16\x03\x01\x02\x00\r\n",
		"GET / HTTP/1.1\r\n",
	} {
		dialog, asked := testDialog(false)
		expectReceive(t, dialog, line, "502 5.5.1 Command not implemented\r\n", mxedgeservice.DialogStepRead)
		if *asked != 0 {
			t.Errorf("%q asked the memory", line)
		}
	}
}

// bytes.EqualFold would read these: U+017F folds to S, and U+212A to K.
func TestOnlyAsciiCaseFolds(t *testing.T) {
	for _, line := range []string{
		"\xc5\xbfTARTTLS\r\n",
		"START\xc5\xbfTLS\r\n",
		"QUIT\xc5\xbf\r\n",
		"\xc5\xbfTARTTL\xc5\xbf\r\n",
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, line, "502 5.5.1 Command not implemented\r\n", mxedgeservice.DialogStepRead)
	}
}

// The CVE-2011-0411 class, in one read.
func TestByteAfterStartTlsResets(t *testing.T) {
	for _, tail := range []string{
		"X",
		"\r\n",
		"RSET\r\n",
		"MAIL FROM:<a@b.example>\r\n",
		"\x16\x03\x01",
		"\x00",
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, "STARTTLS\r\n"+tail, "", mxedgeservice.DialogStepReset)
	}
}

// The reset takes the replies still unwritten with it, so nothing goes out at all.
func TestResetWritesNoEarlierReply(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO relay.example\r\nSTARTTLS\r\nX", "", mxedgeservice.DialogStepReset)
}

// The same, with the stream split at every point: the read that completes the line holds the byte.
func TestByteAfterStartTlsResetsAcrossEverySplit(t *testing.T) {
	stream := "STARTTLS\r\nX"
	for split := 1; split < len(stream)-1; split += 1 {
		dialog, _ := testDialog(false)
		_, step := dialog.Receive([]byte(stream[:split]))
		if step != mxedgeservice.DialogStepRead {
			t.Fatalf("split at %d: first read gave step %d", split, step)
		}
		reply, step := dialog.Receive([]byte(stream[split:]))
		if len(reply) != 0 || step != mxedgeservice.DialogStepReset {
			t.Errorf("split at %d: answered %q and step %d", split, reply, step)
		}
	}
}

// The split the machine cannot see, right after the line, is service_test.go's: the read that catches
// it is outside this machine. Here the machine at least never takes bytes once it has handed over.
func TestDialogIsOverOnceHandedOver(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
	expectReceive(t, dialog, "X", "", mxedgeservice.DialogStepReset)
	expectReceive(t, dialog, "EHLO a.example\r\n", "", mxedgeservice.DialogStepReset)
}

func TestDialogIsOverOnceQuit(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "QUIT\r\n", "221 2.0.0 Bye\r\n", mxedgeservice.DialogStepQuit)
	expectReceive(t, dialog, "EHLO a.example\r\n", "", mxedgeservice.DialogStepReset)
}

// Lines of noise that fill exactly byteCount bytes.
func testNoiseLines(byteCount int) string {
	var builder strings.Builder
	for remaining := byteCount; 0 < remaining; {
		lineByteCount := min(remaining, mxedgeservice.DialogMaxLineByteCount+2)
		// leave the next line room for its CRLF
		if rest := remaining - lineByteCount; 0 < rest && rest < 2 {
			lineByteCount -= 2 - rest
		}
		builder.WriteString(strings.Repeat("N", lineByteCount-2) + "\r\n")
		remaining -= lineByteCount
	}
	return builder.String()
}

// What testNoiseLines is answered.
func testNoiseReplies(lines string) string {
	return strings.Repeat("502 5.5.1 Command not implemented\r\n", strings.Count(lines, "\r\n"))
}

// 2,048 B is within the limit, with its last line answered.
func TestDialogTakes2048Bytes(t *testing.T) {
	lines := testNoiseLines(mxedgeservice.DialogMaxByteCount - len("STARTTLS\r\n"))
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, lines, testNoiseReplies(lines), mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "STARTTLS\r\n", testReply220, mxedgeservice.DialogStepTls)
}

// The 2,049th byte closes, wherever it falls: inside a read or on its own.
func TestDialogCloses2049Bytes(t *testing.T) {
	lines := testNoiseLines(mxedgeservice.DialogMaxByteCount)
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, lines+"N", testNoiseReplies(lines), mxedgeservice.DialogStepClose)

	dialog, _ = testDialog(false)
	expectReceive(t, dialog, lines, testNoiseReplies(lines), mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "N", "", mxedgeservice.DialogStepClose)
}

// A STARTTLS that ends the limit exactly with a byte over it is a byte behind STARTTLS.
func TestByteOverTheLimitBehindStartTlsResets(t *testing.T) {
	lines := testNoiseLines(mxedgeservice.DialogMaxByteCount - len("STARTTLS\r\n"))
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, lines, testNoiseReplies(lines), mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "STARTTLS\r\nX", "", mxedgeservice.DialogStepReset)
}

func TestDialogTakesA510ByteLine(t *testing.T) {
	line := strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount)
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, line+"\r\n", "502 5.5.1 Command not implemented\r\n", mxedgeservice.DialogStepRead)
}

// At 510 B with its CR, a line may yet end well, so it waits.
func TestDialogWaitsOnA510ByteLineAndItsCr(t *testing.T) {
	line := strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount)
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, line+"\r", "", mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "\n", "502 5.5.1 Command not implemented\r\n", mxedgeservice.DialogStepRead)
}

func TestDialogCloses511ByteLine(t *testing.T) {
	line := strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount+1)
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, line+"\r\n", "", mxedgeservice.DialogStepClose)
}

// It closes at the 511th byte, with no need of a line ending to tell.
func TestDialogCloses511ByteLineBeforeItEnds(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount), "", mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "N", "", mxedgeservice.DialogStepClose)
}

func TestDialogCloses511ByteLineWithItsCr(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount+1)+"\r", "", mxedgeservice.DialogStepClose)
}

// RFC 5321 ends a line with CRLF alone, as connect's guard holds, so a bare LF or CR hides no second
// command in one line.
func TestBareLineEndsClose(t *testing.T) {
	for _, stream := range []string{
		"STARTTLS\n",
		"EHLO a.example\n",
		"EHLO a.example\nSTARTTLS\r\n",
		"\n",
		"EHLO a.example\rSTARTTLS\r\n",
		"QUIT\r\r\n",
		"\rX",
	} {
		dialog, _ := testDialog(false)
		expectReceive(t, dialog, stream, "", mxedgeservice.DialogStepClose)
	}
}

// A line that was answered before a broken one keeps its reply.
func TestBrokenLineKeepsEarlierReplies(t *testing.T) {
	dialog, _ := testDialog(false)
	expectReceive(t, dialog, "EHLO a.example\r\nNOOP\n", testReplyEhlo, mxedgeservice.DialogStepClose)
}

func TestPartialLineWaitsForTheRest(t *testing.T) {
	dialog, _ := testDialog(false)
	for _, part := range []string{"E", "HL", "O a.exam", "ple\r"} {
		expectReceive(t, dialog, part, "", mxedgeservice.DialogStepRead)
	}
	expectReceive(t, dialog, "\n", testReplyEhlo, mxedgeservice.DialogStepRead)
}

// No reply carries a byte a sender sent.
func TestRepliesEchoNothing(t *testing.T) {
	canary := "canary-7f3a"
	dialog, _ := testDialog(false)
	for _, line := range []string{
		"EHLO " + canary + "\r\n",
		"HELO " + canary + "\r\n",
		"MAIL FROM:<" + canary + "@b.example>\r\n",
		canary + "\r\n",
		"STARTTLS " + canary + "\r\n",
		"QUIT " + canary + "\r\n",
	} {
		reply, _ := dialog.Receive([]byte(line))
		if bytes.Contains(reply, []byte(canary)) {
			t.Errorf("%q echoed in %q", line, reply)
		}
	}
}

// §15.4's listing row: 554 at the banner, and then RFC 5321 §3.1's rule.
func TestRefusedBannerAnswers554ThenOnlyQuit(t *testing.T) {
	dialog := mxedgeservice.NewDialog(testSettings(), func() bool {
		t.Error("a refused session asked the memory")
		return false
	}, true)
	if banner := string(dialog.Banner()); banner != "554 5.7.1 "+testBannerHostName+" Service refused\r\n" {
		t.Errorf("banner %q", banner)
	}
	for _, line := range []string{"EHLO a.example\r\n", "HELO a.example\r\n", "MAIL FROM:<a@b.example>\r\n", "NOOP\r\n", "STARTTLS\r\n"} {
		expectReceive(t, dialog, line, "503 5.5.1 Bad sequence of commands\r\n", mxedgeservice.DialogStepRead)
	}
	expectReceive(t, dialog, "QUIT\r\n", "221 2.0.0 Bye\r\n", mxedgeservice.DialogStepQuit)
}

// Found by FuzzMxDialog. Only a well-formed QUIT does anything in a refused session, so a malformed one
// is one more command out of sequence, and not a syntax error the session answers as if it were open.
func TestRefusedSessionTakesOnlyAWellFormedQuit(t *testing.T) {
	dialog := mxedgeservice.NewDialog(testSettings(), nil, true)
	expectReceive(t, dialog, "QUIT now\r\n", "503 5.5.1 Bad sequence of commands\r\n", mxedgeservice.DialogStepRead)
	expectReceive(t, dialog, "QUIT \t \r\n", "221 2.0.0 Bye\r\n", mxedgeservice.DialogStepQuit)
}

func TestRefusedSessionKeepsTheDialogsLimits(t *testing.T) {
	dialog := mxedgeservice.NewDialog(testSettings(), nil, true)
	expectReceive(t, dialog, strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount+1), "", mxedgeservice.DialogStepClose)
}
