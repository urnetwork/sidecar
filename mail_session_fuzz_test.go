//go:build !sidecar_http && !js && !ios_extension

// FuzzMailSession (§22.6's receivers row): whatever a sender writes after the handshake, the session ends once the
// sender's side does, every reply is a well-formed SMTP line, no failure becomes go-smtp's generic 554, and every
// deposit that commits is a message and its trailer naming only recipients the sender named, each in its own repo.

package sidecar

import (
	"bufio"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A reply line: a code, then a space or a dash, then text.
var mailSessionFuzzReplyLine = regexp.MustCompile(`^[2-5][0-9][0-9][ -]`)

func FuzzMailSession(f *testing.F) {
	envelope := "EHLO fuzz.example\r\nMAIL FROM:<a@sender.example>\r\nRCPT TO:<" + testMailSessionAlice + ">\r\n"
	f.Add([]byte(envelope + "DATA\r\nSubject: one\r\n\r\nbody\r\n.\r\nQUIT\r\n"))
	f.Add([]byte(envelope + "RCPT TO:<" + testMailSessionBob + ">\r\nRCPT TO:<nobody@lbl0000001.root.example>\r\nBDAT 5 LAST\r\nhelloQUIT\r\n"))
	f.Add([]byte(envelope + "BDAT 3\r\nabcRSET\r\nMAIL FROM:<>\r\nRCPT TO:<" + testMailSessionCarol + ">\r\nBDAT 0 LAST\r\n"))
	f.Add([]byte("MAIL FROM:<a@b>\r\nDATA\r\n.\r\n"))
	f.Add([]byte(envelope + "DATA\r\n" + strings.Repeat("x", 3000) + "\r\n.\r\n"))
	f.Add([]byte(envelope + "BDAT 4294967295 LAST\r\n"))
	f.Add([]byte("EHLO a\r\nSTARTTLS\r\nAUTH PLAIN AAAA\r\nVRFY x\r\nNOOP\r\nHELP\r\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if 64*1024 < len(input) {
			return
		}
		world := newMailSessionTestWorld(t, nil)
		sender := world.open(testMailSessionIngress(t))
		go func() {
			sender.conn.Write(input)
			sender.conn.CloseWrite()
		}()
		reader := bufio.NewReader(sender.conn)
		for {
			line, err := reader.ReadString('\n')
			if line != "" && strings.HasSuffix(line, "\n") {
				if !mailSessionFuzzReplyLine.MatchString(line) {
					t.Fatalf("a reply line that is not SMTP: %q", line)
				}
				if strings.HasPrefix(line, "554 5.0.0 Error: transaction failed") {
					t.Fatalf("a failure reached the sender as go-smtp's generic 554: %q", line)
				}
			}
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
					t.Logf("the session ended with %v", err)
				}
				break
			}
		}
		named := []string{}
		for _, address := range []string{testMailSessionAlice, testMailSessionBob, testMailSessionCarol} {
			if strings.Contains(strings.ToLower(string(input)), address) {
				named = append(named, address)
			}
		}
		for _, deposit := range world.takenDeposits() {
			if deposit.trailer == nil {
				t.Fatal("a committed deposit did not split")
			}
			for _, recipient := range deposit.trailer.GetRecipients() {
				if !slices.Contains(named, recipient) || world.recipients[recipient].RepoId != deposit.repoId {
					t.Fatalf("a deposit names %q, which the sender did not name for its repo", recipient)
				}
			}
		}
	})
}
