//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// §22.7's privacy rows for §15 (MAIL-M7-27): mxedge's half of the splice clause, "tlsedge and mxedge splices are
// byte-identical", on T2. The canaries in bodies, subjects and addresses, the router's closed-handshake memory and
// mail_connection_record holding no address are S7's flow's, under RunScenario's harness (mail_s7_test.go), and T3's
// in server/cli/mxedge.

package sidecartest_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// Through the router's splice (MAIL-M7-19), every byte the sender wrote after STARTTLS's 220 reaches the receiver as
// written, the ClientHello the router read first, as StreamOpen's early data, and every byte the receiver wrote reaches
// the sender as written, each as its own end's socket saw it: a message of 64 KiB inside TLS crosses as ciphertext
// holding every byte value, and nothing is added, dropped or changed either way.
func TestMailSpliceIsByteIdentical(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	world := mailworld.NewMailWorld(t, host, clock, settings)
	recipient := settings.Addresses[0]
	random := make([]byte, 48*1024)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	lines := []string{"From: <sender@sender.example>", "To: <" + recipient + ">", "Subject: bytes", "Message-ID: <bytes@sender.example>", ""}
	encoded := base64.StdEncoding.EncodeToString(random)
	for 0 < len(encoded) {
		take := min(76, len(encoded))
		lines = append(lines, encoded[:take])
		encoded = encoded[take:]
	}
	message := []byte(strings.Join(append(lines, ""), "\r\n"))
	send := &mailworld.MailWorldSend{Sender: s7Sender, Sni: settings.MxHost(), From: "sender@sender.example", Recipients: []string{recipient}, Message: message, Record: true}
	if reply := world.SendWith(send); !reply.Is(250) {
		t.Fatalf("the message: %s", reply)
	}
	written, read := send.Recording.Bytes()
	opens := world.Opens()
	if len(opens) != 1 {
		t.Fatalf("%d opens", len(opens))
	}
	open := opens[0]

	// the sender's side of the dialog, then TLS
	dialog := "EHLO relay.sender.example\r\nSTARTTLS\r\n"
	if !bytes.HasPrefix(written, []byte(dialog)) {
		t.Fatalf("the sender wrote %q before TLS", written[:min(len(written), len(dialog))])
	}
	senderTls := written[len(dialog):]
	receiverRead := append(bytes.Clone(open.HelloBytes), open.ReceiverRead()...)
	// the receiver may close before the sender's own close_notify crosses; everything before it did, unchanged
	if !bytes.HasPrefix(senderTls, receiverRead) || 64 < len(senderTls)-len(receiverRead) {
		t.Fatalf("the receiver read %d of the sender's %d TLS bytes, or other bytes", len(receiverRead), len(senderTls))
	}
	ready := []byte("220 2.0.0 Ready to start TLS\r\n")
	index := bytes.Index(read, ready)
	if index < 0 {
		t.Fatal("the sender never read STARTTLS's 220")
	}
	senderRead := read[index+len(ready):]
	if !bytes.Equal(senderRead, open.ReceiverWrote()) {
		t.Fatalf("the sender read %d bytes after the 220, the receiver wrote %d, or other bytes", len(senderRead), len(open.ReceiverWrote()))
	}
	values := map[byte]bool{}
	for _, value := range receiverRead {
		values[value] = true
	}
	if len(values) != 256 {
		t.Fatalf("the spliced ciphertext held %d byte values", len(values))
	}
}
