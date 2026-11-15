//go:build !js

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// How long a test waits on loopback before it fails: a guard, never the proof.
const recordingTestTimeout = 10 * time.Second

// Writes data to conn and reads it back from an echo, so the backend has logged it when this returns: its reader
// logs a read before it keeps it for the echo.
func recordingEcho(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(recordingTestTimeout))
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(data))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != data {
		t.Fatalf("echoed %q, sent %q", echoed, data)
	}
}

// The bytes of each audience state, joined in arrival order.
func recordingBytesByAudience(backend *RecordingBackend) map[RecordingBackendAudience]string {
	joined := map[RecordingBackendAudience]string{}
	for _, arrival := range backend.Arrivals() {
		joined[arrival.Audience] += string(arrival.Sample)
	}
	return joined
}

// Every byte is logged with the audience state when it arrived: before the check, admitted, and after a revocation,
// each with the reason the world gave.
func TestRecordingBackendLogsEachByteWithItsAudience(t *testing.T) {
	settings := DefaultRecordingBackendSettings()
	settings.Name = "a fixture backend"
	settings.Serve = RecordingBackendEcho
	backend, err := NewRecordingBackend(nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	conn, err := net.Dial("tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	recordingEcho(t, conn, "early")
	backend.SetAudience(RecordingBackendAdmitted, "the fixture's check passed")
	recordingEcho(t, conn, "admitted")
	backend.SetAudience(RecordingBackendRevoked, "the fixture's flow revoked")
	recordingEcho(t, conn, "late")

	joined := recordingBytesByAudience(backend)
	if joined[RecordingBackendUnchecked] != "early" || joined[RecordingBackendAdmitted] != "admitted" || joined[RecordingBackendRevoked] != "late" {
		t.Fatalf("by audience: %q", joined)
	}
	for _, arrival := range backend.Arrivals() {
		if arrival.Connection != 1 || arrival.Step != -1 {
			t.Errorf("an arrival: %+v", arrival)
		}
		if arrival.Audience == RecordingBackendRevoked && arrival.AudienceReason != "the fixture's flow revoked" {
			t.Errorf("a revoked arrival's reason: %q", arrival.AudienceReason)
		}
	}
	if !backend.ReachedAdmitted() || backend.ConnectionCount() != 1 {
		t.Errorf("reached %t, %d connections", backend.ReachedAdmitted(), backend.ConnectionCount())
	}
}

// "Zero bytes" means none: a ClientHello to a backend whose server reads one byte and hangs up is logged, a TLS
// record like any other bytes, before its audience check.
func TestRecordingBackendCountsATlsRecordAsBytes(t *testing.T) {
	settings := DefaultRecordingBackendSettings()
	settings.Serve = func(conn net.Conn) {
		conn.Read(make([]byte, 1))
	}
	backend, err := NewRecordingBackend(nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	raw, err := net.Dial("tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(recordingTestTimeout))
	if err := tls.Client(raw, &tls.Config{ServerName: "private.recording.example"}).Handshake(); err == nil {
		t.Fatal("a handshake completed against a server that hung up")
	}
	arrivals := backend.Arrivals()
	if len(arrivals) == 0 || arrivals[0].ByteCount == 0 || arrivals[0].Sample[0] != 0x16 || arrivals[0].Audience != RecordingBackendUnchecked {
		t.Fatalf("arrivals: %v", arrivals)
	}
}

// Bytes are logged as they arrive at the socket, under the state then, however late the server reads them: a byte
// that arrived before the check stays judged so once the world admits the flow and the server takes it.
func TestRecordingBackendLogsAtTheSocketBeforeItsServerReads(t *testing.T) {
	var admitted atomic.Bool
	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	served := make(chan string, 1)
	settings := DefaultRecordingBackendSettings()
	settings.Audience = func() (RecordingBackendAudience, string) {
		defer func() { arrived <- struct{}{} }()
		if admitted.Load() {
			return RecordingBackendAdmitted, "the world's check passed"
		}
		return RecordingBackendUnchecked, "the world's check has not run"
	}
	settings.Serve = func(conn net.Conn) {
		<-release
		buffer := make([]byte, 16)
		n, _ := conn.Read(buffer)
		served <- string(buffer[:n])
	}
	backend, err := NewRecordingBackend(nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	conn, err := net.Dial("tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(recordingTestTimeout):
		t.Fatal("the backend's reader never took the byte")
	}
	admitted.Store(true)
	close(release)
	select {
	case got := <-served:
		if got != "x" {
			t.Fatalf("the server read %q", got)
		}
	case <-time.After(recordingTestTimeout):
		t.Fatal("the server never read the byte")
	}
	arrivals := backend.Arrivals()
	if len(arrivals) != 1 || arrivals[0].Audience != RecordingBackendUnchecked {
		t.Fatalf("arrivals: %v", arrivals)
	}
}

// Each arrival is stamped once, with the step of the first check that sees it.
func TestRecordingBackendStampsEachArrivalOnce(t *testing.T) {
	settings := DefaultRecordingBackendSettings()
	settings.Serve = RecordingBackendEcho
	backend, err := NewRecordingBackend(nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	conn, err := net.Dial("tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	recordingEcho(t, conn, "first")
	first := backend.Stamp(1, false)
	if len(first) == 0 || first[0].Step != 1 {
		t.Fatalf("first stamp: %v", first)
	}
	if again := backend.Stamp(2, false); len(again) != 0 {
		t.Fatalf("stamped twice: %v", again)
	}
	recordingEcho(t, conn, "second")
	last := backend.Stamp(3, true)
	if len(last) == 0 || last[0].Step != 3 || !last[0].Final || !strings.Contains(last[0].String(), "at the end") {
		t.Fatalf("the end's stamp: %v", last)
	}
	for _, arrival := range backend.Arrivals() {
		if arrival.Step < 0 {
			t.Errorf("unstamped: %v", arrival)
		}
	}
}

// A world's own listener and an in-process pipe are logged as the backend's, and closing the backend closes them.
func TestRecordingBackendWrapsAWorldsListenerAndPipe(t *testing.T) {
	backend := NewRecordingBackendOver(nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := backend.WrapListener(listener)
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			conn, err := wrapped.Accept()
			if err != nil {
				return
			}
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				RecordingBackendEcho(conn)
			}()
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	backend.SetAudience(RecordingBackendAdmitted, "a fixture's check")
	recordingEcho(t, conn, "over the world's listener")

	client, server := NewMxPipe(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 25})
	serverSide := backend.Wrap(server)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		RecordingBackendEcho(serverSide)
	}()
	recordingEcho(t, client, "over a pipe")

	joined := recordingBytesByAudience(backend)[RecordingBackendAdmitted]
	if !strings.Contains(joined, "over the world's listener") || !strings.Contains(joined, "over a pipe") || backend.ConnectionCount() != 2 {
		t.Fatalf("logged %q over %d connections", joined, backend.ConnectionCount())
	}
	backend.Close()
	waitGroup.Wait()
	if _, err := net.Dial("tcp", listener.Addr().String()); err == nil {
		t.Error("the world's listener still accepts after the backend closed")
	}
	if backend.Wrap(client) != nil {
		t.Error("a closed backend wrapped a connection")
	}
}

// A backend and a ledger made on a Net are what it hands FI-11, and the Net's close closes the backend and forgets
// both.
func TestRecordingBackendRegistersOnItsNet(t *testing.T) {
	net := NewNet(t.Context(), nil)
	backend, err := NewRecordingBackend(net, nil)
	if err != nil {
		net.Close()
		t.Fatal(err)
	}
	ledger := NewMxProofLedger(net)
	if backends := net.RecordingBackends(); len(backends) != 1 || backends[0] != backend {
		t.Errorf("backends: %v", backends)
	}
	if ledgers := net.MxProofLedgers(); len(ledgers) != 1 || ledgers[0] != ledger {
		t.Errorf("ledgers: %v", ledgers)
	}
	address := backend.Addr().String()
	net.Close()
	backend.Close()
	if conn, err := (&netDialer{}).dial(address); err == nil {
		conn.Close()
		t.Error("the backend still listens after its Net closed")
	}
	if 0 < len(net.RecordingBackends()) || 0 < len(net.MxProofLedgers()) {
		t.Error("a closed Net still hands FI-11 its worlds")
	}
}

// A dial for a test whose own name shadows the net package.
type netDialer struct{}

func (self *netDialer) dial(address string) (net.Conn, error) {
	return net.Dial("tcp", address)
}

// An MX's record for a ledger fixture.
type fixtureMxTransactions []*MxTransaction

func (self fixtureMxTransactions) Transactions() []*MxTransaction {
	return self
}

// Each proof takes a transaction its MX took, once: a proof of what the MX refused, of one transaction twice, of a
// recipient the MX refused, of another message, or naming an MX the ledger lacks, is a mismatch.
func TestMxProofLedgerMatchesProofsToWhatTheMxTook(t *testing.T) {
	message := []byte("Subject: a fixture\r\n\r\nhello\r\n")
	took := fixtureMxTransactions{{Secure: true, Sender: "<sender@sender.example>", Recipients: []string{"<a@recipient.example>", "<b@recipient.example>"}, Message: message}}
	envelope := func() *MxProvedEnvelope {
		return &MxProvedEnvelope{Mx: "MX.recipient.example", Sender: "<sender@sender.example>", Recipients: []string{"<a@recipient.example>"}, MessageSha256: sha256.Sum256(message), BindsTheMessage: true}
	}
	ledger := NewMxProofLedger(nil)
	ledger.AddMx("mx.recipient.example", took)
	ledger.Proved(envelope())
	if mismatches := ledger.Mismatches(); len(mismatches) != 0 {
		t.Fatalf("an honest proof: %v", mismatches)
	}
	ledger.Proved(envelope())
	if mismatches := ledger.Mismatches(); len(mismatches) != 1 || !strings.Contains(mismatches[0].Error(), "did not accept") {
		t.Fatalf("one transaction proved twice: %v", mismatches)
	}

	for name, change := range map[string]func(*MxProvedEnvelope){
		"a refused recipient": func(proved *MxProvedEnvelope) { proved.Recipients = []string{"<c@recipient.example>"} },
		"another sender":      func(proved *MxProvedEnvelope) { proved.Sender = "<other@sender.example>" },
		"another message":     func(proved *MxProvedEnvelope) { proved.MessageSha256[0] ^= 1 },
		"an unknown mx":       func(proved *MxProvedEnvelope) { proved.Mx = "mx.elsewhere.example" },
	} {
		ledger := NewMxProofLedger(nil)
		ledger.AddMx("mx.recipient.example", took)
		proved := envelope()
		change(proved)
		ledger.Proved(proved)
		if mismatches := ledger.Mismatches(); len(mismatches) != 1 {
			t.Errorf("%s: %v", name, mismatches)
		}
	}
	// a proof that binds no message is held to the envelope alone
	ledger = NewMxProofLedger(nil)
	ledger.AddMx("mx.recipient.example", took)
	unbound := envelope()
	unbound.BindsTheMessage = false
	unbound.MessageSha256 = [sha256.Size]byte{}
	ledger.Proved(unbound)
	if mismatches := ledger.Mismatches(); len(mismatches) != 0 {
		t.Errorf("an envelope-only proof: %v", mismatches)
	}
	// nothing taken: every proof mismatches
	ledger = NewMxProofLedger(nil)
	ledger.AddMx("mx.recipient.example", fixtureMxTransactions{})
	ledger.Proved(envelope())
	if mismatches := ledger.Mismatches(); len(mismatches) != 1 || !bytes.Contains([]byte(mismatches[0].Error()), []byte("<sender@sender.example>")) {
		t.Errorf("a refused message: %v", mismatches)
	}
}
