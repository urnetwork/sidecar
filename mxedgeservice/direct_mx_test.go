// MAIL-M7-23's prober, §22.5's §15.4 direct-MX checks over pipes to scripted receivers: a private address refused
// with no dial, a wrong SPKI refused, no STARTTLS refused, a good receiver verified and its probe sending nothing past
// the TLS handshake; a failing row alerting once it has failed 15 minutes on a fake clock and never reverting by
// itself; and a row gone, as DELETE or a removal leaves it, forgotten.

package mxedgeservice_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A self-signed certificate on a new P-256 key, and its SPKI's SHA-256.
func testDirectMxCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mx.acme.root.example"}, DNSNames: []string{"mx.acme.root.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, sum[:]
}

// A receiver's TCP 25 as a test scripts it: its greeting, whether EHLO lists STARTTLS, its certificate, and what it
// read after the handshake.
type testDirectMxReceiver struct {
	certificate tls.Certificate
	startTls    bool
	stateLock   sync.Mutex
	dials       int
	afterTls    []byte
	handshakes  int
	// each scripted session, joined before a test reads what the sessions saw
	served sync.WaitGroup
}

func (self *testDirectMxReceiver) serve(t *testing.T, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	io.WriteString(conn, "220 rx.example ESMTP\r\n")
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "EHLO ") {
		return
	}
	if self.startTls {
		io.WriteString(conn, "250-rx.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
	} else {
		io.WriteString(conn, "250-rx.example\r\n250 8BITMIME\r\n")
		return
	}
	if line, err = reader.ReadString('\n'); err != nil || line != "STARTTLS\r\n" {
		return
	}
	io.WriteString(conn, "220 2.0.0 Ready to start TLS\r\n")
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{self.certificate}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	read, _ := io.ReadAll(tlsConn)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.handshakes += 1
	self.afterTls = append(self.afterTls, read...)
}

// The prober's store, as a test sets it: its rows, and each outcome recorded.
type testDirectMxStore struct {
	stateLock sync.Mutex
	rows      []*mxedgeservice.MxDirectMxRow
	outcomes  []bool
}

func (self *testDirectMxStore) ListDirectMx(ctx context.Context) ([]*mxedgeservice.MxDirectMxRow, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*mxedgeservice.MxDirectMxRow{}, self.rows...), nil
}

func (self *testDirectMxStore) RecordDirectMxProbe(ctx context.Context, row *mxedgeservice.MxDirectMxRow, passed bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.outcomes = append(self.outcomes, passed)
	if passed {
		row.State = mxedgeservice.MxDirectMxStateVerified
	} else if row.State == mxedgeservice.MxDirectMxStateVerified {
		row.State = mxedgeservice.MxDirectMxStateFailing
	}
	return nil
}

func (self *testDirectMxStore) last() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.outcomes[len(self.outcomes)-1]
}

// A prober whose dial reaches receiver over a pipe, on a fake clock, counting alerts.
type testDirectMxWorld struct {
	store    *testDirectMxStore
	receiver *testDirectMxReceiver
	clock    *sidecartest.FakeClock
	prober   *mxedgeservice.MxDirectMxProber
	alerts   []*mxedgeservice.MxDirectMxRow
	spki     []byte
	row      *mxedgeservice.MxDirectMxRow
}

func newTestDirectMxWorld(t *testing.T) *testDirectMxWorld {
	t.Helper()
	certificate, spki := testDirectMxCertificate(t)
	world := &testDirectMxWorld{
		store:    &testDirectMxStore{},
		receiver: &testDirectMxReceiver{certificate: certificate, startTls: true},
		clock:    sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		spki:     spki,
	}
	world.row = &mxedgeservice.MxDirectMxRow{
		NetworkId: sidecar.NewId(), ReceiverSidecarId: sidecar.NewId(), Address: netip.MustParseAddr("192.0.2.25"),
		State: mxedgeservice.MxDirectMxStatePending, Host: "mx.acme.root.example", SpkiSha256s: [][]byte{spki},
		HintSidecarIds: []sidecar.Id{sidecar.NewId()},
	}
	world.store.rows = []*mxedgeservice.MxDirectMxRow{world.row}
	settings := mxedgeservice.DefaultMxDirectMxSettings()
	settings.EhloName = "mx.bringyour.example"
	var alertLock sync.Mutex
	prober, err := mxedgeservice.NewMxDirectMxProber(&mxedgeservice.MxDirectMxProberArgs{
		Store: world.store,
		Dial: func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
			if address.Port() != 25 {
				return nil, errors.New("not TCP 25")
			}
			world.receiver.stateLock.Lock()
			world.receiver.dials += 1
			world.receiver.stateLock.Unlock()
			client, server := net.Pipe()
			world.receiver.served.Go(func() {
				world.receiver.serve(t, server)
			})
			return client, nil
		},
		Alert: func(ctx context.Context, row *mxedgeservice.MxDirectMxRow) error {
			alertLock.Lock()
			defer alertLock.Unlock()
			world.alerts = append(world.alerts, row)
			return nil
		},
		Clock:    world.clock,
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.prober = prober
	return world
}

// A good receiver verifies: public, STARTTLS, its published key; the probe sends nothing past the handshake.
func TestDirectMxProbeVerifiesAGoodReceiver(t *testing.T) {
	world := newTestDirectMxWorld(t)
	if result := world.prober.Probe(context.Background(), world.row); result != mxedgeservice.MxDirectMxProbePassed {
		t.Fatalf("a good receiver: %s", result)
	}
	world.prober.ProbeAll(context.Background())
	if !world.store.last() || world.row.State != mxedgeservice.MxDirectMxStateVerified {
		t.Fatalf("the outcome %v, state %s", world.store.outcomes, world.row.State)
	}
	world.receiver.served.Wait()
	world.receiver.stateLock.Lock()
	defer world.receiver.stateLock.Unlock()
	if world.receiver.handshakes != 2 || len(world.receiver.afterTls) != 0 {
		t.Fatalf("%d handshakes, %d bytes after one", world.receiver.handshakes, len(world.receiver.afterTls))
	}
}

// §22.5's §15.4 direct-MX checks: a private address refused before any dial, a wrong SPKI refused, no STARTTLS refused,
// and a receiver with no published key refused.
func TestDirectMxProbeRefusals(t *testing.T) {
	world := newTestDirectMxWorld(t)
	ctx := context.Background()
	for _, private := range []string{"10.0.0.25", "127.0.0.1", "169.254.1.1", "fe80::1", "::", "fd00::25"} {
		row := *world.row
		row.Address = netip.MustParseAddr(private)
		if result := world.prober.Probe(ctx, &row); result != mxedgeservice.MxDirectMxProbeNotPublic {
			t.Errorf("%s: %s", private, result)
		}
	}
	if world.receiver.dials != 0 {
		t.Fatal("a private address was dialed")
	}
	wrong := *world.row
	wrong.SpkiSha256s = [][]byte{make([]byte, sha256.Size)}
	if result := world.prober.Probe(ctx, &wrong); result != mxedgeservice.MxDirectMxProbeWrongKey {
		t.Errorf("a wrong SPKI: %s", result)
	}
	none := *world.row
	none.SpkiSha256s = nil
	if result := world.prober.Probe(ctx, &none); result != mxedgeservice.MxDirectMxProbeNoKey {
		t.Errorf("no published key: %s", result)
	}
	world.receiver.startTls = false
	if result := world.prober.Probe(ctx, world.row); result != mxedgeservice.MxDirectMxProbeNoStartTls {
		t.Errorf("no STARTTLS: %s", result)
	}
}

// A failing row alerts once it has failed 15 minutes, on a fake clock, and again only after AlertInterval; it reverts
// nothing by itself; and a row gone is forgotten.
func TestDirectMxFailingProbeAlertsAt15Minutes(t *testing.T) {
	world := newTestDirectMxWorld(t)
	ctx := context.Background()
	world.prober.ProbeAll(ctx)
	if world.row.State != mxedgeservice.MxDirectMxStateVerified {
		t.Fatal("the receiver did not verify")
	}
	world.receiver.startTls = false
	for minute := 0; minute < 15; minute += 5 {
		world.prober.ProbeAll(ctx)
		if len(world.alerts) != 0 {
			t.Fatalf("an alert at minute %d", minute)
		}
		world.clock.Advance(5 * time.Minute)
	}
	world.prober.ProbeAll(ctx)
	if len(world.alerts) != 1 || world.alerts[0].NetworkId != world.row.NetworkId {
		t.Fatalf("at 15 minutes: %d alerts", len(world.alerts))
	}
	if world.row.State != mxedgeservice.MxDirectMxStateFailing {
		t.Fatalf("the row reads %s: a failing direct MX reverts only on DELETE", world.row.State)
	}
	world.clock.Advance(5 * time.Minute)
	world.prober.ProbeAll(ctx)
	if len(world.alerts) != 1 {
		t.Fatal("alerted again within AlertInterval")
	}
	world.clock.Advance(time.Hour)
	world.prober.ProbeAll(ctx)
	if len(world.alerts) != 2 {
		t.Fatal("not alerted again past AlertInterval")
	}
	// passing clears the failure
	world.receiver.startTls = true
	world.prober.ProbeAll(ctx)
	world.receiver.startTls = false
	world.clock.Advance(10 * time.Minute)
	world.prober.ProbeAll(ctx)
	if len(world.alerts) != 2 {
		t.Fatal("a new failure alerted before 15 minutes")
	}
	// DELETE, or the receiver's removal, takes the row: nothing more is probed or alerted
	world.store.stateLock.Lock()
	world.store.rows = nil
	world.store.stateLock.Unlock()
	dials := world.receiver.dials
	world.clock.Advance(time.Hour)
	world.prober.ProbeAll(ctx)
	if world.receiver.dials != dials || len(world.alerts) != 2 {
		t.Fatal("a deleted row was probed or alerted")
	}
}
