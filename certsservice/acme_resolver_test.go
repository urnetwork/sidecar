// Pebble given a resolver of the test's own (sidecartest.PebbleSettings.DnsAddress), as server's e2e world gives it
// one that reaches its dns edge, so each DNS-01 check is asked there; and a renewal window a test sets for a
// certificate (Pebble.SetRenewalWindow), which ARI reads back as a CA's request for an early renewal.

package certsservice_test

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A DNS server on loopback TCP answering each _acme-challenge.<name> TXT question with values' values at name, as a
// recursive resolver answers a zone's challenge, counting the questions asked: its address.
func startTestChallengeResolver(t *testing.T, values *sidecartest.FakeCertsDns, asked *atomic.Int64) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		for _, question := range request.Question {
			asked.Add(1)
			name, found := strings.CutPrefix(strings.ToLower(strings.TrimSuffix(question.Name, ".")), "_acme-challenge.")
			if !found || question.Qtype != dns.TypeTXT {
				continue
			}
			for _, value := range values.Values(name) {
				reply.Answer = append(reply.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{value},
				})
			}
		}
		writer.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.ShutdownContext(ctx)
	})
	return listener.Addr().String()
}

// A Pebble given a resolver starts no DNS server of its own and validates each challenge through the resolver, so an
// order whose challenges only the resolver serves comes back as a chain; and a window set for the certificate is the
// one its ARI answers.
func TestCertsAcmeOrdersThroughTheResolverPebbleIsGiven(t *testing.T) {
	values := sidecartest.NewFakeCertsDns(nil)
	asked := &atomic.Int64{}
	pebbleSettings := sidecartest.DefaultPebbleSettings()
	pebbleSettings.DnsAddress = startTestChallengeResolver(t, values, asked)
	pebble := sidecartest.StartPebble(t, pebbleSettings)
	if pebble.Dns != nil {
		t.Fatal("Pebble started a DNS server of its own beside the resolver it was given")
	}
	accounts, err := certsservice.NewCertsAccountSet([][]byte{testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", "")})
	if err != nil {
		t.Fatal(err)
	}
	client, err := certsservice.NewCertsAcme(testAcmeSettings(pebble, nil), &certsservice.CertsAcmeDeps{
		Accounts:   accounts,
		Dns:        values,
		Clock:      sidecar.RealClock{},
		HttpClient: pebble.HttpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	device := newTestDevice(t, "k6resolve01")
	ctx := testAcmeContext(t)

	issued, err := client.Order(ctx, &certsservice.CertsAcmeOrder{
		Ca:      certsservice.CertsCaLetsEncrypt,
		Profile: sidecartest.PebbleProfileTlsServer,
		Csr:     testCsr(t, device.tlsKey, device.identifierSet),
	})
	if err != nil {
		t.Fatal(err)
	}
	testVerifyChain(t, pebble, issued.Chain, device.identifierSet)
	if asked.Load() == 0 {
		t.Fatal("the order issued with no question to the resolver Pebble was given")
	}
	if names := values.Names(); 0 < len(names) {
		t.Fatalf("challenges left at %v", names)
	}

	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	end := start.Add(time.Minute)
	if err := pebble.SetRenewalWindow(issued.Chain[0], start, end); err != nil {
		t.Fatal(err)
	}
	windowStart, windowEnd, err := client.RenewalInfo(ctx, certsservice.CertsCaLetsEncrypt, issued.Chain[0])
	if err != nil || !windowStart.Equal(start) || !windowEnd.Equal(end) {
		t.Fatalf("ARI answered %v to %v (%v), not the window set, %v to %v", windowStart, windowEnd, err, start, end)
	}
}
