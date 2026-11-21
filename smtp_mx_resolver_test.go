//go:build !sidecar_http && !ios_extension && !js

package sidecar_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The block's adapter validates the destination and the sending address through its wire DNS transport.
func TestSmtpMxDnsResolverValidatesMxTlsaAndFcrdns(t *testing.T) {
	world := newTestStrictWorld(t)
	resolver := sidecar.NewSmtpMxDnsResolver(world.world, world.anchors, nil, world.clock)
	address := netip.MustParseAddr("192.0.2.25")
	host := "mx.customer.example"
	world.world.SetPtr(address, host)
	mx, err := resolver.LookupMx(t.Context(), "customer.example")
	if err != nil || !mx.Secure || len(mx.Hosts) != 1 || mx.Hosts[0].Host != host || len(mx.Chain) == 0 {
		t.Fatalf("MX: %+v, %v", mx, err)
	}
	tlsa, err := resolver.LookupTlsa(t.Context(), host)
	if err != nil || !tlsa.Secure || len(tlsa.Records) != 1 || len(tlsa.Chain) == 0 {
		t.Fatalf("TLSA: %+v, %v", tlsa, err)
	}
	chain, err := sidecar.ParseSmtpDnssecChain(append(mx.Chain, tlsa.Chain...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := chain.Validate(world.anchors, world.clock.Now(), "customer.example", host); err != nil || verified.Status != sidecar.SmtpDnssecStatusTlsa {
		t.Fatalf("device validation: %+v %v", verified, err)
	}
	if ptr, err := resolver.LookupPtr(t.Context(), address); err != nil || !slices.Equal(ptr, []string{host}) {
		t.Fatalf("PTR: %v, %v", ptr, err)
	}
	if ips, err := resolver.LookupAddresses(t.Context(), host); err != nil || !slices.Equal(ips, []netip.Addr{address}) {
		t.Fatalf("addresses: %v, %v", ips, err)
	}
}

// A proven unsigned delegation can send without a DANE chain. A broken signed zone holds the message.
func TestSmtpMxDnsResolverDistinguishesUnsignedBogusAndNullMx(t *testing.T) {
	world := newTestStrictWorld(t)
	resolver := sidecar.NewSmtpMxDnsResolver(world.world, world.anchors, nil, world.clock)
	for _, domain := range []string{"plain.example", "broken.example"} {
		options := &sidecartest.MxWorldZoneOptions{Unsigned: domain == "plain.example", BrokenDs: domain == "broken.example"}
		if err := world.world.AddZone(domain, options); err != nil {
			t.Fatal(err)
		}
		world.mx(t, domain, "mx."+domain)
	}
	mx, err := resolver.LookupMx(t.Context(), "plain.example")
	if err != nil || mx.Secure || len(mx.Chain) != 0 || len(mx.Hosts) != 1 {
		t.Fatalf("unsigned: %+v, %v", mx, err)
	}
	if _, err := resolver.LookupMx(t.Context(), "broken.example"); !errors.Is(err, sidecar.ErrSmtpMxBogus) {
		t.Fatalf("broken DS: %v", err)
	}
	if err := world.world.SetNullMx("null.customer.example"); err != nil {
		t.Fatal(err)
	}
	mx, err = resolver.LookupMx(t.Context(), "null.customer.example")
	if err != nil || !mx.Secure || !mx.NullMx || len(mx.Hosts) != 0 {
		t.Fatalf("null MX: %+v, %v", mx, err)
	}
	if _, err := resolver.LookupMx(t.Context(), "absent.customer.example"); !errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain) {
		t.Fatalf("absent domain: %v", err)
	}
	if err := world.world.AddMx("no-tlsa.customer.example", netip.MustParseAddr("192.0.2.35"), nil); err != nil {
		t.Fatal(err)
	}
	denial, err := resolver.LookupTlsa(t.Context(), "no-tlsa.customer.example")
	if err != nil || !denial.Secure || len(denial.Records) != 0 || len(denial.Chain) == 0 {
		t.Fatalf("signed denial of TLSA: %+v, %v", denial, err)
	}
}
