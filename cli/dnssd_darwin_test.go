//go:build darwin && !ios && !sdk_mobile_bind

// The DNS-SD binding against this machine's mDNSResponder, on the LocalOnly interface alone, so nothing reaches a
// LAN: a record and a service registered there are browsed, resolved and looked up there, an update and a withdrawal
// follow, and a closed connection refuses. Each name is random, so runs side by side never meet.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// A label no other run takes.
func testDarwinDnsSdLabel(t *testing.T, prefix string) string {
	t.Helper()
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(random)
}

// A connection, skipping where no mDNSResponder answers.
func testDarwinDnsSdConnection(t *testing.T) *darwinDnsSdConnection {
	t.Helper()
	connection, err := newDarwinDnsSdConnection()
	var dnsSdErr darwinDnsSdError
	if errors.As(err, &dnsSdErr) && dnsSdErr == darwinDnsSdErrServiceNotRunning {
		t.Skip("no mDNSResponder answers on this machine")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}

// Waits for the next value on values, failing past a bound no local round trip comes near.
func testDarwinDnsSdNext[T any](t *testing.T, values chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s within 10 s", what)
	}
	var zero T
	return zero
}

func TestDarwinDnsSdLocalOnlyRegisterBrowseResolve(t *testing.T) {
	connection := testDarwinDnsSdConnection(t)
	host := testDarwinDnsSdLabel(t, "urtest-host-") + ".urtest-client.local."
	service := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	name := "Shared Device " + testDarwinDnsSdLabel(t, "")

	records := make(chan error, 4)
	record, err := connection.RegisterRecord(darwinDnsSdFlagsUnique, darwinDnsSdInterfaceIndexLocalOnly, host, darwinDnsSdTypeA,
		[]byte{100, 80, 0, 9}, 0, func(err error) { records <- err })
	if err != nil {
		t.Fatal(err)
	}
	if err := testDarwinDnsSdNext(t, records, "record reply"); err != nil {
		t.Fatalf("the A record did not register: %v", err)
	}
	registered := make(chan *darwinDnsSdRegisterReply, 4)
	txt := []byte("\x05a=b c\x04ok=1")
	registration, err := connection.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, service+",_sub1",
		"local.", host, 62078, txt, func(reply *darwinDnsSdRegisterReply) { registered <- reply })
	if err != nil {
		t.Fatal(err)
	}
	reply := testDarwinDnsSdNext(t, registered, "register reply")
	if reply.Err != nil || reply.Name != name {
		t.Fatalf("registered %q, %v", reply.Name, reply.Err)
	}

	browsed := make(chan *darwinDnsSdBrowseReply, 8)
	browse, err := connection.Browse(darwinDnsSdInterfaceIndexLocalOnly, service, "local.", func(reply *darwinDnsSdBrowseReply) {
		browsed <- reply
	})
	if err != nil {
		t.Fatal(err)
	}
	found := testDarwinDnsSdNext(t, browsed, "browse reply")
	if found.Err != nil || found.Flags&darwinDnsSdFlagsAdd == 0 || found.Name != name ||
		found.InterfaceIndex != darwinDnsSdInterfaceIndexLocalOnly {
		t.Fatalf("browsed %+v", found)
	}
	// a subtype browse finds it too
	subtypes := make(chan *darwinDnsSdBrowseReply, 8)
	subtypeBrowse, err := connection.Browse(darwinDnsSdInterfaceIndexLocalOnly, service+",_sub1", "local.", func(reply *darwinDnsSdBrowseReply) {
		subtypes <- reply
	})
	if err != nil {
		t.Fatal(err)
	}
	if found := testDarwinDnsSdNext(t, subtypes, "subtype browse reply"); found.Name != name {
		t.Fatalf("subtype browse found %q", found.Name)
	}
	connection.Cancel(subtypeBrowse)

	resolved := make(chan *darwinDnsSdResolveReply, 8)
	resolve, err := connection.Resolve(darwinDnsSdInterfaceIndexLocalOnly, found.Name, found.Service, found.Domain,
		func(reply *darwinDnsSdResolveReply) { resolved <- reply })
	if err != nil {
		t.Fatal(err)
	}
	target := testDarwinDnsSdNext(t, resolved, "resolve reply")
	if target.Err != nil || target.Host != host || target.Port != 62078 || string(target.Txt) != string(txt) {
		t.Fatalf("resolved %q:%d txt %q, %v", target.Host, target.Port, target.Txt, target.Err)
	}
	connection.Cancel(resolve)

	addresses := make(chan *darwinDnsSdAddressReply, 8)
	lookup, err := connection.GetAddrInfo(darwinDnsSdInterfaceIndexLocalOnly, darwinDnsSdProtocolIpv4, host, func(reply *darwinDnsSdAddressReply) {
		addresses <- reply
	})
	if err != nil {
		t.Fatal(err)
	}
	address := testDarwinDnsSdNext(t, addresses, "address reply")
	if address.Err != nil || address.Flags&darwinDnsSdFlagsAdd == 0 || address.Address != netip.MustParseAddr("100.80.0.9") {
		t.Fatalf("looked up %+v", address)
	}
	// the address moves by a withdrawal and a new record, and the lookup follows it; a lookup may hear one address
	// twice, so what it holds is read as the last word on each
	connection.RemoveRecord(record)
	record, err = connection.RegisterRecord(darwinDnsSdFlagsUnique, darwinDnsSdInterfaceIndexLocalOnly, host, darwinDnsSdTypeA,
		[]byte{100, 80, 0, 10}, 0, func(err error) { records <- err })
	if err != nil {
		t.Fatal(err)
	}
	if err := testDarwinDnsSdNext(t, records, "record reply"); err != nil {
		t.Fatalf("the moved A record did not register: %v", err)
	}
	held := map[netip.Addr]bool{netip.MustParseAddr("100.80.0.9"): true}
	for held[netip.MustParseAddr("100.80.0.9")] || !held[netip.MustParseAddr("100.80.0.10")] {
		change := testDarwinDnsSdNext(t, addresses, "address change")
		held[change.Address] = change.Flags&darwinDnsSdFlagsAdd != 0
	}
	connection.Cancel(lookup)

	// a withdrawal reaches the browse at once
	connection.Cancel(registration)
	gone := testDarwinDnsSdNext(t, browsed, "browse removal")
	if gone.Flags&darwinDnsSdFlagsAdd != 0 || gone.Name != name {
		t.Fatalf("after the withdrawal the browse heard %+v", gone)
	}
	connection.Cancel(browse)
	connection.RemoveRecord(record)

	connection.Close()
	if _, err := connection.Browse(darwinDnsSdInterfaceIndexLocalOnly, service, "local.", func(*darwinDnsSdBrowseReply) {}); !errors.Is(err, errDarwinDnsSdClosed) {
		t.Fatalf("a closed connection browsed: %v", err)
	}
	select {
	case <-connection.Done():
	default:
		t.Fatal("a closed connection is not done")
	}
	if connection.Err() != nil {
		t.Fatalf("a closed connection failed: %v", connection.Err())
	}
}

// Two LocalOnly registrations of one name and type: the second, with NoAutoRename, is refused as a conflict rather than
// renamed, which the proxy's names rule keeps from happening.
func TestDarwinDnsSdLocalOnlyNoAutoRenameConflicts(t *testing.T) {
	connection := testDarwinDnsSdConnection(t)
	service := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	name := "Same " + testDarwinDnsSdLabel(t, "")
	replies := make(chan *darwinDnsSdRegisterReply, 4)
	handle := func(reply *darwinDnsSdRegisterReply) { replies <- reply }
	if _, err := connection.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, service, "local.",
		"", 4000, nil, handle); err != nil {
		t.Fatal(err)
	}
	if reply := testDarwinDnsSdNext(t, replies, "first reply"); reply.Err != nil {
		t.Fatalf("the first registration failed: %v", reply.Err)
	}
	_, err := connection.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, service, "local.", "",
		4001, nil, handle)
	if err == nil {
		err = testDarwinDnsSdNext(t, replies, "second reply").Err
	}
	var dnsSdErr darwinDnsSdError
	if !errors.As(err, &dnsSdErr) || dnsSdErr != darwinDnsSdErrNameConflict {
		t.Fatalf("the second registration answered %v", err)
	}
}
