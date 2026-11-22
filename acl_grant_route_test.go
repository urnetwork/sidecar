//go:build !sidecar_http && !ios_extension

// The one reader of an activated route grant's sealed detail (acl_grant_route.go): a detail's prefixes masked and each
// once across its cidrs and ip: destinations, its sidecar destinations' ports each once and none meaning every port,
// and each way a grant gives nothing, the opener never asked for one whose action seals no detail; and the save's ip:
// tests and AclEngine, given one opener, answering a grant's every address at every port alike. Synthetic values only.

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Each detail reads to its prefixes and ports, or to why it gives nothing, and the opener is asked only where the rule
// limits ports, as a GrantActivate carrying a sealed_detail folds.
func TestAclReadGrantRouteReadsADetailOneWay(t *testing.T) {
	grantId := []byte("one grant's id, thirty-two bytes")
	sidecarDst := "sidecar:" + hex.EncodeToString(NewId().Bytes())
	detailOf := func(detail *protocol.CanonicalActionDetail) AclGrantDetails {
		return &testAclGrantDetails{details: map[string]*protocol.CanonicalActionDetail{string(grantId): detail}}
	}
	errOf := func(err error) AclGrantDetails {
		return &testAclGrantDetails{errs: map[string]error{string(grantId): err}}
	}
	for _, c := range []struct {
		name         string
		portsLimited bool
		details      AclGrantDetails
		cidrs        []string
		ports        []AclPortRange
		unread       aclGrantRouteUnread
	}{
		{
			name: "prefixes and ports, each once", portsLimited: true,
			details: detailOf(&protocol.CanonicalActionDetail{
				Cidrs:    []string{"198.51.100.0/25", "198.51.100.7/24"},
				GrantDst: []string{"ip:198.51.100.0/25", "ip:203.0.113.0/28", sidecarDst + ":tcp:22", sidecarDst + ":tcp:22", sidecarDst + ":udp:53"},
			}),
			cidrs: []string{"198.51.100.0/25", "198.51.100.0/24", "203.0.113.0/28"},
			ports: []AclPortRange{{Protocol: aclIpProtocolTcp, First: 22, Last: 22}, {Protocol: aclIpProtocolUdp, First: 53, Last: 53}},
		},
		{
			name: "no port, every port", portsLimited: true,
			details: detailOf(&protocol.CanonicalActionDetail{Cidrs: []string{"0.0.0.0/0"}}), cidrs: []string{"0.0.0.0/0"},
		},
		{
			name: "ports and no prefix, by its subjects", portsLimited: true,
			details: detailOf(&protocol.CanonicalActionDetail{GrantDst: []string{sidecarDst + ":tcp:443"}}),
			ports:   []AclPortRange{{Protocol: aclIpProtocolTcp, First: 443, Last: 443}},
		},
		{name: "an action that seals no detail", portsLimited: false, details: errOf(errors.New("asked")), unread: aclGrantRouteUnreadUnsealed},
		{name: "no opener", portsLimited: true, unread: aclGrantRouteUnreadNoOpener},
		{name: "an action not held", portsLimited: true, details: &testAclGrantDetails{}, unread: aclGrantRouteUnreadNotHeld},
		{name: "a generation not held", portsLimited: true, details: errOf(fmt.Errorf("%w: 3", ErrConfigSealGenerationMissing)), unread: aclGrantRouteUnreadGeneration},
		{name: "a detail not its action's", portsLimited: true, details: errOf(ErrCanonicalActionDetailInvalid), unread: aclGrantRouteUnreadNotOpened},
		{name: "an aead refusal", portsLimited: true, details: errOf(ErrConfigSealInvalid), unread: aclGrantRouteUnreadNotOpened},
		{name: "no detail", portsLimited: true, details: detailOf(nil), unread: aclGrantRouteUnreadMissing},
		{name: "a prefix that does not read", portsLimited: true, details: detailOf(&protocol.CanonicalActionDetail{Cidrs: []string{"198.51.100.0"}}), unread: aclGrantRouteUnreadPrefix},
		{name: "an ip: destination that does not read", portsLimited: true, details: detailOf(&protocol.CanonicalActionDetail{GrantDst: []string{"ip:fixture"}}), unread: aclGrantRouteUnreadPrefix},
		{name: "a destination that does not read", portsLimited: true, details: detailOf(&protocol.CanonicalActionDetail{GrantDst: []string{sidecarDst}}), unread: aclGrantRouteUnreadDestination},
		{name: "a port with no protocol", portsLimited: true, details: detailOf(&protocol.CanonicalActionDetail{Cidrs: []string{"198.51.100.0/24"}, TargetPort: 22}), unread: aclGrantRouteUnreadPortProtocol},
	} {
		route := aclReadGrantRoute(grantId, c.portsLimited, c.details)
		if route.unread != c.unread {
			t.Errorf("%s: unread %q, want %q", c.name, route.unread, c.unread)
			continue
		}
		if counted, ok := c.details.(*testAclGrantDetails); ok && !c.portsLimited && len(counted.asked()) != 0 {
			t.Errorf("%s: the opener was asked", c.name)
		}
		if c.unread != aclGrantRouteUnreadNone {
			if route.local != nil {
				t.Errorf("%s: a grant giving nothing read to %+v", c.name, route.local)
			}
			if indeterminate := c.unread != aclGrantRouteUnreadUnsealed; route.indeterminate() != indeterminate {
				t.Errorf("%s: indeterminate %t", c.name, route.indeterminate())
			}
			continue
		}
		cidrs := []string{}
		for _, prefix := range route.local.Cidrs {
			cidrs = append(cidrs, prefix.String())
		}
		if !slices.Equal(cidrs, c.cidrs) || !slices.Equal(route.local.Ports, c.ports) || route.indeterminate() {
			t.Errorf("%s: cidrs %q ports %+v", c.name, cidrs, route.local.Ports)
		}
	}
	// no unread reason names a value (I-13)
	for unread := aclGrantRouteUnreadNone; unread <= aclGrantRouteUnreadPortProtocol; unread += 1 {
		if text := unread.String(); text == "" || text == "does not read" || strings.ContainsAny(text, "0123456789") {
			t.Errorf("reason %d reads %q", unread, text)
		}
	}
}

// The save's ip: tests and AclEngine read dana's activated route grant through amir's laptop one way: for each address
// at each protocol and port, a save's accept of that address passes exactly where the engine's preview allows it
// through amir's laptop and acl_check's Check takes it, and a deny of it passes exactly where they refuse it.
func TestAclSaveAndEngineReadAnActivatedRouteGrantAlike(t *testing.T) {
	type flow struct {
		address    string
		ipProtocol uint32
		protocol   string
		port       uint32
	}
	flows := []flow{}
	for _, address := range []string{"198.51.100.1", "198.51.100.127", "198.51.100.128", "203.0.113.1", "203.0.113.15", "203.0.113.16", "192.0.2.1"} {
		for _, port := range []struct {
			ipProtocol uint32
			protocol   string
			port       uint32
		}{{ipProtocol: aclIpProtocolTcp, protocol: "tcp", port: 22}, {ipProtocol: aclIpProtocolTcp, protocol: "tcp", port: 23}, {ipProtocol: aclIpProtocolUdp, protocol: "udp", port: 22}} {
			flows = append(flows, flow{address: address, ipProtocol: port.ipProtocol, protocol: port.protocol, port: port.port})
		}
	}
	dana, amir := aclTestsGrantLaptops()
	checks := []string{}
	for _, f := range flows {
		checks = append(checks, fmt.Sprintf(`"ip:%s/32#route:%s:%d"`, f.address, f.protocol, f.port))
	}
	list := strings.Join(checks, ", ")
	world := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+`, "tests": [
    { "src": "sidecar:`+dana.String()+`", "accept": [`+list+`] },
    { "src": "sidecar:`+dana.String()+`", "deny": [`+list+`] },
  ] }`, true)
	details := &testAclGrantDetails{details: map[string]*protocol.CanonicalActionDetail{
		string(world.grantId): {Cidrs: []string{"198.51.100.0/25"}, GrantDst: []string{"ip:203.0.113.0/28", "sidecar:" + hex.EncodeToString(amir.Bytes()) + ":tcp:22"}},
	}}
	report := world.runWith(t, details)
	failed := map[string]bool{}
	for _, failure := range report.Failures {
		failed[fmt.Sprintf("%s %d", failure.List, failure.Check)] = true
	}

	view := world.world.view()
	view.pin = aclTestEnginePin(1, "save and engine")
	state, err := NewAclState(world.world.compile(t), view)
	if err != nil {
		t.Fatal(err)
	}
	local, err := CompileAclLocal(world.world.input())
	if err != nil {
		t.Fatal(err)
	}
	engine := NewAclEngine(dana, nil, nil, &AclEngineSettings{ClockSkew: 0})
	if err := engine.InstallWithGrants(state, local, details); err != nil {
		t.Fatal(err)
	}
	allowedCount := 0
	for i, f := range flows {
		address := netip.MustParseAddr(f.address)
		routed := engine.AllowRoute(AclSidecarSubject(dana), address, f.ipProtocol, f.port, AclSidecarSubject(amir), aclTestNow)
		if routed.Allowed {
			allowedCount += 1
		}
		if accepted := !failed[fmt.Sprintf("accept %d", i)]; accepted != routed.Allowed {
			t.Errorf("%s %s:%d: the save accepts %t, the engine allows %t", f.address, f.protocol, f.port, accepted, routed.Allowed)
		}
		if denied := !failed[fmt.Sprintf("deny %d", i)]; denied == routed.Allowed {
			t.Errorf("%s %s:%d: the save denies %t, the engine allows %t", f.address, f.protocol, f.port, denied, routed.Allowed)
		}
		if f.ipProtocol == aclIpProtocolTcp && f.port == 22 {
			checked := engine.Check(AclSidecarSubject(dana), protocol.AclAction_ACL_ACTION_ROUTE,
				AclResource{Kind: AclResourceIp, Cidr: netip.PrefixFrom(address, 32)}, aclTestNow)
			if checked.Allowed != routed.Allowed {
				t.Errorf("%s: Check takes %t, the preview %t", f.address, checked.Allowed, routed.Allowed)
			}
		}
	}
	if allowedCount == 0 || allowedCount == len(flows) {
		t.Errorf("the engine allowed %d of %d flows: they tell nothing apart", allowedCount, len(flows))
	}
}
