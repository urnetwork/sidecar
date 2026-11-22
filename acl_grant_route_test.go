//go:build !sidecar_http && !ios_extension

// The one reader of an activated route grant's sealed detail (acl_grant_route.go): a detail's prefixes masked and each
// once across its cidrs and ip: destinations, its sidecar destinations' ports each once and none meaning every port,
// and each way a grant gives nothing, the opener never asked for one whose action seals no detail. Synthetic values
// only.

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
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
