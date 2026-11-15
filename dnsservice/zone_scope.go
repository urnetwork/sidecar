// Team scope zones (§12.5, §12.7, R-DNS-2, R-DNS-6, D-DNS-6; owner decisions 40, 58; DNS-M6-06). A Team
// scope <scope>.<net>.<root> repeats §12.7's set of a network zone under its own apex, with its own mx
// host and, from M8, its TLSA, so a scope's devices hold {*.<scope>.<net>.<root>, <scope>.<net>.<root>}
// (§13.8) and the scope's hosts, <host>.<scope>, are §8.4's dns:<host>.<scope>, one label below the scope.
//
// A scope has no cut and no row of its own kind: the root is one zone (plan reading 2), and the scope's
// set is ordinary rows of its network at owners under <scope>.<net>.<root>, written by the model from the
// same function as the network's set. A view answers them as it answers any name, so the scope's apex
// existing stops the network's wildcard below it (RFC 4592 §2.2) and its own wildcard answers there, and
// an alias of the network answers the scope's rows under the alias too (zone_alias.go).
//
// Scope labels come from the signed projection (§8), which a scope's creator reads, and each is held to
// ValidateDnsScopeLabel: §21.6's ScreenName, as a label draw and an alias are, which holds §12.5's reserved
// block and the brands, and none of §12.7's system hosts, the zone's hosts or the network's client names
// (§7.7). In the network's own zone a scope label is
// then refused as a user owner (validate.go), and inside a scope only hosts one label below it take user
// records; the scope's apex keeps its system set alone.

package dnsservice

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

var (
	// A scope label ValidateDnsScopeLabel refuses. The wrapping error says which rule.
	ErrDnsScopeLabelRefused = errors.New("dns scope label refused")
)

// What a scope label is held to beyond its own text.
type DnsScopeLabelContext struct {
	// The host labels the network's zone holds owners at or below, directly below its apex: what §12.5
	// keeps a scope label from, since a scope would take every name below its label.
	Hosts []string
	// The network's client names (§7.7), whose private names sit at <client-name>.<net>.<root> (§12.9).
	ClientNames []string
	// What §21.6's ScreenName reads of the network: its verified domains, which let a brand's own name pass.
	// nil screens as a network of which nothing is known.
	Facts *sidecar.ScreenFacts
}

// Holds label, a new Team scope's, to §12.5's rules (see the file header). A refusal wraps
// ErrDnsScopeLabelRefused and says which rule.
func ValidateDnsScopeLabel(label string, context *DnsScopeLabelContext) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %q: %s", ErrDnsScopeLabelRefused, label, fmt.Sprintf(format, args...))
	}
	if context == nil {
		context = &DnsScopeLabelContext{}
	}
	switch {
	case !isDnsLowerHostLabel(label):
		return refuse("not a lowercase LDH label")
	case slices.Contains(dnsUserRefusedHostLabels, label):
		return refuse("one of §12.7's system hosts")
	case sidecar.IsWordNumberDnsLabel(label):
		return refuse("a word-number label, which burners keep")
	case slices.Contains(context.Hosts, label):
		return refuse("a host the zone holds")
	case slices.Contains(context.ClientNames, label):
		return refuse("a client name (§7.7)")
	}
	facts := context.Facts
	if facts == nil {
		// a network of which nothing is known: no brand passes and nothing waits for review
		facts = &sidecar.ScreenFacts{}
	}
	// §12.5's reserved block and the brands, a brand passing for the network verifying its own domain
	if verdict := sidecar.ScreenName(label, facts); verdict != sidecar.ScreenVerdictAllow {
		return refuse("the screen answers %s (§21.6)", verdict)
	}
	return nil
}

// A scope's apex, <scope>.<apex>, apex being its network's zone <label>.<root>, both canonical.
func DnsScopeApex(apex string, scope string) string {
	return scope + "." + dns.CanonicalName(apex)
}

// The scope of scopes that owner is at or below, its label directly below apex, or "" for an owner in
// the network's own zone. owner and apex are canonical.
func DnsOwnerScope(apex string, owner string, scopes []string) string {
	rest, ok := strings.CutSuffix(owner, "."+apex)
	if !ok || rest == "" {
		return ""
	}
	labels := dns.SplitDomainName(rest + ".")
	scope := labels[len(labels)-1]
	if !slices.Contains(scopes, scope) {
		return ""
	}
	return scope
}

// The host labels directly below apex that rows hold owners at or below, sorted and each once, * and
// underscore labels left out: what a new scope label may not be (§12.5). owner canonical.
func DnsZoneHostLabels(apex string, owners []string) []string {
	apex = dns.CanonicalName(apex)
	hosts := []string{}
	for _, owner := range owners {
		rest, ok := strings.CutSuffix(owner, "."+apex)
		if !ok || rest == "" {
			continue
		}
		labels := dns.SplitDomainName(rest + ".")
		host := labels[len(labels)-1]
		if host == "*" || strings.HasPrefix(host, "_") || slices.Contains(hosts, host) {
			continue
		}
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts
}
