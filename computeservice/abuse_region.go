// Compute refused by region at the broker (DESIGN-COMPUTE §17.2's sanctioned users row, D-CABUSE-1, I-13;
// CARCH-M12-01): computeRegionRefused, an admission check every broker admission runs (remote calls, searches and
// enclave creates and starts), which maps the request's address to its country and first subdivision through the
// host's geo lookup and refuses one the settings list (ComputeAbuseSettings), 451 region_refused.
//
// The address is the one the broker sees: X-UR-Forwarded-For, which every ingress in front of a block overwrites
// with the address and port it accepted the client's connection from (server's router.SetIngressHeaders, warp's
// nginx), or the connection's peer for a request no ingress fronts. It is read in memory for the one lookup and kept
// nowhere: no log line, no error text, no metric label, no Redis key, no row (I-13; compute-5 names it, QD-1438). A header that is not one address, which no ingress writes,
// and a lookup that cannot answer refuse, unavailable: an admission that cannot check its region does not pass. An
// address the database places nowhere, a reserved or unannounced one, is in no listed region and passes.
//
// Stripe's screening of buyers and the search signer's screen of payees are §9.11's and §21.5's; VPN users pass here,
// as anywhere (§17.2's residual).

package computeservice

import (
	"net/http"
	"net/netip"
	"strings"
)

// The header the ingress writes the client's address and port into, as server's session reads it.
const computeForwardedForHeader = "X-UR-Forwarded-For"

// Every admission's region check, registered after the abuse hold's.
func init() {
	registerComputeAdmissionCheck("abuse_region", computeRegionRefused)
}

// Where an address is, as the host's geo database places it.
type ComputeRegion struct {
	// ISO 3166-1 alpha-2 in lower case; empty where the database places the address in no country.
	CountryCode string
	// The GeoNames id of its first subdivision, the largest (GeoLite2 lists them largest first); 0 for none.
	SubdivisionGeonameId uint32
}

// The host's geo lookup: server's GeoLite2 City reader, which the compute block's host passes in, since the broker
// may not import server (owner rule 2). Safe for concurrent use; it reads a local database and nothing over a
// network.
type ComputeRegionLookup interface {
	// The address's region: a zero region for an address the database places nowhere, an error where it cannot
	// answer. Neither the region nor the error may carry the address.
	Region(addr netip.Addr) (*ComputeRegion, error)
}

// The admission check (see the file header): nil admits, a refusal answers.
func computeRegionRefused(request *ComputeRequest) *ComputeRefusal {
	lookup := request.engine.deps.RegionLookup
	if lookup == nil {
		// a block given no lookup checks no region, so it admits nothing
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	addr, ok := computeRequestAddress(request.Http)
	if !ok {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	region, err := lookup.Region(addr)
	if err != nil || region == nil {
		// the error is not read: a lookup's text may quote what it was asked
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if request.engine.abuseSettings().refusesRegion(region) {
		return NewComputeRefusal(ComputeRefusalRegionRefused)
	}
	return nil
}

// The address the broker sees for httpRequest (see the file header), unmapped from v4-in-v6; false for a forwarded
// header that is not one address, or a peer that does not parse.
func computeRequestAddress(httpRequest *http.Request) (netip.Addr, bool) {
	forwardedValues := httpRequest.Header.Values(computeForwardedForHeader)
	switch len(forwardedValues) {
	case 0:
		return computeParseAddress(httpRequest.RemoteAddr)
	case 1:
		return computeParseAddress(strings.TrimSpace(forwardedValues[0]))
	}
	// two values: no ingress writes that, so it is a client's
	return netip.Addr{}, false
}

// An "ip:port" with a v6 ip bracketed, or a bare ip, unmapped.
func computeParseAddress(text string) (netip.Addr, bool) {
	if addrPort, err := netip.ParseAddrPort(text); err == nil {
		return addrPort.Addr().Unmap(), true
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		return addr.Unmap(), true
	}
	return netip.Addr{}, false
}
