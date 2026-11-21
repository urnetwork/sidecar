//go:build !ios_extension

// §15.1's mail routes on SidecarApi (MAIL-M7-22, QD-478): POST /mail/enable, which creates the network's mailbox
// records on the platform, and GET /mail/status, which a device reads before it offers mail and a sender reads for
// the network's custom domains in strict mode (QD-1129), the set smtpedge derives envelope_domain from. Both carry
// the client JWT, and a refusal of either is a *SidecarApiError as every route's is. An answer that is not the
// route's shape is refused whole (ErrSidecarApiReply), never taken in part: a strict domain that is not a name of
// two or more lowercase LDH labels among them, since a sender would put it in MAIL FROM.
//
// On every leg but the extension's, which holds no mail.

package sidecar

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// The routes as errors name them.
const (
	sidecarMailEnableRoute = "POST /mail/enable"
	sidecarMailStatusRoute = "GET /mail/status"
)

// What POST /mail/enable answers.
type MailEnabled struct {
	// When the network's mail was enabled: the first enable's time, which a repeated enable answers again.
	EnabledTime time.Time
}

// What GET /mail/status answers.
type MailNetworkStatus struct {
	// The network has mail enabled.
	Enabled bool
	// The network is at or past its storage limit, so its receivers defer mail (§20.7).
	StorageFull bool
	// The network is spent (§20.6).
	Spent bool
	// The network names a direct MX, in any state (§15.4).
	DirectMx bool
	// Public addresses assigned to the calling receiver, including pending direct-MX probes.
	DirectMxAddresses []netip.Addr
	// Verified customer recipient domains of this network.
	VerifiedDomains []string
	// The Team entitlement or its downgrade grace permits sending From the network's verified customer domains.
	MaySendFromCustomDomains bool
	// The network's verified custom domains in strict mode (QD-1129): each at or above an active strict-mode MX host
	// the network maps (§12.8 step 4), whose mail's envelope is b.<domain>, the set smtpedge's gate derives
	// envelope_domain from. Lowercase with no final dot; empty while none is. A sender picks a From's envelope from
	// it by SmtpStrictCustomDomain, as the edge does.
	StrictDomains []string
}

// POST /mail/enable: enables mail for the token's network. It takes no body, and enabling an enabled network
// answers the time of its first enable. Never the packet path.
func (self *SidecarApi) MailEnable(ctx context.Context) (*MailEnabled, error) {
	answer := struct {
		EnabledTime *int64 `json:"enabled_time"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarMailEnableRoute,
		operation: "mail_enable",
		method:    "POST",
		url:       self.settings.ApiUrl + "/mail/enable",
		bearer:    true,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	if answer.EnabledTime == nil || *answer.EnabledTime <= 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailEnableRoute, ErrSidecarApiReply)
	}
	return &MailEnabled{EnabledTime: time.UnixMilli(*answer.EnabledTime).UTC()}, nil
}

// GET /mail/status: the token's network's mail status. An answer lacking any of its five fields, or naming a strict
// domain that is no domain name, is not the route's. Never the packet path.
func (self *SidecarApi) MailStatus(ctx context.Context) (*MailNetworkStatus, error) {
	answer := struct {
		Enabled                  *bool        `json:"enabled"`
		StorageFull              *bool        `json:"storage_full"`
		Spent                    *bool        `json:"spent"`
		DirectMx                 *bool        `json:"direct_mx"`
		StrictDomains            *[]string    `json:"strict_domains"`
		VerifiedDomains          []string     `json:"verified_domains"`
		MaySendFromCustomDomains bool         `json:"may_send_from_custom_domains"`
		DirectMxAddresses        []netip.Addr `json:"direct_mx_addresses"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarMailStatusRoute,
		operation: "mail_status",
		method:    "GET",
		url:       self.settings.ApiUrl + "/mail/status",
		bearer:    true,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	if answer.Enabled == nil || answer.StorageFull == nil || answer.Spent == nil || answer.DirectMx == nil || answer.StrictDomains == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailStatusRoute, ErrSidecarApiReply)
	}
	strictDomains := make([]string, 0, len(*answer.StrictDomains))
	for _, strictDomain := range *answer.StrictDomains {
		if !validMailStrictDomain(strictDomain) {
			return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailStatusRoute, ErrSidecarApiReply)
		}
		strictDomains = append(strictDomains, strictDomain)
	}
	for _, domain := range answer.VerifiedDomains {
		if len(domain) > dnsDomainMaxByteCount || !isNetworkLabelRoot(domain) {
			return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailStatusRoute, ErrSidecarApiReply)
		}
	}
	for _, address := range answer.DirectMxAddresses {
		if !*answer.DirectMx || !address.IsGlobalUnicast() || address.IsPrivate() || address.Zone() != "" || address.Is4In6() {
			return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailStatusRoute, ErrSidecarApiReply)
		}
	}
	return &MailNetworkStatus{
		Enabled: *answer.Enabled, StorageFull: *answer.StorageFull, Spent: *answer.Spent, DirectMx: *answer.DirectMx,
		StrictDomains: strictDomains, VerifiedDomains: answer.VerifiedDomains, DirectMxAddresses: answer.DirectMxAddresses,
		MaySendFromCustomDomains: answer.MaySendFromCustomDomains,
	}, nil
}

// Whether domain can be a strict custom domain as GET /mail/status names one: two or more lowercase LDH labels, with
// room for the b. above it in a domain name.
func validMailStrictDomain(domain string) bool {
	return isNetworkLabelRoot(domain) && len(mailBounceLabel)+1+len(domain) <= dnsDomainMaxByteCount
}
