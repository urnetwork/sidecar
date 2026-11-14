//go:build !ios_extension

// §15.1's mail routes on SidecarApi (MAIL-M7-22, QD-478): POST /mail/enable, which creates the network's mailbox
// records on the platform, and GET /mail/status, which a device reads before it offers mail. Both carry the client
// JWT, and a refusal of either is a *SidecarApiError as every route's is. An answer that is not the route's shape
// is refused whole (ErrSidecarApiReply), never taken in part.
//
// On every leg but the extension's, which holds no mail.

package sidecar

import (
	"context"
	"fmt"
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

// GET /mail/status: the token's network's mail status. An answer lacking any of its four fields is not the
// route's. Never the packet path.
func (self *SidecarApi) MailStatus(ctx context.Context) (*MailNetworkStatus, error) {
	answer := struct {
		Enabled     *bool `json:"enabled"`
		StorageFull *bool `json:"storage_full"`
		Spent       *bool `json:"spent"`
		DirectMx    *bool `json:"direct_mx"`
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
	if answer.Enabled == nil || answer.StorageFull == nil || answer.Spent == nil || answer.DirectMx == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarMailStatusRoute, ErrSidecarApiReply)
	}
	return &MailNetworkStatus{
		Enabled: *answer.Enabled, StorageFull: *answer.StorageFull, Spent: *answer.Spent, DirectMx: *answer.DirectMx,
	}, nil
}
