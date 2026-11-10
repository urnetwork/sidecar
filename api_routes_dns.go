//go:build !ios_extension

// §12's api routes for sidecars. GET /sidecar/label is plan-DNS-labels-before-m5's: the caller's
// network's label, allocated on first need, and its alias, which feed NetworkLabelTable from M2, before
// the dns block's GET /dns/zone answers the same from M5.

package sidecar

import (
	"context"
	"fmt"
)

// The route as errors name it.
const sidecarLabelRoute = "GET /sidecar/label"

// What GET /sidecar/label answers.
type SidecarLabel struct {
	NetworkId Id `json:"network_id"`
	// The network's label, which api allocates on the first request that needs one.
	Label string `json:"label"`
	// Empty while the network has no alias.
	Alias string `json:"alias,omitempty"`
}

// GET /sidecar/label (plan-DNS-labels-before-m5): the token's network's label and alias. An answer
// with no network or no label is not the route's. Never the packet path.
func (self *SidecarApi) GetSidecarLabel(ctx context.Context) (*SidecarLabel, error) {
	answer := &SidecarLabel{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarLabelRoute,
		operation: "label",
		method:    "GET",
		url:       self.settings.ApiUrl + "/sidecar/label",
		bearer:    true,
	}, nil, answer)
	if err != nil {
		return nil, err
	}
	if answer.NetworkId == (Id{}) || answer.Label == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarLabelRoute, ErrSidecarApiReply)
	}
	return answer, nil
}
