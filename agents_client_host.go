//go:build !ios_extension && !sidecar_http && !js

// A card view's host (DESIGN-COMPUTE §20.6's stub rule): the client name the config's head gives the card's sidecar_id
// (§7.7), read as the spend view's labels read it (compute_labels.go), never the card's own text.

package sidecar

import (
	"context"
)

// The config's client name of a sidecar on sidecar's newest verified head, "" for none.
func agentsHostNames(sidecar *Sidecar) func(sidecarId Id) string {
	return func(sidecarId Id) string {
		names, err := sidecar.computeConfigSidecarNames(context.Background())
		if err != nil {
			return ""
		}
		return names[sidecarId]
	}
}
