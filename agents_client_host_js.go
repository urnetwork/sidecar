//go:build js && !ios_extension && !sidecar_http

// The js leg's card view host: none, since the config's client names are read by compute_labels.go, which that leg does
// not build; a view shows no host there rather than the card's own text.

package sidecar

// No host names on this leg.
func agentsHostNames(sidecar *Sidecar) func(sidecarId Id) string {
	return nil
}
