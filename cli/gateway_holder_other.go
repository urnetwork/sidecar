//go:build !darwin && !linux

// The gateway port's holder where the OS shows none to ur (gateway_holder.go).

package main

import (
	"github.com/urnetwork/sidecar"
)

// Names no holder.
func urGatewayPortHolder(settings *sidecar.GatewaySettings) func(address string) string {
	return func(address string) string {
		return ""
	}
}
