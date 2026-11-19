//go:build sidecar_leaktest

// The wake vendors' leak for §22.7's self-test (leak_enabled.go; TEST-M8-01): a value in the topic class of a wake a
// vendor is sent, as a sender that passed user text where a class belongs would send it, so CC4/wake must catch it.

package sidecartest

import (
	"testing"

	"github.com/urnetwork/sidecar/pushservice"
)

var _ = RegisterLeak(&Leak{
	Class: PrivacyClassWake,
	// a topic class is JSON text: bytes that are no UTF-8 would be replaced on the way
	Binary: false,
	// inside the vendor's own JSON
	Embeds: true,
	Put: func(t testing.TB, net *Net, value []byte) {
		vendor := NewFakeWakeVendor(pushservice.WakePlatformFcm, net.Clock())
		net.Capture().AddWakeVendor(vendor)
		vendor.Send(net.Context(), "synthetic-fcm-token-leak", &pushservice.WakePayload{TopicClass: string(value), Version: 1})
	},
})
