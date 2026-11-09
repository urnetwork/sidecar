// The keyless device role (§17, §18.6): §17's classify, hook, routes and zone, which device.Bridge brings, and
// §18.6's posture, legacy, pending or enforcing, which it embeds as its one state machine (posture.go, D-SDK-13,
// D-BRIDGE-18). The posture persists in the network process's own store, is restored before the first packet, and
// verifies what it applies offline against the anchor: a state by the log that vouches for it, and the revocations
// between states by their signers' keys.
//
// Imports only connect and protocol/bridge, so the iOS extension links no root init and no protocol descriptor
// (D-SDK-20). The root never imports this package either (§4.4).
package device
