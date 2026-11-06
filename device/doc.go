// The keyless device role: §17's classify, hook, routes and zone, §18.6's posture, and verifying
// anchored revocation deltas. No part of the role exists yet; this package holds its test seams, so
// the role's first file has them to call.
//
// Imports only connect and protocol/bridge, so the iOS extension links no root init and no protocol
// descriptor (D-SDK-20). The root never imports this package either (§4.4).
package device
