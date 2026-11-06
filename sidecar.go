// End-to-end encrypted services for a URnetwork network: identity and keys, the subprotocol over
// connect, and the client side of each service. One Sidecar runs per network. Servers store, order
// and deliver ciphertext and signed statements; keys and plaintext stay on members' devices.
//
// This package builds on every leg, the browser Worker's sidecar_http included. A file that uses
// package connect carries !sidecar_http, because connect links gVisor into every importer (§4.4).
// Everything else, this file included, uses the root's own types and never imports connect.
//
// Of this module's packages the root imports only protocol and protocol/bridge. Server-only engines
// are <svc>service child packages that import the root, and the root never imports device/.
package sidecar

// The release version, yyyy.m.d-code, empty in a development build.
//
// The release fills this in with a sed over this file on its version branch, as it does for
// sdk.Version (build/all/run.sh). That sed matches this declaration's exact text and reports nothing
// when it misses, so keep the explicit type and empty initializer. A linker flag can also set it:
// -ldflags "-X github.com/urnetwork/sidecar.Version=$WARP_VERSION-$WARP_VERSION_CODE"
// Keep it a var, because -X is silently a no-op against a const.
var Version string = ""
