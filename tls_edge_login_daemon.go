//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's control method for §13.7's members-device statement (QD-827; R-TLS-5, D-TLS-5, D-CORE-13, I-4, I-7):
// tls.edge_login.sign, what a remote-mode app's Sidecar.SignEdgeLogin sends (§18.5), has the call's network's Sidecar
// sign this device's SIGNED_TLS_EDGE_LOGIN over the origin and the nonce a members-device front issued
// (Sidecar.SignTlsEdgeLogin, TLS-M6-06). A desktop app's device is its daemon, so this is how it completes the login a
// phone's app completes in its own core.
//
// It is a Confirm method, as §5.8's person acts are: the daemon runs it only from control, for a call whose sender
// confirmed it on /dev/tty or in an app's UI, and never from mcp or hook (D-CORE-9), so no same-user process, an
// agent's included, has the device vouch for a login the person never saw. Any same-uid process can forge the flag,
// the residual owner decision 47 discloses. An unconfirmed call is refused before its handler runs, and the handler
// refuses one again, so it signs nothing either way. The origin and the nonce are held to what a front issues before
// the device's standing is read, and only a member's consented device signs (ErrTlsEdgeLoginNotConsented).
//
// The reply carries the statement, the encoded Signed, and nothing secret of the device's: no key, seed or token, so
// the reply walk passes it. The statement completes one login at one origin: nothing here logs it, the origin or the
// nonce, and a refusal names none of them (I-7, I-13). No ur command sends the method; the app whose page asked does.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
)

// The method.
const (
	// A remote-mode app's Sidecar.SignEdgeLogin.
	DaemonMethodTlsEdgeLoginSign = "tls.edge_login.sign"
)

// The handler ran for a call no person confirmed, which only a host that registered it without Confirm lets through.
// Nothing is signed.
var errDaemonTlsEdgeLoginUnconfirmed = errors.New("an edge login is signed only for a call a person confirmed on /dev/tty or in an app")

// tls.edge_login.sign's params.
type DaemonTlsEdgeLoginSignParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// The origin of the page that asked, as the app's browser or its OS reports it, never one the page names for
	// itself: https://<a canonical host>, with :<port> where the port is not 443.
	Origin string `json:"origin"`
	// The nonce the front issued, its bytes.
	Nonce []byte `json:"nonce"`
}

// tls.edge_login.sign's reply.
type DaemonTlsEdgeLoginSignReply struct {
	// The encoded Signed, which the visitor's browser posts in base64url as the device step's s.
	Statement []byte `json:"statement"`
}

// The daemon's edge-login method, which the daemon's composition registers with RegisterMethod.
func DaemonTlsEdgeLoginMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodTlsEdgeLoginSign,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				// Confirm lets only a confirmed control call here; a host that registered the method otherwise signs
				// nothing
				if !call.Confirmed {
					return nil, errDaemonTlsEdgeLoginUnconfirmed
				}
				params := &DaemonTlsEdgeLoginSignParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				// an origin and a nonce a front issues, refused before the device's standing is read
				if _, err := NewTlsEdgeLogin(params.Origin, params.Nonce); err != nil {
					return nil, err
				}
				statement, err := call.Sidecar.SignTlsEdgeLogin(params.Origin, params.Nonce)
				if err != nil {
					return nil, err
				}
				return &DaemonTlsEdgeLoginSignReply{Statement: statement}, nil
			},
		},
	}
}
