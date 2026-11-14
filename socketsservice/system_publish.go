// §13.9's system publish on the engine (§9.10, §15.5, D-SOCK-14, X3, I-8; SOCK-M8-01): tls/443/mta-sts, where a mail
// receiver serves its network's MTA-STS policy, audience public and app mode http, with no tls/ grant of its own. For
// this name alone, each receiver's own approved smtp/25/mx listen grant stands in for the tls/ listen and publish
// grants, and the engine asks the gate that listen in their place:
//
//	registration  MayListen on smtp/25/mx for the caller's sidecar, while the entry registers app mode http, the
//	              publish's one mode; the name's own tls/ grants count for nothing, so a non-receiver is refused
//	              whatever it holds. The verdict is the one ValidateListen gets (§13.9's other lines are TLS-M8-02's:
//	              a certificate row, network_verified and a mail_network row)
//	Find          step 3 asks nothing: an edge's Find runs as autogroup:public, which the publish's audience public
//	              always admits, and each picked receiver's own listen decides at step 7, as on smtp/. The listener
//	              check asks that listen of the lease's stored sidecar, and its verdict is what the ticket and the
//	              edge's {svc_} pair rest on: its grant id and expiry
//	the sweep     the same listener check, so a revocation's sweep removes the lease
//
// Its expiry or revocation ends that receiver's publish: the next heartbeat answers revoked, a Find refuses and removes
// the lease at its listener check, the sweep removes it, and a ticket's grant_expire_time_millis is the grant's expiry,
// at which the listener resets the stream; the listener holds its half (socket_admission.go). No other name takes this
// path, tls/<port>/mta-sts on another port included, and it takes no tls_endpoints unit (§13.9): units are counted at a
// publish grant's activation (§20.7), and this publish activates none. The engine counts no unit for any name.
//
// Everything here is a function of a view, so the fake gate and the production gate alike see only the smtp/25/mx
// listen asked of them. Safe for concurrent use.

package socketsservice

import (
	"time"

	"github.com/urnetwork/sidecar"
)

// Whether name is §13.9's system publish, which no other name is.
func socketSystemPublish(name *socketParsedName) bool {
	return name != nil && name.namespace == sidecar.SocketNamespaceTls && name.name == sidecar.SocketSystemPublishName
}

// request as the stand-in asks it: the same caller, subject and sidecar, on smtp/25/mx.
func socketSystemPublishRequest(request *SocketGateRequest) *SocketGateRequest {
	standIn := *request
	standIn.Name = sidecar.SocketSystemPublishListenName
	standIn.NameToken = nil
	return &standIn
}

// The system publish's verdict at now for request's sidecar, which a registration of appMode asks: the sidecar's own
// smtp/25/mx listen, standing in for the tls/ listen and publish grants, and a refusal for any app mode but http.
func socketSystemPublishListen(view SocketGateView, request *SocketGateRequest, appMode string, now time.Time) *SocketGateVerdict {
	if appMode != socketDefaultTlsAppMode {
		return &SocketGateVerdict{}
	}
	return view.MayListen(socketSystemPublishRequest(request), now)
}

// The listen verdict a registration's entry rests on (registration step 5): MayListen on its name, except on the system
// publish, where the caller's own smtp/25/mx listen stands in. stored is the entry with §9.5's defaults applied.
func socketEntryListen(view SocketGateView, request *SocketGateRequest, name *socketParsedName, stored *sidecar.SocketRegistration, now time.Time) *SocketGateVerdict {
	if socketSystemPublish(name) {
		return socketSystemPublishListen(view, request, stored.AppMode, now)
	}
	return view.MayListen(request, now)
}

// The listener check's grants on a lease of the system publish (find step 7, and the sweep's): the listener's own
// smtp/25/mx listen, for the sidecar its lease stored, while the lease registers app mode http. On a pass, the verdict
// its ticket and pair rest on.
func socketSystemPublishListenerCheck(view SocketGateView, request *SocketGateRequest, listener *SocketStoreListener, now time.Time) (socketListenerCheck, *SocketGateVerdict) {
	appMode := ""
	if listener.Registration != nil {
		appMode = listener.Registration.AppMode
	}
	listen := socketSystemPublishListen(view, request, appMode, now)
	if listen == nil || !listen.Allowed {
		return socketListenerRefused, nil
	}
	return socketListenerPassed, listen
}
