// The steps every sockets route shares (§9.10, §9.15): who calls, §19.11's sockets gate, the control bound
// and the fair queue, the name a request carries, and the JSON answers. Each route's own file runs its steps
// around these, in DESIGN-DETAILS 13.2.3's order.
//
// Authentication. sockets' callers hold Client-class tokens (plan-SOCK-client-auth, QD-040), which the engine
// verifies through ServiceHost.Authenticate under SocketsAudience. A host whose Authenticator has no verifier
// for that audience, as sidecarhost's has none until plan-SOCK-client-auth's verify-only keyring lands, answers
// an error that is no refusal, and every authenticated route then answers unavailable, never an
// unauthenticated allow. A refused token answers 401, as does a client in the removed-client set. A token
// with no sidecar_id outside urnetwork-edge is denied (QD-040).
//
// Answers. A route answers 200 with its own JSON body, a refusal of the whole call in its error, except 401
// for a refused token or a removed client, and 503 with Retry-After while §19.11's sockets gate is closed for
// the network, which leaves the engine ready (§19.11). Nothing here logs or labels a name, a client or a
// network (I-13).

package socketsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The audience the engine authenticates its callers' Client-class tokens under (plan-SOCK-client-auth).
const SocketsAudience = "sockets"

// §9.4's and §9.5's formats as the routes check them, which every reader applies alike.
const (
	// A name in the clear, and a token path's segments.
	socketNameMaxByteCount      = 112
	socketNameMaxSegmentCount   = 8
	socketTokenSegmentByteCount = 16
	// nonce[24] || the name padded to 112 B, sealed || a 16 B tag.
	socketSealedNameByteCount = 152
	// A name key: a name, or a token path of 8 segments.
	socketNameKeyMaxByteCount = socketNameMaxSegmentCount * socketTokenSegmentByteCount
)

// Who calls, once authenticated.
type socketCaller struct {
	principal *sidecar.Principal
	// The caller is an urnetwork-edge platform client: it takes the edge bound and Finds as autogroup:public
	// (§9.10), and holds no sidecar.
	edge bool
	// The caller's §8 subject: its token's ur_subject_client_id, else its own client.
	subjectClientId connect.Id
}

// The gate request for this caller about name in networkId.
func (self *socketCaller) gateRequest(networkId connect.Id, name *socketParsedName) *SocketGateRequest {
	return &SocketGateRequest{
		NetworkId:       networkId,
		CallerClientId:  self.principal.ClientId,
		CallerNetworkId: self.principal.NetworkId,
		SubjectClientId: self.subjectClientId,
		SidecarId:       self.principal.SidecarId,
		Name:            name.name,
		NameToken:       name.nameToken,
	}
}

// A refusal of a whole call. status 200 answers the route's body with code in its error.
type socketRefusal struct {
	status     int
	code       sidecar.SocketErrorCode
	retryAfter time.Duration
}

// A 200 refusal with code, asking for retryAfter, 0 for none.
func socketRefusalOf(code sidecar.SocketErrorCode, retryAfter time.Duration) *socketRefusal {
	return &socketRefusal{status: http.StatusOK, code: code, retryAfter: retryAfter}
}

// The refusal's wait as retry_after_ms: whole milliseconds, rounded up, so a positive wait never reads as
// none, and at most a uint32's.
func socketRetryAfterMs(retryAfter time.Duration) uint32 {
	if retryAfter <= 0 {
		return 0
	}
	ms := (retryAfter + time.Millisecond - 1) / time.Millisecond
	return uint32(min(int64(ms), int64(^uint32(0))))
}

// The error a body carries for refusal, nil for none.
func (self *socketRefusal) socketError() *sidecar.SocketError {
	if self == nil {
		return nil
	}
	return &sidecar.SocketError{Code: self.code, RetryAfterMs: socketRetryAfterMs(self.retryAfter)}
}

// Writes value as the call's 200 answer.
func writeSocketJson(w http.ResponseWriter, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// Writes a refusal that is no 200: 401 bare, and 503 with Retry-After in whole seconds, rounded up.
func writeSocketStatus(w http.ResponseWriter, refusal *socketRefusal) {
	if refusal.status == http.StatusServiceUnavailable {
		seconds := int64((refusal.retryAfter + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(max(seconds, 1), 10))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(refusal.status)
}

// Reads a JSON body of at most maxByteCount into value. Anything else is the caller's malformed call.
func readSocketJson(r *http.Request, maxByteCount int64, value any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxByteCount+1))
	if err != nil {
		return err
	}
	if maxByteCount < int64(len(body)) {
		return errors.New("socket call body too large")
	}
	return json.Unmarshal(body, value)
}

// §9.15's Client class: the caller's token, verified under SocketsAudience, its client not removed, and a
// sidecar's unless it is urnetwork-edge's. A refusal says how to answer.
func (self *SocketsService) authenticate(r *http.Request) (*socketCaller, *socketRefusal) {
	jwt, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || jwt == "" {
		return nil, &socketRefusal{status: http.StatusUnauthorized}
	}
	principal, err := self.host.Authenticate(r.Context(), SocketsAudience, jwt)
	switch {
	case errors.Is(err, sidecar.ErrAuthenticationRefused):
		return nil, &socketRefusal{status: http.StatusUnauthorized}
	case err != nil:
		// nothing is known about the token, so the caller retries rather than signs out
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	if self.removedClients.contains(principal.ClientId, self.clock.Now()) {
		return nil, &socketRefusal{status: http.StatusUnauthorized}
	}
	caller := &socketCaller{
		principal:       principal,
		edge:            self.isUrnetworkEdge(principal.NetworkId),
		subjectClientId: principal.ClientId,
	}
	if principal.SubjectClientId != nil {
		caller.subjectClientId = *principal.SubjectClientId
	}
	if principal.SidecarId == nil && !caller.edge {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
	}
	return caller, nil
}

// §19.11's sockets gate for networkId: closed answers 503 with the gates' reread interval as Retry-After.
func (self *SocketsService) gateRefusal(networkId connect.Id) *socketRefusal {
	gates := self.host.GatesOrClosed()
	if gates.Service(sidecar.ServiceGateSockets).Admits(networkId) {
		return nil
	}
	return &socketRefusal{status: http.StatusServiceUnavailable, retryAfter: gates.RetryAfter()}
}

// One token of the caller's bucket (§9.10, D-SOCK-15), before anything is read or signed.
func (self *SocketsService) chargeRefusal(caller *socketCaller) *socketRefusal {
	allowed, retryAfter := self.bound.Charge(caller.principal.ClientId, caller.edge)
	if allowed {
		return nil
	}
	return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, min(max(retryAfter, time.Millisecond), self.settings.MaxRetryAfter))
}

// A turn in the fair queue for networkId's calls. release must be called once the call is done.
func (self *SocketsService) queueTurn(ctx context.Context, networkId connect.Id) (release func(), refusal *socketRefusal) {
	release, err := self.fairQueue.Acquire(ctx, networkId)
	if err != nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	return release, nil
}

// A name as a request carries it: an edge name in the clear, or a blinded name's token path.
type socketParsedName struct {
	// tls/, smtp/ and ur/ names only, canonical; "" for a token path.
	name string
	// tls/'s and smtp/'s <host>; "" otherwise.
	host string
	// A token path, 16 B a segment; nil for an edge name.
	nameToken []byte
	// The engine cannot tell an application token path from a share/ one, and needs not, since the gate
	// judges both alike: a token path reads as SocketNamespaceApplication.
	namespace sidecar.SocketNamespace
}

// What a group, a page and the client's set key the name by (§9.5).
func (self *socketParsedName) nameKey() []byte {
	if self.name != "" {
		return []byte(self.name)
	}
	return self.nameToken
}

// Whether the name is a tls/ or smtp/ one, which a {svc_} pair stands for (QD-656).
func (self *socketParsedName) pairName() bool {
	return self.namespace == sidecar.SocketNamespaceTls || self.namespace == sidecar.SocketNamespaceSmtp
}

// Whether a token path has §9.4's shape: 1 to 8 whole segments.
func socketTokenPathFormed(nameToken []byte) bool {
	segmentCount := len(nameToken) / socketTokenSegmentByteCount
	return len(nameToken)%socketTokenSegmentByteCount == 0 && 1 <= segmentCount && segmentCount <= socketNameMaxSegmentCount
}

// The name exactly one of name and nameToken carries, or false. A name in the clear must be canonical and an
// edge name's (D-SOCK-13): the service refuses any other plaintext name, and never folds one, since the
// bytes a client sends are the key it pages and claims by.
func parseSocketRequestName(name string, nameToken []byte) (*socketParsedName, bool) {
	if (name == "") == (len(nameToken) == 0) {
		return nil, false
	}
	if name == "" {
		if !socketTokenPathFormed(nameToken) {
			return nil, false
		}
		return &socketParsedName{nameToken: nameToken, namespace: sidecar.SocketNamespaceApplication}, true
	}
	if socketNameMaxByteCount < len(name) {
		return nil, false
	}
	canonicalName, namespace, err := sidecar.ParseSocketName(name)
	if err != nil || canonicalName != name {
		return nil, false
	}
	parsed := &socketParsedName{name: name, namespace: namespace}
	switch namespace {
	case sidecar.SocketNamespaceTls, sidecar.SocketNamespaceSmtp:
		// <first>/<port>/<host>, which the grammar has checked
		parsed.host = name[strings.LastIndexByte(name, '/')+1:]
	case sidecar.SocketNamespacePlatform:
	default:
		return nil, false
	}
	return parsed, true
}

// The name a store key is: an edge name's own, or a token path, which parses as no edge name but by a
// chance no HMAC gives (SocketPairNameKey's caveat).
func parseSocketNameKey(nameKey []byte) *socketParsedName {
	if parsed, ok := parseSocketRequestName(string(nameKey), nil); ok {
		return parsed
	}
	return &socketParsedName{nameToken: nameKey, namespace: sidecar.SocketNamespaceApplication}
}
