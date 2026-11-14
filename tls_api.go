//go:build !ios_extension

// The bodies of §13.15's routes, and the kill entry sockets and tlsedge both read (§13.9). Every leg links this file,
// so it names no connect type (§4.4). A body holds an attestation as its Signed's encoded bytes, which keeps this file
// off protocol too and means nothing re-marshals what was signed (§22.6).
//
// Every stored field is §13.8's, or §2.8's cert-1 or tls-4, and one that neither row lists needs a row first (I-18).
// sidecartest/tls_api_rows_test.go holds that. A value that only rides a request is stored nowhere.
//
// encoding/json writes the wire: bytes as base64, times as RFC 3339, an Id as its text form.

package sidecar

import (
	"strings"
	"time"
)

// Where a row of network_tls_cert stands (§13.8). A row is written before its order, and it stays 30 days past expiry,
// revocation or failure (cert-1). A reader treats a state it does not know as no certificate.
type TlsCertState string

const (
	// Waiting its turn in certs' queue, or a custom domain's CSR waiting for a desktop to order it.
	TlsCertStateQueued TlsCertState = "queued"
	// At its CA.
	TlsCertStateOrdering TlsCertState = "ordering"
	// Its challenge is written, and the order waits on GET /dns/ready and §12.6's canary.
	TlsCertStateWaitingDns TlsCertState = "waiting_dns"
	// The CA issued it.
	TlsCertStateIssued TlsCertState = "issued"
	// No CA gave it a certificate, and nothing will retry it.
	TlsCertStateFailed TlsCertState = "failed"
	// A revocation is due and has not reached the CA.
	TlsCertStateRevoking TlsCertState = "revoking"
	// The CA took the revocation.
	TlsCertStateRevoked TlsCertState = "revoked"
	// Past its validity.
	TlsCertStateExpired TlsCertState = "expired"

	// A Team custom host's rows (DESIGN-DETAILS 17.2.4): one certificate per device and custom host, ordered under the
	// customer's own ACME account by an ordering desktop, in states no pass of certs reads. A reader that knows none
	// of the four treats each as no certificate, the right answer for an old reader.
	//
	// The CSR waits for an ordering desktop.
	TlsCertStateCustomQueued TlsCertState = "custom_queued"
	// A desktop took it under its account's lock, and its order is at the CA.
	TlsCertStateCustomOrdering TlsCertState = "custom_ordering"
	// Its chain is registered.
	TlsCertStateCustomIssued TlsCertState = "custom_issued"
	// A revocation is due, which only an ordering desktop can send.
	TlsCertStateCustomRevoking TlsCertState = "custom_revoking"
)

// Whether a row in this state is a custom host's that still waits for its chain: no certificate yet (17.2.4).
func (self TlsCertState) CustomOpen() bool {
	return self == TlsCertStateCustomQueued || self == TlsCertStateCustomOrdering
}

// Why a custom row failed, where its device acts on it (17.2.11): its attestation no longer verified at the ordering
// desktop, so the device queues a new CSR with a new one when it is next online.
const TlsCustomReasonAttestation = "attestation"

// What a CA is told when it revokes a certificate, in RFC 5280 §5.3.1's names (§13.8). A row holds one only while its
// revocation waits for its CA (cert-1). A reader treats a reason it does not know as none given.
type TlsCertRevocationReason string

const (
	// The key is compromised, by its device's or an admin's word.
	TlsCertRevocationReasonKeyCompromise TlsCertRevocationReason = "keyCompromise"
	// The names stop being served: a removal, a deletion, a retired alias or §21.6's takedown.
	TlsCertRevocationReasonCessationOfOperation TlsCertRevocationReason = "cessationOfOperation"
)

// POST /tls/cert-order's body. The token names the caller, never this body (§13.15).
type TlsCertOrderArgs struct {
	// A PKCS #10 request in DER, by the device's own P-256 key, for its TlsIdentifierSet.
	Csr []byte `json:"csr"`
	// SignTlsKeyAttestation's answer for that key and set.
	Attestation []byte `json:"attestation"`
	// RFC 9773's certificate id of the certificate this order replaces, which takes the order out of §13.8's limits
	// when that certificate is live. Rides the request and is stored nowhere: the row keeps its successor.
	Replaces string `json:"replaces,omitempty"`
}

// POST /tls/cert-order's answer: the row, written before anything else happens (§13.8).
type TlsCertOrderResult struct {
	CertId Id           `json:"cert_id"`
	State  TlsCertState `json:"state"`
	// How long to wait before asking GET /tls/cert-order/<id>, in milliseconds. Zero sets no wait.
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
}

// GET /tls/cert-order/<id>'s answer, for the caller's own order. The chain is the row's, which keeps it until 30 days
// past the certificate's expiry or revocation (cert-1), so a device that was offline, or asks after a restart, still
// reads it.
type TlsCertOrderStatus struct {
	State TlsCertState `json:"state"`
	// How long to wait before asking again, in milliseconds. Zero sets no wait.
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
	// Each certificate in DER, leaf first. Empty until the order issues.
	Chain [][]byte `json:"chain,omitempty"`
	// RFC 9773's suggested renewal window. Zero until the CA gives one.
	AriWindowStart time.Time `json:"ari_window_start,omitzero"`
	AriWindowEnd   time.Time `json:"ari_window_end,omitzero"`
}

// One row of network_tls_cert, with cert-1's fields. This is a server's answer: a reader acting on a row, as the CT
// watch does, verifies Attestation itself (VerifyTlsKeyAttestation), against the identity key its own config holds.
type TlsCertRecord struct {
	CertId    Id `json:"cert_id"`
	NetworkId Id `json:"network_id"`
	ClientId  Id `json:"client_id"`
	SidecarId Id `json:"sidecar_id"`
	// TlsIdentifierSetHash of its names.
	IdentifierSetSha256 []byte `json:"identifier_set_sha256"`
	// Of the key's DER SubjectPublicKeyInfo.
	SpkiSha256 []byte `json:"spki_sha256"`
	// SignTlsKeyAttestation's answer. A queued custom-domain row holds its device's, which its orderer checks.
	Attestation []byte `json:"attestation"`
	// The PKCS #10 request in DER, shown only in TlsCertsResult.QueuedCsrs.
	Csr []byte `json:"csr,omitempty"`
	// The CA, its account and its profile (§13.8). Empty until an order reaches one.
	Ca         string `json:"ca,omitempty"`
	AccountUri string `json:"account_uri,omitempty"`
	Profile    string `json:"profile,omitempty"`
	// The serial number in lowercase hex. Empty until it issues.
	Serial string `json:"serial,omitempty"`
	// Its validity. Zero until it issues.
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	// RFC 9773's suggested renewal window. Zero until the CA gives one.
	AriWindowStart time.Time    `json:"ari_window_start,omitzero"`
	AriWindowEnd   time.Time    `json:"ari_window_end,omitzero"`
	State          TlsCertState `json:"state"`
	// When the row came to State: its writing for a queued row, and each change of state after. A revoked or failed
	// row's 30 days count from it.
	StateTime time.Time `json:"state_time,omitzero"`
	// The row that took over from this one. Zero until one does.
	SuccessorCertId Id `json:"successor_cert_id,omitzero"`
	// The chain its CA issued, or a custom domain's registered one: each certificate in DER, leaf first. Empty until
	// the row has one, and again 30 days past the certificate's expiry or revocation.
	Chain [][]byte `json:"chain,omitempty"`
	// What the CA is to be told, while State is revoking. Empty in any other state: the row drops it once the CA
	// has taken the revocation.
	RevocationReason TlsCertRevocationReason `json:"revocation_reason,omitempty"`
	// Why a custom row failed, or went back to custom_queued (17.2.3's custom_reason). Off the wire until TLS-M6-05
	// gives it its json name with §2.8's lines (17.2.16), so no answer sets it yet and a device reads none: the
	// certificate manager's new CSR after TlsCustomReasonAttestation waits on that.
	CustomReason string `json:"-"`
}

// GET /tls/certs's answer: its network's certificates and their attestations, for the CT watch (D-TLS-8) and for a
// device checking that its row survived a restore.
type TlsCertsResult struct {
	Certs []*TlsCertRecord `json:"certs"`
	// A custom domain's CSRs waiting for an ordering desktop (§13.8, v1).
	QueuedCsrs []*TlsCertRecord `json:"queued_csrs,omitempty"`
}

// POST /tls/cert-register's body: a custom domain's chain, from a desktop that ordered it (§13.8, v1). The chain's key
// and names must match a queued or attested row, so a device cannot register another's key.
type TlsCertRegisterArgs struct {
	// The queued row this chain answers. Zero when the caller attests its own key instead.
	CertId Id `json:"cert_id,omitzero"`
	// SignTlsKeyAttestation's answer for the chain's key and names. Empty with a queued row, which holds its own.
	Attestation []byte `json:"attestation,omitempty"`
	// Each certificate in DER, leaf first.
	Chain [][]byte `json:"chain"`
	// The customer's ACME account that ordered it.
	AccountUri string `json:"account_uri"`
}

// POST /tls/cert-revoke's body.
type TlsCertRevokeArgs struct {
	CertId Id `json:"cert_id"`
	// Revokes with reason keyCompromise (§13.8); without it the CA is told cessationOfOperation. The revocation chain
	// runs after the request returns, so the reason waits in the row until the CA takes it (cert-1).
	KeyCompromise bool `json:"key_compromise,omitempty"`
}

// A kill's host naming all the network's hosts (§13.9).
const TlsKillAllHosts = "*"

// A row of network_tls_suspension, as §21's process asks for it: POST /tls/suspend's body once a caller outside api
// and taskworker exists, and until then the argument of the model call those two make (plan-TLS-internal-credentials).
type TlsSuspendArgs struct {
	NetworkId Id `json:"network_id"`
	// One host of the network, or TlsKillAllHosts.
	Host   string `json:"host"`
	Reason string `json:"reason"`
	// When it ends by itself. Zero holds it until its case lifts it.
	Until time.Time `json:"until,omitzero"`
}

// One kill as {tes_<network_id>} holds it and network_tls_suspension mirrors it (§13.9), whichever of tlsedge and
// sockets reads it: the hash's field is Host and its value this entry's JSON. A reload drops a kill only once neither
// place holds it, so a restore lifts nothing.
type TlsKillEntry struct {
	// One host of the network, or TlsKillAllHosts.
	Host   string `json:"host"`
	Reason string `json:"reason"`
	// When it ends by itself. Zero holds it until its case lifts it.
	Until time.Time `json:"until,omitzero"`
}

// Whether this kill refuses a connection to host at now: host is its host, or it names them all, and its until, if it
// has one, is still ahead. One rule for tlsedge and Find, so a name one refuses the other does not admit. An entry
// with no host refuses everything, since a kill that cannot say whom it spares spares no one.
func (self *TlsKillEntry) Kills(host string, now time.Time) bool {
	if !self.Until.IsZero() && !now.Before(self.Until) {
		return false
	}
	return self.Host == "" || self.Host == TlsKillAllHosts || self.Host == host
}

// Every network's {tes_}n, the family tlsedge and sockets watch on ServiceHost.Redis's shared subscriber (§13.9).
const TlsKillTriggerKeyPattern = "{tes_*}n"

// {tes_<network_id>}: the network's kills, a hash of host or TlsKillAllHosts to its TlsKillEntry's JSON (§13.9).
func TlsKillKey(networkId Id) string {
	return "{tes_" + networkId.String() + "}"
}

// {tes_<network_id>}n, in TlsKillKey's hash tag: INCR'd in the MULTI that writes the hash, since an INCR emits the key
// event a HSET does not (D-PROTO-12).
func TlsKillTriggerKey(networkId Id) string {
	return TlsKillKey(networkId) + "n"
}

// The network whose {tes_}n key is key, false for any other key.
func ParseTlsKillTriggerKey(key string) (Id, bool) {
	rest, found := strings.CutPrefix(key, "{tes_")
	if !found {
		return Id{}, false
	}
	idText, found := strings.CutSuffix(rest, "}n")
	if !found {
		return Id{}, false
	}
	networkId, err := ParseId(idText)
	if err != nil {
		return Id{}, false
	}
	return networkId, true
}
