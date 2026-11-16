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
	"fmt"
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
	// A Team custom row's host and its domain (DESIGN-DETAILS 17.2.5). Empty on every other row.
	CustomHost   string `json:"custom_host,omitempty"`
	CustomDomain string `json:"custom_domain,omitempty"`
	// Why a custom row failed, or went back to custom_queued (17.2.3's custom_reason): a TlsCustomReason.
	CustomReason string `json:"custom_reason,omitempty"`

	// On a row of an ordering desktop's work list only (TlsCertsResult.QueuedCsrs), computed for the answer:
	//
	// How long its budgets or holds ask it to wait, in milliseconds from the answer. Zero: claimable now.
	WaitMs uint32 `json:"wait_ms,omitempty"`
	// Its custom host is active with every lb interface current for it (§13.4), so TLS-ALPN-01 can reach it.
	HostReady bool `json:"host_ready,omitempty"`
	// The host owner's label, owner(c), whose tls/ names a TLS-ALPN-01 listener registers.
	Owner string `json:"owner,omitempty"`
}

// GET /tls/certs's answer: its network's certificates and their attestations, for the CT watch (D-TLS-8) and for a
// device checking that its row survived a restore. With ?work=1 an ordering desktop gets its accounts and its work
// list alone, so a poll carries no chains (DESIGN-DETAILS 17.2.5).
type TlsCertsResult struct {
	Certs []*TlsCertRecord `json:"certs"`
	// A custom domain's rows waiting for an ordering desktop, in 17.2.8's plan order, each with its CSR, attestation
	// and wait: the work list of an ordering desktop.
	QueuedCsrs []*TlsCertRecord `json:"queued_csrs,omitempty"`
	// The ordering desktop's accounts.
	Accounts []*TlsCustomAccount `json:"accounts,omitempty"`
}

// POST /tls/cert-register's body: a custom domain's chain, registered on the row the caller holds its account's lock
// for (DESIGN-DETAILS 17.2.5). Every custom certificate is a row first, so there is no body that attests its own key.
type TlsCertRegisterArgs struct {
	// The custom_ordering row this chain answers.
	CertId Id `json:"cert_id"`
	// The claim the caller holds the account's lock under.
	ClaimSeq uint64 `json:"claim_seq"`
	// Each certificate in DER, leaf first.
	Chain [][]byte `json:"chain"`
	// The customer's ACME account that ordered it, which must be the account row's.
	AccountUri string `json:"account_uri"`
	// RFC 9773's suggested window, zero when the CA gives none.
	AriWindowStart time.Time `json:"ari_window_start,omitzero"`
	AriWindowEnd   time.Time `json:"ari_window_end,omitzero"`
}

// A claim's purposes (DESIGN-DETAILS 17.2.6).
const (
	TlsCustomPurposeOrder    = "order"
	TlsCustomPurposeRevoke   = "revoke"
	TlsCustomPurposeRollover = "rollover"
)

// POST /tls/custom-progress's events (DESIGN-DETAILS 17.2.5).
const (
	// The granted newOrder's URL, which must answer 200 before anything else goes to the CA.
	TlsCustomEventOrderRecorded = "order_recorded"
	// The recorded order is dead at the CA, or the granted newOrder was refused.
	TlsCustomEventOrderInvalid = "order_invalid"
	// The order's authorization failed, with the problem's type.
	TlsCustomEventAuthzFailed = "authz_failed"
	// The CA answered 429, with its Retry-After.
	TlsCustomEventRateLimited = "rate_limited"
	// The CA refused the newOrder for its replaces.
	TlsCustomEventNotExempt = "not_exempt"
	// The holder gives the lock up.
	TlsCustomEventRelease = "release"
	// The row cannot be certified, with the reason.
	TlsCustomEventFailed = "failed"
	// A revocation reached the CA.
	TlsCustomEventRevoked = "revoked"
	// Renewal windows the CA moved, with no claim.
	TlsCustomEventAri = "ari"
	// A key change is due that this desktop may not make, with no claim.
	TlsCustomEventRolloverDue = "rollover_due"
)

// POST /tls/custom-account's operations (DESIGN-DETAILS 17.2.5, 17.2.13).
const (
	TlsCustomAccountCreate    = "create"
	TlsCustomAccountRollBegin = "roll_begin"
	TlsCustomAccountRollEnd   = "roll_end"
	TlsCustomAccountRollAbort = "roll_abort"
	TlsCustomAccountRepair    = "repair"
)

// A custom route's refusal reasons (DESIGN-DETAILS 17.2.5).
const (
	TlsCustomRefusalCsr       = "csr"
	TlsCustomRefusalGrant     = "grant"
	TlsCustomRefusalHost      = "host"
	TlsCustomRefusalNoAccount = "no_account"
	TlsCustomRefusalInFlight  = "in_flight"
	TlsCustomRefusalOrderer   = "orderer"
	TlsCustomRefusalKeySeq    = "key_seq"
	TlsCustomRefusalLocked    = "locked"
	TlsCustomRefusalState     = "state"
	TlsCustomRefusalBudget    = "budget"
	TlsCustomRefusalHold      = "hold"
	TlsCustomRefusalClaim     = "claim"
	TlsCustomRefusalChain     = "chain"
	TlsCustomRefusalExists    = "exists"
	TlsCustomRefusalRequest   = "request"
)

// A custom row's custom_reason values, beside TlsCustomReasonAttestation.
const (
	// A newer CSR of the same device and host took its place while it was queued.
	TlsCustomReasonSuperseded = "superseded"
	// Its CSR did not check at the ordering desktop.
	TlsCustomReasonCsr = "csr"
	// The CA refused the identifier or the CSR, so the same request would fail again.
	TlsCustomReasonCaRefused = "ca_refused"
	// The CA handed back a chain on another key or for other names.
	TlsCustomReasonForeign = "foreign"
	// The desktop's own probe of the challenge path failed, before the CA was asked.
	TlsCustomReasonNoRoute = "no_route"
	// No desktop had a challenge path for the row.
	TlsCustomReasonNoPath = "no_path"
	// Its device, host or domain was removed.
	TlsCustomReasonRemoved = "removed"
)

// A custom route's refusal, the whole body of its answer. Durations are milliseconds from the answer.
type TlsCustomRefusal struct {
	Reason       string `json:"reason"`
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
	// 409 in_flight: the row to claim instead.
	CertId Id `json:"cert_id,omitzero"`
	// 409 key_seq: the account row's key sequence.
	KeySeq uint64 `json:"key_seq,omitempty"`
}

// A custom route's refusal as an error: its status and body, which api's router answers.
type TlsCustomError struct {
	Status  int
	Refusal TlsCustomRefusal
}

// The status and the reason.
func (self *TlsCustomError) Error() string {
	return fmt.Sprintf("%d %s", self.Status, self.Refusal.Reason)
}

// The body the router answers with.
func (self *TlsCustomError) HttpErrorResultBody() any {
	refusal := self.Refusal
	return &refusal
}

// Whole seconds of the refusal's wait, rounded up; zero for none. api's router sets Retry-After from it.
func (self *TlsCustomError) RetryAfterSeconds() int {
	return int((self.Refusal.RetryAfterMs + 999) / 1000)
}

// An ordering desktop's view of one account (DESIGN-DETAILS 17.2.5): public values only. Never the account key.
type TlsCustomAccount struct {
	Domain     string `json:"domain"`
	Ca         string `json:"ca"`
	AccountUri string `json:"account_uri"`
	KeySeq     uint64 `json:"key_seq"`
	// RFC 7638's SHA-256 thumbprint of the current account key.
	KeyThumbprint []byte `json:"key_thumbprint"`
	// The secret repo that holds the key file.
	KeyRepoId Id `json:"key_repo_id"`
	// While a key change is in flight: the next key's thumbprint and repo.
	NextKeyThumbprint []byte `json:"next_key_thumbprint,omitempty"`
	NextKeyRepoId     Id     `json:"next_key_repo_id,omitzero"`
	// The lock's holder while it holds it, and how long until its lease ends.
	LockSidecarId    Id     `json:"lock_sidecar_id,omitzero"`
	LockRetryAfterMs uint32 `json:"lock_retry_after_ms,omitempty"`
	// What remains of the CA's 429 holds: no order outside an ARI renewal, and no order at all.
	HoldNewMs uint32 `json:"hold_new_ms,omitempty"`
	HoldAllMs uint32 `json:"hold_all_ms,omitempty"`
	// The TXT owner name DNS-01 values are written at: <acme_token>.acme.<root> (QD-175).
	AcmeName string `json:"acme_name"`
}

// POST /tls/custom-claim's body: take or renew an account's lock for one row or for a key change.
type TlsCustomClaimArgs struct {
	Domain  string `json:"domain"`
	Purpose string `json:"purpose"`
	// Zero for a rollover.
	CertId Id `json:"cert_id,omitzero"`
	// The key_seq of the key file the caller holds.
	KeySeq uint64 `json:"key_seq"`
}

// POST /tls/custom-claim's answer.
type TlsCustomClaimResult struct {
	ClaimSeq uint64 `json:"claim_seq"`
	LeaseMs  uint32 `json:"lease_ms"`
	// The row with its CSR and attestation, and for a revoke its chain.
	Record *TlsCertRecord `json:"record,omitempty"`
	// The order to resume. Empty when none is recorded.
	OrderUrl string `json:"order_url,omitempty"`
	// One newOrder is granted. False with an OrderUrl.
	MayOrder bool `json:"may_order,omitempty"`
	// The predecessor's leaf in DER when the order names it in replaces (RFC 9773). Empty for none.
	ReplacesLeaf []byte `json:"replaces_leaf,omitempty"`
}

// POST /tls/custom-progress's body.
type TlsCustomProgressArgs struct {
	Domain string `json:"domain"`
	// Required for every event but ari and rollover_due.
	ClaimSeq uint64 `json:"claim_seq,omitempty"`
	CertId   Id     `json:"cert_id,omitzero"`
	Event    string `json:"event"`
	// order_recorded.
	OrderUrl string `json:"order_url,omitempty"`
	// rate_limited.
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
	// failed, authz_failed.
	Reason string `json:"reason,omitempty"`
	// ari.
	Ari []*TlsCustomAri `json:"ari,omitempty"`
}

// One renewal window the CA gives a custom row's certificate.
type TlsCustomAri struct {
	CertId         Id        `json:"cert_id"`
	AriWindowStart time.Time `json:"ari_window_start"`
	AriWindowEnd   time.Time `json:"ari_window_end"`
}

// POST /tls/custom-account's body: network admins' desktops only.
type TlsCustomAccountArgs struct {
	Domain     string `json:"domain"`
	Op         string `json:"op"`
	AccountUri string `json:"account_uri"`
	// The row's key_seq as the caller read it; 0 for create.
	KeySeq        uint64 `json:"key_seq"`
	KeyThumbprint []byte `json:"key_thumbprint"`
	KeyRepoId     Id     `json:"key_repo_id"`
	// roll_*: the rollover claim.
	ClaimSeq uint64 `json:"claim_seq,omitempty"`
}

// POST /tls/custom-challenge's body (QD-175): a DNS-01 value for a host mapped under domain, which certs writes at
// <acme_token>.acme.<root>.
type TlsCustomChallengeArgs struct {
	Domain string `json:"domain"`
	// The 43-character base64url DNS-01 digest.
	Value string `json:"value"`
}

// POST /tls/custom-challenge's answer, and GET /tls/custom-challenge/<id>'s: whether the dns edges serve the value,
// GET /dns/ready's answer passed through (stale, ready, canary_failing or waiting).
type TlsCustomChallengeResult struct {
	// The serial the write took, which GET /tls/custom-challenge/<id> asks /dns/ready about.
	ChallengeId uint64 `json:"challenge_id"`
	Readiness   string `json:"readiness,omitempty"`
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
