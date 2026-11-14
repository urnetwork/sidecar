//go:build !ios_extension

// The bodies of §12.8's record routes (DNS-M5-12; R-DNS-2, D-DNS-7, plan-DNS-sidecar-zone-read), on every leg but the
// ios_extension legs, with no connect import: POST /dns/records and GET /dns/zone on the dns block, which DnsClient
// calls with a service token of aud dns, and POST /network/dns/records and GET /network/dns on api, which the console
// calls with the network credential. api and the block write through one model function, so the two write routes take
// one body and give one answer.
//
// A name is an owner in its canonical form: lowercase, fully qualified with its final dot and with no escape, at or
// below the zone's apex <label>.<root>. A type is its mnemonic (A, AAAA, CNAME, TXT, MX, SRV), and a value one record's
// RDATA in presentation form. A write under a decision (§16.6) names exactly one RRset with one value, or one delete,
// which must equal its CanonicalAction's dns_name, dns_type, dns_value and dns_ttl (plan reading 12), and carries the
// decision in Approval and the use's effect key in Idempotency-Key, base64url with no padding.
//
// A refusal is a DnsApiError: its status, a stable code, and for a limit the QuotaRefusal that is its whole body
// (§20.7's Refusals paragraph).

package sidecar

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// §12.8's routes and the ones plan-DNS-sidecar-zone-read adds, as their paths read. The /dns/ routes are the dns
// block's, under §7.4's /dns/* for sidecars; the /network/dns routes are api's, for the console and network
// credentials.
const (
	DnsRecordsPath        = "/dns/records"
	DnsZonePath           = "/dns/zone"
	NetworkDnsPath        = "/network/dns"
	NetworkDnsRecordsPath = "/network/dns/records"
)

// The header a write under a decision names its use's effect key in (§16.6), as base64url with no padding.
const DnsIdempotencyKeyHeader = "Idempotency-Key"

// The codes of DnsApiError.
const (
	// A body, name, type or value the route does not take, or a record §12.7 refuses: 400.
	DnsApiCodeInvalid = "invalid"
	// No grant or decision covers the write, or the network's standing refuses it: 403.
	DnsApiCodeRefused = "refused"
	// The zone or a host it names is suspended (§12.9): 403.
	DnsApiCodeSuspended = "suspended"
	// expect_version is not the zone's version, and nothing was written: 409.
	DnsApiCodeVersionConflict = "version_conflict"
	// Every use of the decision is taken or cancelled (§16.6's 409 SPENT).
	DnsApiCodeSpent = "spent"
	// A limit of §20 or §21.7: the body is the QuotaRefusal, 402 or 429.
	DnsApiCodeQuota = "quota"
	// The service cannot answer now, a restore or a state it has not loaded: 503, with Retry-After.
	DnsApiCodeUnavailable = "unavailable"
)

// One RRset a write replaces with Values. Ttl zero takes dns.yml's ttl.user.
type DnsRecordUpsert struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Ttl    uint32   `json:"ttl,omitempty"`
	Values []string `json:"values"`
}

// One RRset a write removes whole.
type DnsRecordDelete struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// The decision a write spends a use of (§16.6, D-MCP-11): what the gate's spend check reads, as stored.
type DnsRecordsApproval struct {
	// Each Signed ApprovalDecision the use spends on: one, or a rule's k.
	Decisions [][]byte `json:"decisions"`
	// This use's CanonicalAction.
	Action []byte `json:"action"`
	// A multi-use decision's template, which the decisions hash and the action falls inside; omitted when they
	// hash the action itself.
	Template []byte `json:"template,omitempty"`
}

// The body of POST /dns/records and POST /network/dns/records: §12.8's {expect_version, upserts, deletes}.
type DnsRecordsRequest struct {
	// When set, the write goes ahead only while the zone's version is this, its last write's serial (plan reading 3).
	ExpectVersion *uint64           `json:"expect_version,omitempty"`
	Upserts       []DnsRecordUpsert `json:"upserts,omitempty"`
	Deletes       []DnsRecordDelete `json:"deletes,omitempty"`
	// POST /dns/records under a decision rather than a standing grant.
	Approval *DnsRecordsApproval `json:"approval,omitempty"`
}

// The answer of a write: the zone's version after it, the serial it took, or the version it found when nothing
// needed writing. Under a decision a retry answers these same bytes from the use's row.
type DnsRecordsAnswer struct {
	Version uint64 `json:"version"`
}

// One RRset of a zone as GET /dns/zone and GET /network/dns show it. Kind is the row's (user, system, edge, router,
// copy, challenge, canary, key or withheld); an edge or router row answers the healthy lb interfaces and holds no
// values, and a copy row answers the wildcard's.
type DnsZoneRecordSet struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Ttl    uint32   `json:"ttl"`
	Kind   string   `json:"kind"`
	Values []string `json:"values,omitempty"`
}

// A network's zone as GET /dns/zone answers a sidecar (plan-DNS-sidecar-zone-read): its label, allocated on first
// need, its alias and its version, and the RRsets of the owners on which the caller holds publish or admin on
// dns:<host>, by §8's gate. GET /network/dns answers the same with every RRset and the quota.
type DnsZone struct {
	NetworkId Id `json:"network_id"`
	// The root, canonical.
	Root  string `json:"root"`
	Label string `json:"label"`
	// Empty while the network has none.
	Alias string `json:"alias,omitempty"`
	// The serial of the zone's last write, zero before any.
	Version    uint64             `json:"version"`
	RecordSets []DnsZoneRecordSet `json:"record_sets"`
}

// The zone's apex, <label>.<root>, canonical; empty while it has no label.
func (self *DnsZone) Apex() string {
	if self.Label == "" || self.Root == "" {
		return ""
	}
	return self.Label + "." + self.Root
}

// What GET /network/dns answers the console: the zone and dns_entries' count against its limit (§20.4), -1 for
// none.
type NetworkDns struct {
	DnsZone
	EntryCount int64 `json:"entry_count"`
	EntryLimit int64 `json:"entry_limit"`
}

// A refusal of a record route. Error starts with the status and a space, the convention api's router answers by.
type DnsApiError struct {
	Status int
	// One of the DnsApiCode constants.
	Code string
	// What the caller may be told, never a token or a name it did not send.
	Message string
	// DnsApiCodeQuota: the refusal, which is the whole body.
	Refusal *QuotaRefusal
	// A 503's or 429's wait; zero for none.
	RetryAfter time.Duration
}

// The status, the code and the message.
func (self *DnsApiError) Error() string {
	if self.Message == "" {
		return fmt.Sprintf("%d %s", self.Status, self.Code)
	}
	return fmt.Sprintf("%d %s: %s", self.Status, self.Code, self.Message)
}

// Whole seconds of RetryAfter, rounded up; zero for none. api's router sets Retry-After from it.
func (self *DnsApiError) RetryAfterSeconds() int {
	if self.RetryAfter <= 0 {
		return 0
	}
	return int((self.RetryAfter + time.Second - 1) / time.Second)
}

// The body a refusal answers with: the QuotaRefusal for a limit, else the code and message.
func (self *DnsApiError) HttpErrorResultBody() any {
	if self.Refusal != nil {
		refusal := *self.Refusal
		return &refusal
	}
	return &dnsApiErrorBody{Code: self.Code, Message: self.Message}
}

// What a refusal's body holds when it is no QuotaRefusal.
type dnsApiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"error,omitempty"`
}

// A refusal of a limit: 429 with Retry-After when a window resets, 402 when a purchase or a higher tier lifts it,
// else 429, as api's QuotaRefusalError answers.
func NewDnsQuotaError(refusal *QuotaRefusal) *DnsApiError {
	status := http.StatusTooManyRequests
	if refusal.RetryAfterMs == 0 && refusal.Upgrade {
		status = http.StatusPaymentRequired
	}
	copied := *refusal
	return &DnsApiError{
		Status:     status,
		Code:       DnsApiCodeQuota,
		Message:    fmt.Sprintf("limit %s reached", refusal.LimitKey),
		Refusal:    &copied,
		RetryAfter: time.Duration(refusal.RetryAfterMs) * time.Millisecond,
	}
}

// The refusal a route's answer of status and body says, its Retry-After seconds given as read: a QuotaRefusal for a
// 402 or a 429 whose body has a limit_key, else the body's code, and invalid's when it has none. Never fails: a body
// it cannot read gives the status's own code.
func ParseDnsApiError(status int, body []byte, retryAfter time.Duration) *DnsApiError {
	apiError := &DnsApiError{Status: status, RetryAfter: retryAfter}
	if status == http.StatusPaymentRequired || status == http.StatusTooManyRequests {
		refusal := &QuotaRefusal{}
		if json.Unmarshal(body, refusal) == nil && refusal.LimitKey != "" {
			apiError.Code = DnsApiCodeQuota
			apiError.Refusal = refusal
			apiError.Message = fmt.Sprintf("limit %s reached", refusal.LimitKey)
			if apiError.RetryAfter <= 0 && 0 < refusal.RetryAfterMs {
				apiError.RetryAfter = time.Duration(refusal.RetryAfterMs) * time.Millisecond
			}
			return apiError
		}
	}
	errorBody := &dnsApiErrorBody{}
	if json.Unmarshal(body, errorBody) == nil && isSidecarApiCode(errorBody.Code) {
		apiError.Code = errorBody.Code
		apiError.Message = errorBody.Message
		return apiError
	}
	switch {
	case status == http.StatusServiceUnavailable:
		apiError.Code = DnsApiCodeUnavailable
	case status == http.StatusForbidden:
		apiError.Code = DnsApiCodeRefused
	case status == http.StatusConflict:
		apiError.Code = DnsApiCodeVersionConflict
	default:
		apiError.Code = DnsApiCodeInvalid
	}
	return apiError
}

// owner's canonical form, the one every record route takes: lowercase, with its final dot.
func CanonicalDnsRecordName(owner string) string {
	owner = dnsAsciiLower(strings.TrimSpace(owner))
	if !strings.HasSuffix(owner, ".") {
		owner += "."
	}
	return owner
}

// The body of POST /dns/key-record (§12.8, DNS-M7-02): a receiver's key for host, its DER SubjectPublicKeyInfo, and
// the TlsKeyAttestation its identity key signed for that key and the host's identifier set (§13.8), so the TLSA the
// write publishes names only a key the caller holds.
type DnsKeyRecordRequest struct {
	// mx, or mx.<scope> for a Team scope's receiver.
	Host        string `json:"host"`
	Spki        []byte `json:"spki"`
	Attestation []byte `json:"attestation"`
}

// The answer of POST /dns/key-record: the zone's version once the host's TLSA holds the key.
type DnsKeyRecordAnswer struct {
	Version uint64 `json:"version"`
}

// §12.8's key route on the dns block.
const DnsKeyRecordPath = "/dns/key-record"
