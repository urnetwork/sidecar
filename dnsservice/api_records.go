// §12.8's record routes on the dns block for sidecars (DNS-M5-12; R-DNS-2, R-DNS-3, D-DNS-7, D-MCP-11, D-MCP-12, I-8,
// Q-DNS-6; plan-DNS-sidecar-zone-read): POST /dns/records and GET /dns/zone, under §7.4's /dns/*, each taking a
// service token of aud dns from an admitted sidecar of the network (§7.8), never the internal bearers. The bodies are
// the sidecar root's (dns_records.go), which api's /network/dns routes share.
//
// POST /dns/records under a standing grant: §8.10's gate first, admin on dns:<host> for every owner the write names
// (DnsRecordGate), refused 403, or 503 while the gate has not loaded the network's state; then the model's one write
// (DnsRecordStore), whose transaction holds every other check in §12.8's order. Under a decision rather than a grant
// (the body's approval and an Idempotency-Key), the model's transaction runs §16.6's gate first instead: a use stored
// under the effect key answers with its stored bytes and no write, even past not_after or with a stale
// expect_version; else the spend check, which needs the one RRset the write names to equal the decision's
// CanonicalAction, then the use's claim, consumed in the write's own transaction.
//
// GET /dns/zone: the label, allocated on first need, the alias and the version, and the RRsets of the owners on whose
// host the caller holds publish or admin on dns:<host> by the same gate, never the whole zone, which §12.8 keeps to
// read roles on api. While the gate has not loaded the network, the view holds no RRset
// (plan-DNS-sidecar-zone-read's interim), so no device starts an order on it.
//
// A block whose host gives no store answers 503 to both, and one whose host gives no gate answers 503 to a write under
// a grant and shows no RRset, so nothing passes around the gate. §19.11's dns gate applies: disabled answers 503, and
// writes: false refuses POST.

package dnsservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

// The audience of every service token the block takes (§7.8).
const DnsServiceTokenAudience = "dns"

// What §8.10's gate says of one caller and host.
type DnsGateVerdict int

const (
	// No grant covers it.
	DnsGateDenied DnsGateVerdict = iota
	// A grant covers it.
	DnsGateAllowed
	// The gate has not loaded the network's state, or the host holds none: refuse, 503.
	DnsGateUnavailable
)

// §8.10's gate for the record routes (I-5, I-8): what the caller's grants allow on dns:<host>, where <host> is @, one
// label or, in a v1 Team scope, <host>.<scope> (§8.4). From memory with no I/O, so a model transaction may ask it.
// Safe for concurrent use.
type DnsRecordGate interface {
	// admin on dns:<host>: a write under a standing grant (§12.8).
	MayAdmin(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict
	// publish or admin on dns:<host>: what GET /dns/zone shows the caller (plan-DNS-sidecar-zone-read).
	MayView(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict
}

// The gate over the process's gate cache (C-09) and its view for the dns service (ACL-M5-01's AclGateView), which
// folds in the abuse halt and quota the rows cannot carry.
type dnsAclRecordGate struct {
	view   *sidecar.AclGateView
	states sidecar.AclContractStateSource
}

// The record routes' gate over view and the cache it wraps, states. Either nil answers unavailable to everything.
func NewDnsAclRecordGate(view *sidecar.AclGateView, states sidecar.AclContractStateSource) DnsRecordGate {
	return &dnsAclRecordGate{view: view, states: states}
}

// A view decision as a verdict: a state not loaded is unavailable, any other refusal denied.
func dnsGateVerdictOf(decision sidecar.AclDecision) DnsGateVerdict {
	switch {
	case decision.Allowed:
		return DnsGateAllowed
	case decision.Reason == sidecar.AclReasonNoState:
		return DnsGateUnavailable
	}
	return DnsGateDenied
}

func (self *dnsAclRecordGate) MayAdmin(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict {
	if self.view == nil || self.states == nil {
		return DnsGateUnavailable
	}
	return dnsGateVerdictOf(self.view.MayAdminDns(networkId, sidecar.AclSidecarSubject(sidecarId), host, now))
}

// admin through the view, which applies its refusals, then publish on the same loaded state, which the view has no
// method for: a rule refusal of admin means the state is loaded and the network neither halted nor over its limit.
func (self *dnsAclRecordGate) MayView(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict {
	if self.view == nil || self.states == nil {
		return DnsGateUnavailable
	}
	subject := sidecar.AclSidecarSubject(sidecarId)
	verdict := dnsGateVerdictOf(self.view.MayAdminDns(networkId, subject, host, now))
	if verdict != DnsGateDenied {
		return verdict
	}
	snapshot, status := self.states.State(networkId)
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		return DnsGateUnavailable
	}
	if snapshot.Acl.MayPublish(subject, host, now).Allowed {
		return DnsGateAllowed
	}
	return DnsGateDenied
}

// The gate of a host that installed none: unavailable to everything, so no write passes under a grant and the zone
// view shows nothing.
type DnsUnloadedRecordGate struct{}

func (self DnsUnloadedRecordGate) MayAdmin(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict {
	return DnsGateUnavailable
}

func (self DnsUnloadedRecordGate) MayView(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) DnsGateVerdict {
	return DnsGateUnavailable
}

// The host an owner of root sits under, as §8.4's dns:<host> names it: @ for the apex <label>.<root> and an underscore
// owner directly below it, else the label directly below the apex, through a wildcard, an underscore label or an SRV
// owner's two. False for root itself and a name outside it.
func DnsOwnerHost(root string, owner string) (string, bool) {
	rest, ok := strings.CutSuffix(owner, "."+root)
	if !ok || rest == "" {
		return "", false
	}
	labels := dns.SplitDomainName(rest + ".")
	if len(labels) == 1 {
		return "@", true
	}
	host := labels[len(labels)-2]
	if strings.HasPrefix(host, "_") {
		return "@", true
	}
	return host, true
}

// One write as the block hands it to the model.
type DnsRecordsCall struct {
	Root      string
	NetworkId sidecar.Id
	SidecarId sidecar.Id
	ClientId  sidecar.Id
	Request   *sidecar.DnsRecordsRequest
	// The Idempotency-Key's bytes under a decision; nil under a standing grant.
	EffectKey []byte
	// The request's time on the block's clock, which the decision's spend check reads.
	Now time.Time
}

// The model's half of the record routes: §12.8's one write and GET /dns/zone's read. Safe for concurrent use.
type DnsRecordStore interface {
	// One write through §12.6's path, the standing grant already checked by the block, or under call.Request.Approval.
	// Returns the answer's body, which a stored use answers again byte for byte, or a *sidecar.DnsApiError; any other
	// error is a failure, answered 503.
	WriteRecords(ctx context.Context, call *DnsRecordsCall) ([]byte, error)
	// The network's zone in root, its label allocated on first need, with every RRset; the block keeps those the
	// caller may see.
	Zone(ctx context.Context, root string, networkId sidecar.Id) (*sidecar.DnsZone, error)
}

// The record routes.
func (self *DnsApi) recordRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: sidecar.DnsRecordsPath, serviceToken: true, write: true, serve: self.serveRecords},
		{method: http.MethodGet, path: sidecar.DnsZonePath, serviceToken: true, serve: self.serveZone},
	}
}

// The labels of the record counter.
const (
	dnsRecordsResultWritten     = "written"
	dnsRecordsResultRefused     = "refused"
	dnsRecordsResultUnavailable = "unavailable"
	dnsRecordsResultFailed      = "failed"
)

// The principal a service-token route runs for, which guard put on the request's context.
type dnsPrincipalContextKey struct{}

// The request's caller: its network, its sidecar and its client.
func dnsRequestPrincipal(request *http.Request) (*sidecar.Principal, bool) {
	principal, ok := request.Context().Value(dnsPrincipalContextKey{}).(*sidecar.Principal)
	return principal, ok && principal != nil && principal.SidecarId != nil
}

// Authenticates a service-token route's bearer (§7.8): 401 for a token the host refuses, 503 when it cannot say,
// 403 for a token that is no sidecar's. Returns the request with the principal on its context, or nil once answered.
func (self *DnsApi) authenticateServiceToken(writer http.ResponseWriter, request *http.Request) *http.Request {
	bearer, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		self.metrics.refused.Add(1, dnsApiRefusedCredential)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	principal, err := self.host.Authenticate(request.Context(), DnsServiceTokenAudience, bearer)
	switch {
	case errors.Is(err, sidecar.ErrAuthenticationRefused):
		self.metrics.refused.Add(1, dnsApiRefusedCredential)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return nil
	case err != nil:
		self.metrics.refused.Add(1, dnsApiRefusedCredential)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return nil
	case principal.SidecarId == nil:
		// a client's token that names no sidecar: the routes are sidecars'
		self.metrics.refused.Add(1, dnsApiRefusedCredential)
		http.Error(writer, "forbidden", http.StatusForbidden)
		return nil
	}
	return request.WithContext(context.WithValue(request.Context(), dnsPrincipalContextKey{}, principal))
}

// Answers a refusal as the routes' bodies say, with Retry-After for a 503 or a window.
func (self *DnsApi) writeRecordsError(writer http.ResponseWriter, apiError *sidecar.DnsApiError) {
	retryAfter := apiError.RetryAfterSeconds()
	if apiError.Status == http.StatusServiceUnavailable && retryAfter == 0 {
		retryAfter = max(int(math.Ceil(self.host.GatesOrClosed().RetryAfter().Seconds())), 1)
	}
	if 0 < retryAfter {
		writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	body, _ := json.Marshal(apiError.HttpErrorResultBody())
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(apiError.Status)
	writer.Write(body)
}

// The request's root: the one dns.yml names, since a sidecar's zone is in the block's one root in v0.
func (self *DnsApi) recordsRoot() (string, bool) {
	if len(self.settings.Roots) != 1 {
		return "", false
	}
	return self.settings.Roots[0], true
}

func (self *DnsApi) serveRecords(writer http.ResponseWriter, request *http.Request) {
	principal, ok := dnsRequestPrincipal(request)
	if !ok {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	invalid := func(message string) {
		self.metrics.records.Add(1, dnsRecordsResultRefused)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusBadRequest, Code: sidecar.DnsApiCodeInvalid, Message: message})
	}
	if self.deps.Records == nil {
		self.metrics.records.Add(1, dnsRecordsResultUnavailable)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return
	}
	root, ok := self.recordsRoot()
	if !ok {
		invalid("no one root")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(self.settings.Api.RecordsRequestMaxByteCount)+1))
	if err != nil || self.settings.Api.RecordsRequestMaxByteCount < len(body) {
		invalid("a body past the bound")
		return
	}
	recordsRequest := &sidecar.DnsRecordsRequest{}
	if err := json.Unmarshal(body, recordsRequest); err != nil {
		invalid("a body that does not parse")
		return
	}
	networkId := sidecar.Id(principal.NetworkId)
	sidecarId := sidecar.Id(*principal.SidecarId)
	now := self.clock.Now()
	call := &DnsRecordsCall{
		Root:      root,
		NetworkId: networkId,
		SidecarId: sidecarId,
		ClientId:  sidecar.Id(principal.ClientId),
		Request:   recordsRequest,
		Now:       now,
	}
	keyText := request.Header.Get(sidecar.DnsIdempotencyKeyHeader)
	switch {
	case recordsRequest.Approval != nil:
		effectKey, err := base64.RawURLEncoding.DecodeString(keyText)
		if err != nil || len(effectKey) == 0 {
			invalid("a decision with no Idempotency-Key")
			return
		}
		call.EffectKey = effectKey
	case keyText != "":
		invalid("an Idempotency-Key with no decision")
		return
	default:
		// a standing grant: admin on dns:<host> for every owner, before the model's transaction
		gate := self.deps.RecordGate
		if gate == nil {
			gate = DnsUnloadedRecordGate{}
		}
		owners := []string{}
		for _, upsert := range recordsRequest.Upserts {
			owners = append(owners, upsert.Name)
		}
		for _, recordDelete := range recordsRequest.Deletes {
			owners = append(owners, recordDelete.Name)
		}
		if len(owners) == 0 {
			invalid("a write of nothing")
			return
		}
		hosts := []string{}
		for _, owner := range owners {
			host, ok := DnsOwnerHost(root, owner)
			if !ok {
				invalid("a name outside the root")
				return
			}
			if !slices.Contains(hosts, host) {
				hosts = append(hosts, host)
			}
		}
		for _, host := range hosts {
			switch gate.MayAdmin(networkId, sidecarId, host, now) {
			case DnsGateAllowed:
			case DnsGateUnavailable:
				self.metrics.records.Add(1, dnsRecordsResultUnavailable)
				self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable, Message: "the network's grants are not loaded"})
				return
			default:
				self.metrics.records.Add(1, dnsRecordsResultRefused)
				self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusForbidden, Code: sidecar.DnsApiCodeRefused, Message: "no grant of admin on dns:" + host})
				return
			}
		}
	}
	answer, err := self.deps.Records.WriteRecords(request.Context(), call)
	var apiError *sidecar.DnsApiError
	switch {
	case err == nil:
		self.metrics.records.Add(1, dnsRecordsResultWritten)
		writer.Header().Set("Content-Type", "application/json")
		writer.Write(answer)
	case errors.As(err, &apiError):
		if apiError.Status == http.StatusServiceUnavailable {
			self.metrics.records.Add(1, dnsRecordsResultUnavailable)
		} else {
			self.metrics.records.Add(1, dnsRecordsResultRefused)
		}
		self.writeRecordsError(writer, apiError)
	default:
		self.metrics.records.Add(1, dnsRecordsResultFailed)
		self.log.Errorf("[dns]records write failed: %v", err)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
	}
}

func (self *DnsApi) serveZone(writer http.ResponseWriter, request *http.Request) {
	principal, ok := dnsRequestPrincipal(request)
	if !ok {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	if self.deps.Records == nil {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return
	}
	root, ok := self.recordsRoot()
	if !ok {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusBadRequest, Code: sidecar.DnsApiCodeInvalid, Message: "no one root"})
		return
	}
	networkId := sidecar.Id(principal.NetworkId)
	sidecarId := sidecar.Id(*principal.SidecarId)
	zone, err := self.deps.Records.Zone(request.Context(), root, networkId)
	if err != nil {
		var apiError *sidecar.DnsApiError
		if errors.As(err, &apiError) {
			self.writeRecordsError(writer, apiError)
			return
		}
		self.log.Errorf("[dns]zone read failed: %v", err)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return
	}
	zone.RecordSets = self.visibleRecordSets(root, networkId, sidecarId, zone.RecordSets)
	answer, err := json.Marshal(zone)
	if err != nil {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Write(answer)
}

// The RRsets on whose host the caller holds publish or admin, each host asked once. A gate with no state shows none.
func (self *DnsApi) visibleRecordSets(root string, networkId sidecar.Id, sidecarId sidecar.Id, recordSets []sidecar.DnsZoneRecordSet) []sidecar.DnsZoneRecordSet {
	gate := self.deps.RecordGate
	if gate == nil {
		gate = DnsUnloadedRecordGate{}
	}
	now := self.clock.Now()
	hostVerdicts := map[string]DnsGateVerdict{}
	visible := []sidecar.DnsZoneRecordSet{}
	for _, recordSet := range recordSets {
		host, ok := DnsOwnerHost(root, recordSet.Name)
		if !ok {
			continue
		}
		verdict, asked := hostVerdicts[host]
		if !asked {
			verdict = gate.MayView(networkId, sidecarId, host, now)
			hostVerdicts[host] = verdict
		}
		if verdict == DnsGateAllowed {
			visible = append(visible, recordSet)
		}
	}
	return visible
}
