// POST /dns/key-record on the dns block (§12.8, DNS-M7-02; D-MAIL-4, I-5, I-15): a receiver's TLSA 3 1 1 at
// _25._tcp.mx, the only TLSA writer. It takes a service token of aud dns from a sidecar, §8.10's gate first: listen on
// sock:smtp/25/mx for the network's own mx, or smtp/25/mx.<scope> for a scope's, a member scope's only from its
// member's consented devices (AclGateView.MayReceive; owner decision 126), through DnsKeyRecordGate. Then the model
// (DnsKeyRecordStore) checks the key is the caller's by its identity key's attestation, writes the key's row, retires
// the caller's own published keys of the host the body's retire_spki_sha256 names, and rebuilds the host's TLSA, in
// one write, and notifies the owners by an admin event and a hint (§15.5; owner decision 443). The block hands the
// body on as it parsed it: the model alone judges the list, so a hash naming another receiver's key retires nothing.
//
// A scope's host is judged in its scope (MAIL-M8-09): the gate resolves mx.<scope> through its DnsKeyRecordScopeOf to
// the scope and, for a member scope, its member, and asks MayReceive there, so a member scope's key is taken only from
// that member's consented devices. A gate with no resolver, or one that cannot name the scope, answers 503, the closed
// direction: no state carries §7.9's TeamScopeRow yet, so no block has a resolver. A block with no store or gate
// answers 503.

package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// §8.10's receiver gate for the key route. From memory with no I/O. Safe for concurrent use.
type DnsKeyRecordGate interface {
	// listen on smtp/25/mx, or smtp/25/mx.<scope> for scope, for the sidecar.
	MayReceive(networkId sidecar.Id, sidecarId sidecar.Id, scope string, now time.Time) DnsGateVerdict
}

// The Team scope a key route's mx.<scope> names in a network's verified state: its label, with its member for a member
// scope (§7.9's TeamScopeRow). False where the state lists no such scope or cannot be read. From memory with no I/O.
type DnsKeyRecordScopeOf func(networkId sidecar.Id, scope string) (sidecar.AclScope, bool)

// What the gate asks of §8.10, which *sidecar.AclGateView answers.
type dnsKeyRecordReceiveView interface {
	MayReceive(networkId sidecar.Id, receiver sidecar.AclSubject, scope sidecar.AclScope, now time.Time) sidecar.AclDecision
}

// The receiver gate over the dns service's AclGateView.
type dnsAclKeyRecordGate struct {
	// nil answers unavailable
	view dnsKeyRecordReceiveView
	// nil answers every scope's host unavailable
	scopeOf DnsKeyRecordScopeOf
}

// The key route's gate over view, taking no scope's host. nil answers unavailable to everything.
func NewDnsAclKeyRecordGate(view *sidecar.AclGateView) DnsKeyRecordGate {
	return NewDnsAclScopedKeyRecordGate(view, nil)
}

// The key route's gate over view, judging a Team scope's host in the scope scopeOf names (see the file header). nil
// view answers unavailable to everything, and nil scopeOf every scope's host.
func NewDnsAclScopedKeyRecordGate(view *sidecar.AclGateView, scopeOf DnsKeyRecordScopeOf) DnsKeyRecordGate {
	gate := &dnsAclKeyRecordGate{scopeOf: scopeOf}
	if view != nil {
		gate.view = view
	}
	return gate
}

func (self *dnsAclKeyRecordGate) MayReceive(networkId sidecar.Id, sidecarId sidecar.Id, scope string, now time.Time) DnsGateVerdict {
	if self.view == nil {
		return DnsGateUnavailable
	}
	aclScope := sidecar.AclScope{}
	if scope != "" {
		if self.scopeOf == nil {
			// a scope's member is not known to the gate, so a scope's receiver is not judged: the closed direction
			return DnsGateUnavailable
		}
		resolved, ok := self.scopeOf(networkId, scope)
		if !ok || resolved.Label != scope {
			return DnsGateUnavailable
		}
		aclScope = resolved
	}
	return dnsGateVerdictOf(self.view.MayReceive(networkId, sidecar.AclSidecarSubject(sidecarId), aclScope, now))
}

// One key write as the block hands it to the model.
type DnsKeyRecordCall struct {
	Root      string
	NetworkId sidecar.Id
	SidecarId sidecar.Id
	Request   *sidecar.DnsKeyRecordRequest
}

// The model's half of the key route. Safe for concurrent use.
type DnsKeyRecordStore interface {
	// Publishes the key's TLSA, or answers a *sidecar.DnsApiError; any other error is a failure, answered 503.
	PublishKeyRecord(ctx context.Context, call *DnsKeyRecordCall) (*sidecar.DnsKeyRecordAnswer, error)
}

// The key route.
func (self *DnsApi) keyRecordRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: sidecar.DnsKeyRecordPath, serviceToken: true, write: true, serve: self.serveKeyRecord},
	}
}

func (self *DnsApi) serveKeyRecord(writer http.ResponseWriter, request *http.Request) {
	principal, ok := dnsRequestPrincipal(request)
	if !ok {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	unavailable := func(message string) {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable, Message: message})
	}
	invalid := func(message string) {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusBadRequest, Code: sidecar.DnsApiCodeInvalid, Message: message})
	}
	if self.deps.KeyRecords == nil {
		unavailable("")
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
	keyRecord := &sidecar.DnsKeyRecordRequest{}
	if err := json.Unmarshal(body, keyRecord); err != nil {
		invalid("a body that does not parse")
		return
	}
	scope := ""
	if keyRecord.Host != "mx" {
		var found bool
		if scope, found = strings.CutPrefix(keyRecord.Host, "mx."); !found || scope == "" || strings.Contains(scope, ".") {
			invalid("a host that is not mx or mx.<scope>")
			return
		}
	}
	networkId := sidecar.Id(principal.NetworkId)
	sidecarId := sidecar.Id(*principal.SidecarId)
	gate := self.deps.KeyRecordGate
	if gate == nil {
		unavailable("the network's grants are not loaded")
		return
	}
	switch gate.MayReceive(networkId, sidecarId, scope, self.clock.Now()) {
	case DnsGateAllowed:
	case DnsGateUnavailable:
		unavailable("the network's grants are not loaded")
		return
	default:
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusForbidden, Code: sidecar.DnsApiCodeRefused, Message: "no grant of listen on smtp/25/" + keyRecord.Host})
		return
	}
	answer, err := self.deps.KeyRecords.PublishKeyRecord(request.Context(), &DnsKeyRecordCall{
		Root:      root,
		NetworkId: networkId,
		SidecarId: sidecarId,
		Request:   keyRecord,
	})
	var apiError *sidecar.DnsApiError
	switch {
	case err == nil:
		data, _ := json.Marshal(answer)
		writer.Header().Set("Content-Type", "application/json")
		writer.Write(data)
	case errors.As(err, &apiError):
		self.writeRecordsError(writer, apiError)
	default:
		self.log.Errorf("[dns]key record failed: %v", err)
		unavailable("")
	}
}
