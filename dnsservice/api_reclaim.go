// POST /dns/label-reclaim on the dns block (DNS-M5-16; plan-DNS-sidecar-zone-read, §12.8, §19.10's labels step): a
// sidecar's reclaim of its network's label or alias after a Postgres restore, the same tuple and signature as api's
// POST /network/dns/label-reclaim, with the service token's network equal to the tuple's network_id. The model holds
// every other check (DnsReclaimStore): an ownerless retiring name, a leaf the replay recorded under the incident, and
// the signature by that leaf's key. A block with no store answers 503.

package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/urnetwork/sidecar"
)

// One reclaim as the block hands it to the model.
type DnsReclaimCall struct {
	Root      string
	NetworkId sidecar.Id
	SidecarId sidecar.Id
	Request   *sidecar.DnsLabelReclaimRequest
}

// The model's half of the reclaim route. Safe for concurrent use.
type DnsReclaimStore interface {
	// Re-binds the name, or answers a *sidecar.DnsApiError; any other error is a failure, answered 503.
	ReclaimLabel(ctx context.Context, call *DnsReclaimCall) (*sidecar.DnsLabelReclaimAnswer, error)
}

// The reclaim route.
func (self *DnsApi) reclaimRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: sidecar.DnsLabelReclaimPath, serviceToken: true, write: true, serve: self.serveReclaim},
	}
}

func (self *DnsApi) serveReclaim(writer http.ResponseWriter, request *http.Request) {
	principal, ok := dnsRequestPrincipal(request)
	if !ok {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	if self.deps.Reclaims == nil {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
		return
	}
	invalid := func(message string) {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusBadRequest, Code: sidecar.DnsApiCodeInvalid, Message: message})
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
	reclaim := &sidecar.DnsLabelReclaimRequest{}
	if err := json.Unmarshal(body, reclaim); err != nil {
		invalid("a body that does not parse")
		return
	}
	networkId := sidecar.Id(principal.NetworkId)
	if reclaim.NetworkId != networkId {
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusForbidden, Code: sidecar.DnsApiCodeRefused, Message: "the tuple names another network"})
		return
	}
	answer, err := self.deps.Reclaims.ReclaimLabel(request.Context(), &DnsReclaimCall{
		Root:      root,
		NetworkId: networkId,
		SidecarId: sidecar.Id(*principal.SidecarId),
		Request:   reclaim,
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
		self.log.Errorf("[dns]label reclaim failed: %v", err)
		self.writeRecordsError(writer, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable})
	}
}
