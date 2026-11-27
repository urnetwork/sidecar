//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's catalog endpoints (DESIGN-COMPUTE §8.4; R-GW-1, IC-11; GW-M12-04), each for the token's own grant:
//
//	models    GET /v1/models: the catalog (§6.3) by canonical name in OpenAI's shape, only the names this device may use
//	          and the grant's model list admits, one per effort; a search endpoint is no model and is not listed.
//	          Anthropic's shape, when anthropic-version is set, comes with the Messages front (GW-M13-01)
//	catalog   GET /v1/ur/catalog: §6.3's entries whole, prices, context, label, efforts, why one is unavailable, with
//	          each one's canonical names, alias, disclosure id, the names the grant admits and its attestation: local
//	          for a model on this device, verified at each call for a TEE label (a call that cannot be verified is
//	          refused tee_unverified, §5), none for a direct one
//	balance   GET /v1/ur/balance: the grant's budget, its caps and what is left where the device knows it, and whether
//	          the network can pay, §9.9's state; never the network's balance, which only §9.10's roles see
//
// A token reads nothing else here (IC-11). Safe for concurrent use.

package sidecar

import (
	"context"
	"net/http"
)

// The routes and the answers' object names: format values.
const (
	GatewayRouteModels  = "GET /v1/models"
	GatewayRouteCatalog = "GET /v1/ur/catalog"
	GatewayRouteBalance = "GET /v1/ur/balance"

	gatewayModelsObjectList   = "list"
	gatewayModelsObjectModel  = "model"
	gatewayCatalogObject      = "ur.catalog"
	gatewayBalanceObject      = "ur.balance"
	gatewayAttestationLocal   = "local"
	gatewayAttestationPerCall = "verified_per_call"
	gatewayAttestationNone    = "none"
)

// Registers the three routes.
func init() {
	gatewayFrontRoutes = append(gatewayFrontRoutes,
		&gatewayFrontRoute{pattern: GatewayRouteModels, serve: (*GatewayFronts).serveModels},
		&gatewayFrontRoute{pattern: GatewayRouteCatalog, serve: (*GatewayFronts).serveCatalog},
		&gatewayFrontRoute{pattern: GatewayRouteBalance, serve: (*GatewayFronts).serveBalance},
	)
}

// What /v1/ur/balance reads of a network: its compute tools' answer for an agent (compute_tools.go). *Sidecar is one.
type GatewayBalanceNetwork interface {
	GatewayBalance(ctx context.Context, agentId Id, caps *HarnessBudget) (*ComputeBalanceToolAnswer, error)
}

// See GatewayBalanceNetwork: compute_balance's answer, the network's state and the agent's budget, never its balance.
func (self *Sidecar) GatewayBalance(ctx context.Context, agentId Id, caps *HarnessBudget) (*ComputeBalanceToolAnswer, error) {
	return NewComputeTools(self).BalanceAnswer(ctx, agentId, caps)
}

// The caller's network's catalog, or the 503 that answers its absence.
func (self *GatewayFronts) callerCatalog(ctx context.Context, caller *GatewayCaller) (*InferCatalog, *gatewayError) {
	network, ok := caller.Network.(GatewayFrontNetwork)
	if !ok {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network serves no model calls here")
	}
	router, err := network.InferRouter()
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network's router is not available now")
	}
	catalog, err := router.Catalog(ctx)
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the catalog does not read now")
	}
	return catalog, nil
}

// Writes value as a 200 JSON answer.
func gatewayWriteJson(writer http.ResponseWriter, value any) {
	encoded, err := gatewayMarshal(value)
	if err != nil {
		gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the answer did not encode").write(writer, SessionGatewayApiResponses)
		return
	}
	writer.Header().Set("Content-Type", gatewayContentTypeJson)
	writer.WriteHeader(http.StatusOK)
	writer.Write(encoded)
}

// GET /v1/models (see the file header's models row).
func (self *GatewayFronts) serveModels(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
	catalog, refusal := self.callerCatalog(request.Context(), caller)
	if refusal != nil {
		refusal.write(writer, SessionGatewayApiResponses)
		return
	}
	data := []any{}
	for _, entry := range catalog.Entries() {
		if entry.Kind == InferCatalogKindSearch || entry.Unavailable != "" {
			continue
		}
		for _, name := range entry.Names() {
			if !caller.Grant.AllowsModel(name) {
				continue
			}
			data = append(data, gatewayJsonObject{
				{Key: "id", Value: name},
				{Key: "object", Value: gatewayModelsObjectModel},
				{Key: "created", Value: 0},
				{Key: "owned_by", Value: entry.Provider},
			})
		}
	}
	gatewayWriteJson(writer, gatewayJsonObject{{Key: "object", Value: gatewayModelsObjectList}, {Key: "data", Value: data}})
}

// One entry of /v1/ur/catalog: §6.3's entry whole, and what the gateway adds.
type GatewayCatalogEntry struct {
	*InferCatalogEntry
	// Its canonical names, one per effort, and its alias, empty where it takes none.
	Names []string `json:"names"`
	Alias string   `json:"alias,omitempty"`
	// The disclosure whose summary line shows beside it (§2.8).
	DisclosureId string `json:"disclosure_id,omitempty"`
	// The names the grant's model list admits.
	Granted []string `json:"granted"`
	// local, verified_per_call or none (see the file header's catalog row).
	Attestation string `json:"attestation"`
}

// /v1/ur/catalog's answer.
type GatewayCatalogAnswer struct {
	Object            string                 `json:"object"`
	Entries           []*GatewayCatalogEntry `json:"entries"`
	LocalUnavailable  string                 `json:"local_unavailable,omitempty"`
	RemoteUnavailable string                 `json:"remote_unavailable,omitempty"`
}

// GET /v1/ur/catalog (see the file header's catalog row).
func (self *GatewayFronts) serveCatalog(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
	catalog, refusal := self.callerCatalog(request.Context(), caller)
	if refusal != nil {
		refusal.write(writer, SessionGatewayApiResponses)
		return
	}
	answer := &GatewayCatalogAnswer{
		Object:            gatewayCatalogObject,
		Entries:           []*GatewayCatalogEntry{},
		LocalUnavailable:  catalog.LocalUnavailable(),
		RemoteUnavailable: catalog.RemoteUnavailable(),
	}
	for _, entry := range catalog.Entries() {
		item := &GatewayCatalogEntry{InferCatalogEntry: entry, Names: entry.Names(), Alias: entry.Alias(), DisclosureId: entry.DisclosureId(), Granted: []string{}}
		for _, name := range item.Names {
			if caller.Grant.AllowsModel(name) {
				item.Granted = append(item.Granted, name)
			}
		}
		switch {
		case entry.Kind == InferCatalogKindLocal:
			item.Attestation = gatewayAttestationLocal
		case entry.Label.Tee():
			item.Attestation = gatewayAttestationPerCall
		default:
			item.Attestation = gatewayAttestationNone
		}
		answer.Entries = append(answer.Entries, item)
	}
	gatewayWriteJson(writer, answer)
}

// /v1/ur/balance's answer: the grant's budget and the network's state, never its balance.
type GatewayBalanceAnswer struct {
	Object     string `json:"object"`
	GrantId    Id     `json:"grant_id"`
	Harness    string `json:"harness"`
	AgentLabel string `json:"agent_label"`
	// §9.9's state, and whether the network can pay for a remote call now.
	State  ComputeAccountState `json:"state"`
	CanPay bool                `json:"can_pay"`
	// The grant's caps, the agent's where the grant names none, and what is left where the device knows it.
	Budget    *ComputeBudgetLeft `json:"budget"`
	LeftKnown bool               `json:"left_known"`
	// Raises above the agent's default waiting on a person's approval (§16.3).
	PendingRaises []*GatewayGrantRaise `json:"pending_raises,omitempty"`
}

// GET /v1/ur/balance (see the file header's balance row).
func (self *GatewayFronts) serveBalance(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
	network, ok := caller.Network.(GatewayBalanceNetwork)
	if !ok {
		gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network's compute balance is not served here").write(writer, SessionGatewayApiResponses)
		return
	}
	grant := caller.Grant
	caps := &HarnessBudget{Id: grant.GrantId}
	if grant.DayNanoUsd != nil && 0 < *grant.DayNanoUsd {
		caps.DayNanoUsd = uint64(*grant.DayNanoUsd)
	}
	if grant.MonthNanoUsd != nil && 0 < *grant.MonthNanoUsd {
		caps.MonthNanoUsd = uint64(*grant.MonthNanoUsd)
	}
	balance, err := network.GatewayBalance(request.Context(), grant.AgentId, caps)
	if err != nil {
		gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network's compute state does not read now").write(writer, SessionGatewayApiResponses)
		return
	}
	gatewayWriteJson(writer, &GatewayBalanceAnswer{
		Object:        gatewayBalanceObject,
		GrantId:       grant.GrantId,
		Harness:       grant.Harness,
		AgentLabel:    grant.AgentLabel,
		State:         balance.State,
		CanPay:        balance.CanPay,
		Budget:        balance.Budget,
		LeftKnown:     balance.LeftKnown,
		PendingRaises: grant.PendingRaises,
	})
}
