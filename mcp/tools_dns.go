//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's dns tools (MCP-M5-01; §12.8, R-MCP-9, D-MCP-11, D-MCP-12, D-MCP-17, AD4, I-7, I-8, I-9;
// plan-DNS-sidecar-zone-read): dns_records at R, and dns_set and dns_delete at O, each over the network's DnsClient
// (dns_client.go), which calls the dns block with this sidecar's service token.
//
//   - dns_records() is the zone as GET /dns/zone answers this sidecar: its apex, alias and version, and the RRsets
//     of the owners it holds publish or admin on. Members wrote the records, so the result is a member's data.
//   - dns_set(name, type, value) replaces one RRset with one value, and dns_delete(name, type) removes one RRset.
//
// Both writes are outward (§5.4). The daemon builds each one's CanonicalAction with NewCanonicalAction from the
// arguments alone: dns_name in its canonical form, dns_type, and for a set dns_value, the one RDATA an approver
// renders (D-MCP-17, plan reading 12: one RRset, one value). The kind takes no preview, no recipient and no path, so
// nothing an agent words reaches the action, and the gate at the dns block sees the action's fields and nothing of
// the run: its run id and agent id ride the request this daemon files, never the bytes a server takes (AD4).
// DnsClient.RecordEffect is the SidecarEffect, which Sidecar.Authorize runs once the use is reserved, or at once
// under a standing grant, and DnsClient.Lookup is the kind's Lookup (RegisterDnsEffectLookups), so a call again
// re-presents the same use under its effect key and the server answers it from the use's row: a write lands once.
//
// With no decision yet a write answers approval_pending and its approval's id, and the same call again, once a
// person has decided, spends the decision. The dns block consumes the use (§8.10's server gate), so the daemon
// reserves it only until the decision's not_after less the decision skew (record_gate_spend.go).
//
// Errors are constants: a refusal names its class, never the name, the type or the value (I-13).

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the dns tools reach the zone through: *sidecar.Sidecar's Dns, the network's DnsClient.
type mcpDnsClients interface {
	Dns() (*sidecar.DnsClient, error)
}

// The record types §12.8's routes take, as their mnemonics.
var mcpDnsRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV"}

// The tools' statuses.
const (
	mcpDnsStatusWritten         = "written"
	mcpDnsStatusApprovalPending = "approval_pending"
)

// The tools' refusals, each constant.
var (
	errMcpDnsUnavailable = NewMcpError(McpCodeUnavailable,
		"this network's zone cannot be reached now: try again later", true)
	errMcpDnsArguments = NewMcpError(McpCodeInvalidArguments,
		"dns_set takes a name, a type and one value; dns_delete takes a name and a type; type is A, AAAA, CNAME, TXT, MX or SRV, and the name is at or below the zone's apex", false)
	errMcpDnsHeld = NewMcpError(McpCodeRefused,
		"no approval of this could be spent: it was denied, cancelled, spent or expired, or no rule lets this sidecar ask", false)
	errMcpDnsRefused = NewMcpError(McpCodeRefused,
		"the zone refused this write and nothing was written: no grant or decision covers it, the zone is suspended, or a limit was reached", false)
	errMcpDnsInvalid = NewMcpError(McpCodeInvalidArguments,
		"the zone does not take this record and nothing was written", false)
	errMcpDnsConflict = NewMcpError(McpCodeFailedPrecondition,
		"the zone changed under this write and nothing was written: read dns_records and ask again", false)
	errMcpDnsUncertain = NewMcpError(McpCodeFailed,
		"the write may have landed: call again with the same arguments, which writes nothing twice", true)
)

// dns_records takes nothing but the network.
type mcpDnsRecordsIn struct{}

// One RRset.
type mcpDnsRecordOut struct {
	// The owner, canonical with its final dot.
	Name string `json:"name"`
	Type string `json:"type"`
	Ttl  uint32 `json:"ttl"`
	// user, system, edge, router, copy, challenge, canary, key or withheld.
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
}

// dns_records' data.
type mcpDnsRecordsOut struct {
	// <label>.<root>; empty while the network has no label.
	Apex  string `json:"apex"`
	Alias string `json:"alias,omitempty"`
	// The serial of the zone's last write.
	Version uint64             `json:"version"`
	Records []*mcpDnsRecordOut `json:"records"`
}

// dns_set's arguments.
type mcpDnsSetIn struct {
	// The owner, at or below the zone's apex.
	Name string `json:"name"`
	// A, AAAA, CNAME, TXT, MX or SRV.
	Type string `json:"type"`
	// One record's RDATA in presentation form.
	Value string `json:"value"`
}

// dns_delete's arguments.
type mcpDnsDeleteIn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// What a write answers.
type mcpDnsWriteOut struct {
	// written, or approval_pending with approval_id, the same call again spending the decision once a person has
	// made it.
	Status     string `json:"status"`
	ApprovalId string `json:"approval_id,omitempty"`
	// The zone's version after the write.
	Version uint64 `json:"version,omitempty"`
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addDnsTools(catalog)
	})
}

// The call's network's DnsClient, an error where it has none.
func mcpDnsClientOf(call *McpCall) (*sidecar.DnsClient, error) {
	clients, ok := call.Network.(mcpDnsClients)
	if !ok {
		return nil, errMcpDnsUnavailable
	}
	client, err := clients.Dns()
	if err != nil || client == nil {
		return nil, errMcpDnsUnavailable
	}
	return client, nil
}

// name and recordType as the routes take them: the owner canonical, the type its mnemonic.
func mcpDnsOwner(name string, recordType string) (string, string, error) {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t\r\n\\") {
		return "", "", errMcpDnsArguments
	}
	recordType = strings.ToUpper(recordType)
	for _, known := range mcpDnsRecordTypes {
		if recordType == known {
			return sidecar.CanonicalDnsRecordName(name), recordType, nil
		}
	}
	return "", "", errMcpDnsArguments
}

// A dns_set or dns_delete action of the call's run, built from the arguments alone, with no effect yet. The run
// binding rides the SidecarAction, never the CanonicalAction a gate sees (AD4).
func mcpDnsAction(call *McpCall, kind sidecar.SidecarActionKind, name string, recordType string, value string) (*sidecar.SidecarAction, error) {
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind:     uint32(kind),
		DnsName:  name,
		DnsType:  recordType,
		DnsValue: value,
	})
	if err != nil {
		return nil, err
	}
	// what a gate may see is the kind's server column, which the builder's row holds this action to
	if err := sidecar.CheckCanonicalActionForServer(stored); err != nil {
		return nil, err
	}
	runId := call.RunId
	return sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, nil)
}

// One write through §5.4's gate: its action, the client's effect, and the outcome as the tool answers it.
func mcpDnsWrite(ctx context.Context, call *McpCall, kind sidecar.SidecarActionKind, name string, recordType string, value string) (*mcpDnsWriteOut, error) {
	owner, recordType, err := mcpDnsOwner(name, recordType)
	if err != nil {
		return nil, err
	}
	authorizer, ok := call.Network.(mcpAuthorizer)
	if !ok {
		return nil, errMcpDnsHeld
	}
	client, err := mcpDnsClientOf(call)
	if err != nil {
		return nil, err
	}
	action, err := mcpDnsAction(call, kind, owner, recordType, value)
	if err != nil {
		return nil, errMcpDnsArguments
	}
	action.Effect = client.RecordEffect(action.Canonical, nil)
	if err := authorizer.Authorize(ctx, action, nil); err != nil {
		var pending *sidecar.ApprovalPendingError
		if errors.As(err, &pending) {
			return &mcpDnsWriteOut{Status: mcpDnsStatusApprovalPending, ApprovalId: pending.ApprovalId.String()}, nil
		}
		if errors.Is(err, sidecar.ErrApprovalNoState) {
			return nil, errMcpDnsUnavailable
		}
		return nil, errMcpDnsHeld
	}
	outcome := action.Outcome
	switch {
	case outcome == nil:
		return nil, errMcpDnsUncertain
	case outcome.State == sidecar.ApprovalOutcomeDone:
		answer := &sidecar.DnsRecordsAnswer{}
		if err := json.Unmarshal(outcome.EffectRef, answer); err != nil {
			return &mcpDnsWriteOut{Status: mcpDnsStatusWritten}, nil
		}
		return &mcpDnsWriteOut{Status: mcpDnsStatusWritten, Version: answer.Version}, nil
	case outcome.State == sidecar.ApprovalOutcomeNotDone:
		return nil, mcpDnsRefusal(outcome.Err)
	}
	return nil, errMcpDnsUncertain
}

// A write that wrote nothing, by the class the zone named; a recorded refusal a retry found names none.
func mcpDnsRefusal(err error) error {
	var apiError *sidecar.DnsApiError
	if !errors.As(err, &apiError) {
		return errMcpDnsRefused
	}
	switch apiError.Code {
	case sidecar.DnsApiCodeInvalid:
		return errMcpDnsInvalid
	case sidecar.DnsApiCodeVersionConflict:
		return errMcpDnsConflict
	}
	return errMcpDnsRefused
}

// Registers the three dns tools on catalog.
func addDnsTools(catalog *McpCatalog) {
	AddTool(catalog, &McpToolSpec[mcpDnsRecordsIn]{
		Name:        "dns_records",
		Tier:        McpTierRead,
		Description: "Lists the network's zone as this sidecar may see it: its apex, alias and version, and the record sets of the names it may publish on.",
		Access:      func(call *McpCall, in *mcpDnsRecordsIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDnsRecordsIn, result *McpResult) (*mcpDnsRecordsOut, error) {
		client, err := mcpDnsClientOf(call)
		if err != nil {
			return nil, err
		}
		zone, err := client.Zone(ctx)
		if err != nil || zone == nil {
			return nil, errMcpDnsUnavailable
		}
		result.Member()
		result.SetSource("dns:zone")
		out := &mcpDnsRecordsOut{Apex: zone.Apex(), Alias: zone.Alias, Version: zone.Version, Records: []*mcpDnsRecordOut{}}
		for _, recordSet := range zone.RecordSets {
			out.Records = append(out.Records, &mcpDnsRecordOut{
				Name: recordSet.Name, Type: recordSet.Type, Ttl: recordSet.Ttl, Kind: recordSet.Kind,
				Values: append([]string{}, recordSet.Values...),
			})
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpDnsSetIn]{
		Name:        "dns_set",
		Tier:        McpTierOutward,
		Description: "Replaces one record set of the network's zone with one value; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpDnsSetIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDnsSetIn, result *McpResult) (*mcpDnsWriteOut, error) {
		if in.Value == "" {
			return nil, errMcpDnsArguments
		}
		result.SetSource("dns:records")
		return mcpDnsWrite(ctx, call, sidecar.SidecarActionDnsSet, in.Name, in.Type, in.Value)
	})

	AddTool(catalog, &McpToolSpec[mcpDnsDeleteIn]{
		Name:        "dns_delete",
		Tier:        McpTierOutward,
		Description: "Removes one record set of the network's zone; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpDnsDeleteIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpDnsDeleteIn, result *McpResult) (*mcpDnsWriteOut, error) {
		result.SetSource("dns:records")
		return mcpDnsWrite(ctx, call, sidecar.SidecarActionDnsDelete, in.Name, in.Type, "")
	})
}
