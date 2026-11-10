// RECORD.md section 9's ocsf format, on every leg: OCSF 1.3.0, one event a line, for SIEMs. The version is pinned
// again at M6's entry.
//
//	membership           Account Change 3001 (category 3): user.uid the subject; member_added 1 Create,
//	                     member_removed 6 Delete, others 99
//	route, publish       Network Activity 4001 (4): action_id 1, dst_endpoint.uid the target or host; opened 1 Open,
//	                     or 7 Listen for publish; closed 2 Close
//	reach                Network Activity 4001 (4): action_id 1, dst_endpoint.uid the peer; 6 Traffic
//	every other kind     API Activity 6003 (6): api.operation recurd.<kind>, api.service.name the log; 1 Create; 3
//	                     Update for coverage, retention and a stage 2 context; 4 Delete for erasure; 2 Read for read
//	                     and disclosure
//
// Every event sets metadata.uid to the entry id, metadata.version, metadata.product, time, severity_id 1 (3 for an
// admission alarm, the recovery alarms and a coverage with gaps), cloud.provider, an empty osint and type_uid as
// class_uid × 100 + activity_id. actor.user.uid is the writer's member or sponsor, actor.session.uid the run, and
// src_endpoint.uid the writer's sidecar id. unmapped carries kind, source, tainted, action, leaf and the body's
// fields recordExportSafeFields keeps: numbers, booleans, ids, hashes and listed identifier strings, never prose,
// captured bytes, canonical_action, relays or cidrs. A host that parses as an IP address is left out of
// dst_endpoint, so no event carries an address the record holds (I-13); an identifier can still spell one.

package sidecar

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
)

// OCSF's values for the events an export writes.
const (
	recordOcsfVersion         = "1.3.0"
	recordOcsfProductName     = "recURd"
	recordOcsfVendorName      = "URnetwork"
	recordOcsfCloudProvider   = "urnetwork"
	recordOcsfClassAccount    = 3001
	recordOcsfClassNetwork    = 4001
	recordOcsfClassApi        = 6003
	recordOcsfCategoryIam     = 3
	recordOcsfCategoryNetwork = 4
	recordOcsfCategoryApp     = 6
	recordOcsfSeverityInfo    = 1
	recordOcsfSeverityMedium  = 3
	recordOcsfActivityOther   = 99
	recordOcsfActionAllowed   = 1
	recordOcsfOperationPrefix = "recurd."
	recordOcsfActivityCreate  = 1
	recordOcsfActivityRead    = 2
	recordOcsfActivityUpdate  = 3
	recordOcsfActivityDelete  = 4
	recordOcsfActivityOpen    = 1
	recordOcsfActivityClose   = 2
	recordOcsfActivityTraffic = 6
	recordOcsfActivityListen  = 7
	recordOcsfAccountCreate   = 1
	recordOcsfAccountDelete   = 6
)

// Body fields whose strings are identifiers: the only strings unmapped and the recurd.* attributes carry.
var recordExportIdentifierFields = []string{
	"harness", "harness_version", "version", "model", "provider", "agent_label", "request_id", "tool_name", "tool_use_id", "sources", "gaps",
}

// Body fields never carried whatever they hold: an action as stored, and addresses.
var recordExportWithheldFields = []string{"canonical_action", "relays", "cidrs", "recipients"}

// Whether text parses as an IP address or prefix.
func recordExportIsAddress(text string) bool {
	if _, err := netip.ParseAddr(text); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(text); err == nil {
		return true
	}
	host, _, found := strings.Cut(text, ":")
	if _, err := netip.ParseAddr(host); found && err == nil {
		return true
	}
	return false
}

// One value of fields as the safe set keeps it, false for one it drops: a number or a boolean; a hex string of an
// id's 16 bytes or a hash's 32; a string under a listed identifier field that is no address; an object or an array of
// such.
func recordExportSafeValue(name string, value any) (any, bool) {
	switch typed := value.(type) {
	case bool, int64, uint64, float64:
		return typed, true
	case string:
		if len(typed) == 2*recordIdByteCount || len(typed) == 2*recordHashByteCount {
			if _, err := hex.DecodeString(typed); err == nil && strings.ToLower(typed) == typed {
				return typed, true
			}
		}
		if slices.Contains(recordExportIdentifierFields, name) && !recordExportIsAddress(typed) {
			return typed, true
		}
	case map[string]any:
		if kept := recordExportSafeFields(typed); 0 < len(kept) {
			return kept, true
		}
	case []any:
		kept := []any{}
		for _, item := range typed {
			if safe, ok := recordExportSafeValue(name, item); ok {
				kept = append(kept, safe)
			}
		}
		if 0 < len(kept) {
			return kept, true
		}
	}
	return nil, false
}

// The part of a body's fields the ocsf and otel formats carry.
func recordExportSafeFields(fields map[string]any) map[string]any {
	kept := map[string]any{}
	for name, value := range fields {
		if slices.Contains(recordExportWithheldFields, name) {
			continue
		}
		if safe, ok := recordExportSafeValue(name, value); ok {
			kept[name] = safe
		}
	}
	return kept
}

// A field of fields as a number, 0 when it is absent or not one.
func recordExportNumber(fields map[string]any, name string) uint64 {
	switch typed := fields[name].(type) {
	case uint64:
		return typed
	case int64:
		return uint64(typed)
	}
	return 0
}

// A field of fields as a string, empty when it is absent or not one.
func recordExportString(fields map[string]any, name string) string {
	text, _ := fields[name].(string)
	return text
}

// One entry as an OCSF event. fields is the body by field name, nil when the body is not held.
func recordExportOcsf(auth RecordAuthView, entry *RecordReadEntry, fields map[string]any) map[string]any {
	header := entry.Header.Header
	kind := entry.Kind()
	writerId := recordIdOf(header.GetWriterSidecarId())
	classUid, categoryUid, activityId := recordOcsfClassApi, recordOcsfCategoryApp, recordOcsfActivityCreate
	severityId := recordOcsfSeverityInfo
	event := map[string]any{}
	switch kind {
	case RecordKindMembership:
		classUid, categoryUid = recordOcsfClassAccount, recordOcsfCategoryIam
		switch recordExportNumber(fields, "event") {
		case 1:
			activityId = recordOcsfAccountCreate
		case 2:
			activityId = recordOcsfAccountDelete
		case 3, 4, 5, 6:
			// an admission alarm and the recovery alarms
			activityId = recordOcsfActivityOther
			severityId = recordOcsfSeverityMedium
		default:
			activityId = recordOcsfActivityOther
		}
		if subject := recordExportString(fields, "member_id"); subject != "" {
			event["user"] = map[string]any{"uid": subject}
		}
	case RecordKindRoute, RecordKindPublish:
		classUid, categoryUid = recordOcsfClassNetwork, recordOcsfCategoryNetwork
		event["action_id"] = recordOcsfActionAllowed
		activityId = recordOcsfActivityOpen
		if kind == RecordKindPublish {
			activityId = recordOcsfActivityListen
		}
		if recordExportNumber(fields, "event") == 2 {
			activityId = recordOcsfActivityClose
		}
		target := recordExportString(fields, "target_sidecar_id")
		if kind == RecordKindPublish {
			target = recordExportString(fields, "host")
		}
		if target != "" && !recordExportIsAddress(target) {
			event["dst_endpoint"] = map[string]any{"uid": target}
		}
	case RecordKindReach:
		classUid, categoryUid, activityId = recordOcsfClassNetwork, recordOcsfCategoryNetwork, recordOcsfActivityTraffic
		event["action_id"] = recordOcsfActionAllowed
		if peers, ok := fields["peers"].([]any); ok && 0 < len(peers) {
			if peer, ok := peers[0].(string); ok {
				event["dst_endpoint"] = map[string]any{"uid": peer}
			}
		}
	default:
		switch {
		case kind == RecordKindCoverage, kind == RecordKindRetention, kind == RecordKindContext && recordExportNumber(fields, "stage") == 2:
			activityId = recordOcsfActivityUpdate
		case kind == RecordKindErasure:
			activityId = recordOcsfActivityDelete
		case kind == RecordKindRead, kind == RecordKindDisclosure:
			activityId = recordOcsfActivityRead
		}
		if gaps, ok := fields["gaps"].([]any); kind == RecordKindCoverage && ok && 0 < len(gaps) {
			severityId = recordOcsfSeverityMedium
		}
		operation := kind.String()
		if !kind.Known() {
			operation = "kind_" + strings.TrimPrefix(operation, "kind ")
		}
		event["api"] = map[string]any{
			"operation": recordOcsfOperationPrefix + operation,
			"service":   map[string]any{"name": RecordLogOrigin(recordIdOf(header.GetLogId()))},
		}
	}
	event["class_uid"] = classUid
	event["category_uid"] = categoryUid
	event["activity_id"] = activityId
	event["type_uid"] = classUid*100 + activityId
	event["severity_id"] = severityId
	event["time"] = header.GetTimeMillis()
	event["metadata"] = map[string]any{
		"uid":     recordExportHex(header.GetEntryId()),
		"version": recordOcsfVersion,
		"product": map[string]any{"name": recordOcsfProductName, "vendor_name": recordOcsfVendorName},
	}
	event["cloud"] = map[string]any{"provider": recordOcsfCloudProvider}
	event["osint"] = []any{}
	actor := map[string]any{}
	if memberId, ok := auth.Member(writerId); ok {
		actor["user"] = map[string]any{"uid": recordExportHex(memberId[:])}
	} else if sponsorId, ok := auth.Sponsor(writerId); ok {
		actor["user"] = map[string]any{"uid": recordExportHex(sponsorId[:])}
	}
	if len(header.GetRunId()) != 0 {
		actor["session"] = map[string]any{"uid": recordExportHex(header.GetRunId())}
	}
	event["actor"] = actor
	event["src_endpoint"] = map[string]any{"uid": recordExportHex(writerId[:])}
	unmapped := recordExportSafeFields(fields)
	kindName := ""
	if kind.Known() {
		kindName = kind.String()
	}
	unmapped["kind"] = kindName
	unmapped["kind_no"] = uint32(kind)
	unmapped["source"] = header.GetSource()
	unmapped["tainted"] = header.GetTainted()
	unmapped["action"] = recordExportHex(header.GetActionId())
	unmapped["leaf"] = recordExportHex(entry.Leaf[:])
	unmapped["state"] = string(entry.State)
	event["unmapped"] = unmapped
	return event
}
