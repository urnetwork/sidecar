// RECORD.md section 9's otel format, on every leg: OTLP JSON log records, one ResourceLogs object a line, under the
// GenAI semantic conventions, which were still in development when this was written and are pinned again at M6's
// entry.
//
// Every record carries recurd.* attributes: the entry, log, kind, writer, seq, source, tainted, action, leaf and
// state, and the body's fields recordExportSafeFields keeps, flattened by dots, the same set ocsf's unmapped carries,
// so neither format carries an IP address the record holds (I-13). The run is gen_ai.conversation.id, the agent
// gen_ai.agent.id and its label gen_ai.agent.name. context and model_call map model to gen_ai.request.model,
// input_tokens and output_tokens to gen_ai.usage.input_tokens and gen_ai.usage.output_tokens and provider to
// gen_ai.provider.name; tool_call adds gen_ai.tool.name and gen_ai.tool.call.id. Other kinds go out as plain log
// records.

package sidecar

import (
	"slices"
	"strconv"
)

// OTLP's and the conventions' values for the records an export writes.
const (
	recordOtelServiceName   = "recurd"
	recordOtelScopeName     = "urnetwork.recurd"
	recordOtelScopeVersion  = "1"
	recordOtelSeverityInfo  = 9
	recordOtelSeverityText  = "INFO"
	recordOtelEventPrefix   = "recurd."
	recordOtelAttributeStem = "recurd."
	recordOtelNanosPerMilli = 1000 * 1000
)

// One attribute, its value in OTLP JSON's AnyValue: 64-bit integers as strings.
func recordOtelAttribute(key string, value any) map[string]any {
	return map[string]any{"key": key, "value": recordOtelValue(value)}
}

// An AnyValue.
func recordOtelValue(value any) map[string]any {
	switch typed := value.(type) {
	case bool:
		return map[string]any{"boolValue": typed}
	case int64:
		return map[string]any{"intValue": strconv.FormatInt(typed, 10)}
	case uint64:
		return map[string]any{"intValue": strconv.FormatUint(typed, 10)}
	case uint32:
		return map[string]any{"intValue": strconv.FormatUint(uint64(typed), 10)}
	case float64:
		return map[string]any{"doubleValue": typed}
	case []any:
		values := []any{}
		for _, item := range typed {
			values = append(values, recordOtelValue(item))
		}
		return map[string]any{"arrayValue": map[string]any{"values": values}}
	case string:
		return map[string]any{"stringValue": typed}
	}
	return map[string]any{"stringValue": ""}
}

// The safe fields as attributes under stem, objects flattened by dots and arrays of objects by index.
func recordOtelFlatten(stem string, fields map[string]any, attributes map[string]any) {
	for name, value := range fields {
		switch typed := value.(type) {
		case map[string]any:
			recordOtelFlatten(stem+name+".", typed, attributes)
		case []any:
			scalars := true
			for i, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					scalars = false
					recordOtelFlatten(stem+name+"."+strconv.Itoa(i)+".", nested, attributes)
				}
			}
			if scalars {
				attributes[stem+name] = typed
			}
		default:
			attributes[stem+name] = value
		}
	}
}

// One entry as an OTLP ResourceLogs object holding one log record. fields is the body by field name, nil when the
// body is not held; agentLabel the run's, empty for none.
func recordExportOtel(entry *RecordReadEntry, fields map[string]any, agentLabel string) map[string]any {
	header := entry.Header.Header
	kind := entry.Kind()
	kindName := ""
	if kind.Known() {
		kindName = kind.String()
	}
	attributes := map[string]any{
		"recurd.entry":   recordExportHex(header.GetEntryId()),
		"recurd.log":     recordExportHex(header.GetLogId()),
		"recurd.kind":    kindName,
		"recurd.kind_no": uint32(kind),
		"recurd.writer":  recordExportHex(header.GetWriterSidecarId()),
		"recurd.seq":     header.GetSeq(),
		"recurd.source":  header.GetSource(),
		"recurd.tainted": header.GetTainted(),
		"recurd.action":  recordExportHex(header.GetActionId()),
		"recurd.leaf":    recordExportHex(entry.Leaf[:]),
		"recurd.state":   string(entry.State),
	}
	safe := recordExportSafeFields(fields)
	recordOtelFlatten(recordOtelAttributeStem+"body.", safe, attributes)
	if len(header.GetRunId()) != 0 {
		attributes["gen_ai.conversation.id"] = recordExportHex(header.GetRunId())
	}
	if len(header.GetAgentId()) != 0 {
		attributes["gen_ai.agent.id"] = recordExportHex(header.GetAgentId())
	}
	if agentLabel != "" && !recordExportIsAddress(agentLabel) {
		attributes["gen_ai.agent.name"] = agentLabel
	}
	take := func(attribute string, field string) {
		if value, ok := safe[field]; ok {
			attributes[attribute] = value
		}
	}
	switch kind {
	case RecordKindContext, RecordKindModelCall:
		take("gen_ai.request.model", "model")
		take("gen_ai.usage.input_tokens", "input_tokens")
		take("gen_ai.usage.output_tokens", "output_tokens")
		take("gen_ai.provider.name", "provider")
	case RecordKindToolCall:
		take("gen_ai.tool.name", "tool_name")
		take("gen_ai.tool.call.id", "tool_use_id")
	}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	list := []any{}
	for _, key := range keys {
		list = append(list, recordOtelAttribute(key, attributes[key]))
	}
	nanos := strconv.FormatInt(header.GetTimeMillis()*recordOtelNanosPerMilli, 10)
	eventName := kindName
	if eventName == "" {
		eventName = "kind_" + strconv.FormatUint(uint64(kind), 10)
	}
	logRecord := map[string]any{
		"timeUnixNano":   nanos,
		"severityNumber": recordOtelSeverityInfo,
		"severityText":   recordOtelSeverityText,
		"eventName":      recordOtelEventPrefix + eventName,
		"body":           map[string]any{"stringValue": eventName},
		"attributes":     list,
	}
	return map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{recordOtelAttribute("service.name", recordOtelServiceName)}},
			"scopeLogs": []any{map[string]any{
				"scope":      map[string]any{"name": recordOtelScopeName, "version": recordOtelScopeVersion},
				"logRecords": []any{logRecord},
			}},
		}},
	}
}
