// websearch.proto held to numbers written here (SRCH-M13-01): design_fence_test.go holds §21.5's four messages to
// DESIGN-COMPUTE.md's fence and the rest to testUnfencedFence, each of which moves with the design until the format
// freezes, so this keeps the fields as written, and a change to both at once still fails.

package protocol

import (
	"slices"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const testWebSearchProtoPath = "protocol/websearch.proto"

// Each message's fields in declaration order: §21.5's four as its fence prints them, then the plan's, numbered in the
// order written.
var testWebSearchFields = map[protoreflect.Name][]string{
	"ComputeSearchAuthorizeRequest": {
		"1 catalog_version uint64", "2 request_id bytes", "3 agent_id bytes", "4 attempt uint32", "5 sealed_payee bytes",
		"6 amount uint64", "7 asset bytes", "8 network string", "9 outcomes SearchOutcomes",
	},
	"SearchPayee":    {"1 pay_to bytes", "2 nonce bytes"},
	"SearchOutcomes": {"1 ok uint32", "2 provider_error uint32", "3 timeout uint32", "4 refused uint32"},
	"ComputeSearchAuthorization": {
		"1 from bytes", "2 to bytes", "3 value uint64", "4 valid_after_s int64", "5 valid_before_s int64", "6 nonce bytes",
		"7 signature bytes",
	},
	"ComputeSearchAuthorizeResponse": {"1 sealed_authorization bytes"},
	"ComputeSearchOutcomesRequest":   {"1 outcomes SearchOutcomes"},
	"SearchSignRequest":              {"1 ticket bytes", "2 amount uint64", "3 minute_s int64", "4 sealed_payee bytes"},
	"SearchSignResponse":             {"1 sealed_authorization bytes", "2 refusal SearchSignRefusal", "3 payee bytes"},
	"SearchSignerReport": {
		"1 ticket bytes", "2 kind SearchSignerReportKind", "3 minute_s int64", "4 payee bytes", "5 transaction bytes",
	},
	"SearchSignerReports":    {"1 reports repeated SearchSignerReport"},
	"SearchSignerAnswer":     {"1 ticket bytes", "2 answer SearchReportAnswer"},
	"SearchSignerAnswers":    {"1 answers repeated SearchSignerAnswer"},
	"SearchSignerDayRequest": {"1 day_s int64"},
	"SearchSignerDay": {
		"1 day_s int64", "2 issued_count uint64", "3 issued_value uint64", "4 settled_count uint64", "5 settled_value uint64",
		"6 attributed_count uint64", "7 attributed_value uint64", "8 unattributed_count uint64",
		"9 unattributed_value uint64",
	},
	"WebSearchCatalogSection": {"1 entries repeated WebSearchCatalogEntry"},
	"WebSearchCatalogEntry":   {"1 engine string", "2 mode string", "3 nano_usd_per_search int64"},
}

// Each enum's values in declaration order.
var testWebSearchValues = map[protoreflect.Name][]string{
	"SearchSignRefusal": {
		"0 SEARCH_SIGN_REFUSAL_UNSPECIFIED", "1 SEARCH_SIGN_REFUSAL_PAYEE_REFUSED", "2 SEARCH_SIGN_REFUSAL_NONCE_REUSED",
		"3 SEARCH_SIGN_REFUSAL_RATE_LIMITED", "4 SEARCH_SIGN_REFUSAL_UNSETTLED_CAP", "5 SEARCH_SIGN_REFUSAL_DAY_CAP",
		"6 SEARCH_SIGN_REFUSAL_CEILING", "7 SEARCH_SIGN_REFUSAL_LISTS_STALE", "8 SEARCH_SIGN_REFUSAL_STOPPED",
		"9 SEARCH_SIGN_REFUSAL_SEAL_INVALID",
	},
	"SearchSignerReportKind": {
		"0 SEARCH_SIGNER_REPORT_KIND_UNSPECIFIED", "1 SEARCH_SIGNER_REPORT_KIND_SETTLED", "2 SEARCH_SIGNER_REPORT_KIND_LAPSED",
		"3 SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND",
	},
	"SearchReportAnswer": {
		"0 SEARCH_REPORT_ANSWER_UNSPECIFIED", "1 SEARCH_REPORT_ANSWER_CHARGED", "2 SEARCH_REPORT_ANSWER_RELEASED",
		"3 SEARCH_REPORT_ANSWER_UNKNOWN",
	},
}

// A field as its line reads: number, name, and its type, a message's or an enum's by name.
func testWebSearchFieldLine(field protoreflect.FieldDescriptor) string {
	if field.Enum() != nil {
		line := testFieldLine(field)
		return line[:len(line)-len(field.Kind().String())] + string(field.Enum().Name())
	}
	return testFieldLine(field)
}

// §21.5's names, numbers and types, and the plan's, each at its number, in its order, with no oneof, nothing nested and
// nothing else in the file.
func TestWebSearchProtoAsDesigned(t *testing.T) {
	file := testFile(t, testWebSearchProtoPath)
	if file.Package() != testProtoPackage {
		t.Errorf("%s is package %s", testWebSearchProtoPath, file.Package())
	}
	messages := file.Messages()
	if messages.Len() != len(testWebSearchFields) {
		t.Errorf("%s declares %d messages, and %d are listed", testWebSearchProtoPath, messages.Len(), len(testWebSearchFields))
	}
	for i := range messages.Len() {
		message := messages.Get(i)
		want, ok := testWebSearchFields[message.Name()]
		if !ok {
			t.Errorf("%s is not listed", message.Name())
			continue
		}
		got := []string{}
		for j := range message.Fields().Len() {
			got = append(got, testWebSearchFieldLine(message.Fields().Get(j)))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", message.Name(), got, want)
		}
		if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s holds a oneof or nests a declaration", message.Name())
		}
		if message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
			t.Errorf("%s reserves numbers", message.Name())
		}
	}
	enums := file.Enums()
	if enums.Len() != len(testWebSearchValues) {
		t.Errorf("%s declares %d enums, and %d are listed", testWebSearchProtoPath, enums.Len(), len(testWebSearchValues))
	}
	for i := range enums.Len() {
		enum := enums.Get(i)
		want, ok := testWebSearchValues[enum.Name()]
		if !ok {
			t.Errorf("enum %s is not listed", enum.Name())
			continue
		}
		got := []string{}
		for j := range enum.Values().Len() {
			value := enum.Values().Get(j)
			got = append(got, testWebSearchValueLine(value))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", enum.Name(), got, want)
		}
	}
}

func testWebSearchValueLine(value protoreflect.EnumValueDescriptor) string {
	return strconv.Itoa(int(value.Number())) + " " + string(value.Name())
}

// A request round-trips deterministically: what the broker decodes is what the device built, field for field, and the
// same request encodes to the same bytes, which a retry under one request id and attempt relies on.
func TestWebSearchAuthorizeRequestRoundTrips(t *testing.T) {
	request := &ComputeSearchAuthorizeRequest{
		CatalogVersion: 7,
		RequestId:      make([]byte, 16),
		AgentId:        make([]byte, 16),
		Attempt:        2,
		SealedPayee:    []byte{1, 2, 3},
		Amount:         10000,
		Asset:          make([]byte, 20),
		Network:        "eip155:84532",
		Outcomes:       &SearchOutcomes{Ok: 3, ProviderError: 1, Timeout: 1, Refused: 2},
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil || !slices.Equal(encoded, again) {
		t.Fatalf("two encodings differ: %v", err)
	}
	decoded := &ComputeSearchAuthorizeRequest{}
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(request, decoded) {
		t.Errorf("decoded %v, want %v", decoded, request)
	}
}
