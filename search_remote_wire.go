//go:build !sidecar_http && !ios_extension

// Remote search's bodies (§11.14's exchange, sizes and status rows; D-EVS-59; DESIGN-DETAILS 11.2.9's Z4 to Z9;
// QD-215, QD-692, QD-693): the builders that make every request exactly RequestByteCount and every reply
// exactly steps × StepByteCount, and the parsers that accept a body only when it is the one encoding of its
// message, so that a relay learns nothing from a length and a pad of zeros hides nothing.
//
// A body is the deterministic proto3 encoding of its message, pad last. Its content is that encoding with pad
// empty, taken with proto.Size after pad is cleared, never from an earlier marshal. Z4's caps, which these
// builders keep and these parsers check, hold every content inside Z3 (rpc_search.go): a request within them is
// at most 3,778 B on page 0 and 36 B on a later page; a reply without hits at most 7,578 B, and one hit adds at
// most 3,248 B; a failure's at most 90 B (Z-B, Z-C). So a request within the caps is always admissible, a reply
// always has an admissible form, and one with a hit to give returns at least one.
//
// Every value is SearchWireSettings' (envelope_search_settings.go). These are pure functions: SearchRemoteServer
// (SEARCH-M10-32) and SearchRemoteClient (SEARCH-M10-33) call them, the server with its own head(k).

package sidecar

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A request a cap refuses: past 512 B of query, 64 repos, 768 B of filters, an id of the wrong length or
	// steps outside 1 to MaxStepCount. It is not sent (Z5): more than 64 repos go in further requests, and a
	// search whose filters pass 768 B stays on the device (QD-215).
	errSearchRequestCaps = errors.New("search request past a cap")
	// A later page carrying a field of page 0's (§11.14's exchange row), which no requester sends.
	errSearchRequestPageFields = errors.New("search request page past 0 carries page 0's fields")
)

// Z4 on a request: its query, repos, ids, filters and steps within the caps.
func searchRemoteRequestWithinCaps(request *protocol.SearchRequest, settings *SearchWireSettings) bool {
	if settings.QueryMaxByteCount < len(request.GetQuery()) || settings.RepoMaxCount < len(request.GetRepos()) {
		return false
	}
	for _, repo := range request.GetRepos() {
		if len(repo.GetRepoId()) != settings.IdByteCount {
			return false
		}
		if refId := repo.GetRefId(); len(refId) != 0 && len(refId) != settings.IdByteCount {
			return false
		}
	}
	if filters := request.GetFilters(); filters != nil && settings.FiltersMaxByteCount < proto.Size(filters) {
		return false
	}
	return 1 <= request.GetSteps() && int(request.GetSteps()) <= settings.MaxStepCount
}

// Whether request carries any field page 0 alone may carry: scope, query, repos, since and until, filters,
// fuzzy.
func searchRemoteRequestHasPageZeroFields(request *protocol.SearchRequest) bool {
	return request.GetScope() != 0 || request.GetQuery() != "" || len(request.GetRepos()) != 0 ||
		request.GetSinceMs() != 0 || request.GetUntilMs() != 0 || request.Filters != nil || request.GetFuzzy()
}

// Z5: request's body, its fields as given and pad sized by Z2 to RequestByteCount. request is not changed.
// errSearchRequestCaps for a request past a cap, which is not sent; errSearchRequestPageFields for a later
// page that carries page 0's fields.
func searchRemoteBuildRequest(request *protocol.SearchRequest, settings *SearchWireSettings) ([]byte, error) {
	if !searchRemoteRequestWithinCaps(request, settings) {
		return nil, errSearchRequestCaps
	}
	if 0 < request.GetPage() && searchRemoteRequestHasPageZeroFields(request) {
		return nil, errSearchRequestPageFields
	}
	sized := proto.Clone(request).(*protocol.SearchRequest)
	sized.Pad = nil
	padByteCount, ok := searchRemotePadByteCount(settings.RequestByteCount, proto.Size(sized), settings)
	if !ok {
		// within the caps a content is at most 3,778 B (Z-B), so only settings off the protocol's reach here
		return nil, errSearchRequestCaps
	}
	sized.Pad = make([]byte, padByteCount)
	return proto.MarshalOptions{Deterministic: true}.Marshal(sized)
}

// Z4 on a hit: the hit as a reply carries it, with fields past HitFieldMaxCount, a field whose text is past its
// cap, and a snippet or correction past its cap left out, the caller's hit unchanged; false when it holds an id
// or signer of the wrong length or a locator past its cap, which no reply carries (Z8 f).
func searchRemoteKeepHit(hit *protocol.SearchHit, settings *SearchWireSettings) (*protocol.SearchHit, bool) {
	if len(hit.GetRepoId()) != settings.IdByteCount || len(hit.GetRefId()) != settings.IdByteCount ||
		len(hit.GetDocKey()) != settings.IdByteCount || len(hit.GetSigner()) != settings.IdByteCount ||
		settings.LocatorMaxByteCount < len(hit.GetLocator()) {
		return nil, false
	}
	trim := settings.HitFieldMaxCount < len(hit.GetFields()) || settings.SnippetMaxByteCount < len(hit.GetSnippet()) ||
		settings.CorrectionMaxByteCount < len(hit.GetCorrection())
	for _, field := range hit.GetFields() {
		if settings.HitFieldTextMaxByteCount < len(field.GetText()) {
			trim = true
		}
	}
	if !trim {
		return hit, true
	}
	kept := proto.Clone(hit).(*protocol.SearchHit)
	fields := []*protocol.SearchField{}
	for _, field := range kept.GetFields() {
		if len(fields) == settings.HitFieldMaxCount {
			break
		}
		if len(field.GetText()) <= settings.HitFieldTextMaxByteCount {
			fields = append(fields, field)
		}
	}
	kept.Fields = fields
	if settings.SnippetMaxByteCount < len(kept.GetSnippet()) {
		kept.Snippet = ""
	}
	if settings.CorrectionMaxByteCount < len(kept.GetCorrection()) {
		kept.Correction = ""
	}
	return kept, true
}

// Z4 on coverage: the rows a reply carries, at most CoverageMaxCount, each with ids of IdByteCount and a chain
// within its cap; the others are left out (Z8 f).
func searchRemoteKeepCoverage(coverage []*protocol.SearchCoverage, settings *SearchWireSettings) []*protocol.SearchCoverage {
	kept := []*protocol.SearchCoverage{}
	for _, row := range coverage {
		if len(kept) == settings.CoverageMaxCount {
			break
		}
		if len(row.GetRepoId()) == settings.IdByteCount && len(row.GetRefId()) == settings.IdByteCount &&
			len(row.GetChain()) <= settings.ChainMaxByteCount {
			kept = append(kept, row)
		}
	}
	return kept
}

// Z6: a reply of steps (1 to MaxStepCount; anything else is taken as one, the size of a failure) from the hits
// still to give, in rank order, and head(k), the reply's other fields when k hits are returned: status, phase,
// complete, checked_through_ms, counts and on page 0 the coverage rows. head is called up to HitMaxCount + 1
// times, so it must be a pure function of k returning a fresh message; its hits and pad are replaced here, and
// its coverage kept within Z4. For k from min(HitMaxCount, the hits to give) down to 0, the first k whose content
// Z3 admits is the reply, padded by Z2; k = 0 is always admissible, and k = 1 when there is a hit (Z-C), so
// building cannot fail on the protocol's settings (on settings off them, nil and 0 say no body fits).
//
// A hit over a cap is left out first, as a receiver would (searchRemoteKeepHit), so head's k counts the hits
// within the caps; a server that drops those itself first, as SEARCH-M10-32's does, reads k as its own first k.
// The int is how many of hits the reply accounts for, those returned and those left out before the first not
// returned; the rest stay with the cursor for the next page.
func searchRemoteBuildReply(steps int, hits []*protocol.SearchHit, head func(hitCount int) *protocol.SearchReply, settings *SearchWireSettings) ([]byte, int) {
	if steps < 1 || settings.MaxStepCount < steps {
		steps = 1
	}
	keptHits := []*protocol.SearchHit{}
	// where in hits each kept hit stands
	keptIndexes := []int{}
	for i, hit := range hits {
		if len(keptHits) == settings.HitMaxCount {
			break
		}
		if kept, ok := searchRemoteKeepHit(hit, settings); ok {
			keptHits = append(keptHits, kept)
			keptIndexes = append(keptIndexes, i)
		}
	}
	// a reply of hitCount accounts for every hit before the first kept one it does not return, the ones left
	// out between included; with every kept one returned and fewer than the cap, for all of hits
	accounted := func(hitCount int) int {
		switch {
		case hitCount < len(keptHits):
			return keptIndexes[hitCount]
		case len(keptHits) < settings.HitMaxCount:
			return len(hits)
		default:
			return keptIndexes[hitCount-1] + 1
		}
	}
	for hitCount := len(keptHits); 0 <= hitCount; hitCount -= 1 {
		reply := head(hitCount)
		if reply == nil {
			reply = &protocol.SearchReply{}
		}
		reply.Hits = keptHits[:hitCount]
		reply.Coverage = searchRemoteKeepCoverage(reply.GetCoverage(), settings)
		if body, err := padSearchReply(reply, steps, settings); err == nil {
			return body, accounted(hitCount)
		}
	}
	// within the caps k = 0 is admissible at every size the protocol's settings give (Z-C), so only settings off
	// the protocol's reach get here, and then there is no body to send
	return nil, 0
}

// Z9: whether body is the one encoding of message, which body parsed to: it holds no field this build does not
// know, at any depth, and marshaling it deterministically gives body back. Both halves are needed, since the
// marshaler writes back an unknown field it kept, and one after pad would marshal to itself.
func searchRemoteOneEncoding(body []byte, message proto.Message) bool {
	if searchRemoteHoldsUnknown(message.ProtoReflect()) {
		return false
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	return err == nil && bytes.Equal(encoded, body)
}

// Whether message, or any message inside it, kept bytes of a field it does not know.
func searchRemoteHoldsUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Message() == nil || field.IsMap():
		case field.IsList():
			list := value.List()
			for i := 0; i < list.Len(); i += 1 {
				if searchRemoteHoldsUnknown(list.Get(i).Message()) {
					unknown = true
					return false
				}
			}
		default:
			if searchRemoteHoldsUnknown(value.Message()) {
				unknown = true
				return false
			}
		}
		return true
	})
	return unknown
}

// Whether every byte of pad is zero (Z8 e).
func searchRemotePadZeros(pad []byte) bool {
	for _, b := range pad {
		if b != 0 {
			return false
		}
	}
	return true
}

// Z8 at an indexer, in its order: (a) the body is RequestByteCount; (b) it parses; (c) its search_version is
// one this build supports; (d) it is its message's one encoding (Z9); (e) its pad is zeros; (f) its fields are
// within Z4. The status answers it: SEARCH_OK when every check holds, UNSUPPORTED_VERSION for (c), judged before
// the encoding so that a later version's fields are not INVALID, and INVALID for the rest. The request is the
// parsed message where (b) held, else nil; a failure is answered searchRemoteFailureReply(status, request), at
// the request's steps where it parsed and asks 1 to MaxStepCount, else at one, and never by an Error.
func searchRemoteParseRequest(body []byte, settings *SearchWireSettings) (*protocol.SearchRequest, protocol.SearchStatus) {
	request := &protocol.SearchRequest{}
	if err := proto.Unmarshal(body, request); err != nil {
		request = nil
	}
	switch {
	case len(body) != settings.RequestByteCount:
		return request, protocol.SearchStatus_SEARCH_INVALID
	case request == nil:
		return nil, protocol.SearchStatus_SEARCH_INVALID
	case request.GetSearchVersion() != searchVersion:
		return request, protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION
	case !searchRemoteOneEncoding(body, request):
		return request, protocol.SearchStatus_SEARCH_INVALID
	case !searchRemotePadZeros(request.GetPad()):
		return request, protocol.SearchStatus_SEARCH_INVALID
	case !searchRemoteRequestWithinCaps(request, settings):
		return request, protocol.SearchStatus_SEARCH_INVALID
	}
	return request, protocol.SearchStatus_SEARCH_OK
}

// Z8's (a), (b), (d) and (e) at a requester, for a request of steps: the reply body holds, exactly as sent, and
// false when it is no reply.
func searchRemoteAcceptReply(body []byte, steps int, settings *SearchWireSettings) (*protocol.SearchReply, bool) {
	if steps < 1 || settings.MaxStepCount < steps || len(body) != steps*settings.StepByteCount {
		return nil, false
	}
	reply := &protocol.SearchReply{}
	if err := proto.Unmarshal(body, reply); err != nil {
		return nil, false
	}
	if !searchRemoteOneEncoding(body, reply) || !searchRemotePadZeros(reply.GetPad()) {
		return nil, false
	}
	return reply, true
}

// Z8 at a requester, for the request of steps, searchId and page it sent: false when the body fails (a) to (e)
// or names another search_id or page, which the requester reads as the indexer failing (§11.14's failover row).
// What passes is the requester's own copy, with (f)'s dropping applied: coverage rows past CoverageMaxCount and
// one with a wrong-length id or a chain past its cap; hits past HitMaxCount and one with a wrong-length id or a
// locator past its cap; a hit's fields past HitFieldMaxCount, and a field, snippet or correction past its cap.
// A status, or a served code, this build does not know is read as unspecified, as is any status but
// UNSUPPORTED_VERSION at a search_version this build does not speak, so none is ever read as OK or served.
func searchRemoteParseReply(body []byte, steps int, searchId uint64, page uint32, settings *SearchWireSettings) (*protocol.SearchReply, bool) {
	reply, ok := searchRemoteAcceptReply(body, steps, settings)
	if !ok || reply.GetSearchId() != searchId || reply.GetPage() != page {
		return nil, false
	}
	reply.Pad = nil
	reply.Coverage = searchRemoteKeepCoverage(reply.GetCoverage(), settings)
	hits := []*protocol.SearchHit{}
	for _, hit := range reply.GetHits() {
		if len(hits) == settings.HitMaxCount {
			break
		}
		if kept, ok := searchRemoteKeepHit(hit, settings); ok {
			hits = append(hits, kept)
		}
	}
	reply.Hits = hits
	status := protocol.SearchStatus(reply.GetStatus())
	if uint32(protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION) < reply.GetStatus() {
		status = protocol.SearchStatus_SEARCH_STATUS_UNSPECIFIED
	}
	if reply.GetSearchVersion() != searchVersion && status != protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION {
		status = protocol.SearchStatus_SEARCH_STATUS_UNSPECIFIED
	}
	reply.Status = uint32(status)
	for _, row := range reply.GetCoverage() {
		if row.GetServed() > uint32(protocol.SearchServed_REFUSED_FORMAT) {
			row.Served = uint32(protocol.SearchServed_SEARCH_SERVED_UNSPECIFIED)
		}
	}
	return reply, true
}
