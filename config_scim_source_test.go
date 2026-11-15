//go:build !ios_extension

// GET /sidecar/scim-changes's client and SCIM's queue source over it (QD-829), on a scripted api that pages as server's
// route does: a page after an id and at most a limit, read whole or refused whole, and the source's members each once,
// oldest first, from every page up to its bound.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"
)

// The change id of position i, ascending with i, as server's change ids sort.
func testScimChangeId(i int) Id {
	return Id{0x01, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(i)}
}

// A queued member_revoke of memberId at position i.
func testScimChange(i int, memberId Id) *ScimChange {
	return &ScimChange{
		ChangeId:   testScimChangeId(i),
		NetworkId:  testConfigId("scim network"),
		MemberId:   &memberId,
		Kind:       ScimChangeKindMemberRevoke,
		Detail:     json.RawMessage(`{"email":"member@scim.example"}`),
		CreateTime: time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC),
	}
}

// An api answering GET /sidecar/scim-changes from changes, in order, a page at most pageMax long and at most the
// request's limit, after the request's after, as server's route reads both.
func scimQueueTransport(changes []*ScimChange, pageMax int) *scriptedApiTransport {
	return &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.Path != "/sidecar/scim-changes" {
				return syntheticResponse(request, http.StatusNotFound, `{"error":"Not found."}`, nil), nil
			}
			query := request.URL.Query()
			limit := pageMax
			if text := query.Get("limit"); text != "" {
				asked, err := strconv.Atoi(text)
				if err != nil || asked <= 0 {
					return syntheticResponse(request, http.StatusBadRequest, `{"error":"Invalid limit."}`, nil), nil
				}
				limit = min(asked, pageMax)
			}
			var after *Id
			if text := query.Get("after"); text != "" {
				afterId, err := ParseId(text)
				if err != nil {
					return syntheticResponse(request, http.StatusBadRequest, `{"error":"Invalid change id."}`, nil), nil
				}
				after = &afterId
			}
			page := &ScimChanges{Changes: []*ScimChange{}}
			for _, change := range changes {
				if after != nil && change.ChangeId.Cmp(*after) <= 0 {
					continue
				}
				if limit <= len(page.Changes) {
					page.More = true
					break
				}
				page.Changes = append(page.Changes, change)
			}
			encoded, err := json.Marshal(page)
			if err != nil {
				return nil, err
			}
			return syntheticResponse(request, http.StatusOK, string(encoded), nil), nil
		},
	}
}

// One page after an id and at most a limit: the request names both and presents the client's token as its bearer, and
// the page decodes in GET /network/scim-changes's form.
func TestScimChangesReadsAPageAfterAnId(t *testing.T) {
	member := testConfigId("page member")
	changes := []*ScimChange{testScimChange(1, testConfigId("before")), testScimChange(2, member), testScimChange(3, testConfigId("after"))}
	transport := scimQueueTransport(changes, 1000)
	api := newTestSidecarApi(t, transport)
	after := testScimChangeId(1)
	page, err := api.ScimChanges(context.Background(), &after, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Changes) != 1 || !page.More || *page.Changes[0].MemberId != member || page.Changes[0].ChangeId != testScimChangeId(2) ||
		!page.Changes[0].CreateTime.Equal(changes[1].CreateTime) || string(page.Changes[0].Detail) != string(changes[1].Detail) {
		t.Fatalf("the page: %+v", page)
	}
	request, body := transport.onlyRequest(t)
	if request.URL.Query().Get("after") != after.String() || request.URL.Query().Get("limit") != "1" || len(body) != 0 {
		t.Errorf("the request %s", request.URL)
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Errorf("authorization %q", request.Header.Get("Authorization"))
	}

	// none and no limit: api's own first page
	whole, err := api.ScimChanges(context.Background(), nil, 0)
	if err != nil || len(whole.Changes) != 3 || whole.More {
		t.Fatalf("the first page: %+v %v", whole, err)
	}
	if query := transport.requests[1].URL.RawQuery; query != "" {
		t.Errorf("a first read asked %q", query)
	}
}

// The source reads every page, after the last change of each, and answers each member once, oldest first by its first
// change; past PassPageMaxCount pages it stops, the rest left to the next pass.
func TestScimSourceReadsEveryPageOnceOldestFirst(t *testing.T) {
	first, second, third := testConfigId("source first"), testConfigId("source second"), testConfigId("source third")
	changes := []*ScimChange{
		testScimChange(1, first), testScimChange(2, second), testScimChange(3, first), testScimChange(4, third), testScimChange(5, second),
	}
	transport := scimQueueTransport(changes, 1000)
	settings := DefaultConfigScimSignerSettings()
	settings.PageCount = 2
	source := newSidecarApiScimChangeSource(newTestSidecarApi(t, transport), settings)
	memberIds, err := source.ScimMemberRevokes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(memberIds, []Id{first, second, third}) {
		t.Errorf("read %v", memberIds)
	}
	if transport.requestCount() != 3 {
		t.Fatalf("%d requests for 5 changes in pages of 2", transport.requestCount())
	}
	for i, wantAfter := range []string{"", testScimChangeId(2).String(), testScimChangeId(4).String()} {
		if query := transport.requests[i].URL.Query(); query.Get("after") != wantAfter || query.Get("limit") != "2" {
			t.Errorf("request %d asked %s", i, transport.requests[i].URL.RawQuery)
		}
	}

	settings.PassPageMaxCount = 1
	bounded := scimQueueTransport(changes, 1000)
	memberIds, err = newSidecarApiScimChangeSource(newTestSidecarApi(t, bounded), settings).ScimMemberRevokes(context.Background())
	if err != nil || !slices.Equal(memberIds, []Id{first, second}) || bounded.requestCount() != 1 {
		t.Errorf("bounded to 1 page: %v %v after %d requests", memberIds, err, bounded.requestCount())
	}
}

// An answer that is not the route's is refused whole: a change of another kind, one naming no member or no id, ids out
// of order or not after the one asked after, more with an empty page, or no JSON. A source whose later page is so
// answers nothing, never the members of the pages before.
func TestScimChangesRefusesAnAnswerThatIsNotItsShape(t *testing.T) {
	member := testConfigId("shape member")
	encode := func(page any) string {
		encoded, err := json.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	groupChange := testScimChange(1, member)
	groupChange.Kind = "group"
	nameless := testScimChange(1, member)
	nameless.MemberId = nil
	idless := testScimChange(1, member)
	idless.ChangeId = Id{}
	for _, body := range []string{
		encode(&ScimChanges{Changes: []*ScimChange{groupChange}}),
		encode(&ScimChanges{Changes: []*ScimChange{nameless}}),
		encode(&ScimChanges{Changes: []*ScimChange{idless}}),
		encode(&ScimChanges{Changes: []*ScimChange{testScimChange(2, member), testScimChange(1, member)}}),
		encode(&ScimChanges{Changes: []*ScimChange{testScimChange(1, member), testScimChange(1, member)}}),
		encode(&ScimChanges{Changes: []*ScimChange{}, More: true}),
		`{"changes":[{"change_id":"not an id","kind":"member_revoke"}]}`,
		`[]`,
	} {
		if _, err := newTestSidecarApi(t, answerWith(http.StatusOK, body)).ScimChanges(context.Background(), nil, 0); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v, want a malformed reply", body, err)
		}
	}
	// a page that does not start after the id asked after
	after := testScimChangeId(5)
	body := encode(&ScimChanges{Changes: []*ScimChange{testScimChange(5, member)}})
	if _, err := newTestSidecarApi(t, answerWith(http.StatusOK, body)).ScimChanges(context.Background(), &after, 0); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a page repeating the id asked after: %v", err)
	}

	pages := &scriptedApiTransport{
		answer: func(request *http.Request, requestBody []byte) (*http.Response, error) {
			if request.URL.Query().Get("after") == "" {
				return syntheticResponse(request, http.StatusOK, encode(&ScimChanges{Changes: []*ScimChange{testScimChange(1, member)}, More: true}), nil), nil
			}
			return syntheticResponse(request, http.StatusOK, encode(&ScimChanges{Changes: []*ScimChange{groupChange}}), nil), nil
		},
	}
	memberIds, err := newSidecarApiScimChangeSource(newTestSidecarApi(t, pages), nil).ScimMemberRevokes(context.Background())
	if !errors.Is(err, ErrSidecarApiReply) || memberIds != nil {
		t.Errorf("a malformed second page: %v %v", memberIds, err)
	}
}

// api's refusal, a client token of a sidecar scim_signer does not name or a Network credential, is a SidecarApiError
// naming the route, and a source that meets it answers no member.
func TestScimChangesRefusal(t *testing.T) {
	refused := answerWith(http.StatusForbidden, `{"error":"Only the indexer ServiceSettings.scim_signer names reads SCIM's queued removals."}`)
	api := newTestSidecarApi(t, refused)
	_, err := api.ScimChanges(context.Background(), nil, 0)
	if apiErr := asSidecarApiError(t, err); apiErr.Route != sidecarScimChangesRoute || apiErr.Status != http.StatusForbidden {
		t.Errorf("%+v", apiErr)
	}
	memberIds, err := newSidecarApiScimChangeSource(api, nil).ScimMemberRevokes(context.Background())
	if err == nil || memberIds != nil {
		t.Errorf("a refused source answered %v %v", memberIds, err)
	}
}
