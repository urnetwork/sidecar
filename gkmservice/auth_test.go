package gkmservice

import (
	"errors"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The subjects of the matrix: one token class each, on one repo whose group the route names.
type gkmMatrixClass string

const (
	gkmClassRead     gkmMatrixClass = "r"
	gkmClassWrite    gkmMatrixClass = "rw"
	gkmClassAdmin    gkmMatrixClass = "admin"
	gkmClassDeposit  gkmMatrixClass = "deposit"
	gkmClassRecovery gkmMatrixClass = "recovery"
	gkmClassNone     gkmMatrixClass = "none"
	gkmClassReadOnly gkmMatrixClass = "read_only"
	gkmClassParked   gkmMatrixClass = "parked"
	gkmClassRevoked  gkmMatrixClass = "revoked"
)

// The classes each route's row admits, by pattern: §10.6's scopes block with QD-177's and QD-066's readings. Every
// class not listed is refused.
var gkmMatrixAllowed = map[string][]gkmMatrixClass{
	"POST /gkm/key-packages":           {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/key-packages/claim":     {gkmClassWrite, gkmClassAdmin},
	"POST /gkm/reader-key":             {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"GET /gkm/reader-key/{sidecar_id}": {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly, gkmClassParked},
	"POST /gkm/reader-keys":            {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly, gkmClassParked},
	"GET /gkm/welcomes":                {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly, gkmClassParked},

	"POST /gkm/groups":                                    {gkmClassAdmin},
	"GET /gkm/groups/{group_id}":                          {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"GET /gkm/repos/{repo_id}/forms":                      {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/repos/{repo_id}/forms":                     {gkmClassAdmin},
	"GET /gkm/groups/{group_id}/epochs":                   {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/groups/{group_id}/epochs/{n}":              {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/groups/{group_id}/welcome/{n}":             {gkmClassWrite, gkmClassAdmin},
	"HEAD /gkm/groups/{group_id}/welcome/{n}":             {gkmClassWrite, gkmClassAdmin},
	"GET /gkm/groups/{group_id}/group-info":               {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/groups/{group_id}/group-info":              {gkmClassRead, gkmClassWrite, gkmClassAdmin},
	"POST /gkm/groups/{group_id}/ack":                     {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"GET /gkm/groups/{group_id}/gen":                      {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/groups/{group_id}/gen/{g}":                 {gkmClassWrite, gkmClassAdmin},
	"GET /gkm/groups/{group_id}/wraps/{g}":                {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/groups/{group_id}/wraps/{g}/{c8}":          {gkmClassRead, gkmClassWrite, gkmClassAdmin},
	"POST /gkm/groups/{group_id}/recovery-wraps/{g}/{c8}": {gkmClassRead, gkmClassWrite, gkmClassAdmin},
	"POST /gkm/groups/{group_id}/ladder":                  {gkmClassAdmin},
	"GET /gkm/repos/{repo_id}/drop-key":                   {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly, gkmClassDeposit},
	"GET /gkm/recovery/{member_id}/wraps":                 {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly, gkmClassRecovery, gkmClassParked},
	"POST /gkm/recovery/{member_id}/wraps":                {gkmClassRead, gkmClassWrite, gkmClassAdmin},
	"DELETE /gkm/recovery/{member_id}/wraps":              {gkmClassRead, gkmClassWrite, gkmClassAdmin},

	"PUT /gkm/delegation-keys/{delegation_id}": {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"GET /gkm/delegation-keys/{delegation_id}": {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
	"POST /gkm/delegation-keys":                {gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassReadOnly},
}

// The matrix's world: one repo on the second cluster whose GroupForm names one group, one member, and a sidecar of
// that member per class.
type gkmMatrix struct {
	fixture         *gkmFixture
	repoId          sidecar.Id
	groupId         sidecar.Id
	memberId        sidecar.Id
	classSidecarIds map[gkmMatrixClass]sidecar.Id
	classTokens     map[gkmMatrixClass]string
	served          map[string]int
}

// Every route served by a probe that authorizes a body-named repo or group as its handler would, then answers 200.
func newGkmMatrix(t *testing.T) *gkmMatrix {
	matrix := &gkmMatrix{
		repoId:          testId("repo-r"),
		groupId:         testId("group-g"),
		memberId:        testId("member-m"),
		classSidecarIds: map[gkmMatrixClass]sidecar.Id{},
		classTokens:     map[gkmMatrixClass]string{},
		served:          map[string]int{},
	}
	matrix.fixture = newGkmFixtureWith(t, func(settings *GkmServiceSettings, deps *GkmEngineDeps) {
		deps.testServes = map[string]func(engine *GkmEngine, request *GkmRequest){}
		for _, route := range gkmRoutes {
			pattern := route.Pattern
			deps.testServes[pattern] = func(engine *GkmEngine, request *GkmRequest) {
				if route.Target == gkmTargetBody {
					authorized := false
					if pattern == "POST /gkm/groups" {
						authorized = request.AuthorizeRepo(matrix.repoId)
					} else {
						authorized = request.AuthorizeGroup(matrix.groupId)
					}
					if !authorized {
						return
					}
				}
				matrix.served[pattern] += 1
				request.Reply(nil)
			}
		}
	})
	fixture := matrix.fixture
	fixture.placeRepo(matrix.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(matrix.repoId, "meta-2", 1, matrix.groupId)
	for _, class := range []gkmMatrixClass{gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassDeposit, gkmClassRecovery, gkmClassNone, gkmClassReadOnly, gkmClassParked, gkmClassRevoked} {
		sidecarId := testId("sc-" + string(class))
		matrix.classSidecarIds[class] = sidecarId
		facts := memberDeviceFacts(matrix.memberId)
		scopes := []string{}
		switch class {
		case gkmClassRead:
			scopes = []string{repoScope(matrix.repoId, "r")}
			fixture.auth.grant(sidecarId, matrix.repoId, sidecar.AclEvsRead)
		case gkmClassWrite:
			scopes = []string{repoScope(matrix.repoId, "rw")}
			fixture.auth.grant(sidecarId, matrix.repoId, sidecar.AclEvsWrite)
		case gkmClassAdmin:
			scopes = []string{repoScope(matrix.repoId, "admin")}
			fixture.auth.grant(sidecarId, matrix.repoId, sidecar.AclEvsAdmin)
		case gkmClassDeposit:
			// an agent holding only §16.8's deposit
			facts = &GkmSidecarFacts{}
			scopes = []string{repoScope(matrix.repoId, "deposit")}
			fixture.auth.grant(sidecarId, matrix.repoId, sidecar.AclEvsDeposit)
		case gkmClassRecovery:
			// an unadmitted client of the member: the state holds no admission for its sidecar
			scopes = []string{"recovery:" + matrix.memberId.String()}
			facts = nil
		case gkmClassNone:
		case gkmClassReadOnly:
			facts.ReadOnly = true
			scopes = []string{repoScope(matrix.repoId, "r")}
			fixture.auth.grant(sidecarId, matrix.repoId, sidecar.AclEvsRead)
		case gkmClassParked:
			// a parked sidecar keeps its token, and the state honors nothing of it (§8.6)
			facts.Parked = true
			scopes = []string{repoScope(matrix.repoId, "rw")}
		case gkmClassRevoked:
			facts.Revoked = true
			scopes = []string{repoScope(matrix.repoId, "rw")}
			fixture.auth.revoke(sidecarId)
		}
		if facts != nil {
			fixture.auth.admit(sidecarId, facts)
		}
		matrix.classTokens[class] = fixture.token(sidecarId, scopes...)
	}
	return matrix
}

// A path for a pattern, its values filled from the matrix's world.
func (self *gkmMatrix) path(pattern string) (method string, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	replacer := strings.NewReplacer(
		"{group_id}", sidecar.EvsKeyId(self.groupId),
		"{repo_id}", sidecar.EvsKeyId(self.repoId),
		"{member_id}", sidecar.EvsKeyId(self.memberId),
		"{sidecar_id}", sidecar.EvsKeyId(testId("sc-r")),
		"{n}", "1",
		"{g}", "2",
		"{c8}", "0123456789abcdef",
		"{delegation_id}", strings.Repeat("d1", 32),
	)
	return method, replacer.Replace(path)
}

// §22.5's matrix: every route × {r, rw, admin, deposit, recovery, none, read_only, parked, revoked}. A class the row
// admits reaches the route's handler; every other is refused before it, 401 or 403, and nothing is served.
func TestGkmScopeMatrixHoldsEveryRouteToItsRow(t *testing.T) {
	matrix := newGkmMatrix(t)
	if len(gkmMatrixAllowed) != len(gkmRoutes) {
		t.Fatalf("the matrix names %d routes and the table %d", len(gkmMatrixAllowed), len(gkmRoutes))
	}
	for _, route := range gkmRoutes {
		allowed, ok := gkmMatrixAllowed[route.Pattern]
		if !ok {
			t.Fatalf("%s: no row in the matrix", route.Pattern)
		}
		for _, class := range []gkmMatrixClass{gkmClassRead, gkmClassWrite, gkmClassAdmin, gkmClassDeposit, gkmClassRecovery, gkmClassNone, gkmClassReadOnly, gkmClassParked, gkmClassRevoked} {
			servedBefore := matrix.served[route.Pattern]
			method, path := matrix.path(route.Pattern)
			recorder := matrix.fixture.serve(method, path, matrix.classTokens[class], nil)
			wantAllowed := slices.Contains(allowed, class)
			switch {
			case wantAllowed && recorder.Code != http.StatusOK:
				t.Errorf("%s by %s: %d, want 200", route.Pattern, class, recorder.Code)
			case !wantAllowed && recorder.Code != http.StatusForbidden && recorder.Code != http.StatusUnauthorized:
				t.Errorf("%s by %s: %d, want 401 or 403", route.Pattern, class, recorder.Code)
			case !wantAllowed && matrix.served[route.Pattern] != servedBefore:
				t.Errorf("%s by %s: a refused request reached the handler", route.Pattern, class)
			}
		}
	}
}

// A token with no ur_sidecar_id reaches nothing but a recovery read under its recovery scope.
func TestGkmTokenWithoutASidecarReachesOnlyItsRecoveryRead(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	recoveryOnly := fixture.token(sidecar.Id{}, "recovery:"+matrix.memberId.String())
	repoOnly := fixture.token(sidecar.Id{}, repoScope(matrix.repoId, "admin"))
	for _, route := range gkmRoutes {
		method, path := matrix.path(route.Pattern)
		if recorder := fixture.serve(method, path, repoOnly, nil); recorder.Code != http.StatusForbidden {
			t.Errorf("%s by a client with no sidecar: %d", route.Pattern, recorder.Code)
		}
		recorder := fixture.serve(method, path, recoveryOnly, nil)
		if route.Scope == gkmScopeRecoveryRead {
			if recorder.Code != http.StatusOK {
				t.Errorf("the recovery read under its scope: %d", recorder.Code)
			}
		} else if recorder.Code != http.StatusForbidden {
			t.Errorf("%s under a recovery scope: %d", route.Pattern, recorder.Code)
		}
	}
	// another member's recovery wraps are refused under this member's scope
	otherPath := "/gkm/recovery/" + sidecar.EvsKeyId(testId("member-other")) + "/wraps"
	if recorder := fixture.serve(http.MethodGet, otherPath, recoveryOnly, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("another member's wraps: %d", recorder.Code)
	}
	// and a device of another member is refused this member's
	otherDevice := testId("sc-other")
	fixture.auth.admit(otherDevice, memberDeviceFacts(testId("member-other")))
	fixture.auth.grant(otherDevice, matrix.repoId, sidecar.AclEvsRead)
	_, path := matrix.path("GET /gkm/recovery/{member_id}/wraps")
	if recorder := fixture.serve(http.MethodGet, path, fixture.token(otherDevice, repoScope(matrix.repoId, "r")), nil); recorder.Code != http.StatusForbidden {
		t.Errorf("another member's device: %d", recorder.Code)
	}
}

// Every route of the table has its handler, so none answers 501, and a route's handler runs only past the guard: the
// ladder, the last to land, refuses a reader's token before it reads a body and holds an admin's to its shape.
func TestGkmEveryRouteHasItsHandlerBehindTheGuard(t *testing.T) {
	for _, route := range gkmRoutes {
		if route.Serve == nil {
			t.Errorf("%s has no handler", route.Pattern)
		}
	}
	fixture := newGkmFixture(t)
	repoId := testId("repo-r")
	groupId := testId("group-g")
	fixture.placeRepo(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(repoId, "meta-1", 1, groupId)
	admin := testId("sc-admin")
	fixture.auth.admit(admin, memberDeviceFacts(testId("member-m")))
	fixture.auth.grant(admin, repoId, sidecar.AclEvsAdmin)
	path := "/gkm/groups/" + sidecar.EvsKeyId(groupId) + "/ladder"
	if recorder := fixture.serve(http.MethodPost, path, fixture.token(admin, repoScope(repoId, "admin")), nil); recorder.Code != http.StatusBadRequest {
		t.Errorf("an empty ladder past the guard: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPost, path, fixture.token(admin, repoScope(repoId, "r")), nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a ladder the guard refuses: %d", recorder.Code)
	}
}

// D-ACL-21: a subject dropped from a repo's readers loses its scope at its next request, with the token unexpired:
// gkm keeps no answer of the state, so the bound is §8.9's 5 s of the state's own.
func TestGkmSubjectDroppedFromReadersLosesScopeAtOnce(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	reader := matrix.classSidecarIds[gkmClassRead]
	token := matrix.classTokens[gkmClassRead]
	_, path := matrix.path("GET /gkm/groups/{group_id}")
	if recorder := fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("before the drop: %d", recorder.Code)
	}
	fixture.auth.drop(reader, matrix.repoId)
	if recorder := fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("after the drop, the token still 15 minutes good: %d", recorder.Code)
	}
	// a state not loaded allows nothing, and answers 503
	fixture.auth.grant(reader, matrix.repoId, sidecar.AclEvsRead)
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a cold state: %d", recorder.Code)
	}
}

// §7.8: a rev/ object voids a token at gkm's next write, before the state has dropped its subject; reads are not
// checked against rev/, and a rev/ read gkm cannot make answers 503.
func TestGkmRevObjectVoidsAToken(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	writer := matrix.classSidecarIds[gkmClassWrite]
	token := matrix.classTokens[gkmClassWrite]
	_, ackPath := matrix.path("POST /gkm/groups/{group_id}/ack")
	_, readPath := matrix.path("GET /gkm/groups/{group_id}")
	if recorder := fixture.serve(http.MethodPost, ackPath, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("before rev/: %d", recorder.Code)
	}
	fixture.auth.revoke(writer)
	if recorder := fixture.serve(http.MethodPost, ackPath, token, nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a write under a voided token: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, readPath, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a read, which rev/ does not gate: %d", recorder.Code)
	}
	fixture.auth.revocationErr = errors.New("rev/ unreachable")
	if recorder := fixture.serve(http.MethodPost, ackPath, matrix.classTokens[gkmClassAdmin], nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("rev/ unreadable: %d", recorder.Code)
	}
}

// §19.11: a network the gkm gate does not admit, or a write while writes are off, answers 503 with Retry-After.
func TestGkmGateClosedAnswers503WithRetryAfter(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	_, readPath := matrix.path("GET /gkm/groups/{group_id}")
	_, ackPath := matrix.path("POST /gkm/groups/{group_id}/ack")
	if err := fixture.host.Gates.Set("sidecar:\n  gkm: {enabled: true, writes: false, networks: [" + testId("network-a").String() + "]}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.serve(http.MethodGet, readPath, matrix.classTokens[gkmClassRead], nil); recorder.Code != http.StatusOK {
		t.Errorf("a read with writes off: %d", recorder.Code)
	}
	recorder := fixture.serve(http.MethodPost, ackPath, matrix.classTokens[gkmClassRead], nil)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Errorf("a write with writes off: %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	if err := fixture.host.Gates.Set(""); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.serve(http.MethodGet, readPath, matrix.classTokens[gkmClassRead], nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a closed gate: %d", recorder.Code)
	}
}

// Ids in a path are 32 lowercase hex characters, the keys' form; anything else is 400, never a lookup.
func TestGkmPathIdsOutOfFormAnswer400(t *testing.T) {
	matrix := newGkmMatrix(t)
	token := matrix.classTokens[gkmClassAdmin]
	for _, path := range []string{
		"/gkm/groups/" + strings.ToUpper(sidecar.EvsKeyId(matrix.groupId)),
		"/gkm/groups/" + matrix.groupId.String(),
		"/gkm/groups/00000000000000000000000000000000",
		"/gkm/groups/xyz",
	} {
		if recorder := matrix.fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, recorder.Code)
		}
	}
}

// A write to a repo whose repo/ is not in a state the route takes is refused (§10.6's checks row): a commit to a
// keying repo, any write to a deleted one outside re-seed mode, and the re-seed's GroupForm in it.
func TestGkmWriteRefusedOutsideItsRepoStates(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	keyingRepoId := testId("repo-keying")
	keyingGroupId := testId("group-keying")
	fixture.placeRepo(keyingRepoId, "meta-1", protocol.EvsRepoState_EVS_REPO_KEYING)
	fixture.fileForm(keyingRepoId, "meta-1", 1, keyingGroupId)
	admin := matrix.classSidecarIds[gkmClassAdmin]
	fixture.auth.grant(admin, keyingRepoId, sidecar.AclEvsAdmin)
	token := fixture.token(admin, repoScope(keyingRepoId, "admin"))
	keyingGroup := "/gkm/groups/" + sidecar.EvsKeyId(keyingGroupId)
	if recorder := fixture.serve(http.MethodPost, keyingGroup+"/epochs/1", token, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit to a keying repo: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPost, keyingGroup+"/wraps/1/0123456789abcdef", token, nil); recorder.Code != http.StatusOK {
		t.Errorf("KF1's first wraps to a keying repo: %d", recorder.Code)
	}

	deletedRepoId := testId("repo-deleted")
	fixture.placeRepo(deletedRepoId, "meta-1", protocol.EvsRepoState_EVS_REPO_DELETED)
	fixture.auth.grant(admin, deletedRepoId, sidecar.AclEvsAdmin)
	deletedToken := fixture.token(admin, repoScope(deletedRepoId, "admin"))
	formsPath := "/gkm/repos/" + sidecar.EvsKeyId(deletedRepoId) + "/forms"
	if recorder := fixture.serve(http.MethodPost, formsPath, deletedToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a GroupForm for a deleted repo outside re-seed mode: %d", recorder.Code)
	}
	if err := fixture.host.Gates.Set("sidecar:\n  gkm: {enabled: true, networks: [" + testId("network-a").String() + "]}\n  reseed: true\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.serve(http.MethodPost, formsPath, deletedToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("a re-seed's GroupForm: %d", recorder.Code)
	}
}

// A write needs the repo's newest GroupForm to name the group: a re-formed group's old id takes reads and no writes.
func TestGkmReformedGroupTakesNoWrites(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	newGroupId := testId("group-new")
	fixture.fileForm(matrix.repoId, "meta-2", 2, newGroupId)
	// the forms cache holds the old list at most FormCacheTtl
	fixture.clock.Advance(fixture.settings.FormCacheTtl)
	token := matrix.classTokens[gkmClassAdmin]
	_, ackPath := matrix.path("POST /gkm/groups/{group_id}/ack")
	_, readPath := matrix.path("GET /gkm/groups/{group_id}")
	if recorder := fixture.serve(http.MethodPost, ackPath, token, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a write to the re-formed group: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, readPath, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a read of the re-formed group: %d", recorder.Code)
	}
	newAck := "/gkm/groups/" + sidecar.EvsKeyId(newGroupId) + "/ack"
	if recorder := fixture.serve(http.MethodPost, newAck, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a write to the new group: %d", recorder.Code)
	}
}

// A group no repo the token scopes names is out of scope, whatever repo holds it.
func TestGkmGroupOutsideTheTokensReposIsRefused(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	otherRepoId := testId("repo-other")
	fixture.placeRepo(otherRepoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	admin := matrix.classSidecarIds[gkmClassAdmin]
	fixture.auth.grant(admin, otherRepoId, sidecar.AclEvsAdmin)
	token := fixture.token(admin, repoScope(otherRepoId, "admin"))
	_, path := matrix.path("GET /gkm/groups/{group_id}")
	if recorder := fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a group of a repo the token does not scope: %d", recorder.Code)
	}
}

// gkm-9's request log holds client, route, group, time and bytes, and no other id.
func TestGkmServiceLogHoldsGkm9sFieldsOnly(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	_, path := matrix.path("GET /gkm/groups/{group_id}")
	fixture.serve(http.MethodGet, path, matrix.classTokens[gkmClassRead], nil)
	entry := fixture.serviceLog.last()
	if entry.Route != "GET /gkm/groups/{group_id}" || entry.GroupId == nil || *entry.GroupId != matrix.groupId {
		t.Errorf("entry %+v", entry)
	}
	if entry.ClientId == (sidecar.Id{}) || !entry.Time.Equal(fixture.clock.Now()) {
		t.Errorf("entry's client or time: %+v", entry)
	}
	// the struct itself is the rule: a field added here is a metadata change (I-18)
	fields := []string{"Time", "Route", "ClientId", "GroupId", "RequestByteCount", "ReplyByteCount"}
	entryType := reflect.TypeFor[GkmServiceLogEntry]()
	got := []string{}
	for i := 0; i < entryType.NumField(); i += 1 {
		got = append(got, entryType.Field(i).Name)
	}
	if !slices.Equal(got, fields) {
		t.Errorf("gkm-9's line holds %v, want %v", got, fields)
	}
}

// The rate counters spend a key's count at once, refill over the interval, and stay within their bound.
func TestGkmRateCountersRefillAndStayBounded(t *testing.T) {
	counters := newGkmRateCounters(4)
	rate := GkmRate{Count: 2, Interval: time.Minute}
	start := time.Unix(1_700_000_000, 0)
	for i, want := range []bool{true, true, false} {
		if got := counters.Allow(rate, "a", start); got != want {
			t.Errorf("event %d: %v", i, got)
		}
	}
	if !counters.Allow(rate, "a", start.Add(30*time.Second)) {
		t.Error("half the interval refills one")
	}
	if counters.Allow(rate, "a", start.Add(30*time.Second)) {
		t.Error("and only one")
	}
	for i := 0; i < 16; i += 1 {
		counters.Allow(rate, "key-"+strconv.Itoa(i), start)
	}
	if 4 < counters.entryCount() {
		t.Errorf("%d entries past a bound of 4", counters.entryCount())
	}
	if counters.Allow(GkmRate{}, "b", start) {
		t.Error("a rate that cannot be met admitted an event")
	}
}

// The settings refuse what the design cannot take.
func TestGkmServiceSettingsRefusePastTheDesignsBounds(t *testing.T) {
	if err := DefaultGkmServiceSettings().Validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	settings := DefaultGkmServiceSettings()
	if settings.RepoCacheMaxTtl != 5*time.Second {
		t.Errorf("§10.6's repo/ bound defaults to %s", settings.RepoCacheMaxTtl)
	}
	settings.RepoCacheTtl = 6 * time.Second
	if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
		t.Errorf("repo/ cached 6 s: %v", err)
	}
	// the bound holds every cache under it, and a lower bound holds them lower
	for _, adjust := range []func(settings *GkmServiceSettings){
		func(settings *GkmServiceSettings) { settings.FormCacheTtl = 6 * time.Second },
		func(settings *GkmServiceSettings) { settings.GroupInfoCacheTtl = 6 * time.Second },
		func(settings *GkmServiceSettings) { settings.RepoCacheMaxTtl = 4 * time.Second },
		func(settings *GkmServiceSettings) { settings.RepoCacheMaxTtl = 0 },
	} {
		settings = DefaultGkmServiceSettings()
		adjust(settings)
		if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
			t.Errorf("a cache past its bound, or no bound: %v", err)
		}
	}
	settings = DefaultGkmServiceSettings()
	settings.RepoCacheMaxTtl = 4 * time.Second
	settings.RepoCacheTtl, settings.FormCacheTtl, settings.GroupInfoCacheTtl = 4*time.Second, 4*time.Second, 4*time.Second
	if err := settings.Validate(); err != nil {
		t.Errorf("caches at a lower bound: %v", err)
	}
	settings = DefaultGkmServiceSettings()
	settings.KeyPackageClaimRate = GkmRate{Count: 10}
	if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
		t.Errorf("a rate with no interval: %v", err)
	}
	settings = DefaultGkmServiceSettings()
	settings.KeyPackageLowCount = 129
	if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
		t.Errorf("a refill point past the count: %v", err)
	}
}

// §22.7, D-REPO-3: gkmservice imports no server, go-redis, minio-go or Postgres driver, directly or through this
// module's packages, and not evsservice (CONTRACTS.md C-14), so server/cli/gkm links none of them through it.
func TestGkmServiceImportsNoServerRedisMinioOrPostgres(t *testing.T) {
	refused := []string{
		"github.com/urnetwork/server",
		"github.com/redis/go-redis",
		"github.com/go-redis/redis",
		"github.com/minio/minio-go",
		"github.com/jackc/pgx",
		"github.com/lib/pq",
		"database/sql",
		"github.com/urnetwork/sidecar/evsservice",
		"github.com/urnetwork/sidecar/sidecartest",
	}
	const modulePath = "github.com/urnetwork/sidecar"
	seen := map[string]bool{}
	pending := []string{"github.com/urnetwork/sidecar/gkmservice"}
	for 0 < len(pending) {
		importPath := pending[0]
		pending = pending[1:]
		if seen[importPath] {
			continue
		}
		seen[importPath] = true
		relative := strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/")
		dir := filepath.Join("..", filepath.FromSlash(relative))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, prefix := range refused {
					if imported == prefix || strings.HasPrefix(imported, prefix+"/") {
						t.Errorf("%s/%s imports %s", importPath, name, imported)
					}
				}
				if imported == modulePath || strings.HasPrefix(imported, modulePath+"/") {
					pending = append(pending, imported)
				}
			}
		}
	}
	if !seen[modulePath] {
		t.Error("the walk never reached the root, so it proved nothing of it")
	}
}
