// A repo's groups step before its re-seed (evs_reseed.go's ReseedPlace; §19.10's groups row; QD-1062, QD-1064): the
// place, the re-form and the activation in that order for a live repo; for a repo this device's verified state shows
// deleted, the place, the re-form of its form and ladder alone and an activate whose 409 REPO_DELETED is the one
// refused call the honest order costs, or, where the place created repo/ keying, an activate that answers 200 and a
// DELETE of no statement of its own that takes repo/ to deleted, waiting out a projection that trails this device's
// state; nothing sent for a repo shredded by a RepoDelete with now or one the state does not hold; and evs's answers
// to the place, 409 SHREDDING and 409 REPO_PLACED. The step against evsservice's route, with the walk after it, is
// sidecartest's (evs_reseed_deleted_world_test.go, evs_reseed_mend_world_test.go).

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One groups step's world: evs as a handler that records each request and keeps repo/'s state as its routes move it,
// a verified state holding the repo's row, and a re-form that records what it was asked.
type evsReseedPlaceTest struct {
	t      *testing.T
	repoId Id
	client *evsTestClient
	config *evsTestConfig

	stateLock sync.Mutex
	// each request evs got, its method and path with any query, and "reform" for each re-form, in order
	routes  []string
	reforms []*GkmReformArgs
	// evs's refusal of the place, the zero code for 200
	placeCode protocol.EvsRefusalCode
	reformErr error
	// what the place creates, and repo/'s state since, unspecified before the place
	created   protocol.EvsRepoState
	repoState protocol.EvsRepoState
	// the DELETEs still to be answered 409 STATEMENT_MISSING, evs's projection not yet holding the RepoDelete
	missingCount int
}

// A world whose verified state holds the repo's row with deletion. The place creates repo/ keying, or deleted for an
// unrestored, dated RepoDelete without now, as evs does with its reseed gate on and the RepoDelete in its projection.
func newEvsReseedPlaceTest(t *testing.T, deletion *protocol.AclRepoDeletionRow) *evsReseedPlaceTest {
	t.Helper()
	repoId := evsTestId("placed repo")
	test := &evsReseedPlaceTest{
		t:       t,
		repoId:  repoId,
		config:  &evsTestConfig{repo: &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Deletion: deletion}},
		created: protocol.EvsRepoState_EVS_REPO_KEYING,
	}
	if deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0 && !deletion.GetNow() {
		test.created = protocol.EvsRepoState_EVS_REPO_DELETED
	}
	test.client = newEvsTestClient(t, test, newEvsTestStore(t))
	test.client.client.args.Config = func() GkmAuthView { return test.config }
	return test
}

// evs's answers, as §11.12's rows give them: the place creates repo/ as set and answers a retry by the repo/ that
// stands; activate takes keying to active, answers active 200 and deleted 409 REPO_DELETED; DELETE, once the
// projection holds the RepoDelete, takes active to deleted, answers deleted 200 and keying 409 REPO_KEYING.
func (self *evsReseedPlaceTest) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(self.routes, request.Method+" "+request.URL.RequestURI())
	answer := func() protocol.EvsRefusalCode {
		switch {
		case request.Method == http.MethodPut:
			if self.placeCode != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
				return self.placeCode
			}
			if self.repoState == protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED {
				self.repoState = self.created
			}
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/activate"):
			switch self.repoState {
			case protocol.EvsRepoState_EVS_REPO_KEYING:
				self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
			case protocol.EvsRepoState_EVS_REPO_DELETED:
				return protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED
			}
		case request.Method == http.MethodDelete:
			if 0 < self.missingCount {
				self.missingCount -= 1
				return protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING
			}
			switch self.repoState {
			case protocol.EvsRepoState_EVS_REPO_ACTIVE:
				self.repoState = protocol.EvsRepoState_EVS_REPO_DELETED
			case protocol.EvsRepoState_EVS_REPO_KEYING:
				return protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING
			}
		default:
			self.t.Errorf("a request the groups step never sends: %s %s", request.Method, request.URL.Path)
		}
		return protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
	}
	if code := answer(); code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code})
		writer.WriteHeader(http.StatusConflict)
		writer.Write(body)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

// The re-form the step is given: recorded in the order of evs's requests, answering a group id or the error set.
func (self *evsReseedPlaceTest) reformGroup(ctx context.Context, args *GkmReformArgs) (Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(self.routes, "reform")
	self.reforms = append(self.reforms, args)
	if self.reformErr != nil {
		return Id{}, self.reformErr
	}
	return evsTestId("re-formed group"), nil
}

func (self *evsReseedPlaceTest) place() (*EvsReseedPlaced, error) {
	return self.client.client.Repo(self.repoId).ReseedPlace(context.Background(), &EvsReseedPlaceArgs{ReformGroup: self.reformGroup})
}

// What evs and the re-form were asked, in order.
func (self *evsReseedPlaceTest) asked() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.routes, ",")
}

// Forgets what was asked, for the step run again.
func (self *evsReseedPlaceTest) forget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes, self.reforms = nil, nil
}

// repo/'s state as evs holds it.
func (self *evsReseedPlaceTest) state() protocol.EvsRepoState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.repoState
}

// The statements the step filed, which must be none.
func (self *evsReseedPlaceTest) filed() []string {
	poster := self.client.poster
	poster.stateLock.Lock()
	defer poster.stateLock.Unlock()
	filed := []string{}
	for _, signedType := range poster.filed {
		filed = append(filed, signedType.String())
	}
	return filed
}

// Each token scope set the step's calls asked for.
func (self *evsReseedPlaceTest) scopes() [][]string {
	tokens := self.client.tokens
	tokens.stateLock.Lock()
	defer tokens.stateLock.Unlock()
	return slices.Clone(tokens.scopes)
}

// A RepoDelete this device's state shows unrestored, dated and without now.
func evsReseedPlaceTestDeletion() *protocol.AclRepoDeletionRow {
	return &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7}
}

func TestEvsReseedPlacePlacesReFormsAndActivatesALiveRepo(t *testing.T) {
	for _, c := range []struct {
		what     string
		deletion *protocol.AclRepoDeletionRow
	}{
		{what: "a repo never deleted"},
		{what: "a restored repo", deletion: &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7, RestoredAt: 9}},
	} {
		test := newEvsReseedPlaceTest(t, c.deletion)
		placed, err := test.place()
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
			t.Errorf("%s: placed %+v", c.what, placed)
		}
		repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
		if got, want := test.asked(), "PUT "+repoPath+",reform,POST "+repoPath+"/activate"; got != want {
			t.Errorf("%s: asked %s, want %s", c.what, got, want)
		}
		if len(test.reforms) != 1 || test.reforms[0].RepoId != test.repoId || test.reforms[0].Reseed {
			t.Errorf("%s: re-forms %+v", c.what, test.reforms)
		}
		if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Errorf("%s: repo/ %s", c.what, state)
		}
	}
}

// A repo the state shows deleted, its RepoDelete unrestored and without now, which evs places with repo/ deleted, its
// projection holding the RepoDelete and its reseed gate on: its group's form and ladder re-formed with Reseed, and the
// activate it is sent answered 409 REPO_DELETED, the one refused call this honest order costs, activating, deleting,
// filing and waiting for nothing. The step run again costs the same.
func TestEvsReseedPlaceCostsARepoReseededAsDeletedOneRefusedActivate(t *testing.T) {
	test := newEvsReseedPlaceTest(t, evsReseedPlaceTestDeletion())
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	for run := 1; run <= 2; run += 1 {
		placed, err := test.place()
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if !placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
			t.Errorf("run %d: placed %+v", run, placed)
		}
		if got, want := test.asked(), "PUT "+repoPath+",reform,POST "+repoPath+"/activate"; got != want {
			t.Errorf("run %d: asked %s, want %s", run, got, want)
		}
		if len(test.reforms) != 1 || test.reforms[0].RepoId != test.repoId || !test.reforms[0].Reseed {
			t.Errorf("run %d: re-forms %+v", run, test.reforms)
		}
		if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
			t.Errorf("run %d: repo/ %s", run, state)
		}
		test.forget()
	}
	if waited := test.client.clock.waited(); len(waited) != 0 {
		t.Errorf("waited %v", waited)
	}
	if filed := test.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
}

// A repo the state shows deleted whose repo/ the place created keying, as evs does with its reseed gate off at the
// place or its projection not yet holding the RepoDelete (QD-1064): the activate answers 200, and a DELETE with no
// query and no statement filed takes repo/ from active to deleted, nothing sent between the two and no call asking
// more than admin. The step run again costs one refused activate and nothing more.
func TestEvsReseedPlaceDeletesARepoReseededAsDeletedThatWasPlacedKeying(t *testing.T) {
	test := newEvsReseedPlaceTest(t, evsReseedPlaceTestDeletion())
	test.created = protocol.EvsRepoState_EVS_REPO_KEYING
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	placed, err := test.place()
	if err != nil {
		t.Fatal(err)
	}
	if !placed.Deleted || !placed.Mended || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
		t.Errorf("placed %+v", placed)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform,POST "+repoPath+"/activate,DELETE "+repoPath; got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if len(test.reforms) != 1 || !test.reforms[0].Reseed {
		t.Errorf("re-forms %+v", test.reforms)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Errorf("repo/ %s", state)
	}
	if filed := test.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
	if waited := test.client.clock.waited(); len(waited) != 0 {
		t.Errorf("waited %v", waited)
	}
	adminScope := []string{evsRepoScope(test.repoId, evsScopeAdmin)}
	scopes := test.scopes()
	if len(scopes) != 3 {
		t.Errorf("%d tokens for 3 calls", len(scopes))
	}
	for _, asked := range scopes {
		if !slices.Equal(asked, adminScope) {
			t.Errorf("a call asked for %v", asked)
		}
	}

	test.forget()
	placed, err = test.place()
	if err != nil || !placed.Deleted || placed.Mended {
		t.Fatalf("the step run again: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform,POST "+repoPath+"/activate"; got != want {
		t.Errorf("the step run again asked %s, want %s", got, want)
	}
}

// A projection that trails this device's state is waited out (QD-1064): DELETE answered 409 STATEMENT_MISSING is
// asked again after ReseedDeleteWait each time until evs holds the RepoDelete. One trailing past ReseedDeleteWaitCount
// waits is the step's error with repo/ left active, and the step run again once the projection holds it takes repo/
// to deleted.
func TestEvsReseedPlaceWaitsOutATrailingProjection(t *testing.T) {
	trailing := func() *evsReseedPlaceTest {
		test := newEvsReseedPlaceTest(t, evsReseedPlaceTestDeletion())
		test.created = protocol.EvsRepoState_EVS_REPO_KEYING
		test.client.client.settings.ReseedDeleteWait = 3 * time.Second
		test.client.client.settings.ReseedDeleteWaitCount = 4
		return test
	}
	deletes := func(repoPath string, count int) string {
		requests := []string{"PUT " + repoPath, "reform", "POST " + repoPath + "/activate"}
		for range count {
			requests = append(requests, "DELETE "+repoPath)
		}
		return strings.Join(requests, ",")
	}

	test := trailing()
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	test.missingCount = 2
	placed, err := test.place()
	if err != nil || !placed.Deleted || !placed.Mended {
		t.Fatalf("a projection two answers behind: %+v, %v", placed, err)
	}
	if got, want := test.asked(), deletes(repoPath, 3); got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if waited := test.client.clock.waited(); !slices.Equal(waited, []time.Duration{3 * time.Second, 3 * time.Second}) {
		t.Errorf("waited %v", waited)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Errorf("repo/ %s", state)
	}

	behind := trailing()
	behind.missingCount = 100
	placed, err = behind.place()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING) || placed == nil || !placed.Deleted || placed.Mended {
		t.Fatalf("a projection behind past the waits: %+v, %v", placed, err)
	}
	if got, want := behind.asked(), deletes(repoPath, 5); got != want {
		t.Errorf("past the waits asked %s, want %s", got, want)
	}
	if waited := behind.client.clock.waited(); len(waited) != 4 {
		t.Errorf("past the waits waited %v", waited)
	}
	if state := behind.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("past the waits repo/ %s", state)
	}
	behind.forget()
	behind.stateLock.Lock()
	behind.missingCount = 0
	behind.stateLock.Unlock()
	placed, err = behind.place()
	if err != nil || !placed.Deleted || !placed.Mended {
		t.Fatalf("the step run again once the projection holds the RepoDelete: %+v, %v", placed, err)
	}
	if got, want := behind.asked(), deletes(repoPath, 1); got != want {
		t.Errorf("the step run again asked %s, want %s", got, want)
	}
	if state := behind.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Errorf("after the step run again repo/ %s", state)
	}
	if filed := behind.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
}

// Nothing is sent for a repo no re-seed returns, by this device's own state: one a RepoDelete with now shredded,
// which evs's projection may still list live, and one the state does not hold; nor with no verified state at all.
func TestEvsReseedPlaceSendsNothingForARepoItsStateShowsGone(t *testing.T) {
	shredded := newEvsReseedPlaceTest(t, &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7, Now: true})
	if placed, err := shredded.place(); !errors.Is(err, ErrEvsReseedNotRestorable) || placed != nil || shredded.asked() != "" {
		t.Errorf("a RepoDelete with now: %+v, %v, asked %q", placed, err, shredded.asked())
	}
	unknown := newEvsReseedPlaceTest(t, nil)
	unknown.config.repo = nil
	if placed, err := unknown.place(); !errors.Is(err, ErrEvsReseedNotRestorable) || placed != nil || unknown.asked() != "" {
		t.Errorf("a repo the state does not hold: %+v, %v, asked %q", placed, err, unknown.asked())
	}
	unverified := newEvsReseedPlaceTest(t, nil)
	unverified.client.client.args.Config = func() GkmAuthView { return nil }
	if _, err := unverified.place(); !errors.Is(err, ErrEvsNoConfig) || unverified.asked() != "" {
		t.Errorf("no verified state: %v, asked %q", err, unverified.asked())
	}
	unverified.client.client.args.Config = nil
	if _, err := unverified.place(); !errors.Is(err, ErrEvsNoConfig) || unverified.asked() != "" {
		t.Errorf("no config: %v, asked %q", err, unverified.asked())
	}
}

// evs's answers to the place: a repo past its restore window is refused 409 SHREDDING, the step's error, with no
// group re-formed and nothing activated; 409 REPO_PLACED says another admin's device placed it, which is no error and
// leaves the re-form, the activation and any DELETE to that device.
func TestEvsReseedPlaceStopsAtEvsRefusalOfThePlace(t *testing.T) {
	past := newEvsReseedPlaceTest(t, evsReseedPlaceTestDeletion())
	past.placeCode = protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING
	placed, err := past.place()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING) || placed != nil {
		t.Errorf("past restoring: %+v, %v", placed, err)
	}
	if got, want := past.asked(), "PUT /evs/v1/repos/"+evsUrlId(past.repoId); got != want {
		t.Errorf("past restoring asked %s, want %s", got, want)
	}

	for _, deletion := range []*protocol.AclRepoDeletionRow{nil, evsReseedPlaceTestDeletion()} {
		other := newEvsReseedPlaceTest(t, deletion)
		other.placeCode = protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED
		placed, err := other.place()
		if err != nil || placed == nil || !placed.PlacedByAnother || placed.Deleted != (deletion != nil) || placed.Mended || placed.GroupId != (Id{}) {
			t.Errorf("placed by another: %+v, %v", placed, err)
		}
		if got, want := other.asked(), "PUT /evs/v1/repos/"+evsUrlId(other.repoId); got != want {
			t.Errorf("placed by another asked %s, want %s", got, want)
		}
	}
}

// A key client that re-forms groups, as GkmGroupClient does.
type evsReseedPlaceTestReformer struct {
	gkmRefusingClient
	test *evsReseedPlaceTest
}

func (self *evsReseedPlaceTestReformer) ReformGroup(ctx context.Context, args *GkmReformArgs) (Id, error) {
	return self.test.reformGroup(ctx, args)
}

// With no re-form given, the step re-forms through the client's key client where that re-forms groups, and where it
// does not it stops after the place, activating nothing; a re-form that fails activates nothing either, and the step
// run again goes through whole.
func TestEvsReseedPlaceActivatesNothingWithoutItsGroup(t *testing.T) {
	test := newEvsReseedPlaceTest(t, nil)
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	repo := test.client.client.Repo(test.repoId)
	// the test client's key client re-forms nothing
	placed, err := repo.ReseedPlace(context.Background(), nil)
	if !errors.Is(err, ErrGkmUnavailable) || placed == nil || placed.GroupId != (Id{}) || test.asked() != "PUT "+repoPath {
		t.Fatalf("a key client that re-forms nothing: %+v, %v, asked %s", placed, err, test.asked())
	}
	test.forget()
	test.reformErr = ErrGkmWait
	if placed, err := test.place(); !errors.Is(err, ErrGkmWait) || placed == nil || test.asked() != "PUT "+repoPath+",reform" {
		t.Fatalf("a re-form that fails: %+v, %v, asked %s", placed, err, test.asked())
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("after a re-form that failed repo/ %s", state)
	}
	test.forget()
	test.reformErr = nil
	test.client.client.args.Gkm = &evsReseedPlaceTestReformer{test: test}
	placed, err = repo.ReseedPlace(context.Background(), nil)
	if err != nil || placed.GroupId != evsTestId("re-formed group") || test.asked() != "PUT "+repoPath+",reform,POST "+repoPath+"/activate" {
		t.Fatalf("through the key client: %+v, %v, asked %s", placed, err, test.asked())
	}
}
