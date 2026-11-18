// A repo's groups step before its re-seed (evs_reseed.go's ReseedPlace; §19.10's groups row; QD-1062): the place, the
// re-form and the activation in that order for a live repo; for a repo this device's verified state shows deleted,
// the place and the re-form of its form and ladder alone, never an activation; nothing sent for a repo shredded by a
// RepoDelete with now or one the state does not hold; and evs's answers to the place, 409 SHREDDING and 409
// REPO_PLACED. The step against evsservice's route, with the walk after it, is sidecartest's
// (evs_reseed_deleted_world_test.go).

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One groups step's world: evs as a handler that records each route and answers the place as set, a verified state
// holding the repo's row, and a re-form that records what it was asked.
type evsReseedPlaceTest struct {
	t      *testing.T
	repoId Id
	client *evsTestClient
	config *evsTestConfig

	stateLock sync.Mutex
	// each request evs got, and each re-form asked after how many of them
	routes  []string
	reforms []*GkmReformArgs
	// evs's refusal of the place, the zero code for 200
	placeCode protocol.EvsRefusalCode
	reformErr error
}

func newEvsReseedPlaceTest(t *testing.T, deletion *protocol.AclRepoDeletionRow) *evsReseedPlaceTest {
	t.Helper()
	repoId := evsTestId("placed repo")
	test := &evsReseedPlaceTest{
		t:      t,
		repoId: repoId,
		config: &evsTestConfig{repo: &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Deletion: deletion}},
	}
	test.client = newEvsTestClient(t, test, newEvsTestStore(t))
	test.client.client.args.Config = func() GkmAuthView { return test.config }
	return test
}

func (self *evsReseedPlaceTest) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(self.routes, request.Method+" "+request.URL.Path)
	if request.Method == http.MethodPut && self.placeCode != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: self.placeCode})
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
		if placed.Deleted || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
			t.Errorf("%s: placed %+v", c.what, placed)
		}
		repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
		if got, want := test.asked(), "PUT "+repoPath+",reform,POST "+repoPath+"/activate"; got != want {
			t.Errorf("%s: asked %s, want %s", c.what, got, want)
		}
		if len(test.reforms) != 1 || test.reforms[0].RepoId != test.repoId || test.reforms[0].Reseed {
			t.Errorf("%s: re-forms %+v", c.what, test.reforms)
		}
	}
}

// A repo the state shows deleted, its RepoDelete unrestored and without now, is placed, its group's form and ladder
// re-formed with Reseed, and never activated.
func TestEvsReseedPlaceNeverActivatesARepoReseededAsDeleted(t *testing.T) {
	test := newEvsReseedPlaceTest(t, &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7})
	placed, err := test.place()
	if err != nil {
		t.Fatal(err)
	}
	if !placed.Deleted || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
		t.Errorf("placed %+v", placed)
	}
	if got, want := test.asked(), "PUT /evs/v1/repos/"+evsUrlId(test.repoId)+",reform"; got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if len(test.reforms) != 1 || test.reforms[0].RepoId != test.repoId || !test.reforms[0].Reseed {
		t.Errorf("re-forms %+v", test.reforms)
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
// leaves the re-form and the activation to that device.
func TestEvsReseedPlaceStopsAtEvsRefusalOfThePlace(t *testing.T) {
	past := newEvsReseedPlaceTest(t, &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7})
	past.placeCode = protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING
	placed, err := past.place()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING) || placed != nil {
		t.Errorf("past restoring: %+v, %v", placed, err)
	}
	if got, want := past.asked(), "PUT /evs/v1/repos/"+evsUrlId(past.repoId); got != want {
		t.Errorf("past restoring asked %s, want %s", got, want)
	}

	for _, deletion := range []*protocol.AclRepoDeletionRow{nil, {DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7}} {
		other := newEvsReseedPlaceTest(t, deletion)
		other.placeCode = protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED
		placed, err := other.place()
		if err != nil || placed == nil || !placed.PlacedByAnother || placed.Deleted != (deletion != nil) || placed.GroupId != (Id{}) {
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
	test.routes = nil
	test.reformErr = ErrGkmWait
	if placed, err := test.place(); !errors.Is(err, ErrGkmWait) || placed == nil || test.asked() != "PUT "+repoPath+",reform" {
		t.Fatalf("a re-form that fails: %+v, %v, asked %s", placed, err, test.asked())
	}
	test.routes, test.reforms, test.reformErr = nil, nil, nil
	test.client.client.args.Gkm = &evsReseedPlaceTestReformer{test: test}
	placed, err = repo.ReseedPlace(context.Background(), nil)
	if err != nil || placed.GroupId != evsTestId("re-formed group") || test.asked() != "PUT "+repoPath+",reform,POST "+repoPath+"/activate" {
		t.Fatalf("through the key client: %+v, %v, asked %s", placed, err, test.asked())
	}
}
