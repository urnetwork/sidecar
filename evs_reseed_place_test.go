// A repo's groups step before its re-seed (evs_reseed.go's ReseedPlace; §19.10's groups row; QD-1062, QD-1064,
// QD-1076, QD-1077): for a live repo, the place, the re-form's form and ladder, the activation, and only then the
// re-form's rotation and Adds, which gkm takes for an active repo/ alone; for a restored repo, a restore between the
// place and the re-form, whose 409 REPO_KEYING is the one refused call the honest order costs, or which takes a repo/
// the place created deleted to active, waiting out a projection that trails this device's state; for a repo this
// device's verified state shows deleted, the place, the re-form of its form and ladder alone and an activate whose 409
// REPO_DELETED is the one refused call the honest order costs, or, where the place created repo/ keying, an activate
// that answers 200 and a DELETE of no statement of its own that takes repo/ to deleted, waiting out a projection that
// trails this device's state; nothing sent for a repo shredded by a RepoDelete with now or one the state does not
// hold; and evs's answers to the place, 409 SHREDDING and 409 REPO_PLACED. The step against evsservice's routes, with
// the walk after it, is sidecartest's (evs_reseed_deleted_world_test.go, evs_reseed_mend_world_test.go,
// evs_reseed_restored_world_test.go), and the step with GkmGroupClient's own re-form, its members returning, is
// evs_reseed_reform_test.go's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
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
// a verified state holding the repo's row, and a re-form that records what it was asked and holds its rotation to
// repo/'s state as gkm does.
type evsReseedPlaceTest struct {
	t      *testing.T
	repoId Id
	client *evsTestClient
	config *evsTestConfig

	stateLock sync.Mutex
	// each request evs got, its method and path with any query, and each re-form, "reform reseed" for the form, epoch
	// 0 and the ladder alone and "reform" for the whole re-form or its resume, in order
	routes  []string
	reforms []*GkmReformArgs
	// each refusal evs answered: the request and its code
	refusals []string
	// evs's refusal of the place, the zero code for 200
	placeCode protocol.EvsRefusalCode
	// what every re-form answers in place of its group, and what the rotation answers once repo/ is active
	reformErr error
	rotateErr error
	// what the place creates, and repo/'s state since, unspecified before the place
	created   protocol.EvsRepoState
	repoState protocol.EvsRepoState
	// gkm holds the repo's newest GroupForm and its group's gen/1, which a re-form writes first
	groupReady bool
	// the DELETEs and restores still to be answered 409 STATEMENT_MISSING, evs's projection not yet holding the
	// RepoDelete or the RepoRestore
	deleteMissingCount  int
	restoreMissingCount int
}

// A world whose verified state holds the repo's row with deletion. The place creates repo/ keying, or deleted for an
// unrestored, dated RepoDelete without now, as evs does with its reseed gate on and the statements in its projection.
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
// stands; activate takes keying to active once gkm holds the GroupForm and gen/1, answers active 200 and deleted 409
// REPO_DELETED; restore, once the projection holds the RepoRestore, takes deleted to active, answers active 200 and
// keying 409 REPO_KEYING; DELETE, once the projection holds the RepoDelete, takes active to deleted, answers deleted
// 200 and keying 409 REPO_KEYING.
func (self *evsReseedPlaceTest) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := request.Method + " " + request.URL.RequestURI()
	self.routes = append(self.routes, asked)
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
				if !self.groupReady {
					return protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY
				}
				self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
			case protocol.EvsRepoState_EVS_REPO_DELETED:
				return protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED
			}
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/restore"):
			if 0 < self.restoreMissingCount {
				self.restoreMissingCount -= 1
				return protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING
			}
			switch self.repoState {
			case protocol.EvsRepoState_EVS_REPO_DELETED:
				self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
			case protocol.EvsRepoState_EVS_REPO_KEYING:
				return protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING
			}
		case request.Method == http.MethodDelete:
			if 0 < self.deleteMissingCount {
				self.deleteMissingCount -= 1
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
		self.refusals = append(self.refusals, asked+" "+code.String())
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code})
		writer.WriteHeader(http.StatusConflict)
		writer.Write(body)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

// The re-form the step is given, recorded in the order of evs's requests, as gkm takes it (§10.6's checks row): the
// form, epoch 0 and the ladder land, which activate then finds, and a call without Reseed goes on to the rotation's
// generation claim and the Adds' commits, which gkm refuses while repo/ reads anything but active, as
// GkmGroupClient's claim answers gkm's 403. It answers a group id, or the error set.
func (self *evsReseedPlaceTest) reformGroup(ctx context.Context, args *GkmReformArgs) (Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reforms = append(self.reforms, args)
	if args.Reseed {
		self.routes = append(self.routes, "reform reseed")
	} else {
		self.routes = append(self.routes, "reform")
	}
	if self.reformErr != nil {
		return Id{}, self.reformErr
	}
	self.groupReady = true
	if args.Reseed {
		return evsTestId("re-formed group"), nil
	}
	if self.repoState != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		return Id{}, fmt.Errorf("%w: gkm refused the claim of the re-form's rotation, repo/ %s", ErrGkmWait, self.repoState)
	}
	if self.rotateErr != nil {
		return Id{}, self.rotateErr
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

// The refusals evs answered, in order.
func (self *evsReseedPlaceTest) refused() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.refusals)
}

// Forgets what was asked and refused, for the step run again.
func (self *evsReseedPlaceTest) forget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes, self.reforms, self.refusals = nil, nil, nil
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

// A RepoDelete this device's state shows with a RepoRestore of it.
func evsReseedPlaceTestRestoredDeletion() *protocol.AclRepoDeletionRow {
	return &protocol.AclRepoDeletionRow{DeletionId: evsTestId("deletion").Bytes(), DeletedAt: 7, RestoredAt: 9}
}

// A repo never deleted, which evs places keying (owner decision 618; QD-1076): the re-form's first call takes its
// form, epoch 0 and ladder alone, activate finds them and takes repo/ to active, and only then does the re-form's
// second call resume with the rotation and the Adds, which gkm takes for an active repo/ alone. Nothing is refused,
// waited for or filed.
func TestEvsReseedPlaceReFormsALiveRepoAroundItsActivate(t *testing.T) {
	test := newEvsReseedPlaceTest(t, nil)
	placed, err := test.place()
	if err != nil {
		t.Fatal(err)
	}
	if placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
		t.Errorf("placed %+v", placed)
	}
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,reform"; got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if len(test.reforms) != 2 || test.reforms[0].RepoId != test.repoId || !test.reforms[0].Reseed || test.reforms[1].RepoId != test.repoId || test.reforms[1].Reseed {
		t.Errorf("re-forms %+v", test.reforms)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %s", state)
	}
	if refused := test.refused(); len(refused) != 0 {
		t.Errorf("refused %v", refused)
	}
	if waited := test.client.clock.waited(); len(waited) != 0 {
		t.Errorf("waited %v", waited)
	}
	if filed := test.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
}

// QD-1076's failure as the step met it before: the whole re-form, sent before activate as a re-form that drops
// Reseed sends it, has its rotation's claim refused while repo/ reads keying, so the step's error is the re-form's
// and nothing activates. The step run again in its own order activates between the form and the rotation and ends
// active.
func TestEvsReseedPlaceFinishesALiveRepoTheWholeReFormLeftKeying(t *testing.T) {
	test := newEvsReseedPlaceTest(t, nil)
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	whole := func(ctx context.Context, args *GkmReformArgs) (Id, error) {
		return test.reformGroup(ctx, &GkmReformArgs{RepoId: args.RepoId})
	}
	placed, err := test.client.client.Repo(test.repoId).ReseedPlace(context.Background(), &EvsReseedPlaceArgs{ReformGroup: whole})
	if !errors.Is(err, ErrGkmWait) || placed == nil || placed.GroupId != (Id{}) {
		t.Fatalf("the whole re-form before activate: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform"; got != want {
		t.Errorf("the whole re-form before activate asked %s, want %s", got, want)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Errorf("after the whole re-form before activate repo/ %s", state)
	}

	test.forget()
	placed, err = test.place()
	if err != nil || placed.GroupId != evsTestId("re-formed group") {
		t.Fatalf("the step run again: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,reform"; got != want {
		t.Errorf("the step run again asked %s, want %s", got, want)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("after the step run again repo/ %s", state)
	}
}

// The honest order costs one refused call for each mend (owner decisions 602 and 618): a restored repo's restore,
// answered 409 REPO_KEYING since the place created repo/ keying, and a repo re-seeded as deleted's activate, answered
// 409 REPO_DELETED since the place created repo/ deleted; a repo never deleted costs none. Each ends in the state its
// verified state shows, nothing mended, waited for or filed.
func TestEvsReseedPlaceCostsTheHonestOrderOneRefusedCallEach(t *testing.T) {
	for _, c := range []struct {
		what     string
		deletion *protocol.AclRepoDeletionRow
		// what evs and the re-form were asked and what evs refused, {repo} standing for the repo's path
		asked   []string
		refused []string
		state   protocol.EvsRepoState
	}{
		{
			what:  "a repo never deleted",
			asked: []string{"PUT {repo}", "reform reseed", "POST {repo}/activate", "reform"},
			state: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		},
		{
			what:     "a restored repo",
			deletion: evsReseedPlaceTestRestoredDeletion(),
			asked:    []string{"PUT {repo}", "POST {repo}/restore", "reform reseed", "POST {repo}/activate", "reform"},
			refused:  []string{"POST {repo}/restore EVS_REFUSAL_REPO_KEYING"},
			state:    protocol.EvsRepoState_EVS_REPO_ACTIVE,
		},
		{
			what:     "a repo re-seeded as deleted",
			deletion: evsReseedPlaceTestDeletion(),
			asked:    []string{"PUT {repo}", "reform reseed", "POST {repo}/activate"},
			refused:  []string{"POST {repo}/activate EVS_REFUSAL_REPO_DELETED"},
			state:    protocol.EvsRepoState_EVS_REPO_DELETED,
		},
	} {
		test := newEvsReseedPlaceTest(t, c.deletion)
		repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
		withPath := func(requests []string) []string {
			named := []string{}
			for _, request := range requests {
				named = append(named, strings.ReplaceAll(request, "{repo}", repoPath))
			}
			return named
		}
		placed, err := test.place()
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if placed.Mended || placed.Deleted != (c.state == protocol.EvsRepoState_EVS_REPO_DELETED) || placed.GroupId != evsTestId("re-formed group") {
			t.Errorf("%s: placed %+v", c.what, placed)
		}
		if got, want := test.asked(), strings.Join(withPath(c.asked), ","); got != want {
			t.Errorf("%s: asked %s, want %s", c.what, got, want)
		}
		if got, want := test.refused(), withPath(c.refused); !slices.Equal(got, want) {
			t.Errorf("%s: refused %v, want %v", c.what, got, want)
		}
		if state := test.state(); state != c.state {
			t.Errorf("%s: repo/ %s", c.what, state)
		}
		if waited := test.client.clock.waited(); len(waited) != 0 {
			t.Errorf("%s: waited %v", c.what, waited)
		}
		if filed := test.filed(); len(filed) != 0 {
			t.Errorf("%s: filed %v", c.what, filed)
		}
	}
}

// A restored repo whose repo/ the place created deleted, evs's projection trailing the RepoRestore this device's state
// shows (owner decision 618; QD-1077): the restore, with no query and no statement filed, is answered 409
// STATEMENT_MISSING and asked again after ReseedDeleteWait until the projection holds the RepoRestore, then takes
// repo/ to active, before the re-form; the step then re-forms around its activate, which answers the active repo/ 200,
// and ends active, every call asking admin alone.
func TestEvsReseedPlaceRestoresARestoredRepoPlacedDeleted(t *testing.T) {
	test := newEvsReseedPlaceTest(t, evsReseedPlaceTestRestoredDeletion())
	test.created = protocol.EvsRepoState_EVS_REPO_DELETED
	test.restoreMissingCount = 2
	test.client.client.settings.ReseedDeleteWait = 3 * time.Second
	test.client.client.settings.ReseedDeleteWaitCount = 4
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	placed, err := test.place()
	if err != nil {
		t.Fatal(err)
	}
	if placed.Deleted || !placed.Mended || placed.PlacedByAnother || placed.GroupId != evsTestId("re-formed group") {
		t.Errorf("placed %+v", placed)
	}
	restore := "POST " + repoPath + "/restore"
	want := strings.Join([]string{"PUT " + repoPath, restore, restore, restore, "reform reseed", "POST " + repoPath + "/activate", "reform"}, ",")
	if got := test.asked(); got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if got, want := test.refused(), []string{restore + " EVS_REFUSAL_STATEMENT_MISSING", restore + " EVS_REFUSAL_STATEMENT_MISSING"}; !slices.Equal(got, want) {
		t.Errorf("refused %v, want %v", got, want)
	}
	if waited := test.client.clock.waited(); !slices.Equal(waited, []time.Duration{3 * time.Second, 3 * time.Second}) {
		t.Errorf("waited %v", waited)
	}
	if len(test.reforms) != 2 || !test.reforms[0].Reseed || test.reforms[1].Reseed {
		t.Errorf("re-forms %+v", test.reforms)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %s", state)
	}
	if filed := test.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
	adminScope := []string{evsRepoScope(test.repoId, evsScopeAdmin)}
	scopes := test.scopes()
	if len(scopes) != 5 {
		t.Errorf("%d tokens for 5 calls", len(scopes))
	}
	for _, asked := range scopes {
		if !slices.Equal(asked, adminScope) {
			t.Errorf("a call asked for %v", asked)
		}
	}
}

// A projection that trails the RepoRestore past ReseedDeleteWaitCount waits leaves the restore's 409
// STATEMENT_MISSING the step's error, with repo/ left deleted and no group re-formed; the step run again once the
// projection holds the RepoRestore takes repo/ to active and finishes.
func TestEvsReseedPlaceStopsAtARestoreRefusedPastItsWaits(t *testing.T) {
	test := newEvsReseedPlaceTest(t, evsReseedPlaceTestRestoredDeletion())
	test.created = protocol.EvsRepoState_EVS_REPO_DELETED
	test.restoreMissingCount = 100
	test.client.client.settings.ReseedDeleteWait = 3 * time.Second
	test.client.client.settings.ReseedDeleteWaitCount = 4
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	placed, err := test.place()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING) || placed == nil || placed.Mended || placed.GroupId != (Id{}) {
		t.Fatalf("a projection behind past the waits: %+v, %v", placed, err)
	}
	requests := []string{"PUT " + repoPath}
	for range 5 {
		requests = append(requests, "POST "+repoPath+"/restore")
	}
	if got, want := test.asked(), strings.Join(requests, ","); got != want {
		t.Errorf("past the waits asked %s, want %s", got, want)
	}
	if waited := test.client.clock.waited(); len(waited) != 4 {
		t.Errorf("past the waits waited %v", waited)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Errorf("past the waits repo/ %s", state)
	}

	test.forget()
	test.stateLock.Lock()
	test.restoreMissingCount = 0
	test.stateLock.Unlock()
	placed, err = test.place()
	if err != nil || !placed.Mended || placed.Deleted {
		t.Fatalf("the step run again once the projection holds the RepoRestore: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",POST "+repoPath+"/restore,reform reseed,POST "+repoPath+"/activate,reform"; got != want {
		t.Errorf("the step run again asked %s, want %s", got, want)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("after the step run again repo/ %s", state)
	}
	if filed := test.filed(); len(filed) != 0 {
		t.Errorf("filed %v", filed)
	}
}

// A live repo whose activate evs refuses rotates nothing: here the place created repo/ deleted under a RepoDelete this
// device's state does not hold yet, so the activate's 409 REPO_DELETED is the step's error, and the re-form's second
// call, which gkm would refuse, is never asked.
func TestEvsReseedPlaceRotatesNothingWhileActivateIsRefused(t *testing.T) {
	test := newEvsReseedPlaceTest(t, nil)
	test.created = protocol.EvsRepoState_EVS_REPO_DELETED
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	placed, err := test.place()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED) || placed == nil || placed.Deleted || placed.Mended {
		t.Fatalf("an activate refused for a live repo: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate"; got != want {
		t.Errorf("asked %s, want %s", got, want)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Errorf("repo/ %s", state)
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
		if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate"; got != want {
			t.Errorf("run %d: asked %s, want %s", run, got, want)
		}
		if got, want := test.refused(), []string{"POST " + repoPath + "/activate EVS_REFUSAL_REPO_DELETED"}; !slices.Equal(got, want) {
			t.Errorf("run %d: refused %v, want %v", run, got, want)
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
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,DELETE "+repoPath; got != want {
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
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate"; got != want {
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
		requests := []string{"PUT " + repoPath, "reform reseed", "POST " + repoPath + "/activate"}
		for range count {
			requests = append(requests, "DELETE "+repoPath)
		}
		return strings.Join(requests, ",")
	}

	test := trailing()
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	test.deleteMissingCount = 2
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
	behind.deleteMissingCount = 100
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
	behind.deleteMissingCount = 0
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
// leaves the restore, the re-form, the activation and any DELETE to that device.
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

	for _, deletion := range []*protocol.AclRepoDeletionRow{nil, evsReseedPlaceTestRestoredDeletion(), evsReseedPlaceTestDeletion()} {
		other := newEvsReseedPlaceTest(t, deletion)
		other.placeCode = protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED
		placed, err := other.place()
		deleted := deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0
		if err != nil || placed == nil || !placed.PlacedByAnother || placed.Deleted != deleted || placed.Mended || placed.GroupId != (Id{}) {
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
	if placed, err := test.place(); !errors.Is(err, ErrGkmWait) || placed == nil || test.asked() != "PUT "+repoPath+",reform reseed" {
		t.Fatalf("a re-form that fails: %+v, %v, asked %s", placed, err, test.asked())
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("after a re-form that failed repo/ %s", state)
	}
	test.forget()
	test.reformErr = nil
	test.client.client.args.Gkm = &evsReseedPlaceTestReformer{test: test}
	placed, err = repo.ReseedPlace(context.Background(), nil)
	if err != nil || placed.GroupId != evsTestId("re-formed group") || test.asked() != "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,reform" {
		t.Fatalf("through the key client: %+v, %v, asked %s", placed, err, test.asked())
	}
}

// A rotation that fails once repo/ is active is the step's error, with repo/ left active and its group's form and
// ladder standing; the step run again re-forms around an activate that answers the active repo/ 200, and its second
// call finishes the group.
func TestEvsReseedPlaceRunsAgainAfterARotationThatFailed(t *testing.T) {
	test := newEvsReseedPlaceTest(t, nil)
	test.rotateErr = ErrGkmUnavailable
	repoPath := "/evs/v1/repos/" + evsUrlId(test.repoId)
	placed, err := test.place()
	if !errors.Is(err, ErrGkmUnavailable) || placed == nil || placed.GroupId != evsTestId("re-formed group") {
		t.Fatalf("a rotation that fails: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,reform"; got != want {
		t.Errorf("a rotation that fails asked %s, want %s", got, want)
	}
	if state := test.state(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("after a rotation that failed repo/ %s", state)
	}

	test.forget()
	test.stateLock.Lock()
	test.rotateErr = nil
	test.stateLock.Unlock()
	placed, err = test.place()
	if err != nil || placed.GroupId != evsTestId("re-formed group") {
		t.Fatalf("the step run again: %+v, %v", placed, err)
	}
	if got, want := test.asked(), "PUT "+repoPath+",reform reseed,POST "+repoPath+"/activate,reform"; got != want {
		t.Errorf("the step run again asked %s, want %s", got, want)
	}
	if refused := test.refused(); len(refused) != 0 {
		t.Errorf("the step run again refused %v", refused)
	}
}
