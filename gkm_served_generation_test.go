// The rows a served gen/<g> stands under (gkm_served_generation.go), which evs's resolution and the Forwarder share:
// the group's own statement, a ladder's carried under the GroupForm that makes the group, and each refusal of one no
// such form carries.

package sidecar

import (
	"errors"
	"testing"
)

// The group's own statement stands with no form read; a statement of another group stands only under the form that
// makes the group read in, re-forming another at a generation of g or more, and naming the repo, the form being read
// only for it; anything else is malformed.
func TestAServedGenerationStandsOwnOrCarriedUnderTheFormThatMakesItsGroup(t *testing.T) {
	world := newTestForwarderWorld(t)
	repoId := world.net.configRepoId()
	oldGroupId, groupId := world.groupId, testConfigId("re-formed group")
	identityKey := GkmIdentityKeys(world.net.log.State())
	own := testConfigMarshal(t, world.genRotateIn(groupId, repoId, 3))
	carried := testConfigMarshal(t, world.genRotateIn(oldGroupId, repoId, 2))
	ofAnotherRepo := testConfigMarshal(t, world.genRotateIn(oldGroupId, testConfigId("another repo"), 2))
	form := &GkmGroupFormFacts{GroupId: groupId, PreviousGroupId: oldGroupId, Generation: 2}
	cases := []struct {
		name        string
		objectBytes []byte
		generation  uint64
		form        *GkmGroupFormFacts
		// the group the statement that stands names, zero for a refusal
		namedGroupId Id
		formAsked    bool
	}{
		{name: "own", objectBytes: own, generation: 3, namedGroupId: groupId},
		{name: "own at another generation", objectBytes: own, generation: 4},
		{name: "carried under the form", objectBytes: carried, generation: 2, form: form, namedGroupId: oldGroupId, formAsked: true},
		{name: "carried with no form", objectBytes: carried, generation: 2, formAsked: true},
		{name: "carried under a creation's form", objectBytes: carried, generation: 2, form: &GkmGroupFormFacts{GroupId: groupId, Generation: 2}, formAsked: true},
		{
			name: "carried under another group's form", objectBytes: carried, generation: 2, formAsked: true,
			form: &GkmGroupFormFacts{GroupId: testConfigId("another group"), PreviousGroupId: oldGroupId, Generation: 2},
		},
		{
			name: "carried past the form's generation", objectBytes: carried, generation: 2, formAsked: true,
			form: &GkmGroupFormFacts{GroupId: groupId, PreviousGroupId: oldGroupId, Generation: 1},
		},
		{name: "carried of another repo", objectBytes: ofAnotherRepo, generation: 2, form: form, formAsked: true},
	}
	for _, c := range cases {
		asked := false
		parsed, err := GkmParseServedGeneration(c.objectBytes, repoId, groupId, c.generation, func() (*GkmGroupFormFacts, error) {
			asked = true
			return c.form, nil
		}, identityKey)
		if asked != c.formAsked {
			t.Errorf("%s: the form was asked for %t", c.name, asked)
		}
		if c.namedGroupId == (Id{}) {
			if !errors.Is(err, ErrGkmMalformed) {
				t.Errorf("%s: %v, want a malformed refusal", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if namedGroupId, err := IdFromBytes(parsed.Rotate.GetGroupId()); err != nil || namedGroupId != c.namedGroupId || parsed.Rotate.GetGeneration() != c.generation {
			t.Errorf("%s: stood as gen/%d of %s", c.name, parsed.Rotate.GetGeneration(), namedGroupId)
		}
	}
}
