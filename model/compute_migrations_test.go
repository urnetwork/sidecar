package model

// The compute groups' registry (CSRV-M12-02, CONTRACTS C-30): a part registers once, from a group's own owner, with
// statements alone, and reads back as registered.

import (
	"context"
	"testing"

	operator "github.com/urnetwork/operator-core"
)

// A part reads back as registered, a copy, and an owner with none reads empty; every refusal panics and registers
// nothing.
func TestComputeMigrationPartsRegisterOnce(t *testing.T) {
	saved := computeMigrationParts
	t.Cleanup(func() { computeMigrationParts = saved })
	computeMigrationParts = map[string]map[string][]*operator.Migration{}

	step := &operator.Migration{Id: "compute_provider", Sql: "CREATE TABLE compute_provider_test (id uuid NOT NULL)"}
	RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerProv, []*operator.Migration{step})
	part := ComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerProv)
	if len(part) != 1 || part[0] != step {
		t.Fatalf("PROV's part reads %v", part)
	}
	part[0] = nil
	if ComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerProv)[0] != step {
		t.Fatal("a reader's copy changed the registry")
	}
	if part := ComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerBal); len(part) != 0 {
		t.Fatalf("BAL's unregistered part reads %v", part)
	}
	if owners := ComputeMigrationGroupOwners(ComputeMigrationGroupC2); len(owners) != 3 || owners[0] != ComputeMigrationOwnerProv || owners[2] != ComputeMigrationOwnerSrch {
		t.Fatalf("MG-C2's owners are %v", owners)
	}

	code := &operator.Migration{Id: "data", Code: func(ctx context.Context, db operator.Db) error { return nil }}
	for label, register := range map[string]func(){
		"another group's owner": func() { RegisterComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerEnc, nil) },
		"no group":              func() { RegisterComputeMigrationPart("MG-C9", ComputeMigrationOwnerBal, nil) },
		"twice":                 func() { RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerProv, nil) },
		"a step with no id": func() {
			RegisterComputeMigrationPart(ComputeMigrationGroupC3, ComputeMigrationOwnerEnc, []*operator.Migration{{Sql: "SELECT 1"}})
		},
		"a data step": func() {
			RegisterComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerBal, []*operator.Migration{code})
		},
		"an id twice": func() {
			RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerGamma, []*operator.Migration{step, step})
		},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
	for _, owner := range []string{ComputeMigrationOwnerBal, ComputeMigrationOwnerGamma, ComputeMigrationOwnerEnc} {
		for _, group := range []string{ComputeMigrationGroupC1, ComputeMigrationGroupC2, ComputeMigrationGroupC3} {
			if part := ComputeMigrationPart(group, owner); len(part) != 0 {
				t.Errorf("a refused registration left %s's part of %s", owner, group)
			}
		}
	}
}
