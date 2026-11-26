// The compute migration groups' parts (DESIGN-COMPUTE §14.4; CONTRACTS C-30): MG-C1, the ledger, BAL's; MG-C2, the
// providers, PROV's, GAMMA's and SRCH's, in §14.4's order; MG-C3, the enclaves, ENC's. Each owner registers its part
// from its own file in this package, at init, through RegisterComputeMigrationPart, and server's migration groups
// (server/db_migrations_sidecar_pending.go, CSRV-M12-02) read every part through ComputeMigrationPart, so no owner
// edits server's group files. server imports this package, so every registration has run before server's migrations
// slice is built: a part registered from any other package would not be, and is refused nowhere but in its absence.
//
// A part's steps are statements alone, each an operator-core Migration with an id and Sql: server's runner applies a
// statement as its own, one transaction each, and a data step waits for the review phase's move of sidecar's schema to
// operator-core's Extension (DESIGN §4.5, D-REPO-3), so a Code step is refused at registration. Every step is additive
// and works with the release running when it applies (connect/CODESTYLE.md's migration rules), which server's
// TestSidecarGroupsAreAdditive holds each group to; a group's steps never change once its Gn-out registers it.
//
// The registry is written at init and read once by server's migrations slice, so nothing guards it beyond that order.

package model

import (
	"fmt"
	"slices"

	operator "github.com/urnetwork/operator-core"
)

// §14.4's compute groups, by name.
const (
	ComputeMigrationGroupC1 = "MG-C1"
	ComputeMigrationGroupC2 = "MG-C2"
	ComputeMigrationGroupC3 = "MG-C3"
)

// The areas that own a part, by their plan's code.
const (
	ComputeMigrationOwnerBal   = "BAL"
	ComputeMigrationOwnerProv  = "PROV"
	ComputeMigrationOwnerInfer = "INFER"
	ComputeMigrationOwnerGamma = "GAMMA"
	ComputeMigrationOwnerSrch  = "SRCH"
	ComputeMigrationOwnerEnc   = "ENC"
)

// Each group's owners, in the order their parts apply.
var computeMigrationGroupOwners = map[string][]string{
	ComputeMigrationGroupC1: {ComputeMigrationOwnerBal},
	ComputeMigrationGroupC2: {ComputeMigrationOwnerProv, ComputeMigrationOwnerInfer, ComputeMigrationOwnerGamma, ComputeMigrationOwnerSrch},
	ComputeMigrationGroupC3: {ComputeMigrationOwnerEnc},
}

// The registered parts, by group and owner.
var computeMigrationParts = map[string]map[string][]*operator.Migration{}

// The owners of group, in the order their parts apply; nil for no compute group.
func ComputeMigrationGroupOwners(group string) []string {
	return slices.Clone(computeMigrationGroupOwners[group])
}

// Registers owner's part of group, from the owner's file at init. A group or owner §14.4 does not name, a part
// registered twice, a step without an id or with Code, and an id used twice in the part each panic: a build that
// registers wrongly does not start.
func RegisterComputeMigrationPart(group string, owner string, migrations []*operator.Migration) {
	if !slices.Contains(computeMigrationGroupOwners[group], owner) {
		panic(fmt.Errorf("compute migrations: %s holds no part of %s", group, owner))
	}
	if _, registered := computeMigrationParts[group][owner]; registered {
		panic(fmt.Errorf("compute migrations: %s's part of %s registered twice", owner, group))
	}
	ids := map[string]bool{}
	for _, migration := range migrations {
		if err := migration.Validate(); err != nil {
			panic(fmt.Errorf("compute migrations: %s's part of %s: %w", owner, group, err))
		}
		if migration.Code != nil {
			panic(fmt.Errorf("compute migrations: %s's part of %s: step %s is a data step, which server's runner does not take from a part yet", owner, group, migration.Id))
		}
		if ids[migration.Id] {
			panic(fmt.Errorf("compute migrations: %s's part of %s uses id %s twice", owner, group, migration.Id))
		}
		ids[migration.Id] = true
	}
	if computeMigrationParts[group] == nil {
		computeMigrationParts[group] = map[string][]*operator.Migration{}
	}
	computeMigrationParts[group][owner] = slices.Clone(migrations)
}

// owner's part of group as registered, a copy; empty until the owner registers one.
func ComputeMigrationPart(group string, owner string) []*operator.Migration {
	return slices.Clone(computeMigrationParts[group][owner])
}
