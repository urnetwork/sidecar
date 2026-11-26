// INFER's part of MG-C2 (DESIGN-COMPUTE §6.3, §14.4; CONTRACTS C-30; INFER-M12-01): compute_catalog_version, one row a
// published version of the remote catalog, which keeps every broker instance answering alike and the version a request
// was admitted under pricing its charge (compute-plan-catalog-versions, QD-1237). computeservice's catalog
// (broker_catalog.go) is its one reader and writer, and compute-7 its row of the published metadata list: public models,
// limits and prices, and each direct provider's costliest worst case, never a network's anything.
//
//   - version, from 1, one past the newest at each publish, which the primary key holds to one publisher;
//     published_time, when it was published;
//   - answer, the version's InferCatalogAnswer as deterministic protobuf with its broker time zero, and answer_sha256
//     its SHA-256, which a reader checks before it answers it;
//   - exposure, each direct provider's costliest worst case as a JSON array, and exposure_time the hourly read it is of,
//     which BAL's exposure rule reads (§9.7).
//
// Every step is additive, and the group's steps change no more once its Gn-out registers it (§19.7).

package model

import (
	operator "github.com/urnetwork/operator-core"
)

// INFER's part, registered once at init, before server builds its migrations slice.
func init() {
	RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerInfer, computeCatalogMigrations())
}

// The part's statements, in order.
func computeCatalogMigrations() []*operator.Migration {
	return []*operator.Migration{
		{
			Id: "compute_catalog_version",
			Sql: `
				CREATE TABLE compute_catalog_version (
					version bigint NOT NULL,
					published_time timestamp NOT NULL,
					answer bytea NOT NULL,
					answer_sha256 bytea NOT NULL,
					exposure jsonb NOT NULL,
					exposure_time timestamp NOT NULL,
					PRIMARY KEY (version)
				)
			`,
		},
	}
}
