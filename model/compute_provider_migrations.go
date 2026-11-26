// PROV's part of MG-C2 (DESIGN-COMPUTE §14.4; CONTRACTS C-30; PROV-M12-01): compute_provider, one row a provider,
// and compute_provider_price, one row a model or shape a provider and hour. computeservice's provider store
// (provider_store.go) is their one reader and writer, and compute-7 is their row of the published metadata list: per
// provider its id, kind, status and gate results, and its hourly price reads, never a network's anything.
//
//   - compute_provider.provider is the provider's fixed code, the smallint every provider column holds
//     (compute_charge.provider, §9.4; compute-plan-inference-small-readings, QD-1247), and slug its name, unique;
//     kind 1 inference, 2 enclave, 3 search; status 1 listed, 2 gated, 3 suspended, 4 out (§4.7), status_time when it
//     took it; history every gate result and status change, a JSON array, oldest first.
//   - compute_provider_price: item_kind 1 a model, priced per million tokens, 2 a shape, priced per hour and per GiB of
//     egress; prices in nano-gamma as the provider answered, with gamma_nano_usd the gamma's USD value at that read
//     (§9.6, §10.2); capacity NULL where the provider gave none. One row a model or shape and UTC hour.
//
// Every step is additive, and the group's steps change no more once its Gn-out registers it (§19.7).

package model

import (
	operator "github.com/urnetwork/operator-core"
)

// PROV's part, registered once at init, before server builds its migrations slice.
func init() {
	RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerProv, computeProviderMigrations())
}

// The part's statements, in order.
func computeProviderMigrations() []*operator.Migration {
	return []*operator.Migration{
		{
			Id: "compute_provider",
			Sql: `
				CREATE TABLE compute_provider (
					provider smallint NOT NULL,
					slug text NOT NULL,
					kind smallint NOT NULL,
					status smallint NOT NULL,
					status_time timestamp NOT NULL,
					history jsonb NOT NULL,
					PRIMARY KEY (provider)
				)
			`,
		},
		{
			Id: "compute_provider_slug",
			Sql: `
				CREATE UNIQUE INDEX compute_provider_slug ON compute_provider (slug)
			`,
		},
		{
			Id: "compute_provider_price",
			Sql: `
				CREATE TABLE compute_provider_price (
					provider smallint NOT NULL,
					item_kind smallint NOT NULL,
					item_id text NOT NULL,
					read_hour timestamp NOT NULL,
					read_time timestamp NOT NULL,
					gamma_nano_usd bigint NOT NULL,
					input_nano_gamma_per_million bigint NOT NULL,
					output_nano_gamma_per_million bigint NOT NULL,
					cached_input_nano_gamma_per_million bigint NOT NULL,
					hour_nano_gamma bigint NOT NULL,
					egress_nano_gamma_per_gib bigint NOT NULL,
					price_varies boolean NOT NULL,
					capacity bigint,
					PRIMARY KEY (provider, item_kind, item_id, read_hour)
				)
			`,
		},
		{
			// the hours' reads across providers, which the catalog's build and the margin checks read by hour
			Id: "compute_provider_price_read_hour",
			Sql: `
				CREATE INDEX compute_provider_price_read_hour ON compute_provider_price (read_hour)
			`,
		},
	}
}
