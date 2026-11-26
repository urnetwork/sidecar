// §14.4's Redis families, one builder each under its hash tag, and which instance each lives on. Every key is soft
// state the broker rebuilds: no Redis key is the only record of a debt, since a settlement's outcome is committed to
// its operation row in Postgres before a script turns its hold into an unsettled charge (§9.7, §14.4).
//
// The rules every caller keeps (host_redis.go's, and §14.4's):
//
//   - A script or multi-key call touches one hash tag, as production's Redis Cluster requires: a network's projection,
//     holds and budget counters share {cmp_<network_id>}, so one script holds and checks the floor and the budgets; a
//     network's search rate, the global search limiter, the open searches and a K_P's nonces each take a second script
//     in their own slot after the first admits, which undoes the hold when it refuses. RedisKeysShareTag states the
//     rule, crossslot.Check holds this package to it, and FakeRedis fails a call that breaks it.
//   - A script is a package-level sidecar.RedisScript whose source reads every key from KEYS and builds none.
//   - {cmpa}, the open search admissions, lives only on the Redis instance of its own the host gives the engine
//     (ComputeEngineDeps.AdmissionsRedis), with persistence off and outside every backup; every other family lives only
//     on the host's Redis. RedisFor hands out the instance a key's family lives on and refuses the other, so no
//     {cmpa} key is ever written where the rdb bundles would keep it.
//
// Each family's row in §2.8's list (I-18), as metadata_list.yml's store fields name them and fields.yml's guard reads
// them: {cmp_} (holds and unsettled charges), {cmpd_} and {cmpp_} compute-1; the budget counters {cmp_}:b: compute-6;
// {cmpk_} compute-2 (QD-1367); {cmpe_} compute-4; {cmpc_} compute-9; {cmpr_}, {cmps} and {cmpa} compute-10; {cmpo}
// compute-11.

package computeservice

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// A network's projection, holds and unsettled charges, each under its operation key (§9.7): {cmp_<network_id>}.
func ComputeNetworkRedisKey(networkId sidecar.Id) string {
	return "{cmp_" + sidecar.EvsKeyId(networkId) + "}"
}

// A subject's budget counters, per day and month, beside its network's holds: {cmp_<network_id>}:b:<subject_id>.
func ComputeBudgetRedisKey(networkId sidecar.Id, subjectId sidecar.Id) string {
	return "{cmp_" + sidecar.EvsKeyId(networkId) + "}:b:" + sidecar.EvsKeyId(subjectId)
}

// One collateral item, public vendor data under its own expiry (§5.7): {cmpc_<sha256>}.
func ComputeCollateralRedisKey(sha256 [32]byte) string {
	return "{cmpc_" + hex.EncodeToString(sha256[:]) + "}"
}

// An enclave's orchestrator lease and its nonces in flight (§11.6): {cmpe_<enclave_id>}.
func ComputeEnclaveRedisKey(enclaveId sidecar.Id) string {
	return "{cmpe_" + sidecar.EvsKeyId(enclaveId) + "}"
}

// A network's search rate and its searches today, against day_max (§21.9): {cmpr_<network_id>}.
func ComputeSearchRateRedisKey(networkId sidecar.Id) string {
	return "{cmpr_" + sidecar.EvsKeyId(networkId) + "}"
}

// The global search limiter, which names no network (§21.5): {cmps}.
func ComputeSearchLimiterRedisKey() string {
	return "{cmps}"
}

// The open search admissions, ticket to network, sidecar, agent, request id and hold (§21.5), on the admissions
// instance alone: {cmpa}.
func ComputeSearchAdmissionsRedisKey() string {
	return "{cmpa}"
}

// A network's failed promotion code redemptions this UTC day (§9.11): {cmpk_<network_id>}.
func ComputePromoFailureRedisKey(networkId sidecar.Id) string {
	return "{cmpk_" + sidecar.EvsKeyId(networkId) + "}"
}

// Direct calls pending while their provider's lookup fails, nonce to hold, no hash, at most 24 hours (§6.6), by K_P,
// the provider's API-key hotkey, whose public key is public on chain (compute-7): {cmpp_<k_p>}.
func ComputeDirectPendingRedisKey(hotkey []byte) string {
	return "{cmpp_" + hex.EncodeToString(hotkey) + "}"
}

// This hour's search outcome counts by class, across all networks (§21.8): {cmpo}.
func ComputeSearchOutcomesRedisKey() string {
	return "{cmpo}"
}

// Direct calls in flight, nonce to hash and hold, and the nonces K_P used in the last 15 seconds (§6.6), by K_P's
// public key: {cmpd_<k_p>}.
func ComputeDirectInFlightRedisKey(hotkey []byte) string {
	return "{cmpd_" + hex.EncodeToString(hotkey) + "}"
}

// A key whose family lives on the instance it was not asked of.
var ErrComputeRedisInstance = errors.New("compute key on the wrong Redis instance")

// Whether key belongs to {cmpa}, the admissions instance's one family.
func computeAdmissionsKey(key string) bool {
	return sidecar.RedisHashTag(key) == "cmpa"
}

// The instance key's family lives on: the admissions instance for {cmpa}, the host's Redis for every other family.
// An error when that instance was not given, which a route answers 503.
func (self *ComputeEngine) RedisFor(key string) (sidecar.Redis, error) {
	if computeAdmissionsKey(key) {
		if self.deps.AdmissionsRedis == nil {
			return nil, errors.New("this compute block holds no admissions instance for {cmpa}")
		}
		return self.deps.AdmissionsRedis, nil
	}
	if self.host.Redis == nil {
		return nil, errors.New("this compute block holds no Redis")
	}
	return self.host.Redis, nil
}

// The host's Redis for keys, refusing any {cmpa} key among them, which never lives there. For a call or script of
// several keys, which must share one tag besides.
func (self *ComputeEngine) MainRedis(keys ...string) (sidecar.Redis, error) {
	for _, key := range keys {
		if computeAdmissionsKey(key) {
			return nil, fmt.Errorf("%w: {cmpa} lives on the admissions instance alone", ErrComputeRedisInstance)
		}
	}
	if !sidecar.RedisKeysShareTag(keys) {
		return nil, errors.New("CROSSSLOT: the keys of one compute call share no hash tag")
	}
	if self.host.Redis == nil {
		return nil, errors.New("this compute block holds no Redis")
	}
	return self.host.Redis, nil
}

// The admissions instance for keys, refusing any key of another family, which never lives there.
func (self *ComputeEngine) AdmissionsRedis(keys ...string) (sidecar.Redis, error) {
	for _, key := range keys {
		if !computeAdmissionsKey(key) {
			return nil, fmt.Errorf("%w: only {cmpa} lives on the admissions instance", ErrComputeRedisInstance)
		}
	}
	if self.deps.AdmissionsRedis == nil {
		return nil, errors.New("this compute block holds no admissions instance for {cmpa}")
	}
	return self.deps.AdmissionsRedis, nil
}
