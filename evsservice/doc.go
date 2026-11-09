// The evs engine (§11), which server/cli/evs hosts, and taskworker's evs passes. EVS1's tasks add the
// engine itself, its routes and its passes, each in its own file: the engine, its router and token check
// (engine.go, auth.go), the object families' keys (objects.go), placement (place.go) and repo/'s cache
// (repo_cache.go), the head, its cache and group-commit batches (head.go, head_cache.go, batch.go,
// record_cache.go), index entries and the newest-version rule every read and CAS uses (entry.go,
// newest.go, sources.go, versions.go), with the barriers every step calls (barriers.go). §11.13's write budget is here too
// (budget_*.go), §4.5's home for it: the governor's accounts per metadata cluster, the price table, and
// the client each evs, gkm, api and taskworker process spends through, which every engine reaches as
// ServiceHost.Budget (host_budget.go).
package evsservice
