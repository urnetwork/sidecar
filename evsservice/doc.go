// The evs engine (§11), which server/cli/evs hosts, and taskworker's evs passes. EVS1's tasks add the
// engine itself, its routes and its passes, each in its own file. What is here so far is §11.13's
// write budget (budget_*.go), §4.5's home for it: the governor's accounts per metadata cluster, the
// price table, and the client each evs, gkm, api and taskworker process spends through, which every
// engine reaches as ServiceHost.Budget (host_budget.go).
package evsservice
