// The sockets engine (§9), which server/cli/sockets hosts on every lb host (D-SOCK-10). Clients lease
// registrations and dialers Find them. The service picks two listeners, signs a ticket for each and
// never contacts a listener (D-SOCK-4). Its state is soft and lives in Redis Cluster (§9.8), and no
// connection's bytes pass through it (R-SOCK-6).
//
// scheduler.go and ejection.go are §9.7 and §9.6's outlier rules as pure functions, which every store
// repeats pick for pick.
package socketsservice
