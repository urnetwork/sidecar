// Package bench holds §22.8's search, remote and phone rows as harnesses and the index writers' load driver that
// server/cli/filecluster-bench's index mode runs (SEARCH-M10-40): each runs at reduced scale in T2, where its tests
// show it gives the row's fields, and at the row's scale where the row runs, which is external. Every harness stands
// on the root's sidecar_testhooks seams, so its files build with that tag alone; this file is the package without it.
package bench
