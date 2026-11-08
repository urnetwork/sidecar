// Differential test peers for the MLS subset and evs's git codec, kept out of the root (D-REPO-2): tmc/mls,
// whose 0x0010 interop artifact is ARTIFACT.md (§22.10; xwing_kat_test.go, ladder_test.go, overlay_test.go and
// tmc_test.go), and go-git, the git codec's oracle (§22.6), in git_oracle_test.go. thomas-vilte/mls-go, the
// 0x0001 peer owner decision 43 names, is not here yet (KEYS-M2-10). No mlswg interop client is built
// (plan-KEYS-mlswg-license #2).
//
// Test only, and a nested module so these peers cannot raise consumers' versions (D-REPO-2). Nothing
// outside this module imports it.
package mlsinterop
