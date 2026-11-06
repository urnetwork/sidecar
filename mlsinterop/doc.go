// Differential test peers: tmc/mls, thomas-vilte/mls-go and the mlswg interop client for the MLS
// subset (§10.4), and go-git as the git codec's oracle (§22.6). No peer exists yet.
//
// Test only, and a nested module so these peers cannot raise consumers' versions (D-REPO-2). Nothing
// outside this module imports it.
package mlsinterop
