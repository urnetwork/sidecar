//go:build sidecar_check

// §22.7's list is generated: metadata_list.yml is §2.8's fenced block, byte for byte, comments
// included, so a row changes in the design and reaches the repository through make metadata. A hand
// edit here, or a design change that skipped make metadata, fails. sidecartest's strict reader reads
// the same bytes in go test ./..., and this package imports nothing of ours, so this reads only bytes.
//
// The one hand edit that passes is a line an owner's answer adds to the list ahead of design-records'
// fold of §2.8, named in metadataListAdditions with the question that holds the answer: the list is
// then §2.8's block with exactly those edits, byte for byte.

package check

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The list moves with the root module on a release branch, so it is relative to the module. design/
// stays at the repository's top, beside that module (§4.9), so the section is relative to the top.
const (
	metadataListFileName    = "metadata_list.yml"
	metadataListSectionPath = "design/source/sections/02-TRUST.md"
)

// What opens the block in §2.8, and what closes it.
const (
	metadataListHeading = "**The list**"
	metadataFenceOpen   = "```yaml"
	metadataFenceClose  = "```"
)

// The fenced block after §2.8's heading, without its fence lines, each line with its newline.
func metadataListBlock(section []byte) ([]byte, bool) {
	block := bytes.Buffer{}
	headingSeen := false
	fenceOpen := false
	for _, line := range bytes.SplitAfter(section, []byte("\n")) {
		text := strings.TrimSuffix(string(line), "\n")
		switch {
		case fenceOpen && text == metadataFenceClose:
			return block.Bytes(), true
		case fenceOpen:
			block.Write(line)
		case headingSeen && text == metadataFenceOpen:
			fenceOpen = true
		case strings.HasPrefix(text, metadataListHeading):
			headingSeen = true
		}
	}
	return nil, false
}

// Text an owner's answer adds to the list ahead of design-records' fold of §2.8: the block's text as the
// design writes it, which the block holds exactly once, the text the list holds in its place, and the
// question that holds the answer. Each applies to the block before the comparison, so the list stays
// exact in both directions: a list without the text fails, and so does an entry whose text the block no
// longer holds once, which is how one the design comes to write fails until its entry here leaves.
type metadataListAddition struct {
	question string
	block    string
	list     string
}

var metadataListAdditions = []metadataListAddition{
	{
		// QD-720: api-3's sees gains the IdP sign-in flows api keeps in Redis under {sso_<state>}
		question: "team-m2-16-sso-flow-state-row",
		block:    "keyed by the address's peppered hash; no domain or address held)\n  why: sign-in, roles and SSO (§7.5, §7.6);",
		list:     "keyed by the address's peppered hash; no domain or address held); IdP sign-in flows in progress (state, nonce, PKCE verifier, IdP, network, the signed-in user that began one; 10 min, taken once)\n  why: sign-in, roles and SSO (§7.5, §7.6);",
	},
	{
		// QD-741 and QD-742: cert-1's sees gains a row's issued chain, a requested revocation's reason and
		// the time of its latest state
		question: "tls-m5-05-cert-row-values",
		block:    "ARI window, state and successor; Team custom-domain chains and queued CSRs (v1);",
		list:     "ARI window, state and successor, the time of its latest state; issued chains until 30 d after expiry or revocation, and a requested revocation's reason; Team custom-domain chains and queued CSRs (v1);",
	},
	{
		// QD-742: cert-1's ttl counts a failed order's 30 d too
		question: "tls-m5-14-cert-row-end-time",
		block:    "  ttl: 30 d after expiry or revocation; budget entries 7 d,",
		list:     "  ttl: 30 d after expiry, revocation or failure; budget entries 7 d,",
	},
	{
		// QD-741's list version bump: the first line's version
		question: "tls-m5-05-cert-row-values",
		block:    "# metadata_list.yml v11;",
		list:     "# metadata_list.yml v12;",
	},
	{
		// and what the version adds, after v11's lines
		question: "tls-m5-05-cert-row-values",
		block:    "# until CONSUME; and evs-4's and evs-12's content kept until a later compaction, unscheduled (247).\n",
		list:     "# until CONSUME; and evs-4's and evs-12's content kept until a later compaction, unscheduled (247).\n# v12, updated 2026-11-12 for the owner's answers on certs' rows (QD-741, QD-742), adds cert-1's issued chains, a\n# requested revocation's reason and the time of a row's latest state, and counts a failed order's 30 d from its failure.\n",
	},
	{
		// QD-743: api-7's folded access log names what its rows now keep, which were already visible as their
		// entries' times and positions, so only the wording changes
		question: "acl-m2-06-access-log-positions",
		block:    "folded access log with its versioning lock (its rules stay sealed), each EvsShare's signer, position and expiry",
		list:     "folded access log with its versioning lock (its rules stay sealed), each repo admin's add position and a removed one's removal position until a later base drops it, the newest RepoDelete's entry time, each EvsShare's signer, position and expiry",
	},
	{
		// QD-798: the deletion row keeps its RepoDelete's signer too, already visible as the statement's signer, so
		// only the wording changes, on the text QD-743's addition wrote
		question: "acl-repo-delete-times-deletion-signer",
		block:    "the newest RepoDelete's entry time, each EvsShare's signer",
		list:     "the newest RepoDelete's entry time and signer, each EvsShare's signer",
	},
	{
		// QD-746: a base's header names the repos its own config head change shrinks, which every verifier already
		// held as those repos' holders_shrunk_at at the base's position, so only the wording changes
		question: "team-m2-09-base-shrinks",
		block:    "whose base headers carry the config_version, config head hash, folded_through, rows hash, rows_byte_count and threshold;",
		list:     "whose base headers carry the config_version, config head hash, folded_through, rows hash, rows_byte_count and threshold, and the repos whose key holders the base's own config head change shrinks;",
	},
	{
		// QD-763: gkm-1's forwarding reader keys are keyed by their network as well
		question: "core-owner-fixes-dkey-sweep-network",
		block:    "(metadata cluster); gkm/dkey/<delegation_id>\n",
		list:     "(metadata cluster); gkm/dkey/<network_id>/<delegation_id>\n",
	},
	{
		// QD-763's list version bump, on the version the additions above give
		question: "core-owner-fixes-dkey-sweep-network",
		block:    "# metadata_list.yml v12;",
		list:     "# metadata_list.yml v13;",
	},
	{
		// and what the version adds, after v12's lines
		question: "core-owner-fixes-dkey-sweep-network",
		block:    "# requested revocation's reason and the time of a row's latest state, and counts a failed order's 30 d from its failure.\n",
		list:     "# requested revocation's reason and the time of a row's latest state, and counts a failed order's 30 d from its failure.\n# v13, updated 2026-11-13 for the owner's answer QD-763, keys gkm-1's forwarding reader keys by their network as\n# well, gkm/dkey/<network_id>/<delegation_id>, so gkm's reconciler sweeps one network's at a time (QD-675).\n",
	},
	{
		// QD-765: the list's version names the slot origin's change (DESIGN-DETAILS 14.8), after v13's
		question: "details-14-slot-origin",
		block:    "# metadata_list.yml v13;",
		list:     "# metadata_list.yml v14;",
	},
	{
		// QD-765: v14's line, after v13's
		question: "details-14-slot-origin",
		block:    "# well, gkm/dkey/<network_id>/<delegation_id>, so gkm's reconciler sweeps one network's at a time (QD-675).\n",
		list: "# well, gkm/dkey/<network_id>/<delegation_id>, so gkm's reconciler sweeps one network's at a time (QD-675).\n" +
			"# v14, updated 2026-11-13 for the slot fix (DESIGN-DETAILS 14; QD-765), adds evs-5's origin of each slot object, in\n" +
			"# object metadata, and narrows evs-5's ttl to a dead push's own slots; evs-10 names the object metadata evs writes.\n",
	},
	{
		// QD-765: evs-5's sees gains each slot's origin (DESIGN-DETAILS 14.8), whose colon and space quote the value,
		// as every strict row's are
		question: "details-14-slot-origin",
		block:    "  sees: slot id, up to 64 wrapped object keys (ciphertext)",
		list:     "  sees: \"slot id, up to 64 wrapped object keys (ciphertext)",
	},
	{
		// QD-765: the origin itself, closing the quoted value
		question: "details-14-slot-origin",
		block:    "and their deletion by the drop's job (evs-28)\n  why: per-entry erasure for record-class repos and mail",
		list:     "and their deletion by the drop's job (evs-28); each slot's origin, in object metadata: the push id, statement hash prefix, ref, signer sidecar, base version, path epoch and mode of the statement that created it, or a re-seed's mark; all of it also in that push's record (evs-12)\"\n  why: per-entry erasure for record-class repos and mail",
	},
	{
		// QD-765: evs-5's ttl keeps a dead push's own slots only (DESIGN-DETAILS 14.8)
		question: "details-14-slot-origin",
		block:    "a refused or dead push's new slots until evacuation finds it dead, at most about 26 h after its batch",
		list:     "a refused or dead push's own slots until evacuation finds it dead, at most about 26 h after its batch, a slot stored within 2 s of that or after it staying",
	},
	{
		// QD-765: the MinIO row's object metadata, a slot/ object's origin beside QD-248's idx/ entry state
		// (DESIGN-DETAILS 14.8's §19.6 text, carried to evs-10)
		question: "details-14-slot-origin",
		block:    "object key with its size, checksum, times and access pattern, on an NVMe metadata cluster",
		list:     "object key with its size, checksum, times and access pattern, and no object metadata but an idx/ entry's state while its head lists sources (evs-11) and a slot/ object's origin (evs-5), on an NVMe metadata cluster",
	},
	{
		// QD-040's list version, after v14's
		question: "plan-SOCK-client-auth",
		block:    "# metadata_list.yml v14;",
		list:     "# metadata_list.yml v15;",
	},
	{
		// QD-040: v15's line, after v14's
		question: "plan-SOCK-client-auth",
		block:    "# object metadata, and narrows evs-5's ttl to a dead push's own slots; evs-10 names the object metadata evs writes.\n",
		list: "# object metadata, and narrows evs-5's ttl to a dead push's own slots; evs-10 names the object metadata evs writes.\n" +
			"# v15, updated 2026-11-13 for the owner's answer QD-040 (plan-SOCK-client-auth), adds sock-2's caller sidecar id,\n" +
			"# which its token names, and sock-5's {sc_<client_id>}ok, the time a client's token last checked valid at sockets.\n",
	},
	{
		// QD-040: sock-2 gains the sidecar id, from the caller's by_client_jwt
		question: "plan-SOCK-client-auth",
		block:    "each Find's dialer client and network (edges add their K client ids)",
		list:     "each Find's dialer client, network and sidecar id, which its token names (QD-040; edges add their K client ids and name no sidecar)",
	},
	{
		// QD-040: sockets keeps a client's last valid time under its own tag, {sc_<client_id>}ok, for the revocation
		// record's 120 s grace (§9.8's {sc_})
		question: "plan-SOCK-client-auth",
		block: "  store: Redis {sc_<client_id>}set\n" +
			"  sees: a client's set_version and registered entries\n" +
			"  why: idempotent full-set calls; removal on the client's removal signal (§9.5, §9.8)\n" +
			"  ttl: 5 min after the client's last call\n",
		list: "  store: Redis {sc_<client_id>}set and {sc_<client_id>}ok\n" +
			"  sees: a client's set_version and registered entries; the time its token last checked valid (QD-040)\n" +
			"  why: idempotent full-set calls; removal on the client's removal signal (§9.5, §9.8); a revocation-record miss within 120 s of a valid check counts as valid, since only api's and connect's SQL fallback projects the record again (QD-040)\n" +
			"  ttl: 5 min after the client's last call; the valid time 120 s after the check it records\n",
	},
	{
		// QD-716's list version, after v15's
		question: "details-3-metadata-rows",
		block:    "# metadata_list.yml v15;",
		list:     "# metadata_list.yml v16;",
	},
	{
		// QD-716: v16's line, after v15's
		question: "details-3-metadata-rows",
		block:    "# which its token names, and sock-5's {sc_<client_id>}ok, the time a client's token last checked valid at sockets.\n",
		list: "# which its token names, and sock-5's {sc_<client_id>}ok, the time a client's token last checked valid at sockets.\n" +
			"# v16, updated 2026-11-13 for the owner's answer QD-716 (details-3-metadata-rows), amends smtp-2 with the key set a\n" +
			"# sidecar proves under, a proof per part with its reply count and the header block's record count, and the key and\n" +
			"# scan-state commitments the sidecar publishes, uniformly random group elements (DESIGN-DETAILS 3.2.2, 3.2.5).\n",
	},
	{
		// QD-716: smtp-2's proofs become parts bound to one key part (DESIGN-DETAILS 3.8), whose colon and space
		// quote the value, as every strict row's are
		question: "details-3-metadata-rows",
		block:    "  sees: per connection the network and sidecar (from the ticket), the sending IP",
		list:     "  sees: \"per connection the network and sidecar (from the ticket), the sending IP",
	},
	{
		// QD-716: the parts, their counts and the commitments, in place of pi1 to pi3 (DESIGN-DETAILS 3.8)
		question: "details-3-metadata-rows",
		block:    "the DNSSEC chain, proofs π1 to π3 and, in DATA mode, one per later body part (owner decision 125), the length",
		list:     "the DNSSEC chain, the id of the key set the sidecar proves under; a proof per part: the key part, one per envelope group, one per header record and, in DATA mode, one per body record (owner decision 125), each with its reply count and, once, the header block's record count; the key commitment and the scan-state commitments the sidecar publishes, uniformly random group elements that depend on no key and no plaintext (D-SMTP-22), the length",
	},
	{
		// QD-716: closing smtp-2's quoted value
		question: "details-3-metadata-rows",
		block:    "so no MX reply's plaintext inside TLS (D-SMTP-21, D-SMTP-22)\n  why: send, verify proofs",
		list:     "so no MX reply's plaintext inside TLS (D-SMTP-21, D-SMTP-22)\"\n  why: send, verify proofs",
	},
	{
		// QD-725's list version, after v16's
		question: "evsb-m2-19-reseed-route-body",
		block:    "# metadata_list.yml v16;",
		list:     "# metadata_list.yml v17;",
	},
	{
		// QD-725: v17's line, after v16's
		question: "evsb-m2-19-reseed-route-body",
		block:    "# scan-state commitments the sidecar publishes, uniformly random group elements (DESIGN-DETAILS 3.2.2, 3.2.5).\n",
		list: "# scan-state commitments the sidecar publishes, uniformly random group elements (DESIGN-DETAILS 3.2.2, 3.2.5).\n" +
			"# v17, updated 2026-11-13 for the owner's answer QD-725 (evsb-m2-19-reseed-route-body), adds evs-29, the Signed\n" +
			"# EvsReseed statements evs keeps at reseed/<repo>/<ref> and serves with the head after a site loss.\n",
	},
	{
		// QD-725: evs-29, the Signed EvsReseed statements evs keeps per ref, after evs-28's row
		question: "evsb-m2-19-reseed-route-body",
		block:    "  owner: §11.13\ngkm-1:\n",
		list: "  owner: §11.13\n" +
			"evs-29:\n" +
			"  service: evs\n" +
			"  store: reseed/<repo>/<ref> (the repo's metadata cluster)\n" +
			"  sees: \"after a site loss, per ref the Signed EvsReseed statements its repo admins filed: repo_id, ref_id, the re-seeded head's version and chain, the recovery's incident id, and the signing sidecar\"\n" +
			"  why: a reader whose pin lies above every surviving copy accepts the shorter history only under a repo admin's EvsReseed, shown as a loss (§11.13, §19.10; QD-725)\n" +
			"  ttl: the ref's life; deleted with the repo at its shred (§11.12's phase 5)\n" +
			"  owner: §11.13\n" +
			"gkm-1:\n",
	},
}

// §2.8's block with each addition in place, in order, and a finding for each that does not apply.
func applyMetadataListAdditions(block []byte, additions []metadataListAddition) ([]byte, []string) {
	findings := []string{}
	for _, addition := range additions {
		if addition.question == "" || addition.block == "" || addition.block == addition.list {
			findings = append(findings, findingf("the addition for question %q names no question or changes nothing", addition.question))
			continue
		}
		if count := bytes.Count(block, []byte(addition.block)); count != 1 {
			findings = append(findings, findingf("the addition for question %s no longer applies: §2.8's block holds its text %d times, not once; if the design now writes the line, its entry in metadataListAdditions leaves and make metadata brings the block here", addition.question, count))
			continue
		}
		block = bytes.Replace(block, []byte(addition.block), []byte(addition.list), 1)
	}
	return block, findings
}

// The first line two texts differ on, numbered from 1, for a finding a reader can act on.
func firstDifferentLine(a []byte, b []byte) int {
	aLines := bytes.Split(a, []byte("\n"))
	bLines := bytes.Split(b, []byte("\n"))
	for index := 0; index < len(aLines) && index < len(bLines); index += 1 {
		if !bytes.Equal(aLines[index], bLines[index]) {
			return index + 1
		}
	}
	return 1 + min(len(aLines), len(bLines))
}

// Whether the list in moduleDirectory is the block of §2.8 in topDirectory. The two are one directory
// in development and differ on a release branch.
func metadataListFindings(topDirectory string, moduleDirectory string) []string {
	return metadataListFindingsWithAdditions(topDirectory, moduleDirectory, nil)
}

// As metadataListFindings, the block first taking the additions.
func metadataListFindingsWithAdditions(topDirectory string, moduleDirectory string, additions []metadataListAddition) []string {
	section, err := os.ReadFile(filepath.Join(topDirectory, metadataListSectionPath))
	if err != nil {
		return []string{findingf("reading §2.8: %v", err)}
	}
	block, found := metadataListBlock(section)
	if !found {
		return []string{findingf("%s holds no fenced block under %s", metadataListSectionPath, metadataListHeading)}
	}
	list, err := os.ReadFile(filepath.Join(moduleDirectory, metadataListFileName))
	if err != nil {
		return []string{findingf("reading the list: %v; make metadata writes it", err)}
	}
	block, findings := applyMetadataListAdditions(block, additions)
	if 0 < len(findings) {
		return findings
	}
	if !bytes.Equal(list, block) {
		return []string{findingf("%s differs from §2.8's block at line %d: a row changes in the design, and make metadata brings it here", metadataListFileName, firstDifferentLine(list, block))}
	}
	return nil
}

func TestMetadataListIsSection2sBlock(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "metadata list", metadataListFindingsWithAdditions(repository.topDirectory, repository.moduleDirectory, metadataListAdditions))
}

// An owner's answer ahead of the fold: the list holds the added text and the block does not yet.
func TestMetadataListPassesAnAdditionAheadOfTheFold(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"}}
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: gone, and more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindingsWithAdditions(directory, directory, additions))
	// without its entry the same list is a hand edit
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 3")
}

// An entry is owed its text: a list still as the block writes it fails.
func TestMetadataListRefusesAListBehindItsAddition(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"}}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "differs from §2.8's block at line 3")
}

// Once the design writes the line, or changes the text around it, the entry no longer applies and fails
// until it leaves.
func TestMetadataListRefusesAnAdditionTheBlockNoLongerHolds(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: went\n", list: "withdrawn: gone\n"}}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "the addition for question a-question no longer applies")
}

// Text the block holds twice names no one place.
func TestMetadataListRefusesAnAdditionThatAppliesTwice(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "evs-1", list: "evs-2"}}
	section := "**The list**\n\n```yaml\n# metadata_list.yml v1\nevs-1:\n  withdrawn: see evs-1\n```\n"
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte(section), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "holds its text 2 times")
}

// An entry names its question and changes something.
func TestMetadataListRefusesAnEmptyAddition(t *testing.T) {
	directory := plantMetadataList(t)
	for _, addition := range []metadataListAddition{
		{block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"},
		{question: "a-question", list: "withdrawn: gone, and more\n"},
		{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone\n"},
	} {
		wantFindings(t, metadataListFindingsWithAdditions(directory, directory, []metadataListAddition{addition}), "names no question or changes nothing")
	}
}

// A module directory holding what make metadata reads, and a list it would write.
func plantMetadataList(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, filepath.Dir(metadataListSectionPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	section := "### 2.8\n\n```yaml\nnot: this block\n```\n\n**The list** (the only TTL table):\n\n```yaml\n# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n```\n\nAfter it.\n"
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte(section), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestMetadataListPassesTheBlockItself(t *testing.T) {
	directory := plantMetadataList(t)
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// A release branch's shape: the section at the top, and the list one directory down in v2026/.
func TestMetadataListReadsTheSectionBesideAReleaseModule(t *testing.T) {
	topDirectory := plantMetadataList(t)
	moduleDirectory := filepath.Join(topDirectory, "v2026")
	if err := os.Mkdir(moduleDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(topDirectory, metadataListFileName), filepath.Join(moduleDirectory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(topDirectory, moduleDirectory))
	wantFindings(t, metadataListFindings(moduleDirectory, moduleDirectory), "reading §2.8")
}

func TestMetadataListRefusesAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 3")
}

func TestMetadataListRefusesAnEditedComment(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v2\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 1")
}

func TestMetadataListRefusesAMissingList(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.Remove(filepath.Join(directory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "make metadata writes it")
}

func TestMetadataListRefusesASectionWithNoBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n\nNo list here.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// A block §2.8 opened and never closed is no block.
func TestMetadataListRefusesAnUnclosedBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("**The list**\n\n```yaml\nevs-1:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// The real Makefile on a planted section, so make metadata and this rule are shown to read one block.
func runMakeMetadata(t *testing.T, directory string) error {
	t.Helper()
	makefile, err := os.ReadFile(filepath.Join(openThisCheckout(t).moduleDirectory, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "Makefile"), makefile, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("make", "metadata")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func TestMakeMetadataRestoresAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// With no block to copy it fails, and an empty list never replaces a real one.
func TestMakeMetadataKeepsTheListWithoutABlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err == nil {
		t.Errorf("make metadata succeeded with nothing to copy")
	}
	list, err := os.ReadFile(filepath.Join(directory, metadataListFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Errorf("make metadata emptied the list")
	}
}
