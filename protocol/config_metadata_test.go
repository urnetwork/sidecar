// §2.8's guard for §7.9's records (I-18): every field a server can read in signed.proto, auth.proto and config.proto is
// named by the api-7 row of the published list, read here from DESIGN.md. It is the same check sidecartest's schema
// guard makes of every row once that lands, and this table is what it takes over: a new field fails here until someone
// says what the list calls it, so a value cannot reach the server unlisted.

package protocol

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// How a server sees a field: by a phrase of api-7's, or not at all because a seal or the config repo's ciphertext holds it.
const (
	// Behind a sealed field of a statement, opened only by config readers.
	testBehindSeal = "the rest, X-Wing key and genesis signature included, sealed"
	// In a record that travels only in config heads.
	testInConfigRepo = "the config repo itself only as evs ciphertext"
	// Where the network's id shows: every entry is stored under it.
	testInObjectKey = "proj/<network_id>/<n>/_"

	testPinPhrase         = "signer's pin"
	testHeaderPhrase      = "headers (signer's pin, nonce, expiry)"
	testPositionPhrase    = "(position, chain digest, kind, time)"
	testRolePhrase        = "members with roles"
	testBindingPhrase     = "recovery bindings newest first (key hash, reason)"
	testAdmissionPhrase   = "sidecar admissions with identity keys"
	testSignerPhrase      = "the signer and position of each admission, AdmissionConfirm, OwnerConfirm, Delegation, recovery binding and key registration"
	testPositionsPhrase   = "admission, revocation and park positions"
	testMemberPhrase      = "member or keyed tag ids, ephemeral flags, expiry and sponsors"
	testDelegationPhrase  = "Delegations' signing and reader public keys, tag ids, max_admits and admissions, expiry, key drops and ends"
	testKeyPhrase         = "registered presence and SSH public keys with member and purpose"
	testRevocationPhrase  = "revocations (reason, and since_n for a compromise or a leak)"
	testRebindPhrase      = "recovery bindings and rebinds as ids (member, signer, reason, the new and replaced recovery Ed25519 keys' hashes)"
	testProposalPhrase    = "authority proposals, cosigns and vetoes"
	testSuspensionPhrase  = "suspensions and unsuspensions"
	testGrantPhrase       = "grant activations and revocations"
	testIndexerPhrase     = "indexer designations as ids (signer, subject, scope, retire; services sealed"
	testConfirmPhrase     = "OwnerConfirms and AdmissionConfirms"
	testRegisterPhrase    = "key registrations"
	testSponsorPhrase     = "SponsorSets"
	testCountersignPhrase = "presence countersignatures with evidence and act path"
	testStatementPhrase   = "statements with their types"
	testSignaturePhrase   = "and signatures"
)

// Every field of the three files, by message, with the phrase of api-7 that names it. A message a statement carries inside
// a seal, or that rides only heads, is listed with where it stays, so nothing here is a skip.
var testApi7Fields = map[string]map[string]string{
	"Signed": {
		"body": testStatementPhrase, "signer_id": testSignaturePhrase, "signature": testSignaturePhrase,
		"webauthn": testCountersignPhrase, "type": testStatementPhrase,
	},
	"WebAuthnEvidence": {
		"authenticator_data": testCountersignPhrase, "client_data_json": testCountersignPhrase, "key_id": testCountersignPhrase,
		"signature": testCountersignPhrase, "act_size": testCountersignPhrase, "act_index": testCountersignPhrase,
		"act_path": testCountersignPhrase,
	},

	"StatementHeader": {
		"network_id": testInObjectKey, "at": testPinPhrase, "nonce": testHeaderPhrase, "not_after_ms": testHeaderPhrase,
	},
	"AuthEntry": {
		"network_id": testInObjectKey, "n": testPositionPhrase, "prev_chain": testPositionPhrase, "kind": testPositionPhrase,
		"time_ms": testPositionPhrase, "body": testStatementPhrase,
	},
	"AuthPin": {"version": testPositionPhrase, "chain": testPositionPhrase},
	"ProjectionHeader": {
		"network_id": testInObjectKey, "version": testPositionPhrase, "prev_chain": testPositionPhrase,
		"folded_through": "folded_through", "config_head_sha256": "config head hash", "rows_sha256": "rows hash",
		"threshold": "threshold",
	},
	"ProjectionRows": {
		"members": testRolePhrase, "sidecars": testAdmissionPhrase, "delegations": testDelegationPhrase,
		"registered_keys": testKeyPhrase, "acl": "their AclRows",
	},
	"MemberRow": {
		"member_id": testRolePhrase, "role": testRolePhrase, "recovery_key_sha256": testBindingPhrase, "bindings": testBindingPhrase,
	},
	"RecoveryBindingRow": {
		"key_sha256": testBindingPhrase, "signer": testSignerPhrase, "at": testSignerPhrase, "reason": testBindingPhrase,
	},
	"SidecarRow": {
		"sidecar_id": testAdmissionPhrase, "admission_sha256": testAdmissionPhrase, "admission_signers": testSignerPhrase,
		"admitted_at": testPositionsPhrase, "confirm_signer": testSignerPhrase, "confirmed_at": testSignerPhrase,
		"owner_confirm_signer": testSignerPhrase, "owner_confirmed_at": testSignerPhrase, "revoked_at": testPositionsPhrase,
		"parked_at": testPositionsPhrase, "sponsor": testMemberPhrase, "capabilities": "capabilities",
		"delegation_id": testSignerPhrase, "live_since": "live_since", "not_after": testMemberPhrase,
	},
	"DelegationRow": {
		"delegation_id": testDelegationPhrase, "signer": testSignerPhrase, "at": testSignerPhrase, "tag_atoms": testDelegationPhrase,
		"not_after": testDelegationPhrase, "key_dropped_at": testDelegationPhrase, "ended_at": testDelegationPhrase,
		"admissions": testDelegationPhrase,
	},
	"KeyRow": {
		"key_id": testKeyPhrase, "member_id": testKeyPhrase, "alg": testKeyPhrase, "public_key": testKeyPhrase, "purpose": testKeyPhrase,
		"signer": testSignerPhrase, "at": testSignerPhrase, "not_after": testRegisterPhrase, "revoked_at": testPositionsPhrase,
	},
	"ApiTick": {
		"reaped_sidecar_ids": "reaped ephemeral sidecar ids", "activated_proposal_ids": "activated proposal ids",
	},
	"MemberRevoke":  {"header": testHeaderPhrase, "member_id": testRevocationPhrase},
	"SidecarRevoke": {"header": testHeaderPhrase, "sidecar_id": testRevocationPhrase, "reason": testRevocationPhrase, "since_n": testRevocationPhrase},
	"GrantRevoke":   {"header": testHeaderPhrase, "grant_id": testGrantPhrase},
	"Suspend":       {"header": testHeaderPhrase, "subject": testSuspensionPhrase, "suspend_id": testSuspensionPhrase},
	"Unsuspend":     {"header": testHeaderPhrase, "subject": testSuspensionPhrase, "suspend_id": testSuspensionPhrase},

	"AdminSet": {
		"header": testHeaderPhrase, "owners": testRolePhrase, "admins": testRolePhrase, "network_admins": testRolePhrase,
		"it_admins": testRolePhrase, "threshold": "threshold",
	},
	"MemberAdmit": {"header": testHeaderPhrase, "member_id": testRolePhrase, "role": testRolePhrase},
	"SidecarAdmit": {
		"header": testHeaderPhrase, "network_id": testInObjectKey, "sidecar_id": testAdmissionPhrase,
		"identity_public_key": testAdmissionPhrase, "identity_alg": testAdmissionPhrase, "member_id": testMemberPhrase,
		"tag_ids": testMemberPhrase, "ephemeral": testMemberPhrase, "not_after": testMemberPhrase, "capabilities": "capabilities",
	},
	"AdmissionConfirm": {"header": testHeaderPhrase, "sidecar_id": testConfirmPhrase},
	"SponsorSet":       {"header": testHeaderPhrase, "sidecar_id": testSponsorPhrase, "sponsor_member_id": testSponsorPhrase},
	"IndexerSet": {
		"header": testHeaderPhrase, "sidecar_id": testIndexerPhrase, "scope": testIndexerPhrase, "retire": testIndexerPhrase,
		"sealed_services": testIndexerPhrase,
	},
	"IndexerServices": {"services": testBehindSeal},
	"RecoveryBind": {
		"header": testHeaderPhrase, "member_id": testRebindPhrase, "prev_sha256": testRebindPhrase,
		"ed25519_public_key_sha256": testRebindPhrase, "sealed_body": testBehindSeal,
	},
	"RecoveryBindBody": {"xwing_public_key": testBehindSeal, "ed25519_public_key": testBehindSeal, "genesis_sig": testBehindSeal},
	"RecoveryRebind": {
		"header": testHeaderPhrase, "member_id": testRebindPhrase, "prev_sha256": testRebindPhrase,
		"ed25519_public_key_sha256": testRebindPhrase, "sealed_body": testBehindSeal, "reason": testRebindPhrase,
	},
	"KeyRegister": {
		"header": testHeaderPhrase, "member_id": testKeyPhrase, "key_id": testKeyPhrase, "alg": testKeyPhrase, "public_key": testKeyPhrase,
		"attestation": testRegisterPhrase, "purpose": testKeyPhrase, "not_after": testRegisterPhrase,
	},
	"KeyRevoke": {"header": testHeaderPhrase, "key_id": testRevocationPhrase},
	"Delegation": {
		"header": testHeaderPhrase, "pubkey": testDelegationPhrase, "reader_xwing_public_key": testDelegationPhrase,
		"tag_ids": testDelegationPhrase, "max_admits": testDelegationPhrase, "not_after": testDelegationPhrase,
	},
	"DelegationRevoke": {"header": testHeaderPhrase, "delegation_id": testRevocationPhrase, "since_n": testRevocationPhrase},
	"ServiceSettings": {
		"team_mail": testInConfigRepo, "stale_leaf_days": testInConfigRepo, "self_admit": testInConfigRepo,
		"witness_bound_hours": testInConfigRepo, "scim_signer": testInConfigRepo, "directory": testInConfigRepo,
	},
	"ServiceDirectorySettings": {"runs": testInConfigRepo, "workers": testInConfigRepo},
	"VersioningRule": {
		"kinds": testInConfigRepo, "repo_ids": testInConfigRepo, "path_glob": testInConfigRepo,
		"size_above_bytes": testInConfigRepo, "versioning": testInConfigRepo,
	},
	"VersioningRules":   {"rules": testInConfigRepo},
	"AuthorityProposal": {"header": testHeaderPhrase, "statement_type": testProposalPhrase, "statement": testProposalPhrase},
	"AuthorityCosign":   {"header": testHeaderPhrase, "proposal_id": testProposalPhrase},
	"RecoveryVeto":      {"header": testHeaderPhrase, "proposal_id": testProposalPhrase},
}

// Fields a server reads that api-7 does not name yet, each with the question that asks for its words. These fail the
// moment api-7 grows the word, so the entry cannot outlive its answer.
var testApi7Unlisted = map[string]struct {
	question string
	word     string
}{
	"Genesis":                          {question: "plan-TEAM-genesis-custody", word: "Genesis"},
	"Signed.key_id":                    {question: "protos-bridge-recovery-key-carrier", word: "recovery Ed25519 public key"},
	"ProjectionHeader.config_version":  {question: "team-records-api7-base-header-fields", word: "config_version"},
	"ProjectionHeader.rows_byte_count": {question: "team-records-api7-base-header-fields", word: "rows_byte_count"},
}

// api-7's block of §2.8's list as DESIGN.md prints it.
func testApi7Row(t *testing.T) string {
	design, err := os.ReadFile(testDesignPath)
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(design), "\napi-7:\n")
	if !found {
		t.Fatal("no api-7 row in DESIGN.md")
	}
	row, _, found := strings.Cut(rest, "\napi-8:\n")
	if !found {
		t.Fatal("no row after api-7 in DESIGN.md")
	}
	return row
}

func TestConfigFieldsMapToApi7(t *testing.T) {
	row := testApi7Row(t)
	seen := map[string]bool{}
	for _, path := range []string{"protocol/bridge/signed.proto", "protocol/bridge/auth.proto", "protocol/config.proto"} {
		messages := testFile(t, path).Messages()
		for i := range messages.Len() {
			message := messages.Get(i)
			name := string(message.Name())
			seen[name] = true
			if _, ok := testApi7Unlisted[name]; ok {
				continue
			}
			wantFields := testApi7Fields[name]
			fields := message.Fields()
			gotFields := make([]string, 0, fields.Len())
			for j := range fields.Len() {
				field := fields.Get(j)
				gotFields = append(gotFields, string(field.Name()))
				if _, ok := testApi7Unlisted[name+"."+string(field.Name())]; ok {
					continue
				}
				phrase := wantFields[string(field.Name())]
				if phrase == "" {
					t.Errorf("%s.%s maps to no phrase of api-7", name, field.Name())
					continue
				}
				if !strings.Contains(row, phrase) {
					t.Errorf("%s.%s maps to %q, which api-7 does not hold", name, field.Name(), phrase)
				}
			}
			for fieldName := range wantFields {
				if !slices.Contains(gotFields, fieldName) {
					t.Errorf("%s.%s is no field", name, fieldName)
				}
			}
		}
	}
	for name := range testApi7Fields {
		if !seen[name] {
			t.Errorf("%s is no message", name)
		}
	}
}

// An exception is a debt, not a skip: once api-7 holds the word, the entry goes and the field takes its phrase.
func TestApi7ExceptionsStillNeedTheirQuestions(t *testing.T) {
	row := testApi7Row(t)
	for _, name := range slices.Sorted(maps.Keys(testApi7Unlisted)) {
		exception := testApi7Unlisted[name]
		if strings.Contains(row, exception.word) {
			t.Errorf("api-7 now names %s, so %s's exception should go", exception.word, name)
		}
	}
}
