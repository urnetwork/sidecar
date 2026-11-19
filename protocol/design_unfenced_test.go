// What the package declares that no fence in DESIGN.md does, written as a fence would be, so one parser and one
// comparison hold it: a field or value changed here without changing the proto, or there without changing this, fails
// TestDeclarationsMatchTheirFences. This is the repository's own addition to the design's wire, so a reviewer reads
// it here, and a new field of one of these has to pass through this file on its way to a release. Where a server
// reads the field, it needs its §2.8 row first (I-18), which §22.7's guard holds it to.
//
// The design gives most of these as field lists or names without numbers. They take numbers in the order written,
// which the answers to the questions that asked, among them protos-bridge-unwritten-numbers,
// protos-services-unwritten-numbers, keys-wire-route-bodies, mail-proto-format-readings and plan-TLS-small-readings,
// ratify as landed. They freeze with their formats, and as design-records writes each into the design as a fence, it
// leaves this file.

package protocol

// Each block names its file, as a fence does, and each declaration says where the design writes it. A declaration
// that gains a real fence is then written twice, which says to take it out of here.
const testUnfencedFence = `
// sidecar/protocol/envelope.proto
// §6.5: each result has its request's fields.
message HelloResult {
  uint32 min_version = 1; uint32 max_version = 2; uint32 secure_version = 3; uint64 features = 4;
  uint32 max_body_byte_count = 5; uint32 initial_window = 6; bytes binding = 7;
}
message HeadCheckResult {
  bytes network_id = 1; AuthPin auth = 2; repeated GroupHead groups = 3; repeated GenHead gens = 4;
  repeated RefHead refs = 5; repeated bytes vetoes = 6; AuthPin proven = 7;
  repeated UnverifiedPin unverified = 8;
}

// sidecar/protocol/config.proto
// plan-SOCK-ksock-rotation #2's K_sock file, which the owner's answer gives with its numbers.
message SocketKeyFile { bytes current_key = 1; bytes previous_key = 2; int64 rotated_at_ms = 3; }
// plan-TEAM-config-head-format #1's fold records, which the owner's answer gives with their numbers.
message ConfigRecord { bytes id = 1; uint64 n = 2; int64 time_ms = 3; uint32 kind = 4; bytes body = 5; }
message ConfigFold { uint64 after = 1; uint64 folded_through = 2; repeated ConfigRecord records = 3; }
// §7.7's names file: the resolution names it a deterministically encoded protobuf and gives no fields, so these
// are TEAM-M2-08's reading, open until §7.9's records freeze.
message ConfigNameTable { repeated ConfigName names = 1; }
message ConfigName { bytes sidecar_id = 1; string name = 2; }
// plan-TEAM-config-head-format #1's tags, groups, rules, labels and resolve files, which the answers name as
// deterministically encoded protobufs: the tables plan-ACL-atom-and-rule-ids #1 and #3 and
// plan-ACL-selector-resolution describe, ACL-M2-04's reading of their fields, open until §7.9's records freeze.
message ConfigAtomTable { repeated ConfigAtomName atoms = 1; }
message ConfigAtomName { string name = 1; bytes atom_id = 2; }
message ConfigRuleTable { repeated ConfigRuleId rules = 1; }
message ConfigRuleId { bytes canonical_sha256 = 1; bytes rule_id = 2; }
message ConfigLabelTable { repeated ConfigRepoLabel labels = 1; }
message ConfigRepoLabel { string label = 1; bytes repo_id = 2; }
message ConfigResolution {
  repeated ConfigMemberResolution members = 1; repeated ConfigNetworkResolution networks = 2;
  repeated ConfigClientResolution clients = 3;
}
message ConfigMemberResolution { string email = 1; bytes member_id = 2; }
message ConfigNetworkResolution { string text = 1; bytes network_id = 2; }
message ConfigClientResolution { bytes client_id = 1; bytes sidecar_id = 2; }
// The bridge ledger's fold files beside fold/<d>/<i>, DESIGN-DETAILS 12.2.2's proto block's own numbers (complete
// 2026-11-11, QD-667), pending its fold into §17.8 and §7.9.
message BridgeLedgerManifest {
  uint32 format = 1; uint64 folded_through = 2; int64 time_ms = 3; uint32 rule_shard_bits = 4;
  repeated BridgeLedgerFile files = 5;
}
message BridgeLedgerFile { string path = 1; bytes sha256 = 2; uint64 row_count = 3; }
message BridgeLedgerAddresses { repeated BridgeLedgerAddressRow rows = 1; }
message BridgeLedgerAddressRow {
  uint32 host_bits = 1; bytes sidecar_id = 2; uint64 claimed_at = 3; uint64 released_at = 4; int64 released_ms = 5;
}
message BridgeLedgerRules { repeated BridgeLedgerRuleRow rows = 1; }
message BridgeLedgerRuleRow {
  bytes rule_id = 1; uint32 signed_type = 2; bytes owner = 3; uint64 first_at = 4; int64 first_ms = 5;
  uint64 newest_at = 6; int64 newest_ms = 7; BridgeLedgerDisposition disposition = 8; BridgeRouteBody route = 9;
  BridgeMapBody map = 10; repeated bytes route_rule_ids = 11; int64 expires = 12; bool standing = 13;
  bytes approval_id = 14; int64 approval_not_after_ms = 15; uint32 approval_uses = 16; uint64 withdrawn_at = 17;
  int64 withdrawn_ms = 18; BridgeWithdrawMode withdraw_mode = 19; bytes withdrawn_by = 20;
  bool withdrawn_by_admin = 21; int64 retain_until_ms = 22;
}
enum BridgeLedgerDisposition {
  BRIDGE_LEDGER_DISPOSITION_UNSPECIFIED = 0; BRIDGE_LEDGER_DISPOSITION_ACTIVE = 1; BRIDGE_LEDGER_DISPOSITION_VOID = 2;
  BRIDGE_LEDGER_DISPOSITION_WITHDRAWN = 3; BRIDGE_LEDGER_DISPOSITION_RESERVED = 4;
}
message BridgeLedgerEgressSpecs { repeated BridgeLedgerEgressRow rows = 1; }
message BridgeLedgerEgressRow {
  bytes subject = 1; BridgeEgressMode mode = 2; repeated bytes exit_sidecar_ids = 3; bytes exit_tag_id = 4;
  uint64 at = 5;
  // QD-1053 (question ur-tun-default-egress-admin-lock): the exits body's requirement, kept through a fold.
  bool require_default_egress = 6;
}
message BridgeLedgerAliases { repeated BridgeLedgerAliasRow rows = 1; }
message BridgeLedgerAliasRow {
  BridgeAliasBody body = 1; bytes signer = 2; uint64 at = 3; uint64 released_at = 4; int64 released_ms = 5;
}
// §7.8's client-only bundle, a field list without numbers.
message AuthKeyBundle {
  uint32 version = 1; bytes genesis_sha256 = 2; AuthPin head = 3; bytes delegation_id = 4;
  bytes delegation_signing_seed = 5; bytes delegation_reader_seed = 6; repeated bytes tag_ids = 7;
}

// sidecar/protocol/bridge/auth.proto
// §5.5's identity binding, as plan-CORE-binding-wire #1 numbers it.
message SidecarIdentityBinding {
  bytes network_id = 1; bytes sidecar_id = 2; bytes client_id = 3; int64 generation = 4;
  bytes client_public_key = 5; bytes identity_public_key = 6; int64 issued_at_ms = 7;
}
message SignedSidecarIdentityBinding { bytes body = 1; bytes client_signature = 2; bytes identity_signature = 3; }

// sidecar/protocol/bridge/bridge.proto
// Forwarding's setup messages between an app's VPN component and its sidecar role, DESIGN-DETAILS 4.2.2's proto
// block's own numbers (owner decision 197; §18.6).
message ForwardingKeys {
  bytes key_set_id = 1; bytes forward_public_key = 2; bytes reader_xwing_public_key = 3;
  bytes client_public_key = 4; bytes host_client_id = 5; bytes host_client_public_key = 6;
}
message ForwardingHandOff {
  Pending pending = 1; bytes key_set_id = 2; bytes forward_client_id = 3; string forward_client_jwt = 4;
  int64 strict_exp_ms = 5; bytes config_repo_id = 6; bytes config_group_id = 7; bytes signed_delegation = 8;
  AuthPin delegation_at = 9;
}

// sidecar/protocol/bridge/bridge.proto
// §17.8's opaque BridgeState.rules as BridgeRules and its rows, numbered as BRIDGE-M4-06 first wrote them
// (plan-BRIDGE-small-readings #2), and untagged as DESIGN-DETAILS 12.2.2 writes it (bridge-m4-09-other-client-rows).
// They never reach a server, so no §2.8 row.
message BridgeRules {
  BridgeIpv4Prefix block = 1; BridgeIpv4Prefix previous_block = 2; int64 previous_block_drain_until = 3;
  repeated fixed32 addresses = 4; repeated BridgeRuleEntry entries = 5; repeated BridgeRuleMap maps = 6;
  repeated BridgeRuleServed served = 7; repeated BridgeRuleSubject subjects = 8; BridgeRuleEgress egress = 9;
  BridgeRuleSubject untagged = 10; repeated BridgeRuleShare shares = 11;
}
message BridgeRuleEntry {
  BridgeIpv4Prefix prefix = 1; BridgeRuleEntryKind kind = 2; repeated BridgeRuleLink links = 3;
}
message BridgeRuleLink {
  bytes target_client_id = 1; bytes target_sidecar_id = 2; bytes target_identity_public_key = 3;
  bytes target_member_id = 4; bytes rule_id = 5; uint32 weight = 6; bytes site_id = 7; int64 draining_since = 8;
  int64 drain_until = 9; bytes share_id = 10; bytes target_network_id = 11; bytes target_client_public_key = 12;
}
message BridgeRuleMap {
  bytes map_id = 1; BridgeIpv4Prefix match_prefix = 2; uint32 protocol = 3; repeated BridgePortRange ports = 4;
  bytes target = 5; uint32 target_port = 6; int64 expires = 7; int64 draining_since = 8; int64 drain_until = 9;
}
message BridgeRuleServed {
  bytes route_id = 1; BridgeRouteKind kind = 2; BridgeIpv4Prefix prefix = 3; BridgeIpv4Prefix exposed_prefix = 4;
  int64 draining_since = 5; int64 drain_until = 6;
}
message BridgeRuleSubject {
  bytes sidecar_id = 1; bytes member_id = 2; repeated bytes client_ids = 3; bool tagged = 4;
  repeated BridgeRuleReach dial = 5; repeated BridgeRuleReach route = 6; repeated BridgeRuleReach exit = 7;
}
message BridgeRuleReach {
  bytes grant_id = 1; BridgeIpv4Prefix prefix = 2; uint32 protocol = 3; repeated BridgePortRange ports = 4;
  int64 expires = 5;
}
message BridgeRuleEgress {
  BridgeEgressMode mode = 1; repeated BridgeRuleLink exits = 2;
  // QD-1053 (question ur-tun-default-egress-admin-lock): the spec's requirement of default egress, for ur tun.
  bool require_default_egress = 3;
}
// §17.9's shares as the rows a host compiles a share to, as DESIGN-DETAILS 12.2.2 writes them (QD-077, QD-108,
// QD-670), landing with BridgeRules' shares; §17.9's fences write X's pin and the share seal's bodies. In-process
// rows: none reaches a server.
message BridgeRuleShare {
  bytes share_id = 1; bytes accepting_network_id = 2; bytes share_public_key = 3; bytes grant_id = 4;
  int64 expires = 5; repeated BridgeRuleShareTarget targets = 6;
}
message BridgeRuleShareTarget {
  uint32 index = 1; uint32 alias_host_bits = 2; uint32 length = 3; BridgeIpv4Prefix target = 4;
  uint32 protocol = 5; repeated BridgePortRange ports = 6;
}
enum BridgeRuleEntryKind {
  BRIDGE_RULE_ENTRY_KIND_UNSPECIFIED = 0; BRIDGE_RULE_ENTRY_KIND_LINK = 1; BRIDGE_RULE_ENTRY_KIND_UNASSIGNED = 2;
  BRIDGE_RULE_ENTRY_KIND_CARVED = 3; BRIDGE_RULE_ENTRY_KIND_SERVICE = 4;
}

// sidecar/protocol/gkm.proto
// §10.5's list; not_after holds ms, so it stays 64 bits.
message ReaderKey { bytes sidecar_id = 1; bytes xwing_public_key = 2; int64 not_after = 3; }
// §10.14's list and kinds.
message GkmHint { bytes group_id = 1; uint64 epoch = 2; GkmHintKind kind = 3; bytes recipient = 4; }
enum GkmHintKind {
  GKM_HINT_KIND_UNSPECIFIED = 0; GKM_HINT_COMMIT = 1; GKM_HINT_PENDING = 2; GKM_HINT_WELCOME = 3;
  GKM_HINT_KEY_PACKAGES_LOW = 4; GKM_HINT_WRAP_PENDING = 5;
}
// §10.14's routes: POST /gkm/key-packages and .../claim; POST /gkm/groups, as KF1 writes it; POST
// /gkm/repos/<id>/forms, with 10.8's epoch 0; GET /gkm/groups/<id>; POST .../epochs/<n>; GET .../epochs, with sizes.
message GkmKeyPackagesRequest { repeated bytes key_packages = 1; }
message GkmKeyPackageClaimRequest { bytes group_id = 1; bytes target = 2; }
message GkmKeyPackageClaimReply { bytes key_package_ref = 1; bytes key_package = 2; }
message GkmGroupCreateRequest {
  Signed form = 1; Signed gen_rotate = 2; bytes gen_wrap = 3; bytes sealed_group_info = 4;
  uint32 cipher_suite = 5;
}
message GkmGroupReformRequest {
  Signed form = 1; bytes gen_wrap = 2; bytes sealed_group_info = 3; uint32 cipher_suite = 4;
}
message GkmGroupReply { Signed form = 1; }
message GkmEpochRequest {
  bytes commit = 1; bytes gen_wrap = 2; bytes sealed_group_info = 3; uint64 group_info_generation = 4;
}
message GkmEpochEntry { uint64 epoch = 1; uint64 size = 2; GkmEpochObject object = 3; }
message GkmEpochsReply { repeated GkmEpochEntry epochs = 1; }
// §10.14's GET .../gen and .../drop-key; GET /gkm/repos/<id>/forms, which §10.14 lacks and members need; POST
// .../ladder, which a re-form's ladder needs; and POST /gkm/reader-keys, for a rotator's batches.
message GkmGenerationsReply { repeated Signed generations = 1; }
message GkmFormsReply { repeated Signed forms = 1; }
message GkmLadderRequest { repeated Signed generations = 1; }
message GkmReaderKeysRequest { repeated bytes sidecar_ids = 1; }
message GkmReaderKeysReply { repeated Signed reader_keys = 1; }
// POST /gkm/delegation-keys (QD-637), a config rotator's batches of forwarding Delegations' reader keys.
message GkmDelegationKeysRequest { repeated bytes delegation_ids = 1; }
message GkmDelegationKeysReply { repeated bytes reader_keys = 1; }
// §10.14's POST .../wraps/<g>/<c8>, batched, and GET .../wraps/<g>; POST .../welcome/<n>, for gkm-5's recipients, and
// GET /gkm/welcomes; POST .../ack, for gkm-10; GET and POST /gkm/recovery/<member_id>/wraps, for gkm-8; and POST
// .../recovery-wraps/<g>/<c8>, a rotator's batches.
message GkmWrapBatch { repeated bytes deliveries = 1; }
message GkmWrapResult { uint32 status = 1; bytes winner = 2; }
message GkmWrapBatchReply { repeated GkmWrapResult results = 1; }
message GkmWrapsReply { repeated Signed wraps = 1; }
message GkmWelcomeRecipient { bytes sidecar_id = 1; bytes key_package_ref = 2; }
message GkmWelcomeRequest { bytes welcome = 1; repeated GkmWelcomeRecipient recipients = 2; }
message GkmWelcomeEntry { bytes key_package_ref = 1; GkmWelcomePointer pointer = 2; bytes welcome = 3; }
message GkmWelcomesReply { repeated GkmWelcomeEntry welcomes = 1; }
message GkmAckRequest { uint64 epoch = 1; }
message GkmRecoveryWrap {
  bytes group_id = 1; uint64 generation = 2; bytes commitment_prefix = 3; bytes binding_prefix = 4;
  bytes ciphertext = 5;
}
message GkmRecoveryWrapsReply { repeated GkmRecoveryWrap wraps = 1; }
message GkmRecoveryWrapItem { bytes member_id = 1; bytes binding_prefix = 2; bytes ciphertext = 3; }
message GkmRecoveryWrapBatch { repeated GkmRecoveryWrapItem items = 1; }

// sidecar/protocol/evs.proto
// §11.10's list.
message EvsHeadChanged { bytes ref_id = 1; uint64 version = 2; bytes chain = 3; bytes push_id = 4; }
// EvsPush.flags', EvsLocator.kind's and EvsEntryVersion.versioning's comments and §11.8's entry row, numbers as
// written, so that D-PHASE-9's reservations are numbers a lint can read.
enum EvsPushFlag {
  EVS_PUSH_FLAG_NONE = 0; EVS_PUSH_FORCE = 1; EVS_PUSH_DELETE = 2; EVS_PUSH_BASE = 4; EVS_PUSH_IMMUTABLE = 8;
  EVS_PUSH_CONSUME = 16; EVS_PUSH_PATH_EPOCH = 32; EVS_PUSH_ERASE = 64; EVS_PUSH_CLOSURE = 128;
  EVS_PUSH_DROP = 256; EVS_PUSH_CUT = 512;
}
enum EvsLocatorKind {
  EVS_LOCATOR_KIND_UNSPECIFIED = 0; EVS_LOCATOR_SEGMENT = 1; EVS_LOCATOR_INLINE = 2;
  reserved 3, 4;
  EVS_LOCATOR_VERSIONLESS_SEGMENT = 5;
}
enum EvsVersioning { EVS_VERSIONING_KEPT = 0; EVS_VERSIONING_VERSIONLESS = 1; EVS_VERSIONING_INDEX = 2; }
enum EvsWindowFlag {
  EVS_WINDOW_FLAG_NONE = 0; EVS_WINDOW_CREATES_PATH = 1; EVS_WINDOW_CHANGES_IN_PAYLOAD = 2;
  EVS_WINDOW_PATH_EPOCH = 4; EVS_WINDOW_REWRITES_HISTORY = 8; EVS_WINDOW_VERSIONLESS_REPLACED = 16;
  EVS_WINDOW_DROP = 32;
}
// plan-EVS1-format-bytes's answer, rows 3 and 6 to 9, the answers EVS-FORMAT.md cites beside it, and what that file
// proposes past them, as it says: 11.8's refs table, EvsPush.ref_mode's comment, the kinds of entries, records, key
// refs and oids, 11.8's record row, 11.6's payload row, 11.12's state row, 11.8's code table and 503, 11.9's states and
// request row.
enum EvsRefKind {
  EVS_REF_KIND_UNSPECIFIED = 0; EVS_REF_SHARED = 1; EVS_REF_OWNED = 2; EVS_REF_DEPOSIT = 3; EVS_REF_ERASURE = 4;
}
enum EvsRefMode { EVS_REF_MODE_UNSPECIFIED = 0; EVS_REF_GIT = 1; EVS_REF_FILE = 2; }
enum EvsEntryKind { EVS_ENTRY_KIND_UNSPECIFIED = 0; EVS_ENTRY_FILE = 1; EVS_ENTRY_DIRECTORY = 2; }
enum EvsRecordKind {
  EVS_RECORD_KIND_UNSPECIFIED = 0; EVS_RECORD_CHECKPOINT = 1; EVS_RECORD_DIFF = 2; EVS_RECORD_CHUNK = 3;
}
enum EvsKeyRefKind { EVS_KEY_REF_CONTAINER = 0; EVS_KEY_REF_SLOT = 1; }
enum EvsOidKind { EVS_OID_KIND_UNSPECIFIED = 0; EVS_OID_SHA1 = 1; EVS_OID_SHA256 = 2; }
enum EvsBatchRecordType {
  EVS_BATCH_RECORD_TYPE_UNSPECIFIED = 0; EVS_BATCH_PUSH = 1; EVS_BATCH_PART = 2; EVS_BATCH_SEAL = 3;
  EVS_BATCH_RESEED = 4;
}
enum EvsPayloadSection {
  EVS_PAYLOAD_SECTION_UNSPECIFIED = 0; EVS_PAYLOAD_ENTRY_VERSIONS = 1; EVS_PAYLOAD_SEALED_METADATA = 2;
  EVS_PAYLOAD_INLINE_RECORDS = 3; EVS_PAYLOAD_CHANGE_LIST = 4; EVS_PAYLOAD_PART_HASHES = 5;
  EVS_PAYLOAD_NEW_OBJECTS = 6; EVS_PAYLOAD_SLOT_BODIES = 7; EVS_PAYLOAD_ERASED_LIST = 8; EVS_PAYLOAD_DROP_BODY = 9;
  EVS_PAYLOAD_DROP_LISTS = 10; EVS_PAYLOAD_TAIL_MOVES = 11; EVS_PAYLOAD_SOURCE_PATHS = 12;
  EVS_PAYLOAD_REUSE_LIST = 13; EVS_PAYLOAD_MERKLE_PROOFS = 14;
  // DESIGN-DETAILS 8.2.2's sections row: a creating push's sealed ref name and overlay base (question
  // evs1-m2-01-ref-creation-fields, option 1)
  EVS_PAYLOAD_REF_NAME = 15; EVS_PAYLOAD_OVERLAY_BASE = 16;
}
// DESIGN-DETAILS 8.2.2's git update shapes.
enum EvsGitShape { EVS_GIT_SHAPE_UNSPECIFIED = 0; EVS_GIT_UPDATE = 1; EVS_GIT_DELETE = 2; EVS_GIT_REKEY = 3; }
enum EvsNewObjectKind {
  EVS_NEW_OBJECT_KIND_UNSPECIFIED = 0; EVS_NEW_OBJECT_SEGMENT = 1; EVS_NEW_OBJECT_STAGED_SEGMENT = 2;
  EVS_NEW_OBJECT_SLOT = 3;
}
enum EvsRepoState {
  EVS_REPO_STATE_UNSPECIFIED = 0; EVS_REPO_KEYING = 1; EVS_REPO_ACTIVE = 2; EVS_REPO_DELETED = 3;
  EVS_REPO_SHREDDING = 4; EVS_REPO_SHREDDED = 5;
}
enum EvsRefusalCode {
  EVS_REFUSAL_CODE_UNSPECIFIED = 0; EVS_REFUSAL_SCOPE = 1; EVS_REFUSAL_TIME_STALE = 2; EVS_REFUSAL_REPO_KEYING = 3;
  EVS_REFUSAL_REPO_DELETED = 4; EVS_REFUSAL_QUOTA_PAYMENT = 5; EVS_REFUSAL_QUOTA_LIMIT = 6;
  EVS_REFUSAL_CLUSTER_FULL = 7; EVS_REFUSAL_GATE_CLOSED = 8; EVS_REFUSAL_INDEX_EPOCH = 9; EVS_REFUSAL_MAP_PARTS = 10;
  EVS_REFUSAL_EPOCH_SOURCES_FULL = 11; EVS_REFUSAL_PATH_EPOCH_DUE = 12; EVS_REFUSAL_DIRECTORY_FULL = 13;
  EVS_REFUSAL_SEGMENT_GONE = 14; EVS_REFUSAL_VERSIONING = 15; EVS_REFUSAL_SLOT_UNKNOWN = 16;
  EVS_REFUSAL_SLOT_STALE = 17; EVS_REFUSAL_NOTHING_TO_ERASE = 18; EVS_REFUSAL_DROPPED = 19;
  EVS_REFUSAL_DROP_PATH = 20; EVS_REFUSAL_DROP_CONSENT = 21; EVS_REFUSAL_DROP_STATE = 22;
  EVS_REFUSAL_DROP_BOUNDARY = 23; EVS_REFUSAL_DROP_LIST = 24; EVS_REFUSAL_FORMAT_UNSUPPORTED = 25;
  EVS_REFUSAL_REF_MODE = 64; EVS_REFUSAL_PUSH_ID_REUSED = 65; EVS_REFUSAL_NON_FAST_FORWARD = 66;
  EVS_REFUSAL_BASE_STALE = 67; EVS_REFUSAL_PATH_CONFLICT = 68; EVS_REFUSAL_PATH_EPOCH = 69;
  EVS_REFUSAL_SHREDDING = 70; EVS_REFUSAL_DROP_KIND = 71; EVS_REFUSAL_SEGMENT_STALE = 72;
  EVS_REFUSAL_STATEMENT_MISSING = 73; EVS_REFUSAL_GROUP_NOT_READY = 74; EVS_REFUSAL_MAP_SOURCE = 75;
  // 11.8's codes row: the placement's 409 and every 401 (owner decision 411; question
  // evs1-m2-07-placement-refusal-code, QD-927)
  EVS_REFUSAL_REPO_PLACED = 76;
  EVS_REFUSAL_INVALID = 128; EVS_REFUSAL_NOT_FOUND = 129; EVS_REFUSAL_PARTS_MISSING = 130; EVS_REFUSAL_BUSY = 131;
  EVS_REFUSAL_FOLD_BEHIND = 132; EVS_REFUSAL_TIME_AHEAD = 133; EVS_REFUSAL_RESOURCE_EXHAUSTED = 134;
  EVS_REFUSAL_WAIT = 135; EVS_REFUSAL_UNAVAILABLE = 136; EVS_REFUSAL_UNAUTHENTICATED = 137;
}
enum EvsPushOutcome { EVS_PUSH_OUTCOME_SETTLED = 0; EVS_PUSH_OUTCOME_UNKNOWN = 1; }
enum EvsReadPathState {
  EVS_READ_PATH_STATE_UNSPECIFIED = 0; EVS_READ_PATH_COLLECTED = 1; EVS_READ_PATH_DROP_PENDING = 2;
  EVS_READ_PATH_DROPPED = 3;
}
enum EvsReadObjectKind {
  EVS_READ_OBJECT_KIND_UNSPECIFIED = 0; EVS_READ_OBJECT_SEGMENT = 1; EVS_READ_OBJECT_SLOT = 2;
  EVS_READ_OBJECT_MAP_PART = 3; EVS_READ_OBJECT_LOG_PAGE = 4; EVS_READ_OBJECT_BATCH_RECORD = 5;
  // QD-725 (question evsb-m2-19-reseed-route-body): the ref's Signed EvsReseed, served with the head.
  EVS_READ_OBJECT_RESEED = 6;
}
// 11.8's repo/, place and slot/ rows, by plan-EVS1-format-bytes#9 and plan-EVSB-repo-network.
message EvsRepoObject {
  bytes repo_id = 1; RepoKind kind = 2; bytes owner_member_id = 3; EvsRepoState state = 4; int64 state_ms = 5;
  bytes state_signer = 6; bytes deletion_id = 7; uint32 format = 8; bytes sealed_name = 9; bytes network_id = 10;
}
message EvsRepoPlacement { string cluster_id = 1; bytes creator_sidecar_id = 2; }
// 11.13's index row, by EVSB-M2-10's plan line: pidx/ entries and the containers they name.
message EvsPidxEntry {
  EvsContainerKind container_kind = 1; bytes container_id = 2; uint64 first_version = 3; uint64 last_version = 4;
  repeated EvsPidxRecord records = 5; repeated EvsPidxLogPage log_pages = 6; repeated bytes segment_ids = 7;
}
message EvsPidxRecord { uint64 version = 1; EvsBatchRecordType type = 2; uint64 offset = 3; uint32 length = 4; EvsPlace place = 5; }
message EvsPidxLogPage { uint64 page = 1; uint64 offset = 2; uint32 length = 3; }
enum EvsContainerKind { EVS_CONTAINER_KIND_UNSPECIFIED = 0; EVS_CONTAINER_PACK = 1; EVS_CONTAINER_PARCEL = 2; }
message EvsSlotObject { repeated EvsSlotKey keys = 1; }
message EvsSlotKey { uint32 key_index = 1; uint64 generation = 2; bytes wrapped = 3; }
// 11.7's index entries, removal row and drop mark, by plan-EVS1-format-bytes#9.
message EvsIndexEntry {
  repeated EvsIndexVersion versions = 1; EvsNameTable names = 2; uint64 names_through = 3;
  EvsRemovalMarker marker = 4; EvsDropMark drop_mark = 5; uint32 names_leaf_part = 7; uint32 names_leaf_index = 8;
}
// DESIGN-DETAILS 9.2.2's leaf places, on the versions, markers and tables a fold writes (question
// details-9-index-leaf).
message EvsIndexVersion {
  bytes push_id = 1; uint64 commit_version = 2; bytes entry_version = 3; bool elided = 4; uint32 leaf_part = 5;
  uint32 leaf_index = 6;
}
message EvsRemovalMarker {
  bytes push_id = 1; uint64 removal_version = 2; uint64 path_version = 3; repeated bytes segment_ids = 4;
  repeated bytes slot_ids = 5; uint32 leaf_part = 6; uint32 leaf_index = 7;
}
message EvsDropMark { bytes drop_id = 1; uint64 through_version = 2; }
// 11.8's log/ row.
message EvsLogPage {
  uint64 page = 1; bytes first_chain = 2; bytes last_chain = 3; bytes window = 4; repeated bytes statements = 5;
}
// What EvsEntryVersion.sealed_fields opens to, by its comment and plan-EVS1-format-bytes#9, and the messages a push's
// sealed metadata holds, from EvsPush.sealed_metadata_sha256's comment, 11.6's records row and 11.7's mapping to git;
// §11.6's fence writes EvsSealedMetadata itself.
message EvsSealedFields {
  bytes file_id = 1; uint32 mode = 2; bytes git_oid = 3; EvsOidKind oid_kind = 4; uint64 size = 5;
  bytes content_sha256 = 6;
}
message EvsGitUpdate {
  EvsGitShape shape = 1; bytes old_tip = 2; bytes new_tip = 3; repeated bytes tags = 4;
  repeated EvsOverlay sources = 5; repeated bytes segment_ids = 6; repeated EvsSealedBlob blobs = 7;
}
message EvsSealedBlob {
  bytes git_oid = 1; uint64 size = 2; bytes base_oid = 3; bytes file_id = 4; repeated EvsHistoryLocator records = 5;
}
message EvsHistoryLocator { uint32 segment = 1; uint32 offset = 2; uint32 length = 3; }
message EvsProvenance {
  bytes agent_id = 1; bool tainted = 2; bytes agent_cert = 3; bytes agent_key_id = 4; bytes agent_signature = 5;
}
// DESIGN-DETAILS 8.2.2 adds trees: a commit's trees that do not rebuild from names, modes and oids.
message EvsSealedCommit { bytes object = 1; repeated EvsSealedChange changes = 2; repeated EvsSealedTree trees = 3; }
message EvsSealedTree { repeated bytes path = 1; bytes object = 2; }
message EvsSealedChange { repeated bytes path = 1; uint32 mode = 2; bytes git_oid = 3; }
// 11.8's push, parts, seal and lease rows and 11.20's refusals, by plan-EVS1-format-bytes#8, with
// plan-EVS1-deposit-head's and plan-RECORD-depositor-spool's deposit head and §20.7's QuotaRefusal.
message EvsPushRequest {
  bytes statement = 1; bytes payload = 2; repeated EvsUploadReceipt receipts = 3; bytes staged = 4;
  repeated EvsPlace part_places = 5;
  // QD-819 (question push-record-no-slot-bodies-part-slot-bodies): a seal's slot bodies, section 7, in no part.
  bytes slot_bodies = 6;
}
message EvsPartRequest {
  bytes statement = 1; bytes part = 2; repeated EvsUploadReceipt receipts = 3; bytes staged = 4;
}
// 11.13's re-seed row's body, the owner's answer to evsb-m2-19-reseed-route-body (QD-725).
message EvsReseedRequest {
  bytes statement = 1; bytes payload = 2; repeated bytes parts = 3; bytes slot_id = 4; bytes slot = 5;
  // QD-836 (question evs-reseed-parts-request-bound): a push in parts goes one part a call, then a seal naming the
  // parts' places.
  uint32 part_number = 6; repeated EvsPlace part_places = 7;
}
message EvsLeaseRequest { bytes ref_id = 1; uint64 base_version = 2; uint32 ms = 3; }
// 11.6's map and block rows and 11.10's lease row, whose bodies plan-EVS1-format-bytes#8 does not list: proposed by
// EVS1-M2-15 and EVS1-M2-16, in the order the rows write their fields.
message EvsPathMapRequest { bytes path_map_sha256 = 1; bytes part = 2; }
message EvsPathEpochBlockRequest { bytes ref_id = 1; uint32 ms = 2; }
message EvsSubscriptionRequest {
  bytes repo_id = 1; bytes ref_id = 2; uint64 path_epoch = 3; repeated EvsTokenPath prefixes = 4;
}
message EvsSubscription { bytes ref_id = 1; uint64 path_epoch = 2; EvsTokenPath prefix = 3; int64 expires_ms = 4; }
message EvsSubscriptionsReply { repeated EvsSubscription subscriptions = 1; }
message EvsPushReply { uint64 version = 1; EvsPlace place = 2; EvsDepositHead deposit_head = 3; }
message EvsRefusalReply {
  bytes push_id = 1; EvsRefusalCode code = 2; bool recorded = 3; uint32 retry_after_ms = 4;
  repeated EvsTokenPath paths = 5; EvsPushOutcome outcome = 6; uint32 needs_format = 7; EvsQuotaRefusal quota = 8;
  EvsDepositHead deposit_head = 9;
}
message EvsQuotaRefusal {
  string limit_key = 1; int64 limit = 2; int64 used = 3; uint32 retry_after_ms = 4; bool upgrade = 5;
}
message EvsDepositHead { uint64 version = 1; bytes chain = 2; uint64 consumed_through = 3; }
// 11.9's request, streams and reply rows, by plan-EVS1-format-bytes#8 and protos-services-read-states; held_drops is
// DESIGN-DETAILS 10.2.2's.
message EvsReadRequest {
  bytes ref_id = 1; uint64 pin_version = 2; bool fresh = 3; repeated EvsReadPath paths = 4;
  repeated EvsReadRange ranges = 5; repeated bytes slot_ids = 6; repeated EvsReadMap maps = 7;
  repeated uint64 log_pages = 8; repeated EvsReadPush pushes = 9; repeated EvsReadRef refs = 10;
  repeated uint64 held_drops = 11;
}
// DESIGN-DETAILS 9.2.2: a read's commit_version.
message EvsReadPath { repeated EvsSourcePath token_paths = 1; uint64 version = 2; uint64 commit_version = 3; }
message EvsReadRange { bytes segment_id = 1; uint32 offset = 2; uint32 length = 3; }
message EvsReadMap { uint64 path_epoch = 1; bytes map_sha256 = 2; uint32 part = 3; }
message EvsReadPush { bytes push_id = 1; uint64 version = 2; uint32 part = 3; }
message EvsReadRef { bytes ref_id = 1; uint64 pin_version = 2; }
message EvsHeadSummary {
  bytes ref_id = 1; uint64 version = 2; bytes chain = 3; bytes push_id = 4; EvsRefKind ref_kind = 5;
  EvsRefMode ref_mode = 6; bytes owner_sidecar_id = 7; bytes sealed_ref_name = 8; EvsOverlay base = 9;
  AuthPin auth = 10; bytes group_id = 11; uint64 generation = 12; bytes generation_commitment = 13;
  EvsPathEpoch path_epoch = 14; uint64 index_epoch = 15; bool deleted = 16; uint64 push_sequence = 17;
}
message EvsReadStatement { uint64 version = 1; bytes statement = 2; }
message EvsMerkleProof { bytes leaf = 1; uint64 index = 2; uint64 size = 3; repeated bytes path = 4; }
message EvsReadObject {
  EvsReadObjectKind kind = 1; bytes id = 2; uint64 number = 3; uint32 offset = 4; bytes body = 5; bool missing = 6;
}
// 11.9's moved row and 11.10's sequence and gap rows.
message EvsRefsReply { uint32 format = 1; uint64 push_sequence = 2; repeated EvsHeadSummary refs = 3; bool all = 4; }
message EvsLogReply { repeated EvsReadStatement statements = 1; uint64 next_version = 2; }
// Format 2's chapter (EVS-FORMAT.md, EVS2-M10-01): 11.13's purge row and 11.20's drop routes, with 11.9's dropped
// row's DROP statement and body above, proposed until M10's entry review; replaced, EVS_DROP_HORIZON, map_parts and
// linked are DESIGN-DETAILS 10.2.2's.
message EvsPurgeList { repeated EvsPurgeCandidate candidates = 1; bool marked = 2; bool replaced = 3; }
message EvsPurgeCandidate {
  repeated bytes token_path = 1; uint64 replaced_version = 2; repeated bytes segment_ids = 3;
  repeated bytes staged_segment_ids = 4; repeated bytes slot_ids = 5;
}
enum EvsDropState {
  EVS_DROP_STATE_UNSPECIFIED = 0; EVS_DROP_PENDING = 1; EVS_DROP_CANCELLED = 2; EVS_DROP_EXECUTING = 3;
  EVS_DROP_DONE = 4; EVS_DROP_REFUSED = 5; EVS_DROP_OBSERVED = 6;
}
enum EvsDropPhase {
  EVS_DROP_PHASE_UNSPECIFIED = 0; EVS_DROP_RESOLVE = 1; EVS_DROP_MARK = 2; EVS_DROP_VERIFY = 3; EVS_DROP_DELETE = 4;
  EVS_DROP_HORIZON = 5;
}
enum EvsDropRefusal {
  EVS_DROP_REFUSAL_UNSPECIFIED = 0; EVS_DROP_REFUSAL_LOCKED = 1; EVS_DROP_REFUSAL_MISMATCH = 2;
  EVS_DROP_REFUSAL_VERIFY = 3;
}
enum EvsDropPreviewState {
  EVS_DROP_PREVIEW_STATE_UNSPECIFIED = 0; EVS_DROP_PREVIEW_QUEUED = 1; EVS_DROP_PREVIEW_RUNNING = 2;
  EVS_DROP_PREVIEW_DONE = 3; EVS_DROP_PREVIEW_FAILED = 4;
}
message EvsDropStatus {
  bytes drop_id = 1; bytes ref_id = 2; bytes push_id = 3; uint64 version = 4; int64 not_before_ms = 5;
  EvsDropState state = 6; EvsDropPhase phase = 7; uint64 progress = 8; uint64 progress_total = 9;
  EvsDropRefusal reason = 10; uint64 freed_bytes = 11; bytes preview_id = 12;
}
message EvsDropsReply { repeated EvsDropStatus drops = 1; }
message EvsDropPreviewRequest { bytes ref_id = 1; repeated EvsDropPath paths = 2; }
message EvsDropPreviewReply {
  bytes preview_id = 1; EvsDropPreviewState state = 2; uint64 progress = 3; uint64 progress_total = 4;
  repeated EvsDropPreviewPath paths = 5; uint64 freed_bytes = 6; uint64 shared_bytes = 7; uint64 inline_bytes = 8;
  uint64 packed_bytes = 9; uint64 young_bytes = 10; uint64 snapshot_version = 11; int64 snapshot_ms = 12;
}
message EvsDropPreviewPath { bool list_match = 1; uint32 count = 2; repeated uint32 map_parts = 3; bool linked = 4; }

// sidecar/protocol/socket.proto
// §9.5's Claim, the tuple its comment lists, in that order, its name or token path written as SocketTicket's two.
message SocketRegistrationClaim {
  bytes network_id = 1; string name = 2; bytes name_token = 3; bytes listen_id = 4; string protocol = 5;
  string app_mode = 6;
}

// sidecar/protocol/core.proto
// plan-CORE-core-hint-body #1's CoreHint and its kinds, PushHint.hint's body on topic core, and QD-159's agent subkey
// certificate, its fields in the order the owner's answer lists them.
message CoreHint { CoreHintKind kind = 1; bytes sidecar_id = 2; uint32 min_secure_version = 3; }
enum CoreHintKind {
  CORE_HINT_KIND_UNSPECIFIED = 0; CORE_HINT_KIND_REVOCATION = 1; CORE_HINT_KIND_RESYNC = 2; CORE_HINT_KIND_WAKE = 3;
  CORE_HINT_KIND_MIN_SECURE = 4; CORE_HINT_KIND_GATES = 5;
}
message AgentCert { bytes sidecar_id = 1; bytes agent_id = 2; bytes public_key = 3; int64 not_after_ms = 4; }

// sidecar/protocol/mail.proto
// MailAuthEvidence's comments, which name each result's fields in this order.
message SpfResult { SpfVerdict result = 1; string domain = 2; bytes ip = 3; repeated string records = 4; }
message DkimResult { string domain = 1; string selector = 2; DkimVerdict result = 3; bytes public_key = 4; }
message DmarcResult {
  string p = 1; string adkim = 2; string aspf = 3; uint32 alignment = 4; DmarcVerdict result = 5;
}
message ArcSet { string domain = 1; string selector = 2; bytes public_key = 3; }
message ArcResult { ArcVerdict cv = 1; repeated ArcSet sets = 2; }
enum SpfVerdict {
  SPF_VERDICT_UNSPECIFIED = 0; SPF_PASS = 1; SPF_FAIL = 2; SPF_SOFTFAIL = 3; SPF_NEUTRAL = 4; SPF_NONE = 5;
  SPF_TEMPERROR = 6; SPF_PERMERROR = 7; SPF_INCOMPLETE = 8;
}
enum DkimVerdict {
  DKIM_VERDICT_UNSPECIFIED = 0; DKIM_PASS = 1; DKIM_FAIL = 2; DKIM_PERMERROR = 3; DKIM_TEMPERROR = 4;
  DKIM_INCOMPLETE = 5;
}
enum DmarcVerdict {
  DMARC_VERDICT_UNSPECIFIED = 0; DMARC_PASS = 1; DMARC_FAIL = 2; DMARC_NONE = 3; DMARC_TEMPERROR = 4;
}
enum ArcVerdict { ARC_VERDICT_UNSPECIFIED = 0; ARC_NONE = 1; ARC_PASS = 2; ARC_FAIL = 3; ARC_INCOMPLETE = 4; }
// §15.15's field list and kinds, with plan-MAIL-format-bytes#2's host.
message MailHint { MailHintKind kind = 1; string host = 2; }
enum MailHintKind { MAIL_HINT_KIND_UNSPECIFIED = 0; MAIL_HINT_DEPOSIT = 1; MAIL_HINT_RECEIVER_NEEDED = 2; }
// §15.7's deposit list.
message MailDeposit {
  uint32 version = 1; MailIngress ingress = 2; MailAuthEvidence evidence = 3; bytes mail_from = 4;
  bool require_tls = 5; repeated string recipients = 6; uint32 tls_version = 7; uint32 tls_suite = 8;
  bytes receiver_sidecar_id = 9;
}
// §15.7's addr/ and burner/ lists, with their kinds and states.
message MailAddress {
  MailAddressKind kind = 1; bytes mailbox = 2; repeated bytes members = 3; bytes creator = 4;
  bytes effect_key = 5;
}
enum MailAddressKind {
  MAIL_ADDRESS_KIND_UNSPECIFIED = 0; MAIL_ADDRESS_ADMIN = 1; MAIL_ADDRESS_ID = 2; MAIL_ADDRESS_GROUP = 3;
  MAIL_ADDRESS_AGENT = 4; MAIL_ADDRESS_BURNER = 5; MAIL_ADDRESS_BOUNCE = 6;
}
message MailBurner {
  bytes mailbox = 1; MailBurnerState state = 2; bool replying = 3; uint64 created = 4; bytes effect_key = 5;
}
enum MailBurnerState {
  MAIL_BURNER_STATE_UNSPECIFIED = 0; MAIL_BURNER_LIVE = 1; MAIL_BURNER_PAUSED = 2; MAIL_BURNER_BURNED = 3;
}
// §15.7's i/ list and attachments; auth_results as MAIL-FORMAT.md reads it; §15.5's labels and D-MAIL-8's signature;
// §15.7's tls_basis list and rules; and the i/ row's container, which MAIL-FORMAT.md states.
message IndexEntry {
  bytes id = 1; string address = 2; uint64 time = 3; string from = 4; string subject = 5; string snippet = 6;
  string message_id = 7; bytes thread_key = 8; uint64 size = 9; repeated MailAttachment attachments = 10;
  MailAuthResults auth_results = 11; MailTlsLabel tls_label = 12; MailTlsBasis tls_basis = 13;
  uint32 spam_score = 14; string one_time_code = 15;
}
message MailAttachment { string name = 1; string type = 2; uint64 size = 3; }
message MailAuthResults {
  SpfVerdict spf = 1; DkimVerdict dkim = 2; DmarcVerdict dmarc = 3; ArcVerdict arc = 4;
  bool checks_incomplete = 5; bool evidence_unavailable = 6;
}
enum MailTlsLabel {
  MAIL_TLS_LABEL_UNSPECIFIED = 0; MAIL_TLS_VALIDATED = 1; MAIL_TLS_OPPORTUNISTIC = 2;
  MAIL_TLS_MEMBER_SIGNED = 3;
}
enum MailTlsRule { MAIL_TLS_RULE_UNSPECIFIED = 0; MAIL_TLS_RULE_REQUIRETLS = 1; MAIL_TLS_RULE_OPERATOR = 2; }
message MailTlsBasis {
  MailTlsRule rule = 1; string operator_id = 2; uint32 list_version = 3; bool strict_custom_mx = 4;
}
message MailIndexSegment { repeated IndexEntry entries = 1; }
// §15.7's f/ kinds, and the f/ row's op and container, as plan-MAIL-format-bytes#5 numbers them, one clock field
// holding its hlc_ms and hlc_count.
enum MailFlagKind {
  MAIL_FLAG_KIND_UNSPECIFIED = 0; MAIL_FLAG_SEEN = 1; MAIL_FLAG_FLAGGED = 2; MAIL_FLAG_LABEL = 3;
  MAIL_FLAG_TRASH = 4;
}
message MailFlagOp {
  reserved 6;
  bytes message_id = 1; MailFlagKind op = 2; bool set = 3; string label = 4; uint64 hlc = 5;
  bytes sidecar_id = 7;
}
message MailFlagSegment { repeated MailFlagOp ops = 1; }
// §15.7's r/ row, as plan-MAIL-format-bytes#5 names it.
message MailGroupRef { bytes repo_id = 1; bytes message_id = 2; }
// §15.8's list, its state, whose burned is §15.9's, its totp list, by RFC 6238's hashes, and its used_at list.
message VaultEntry {
  bytes entry_id = 1; string address = 2; string title = 3; string username = 4; string password = 5;
  repeated string password_history = 6; VaultTotp totp = 7; repeated string urls = 8; string notes = 9;
  repeated VaultUsedAt used_at = 10; uint64 created = 11; uint64 updated = 12; VaultEntryState state = 13;
}
enum VaultEntryState { VAULT_ENTRY_STATE_UNSPECIFIED = 0; VAULT_ENTRY_LIVE = 1; VAULT_ENTRY_BURNED = 2; }
message VaultTotp { bytes secret = 1; VaultTotpAlgorithm algorithm = 2; uint32 digits = 3; uint32 period = 4; }
enum VaultTotpAlgorithm {
  VAULT_TOTP_ALGORITHM_UNSPECIFIED = 0; VAULT_TOTP_SHA1 = 1; VAULT_TOTP_SHA256 = 2; VAULT_TOTP_SHA512 = 3;
}
message VaultUsedAt { string registrable_domain = 1; uint64 first = 2; uint64 last = 3; }
// §15.7's forward and ra/ rows.
message MailForward { string address = 1; repeated string burners = 2; uint64 verified_time_ms = 3; }
message MailReverseAlias { string original_sender = 1; string burner_address = 2; }
// The reverse aliases' key in vault/ and rcpt/'s record, which the answers to mail-m9-04-reverse-alias-key (QD-1095)
// and mail-m9-01-recipient-approval-bytes (QD-1094) give with their numbers.
message MailReverseAliasKey { bytes key = 1; }
message MailRecipientApproval { string alias = 1; string recipient = 2; bytes decision = 3; bytes action = 4; }
// §15.7's o/ row, §14's D-SMTP-18 and plan-SMTP-wire-gaps#4, with mail-proto-format-readings' approval_not_after.
message SmtpOutboxEntry {
  bytes effect_key = 1; bytes message_sha256 = 2; string sender = 3; repeated string recipients = 4;
  uint32 flags = 5; repeated string tl4_domains = 6; uint64 create_time_ms = 7; uint64 approval_not_after = 8;
}
// §14.5's modes, numbered as SmtpProof.mode, and its outcomes, in the order written; §15.7's or/ row, one file a send.
enum MailSendMode { MAIL_SEND_MODE_UNSPECIFIED = 0; MAIL_SEND_BDAT = 1; MAIL_SEND_DATA = 2; }
enum MailOutcomeKind {
  MAIL_OUTCOME_KIND_UNSPECIFIED = 0; MAIL_OUTCOME_SENT = 1; MAIL_OUTCOME_QUEUED = 2; MAIL_OUTCOME_DEFERRED = 3;
  MAIL_OUTCOME_TOO_LARGE = 4; MAIL_OUTCOME_REFUSED = 5; MAIL_OUTCOME_TLS_REFUSED = 6; MAIL_OUTCOME_FAILED = 7;
}
message MailOutcome {
  string domain = 1; MailSendMode mode = 2; uint64 byte_count = 3; uint64 cap_byte_count = 4;
  MailOutcomeKind outcome = 5; uint32 reply_code = 6; uint32 retry_after_ms = 7; uint64 update_time_ms = 8;
  uint32 tls_level = 9;
}
message MailOutcomeRecord { repeated MailOutcome outcomes = 1; }
// §15.7's p/ row, with DESIGN-DETAILS 3.7's fields for SMTP-M9-09 in the order it writes them.
message MailProverRecord {
  uint64 smtp_data_proof_bytes = 1; uint64 data_bytes_per_s = 2; uint64 measure_time_ms = 3;
  uint64 unit_millis = 4; uint64 head_byte_count = 5; uint64 header_record_byte_count = 6;
  uint64 envelope_group_count = 7; bytes key_set_id = 8; repeated uint32 ready_suites = 9;
}
// §15.7's s/model row and plan-MAIL-format-bytes#5's two fields, counts MAIL-M7-12's.
message MailSpamModel { uint32 version = 1; repeated uint32 counts = 2; }

// sidecar/protocol/record.proto
// record-m2-01-canonical-action-detail's answer (QD-740): what CanonicalAction.sealed_detail opens to, a dial or
// route grant's prefixes and ports and a version-3 access request's, with the numbers the answer gives.
message CanonicalActionDetail { repeated string cidrs = 1; uint32 target_port = 2; repeated string grant_dst = 3; }
`

// Fields the owner's answers add to messages the design fences, ahead of design-records' fold, each with the question
// that holds its answer. Each joins the fence it extends, so both directions stay exact, and one the design comes to
// write fails until its line here leaves.
var testFenceAdditions = []struct {
	message  string
	field    testFenceField
	question string
}{
}

// One field an owner's answer takes out of a message the design fences, its number reserved.
type testFenceReservation struct {
	message  string
	name     string
	number   int32
	question string
}

// Fields the owner's answers take out of messages the design fences, ahead of design-records' fold, each with the
// question that holds its answer. Each leaves the fence that writes it and its number joins that fence's
// reservations, so both directions stay exact, and one the design comes to reserve, or stops writing, fails until its
// line here leaves.
var testFenceReservations = []testFenceReservation{
}

// One value an owner's answer adds to an enum the design fences.
type testFenceValueAddition struct {
	enum     string
	name     string
	number   int32
	question string
}

// Values the owner's answers add to enums the design fences, ahead of design-records' fold, each with the question
// that holds its answer. Each joins the fence it extends, as testFenceAdditions' fields do, and one the design comes
// to write fails until its line here leaves.
var testFenceValueAdditions = []testFenceValueAddition{
}

// One value an owner's answer takes out of an enum the design fences, its number reserved.
type testFenceValueReservation struct {
	enum     string
	name     string
	number   int32
	question string
}

// Values the owner's answers take out of enums the design fences, ahead of design-records' fold, each with the
// question that holds its answer. Each leaves the fence that writes it and its number joins that fence's
// reservations, as testFenceReservations' fields do, and one the design comes to reserve, or stops writing, fails
// until its line here leaves.
var testFenceValueReservations = []testFenceValueReservation{
}
