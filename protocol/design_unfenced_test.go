// What the package declares that no fence in DESIGN.md does, written as a fence would be, so one parser and one
// comparison hold it: a field or value changed here without changing the proto, or there without changing this, fails
// TestDeclarationsMatchTheirFences. This is the repository's own addition to the design's wire, so a reviewer reads
// it here, and a new field of one of these has to pass through this file on its way to a release. Where a server
// reads the field, it needs its §2.8 row first (I-18), which §22.7's guard holds it to.
//
// The design gives most of these as field lists or names without numbers. They take numbers in the order written,
// which the answers to the questions that asked, among them protos-bridge-unwritten-numbers,
// protos-services-unwritten-numbers, keys-wire-route-bodies and mail-proto-format-readings, ratify as landed. They
// freeze with their formats, and as design-records writes each into the design as a fence, it leaves this file.

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

// sidecar/protocol/acl.proto
// §8.8's rows, which its AclRows comments list.
message AclAtom { bytes atom = 1; repeated bytes member_ids = 2; repeated bytes sidecar_ids = 3; }
message AclPortRange { uint32 protocol = 1; uint32 first = 2; uint32 last = 3; }
message AclRule {
  bytes rule_id = 1; repeated bytes src_atoms = 2; repeated AclTarget targets = 3; repeated uint32 actions = 4;
  repeated AclPortRange ports = 5; int64 expires = 6; AclAudience audience = 7; AclAppMode app_mode = 8;
  bytes link_spki_sha256 = 9;
}
message AclRepo {
  bytes repo_id = 1; RepoKind kind = 2; bytes owner_member_id = 3; repeated bytes consented_sidecar_ids = 4;
  repeated AclRepoAdminRow admins = 5; repeated AclRepoGrantRow grants = 6; repeated AclRepoShareRow shares = 7;
  repeated AclRepoRevokeRow revokes = 8; AclRepoDeletionRow deletion = 9; RepoVersioningLock lock = 10;
  uint64 holders_shrunk_at = 11;
}
message AclRepoAdminRow { bytes sidecar_id = 1; bytes signer = 2; uint64 at = 3; }
message AclRepoGrantRow {
  bytes subject = 1; RepoGrantRole role = 2; int64 expires = 3; bytes signer = 4; uint64 at = 5;
}
message AclRepoShareRow { bytes subject = 1; int64 expires = 2; bytes signer = 3; uint64 at = 4; }
message AclRepoRevokeRow { bytes subject = 1; bytes signer = 2; uint64 at = 3; }
message AclRepoDeletionRow {
  bytes deletion_id = 1; bool now = 2; uint64 deleted_at = 3; uint64 restored_at = 4;
}
// §8.8's statements, as its table lists them.
message GrantActivate {
  StatementHeader header = 1; bytes grant_id = 2; bytes canonical_action = 3; repeated Signed decisions = 4;
}
message EvsShare { StatementHeader header = 1; bytes repo_id = 2; bytes subject = 3; int64 expires = 4; }
message OwnerConfirm { StatementHeader header = 1; bytes sidecar_id = 2; }
message RepoCreate { StatementHeader header = 1; bytes repo_id = 2; RepoKind kind = 3; }
message RepoAdmin {
  StatementHeader header = 1; bytes repo_id = 2; bytes sidecar_id = 3; RepoAdminChange change = 4;
}
message RepoGrant {
  StatementHeader header = 1; bytes repo_id = 2; bytes subject = 3; RepoGrantRole role = 4; int64 expires = 5;
}
message RepoRevoke { StatementHeader header = 1; bytes repo_id = 2; bytes subject = 3; }
message RepoDelete { StatementHeader header = 1; bytes repo_id = 2; bytes deletion_id = 3; bool now = 4; }
message RepoRestore { StatementHeader header = 1; bytes repo_id = 2; bytes deletion_id = 3; }
message RepoVersioning {
  StatementHeader header = 1; bytes repo_id = 2; RepoVersioningLock lock = 3; bytes sealed_rules = 4;
}
message AuditOptIn { StatementHeader header = 1; repeated bytes reader_atoms = 2; int64 not_after = 3; }
message AuditOptOut { StatementHeader header = 1; }
// §8.4's autogroups, actions, audiences and modes, §11.12's kinds, and §8.8's names, in the order written.
enum AclAutogroup {
  ACL_AUTOGROUP_UNSPECIFIED = 0; ACL_AUTOGROUP_MEMBER = 1; ACL_AUTOGROUP_OWNER = 2; ACL_AUTOGROUP_ADMIN = 3;
  ACL_AUTOGROUP_AUDITOR = 4; ACL_AUTOGROUP_SIDECAR = 5; ACL_AUTOGROUP_TAGGED = 6; ACL_AUTOGROUP_NETWORK = 7;
  ACL_AUTOGROUP_UNTAGGED = 8; ACL_AUTOGROUP_EPHEMERAL = 9; ACL_AUTOGROUP_PUBLIC = 10;
  ACL_AUTOGROUP_INTERNET = 11; ACL_AUTOGROUP_SELF = 12; ACL_AUTOGROUP_SPONSOR = 13;
  ACL_AUTOGROUP_DST_OWNER = 14;
}
enum AclAction {
  ACL_ACTION_UNSPECIFIED = 0; ACL_ACTION_DIAL = 1; ACL_ACTION_LISTEN = 2; ACL_ACTION_ROUTE = 3;
  ACL_ACTION_READ = 4; ACL_ACTION_WRITE = 5; ACL_ACTION_ADMIN = 6; ACL_ACTION_DEPOSIT = 7;
  ACL_ACTION_PUBLISH = 8; ACL_ACTION_SEND = 9;
}
enum AclAudience {
  ACL_AUDIENCE_UNSPECIFIED = 0; ACL_AUDIENCE_MEMBERS = 1; ACL_AUDIENCE_MEMBERS_DEVICE = 2;
  ACL_AUDIENCE_LINK = 3; ACL_AUDIENCE_PUBLIC = 4;
}
enum AclAppMode { ACL_APP_MODE_UNSPECIFIED = 0; ACL_APP_MODE_HTTP = 1; ACL_APP_MODE_RAW = 2; }
enum RepoKind {
  REPO_KIND_UNSPECIFIED = 0; REPO_KIND_GENERAL = 1; REPO_KIND_RECORD = 2; REPO_KIND_CONFIG = 3;
  REPO_KIND_DIRECTORY = 4; REPO_KIND_TEAM_RECORD = 5; REPO_KIND_MAILCFG = 6; REPO_KIND_VAULT = 7;
  REPO_KIND_MAILBOX = 8; REPO_KIND_SECRET = 9;
}
enum RepoGrantRole {
  REPO_GRANT_ROLE_UNSPECIFIED = 0; REPO_GRANT_ROLE_DEPOSIT = 1; REPO_GRANT_ROLE_READER = 2;
  REPO_GRANT_ROLE_WRITER = 3;
}
enum RepoVersioningLock {
  REPO_VERSIONING_LOCK_UNSPECIFIED = 0; REPO_VERSIONING_LOCK_LOCKED = 1; REPO_VERSIONING_LOCK_UNLOCKED = 2;
}
enum RepoAdminChange {
  REPO_ADMIN_CHANGE_UNSPECIFIED = 0; REPO_ADMIN_CHANGE_ADD = 1; REPO_ADMIN_CHANGE_REMOVE = 2;
}

// sidecar/protocol/config.proto
// §7.9's record table.
message AdminSet {
  StatementHeader header = 1; repeated bytes owners = 2; repeated bytes admins = 3;
  repeated bytes network_admins = 4; repeated bytes it_admins = 5; uint32 threshold = 6;
}
message MemberAdmit { StatementHeader header = 1; bytes member_id = 2; MemberRole role = 3; }
message SidecarAdmit {
  StatementHeader header = 1; bytes network_id = 2; bytes sidecar_id = 3; bytes identity_public_key = 4;
  string identity_alg = 5; bytes member_id = 6; repeated bytes tag_ids = 7; bool ephemeral = 8;
  int64 not_after = 9; uint32 capabilities = 10;
}
message AdmissionConfirm { StatementHeader header = 1; bytes sidecar_id = 2; }
message SponsorSet { StatementHeader header = 1; bytes sidecar_id = 2; bytes sponsor_member_id = 3; }
message IndexerSet {
  StatementHeader header = 1; bytes sidecar_id = 2; IndexerScope scope = 3; bool retire = 4;
  bytes sealed_services = 5;
}
message IndexerServices { repeated IndexerService services = 1; }
message RecoveryBind {
  StatementHeader header = 1; bytes member_id = 2; bytes prev_sha256 = 3; bytes ed25519_public_key_sha256 = 4;
  bytes sealed_body = 5;
}
message RecoveryBindBody { bytes xwing_public_key = 1; bytes ed25519_public_key = 2; bytes genesis_sig = 3; }
message RecoveryRebind {
  StatementHeader header = 1; bytes member_id = 2; bytes prev_sha256 = 3; bytes ed25519_public_key_sha256 = 4;
  bytes sealed_body = 5; RecoveryRebindReason reason = 6;
}
message KeyRegister {
  StatementHeader header = 1; bytes member_id = 2; bytes key_id = 3; KeyAlg alg = 4; bytes public_key = 5;
  bytes attestation = 6; KeyPurpose purpose = 7; int64 not_after = 8;
}
message KeyRevoke { StatementHeader header = 1; bytes key_id = 2; }
message Delegation {
  StatementHeader header = 1; bytes pubkey = 2; bytes reader_xwing_public_key = 3; repeated bytes tag_ids = 4;
  uint32 max_admits = 5; int64 not_after = 6;
}
message DelegationRevoke { StatementHeader header = 1; bytes delegation_id = 2; uint64 since_n = 3; }
message ServiceDirectorySettings { DirectoryRunsMode runs = 1; DirectoryWorkersMode workers = 2; }
message ServiceSettings {
  TeamMailMode team_mail = 1; uint32 stale_leaf_days = 2; SelfAdmitMode self_admit = 3;
  uint32 witness_bound_hours = 4; bytes scim_signer = 5; ServiceDirectorySettings directory = 6;
}
message VersioningRule {
  repeated uint32 kinds = 1; repeated bytes repo_ids = 2; string path_glob = 3; uint64 size_above_bytes = 4;
  VersioningMode versioning = 5;
}
message VersioningRules { repeated VersioningRule rules = 1; }
message AuthorityProposal { StatementHeader header = 1; uint32 statement_type = 2; bytes statement = 3; }
message AuthorityCosign { StatementHeader header = 1; bytes proposal_id = 2; }
message RecoveryVeto { StatementHeader header = 1; bytes proposal_id = 2; }
// §7.8's client-only bundle, a field list without numbers.
message AuthKeyBundle {
  uint32 version = 1; bytes genesis_sha256 = 2; AuthPin head = 3; bytes delegation_id = 4;
  bytes delegation_signing_seed = 5; bytes delegation_reader_seed = 6; repeated bytes tag_ids = 7;
}
// §7.9's and §16.11's settings, in the order written.
enum IndexerScope { INDEXER_SCOPE_UNSPECIFIED = 0; INDEXER_SCOPE_NETWORK = 1; INDEXER_SCOPE_MEMBER = 2; }
enum IndexerService {
  INDEXER_SERVICE_UNSPECIFIED = 0; INDEXER_SERVICE_MAIL = 1; INDEXER_SERVICE_MIRROR = 2;
  INDEXER_SERVICE_SEARCH = 3;
}
enum TeamMailMode {
  TEAM_MAIL_MODE_UNSPECIFIED = 0; TEAM_MAIL_MODE_INDEXERS = 1; TEAM_MAIL_MODE_MEMBER_SCOPES = 2;
}
enum SelfAdmitMode { SELF_ADMIT_MODE_UNSPECIFIED = 0; SELF_ADMIT_MODE_ON = 1; SELF_ADMIT_MODE_OFF = 2; }
enum DirectoryRunsMode {
  DIRECTORY_RUNS_MODE_UNSPECIFIED = 0; DIRECTORY_RUNS_MODE_AUTO = 1; DIRECTORY_RUNS_MODE_PROMPT = 2;
  DIRECTORY_RUNS_MODE_OFF = 3;
}
enum DirectoryWorkersMode {
  DIRECTORY_WORKERS_MODE_UNSPECIFIED = 0; DIRECTORY_WORKERS_MODE_ON = 1; DIRECTORY_WORKERS_MODE_OFF = 2;
}
enum VersioningMode { VERSIONING_MODE_UNSPECIFIED = 0; VERSIONING_MODE_ON = 1; VERSIONING_MODE_OFF = 2; }

// sidecar/protocol/bridge/auth.proto
// §7.9's rows, as ProjectionRows' comments list them; protos-bridge-row-fields asks what else they carry.
message MemberRow {
  bytes member_id = 1; MemberRole role = 2; bytes recovery_key_sha256 = 3;
  repeated RecoveryBindingRow bindings = 4;
}
message RecoveryBindingRow {
  bytes key_sha256 = 1; bytes signer = 2; uint64 at = 3; RecoveryRebindReason reason = 4;
}
message SidecarRow {
  bytes sidecar_id = 1; bytes admission_sha256 = 2; repeated bytes admission_signers = 3;
  uint64 admitted_at = 4; bytes confirm_signer = 5; uint64 confirmed_at = 6; bytes owner_confirm_signer = 7;
  uint64 owner_confirmed_at = 8; uint64 revoked_at = 9; uint64 parked_at = 10; bytes sponsor = 11;
  uint32 capabilities = 12; bytes delegation_id = 13; uint64 live_since = 14; int64 not_after = 15;
}
message DelegationRow {
  bytes delegation_id = 1; bytes signer = 2; uint64 at = 3; repeated bytes tag_atoms = 4; int64 not_after = 5;
  uint64 key_dropped_at = 6; uint64 ended_at = 7; uint32 admissions = 8;
}
message KeyRow {
  bytes key_id = 1; bytes member_id = 2; KeyAlg alg = 3; bytes public_key = 4; KeyPurpose purpose = 5;
  bytes signer = 6; uint64 at = 7; int64 not_after = 8; uint64 revoked_at = 9;
}
// §7.9's and §8.8's statements the device role applies between states.
message Genesis {
  bytes network_id = 1; bytes config_repo_id = 2; bytes owner_member_id = 3; bytes owner_sidecar_id = 4;
  bytes owner_identity_public_key = 5; int64 time_ms = 6;
}
message MemberRevoke { StatementHeader header = 1; bytes member_id = 2; }
message SidecarRevoke {
  StatementHeader header = 1; bytes sidecar_id = 2; SidecarRevokeReason reason = 3; uint64 since_n = 4;
}
message GrantRevoke { StatementHeader header = 1; bytes grant_id = 2; }
message Suspend { StatementHeader header = 1; bytes subject = 2; bytes suspend_id = 3; }
message Unsuspend { StatementHeader header = 1; bytes subject = 2; bytes suspend_id = 3; }
// §5.5's identity binding, as plan-CORE-binding-wire #1 numbers it.
message SidecarIdentityBinding {
  bytes network_id = 1; bytes sidecar_id = 2; bytes client_id = 3; int64 generation = 4;
  bytes client_public_key = 5; bytes identity_public_key = 6; int64 issued_at_ms = 7;
}
message SignedSidecarIdentityBinding { bytes body = 1; bytes client_signature = 2; bytes identity_signature = 3; }
// §7.5's roles and §7.9's names, in the order written.
enum MemberRole {
  MEMBER_ROLE_UNSPECIFIED = 0; MEMBER_ROLE_OWNER = 1; MEMBER_ROLE_ADMIN = 2; MEMBER_ROLE_NETWORK_ADMIN = 3;
  MEMBER_ROLE_IT_ADMIN = 4; MEMBER_ROLE_BILLING_ADMIN = 5; MEMBER_ROLE_AUDITOR = 6; MEMBER_ROLE_MEMBER = 7;
}
enum SidecarCapability { SIDECAR_CAPABILITY_NONE = 0; SIDECAR_CAPABILITY_READ_ONLY = 2; }
enum KeyAlg {
  KEY_ALG_UNSPECIFIED = 0; KEY_ALG_WEBAUTHN_ES256 = 1; KEY_ALG_ECDSA_P256_SHA256 = 2; KEY_ALG_SSH_ED25519 = 3;
}
enum KeyPurpose { KEY_PURPOSE_UNSPECIFIED = 0; KEY_PURPOSE_PRESENCE = 1; KEY_PURPOSE_SSHSIG = 2; }
enum RecoveryRebindReason {
  RECOVERY_REBIND_REASON_UNSPECIFIED = 0; RECOVERY_REBIND_REASON_ROUTINE = 1; RECOVERY_REBIND_REASON_LOST = 2;
  RECOVERY_REBIND_REASON_COMPROMISE = 3;
}
enum SidecarRevokeReason {
  SIDECAR_REVOKE_REASON_UNSPECIFIED = 0; SIDECAR_REVOKE_REASON_LOST = 1; SIDECAR_REVOKE_REASON_REAPED = 2;
  SIDECAR_REVOKE_REASON_REMOVED = 3; SIDECAR_REVOKE_REASON_COMPROMISE = 4;
}

// sidecar/protocol/bridge/bridge.proto
// §17.8's statements and their rows, each statement's sealed part in its *Body.
message BridgeEgressRow { bytes subject = 1; BridgeEgressMode mode = 2; }
message BridgeIpv4Prefix { fixed32 address = 1; uint32 length = 2; }
message BridgePortRange { uint32 first = 1; uint32 last = 2; }
message BridgeApproval { bytes canonical_action = 1; repeated Signed decisions = 2; }
message BridgeBlock {
  BridgeIpv4Prefix ipv4_prefix = 1; BridgeIpv4Prefix previous_prefix = 2; int64 drain_until = 3;
}
message BridgeAddress { StatementHeader header = 1; bytes sidecar_id = 2; bytes sealed_body = 3; }
message BridgeAddressBody { fixed32 ipv4 = 1; }
message BridgeRoute {
  StatementHeader header = 1; bytes route_id = 2; bytes advertiser = 3; repeated bytes route_rule_ids = 4;
  bytes sealed_body = 5;
}
message BridgeRouteBody {
  repeated BridgeIpv4Prefix prefixes = 1; BridgeIpv4Prefix exposed_prefix = 2; bytes site_id = 3;
  uint32 weight = 4; BridgeRouteKind kind = 5; uint32 drain_seconds = 6; BridgeApproval approval = 7;
}
message BridgeMap {
  StatementHeader header = 1; bytes map_id = 2; bytes host = 3; int64 expires = 4; bytes sealed_body = 5;
}
message BridgeMapBody {
  BridgeIpv4Prefix match_prefix = 1; uint32 protocol = 2; repeated BridgePortRange ports = 3; bytes target = 4;
  uint32 target_port = 5; uint32 drain_seconds = 6; BridgeApproval approval = 7;
}
message BridgeEgress { StatementHeader header = 1; bytes subject = 2; bytes sealed_body = 3; }
message BridgeEgressBody {
  BridgeEgressMode mode = 1; repeated bytes exit_sidecar_ids = 2; bytes exit_tag_id = 3;
}
message BridgeAlias { StatementHeader header = 1; bytes sealed_body = 2; }
message BridgeAliasBody {
  bytes share_id = 1; uint32 target_index = 2; BridgeIpv4Prefix alias_prefix = 3; bytes host = 4;
}
message BridgeWithdraw { StatementHeader header = 1; bytes rule_id = 2; BridgeWithdrawMode mode = 3; }
enum BridgeRouteKind {
  BRIDGE_ROUTE_KIND_UNSPECIFIED = 0; BRIDGE_ROUTE_KIND_SUBNET = 1; BRIDGE_ROUTE_KIND_EXIT = 2;
}
enum BridgeEgressMode {
  BRIDGE_EGRESS_MODE_UNSPECIFIED = 0; BRIDGE_EGRESS_MODE_AUTO = 1; BRIDGE_EGRESS_MODE_EXITS = 2;
  BRIDGE_EGRESS_MODE_NONE = 3;
}
enum BridgeWithdrawMode {
  BRIDGE_WITHDRAW_MODE_UNSPECIFIED = 0; BRIDGE_WITHDRAW_MODE_RESET = 1; BRIDGE_WITHDRAW_MODE_DRAIN = 2;
}

// sidecar/protocol/gkm.proto
// §10.5's list; not_after holds ms, so it stays 64 bits.
message ReaderKey { bytes sidecar_id = 1; bytes xwing_public_key = 2; int64 not_after = 3; }
// §2.8's gkm-1; its signer is Signed's.
message GroupForm { bytes repo_id = 1; bytes group_id = 2; bytes previous_group_id = 3; uint64 generation = 4; }
// §10.14's list and kinds.
message GkmHint { bytes group_id = 1; uint64 epoch = 2; GkmHintKind kind = 3; bytes recipient = 4; }
enum GkmHintKind {
  GKM_HINT_KIND_UNSPECIFIED = 0; GKM_HINT_COMMIT = 1; GKM_HINT_PENDING = 2; GKM_HINT_WELCOME = 3;
  GKM_HINT_KEY_PACKAGES_LOW = 4; GKM_HINT_WRAP_PENDING = 5;
}
// §10.6's objects: the epoch/<n> row with gkm-1's epoch 0, the group-info row, the welcome/<sidecar_id>/<ref> row and
// the <ref>.claim row, which §10 names and gives no bytes.
message GkmEpochObject {
  bytes commit = 1; GkmCommitHeader header = 2; bytes uploader = 3; int64 time_ms = 4; bytes gen_wrap = 5;
  bytes sealed_group_info = 6; uint64 group_info_generation = 7; bytes network_id = 8; uint32 cipher_suite = 9;
}
message GkmGroupInfoObject { uint64 epoch = 1; uint64 generation = 2; bytes sealed_group_info = 3; }
message GkmWelcomePointer { bytes group_id = 1; uint64 epoch = 2; }
message GkmKeyPackageClaim { bytes group_id = 1; bytes claimer = 2; }
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
}
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
  EVS_REFUSAL_STATEMENT_MISSING = 73; EVS_REFUSAL_GROUP_NOT_READY = 74;
  EVS_REFUSAL_INVALID = 128; EVS_REFUSAL_NOT_FOUND = 129; EVS_REFUSAL_PARTS_MISSING = 130; EVS_REFUSAL_BUSY = 131;
  EVS_REFUSAL_FOLD_BEHIND = 132; EVS_REFUSAL_TIME_AHEAD = 133; EVS_REFUSAL_RESOURCE_EXHAUSTED = 134;
  EVS_REFUSAL_WAIT = 135; EVS_REFUSAL_UNAVAILABLE = 136;
}
enum EvsPushOutcome { EVS_PUSH_OUTCOME_SETTLED = 0; EVS_PUSH_OUTCOME_UNKNOWN = 1; }
enum EvsReadPathState {
  EVS_READ_PATH_STATE_UNSPECIFIED = 0; EVS_READ_PATH_COLLECTED = 1; EVS_READ_PATH_DROP_PENDING = 2;
  EVS_READ_PATH_DROPPED = 3;
}
enum EvsReadObjectKind {
  EVS_READ_OBJECT_KIND_UNSPECIFIED = 0; EVS_READ_OBJECT_SEGMENT = 1; EVS_READ_OBJECT_SLOT = 2;
  EVS_READ_OBJECT_MAP_PART = 3; EVS_READ_OBJECT_LOG_PAGE = 4; EVS_READ_OBJECT_BATCH_RECORD = 5;
}
// 11.8's repo/, place and slot/ rows, by plan-EVS1-format-bytes#9 and plan-EVSB-repo-network.
message EvsRepoObject {
  bytes repo_id = 1; RepoKind kind = 2; bytes owner_member_id = 3; EvsRepoState state = 4; int64 state_ms = 5;
  bytes state_signer = 6; bytes deletion_id = 7; uint32 format = 8; bytes sealed_name = 9; bytes network_id = 10;
}
message EvsRepoPlacement { string cluster_id = 1; bytes creator_sidecar_id = 2; }
message EvsSlotObject { repeated EvsSlotKey keys = 1; }
message EvsSlotKey { uint32 key_index = 1; uint64 generation = 2; bytes wrapped = 3; }
// 11.7's index entries, removal row and drop mark, by plan-EVS1-format-bytes#9.
message EvsIndexEntry {
  repeated EvsIndexVersion versions = 1; EvsNameTable names = 2; uint64 names_through = 3;
  EvsRemovalMarker marker = 4; EvsDropMark drop_mark = 5;
}
message EvsIndexVersion { bytes push_id = 1; uint64 commit_version = 2; bytes entry_version = 3; bool elided = 4; }
message EvsRemovalMarker {
  bytes push_id = 1; uint64 removal_version = 2; uint64 path_version = 3; repeated bytes segment_ids = 4;
  repeated bytes slot_ids = 5;
}
message EvsDropMark { bytes drop_id = 1; uint64 through_version = 2; }
// 11.8's log/ row.
message EvsLogPage {
  uint64 page = 1; bytes first_chain = 2; bytes last_chain = 3; bytes window = 4; repeated bytes statements = 5;
}
// What EvsEntryVersion.sealed_fields and a push's sealed metadata open to: the former's comment, by
// plan-EVS1-format-bytes#9; the latter's from EvsPush.sealed_metadata_sha256's comment, 11.6's records row and 11.7's
// mapping to git.
message EvsSealedFields {
  bytes file_id = 1; uint32 mode = 2; bytes git_oid = 3; EvsOidKind oid_kind = 4; uint64 size = 5;
  bytes content_sha256 = 6;
}
message EvsSealedMetadata {
  GroupHead group = 1; EvsProvenance provenance = 2; repeated EvsSealedCommit commits = 3; bytes signed_import = 4;
}
message EvsProvenance { bytes agent_id = 1; bool tainted = 2; }
message EvsSealedCommit { bytes object = 1; repeated EvsSealedChange changes = 2; }
message EvsSealedChange { repeated bytes path = 1; uint32 mode = 2; bytes git_oid = 3; }
// 11.8's push, parts, seal and lease rows and 11.20's refusals, by plan-EVS1-format-bytes#8, with
// plan-EVS1-deposit-head's and plan-RECORD-depositor-spool's deposit head and §20.7's QuotaRefusal.
message EvsPushRequest {
  bytes statement = 1; bytes payload = 2; repeated EvsUploadReceipt receipts = 3; bytes staged = 4;
  repeated EvsPlace part_places = 5;
}
message EvsPartRequest {
  bytes statement = 1; bytes part = 2; repeated EvsUploadReceipt receipts = 3; bytes staged = 4;
}
message EvsLeaseRequest { bytes ref_id = 1; uint64 base_version = 2; uint32 ms = 3; }
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
// 11.9's request, streams and reply rows, by plan-EVS1-format-bytes#8 and protos-services-read-states.
message EvsReadRequest {
  bytes ref_id = 1; uint64 pin_version = 2; bool fresh = 3; repeated EvsReadPath paths = 4;
  repeated EvsReadRange ranges = 5; repeated bytes slot_ids = 6; repeated EvsReadMap maps = 7;
  repeated uint64 log_pages = 8; repeated EvsReadPush pushes = 9; repeated EvsReadRef refs = 10;
}
message EvsReadPath { repeated EvsSourcePath token_paths = 1; uint64 version = 2; }
message EvsReadRange { bytes segment_id = 1; uint32 offset = 2; uint32 length = 3; }
message EvsReadMap { uint64 path_epoch = 1; bytes map_sha256 = 2; uint32 part = 3; }
message EvsReadPush { bytes push_id = 1; uint64 version = 2; uint32 part = 3; }
message EvsReadRef { bytes ref_id = 1; uint64 pin_version = 2; }
message EvsReadFrame {
  EvsHeadSummary head = 1; EvsReadStatement statement = 2; uint64 behind = 3; uint64 more = 4;
  EvsReadPathReply path = 5; EvsReadObject object = 6; bool end = 7;
}
message EvsHeadSummary {
  bytes ref_id = 1; uint64 version = 2; bytes chain = 3; bytes push_id = 4; EvsRefKind ref_kind = 5;
  EvsRefMode ref_mode = 6; bytes owner_sidecar_id = 7; bytes sealed_ref_name = 8; EvsOverlay base = 9;
  AuthPin auth = 10; bytes group_id = 11; uint64 generation = 12; bytes generation_commitment = 13;
  EvsPathEpoch path_epoch = 14; uint64 index_epoch = 15; bool deleted = 16; uint64 push_sequence = 17;
}
message EvsReadStatement { uint64 version = 1; bytes statement = 2; }
message EvsReadPathReply {
  repeated bytes token_path = 1; EvsIndexVersion version = 2; bytes statement = 3;
  repeated EvsMerkleProof proof = 4; repeated EvsAbsenceProof absences = 5; EvsRemovalMarker removal = 6;
  EvsOverlay base = 7; EvsNameTable names = 8; uint64 names_through = 9; repeated EvsIndexVersion deltas = 10;
  EvsReadPathState state = 11; bytes drop_id = 12; int64 not_before_ms = 13; uint64 drop_version = 14;
}
message EvsMerkleProof { bytes leaf = 1; uint64 index = 2; uint64 size = 3; repeated bytes path = 4; }
message EvsAbsenceProof {
  uint64 version = 1; repeated bytes token_path = 2; repeated EvsMerkleProof below = 3;
  repeated EvsMerkleProof above = 4;
}
message EvsReadObject {
  EvsReadObjectKind kind = 1; bytes id = 2; uint64 number = 3; uint32 offset = 4; bytes body = 5; bool missing = 6;
}
// 11.9's moved row and 11.10's sequence and gap rows.
message EvsRefsReply { uint32 format = 1; uint64 push_sequence = 2; repeated EvsHeadSummary refs = 3; }
message EvsLogReply { repeated EvsReadStatement statements = 1; uint64 next_version = 2; }

// sidecar/protocol/smtp.proto
// §6.11's edge codes, numbers as written.
enum SmtpPreambleCode {
  SMTP_PREAMBLE_CODE_UNSPECIFIED = 0; SMTP_PREAMBLE_OK = 1; SMTP_PREAMBLE_HALTED = 2; SMTP_PREAMBLE_QUOTA = 3;
  SMTP_PREAMBLE_DENIED = 4; SMTP_PREAMBLE_NO_MX = 5; SMTP_PREAMBLE_NO_TLS = 6; SMTP_PREAMBLE_TRY_LATER = 7;
}
enum SmtpProofCode { SMTP_PROOF_CODE_UNSPECIFIED = 0; SMTP_PROOF_OK = 1; SMTP_PROOF_INVALID = 2; }

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
// §15.7's p/ row.
message MailProverRecord {
  uint64 smtp_data_proof_bytes = 1; uint64 data_bytes_per_s = 2; uint64 measure_time_ms = 3;
}
`

// Fields the owner's answers add to messages the design fences, ahead of design-records' fold, each with the question
// that holds its answer. Each joins the fence it extends, so both directions stay exact, and one the design comes to
// write fails until its line here leaves.
var testFenceAdditions = []struct {
	message  string
	field    testFenceField
	question string
}{
	{
		message:  "EvsPush",
		field:    testFenceField{name: "consumed_through", number: 35, typeName: "uint64"},
		question: "plan-RECORD-depositor-spool",
	},
	{
		message:  "EvsPushPart",
		field:    testFenceField{name: "sections", number: 8, typeName: "bytes"},
		question: "plan-EVS2-drop-list-parts",
	},
	{
		message:  "EvsHead",
		field:    testFenceField{name: "consumed_through", number: 27, typeName: "uint64"},
		question: "plan-RECORD-depositor-spool",
	},
}
