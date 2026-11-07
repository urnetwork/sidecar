// What the package declares that no fence in DESIGN.md does, written as a fence would be, so one parser and one
// comparison hold it: a field or value changed here without changing the proto, or there without changing this, fails
// TestDeclarationsMatchTheirFences. This is the repository's own addition to the design's wire, so a reviewer reads
// it here, and a new field of one of these has to pass through this file on its way to a release. Where a server
// reads the field, it needs its §2.8 row first (I-18; metadata_walk_test.go).
//
// The design gives most of these as field lists or names without numbers. They take numbers in the order written,
// and those numbers stay open until their format freezes: protos-bridge-unwritten-numbers and
// protos-services-unwritten-numbers ask for them to be ratified.

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
// §15.15's field list and kinds.
message MailHint { MailHintKind kind = 1; }
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
message MailIndexSegment { uint32 version = 1; repeated IndexEntry entries = 2; }
// §15.7's f/ kinds, and the f/ row's op and container, which MAIL-FORMAT.md states.
enum MailFlagKind {
  MAIL_FLAG_KIND_UNSPECIFIED = 0; MAIL_FLAG_SEEN = 1; MAIL_FLAG_FLAGGED = 2; MAIL_FLAG_LABEL = 3;
  MAIL_FLAG_TRASH = 4;
}
message MailFlagOp {
  bytes message_id = 1; MailFlagKind kind = 2; string label = 3; bool set = 4; uint64 hlc = 5;
  bytes sidecar_id = 6;
}
message MailFlagSegment { uint32 version = 1; repeated MailFlagOp ops = 2; }
// §15.7's r/ row.
message MailReference { bytes repo_id = 1; bytes message_id = 2; }
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
message MailForward { string address = 1; repeated string burners = 2; }
message MailReverseAlias { string original_sender = 1; string burner_address = 2; }
// §15.7's o/ row, and §14's D-SMTP-18.
message MailOutboxEntry {
  uint32 version = 1; bytes effect_key = 2; string mail_from = 3; repeated string recipients = 4;
  bytes message = 5; uint32 flags = 6; repeated string tl4_domains = 7; uint64 created = 8;
  uint64 approval_not_after = 9;
}
// §14.5's modes, numbered as SmtpProof.mode, and its outcomes, in the order written; §15.7's or/ row, one file a send.
enum MailSendMode { MAIL_SEND_MODE_UNSPECIFIED = 0; MAIL_SEND_BDAT = 1; MAIL_SEND_DATA = 2; }
enum MailOutcomeKind {
  MAIL_OUTCOME_KIND_UNSPECIFIED = 0; MAIL_OUTCOME_SENT = 1; MAIL_OUTCOME_QUEUED = 2; MAIL_OUTCOME_DEFERRED = 3;
  MAIL_OUTCOME_TOO_LARGE = 4; MAIL_OUTCOME_REFUSED = 5; MAIL_OUTCOME_TLS_REFUSED = 6; MAIL_OUTCOME_FAILED = 7;
}
message MailOutcome {
  string domain = 1; MailSendMode mode = 2; MailOutcomeKind kind = 3; uint64 message_byte_count = 4;
  uint64 cap_byte_count = 5; uint32 retry_after_ms = 6; uint32 reply_code = 7; uint32 tls_level = 8;
}
message MailOutcomeRecord { repeated MailOutcome outcomes = 1; }
// §15.7's p/ row.
message MailProverRecord { uint64 smtp_data_proof_bytes = 1; uint64 data_bytes_per_second = 2; }
`
