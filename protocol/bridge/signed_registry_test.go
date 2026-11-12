// The signed type registry (§6.11) and this package's import boundary (§4.4).

package bridge

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Numbers as the design writes them, or for 0x10xx, 0x13xx and 0x14xx as §6.11's list orders them, with §10's two and
// §11.6's two more statements after it, 0x11xx and 0x12xx as §8.8's and §7.9's rows do, and 0x15xx as
// plan-TLS-small-readings#2 numbers §13.8's attestation and QD-134 the link token, 0x1502 left for M6's edge login.
// Values are permanent once released, so a change here is a change to the wire.
func TestSignedTypeNumbersStable(t *testing.T) {
	cases := []struct {
		signedType SignedType
		number     int32
	}{
		{signedType: SignedType_SIGNED_SOCKET_REGISTRATION, number: 0x1001},
		{signedType: SignedType_SIGNED_SOCKET_TICKET, number: 0x1002},

		{signedType: SignedType_SIGNED_GRANT_ACTIVATE, number: 0x1101},
		{signedType: SignedType_SIGNED_GRANT_REVOKE, number: 0x1102},
		{signedType: SignedType_SIGNED_SUSPEND, number: 0x1103},
		{signedType: SignedType_SIGNED_UNSUSPEND, number: 0x1104},
		{signedType: SignedType_SIGNED_EVS_SHARE, number: 0x1105},
		{signedType: SignedType_SIGNED_OWNER_CONFIRM, number: 0x1106},
		{signedType: SignedType_SIGNED_REPO_CREATE, number: 0x1107},
		{signedType: SignedType_SIGNED_REPO_ADMIN, number: 0x1108},
		{signedType: SignedType_SIGNED_REPO_GRANT, number: 0x1109},
		{signedType: SignedType_SIGNED_REPO_REVOKE, number: 0x110A},
		{signedType: SignedType_SIGNED_REPO_DELETE, number: 0x110B},
		{signedType: SignedType_SIGNED_REPO_RESTORE, number: 0x110C},
		{signedType: SignedType_SIGNED_REPO_VERSIONING, number: 0x110D},
		{signedType: SignedType_SIGNED_AUDIT_OPT_IN, number: 0x110E},
		{signedType: SignedType_SIGNED_AUDIT_OPT_OUT, number: 0x110F},

		{signedType: SignedType_SIGNED_GENESIS, number: 0x1201},
		{signedType: SignedType_SIGNED_ADMIN_SET, number: 0x1202},
		{signedType: SignedType_SIGNED_MEMBER_ADMIT, number: 0x1203},
		{signedType: SignedType_SIGNED_MEMBER_REVOKE, number: 0x1204},
		{signedType: SignedType_SIGNED_SIDECAR_ADMIT, number: 0x1205},
		{signedType: SignedType_SIGNED_SIDECAR_REVOKE, number: 0x1206},
		{signedType: SignedType_SIGNED_ADMISSION_CONFIRM, number: 0x1207},
		{signedType: SignedType_SIGNED_SPONSOR_SET, number: 0x1208},
		{signedType: SignedType_SIGNED_INDEXER_SET, number: 0x1209},
		{signedType: SignedType_SIGNED_RECOVERY_BIND, number: 0x120A},
		{signedType: SignedType_SIGNED_RECOVERY_REBIND, number: 0x120B},
		{signedType: SignedType_SIGNED_KEY_REGISTER, number: 0x120C},
		{signedType: SignedType_SIGNED_KEY_REVOKE, number: 0x120D},
		{signedType: SignedType_SIGNED_DELEGATION, number: 0x120E},
		{signedType: SignedType_SIGNED_DELEGATION_REVOKE, number: 0x120F},
		{signedType: SignedType_SIGNED_SERVICE_SETTINGS, number: 0x1210},
		{signedType: SignedType_SIGNED_VERSIONING_RULES, number: 0x1211},
		{signedType: SignedType_SIGNED_AUTHORITY_PROPOSAL, number: 0x1212},
		{signedType: SignedType_SIGNED_AUTHORITY_COSIGN, number: 0x1213},
		{signedType: SignedType_SIGNED_RECOVERY_VETO, number: 0x1214},
		{signedType: SignedType_SIGNED_PROJECTION_HEADER, number: 0x1215},

		{signedType: SignedType_SIGNED_GEN_ROTATE, number: 0x1301},
		{signedType: SignedType_SIGNED_READER_KEY, number: 0x1302},
		{signedType: SignedType_SIGNED_READER_WRAP, number: 0x1303},
		{signedType: SignedType_SIGNED_DELEGATION_WRAP, number: 0x1304},
		{signedType: SignedType_SIGNED_GROUP_FORM, number: 0x1305},
		{signedType: SignedType_SIGNED_UR_MLS_CREDENTIAL, number: 0x1306},

		{signedType: SignedType_SIGNED_EVS_PUSH, number: 0x1401},
		{signedType: SignedType_SIGNED_EVS_RESEED, number: 0x1402},
		{signedType: SignedType_SIGNED_EVS_PATH_MAP, number: 0x1403},
		{signedType: SignedType_SIGNED_EVS_IMPORT, number: 0x1404},

		{signedType: SignedType_SIGNED_TLS_KEY_ATTESTATION, number: 0x1501},
		{signedType: SignedType_SIGNED_TLS_LINK, number: 0x1503},

		{signedType: SignedType_SIGNED_RECORD_HEADER, number: 0x1801},
		{signedType: SignedType_SIGNED_APPROVAL_DECISION, number: 0x1802},
		{signedType: SignedType_SIGNED_APPROVAL_CANCEL, number: 0x1803},
		{signedType: SignedType_SIGNED_RETENTION_POLICY, number: 0x1804},
		{signedType: SignedType_SIGNED_DIRECTORY_CARD, number: 0x1805},
		{signedType: SignedType_SIGNED_DIRECTORY_REPO, number: 0x1806},

		{signedType: SignedType_SIGNED_BRIDGE_BLOCK, number: 0x1901},
		{signedType: SignedType_SIGNED_BRIDGE_ADDRESS, number: 0x1902},
		{signedType: SignedType_SIGNED_BRIDGE_ROUTE, number: 0x1903},
		{signedType: SignedType_SIGNED_BRIDGE_MAP, number: 0x1904},
		{signedType: SignedType_SIGNED_BRIDGE_EGRESS, number: 0x1905},
		{signedType: SignedType_SIGNED_BRIDGE_ALIAS, number: 0x1906},
		{signedType: SignedType_SIGNED_BRIDGE_WITHDRAW, number: 0x1907},
		{signedType: SignedType_SIGNED_WINDOW_DELEGATION, number: 0x1908},
		{signedType: SignedType_SIGNED_SHARE_CERT, number: 0x1909},

		{signedType: SignedType_SIGNED_SIDECAR_BINDING, number: 0x1A01},
	}
	for _, c := range cases {
		if int32(c.signedType) != c.number {
			t.Errorf("%s is %#x, want %#x", c.signedType, int32(c.signedType), c.number)
		}
	}
	// Each case is a value, so a value added to signed.proto joins this list deliberately.
	if len(cases) != len(SignedType_name)-1 {
		t.Errorf("%d cases for %d values", len(cases), len(SignedType_name)-1)
	}
}

// §6.11: service << 8 | n, with MessageType's service bytes, each value one body's.
func TestSignedTypesFollowServiceRule(t *testing.T) {
	services := []int32{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B}
	for number, name := range SignedType_name {
		if number == 0 {
			continue
		}
		if !slices.Contains(services, number>>8) || number&0xFF == 0 {
			t.Errorf("%s is %#x, outside service << 8 | n", name, number)
		}
		if !strings.HasPrefix(name, "SIGNED_") {
			t.Errorf("%s does not read SIGNED_<MESSAGE>", name)
		}
	}
}

// §4.4: std and protobuf only, tests included, so the iOS extension links this without the root or
// protocol (D-SDK-20).
func TestBridgeImportsOnlyStdAndProtobuf(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no source files found")
	}
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			firstElement, _, _ := strings.Cut(importPath, "/")
			std := !strings.Contains(firstElement, ".")
			protobuf := strings.HasPrefix(importPath, "google.golang.org/protobuf/")
			if !std && !protobuf {
				t.Errorf("%s imports %s", path, importPath)
			}
		}
	}
}
