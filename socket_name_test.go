// §9.4's grammar, and §22.5's fixed vectors for K_tok, K_seal, tokens and 152 B seals. The vectors
// under testdata/socket came from §9.4's text by a separate implementation, with its own ChaCha20 and
// Poly1305 checked against RFC 8439's and the XChaCha draft's published vectors, so a mistake in how
// this code composes its primitives fails here instead of being written into the file.
//
// The files are built into the test binary: this runs on the sidecar_http leg too, whose Worker has no
// file system, and §22.5 wants the bytes equal on every leg (TestHttpLegPassesInAWorker names these).

package sidecar

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed testdata/socket/tokens.json testdata/socket/seals.json testdata/socket/key_file.json
var socketVectorFiles embed.FS

// Fixed test ids and keys, none of which come from the vector files.
var (
	testSocketNetworkId      = Id{1: 1, 15: 1}
	testSocketOtherNetworkId = Id{1: 2, 15: 2}
	testSocketKey            = bytes.Repeat([]byte{0x11}, socketKeyByteCount)
	testSocketOtherKey       = bytes.Repeat([]byte{0x22}, socketKeyByteCount)
)

// One 26-character share token.
const testSocketShareToken = "abcdefghijklmnopqrstuvwx27"

func testSocketKeys(t testing.TB, networkId Id, socketKey []byte) *SocketKeys {
	t.Helper()
	keys, err := NewSocketKeys(networkId, socketKey)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Hex text in a vector file.
func testSocketHex(t testing.TB, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// Reads one vector file under testdata/socket into target.
func testSocketVectors(t testing.TB, name string, target any) {
	t.Helper()
	data, err := socketVectorFiles.ReadFile("testdata/socket/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

// A name of exactly byteCount bytes, in two segments of application bytes.
func testSocketLongName(byteCount int) string {
	return strings.Repeat("x", socketSegmentMaxByteCount) + "/" + strings.Repeat("y", byteCount-socketSegmentMaxByteCount-1)
}

func TestParseSocketNameAccepts(t *testing.T) {
	cases := []struct {
		text      string
		name      string
		namespace SocketNamespace
	}{
		// application names, with every byte of the set
		{text: "db", name: "db", namespace: SocketNamespaceApplication},
		{text: "db/primary", name: "db/primary", namespace: SocketNamespaceApplication},
		{text: "a-b_c.d/0-9", name: "a-b_c.d/0-9", namespace: SocketNamespaceApplication},
		{text: "db/@", name: "db/@", namespace: SocketNamespaceApplication},
		{text: "db/@/primary", name: "db/@/primary", namespace: SocketNamespaceApplication},
		{text: "db/_x", name: "db/_x", namespace: SocketNamespaceApplication},
		{text: "db/.../x", name: "db/.../x", namespace: SocketNamespaceApplication},
		{text: "db/.a", name: "db/.a", namespace: SocketNamespaceApplication},
		{text: "-a/b", name: "-a/b", namespace: SocketNamespaceApplication},
		{text: "1a", name: "1a", namespace: SocketNamespaceApplication},
		// uppercase ASCII folds
		{text: "DB/Primary", name: "db/primary", namespace: SocketNamespaceApplication},
		{text: "AZ/az", name: "az/az", namespace: SocketNamespaceApplication},
		// a reserved word that is not the whole first segment, or is not the first
		{text: "tlsx/443/blog", name: "tlsx/443/blog", namespace: SocketNamespaceApplication},
		{text: "tls.x/y", name: "tls.x/y", namespace: SocketNamespaceApplication},
		{text: "shared/x", name: "shared/x", namespace: SocketNamespaceApplication},
		{text: "urn/x", name: "urn/x", namespace: SocketNamespaceApplication},
		{text: "system/x", name: "system/x", namespace: SocketNamespaceApplication},
		{text: "db/tls/443/blog", name: "db/tls/443/blog", namespace: SocketNamespaceApplication},
		// each tls/ port
		{text: "tls/443/blog", name: "tls/443/blog", namespace: SocketNamespaceTls},
		{text: "tls/8443/blog", name: "tls/8443/blog", namespace: SocketNamespaceTls},
		{text: "tls/8883/blog", name: "tls/8883/blog", namespace: SocketNamespaceTls},
		{text: "tls/5671/blog", name: "tls/5671/blog", namespace: SocketNamespaceTls},
		// each form of <host>
		{text: "tls/443/@", name: "tls/443/@", namespace: SocketNamespaceTls},
		{text: "tls/443/api-dev", name: "tls/443/api-dev", namespace: SocketNamespaceTls},
		{text: "tls/443/blog.scope", name: "tls/443/blog.scope", namespace: SocketNamespaceTls},
		{text: "tls/443/" + strings.Repeat("a", 63), name: "tls/443/" + strings.Repeat("a", 63), namespace: SocketNamespaceTls},
		{text: "tls/443/" + strings.Repeat("a", 31) + "." + strings.Repeat("b", 31), name: "tls/443/" + strings.Repeat("a", 31) + "." + strings.Repeat("b", 31), namespace: SocketNamespaceTls},
		// the fold comes before the namespace, so case hides nothing
		{text: "TLS/443/Blog", name: "tls/443/blog", namespace: SocketNamespaceTls},
		{text: "Smtp/25/MX", name: "smtp/25/mx", namespace: SocketNamespaceSmtp},
		{text: "UR/SmtpEdge", name: "ur/smtpedge", namespace: SocketNamespacePlatform},
		{text: "SHARE/" + strings.ToUpper(testSocketShareToken), name: "share/" + testSocketShareToken, namespace: SocketNamespaceShare},
		// the other owners
		{text: "smtp/25/mx", name: "smtp/25/mx", namespace: SocketNamespaceSmtp},
		{text: "smtp/25/mx.scope", name: "smtp/25/mx.scope", namespace: SocketNamespaceSmtp},
		{text: "smtp/25/@", name: "smtp/25/@", namespace: SocketNamespaceSmtp},
		{text: "ur/smtpedge", name: "ur/smtpedge", namespace: SocketNamespacePlatform},
		{text: "share/" + testSocketShareToken, name: "share/" + testSocketShareToken, namespace: SocketNamespaceShare},
		// reserved, with no owner, parse as that
		{text: "c/invite", name: "c/invite", namespace: SocketNamespaceReserved},
		{text: "c", name: "c", namespace: SocketNamespaceReserved},
		{text: "sys", name: "sys", namespace: SocketNamespaceReserved},
		{text: "sys/x", name: "sys/x", namespace: SocketNamespaceReserved},
		{text: "x", name: "x", namespace: SocketNamespaceReserved},
		{text: "7/x", name: "7/x", namespace: SocketNamespaceReserved},
		{text: "@", name: "@", namespace: SocketNamespaceReserved},
		{text: "@/x", name: "@/x", namespace: SocketNamespaceReserved},
		{text: "-", name: "-", namespace: SocketNamespaceReserved},
		{text: "_", name: "_", namespace: SocketNamespaceReserved},
		{text: "_x", name: "_x", namespace: SocketNamespaceReserved},
		{text: "_x/y", name: "_x/y", namespace: SocketNamespaceReserved},
		{text: "X/y", name: "x/y", namespace: SocketNamespaceReserved},
		{text: "SYS/y", name: "sys/y", namespace: SocketNamespaceReserved},
	}
	for _, c := range cases {
		name, namespace, err := ParseSocketName(c.text)
		if err != nil {
			t.Errorf("%q: %v", c.text, err)
			continue
		}
		if name != c.name || namespace != c.namespace {
			t.Errorf("%q: got %q %d, want %q %d", c.text, name, namespace, c.name, c.namespace)
		}
		// canonical means a fixed point
		again, againNamespace, err := ParseSocketName(name)
		if err != nil || again != name || againNamespace != namespace {
			t.Errorf("%q: %q did not read back: %q %d %v", c.text, name, again, againNamespace, err)
		}
	}
}

func TestParseSocketNameRefuses(t *testing.T) {
	cases := []string{
		// empty segments
		"", "/", "/db", "db/", "db//primary",
		// "." and ".." as whole segments, here and in every namespace, however spelled
		".", "..", "db/.", "db/..", "./db", "../db", "db/../primary", "tls/443/..",
		// "@" is a whole segment, never a byte of one
		"a@b/c", "db/@x", "db/x@", "db/@@",
		// out of the set: no percent decoding, and no other byte folds or passes
		"db%2fprimary", "%2e%2e/db", "db/%41", "db primary", " db", "db ", "db\tprimary", "db\n", "db\x00", "\x00",
		"db\\primary", "db:primary", "db+x", "db#x", "db?x", "db*", "db/*",
		"db/\xff", "\xc3\xa9db", "db/caf\xc3\xa9",
		// U+212A folds to "k" in Unicode and must not here, nor U+0130 to "i"
		"\xe2\x84\xaa/x", "ab/\xe2\x84\xaa", "\xc4\xb0x/y",
		// the owners' forms are exact: too short
		"tls", "tls/443", "smtp", "smtp/25", "ur", "share",
		// deeper names are refused, not read as a shallower one
		"tls/443/blog/x", "smtp/25/mx/x", "ur/smtpedge/x", "share/" + testSocketShareToken + "/x",
		// ports, with no leading zeros, nor anything else that reads the same
		"tls/80/blog", "tls/444/blog", "tls/25/blog", "tls/0443/blog", "tls/00443/blog", "tls/443x/blog", "tls/+443/blog", "tls/4.43/blog",
		"tls/@/blog", "smtp/587/mx", "smtp/465/mx", "smtp/443/mx", "smtp/025/mx", "smtp/25x/mx",
		// <host>: LDH, no hyphen at either end, one scope at most
		"tls/443/-blog", "tls/443/blog-", "tls/443/a_b", "tls/443/.blog", "tls/443/blog.", "tls/443/a..b", "tls/443/-a.b", "tls/443/a-.b",
		"tls/443/a.-b", "tls/443/a.b-", "tls/443/a.b.c", "tls/443/a.b.c.d", "tls/443/@.scope", "tls/443/a.@",
		// a scope form's 63 bytes are one segment's, and smtp/ scopes only mx
		"tls/443/" + strings.Repeat("a", 64), "tls/443/" + strings.Repeat("a", 32) + "." + strings.Repeat("b", 31),
		"smtp/25/mail.scope", "smtp/25/mx.a.b", "smtp/25/mx.", "smtp/25/.mx", "smtp/25/@.scope",
		// ur/<service> is a label
		"ur/@", "ur/-x", "ur/x-", "ur/a.b", "ur/a_b",
		// share/<token> is 26 bytes of lowercase base32, and base32 has no 0, 1, 8 or 9
		"share/x", "share/@", "share/" + testSocketShareToken[:25], "share/" + testSocketShareToken + "a",
		"share/" + testSocketShareToken[:25] + "0", "share/" + testSocketShareToken[:25] + "1", "share/" + testSocketShareToken[:25] + "8",
		"share/" + testSocketShareToken[:25] + "9", "share/" + testSocketShareToken[:25] + "-",
		// lengths: the positive twins are in TestSocketNameBounds
		strings.Repeat("a", 64), "db/" + strings.Repeat("a", 64), testSocketLongName(113),
		"a1/b2/c3/d4/e5/f6/g7/h8/i9",
	}
	for _, text := range cases {
		name, namespace, err := ParseSocketName(text)
		if err == nil {
			t.Errorf("%q parsed: %q %d", text, name, namespace)
		}
		if name != "" || namespace != 0 {
			t.Errorf("%q: a refusal came back with %q %d", text, name, namespace)
		}
	}
}

func TestSocketNameBounds(t *testing.T) {
	cases := []string{
		strings.Repeat("a", 63),
		"db/" + strings.Repeat("a", 63),
		testSocketLongName(112),
		"a1/b2/c3/d4/e5/f6/g7/h8",
	}
	if len(testSocketLongName(112)) != 112 {
		t.Fatal("the long name is the wrong length")
	}
	for _, text := range cases {
		if name, namespace, err := ParseSocketName(text); err != nil || name != text || namespace != SocketNamespaceApplication {
			t.Errorf("%q: %q %d %v", text, name, namespace, err)
		}
	}
}

// A refusal must not hand an unexpected name back through its error (I-13).
func TestSocketErrorsNeverRepeatTheName(t *testing.T) {
	secret := "SECRETNAME"
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	calls := []func() error{
		func() error { _, _, err := ParseSocketName(secret + "%"); return err },
		func() error { _, _, err := parseSocketAddressText(secret + "%:db"); return err },
		func() error { _, _, err := parseSocketAddressText("acme:" + secret + "%"); return err },
		func() error { _, err := keys.TokenPath(secret + "%"); return err },
		func() error { _, err := keys.TokenPrefix(secret + "%"); return err },
		func() error { _, err := keys.Seal(secret + "%"); return err },
	}
	for index, call := range calls {
		err := call()
		if err == nil {
			t.Errorf("call %d passed", index)
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret)) {
			t.Errorf("call %d repeated the name: %v", index, err)
		}
	}
}

func TestParseSocketAddressTextOnEveryLeg(t *testing.T) {
	cases := []struct {
		text         string
		networkLabel string
		name         string
	}{
		{text: "db", name: "db"},
		{text: "acme:db/primary", networkLabel: "acme", name: "db/primary"},
		{text: "ACME:DB/Primary", networkLabel: "acme", name: "db/primary"},
		{text: "abcdefghij:tls/443/blog", networkLabel: "abcdefghij", name: "tls/443/blog"},
		{text: "a-1:smtp/25/mx", networkLabel: "a-1", name: "smtp/25/mx"},
		{text: "ur/smtpedge", name: "ur/smtpedge"},
		{text: strings.Repeat("a", 63) + ":db", networkLabel: strings.Repeat("a", 63), name: "db"},
	}
	for _, c := range cases {
		networkLabel, name, err := parseSocketAddressText(c.text)
		if err != nil {
			t.Errorf("%q: %v", c.text, err)
			continue
		}
		if networkLabel != c.networkLabel || name != c.name {
			t.Errorf("%q: got %q %q", c.text, networkLabel, name)
		}
	}
	for _, text := range []string{
		"", ":", ":db", "acme:", "a:b:c", "acme:db:x", "acme::db",
		"-acme:db", "acme-:db", "ac_me:db", "ac.me:db", "ac me:db", "%61cme:db", "\xe2\x84\xaa:db",
		strings.Repeat("a", 64) + ":db", "acme:db/..", "acme:db/", "acme:tls/80/blog",
	} {
		if networkLabel, name, err := parseSocketAddressText(text); err == nil {
			t.Errorf("%q parsed: %q %q", text, networkLabel, name)
		}
	}
}

func TestSocketKeysRefuseWhatIsNotAKey(t *testing.T) {
	for _, socketKey := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := NewSocketKeys(testSocketNetworkId, socketKey); err == nil {
			t.Errorf("a %d-byte key passed", len(socketKey))
		}
	}
	if _, err := NewSocketKeys(Id{}, testSocketKey); err == nil {
		t.Error("the zero network id passed")
	}
}

func TestSocketTokenVectors(t *testing.T) {
	var vectors struct {
		Groups []struct {
			NetworkId string `json:"network_id"`
			SocketKey string `json:"k_sock"`
			TokenKey  string `json:"k_tok"`
			SealKey   string `json:"k_seal"`
			Names     []struct {
				Input     string   `json:"input"`
				Name      string   `json:"name"`
				Tokens    []string `json:"tokens"`
				NameToken string   `json:"name_token"`
			} `json:"names"`
			Prefixes []struct {
				Input     string `json:"input"`
				NameToken string `json:"name_token"`
			} `json:"prefixes"`
		} `json:"groups"`
	}
	testSocketVectors(t, "tokens.json", &vectors)
	if len(vectors.Groups) != 3 {
		t.Fatalf("%d groups", len(vectors.Groups))
	}
	for _, group := range vectors.Groups {
		networkId, err := IdFromBytes(testSocketHex(t, group.NetworkId))
		if err != nil {
			t.Fatal(err)
		}
		keys := testSocketKeys(t, networkId, testSocketHex(t, group.SocketKey))
		if !bytes.Equal(keys.tokenKey, testSocketHex(t, group.TokenKey)) {
			t.Errorf("%s: K_tok %x", group.NetworkId, keys.tokenKey)
		}
		// NewSocketKeys keeps K_seal only inside its AEAD, so compare it with one built from the file's
		// bytes: equal tags mean equal keys
		fileAead, err := chacha20poly1305.NewX(testSocketHex(t, group.SealKey))
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, fileAead.NonceSize())
		if !bytes.Equal(fileAead.Seal(nil, nonce, nil, nil), keys.sealAead.Seal(nil, nonce, nil, nil)) {
			t.Errorf("%s: K_seal differs", group.NetworkId)
		}
		if len(group.Names) == 0 || len(group.Prefixes) == 0 {
			t.Fatal("nothing to check")
		}
		for _, vector := range group.Names {
			nameToken, err := keys.TokenPath(vector.Input)
			if err != nil {
				t.Errorf("%q: %v", vector.Input, err)
				continue
			}
			if !bytes.Equal(nameToken, testSocketHex(t, vector.NameToken)) {
				t.Errorf("%q: name_token %x", vector.Input, nameToken)
			}
			if len(nameToken) != len(vector.Tokens)*socketTokenByteCount {
				t.Errorf("%q: %d bytes for %d segments", vector.Input, len(nameToken), len(vector.Tokens))
			}
			canonical, _, err := ParseSocketName(vector.Input)
			if err != nil || canonical != vector.Name {
				t.Errorf("%q: canonical %q %v", vector.Input, canonical, err)
			}
			for index, token := range vector.Tokens {
				got := nameToken[index*socketTokenByteCount : (index+1)*socketTokenByteCount]
				if !bytes.Equal(got, testSocketHex(t, token)) {
					t.Errorf("%q: t_%d %x", vector.Input, index+1, got)
				}
			}
		}
		for _, vector := range group.Prefixes {
			nameToken, err := keys.TokenPrefix(vector.Input)
			if err != nil {
				t.Errorf("%q: %v", vector.Input, err)
				continue
			}
			if !bytes.Equal(nameToken, testSocketHex(t, vector.NameToken)) {
				t.Errorf("%q: prefix %x", vector.Input, nameToken)
			}
		}
	}
}

// The file's name_token and sealed_name, with what an open must answer.
type socketSealVectors struct {
	NetworkId string `json:"network_id"`
	SocketKey string `json:"k_sock"`
	Kept      []struct {
		Name       string `json:"name"`
		Nonce      string `json:"nonce"`
		NameToken  string `json:"name_token"`
		SealedName string `json:"sealed_name"`
	} `json:"kept"`
	Dropped []struct {
		Reason     string `json:"reason"`
		NameToken  string `json:"name_token"`
		SealedName string `json:"sealed_name"`
	} `json:"dropped"`
}

func TestSocketSealVectors(t *testing.T) {
	var vectors socketSealVectors
	testSocketVectors(t, "seals.json", &vectors)
	networkId, err := IdFromBytes(testSocketHex(t, vectors.NetworkId))
	if err != nil {
		t.Fatal(err)
	}
	keys := testSocketKeys(t, networkId, testSocketHex(t, vectors.SocketKey))
	if len(vectors.Kept) == 0 {
		t.Fatal("nothing to keep")
	}
	for _, vector := range vectors.Kept {
		want := testSocketHex(t, vector.SealedName)
		if len(want) != 152 {
			t.Errorf("%q: a %d-byte seal", vector.Name, len(want))
		}
		sealed, err := keys.sealWithNonce(vector.Name, testSocketHex(t, vector.Nonce))
		if err != nil {
			t.Errorf("%q: %v", vector.Name, err)
			continue
		}
		if !bytes.Equal(sealed, want) {
			t.Errorf("%q: seal %x", vector.Name, sealed)
		}
		name, ok := keys.Open(testSocketHex(t, vector.NameToken), want)
		if !ok || name != vector.Name {
			t.Errorf("%q: opened %q %v", vector.Name, name, ok)
		}
	}
}

// Each one fixed by the file: moved, mismatched, tampered, the wrong length, or authentic and still
// not a name this token may stand for.
func TestSocketSealDropVectors(t *testing.T) {
	var vectors socketSealVectors
	testSocketVectors(t, "seals.json", &vectors)
	networkId, err := IdFromBytes(testSocketHex(t, vectors.NetworkId))
	if err != nil {
		t.Fatal(err)
	}
	keys := testSocketKeys(t, networkId, testSocketHex(t, vectors.SocketKey))
	if len(vectors.Dropped) < 15 {
		t.Fatalf("%d drops", len(vectors.Dropped))
	}
	for _, vector := range vectors.Dropped {
		if name, ok := keys.Open(testSocketHex(t, vector.NameToken), testSocketHex(t, vector.SealedName)); ok || name != "" {
			t.Errorf("%s: kept %q", vector.Reason, name)
		}
	}
}

func TestSealRoundTripsEveryBlindedForm(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	for _, name := range []string{"db", "db/primary", "db/@", "a1/b2/c3/d4/e5/f6/g7/h8", testSocketLongName(112), "share/" + testSocketShareToken} {
		nameToken, err := keys.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := keys.Seal(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != 152 {
			t.Errorf("%q: %d bytes", name, len(sealed))
		}
		if opened, ok := keys.Open(nameToken, sealed); !ok || opened != name {
			t.Errorf("%q: opened %q %v", name, opened, ok)
		}
	}
}

func TestSealFoldsItsName(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	nameToken, err := keys.TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.Seal("DB/Primary")
	if err != nil {
		t.Fatal(err)
	}
	if opened, ok := keys.Open(nameToken, sealed); !ok || opened != "db/primary" {
		t.Errorf("opened %q %v", opened, ok)
	}
}

func TestSealsOfOneNameDiffer(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	first, err := keys.Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || bytes.Equal(first[:24], second[:24]) {
		t.Error("two seals shared a nonce")
	}
}

func TestEdgeAndReservedNamesHaveNoTokenPath(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	for _, name := range []string{"tls/443/blog", "smtp/25/mx", "ur/smtpedge", "TLS/443/blog", "sys/x", "c/x", "x", "@", "_x"} {
		if nameToken, err := keys.TokenPath(name); err == nil {
			t.Errorf("%q: token path %x", name, nameToken)
		}
		if sealed, err := keys.Seal(name); err == nil {
			t.Errorf("%q: seal %x", name, sealed)
		}
	}
	for _, prefix := range []string{"tls", "smtp", "ur", "tls/443", "SMTP/25", "sys", "c", "x", "@", "_x"} {
		if nameToken, err := keys.TokenPrefix(prefix); err == nil {
			t.Errorf("%q: prefix %x", prefix, nameToken)
		}
	}
}

func TestTokenPrefixIsAWholeSegmentCut(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	name := "a1/b2/c3/d4/e5/f6/g7/h8"
	nameToken, err := keys.TokenPath(name)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(name, "/")
	for count := 1; count <= len(segments); count += 1 {
		prefix, err := keys.TokenPrefix(strings.Join(segments[:count], "/"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prefix, nameToken[:count*socketTokenByteCount]) {
			t.Errorf("%d segments: %x", count, prefix)
		}
	}
	// a prefix need not be a whole name: share/<token> is one, share is not
	sharePrefix, err := keys.TokenPrefix("share")
	if err != nil {
		t.Fatal(err)
	}
	shareToken, err := keys.TokenPath("share/" + testSocketShareToken)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(shareToken, sharePrefix) || len(sharePrefix) != socketTokenByteCount {
		t.Errorf("share prefix %x of %x", sharePrefix, shareToken)
	}
	if empty, err := keys.TokenPrefix(""); err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("no segments: %x %v", empty, err)
	}
	for _, prefix := range []string{"db/", "/db", "db//x", "db/..", "db%2f", "a1/b2/c3/d4/e5/f6/g7/h8/i9", testSocketLongName(113)} {
		if got, err := keys.TokenPrefix(prefix); err == nil {
			t.Errorf("%q: %x", prefix, got)
		}
	}
}

// t_i covers t_{i-1}, so a segment's token depends on where it sits, and two names that share a last
// segment share no token.
func TestTokensChainThroughEarlierSegments(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	first, err := keys.TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.TokenPath("cache/primary")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[socketTokenByteCount:], second[socketTokenByteCount:]) {
		t.Error("a segment's token ignored the segment before it")
	}
	joined, err := keys.TokenPath("db.primary")
	if err != nil {
		t.Fatal(err)
	}
	if len(joined) != socketTokenByteCount {
		t.Errorf("one segment made %d bytes", len(joined))
	}
}

// The network id is the salt and t_0, and a label is neither, so a rename or a reclaim moves nothing
// and two networks share no token (D-SOCK-1, R-SOCK-5).
func TestTokensFollowTheNetworkIdAlone(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	renamed := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	other := testSocketKeys(t, testSocketOtherNetworkId, testSocketKey)
	for _, addressText := range [][2]string{{"acme:db/primary", "renamed:db/primary"}, {"db/primary", "renamed:db/primary"}} {
		_, name, err := parseSocketAddressText(addressText[0])
		if err != nil {
			t.Fatal(err)
		}
		_, renamedName, err := parseSocketAddressText(addressText[1])
		if err != nil {
			t.Fatal(err)
		}
		nameToken, err := keys.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		renamedToken, err := renamed.TokenPath(renamedName)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nameToken, renamedToken) {
			t.Error("a rename moved a token path")
		}
		otherToken, err := other.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(nameToken[:socketTokenByteCount], otherToken[:socketTokenByteCount]) {
			t.Error("two networks shared a token")
		}
	}
}

func TestMovedSealsAreDropped(t *testing.T) {
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	other := testSocketKeys(t, testSocketOtherNetworkId, testSocketKey)
	sealed, err := keys.Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	nameToken, err := keys.TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := keys.TokenPath("db/replica")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := keys.Open(otherToken, sealed); ok {
		t.Errorf("moved to another token: %q", name)
	}
	if name, ok := other.Open(nameToken, sealed); ok {
		t.Errorf("moved to another network: %q", name)
	}
	if name, ok := keys.Open(nameToken[:socketTokenByteCount], sealed); ok {
		t.Errorf("under a prefix of its token: %q", name)
	}
	if name, ok := keys.Open(nil, sealed); ok {
		t.Errorf("under no token: %q", name)
	}
	if name, ok := keys.Open(nameToken, nil); ok {
		t.Errorf("no seal: %q", name)
	}
	if name, ok := keys.Open(nameToken, sealed); !ok || name != "db/primary" {
		t.Errorf("its own token: %q %v", name, ok)
	}
}

// The overlap's two sides (§9.4): a caller inside it passes the previous keys, a caller past it does
// not, and a seal of the old key opens only for the first.
func TestPreviousKeysOpenOnlyInsideTheOverlap(t *testing.T) {
	newest := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	previous := testSocketKeys(t, testSocketNetworkId, testSocketOtherKey)
	oldToken, err := previous.TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	oldSeal, err := previous.Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := newest.TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	newSeal, err := newest.Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldToken, newToken) {
		t.Fatal("a rotation left the token path alone")
	}

	if name, ok := OpenSocketName(newest, previous, oldToken, oldSeal); !ok || name != "db/primary" {
		t.Errorf("inside the overlap: %q %v", name, ok)
	}
	if name, ok := OpenSocketName(newest, nil, oldToken, oldSeal); ok {
		t.Errorf("past the overlap: %q", name)
	}
	// the newest keys first, and a new seal needs no overlap at all
	if name, ok := OpenSocketName(newest, previous, newToken, newSeal); !ok || name != "db/primary" {
		t.Errorf("a new seal with both: %q %v", name, ok)
	}
	if name, ok := OpenSocketName(newest, nil, newToken, newSeal); !ok || name != "db/primary" {
		t.Errorf("a new seal alone: %q %v", name, ok)
	}
	// each path's seal is bound to its own key's token
	if name, ok := OpenSocketName(newest, previous, newToken, oldSeal); ok {
		t.Errorf("the old seal under the new path: %q", name)
	}
	if name, ok := OpenSocketName(newest, previous, oldToken, newSeal); ok {
		t.Errorf("the new seal under the old path: %q", name)
	}
	if name, ok := OpenSocketName(nil, nil, newToken, newSeal); ok {
		t.Errorf("no keys: %q", name)
	}
}
