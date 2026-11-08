// What the stacks row, the transcript replays and the fuzz targets share: tmc/mls reading credential 0xF552, in every
// build, and where the root's testdata is.

package mlsinterop

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tmc/mls"
	"github.com/tmc/mls/tlssyntax"
)

// The subset's credential and ur_group (§10.4).
const (
	tmcCredentialTypeUrSidecar mls.CredentialType = 0xf552
	tmcExtensionTypeUrGroup    mls.ExtensionType  = 0xf553
)

func init() {
	mls.RegisterCredential(tmcCredentialTypeUrSidecar, func() mls.CredentialCodec { return &tmcUrCredential{} })
}

// 0xF552's body: opaque<V> of UrMlsCredential's encoding (§10.4).
type tmcUrCredential struct {
	encoded []byte
}

func (self *tmcUrCredential) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(self.encoded)
}

func (self *tmcUrCredential) UnmarshalTLS(r *tlssyntax.Reader) {
	self.encoded = r.ReadOpaque()
}

// The root module's directory, wherever the layout puts it: this module's parent in development, v2026/ beside it
// on a release branch, whose go.mod requires the root by that versioned path (seedFiles's rule).
func interopRootDirectory(t testing.TB) string {
	t.Helper()
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if match := versionedRootRequire.FindSubmatch(goMod); match != nil {
		return filepath.Join("..", string(match[1]))
	}
	return ".."
}
