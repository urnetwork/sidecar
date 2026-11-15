//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// R(c) on real git repositories (EVS2-M10-26): nested .gitattributes, a later pattern overriding an earlier one, a
// pointer outside filter=lfs and a non-pointer under it, a .gitattributes-only commit bringing a stored pointer under
// filter=lfs (FS-73's clause), a tag peeled to its commit, the repository's own info/attributes not counting, a
// rename needing nothing, a 100,000-path tree's diff judging only the changed paths, git-lfs's pointer spec, and the
// same answers from git 2.34 where UR_TEST_GIT_2_34 names one.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A bare repository commits are written into by fast-import, each commit's tree exactly its files.
type evsTestLfsRepo struct {
	t       *testing.T
	git     *EvsGitRunner
	dir     string
	commits int
}

// A new bare repository on the system git.
func newEvsTestLfsRepo(t *testing.T) *evsTestLfsRepo {
	git := evsTestGitRunner(t)
	dir := filepath.Join(t.TempDir(), "repo.git")
	if _, err := git.Run(context.Background(), "", "init", "-q", "--bare", dir); err != nil {
		t.Fatal(err)
	}
	return &evsTestLfsRepo{t: t, git: git, dir: dir}
}

// A commit whose tree is exactly files, path to content; a content of "@<n>" is mode 120000, a symlink to n.
func (self *evsTestLfsRepo) commit(files map[string]string) EvsGitOid {
	self.t.Helper()
	self.commits += 1
	branch := fmt.Sprintf("refs/heads/c%d", self.commits)
	stream := &bytes.Buffer{}
	fmt.Fprintf(stream, "commit %s\ncommitter T <t@x.example> 1700000000 +0000\ndata 1\nc\ndeleteall\n", branch)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		content := files[path]
		mode := "100644"
		if target, isLink := strings.CutPrefix(content, "@"); isLink {
			mode, content = "120000", target
		}
		fmt.Fprintf(stream, "M %s inline %s\ndata %d\n%s\n", mode, path, len(content), content)
	}
	self.fastImport(stream)
	return self.revParse(branch)
}

// Runs fast-import over stream.
func (self *evsTestLfsRepo) fastImport(stream *bytes.Buffer) {
	self.t.Helper()
	if _, err := self.git.RunWith(context.Background(), &EvsGitRunArgs{Dir: self.dir, Args: []string{"fast-import", "--quiet"}, Input: stream}); err != nil {
		self.t.Fatal(err)
	}
}

// The oid a name resolves to.
func (self *evsTestLfsRepo) revParse(name string) EvsGitOid {
	self.t.Helper()
	out, err := self.git.Run(context.Background(), self.dir, "rev-parse", "--verify", name)
	if err != nil {
		self.t.Fatal(err)
	}
	oid, err := evsGitOidDecodeHex(bytes.TrimSpace(out))
	if err != nil {
		self.t.Fatal(err)
	}
	return oid
}

// The repository as R reads it.
func (self *evsTestLfsRepo) lfs() *EvsLfsGitRepo {
	return &EvsLfsGitRepo{Git: self.git, Dir: self.dir, Settings: DefaultEvsSettings()}
}

// A canonical v1 pointer to content named by n.
func evsTestLfsPointer(n int) string {
	return fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%064x\nsize %d\n", n, 1000+n)
}

// The oid evsTestLfsPointer(n) names.
func evsTestLfsOid(n int) EvsLfsOid {
	oid, err := EvsLfsOidDecodeHex(fmt.Sprintf("%064x", n))
	if err != nil {
		panic(err)
	}
	return oid
}

// The oids and paths of requirements, as "<n>@<path>" in oid order, for comparing.
func evsTestLfsNames(required []*EvsLfsRequirement) []string {
	names := []string{}
	for _, requirement := range required {
		names = append(names, fmt.Sprintf("%s@%s", strings.TrimLeft(requirement.Oid.String(), "0"), requirement.Path))
	}
	return names
}

// Fails unless R(c) is want.
func evsTestLfsExpect(t *testing.T, required []*EvsLfsRequirement, err error, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if got := evsTestLfsNames(required); !slices.Equal(got, want) {
		t.Fatalf("required %q, want %q", got, want)
	}
}

// Attributes nest by directory: a deeper .gitattributes overrides the root's for its subtree, and a directory without
// one takes its parent's.
func TestEvsLfsRequiredNestedAttributes(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	c := repo.commit(map[string]string{
		".gitattributes":            "*.bin filter=lfs diff=lfs merge=lfs -text\n",
		"a.bin":                     evsTestLfsPointer(1),
		"plain/b.bin":               evsTestLfsPointer(2),
		"off/.gitattributes":        "*.bin -filter\n",
		"off/c.bin":                 evsTestLfsPointer(3),
		"off/on/.gitattributes":     "d.bin filter=lfs\n",
		"off/on/d.bin":              evsTestLfsPointer(4),
		"off/on/e.bin":              evsTestLfsPointer(5),
		"other/.gitattributes":      "*.bin filter=other\n",
		"other/f.bin":               evsTestLfsPointer(6),
		"deep/er/still/g.bin":       evsTestLfsPointer(7),
		"deep/er/still/notbin.data": evsTestLfsPointer(8),
	})
	required, err := EvsLfsRequired(context.Background(), repo.lfs(), c)
	evsTestLfsExpect(t, required, err, "1@a.bin", "2@plain/b.bin", "4@off/on/d.bin", "7@deep/er/still/g.bin")
}

// Within one file a later line overrides an earlier one for the paths both match.
func TestEvsLfsRequiredLaterPatternOverrides(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	c := repo.commit(map[string]string{
		".gitattributes": "*.bin filter=lfs\nskip.bin -filter\n*.dat -filter\nkeep.dat filter=lfs\nunset.bin !filter\n",
		"a.bin":          evsTestLfsPointer(1),
		"skip.bin":       evsTestLfsPointer(2),
		"x.dat":          evsTestLfsPointer(3),
		"keep.dat":       evsTestLfsPointer(4),
		"unset.bin":      evsTestLfsPointer(5),
	})
	required, err := EvsLfsRequired(context.Background(), repo.lfs(), c)
	evsTestLfsExpect(t, required, err, "1@a.bin", "4@keep.dat")
}

// A stored pointer under no filter=lfs requires nothing, a filter=lfs blob that is no pointer requires nothing and
// is no error, and neither does a symlink whose target reads as a pointer, nor an empty file.
func TestEvsLfsRequiredOnlyPointersUnderFilter(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	c := repo.commit(map[string]string{
		".gitattributes": "*.bin filter=lfs\n",
		"plain.txt":      evsTestLfsPointer(1),
		"text.bin":       "just bytes, not a pointer\n",
		"large.bin":      strings.Repeat("x", 4096),
		"empty.bin":      "",
		"link.bin":       "@" + evsTestLfsPointer(2),
		"real.bin":       evsTestLfsPointer(3),
	})
	required, err := EvsLfsRequired(context.Background(), repo.lfs(), c)
	evsTestLfsExpect(t, required, err, "3@real.bin")
}

// FS-73's clause: a commit that changes only .gitattributes brings a stored pointer under filter=lfs, so the diff
// takes both trees whole and the unchanged pointer is required; the reverse requires nothing new.
func TestEvsLfsRequiredDiffAttributesOnlyCommit(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	files := map[string]string{"data.dat": evsTestLfsPointer(1), "other.dat": evsTestLfsPointer(2)}
	before := repo.commit(files)
	files[".gitattributes"] = "data.dat filter=lfs\n"
	after := repo.commit(files)
	required, err := EvsLfsRequiredDiff(context.Background(), repo.lfs(), &before, after)
	evsTestLfsExpect(t, required, err, "1@data.dat")
	required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), &after, before)
	evsTestLfsExpect(t, required, err)
	// a nested .gitattributes alone does the same
	files["sub/.gitattributes"] = "*.dat filter=lfs\n"
	files["sub/x.dat"] = evsTestLfsPointer(3)
	nested := repo.commit(files)
	files["sub/.gitattributes"] = "*.dat -filter\n"
	turnedOff := repo.commit(files)
	required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), &turnedOff, nested)
	evsTestLfsExpect(t, required, err, "3@sub/x.dat")
}

// An annotated tag requires what the commit it peels to requires, and a diff from no old tip is R(new) whole.
func TestEvsLfsRequiredTagPeeled(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	c := repo.commit(map[string]string{".gitattributes": "*.bin filter=lfs\n", "a.bin": evsTestLfsPointer(1)})
	stream := &bytes.Buffer{}
	fmt.Fprintf(stream, "tag v1\nfrom %s\ntagger T <t@x.example> 1700000000 +0000\ndata 1\nt\n", c)
	repo.fastImport(stream)
	// a tag of the tag, once the first is a ref
	stream.Reset()
	fmt.Fprintf(stream, "tag v2\nfrom refs/tags/v1\ntagger T <t@x.example> 1700000000 +0000\ndata 1\nt\n")
	repo.fastImport(stream)
	for _, name := range []string{"refs/tags/v1", "refs/tags/v2"} {
		tag := repo.revParse(name)
		if tag == c {
			t.Fatalf("%s is no annotated tag", name)
		}
		required, err := EvsLfsRequired(context.Background(), repo.lfs(), tag)
		evsTestLfsExpect(t, required, err, "1@a.bin")
		required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), nil, tag)
		evsTestLfsExpect(t, required, err, "1@a.bin")
	}
}

// The bare repository's info/attributes and a system attributes file do not count: attributes come from the tree.
func TestEvsLfsRequiredIgnoresRepositoryAttributes(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	c := repo.commit(map[string]string{".gitattributes": "kept.bin filter=lfs\n", "kept.bin": evsTestLfsPointer(1), "loose.bin": evsTestLfsPointer(2)})
	if err := os.MkdirAll(filepath.Join(repo.dir, "info"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo.dir, "info", "attributes"), []byte("loose.bin filter=lfs\nkept.bin -filter\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	required, err := EvsLfsRequired(context.Background(), repo.lfs(), c)
	evsTestLfsExpect(t, required, err, "1@kept.bin")
	// nothing is left behind in the repository
	entries, err := os.ReadDir(repo.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ur-lfs-") {
			t.Fatalf("scratch %s left in the repository", entry.Name())
		}
	}
}

// A pointer moved to another path requires nothing new, one copied requires its object (the superset the header
// names), and a pointer changed in place requires its new object alone.
func TestEvsLfsRequiredDiffRenameAndChange(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	attributes := "*.bin filter=lfs\n"
	before := repo.commit(map[string]string{".gitattributes": attributes, "a.bin": evsTestLfsPointer(1), "b.bin": evsTestLfsPointer(2)})
	moved := repo.commit(map[string]string{".gitattributes": attributes, "dir/moved.bin": evsTestLfsPointer(1), "b.bin": evsTestLfsPointer(2)})
	required, err := EvsLfsRequiredDiff(context.Background(), repo.lfs(), &before, moved)
	evsTestLfsExpect(t, required, err)
	changed := repo.commit(map[string]string{".gitattributes": attributes, "a.bin": evsTestLfsPointer(1), "b.bin": evsTestLfsPointer(3)})
	required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), &before, changed)
	evsTestLfsExpect(t, required, err, "3@b.bin")
	copied := repo.commit(map[string]string{".gitattributes": attributes, "a.bin": evsTestLfsPointer(1), "b.bin": evsTestLfsPointer(2), "c.bin": evsTestLfsPointer(1)})
	required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), &before, copied)
	evsTestLfsExpect(t, required, err, "1@c.bin")
	required, err = EvsLfsRequiredDiff(context.Background(), repo.lfs(), &before, before)
	evsTestLfsExpect(t, required, err)
}

// A 100,000-path tree's diff asks attributes of, and reads, only the paths that changed, and finds what they need.
func TestEvsLfsRequiredDiffJudgesOnlyChangedPaths(t *testing.T) {
	repo := newEvsTestLfsRepo(t)
	const pathCount = 100000
	stream := &bytes.Buffer{}
	pointer := evsTestLfsPointer(1)
	fmt.Fprintf(stream, "blob\nmark :1\ndata %d\n%s\n", len(pointer), pointer)
	fmt.Fprintf(stream, "commit refs/heads/big\nmark :2\ncommitter T <t@x.example> 1700000000 +0000\ndata 1\nc\n")
	fmt.Fprintf(stream, "M 100644 inline .gitattributes\ndata 17\n*.bin filter=lfs\n\n")
	for i := 0; i < pathCount; i += 1 {
		fmt.Fprintf(stream, "M 100644 :1 d%03d/e%03d/f%d.bin\n", i%100, (i/100)%100, i)
	}
	fmt.Fprintf(stream, "commit refs/heads/next\ncommitter T <t@x.example> 1700000001 +0000\ndata 1\nn\nfrom :2\n")
	added, changed := evsTestLfsPointer(2), evsTestLfsPointer(3)
	fmt.Fprintf(stream, "M 100644 inline d007/e000/new.bin\ndata %d\n%s\n", len(added), added)
	fmt.Fprintf(stream, "M 100644 inline d042/e000/f42.bin\ndata %d\n%s\n", len(changed), changed)
	fmt.Fprintf(stream, "D d099/e000/f99.bin\n")
	repo.fastImport(stream)
	old, new := repo.revParse("refs/heads/big"), repo.revParse("refs/heads/next")
	judged := []string{}
	lfs := repo.lfs()
	lfs.judged = func(path string) { judged = append(judged, path) }
	required, err := EvsLfsRequiredDiff(context.Background(), lfs, &old, new)
	evsTestLfsExpect(t, required, err, "2@d007/e000/new.bin", "3@d042/e000/f42.bin")
	slices.Sort(judged)
	want := []string{"d007/e000/new.bin", "d042/e000/f42.bin", "d042/e000/f42.bin", "d099/e000/f99.bin"}
	if !slices.Equal(judged, want) {
		t.Fatalf("judged %q, want %q", judged, want)
	}
}

// git-lfs's pointer spec: the canonical form and the pre-release version pass, as do extensions in order; anything
// else is no pointer.
func TestEvsLfsParsePointer(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	canonical := "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex + "\nsize 12345\n"
	cases := []struct {
		data string
		ok   bool
	}{
		{data: canonical, ok: true},
		{data: "version https://hawser.github.com/spec/v1\noid sha256:" + hex + "\nsize 0\n", ok: true},
		{data: "version https://git-lfs.github.com/spec/v1\next-0-foo sha256:" + hex + "\next-1-bar sha256:" + hex + "\noid sha256:" + hex + "\nsize 1\n", ok: true},
		{data: "version https://git-lfs.github.com/spec/v1\next-1-bar sha256:" + hex + "\next-0-foo sha256:" + hex + "\noid sha256:" + hex + "\nsize 1\n", ok: false},
		{data: strings.TrimSuffix(canonical, "\n"), ok: false},
		{data: strings.ReplaceAll(canonical, "\n", "\r\n"), ok: false},
		{data: strings.ToUpper(canonical[:0]) + strings.Replace(canonical, hex, strings.ToUpper(hex), 1), ok: false},
		{data: "version https://git-lfs.github.com/spec/v2\noid sha256:" + hex + "\nsize 1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha1:" + hex[:40] + "\nsize 1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex[:62] + "\nsize 1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex + "\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex + "\nsize -1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex + "\nsize 1x\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\noid sha256:" + hex + "\nsize 1\nextra 1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\nsize 1\noid sha256:" + hex + "\n", ok: false},
		{data: "oid sha256:" + hex + "\nversion https://git-lfs.github.com/spec/v1\nsize 1\n", ok: false},
		{data: "version https://git-lfs.github.com/spec/v1\n\noid sha256:" + hex + "\nsize 1\n", ok: false},
		{data: canonical + strings.Repeat(" ", 1024), ok: false},
		{data: "", ok: false},
	}
	for i, c := range cases {
		pointer, ok := EvsLfsParsePointer([]byte(c.data), 1024)
		if ok != c.ok {
			t.Errorf("case %d: parsed %v, want %v", i, ok, c.ok)
		}
		if ok && i == 0 && (pointer.Size != 12345 || pointer.Oid.String() != hex) {
			t.Errorf("the canonical pointer read as %+v", pointer)
		}
	}
	// the bound: a pointer padded to 1,024 bytes is no pointer, one byte less still parses if its form holds
	if _, ok := EvsLfsParsePointer([]byte(canonical), int64(len(canonical))); ok {
		t.Error("a pointer at the bound parsed")
	}
	if _, ok := EvsLfsParsePointer([]byte(canonical), int64(len(canonical)+1)); !ok {
		t.Error("a pointer under the bound did not parse")
	}
}

// git 2.34, §22.9's matrix floor, answers as this host's git does, where UR_TEST_GIT_2_34 names its absolute path.
func TestEvsLfsRequiredMatchesGitFloor(t *testing.T) {
	floorPath := os.Getenv("UR_TEST_GIT_2_34")
	if floorPath == "" {
		t.Skip("UR_TEST_GIT_2_34 names no git 2.34")
	}
	repo := newEvsTestLfsRepo(t)
	before := repo.commit(map[string]string{".gitattributes": "*.bin filter=lfs\nsub/** -filter\n", "a.bin": evsTestLfsPointer(1), "sub/b.bin": evsTestLfsPointer(2)})
	after := repo.commit(map[string]string{".gitattributes": "*.bin filter=lfs\n", "a.bin": evsTestLfsPointer(1), "sub/b.bin": evsTestLfsPointer(2), "c.bin": evsTestLfsPointer(3)})
	floor, err := NewEvsGitRunner(context.Background(), floorPath, t.TempDir(), DefaultEvsSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, git := range []*EvsGitRunner{repo.git, floor} {
		lfs := &EvsLfsGitRepo{Git: git, Dir: repo.dir, Settings: DefaultEvsSettings()}
		required, err := EvsLfsRequired(context.Background(), lfs, after)
		evsTestLfsExpect(t, required, err, "1@a.bin", "2@sub/b.bin", "3@c.bin")
		required, err = EvsLfsRequiredDiff(context.Background(), lfs, &before, after)
		evsTestLfsExpect(t, required, err, "2@sub/b.bin", "3@c.bin")
	}
}
