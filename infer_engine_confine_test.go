//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The helper's confinement on every leg (infer_engine_confine.go; INFER-M11-05): what the daemon names in the helper's
// environment, read back and refused unless whole; the Linux seccomp filter run on bpf's VM for both architectures;
// the Landlock rights each ABI takes; the proof a helper runs once confined, which a readable state directory fails;
// and a helper outside its confinement refusing to run on the OSes whose code the test process can call in place. The
// Linux confinement itself runs in infer_engine_confine_linux_test.go, Windows' by hand.

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

// A confinement over three fresh directories, the state one holding the other two, as a daemon's <state> does.
func testInferEngineConfinement(t *testing.T) *inferEngineConfinement {
	t.Helper()
	state := t.TempDir()
	confinement := &inferEngineConfinement{
		EngineDirectory: filepath.Join(state, "engine"),
		ModelDirectory:  filepath.Join(state, "models"),
		DeniedDirectory: state,
	}
	for _, directory := range []string{confinement.EngineDirectory, confinement.ModelDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return confinement
}

// The environment's three entries read back as they were written; one missing, one twice, a relative or unclean path,
// or a denied directory inside one the helper reads is refused, so a helper not told what to confine itself to runs
// nothing.
func TestEngineConfineEnvironmentRoundTrip(t *testing.T) {
	confinement := testInferEngineConfinement(t)
	env := append([]string{"PATH=/usr/bin"}, inferEngineConfineEnvironment(confinement)...)
	read, err := parseInferEngineConfineEnvironment(env)
	if err != nil {
		t.Fatal(err)
	}
	if *read != *confinement {
		t.Errorf("read %+v, wrote %+v", read, confinement)
	}
	entries := inferEngineConfineEnvironment(confinement)
	refused := [][]string{
		entries[:2],
		append(slices.Clone(entries), entries[0]),
		{inferEngineEnvEngineDirectory + "=engine", entries[1], entries[2]},
		{inferEngineEnvEngineDirectory + "=" + confinement.EngineDirectory + "/../engine", entries[1], entries[2]},
		{entries[0], entries[1], inferEngineEnvDeniedDirectory + "=" + filepath.Join(confinement.ModelDirectory, "inside")},
		{entries[0], entries[1], inferEngineEnvDeniedDirectory + "=" + confinement.EngineDirectory},
		{entries[0], entries[1], inferEngineEnvDeniedDirectory + "="},
	}
	for i, env := range refused {
		if _, err := parseInferEngineConfineEnvironment(env); !errors.Is(err, errInferEngineConfinementInvalid) {
			t.Errorf("case %d was read: %v", i, err)
		}
	}
	// the daemon's spec carries the entries after its own, and its arguments alone
	spec := &inferEngineChildSpec{Path: "/opt/ur/ur-engine", Args: []string{"-v"}, Env: []string{"LANG=C"}, Confinement: confinement}
	if !slices.Equal(spec.argv(), []string{"/opt/ur/ur-engine", "-v"}) {
		t.Errorf("argv %v", spec.argv())
	}
	if environment := spec.environment(); environment[0] != "LANG=C" || !slices.Equal(environment[1:], entries) {
		t.Errorf("environment %v", environment)
	}
}

// A struct seccomp_data for bpf's VM, whose loads read big-endian words: each word written so the VM reads the value
// the kernel's native load would.
func testInferEngineSeccompData(nr uint32, arch uint32) []byte {
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:4], nr)
	binary.BigEndian.PutUint32(data[4:8], arch)
	return data
}

// The filter on each architecture: socket and socketpair refused EACCES, io_uring's calls ENOSYS, a call of the other
// architecture's ABI or x32's ending the process, and everything else, reads, mmap, execve, ioctl, allowed.
func TestEngineSeccompFilterRefusesSockets(t *testing.T) {
	allow := int(inferEngineSeccompRetAllow)
	kill := int(inferEngineSeccompRetKillProcess)
	eacces := int(inferEngineSeccompRetErrno | inferEngineSeccompErrnoEacces)
	enosys := int(inferEngineSeccompRetErrno | inferEngineSeccompErrnoEnosys)
	// read, mmap, execve, ioctl and openat on each ABI
	allowed := map[string][]uint32{"amd64": {0, 9, 59, 16, 257}, "arm64": {63, 222, 221, 29, 56}}
	for goarch, architecture := range inferEngineSeccompArchitectures {
		program, err := inferEngineSeccompProgram(goarch)
		if err != nil {
			t.Fatal(err)
		}
		vm, err := bpf.NewVM(program)
		if err != nil {
			t.Fatal(err)
		}
		other := inferEngineSeccompArchitectures["arm64"].auditArch
		if goarch == "arm64" {
			other = inferEngineSeccompArchitectures["amd64"].auditArch
		}
		number := func(name string) uint32 {
			for _, refusal := range architecture.refusals {
				if refusal.name == name {
					return refusal.number
				}
			}
			t.Fatalf("%s refuses no %s", goarch, name)
			return 0
		}
		cases := []struct {
			nr   uint32
			arch uint32
			want int
		}{
			{nr: number("socket"), arch: architecture.auditArch, want: eacces},
			{nr: number("socketpair"), arch: architecture.auditArch, want: eacces},
			{nr: number("io_uring_setup"), arch: architecture.auditArch, want: enosys},
			{nr: number("io_uring_enter"), arch: architecture.auditArch, want: enosys},
			{nr: number("io_uring_register"), arch: architecture.auditArch, want: enosys},
			{nr: number("socket"), arch: other, want: kill},
			{nr: allowed[goarch][0], arch: other, want: kill},
		}
		for _, nr := range allowed[goarch] {
			cases = append(cases, struct {
				nr   uint32
				arch uint32
				want int
			}{nr: nr, arch: architecture.auditArch, want: allow})
		}
		if architecture.x32 {
			cases = append(cases, struct {
				nr   uint32
				arch uint32
				want int
			}{nr: inferEngineSeccompX32SyscallBit | number("socket"), arch: architecture.auditArch, want: kill})
		}
		for i, c := range cases {
			got, err := vm.Run(testInferEngineSeccompData(c.nr, c.arch))
			if err != nil || got != c.want {
				t.Errorf("%s case %d: %#x %v, want %#x", goarch, i, got, err, c.want)
			}
		}
	}
	if _, err := inferEngineSeccompProgram("riscv64"); err == nil {
		t.Error("a filter was made for an architecture the helper is not built for")
	}
}

// Each ABI's ruleset: refused with none; every file system right the ABI knows handled, so nothing is writable,
// creatable, removable or executable but by a rule; TCP from ABI 4, ioctl on devices from 5, the scopes from 6, the
// attribute's size following; and a file's rule never granting a directory's right.
func TestEngineLandlockRightsByAbi(t *testing.T) {
	if _, err := inferLandlockRightsFor(0); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("no Landlock was taken: %v", err)
	}
	cases := []struct {
		abi        int
		handledFs  uint64
		handledNet uint64
		scoped     uint64
		device     uint64
		attrSize   int
	}{
		{abi: 1, handledFs: 0x1fff, device: 0x6, attrSize: 8},
		{abi: 2, handledFs: 0x3fff, device: 0x6, attrSize: 8},
		{abi: 3, handledFs: 0x7fff, device: 0x6, attrSize: 8},
		{abi: 4, handledFs: 0x7fff, handledNet: 0x3, device: 0x6, attrSize: 16},
		{abi: 5, handledFs: 0xffff, handledNet: 0x3, device: 0x8006, attrSize: 16},
		{abi: 6, handledFs: 0xffff, handledNet: 0x3, scoped: 0x3, device: 0x8006, attrSize: 24},
		{abi: 9, handledFs: 0xffff, handledNet: 0x3, scoped: 0x3, device: 0x8006, attrSize: 24},
	}
	for _, c := range cases {
		rights, err := inferLandlockRightsFor(c.abi)
		if err != nil {
			t.Fatal(err)
		}
		if rights.handledFs != c.handledFs || rights.handledNet != c.handledNet || rights.scoped != c.scoped ||
			rights.device != c.device || rights.attrSize != c.attrSize {
			t.Errorf("ABI %d: %+v", c.abi, rights)
		}
		// read-only on directories and files, execute only where the exec needs it, no right to write or make anything
		writes := inferLandlockFsWriteFile | inferLandlockFsRemoveDir | inferLandlockFsRemoveFile | inferLandlockFsMakeChar |
			inferLandlockFsMakeDir | inferLandlockFsMakeReg | inferLandlockFsMakeSock | inferLandlockFsMakeFifo |
			inferLandlockFsMakeBlock | inferLandlockFsMakeSym | inferLandlockFsRefer | inferLandlockFsTruncate
		if rights.readDirectory&writes != 0 || rights.readFile&writes != 0 || rights.execFile&writes != 0 ||
			rights.readDirectory&inferLandlockFsExecute != 0 {
			t.Errorf("ABI %d grants more than reading: %+v", c.abi, rights)
		}
		if inferLandlockFileAccess(rights.readDirectory) != inferLandlockFsReadFile {
			t.Errorf("ABI %d: a file's rule from a directory's rights is %#x", c.abi, inferLandlockFileAccess(rights.readDirectory))
		}
	}
}

// The proof: a directory this process can list is no proof, and neither is one that is not there; only a refusal by
// permission is.
func TestEngineConfineProofRefusesAReadableStateDirectory(t *testing.T) {
	confinement := testInferEngineConfinement(t)
	if err := inferEngineConfineProbe(confinement.DeniedDirectory); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("a readable state directory passed: %v", err)
	}
	if err := inferEngineConfineProbe(filepath.Join(confinement.DeniedDirectory, "absent")); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("a state directory not there passed: %v", err)
	}
}

// A helper that is not confined refuses to run: on macOS a helper the sandbox does not hold, on Windows one outside an
// AppContainer, elsewhere any. Linux's two stages run in their own process (infer_engine_confine_linux_test.go).
func TestEngineHelperRefusesToRunUnconfined(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux's confinement execs the process: infer_engine_confine_linux_test.go runs it in a child")
	}
	confinement := testInferEngineConfinement(t)
	if err := inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ()); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("an unconfined helper would run: %v", err)
	}
	if err := inferEngineConfine(&inferEngineConfinement{}, DefaultInferSettings(), os.Args, os.Environ()); err == nil {
		t.Error("a helper told nothing would run")
	}
}

// Where a daemon looks for its helper: inside ur.app on macOS, where ur runs from its bundle, else beside ur.
func TestEngineDefaultHelperPath(t *testing.T) {
	directory := t.TempDir()
	beside := filepath.Join(directory, "bin", "ur")
	if got := inferEngineDefaultHelperPath(beside); got != filepath.Join(directory, "bin", inferEngineHelperName()) {
		t.Errorf("beside ur: %s", got)
	}
	if runtime.GOOS != "darwin" {
		return
	}
	bundled := filepath.Join(directory, "ur.app", "Contents", "MacOS", "ur")
	want := filepath.Join(directory, "ur.app", "Contents", "Helpers", "ur-engine.app", "Contents", "MacOS", "ur-engine")
	if got := inferEngineDefaultHelperPath(bundled); got != want {
		t.Errorf("inside ur.app: %s, want %s", got, want)
	}
	// /usr/local/bin/ur is a link into the bundle, which the path follows
	if err := os.MkdirAll(filepath.Dir(bundled), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundled, []byte("ur"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "ur")
	if err := os.Symlink(bundled, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(bundled)
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join(filepath.Dir(resolved), "..", "Helpers", "ur-engine.app", "Contents", "MacOS", "ur-engine")
	if got := inferEngineDefaultHelperPath(link); got != want {
		t.Errorf("through a link: %s, want %s", got, want)
	}
}

// A daemon whose helper is not at its place says so, and lists no local model, rather than failing each call.
func TestEngineProcessCapabilitiesNeedTheHelper(t *testing.T) {
	confinement := testInferEngineConfinement(t)
	process, err := NewInferEngineProcess(&InferEngineProcessArgs{
		HelperPath:      filepath.Join(confinement.DeniedDirectory, "absent", inferEngineHelperName()),
		EngineDirectory: confinement.EngineDirectory,
		ModelDirectory:  confinement.ModelDirectory,
		StateDirectory:  confinement.DeniedDirectory,
		Manifest:        &InferManifest{Version: inferManifestVersion},
		Capabilities:    testInferDevice(runtime.GOOS+"/"+runtime.GOARCH, InferDeviceClassDesktop, 64, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	process.confineAvailable = func() error { return nil }
	if _, err := process.Capabilities(t.Context()); err == nil || !strings.Contains(err.Error(), "ur-engine") {
		t.Errorf("a helper not there: %v", err)
	}
	// a state directory inside one the helper reads is refused at construction
	if _, err := NewInferEngineProcess(&InferEngineProcessArgs{
		EngineDirectory: confinement.EngineDirectory,
		ModelDirectory:  confinement.ModelDirectory,
		StateDirectory:  filepath.Join(confinement.ModelDirectory, "state"),
	}); err == nil {
		t.Error("a state directory inside the models' was taken")
	}
}
