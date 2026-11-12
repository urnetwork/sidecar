//go:build !ios_extension

package sidecar

// EVS2-M10-14: a path's versioning on the client, FS-68's writer clauses as a table over a real config state: 65 MiB
// versionless and 63 MiB versioned with no record; a present record matching nothing leaving 65 MiB versioned; a repo's
// own rules replacing the network's; an edit moving no existing path; git-mode, creates-only, config and mailcfg always
// 0; a lock turning 1 into 0, never the index's 2; reserved writers beating the rules; a network outside the gate
// writing 0; and the gate read from core's answer, false with no source.

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestEvsVersioningForFollowsFs68sWriterRules(t *testing.T) {
	mib := uint64(1024 * 1024)
	net := newTestConfigNet(t)
	repoId := testConfigId("versioned general")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	noRecord := net.log.State()
	// the network's record: logs/ versionless, nothing else matched
	networkRules := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{PathGlob: "logs/**", Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}}}
	net.source.versioning[[sha256.Size]byte(testConfigHeadSha256(2))] = networkRules
	net.fold(net.owner, net.n, 2)
	withRecord := net.log.State()
	repoRules := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{PathGlob: "media/**", Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}}}

	versionless := &protocol.EvsEntryVersion{Version: 4, Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)}
	versioned := &protocol.EvsEntryVersion{Version: 4}
	index := &protocol.EvsEntryVersion{Version: 4, Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX)}
	base := func() *EvsVersioningArgs {
		return &EvsVersioningArgs{
			RepoId: repoId, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefName: []byte("main"),
			RefMode: protocol.EvsRefMode_EVS_REF_FILE, Format2Admitted: true,
			Rules: EvsConfigVersioningRules(noRecord, nil),
		}
	}
	for _, c := range []struct {
		name   string
		mutate func(args *EvsVersioningArgs)
		want   uint32
	}{
		{name: "65 MiB with no record: the platform rule", mutate: func(args *EvsVersioningArgs) { args.Path, args.Size = "big.iso", 65*mib }, want: 1},
		{name: "63 MiB with no record", mutate: func(args *EvsVersioningArgs) { args.Path, args.Size = "big.iso", 63*mib }, want: 0},
		{name: "64 MiB exactly is not above it", mutate: func(args *EvsVersioningArgs) { args.Path, args.Size = "big.iso", 64*mib }, want: 0},
		{name: "a present record matching nothing leaves 65 MiB versioned", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Rules = "big.iso", 65*mib, EvsConfigVersioningRules(withRecord, nil)
		}, want: 0},
		{name: "the network's record's rule", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Rules = "logs/a/b.log", 1, EvsConfigVersioningRules(withRecord, nil)
		}, want: 1},
		{name: "the repo's own rules replace the network's", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Rules = "logs/a/b.log", 1, EvsConfigVersioningRules(withRecord, repoRules)
		}, want: 0},
		{name: "the repo's own rule", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Rules = "media/a.mov", 1, EvsConfigVersioningRules(withRecord, repoRules)
		}, want: 1},
		{name: "an edit moves no existing versioned path", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Newest, args.Rules = "logs/a/b.log", 1, versioned, EvsConfigVersioningRules(withRecord, nil)
		}, want: 0},
		{name: "an edit moves no existing versionless path", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Newest = "small.txt", 1, versionless
		}, want: 1},
		{name: "an explicit off on a versioned path", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Newest, args.Options = "a.txt", versioned, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 1},
		{name: "an explicit on on a versionless path", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Newest, args.Options = "a.txt", versionless, &EvsWriteOptions{Versioning: EvsVersioningOn}
		}, want: 0},
		{name: "a git-mode ref", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.RefMode, args.Options = "big.iso", 65*mib, protocol.EvsRefMode_EVS_REF_GIT, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 0},
		{name: "a creates-only ref", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.CreatesOnly, args.Options = "big.iso", 65*mib, true, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 0},
		{name: "a config repo", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.RepoKind, args.Options = "big.iso", 65*mib, protocol.RepoKind_REPO_KIND_CONFIG, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 0},
		{name: "a mailcfg repo", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.RepoKind, args.Newest = "big.iso", 65*mib, protocol.RepoKind_REPO_KIND_MAILCFG, versionless
		}, want: 0},
		{name: "a lock turns 1 into 0", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Locked = "big.iso", 65*mib, true
		}, want: 0},
		{name: "a lock turns an explicit off into 0", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Locked, args.Options = "a.txt", true, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 0},
		{name: "a lock turns a versionless path's next version into 0", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Locked, args.Newest = "a.txt", true, versionless
		}, want: 0},
		{name: "a lock keeps the index's 2", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Locked, args.Options = ".ur-index/b/1/m", true, &EvsWriteOptions{Reserved: EvsReservedIndex}
		}, want: 2},
		{name: "an index file keeps its 2", mutate: func(args *EvsVersioningArgs) { args.Path, args.Newest = ".ur-index/b/1/m", index }, want: 2},
		{name: "the index writer beats the rules", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Options = ".ur-index/a/m", 65*mib, &EvsWriteOptions{Reserved: EvsReservedIndex}
		}, want: 2},
		{name: "git-lfs's store beats a rule matching nothing", mutate: func(args *EvsVersioningArgs) {
			args.RefName, args.Path, args.Size, args.Options, args.Rules = []byte("ur/lfs"), "ab/cd/x", 1, &EvsWriteOptions{Reserved: EvsReservedLfs}, EvsConfigVersioningRules(withRecord, nil)
		}, want: 1},
		{name: "git-lfs's store under a lock", mutate: func(args *EvsVersioningArgs) {
			args.RefName, args.Path, args.Locked, args.Options = []byte("ur/lfs"), "ab/cd/x", true, &EvsWriteOptions{Reserved: EvsReservedLfs}
		}, want: 0},
		{name: "the mail component's s/model", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Options = "s/model", &EvsWriteOptions{Reserved: EvsReservedMailModel}
		}, want: 1},
		{name: "the directory's d/ paths", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Options = "d/card", &EvsWriteOptions{Reserved: EvsReservedDirectory}
		}, want: 1},
		{name: "no rule under .ur-index/ without its writer", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size = ".ur-index/x", 65*mib
		}, want: 0},
		{name: "no rule on ur/lfs without its writer", mutate: func(args *EvsVersioningArgs) {
			args.RefName, args.Path, args.Size = []byte("ur/lfs"), "x", 65*mib
		}, want: 0},
		{name: "a network outside the gate writes 0", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Size, args.Format2Admitted, args.Options = "big.iso", 65*mib, false, &EvsWriteOptions{Versioning: EvsVersioningOff}
		}, want: 0},
		{name: "outside the gate a versionless path's next version is 0", mutate: func(args *EvsVersioningArgs) {
			args.Path, args.Format2Admitted, args.Newest = "a.txt", false, versionless
		}, want: 0},
		{name: "no rules given: versioned", mutate: func(args *EvsVersioningArgs) { args.Path, args.Size, args.Rules = "big.iso", 65*mib, nil }, want: 0},
	} {
		args := base()
		c.mutate(args)
		got, err := EvsVersioningFor(args)
		if err != nil || got != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, got, err, c.want)
		}
	}
}

// A reader that cannot open the network's rules, and a repo the rules do not cover, write versioned; a setting that
// is no setting, and an unknown reserved writer, are refused.
func TestEvsVersioningForRefusesNoSettingAndKeepsWhatItCannotRead(t *testing.T) {
	args := &EvsVersioningArgs{
		RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefMode: protocol.EvsRefMode_EVS_REF_FILE, Format2Admitted: true,
		Path: "big.iso", Size: 65 * 1024 * 1024,
	}
	for _, err := range []error{ErrConfigVersioningUnknown, ErrConfigVersioningNotCovered} {
		args.Rules = func(repoId Id, filePath string, size uint64) (uint32, error) { return 1, err }
		if got, err := EvsVersioningFor(args); err != nil || got != 0 {
			t.Errorf("rules answering %v: %d %v", err, got, err)
		}
	}
	failed := errors.New("a store that did not answer")
	args.Rules = func(repoId Id, filePath string, size uint64) (uint32, error) { return 0, failed }
	if _, err := EvsVersioningFor(args); !errors.Is(err, failed) {
		t.Errorf("rules failing: %v", err)
	}
	args.Rules = nil
	args.Options = &EvsWriteOptions{Versioning: "versionless"}
	if _, err := EvsVersioningFor(args); !errors.Is(err, ErrEvsVersioningSetting) {
		t.Errorf("a setting that is no setting: %v", err)
	}
	args.Options = &EvsWriteOptions{Reserved: EvsReservedWriter(99)}
	if _, err := EvsVersioningFor(args); !errors.Is(err, ErrEvsVersioningSetting) {
		t.Errorf("an unknown reserved writer: %v", err)
	}
}

// Format2Admitted reads core's gates through the composition's source: false with none, true only while the gates
// list format2.
func TestEvsFormat2AdmittedReadsCoresGates(t *testing.T) {
	client := &EvsClient{}
	if client.Format2Admitted() {
		t.Error("admitted with no source")
	}
	var core *SidecarSyncCore
	client.SetFormat2Source(func() bool { return EvsFormat2AdmittedBy(core) })
	if client.Format2Admitted() {
		t.Error("admitted with no core answer")
	}
	core = &SidecarSyncCore{Version: 1, Gates: []string{"evs", "gkm"}}
	if client.Format2Admitted() {
		t.Error("admitted while the gates leave format2 out")
	}
	core = &SidecarSyncCore{Version: 2, Gates: []string{"evs", EvsFormat2GateName, "gkm"}}
	if !client.Format2Admitted() {
		t.Error("not admitted while the gates list format2")
	}
	client.SetFormat2Source(nil)
	if client.Format2Admitted() {
		t.Error("admitted once the source was removed")
	}
}
