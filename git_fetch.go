//go:build !ios_extension && !sidecar_http

// Fetching from EVS (DESIGN-COMPUTE §13.4's remote, clone and fetch rows, §13.6's read taint, IC-12, I-9; D-GIT-2;
// GIT-M13-02): the bundled git reads a git-mode ref through the network's evs client and replays its pushes into the
// worktree's object store with export's replayer, never a git process and never a network remote.
//
//	connect  a repository fetches through the evs client of its remote's network, which the caller resolves from <net>
//	         (GitRepository.Connect), with the run's taint and the judge of a push's provenance
//	resume   each ref's replay state is kept in .git/ur/refs/<ref id> after a fetch (EvsGitReplayState), so the next
//	         fetch replays only from the version it passed, its walk from that version's chain: no version is replayed
//	         twice. A head below what the worktree passed (a reseed) is refused, never replayed into the same objects
//	defer    a sparse worktree defers every blob, its locator kept in the promisor table (git_promisor.go), so trees and
//	         commits are built from the changes' modes and oids and only the paths checked out are fetched; a full one
//	         fetches every blob, so stock git opens it
//	taint    each push the fetch takes objects from, sources and overlay bases included, is judged by its sealed
//	         provenance before any of its objects is written: a tainted run, an import, a refused agent signature, no
//	         provenance this reader can read, another member, or a tagged sidecar (from M14 the member's own enclave
//	         excepted, which no admission carries before the enclaves feature) taints the run, fsynced, through the
//	         caller's GitFetchTaint, before the first object, the worktree's first byte and the answer. A fetch that meets
//	         such a push with no taint to call is refused, failing closed. A member's own untainted push taints nothing
//	refs     each fetched branch's tip lands in refs/remotes/origin/<branch>, by compare-and-swap; the local branches are
//	         the porcelain's (clone, merge, pull)
//
// The remote is ur:// alone (Q-GIT-2): any other answers "not supported by ur git" before anything is read or written.
// Which branches a bare `fetch` follows: the worktree's upstreams and remote-tracking refs; discovering a branch the
// worktree has never named waits on reading refs' sealed names from a listing, which is GIT-M13-05's.
//
// A GitRepository is one command's: not safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The directory each ref's kept replay state lives in.
const gitReplayStatesDirectory = ".git/ur/refs"

var (
	// A command that needs the remote's evs and has none connected.
	ErrGitNotConnected = errors.New("git: no evs client for the remote's network; connect the repository first")
	// A fetch that met an untrusted push with no run to taint: refused, failing closed.
	ErrGitFetchUntrusted = errors.New("git: a push from an untrusted source, and no run to taint before reading it")
	// A ref evs now holds below what the worktree fetched: a reseed, which a fresh clone takes.
	ErrGitFetchBehind = errors.New("git: the remote ref is below what this worktree fetched; clone it again")
)

// Taints the run, fsynced, before anything fetched is written or answered (§13.6): in a Harness through its run's
// taint (HarnessRun.Taint), from `ur git` by Sidecar.TaintAncestorRuns. An error fails the command before it writes.
type GitFetchTaint func(ctx context.Context) error

// Whether the run may take a push's objects without taint: its signer and its sealed provenance, nil for none the
// reader can read (§13.6, IC-12).
type GitFetchTrust func(ctx context.Context, signerSidecarId Id, provenance *EvsPushProvenance) bool

// The evs side of a repository's fetches.
type GitEvsArgs struct {
	// The evs client of the remote's network, which the caller resolves from <net>.
	Evs *EvsClient
	// The run's taint; nil refuses a fetch that meets an untrusted push.
	Taint GitFetchTaint
	// The judge of a push's provenance; nil judges by the client's verified config (GitFetchTrustOf).
	Trust GitFetchTrust
}

// The judge IC-12 gives a reader on client's verified config: a push is trusted only where its provenance reads,
// shows no tainted run, no import and no refused agent signature, and its signer is this sidecar or an untagged device
// of this sidecar's member. Another member's, a tagged sidecar's (the member's own enclave among them until M14's
// admission names one), and an unknown signer's taint; a reader that is itself tagged trusts only its own.
func GitFetchTrustOf(client *EvsClient) GitFetchTrust {
	return func(ctx context.Context, signerSidecarId Id, provenance *EvsPushProvenance) bool {
		if provenance == nil || provenance.Tainted || provenance.Imported || provenance.Refused {
			return false
		}
		if client.args.Identity == nil {
			return false
		}
		identity := client.args.Identity()
		if identity == nil {
			return false
		}
		if signerSidecarId == identity.SidecarId {
			return true
		}
		view, err := client.verifier.config()
		if err != nil {
			return false
		}
		ownMemberId, ownUntagged := configRowMember(view.SidecarRow(identity.SidecarId))
		signerMemberId, signerUntagged := configRowMember(view.SidecarRow(signerSidecarId))
		return ownUntagged && signerUntagged && ownMemberId == signerMemberId
	}
}

// What a fetch did.
type GitFetchResult struct {
	Refs []*GitFetchedRef
	// The run was tainted: a push the fetch took objects from was untrusted.
	Tainted bool
}

// One branch a fetch read.
type GitFetchedRef struct {
	// The branch's short name, its evs ref's name.
	Branch string
	// Its remote-tracking ref's tip before and after, nil for none.
	OldTip *EvsGitOid
	Tip    *EvsGitOid
	// The versions the fetch replayed: past FromVersion through ToVersion, none where they are equal.
	FromVersion uint64
	ToVersion   uint64
	// The versions a check refused, which stop the ref until a DELETE, as export reports them.
	Refused []*EvsExportRefusal
	// The ref does not stand on evs.
	Missing bool
}

// Judges each push a fetch takes objects from and taints the run once, before the first untrusted one's objects.
type gitFetchGate struct {
	client  *EvsClient
	repoId  Id
	taint   GitFetchTaint
	trust   GitFetchTrust
	tainted bool
}

// A gate over args for the repo.
func newGitFetchGate(args *GitEvsArgs, repoId Id) *gitFetchGate {
	trust := args.Trust
	if trust == nil {
		trust = GitFetchTrustOf(args.Evs)
	}
	return &gitFetchGate{client: args.Evs, repoId: repoId, taint: args.Taint, trust: trust}
}

// Judges one push, its sealed metadata opened, tainting the run before anything of it is written where it is untrusted.
func (self *gitFetchGate) see(ctx context.Context, refId Id, statement *EvsStatement, metadata *protocol.EvsSealedMetadata) error {
	if self.tainted {
		return nil
	}
	provenance, err := self.client.versionProvenance(self.repoId, refId, statement, metadata)
	if err != nil {
		return err
	}
	signerId, err := IdFromBytes(statement.Push.GetSignerSidecarId())
	if err == nil && self.trust(ctx, signerId, provenance) {
		return nil
	}
	if self.taint == nil {
		return ErrGitFetchUntrusted
	}
	if err := self.taint(ctx); err != nil {
		return fmt.Errorf("git: the run's taint did not persist, so nothing was fetched: %w", err)
	}
	self.tainted = true
	testHookBarrier("git.fetch_taint", "")
	return nil
}

// Connects the repository to its remote's evs for this command's fetches and lazy blobs, the caller having resolved
// the remote's <net> to args.Evs; refuses a remote that is not ur:// (Q-GIT-2).
func (self *GitRepository) Connect(args *GitEvsArgs) error {
	if _, err := ParseGitRemoteUrl(self.state.Remote); err != nil {
		return err
	}
	if args == nil || args.Evs == nil {
		return ErrGitNotConnected
	}
	// a new connection judges and taints by its own args from here on
	self.evs, self.fetchGate = args, nil
	return nil
}

// The repository's evs client and its remote's repo.
func (self *GitRepository) connected() (*GitEvsArgs, *EvsRepo, error) {
	remote, err := ParseGitRemoteUrl(self.state.Remote)
	if err != nil {
		return nil, nil, err
	}
	if self.evs == nil {
		return nil, nil, ErrGitNotConnected
	}
	return self.evs, self.evs.Evs.Repo(remote.RepoId), nil
}

// The branches a bare fetch follows: each upstream's, then each remote-tracking ref's, by name.
func (self *GitRepository) followedBranches() ([]string, error) {
	branches := []string{}
	for _, upstream := range self.state.Branches {
		if name, found := strings.CutPrefix(upstream.Merge, GitBranchPrefix); found && !slices.Contains(branches, name) {
			branches = append(branches, name)
		}
	}
	tracked, err := self.refs.List(GitRemotePrefix)
	if err != nil {
		return nil, err
	}
	for _, ref := range tracked {
		if name := strings.TrimPrefix(ref.Name, GitRemotePrefix); name != "HEAD" && !slices.Contains(branches, name) {
			branches = append(branches, name)
		}
	}
	return branches, nil
}

// Reads every branch named (nil: those the worktree follows) from evs into the store, from where the last fetch of
// each stopped: see the file header.
func (self *GitRepository) Fetch(ctx context.Context, branches []string) (*GitFetchResult, error) {
	evsArgs, repo, err := self.connected()
	if err != nil {
		return nil, err
	}
	if branches == nil {
		if branches, err = self.followedBranches(); err != nil {
			return nil, err
		}
	}
	for _, branch := range branches {
		if err := GitCheckRefName(GitBranchPrefix + branch); err != nil {
			return nil, err
		}
	}
	states, err := self.readReplayStates()
	if err != nil {
		return nil, err
	}
	gate := self.gate(evsArgs, repo.repoId)
	options := &evsGitReplayOptions{
		resume: states,
		provenance: func(ctx context.Context, refId Id, statement *EvsVerifiedStatement, metadata *protocol.EvsSealedMetadata) error {
			return gate.see(ctx, refId, statement.Statement, metadata)
		},
	}
	if self.state.Lazy {
		options.deferBlob = self.promisorTable().record
	}
	replayer := newEvsGitReplayerWith(repo, self.objects, options)
	defer replayer.release()
	client := evsArgs.Evs
	result := &GitFetchResult{}
	for _, branch := range branches {
		refName := []byte(branch)
		refId, err := repo.RefIdOf(ctx, refName)
		if err != nil {
			return nil, err
		}
		done := client.pins.beginRead(repo.repoId, refId)
		head, err := repo.pinnedHead(ctx, refId)
		if err != nil {
			done()
			return nil, err
		}
		replayer.reading(done)
		fetched := &GitFetchedRef{Branch: branch}
		if fetched.OldTip, err = self.refs.Read(GitRemotePrefix + branch); err != nil {
			return nil, err
		}
		if head.Version == 0 {
			fetched.Missing = true
			result.Refs = append(result.Refs, fetched)
			continue
		}
		if protocol.EvsRefMode(head.Head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
			return nil, fmt.Errorf("%w: %s is a file-mode ref, which ur git does not fetch", ErrEvsGitRef, branch)
		}
		if kept := states[refId]; kept != nil && head.Version < kept.Passed {
			return nil, ErrGitFetchBehind
		}
		ref := replayer.ref(head)
		if ref.name == nil {
			ref.name = refName
		}
		fetched.FromVersion = ref.passed
		if err := replayer.replay(ctx, ref, head.Version); err != nil {
			return nil, err
		}
		if err := replayer.finish(ctx, ref); err != nil {
			return nil, err
		}
		fetched.ToVersion, fetched.Tip, fetched.Refused = ref.passed, ref.tip, ref.refused
		result.Refs = append(result.Refs, fetched)
	}
	if err := replayer.finishSources(ctx); err != nil {
		return nil, err
	}
	for _, ref := range replayer.refs {
		if err := self.writeReplayState(ref.kept()); err != nil {
			return nil, err
		}
	}
	result.Tainted = gate.tainted
	for _, fetched := range result.Refs {
		if fetched.Missing {
			continue
		}
		name := GitRemotePrefix + fetched.Branch
		switch {
		case fetched.Tip == nil && fetched.OldTip != nil:
			err = self.refs.Delete(name, fetched.OldTip)
		case fetched.Tip != nil && !gitOidEqual(fetched.Tip, fetched.OldTip):
			err = self.refs.Update(name, *fetched.Tip, fetched.OldTip)
		}
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// A replay state as .git/ur/refs keeps it: ids, oids and chains in hex.
type gitReplayStateFile struct {
	RefId     string      `json:"ref_id"`
	Name      string      `json:"name"`
	Passed    uint64      `json:"passed"`
	Chain     string      `json:"chain"`
	Tip       string      `json:"tip,omitempty"`
	Exists    bool        `json:"exists,omitempty"`
	LastTip   string      `json:"last_tip,omitempty"`
	Kind      int32       `json:"kind"`
	StoppedAt uint64      `json:"stopped_at,omitempty"`
	Stopped   [][2]uint64 `json:"stopped,omitempty"`
	// each tip move, `<version> <hex>`, the hex empty for none
	Tips []string `json:"tips,omitempty"`
}

// An optional oid's hex, "" for none.
func gitOidHex(oid *EvsGitOid) string {
	if oid == nil {
		return ""
	}
	return oid.String()
}

// An optional oid from its hex, nil for "".
func gitOidFromHex(text string) (*EvsGitOid, error) {
	if text == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(EvsGitOid{}) {
		return nil, ErrGitRefCorrupt
	}
	oid := EvsGitOid(decoded)
	return &oid, nil
}

// Keeps a ref's replay state.
func (self *GitRepository) writeReplayState(state *EvsGitReplayState) error {
	file := &gitReplayStateFile{
		RefId: state.RefId.String(), Name: hex.EncodeToString(state.Name), Passed: state.Passed,
		Chain: hex.EncodeToString(state.Chain[:]), Tip: gitOidHex(state.Tip), Exists: state.Exists,
		LastTip: gitOidHex(state.LastTip), Kind: int32(state.Kind), StoppedAt: state.StoppedAt, Stopped: state.Stopped,
	}
	for _, moved := range state.Tips {
		file.Tips = append(file.Tips, fmt.Sprintf("%d %s", moved.Version, gitOidHex(moved.Tip)))
	}
	content, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := self.fileSystem.MkdirAll(gitReplayStatesDirectory, 0o755); err != nil {
		return err
	}
	return gitWriteFileAtomic(self.fileSystem, gitUrDirectory, gitReplayStatesDirectory+"/"+hex.EncodeToString(state.RefId[:]), content, 0o644, false)
}

// Every kept replay state, by ref id.
func (self *GitRepository) readReplayStates() (map[Id]*EvsGitReplayState, error) {
	states := map[Id]*EvsGitReplayState{}
	entries, err := self.fileSystem.ReadDir(gitReplayStatesDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		return states, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		content, err := gitReadFile(self.fileSystem, gitReplayStatesDirectory+"/"+entry.Name(), self.settings.ReplayStateByteCount)
		if err != nil {
			return nil, err
		}
		state, err := gitParseReplayState(content)
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(state.RefId[:]) != entry.Name() {
			return nil, fmt.Errorf("%w: a replay state under another ref's name", ErrGitRefCorrupt)
		}
		states[state.RefId] = state
	}
	return states, nil
}

// A kept replay state from its file's bytes.
func gitParseReplayState(content []byte) (*EvsGitReplayState, error) {
	refused := fmt.Errorf("%w: a replay state that does not read", ErrGitRefCorrupt)
	file := &gitReplayStateFile{}
	if err := json.Unmarshal(content, file); err != nil {
		return nil, refused
	}
	refId, err := ParseId(file.RefId)
	if err != nil {
		return nil, refused
	}
	name, err := hex.DecodeString(file.Name)
	if err != nil {
		return nil, refused
	}
	chain, err := hex.DecodeString(file.Chain)
	if err != nil || len(chain) != len([32]byte{}) {
		return nil, refused
	}
	state := &EvsGitReplayState{
		RefId: refId, Name: name, Passed: file.Passed, Chain: [32]byte(chain), Exists: file.Exists,
		Kind: protocol.EvsRefKind(file.Kind), StoppedAt: file.StoppedAt, Stopped: file.Stopped,
	}
	if state.Tip, err = gitOidFromHex(file.Tip); err != nil {
		return nil, refused
	}
	if state.LastTip, err = gitOidFromHex(file.LastTip); err != nil {
		return nil, refused
	}
	for _, line := range file.Tips {
		versionText, tipText, _ := strings.Cut(line, " ")
		version := uint64(0)
		if _, err := fmt.Sscan(versionText, &version); err != nil {
			return nil, refused
		}
		tip, err := gitOidFromHex(tipText)
		if err != nil {
			return nil, refused
		}
		state.Tips = append(state.Tips, EvsGitReplayTip{Version: version, Tip: tip})
	}
	return state, nil
}
