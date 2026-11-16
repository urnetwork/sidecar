//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// §22.9's git-lfs matrix (EVS2-M10-29): every row runs when its binaries answer the versions it names; a row whose
// variable is unset, whose binary answers another release, or whose latest git-lfs is older than the floor is skipped,
// the report saying why; and the host's own plan, logged, which on a host with only PATH's git-lfs runs the latest row
// at most.

package sidecartest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A lookup over named binaries answering fixed version lines.
func gitLfsTestLookup(env map[string]string, versions map[string]string) *GitLfsLookup {
	return &GitLfsLookup{
		Getenv: func(name string) string { return env[name] },
		LookPath: func(name string) (string, error) {
			if path, ok := env["PATH:"+name]; ok {
				return path, nil
			}
			return "", errors.New("not found")
		},
		Version: func(ctx context.Context, path string) (string, error) {
			if line, ok := versions[path]; ok {
				return line, nil
			}
			return "", errors.New("no such binary")
		},
	}
}

func TestGitLfsMatrixRunsEveryRowItsBinariesAnswer(t *testing.T) {
	lookup := gitLfsTestLookup(map[string]string{
		"UR_TEST_GIT_LFS_3_0_2": "/x/lfs-3.0.2", "UR_TEST_GIT_2_34": "/x/git-2.34",
		"UR_TEST_GIT_LFS_3_4_1": "/x/lfs-3.4.1", "UR_TEST_GIT_2_43": "/x/git-2.43",
		"PATH:git-lfs": "/x/lfs-latest", "PATH:git": "/x/git-latest",
	}, map[string]string{
		"/x/lfs-3.0.2": "git-lfs/3.0.2 (GitHub; linux amd64; go 1.18.1)", "/x/git-2.34": "git version 2.34.1",
		"/x/lfs-3.4.1": "git-lfs/3.4.1 (GitHub; linux amd64; go 1.22.2)", "/x/git-2.43": "git version 2.43.0",
		"/x/lfs-latest": "git-lfs/3.8.0 (GitHub; darwin arm64; go 1.27.0)", "/x/git-latest": "git version 2.56.0",
	})
	runs := PlanGitLfsMatrix(context.Background(), lookup)
	if len(GitLfsMatrixRunnable(runs)) != 3 {
		t.Fatalf("a host holding every row: %s", strings.Join(GitLfsMatrixReport(runs), "; "))
	}
	report := strings.Join(GitLfsMatrixReport(runs), "\n")
	for _, want := range []string{"ran ubuntu-22.04: git-lfs 3.0.2, git 2.34.1", "ran ubuntu-24.04: git-lfs 3.4.1, git 2.43.0", "ran latest: git-lfs 3.8.0, git 2.56.0"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report lacks %q:\n%s", want, report)
		}
	}
}

func TestGitLfsMatrixSkipsWhatTheHostLacksSayingWhy(t *testing.T) {
	lookup := gitLfsTestLookup(map[string]string{
		"UR_TEST_GIT_LFS_3_4_1": "/x/lfs-3.4.2", "UR_TEST_GIT_2_43": "/x/git-2.43",
		"PATH:git-lfs": "/x/lfs-old", "PATH:git": "/x/git-latest",
	}, map[string]string{
		"/x/lfs-3.4.2": "git-lfs/3.4.2", "/x/git-2.43": "git version 2.43.0",
		"/x/lfs-old": "git-lfs/3.1.0", "/x/git-latest": "git version 2.56.0",
	})
	runs := PlanGitLfsMatrix(context.Background(), lookup)
	if len(GitLfsMatrixRunnable(runs)) != 0 {
		t.Fatalf("a host holding no row as named ran some: %s", strings.Join(GitLfsMatrixReport(runs), "; "))
	}
	report := strings.Join(GitLfsMatrixReport(runs), "\n")
	for _, want := range []string{
		"skipped ubuntu-22.04: UR_TEST_GIT_LFS_3_0_2 is not set",
		"skipped ubuntu-24.04: git-lfs at /x/lfs-3.4.2 is 3.4.2, not 3.4.1",
		"skipped latest: git-lfs on PATH is 3.1.0, older than the latest row's 3.5.0",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report lacks %q:\n%s", want, report)
		}
	}
}

// The host's own plan, logged, as a conformance run records it.
func TestGitLfsMatrixOnThisHost(t *testing.T) {
	runs := PlanGitLfsMatrix(t.Context(), HostGitLfsLookup())
	if len(runs) != len(GitLfsMatrix()) {
		t.Fatalf("%d runs for %d rows", len(runs), len(GitLfsMatrix()))
	}
	for _, line := range GitLfsMatrixReport(runs) {
		t.Log(line)
	}
}
