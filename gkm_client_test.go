// Until the real client is wired, a sidecar's GkmClient refuses every call, so nothing reads as keyed (KEYS-M2-04's
// fail-closed trap).

package sidecar

import (
	"errors"
	"testing"
)

func TestGkmRefusingClientRefusesEveryCall(t *testing.T) {
	client := newGkmRefusingClient()
	ctx := t.Context()
	repoId := gkmTestId("repo")
	refusals := map[string]func() error{
		"CurrentRepoKey": func() error {
			key, err := client.CurrentRepoKey(ctx, repoId)
			if key != nil {
				t.Error("CurrentRepoKey answered a key")
			}
			return err
		},
		"RepoKey": func() error {
			key, err := client.RepoKey(ctx, repoId, 1)
			if key != nil {
				t.Error("RepoKey answered a key")
			}
			return err
		},
		"EnsureWritable": func() error {
			key, err := client.EnsureWritable(ctx, repoId)
			if key != nil {
				t.Error("EnsureWritable answered a key")
			}
			return err
		},
		"DropKey": func() error {
			dropKey, err := client.DropKey(ctx, repoId)
			if dropKey != nil {
				t.Error("DropKey answered a key")
			}
			return err
		},
		"CreateGroup": func() error {
			key, err := client.CreateGroup(ctx, &GkmCreateGroupArgs{RepoId: repoId})
			if key != nil {
				t.Error("CreateGroup answered a key")
			}
			return err
		},
		"RotateRepo": func() error {
			key, err := client.RotateRepo(ctx, repoId)
			if key != nil {
				t.Error("RotateRepo answered a key")
			}
			return err
		},
		"ForgetRepo": func() error {
			return client.ForgetRepo(ctx, repoId)
		},
	}
	for name, call := range refusals {
		if err := call(); !errors.Is(err, ErrGkmUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A state changes nothing: every call still refuses after one.
	client.AuthAdvanced(nil)
	if _, err := client.EnsureWritable(ctx, repoId); !errors.Is(err, ErrGkmUnavailable) {
		t.Errorf("after a state: %v", err)
	}
}
