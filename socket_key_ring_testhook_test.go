//go:build sidecar_testhooks

// Under the tag, a K_sock a writer creates or rotates to reaches the privacy harness's hook as "K_sock"
// at its creation, before any use, so §22.7's scan looks for the very bytes the config repo carries.

package sidecar

import (
	"bytes"
	"slices"
	"testing"
)

func TestSocketKeyFileKeysReachTheHook(t *testing.T) {
	hookedKeys := [][]byte{}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			if kind == "K_sock" {
				hookedKeys = append(hookedKeys, bytes.Clone(secret))
			}
		},
	})
	created := NewSocketKeyFile()
	rotated, err := RotateSocketKeyFile(created, 1767323045000)
	if err != nil {
		t.Fatal(err)
	}
	SetTestHooks(nil)
	for _, socketKey := range [][]byte{created.GetCurrentKey(), rotated.GetCurrentKey()} {
		if !slices.ContainsFunc(hookedKeys, func(hooked []byte) bool { return bytes.Equal(hooked, socketKey) }) {
			t.Error("a created K_sock did not reach the hook")
		}
	}
}
