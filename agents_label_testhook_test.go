//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// Under the tag, K_label's derivation reaches the privacy harness's hook by value and under its name, beside the config
// repo's K_ref it derives from (QD-1434).

package sidecar

import (
	"testing"
)

func TestAgentRepoLabelHookSeesItsDerivation(t *testing.T) {
	recorder := mlsRecordHooks(t)
	_, networkId, configRepoId, configKey := testAgentRepoLabelWorld(t, 2)
	labelKey, err := NewAgentRepoLabelKey(networkId, configRepoId, configKey)
	if err != nil {
		t.Fatal(err)
	}
	refKey, err := configKey.DeriveKey(EvsKeyPurposeRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_ref", refKey)
	recorder.require(t, "K_agent_label", labelKey.key)
}
