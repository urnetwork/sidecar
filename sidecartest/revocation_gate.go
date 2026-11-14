//go:build !sidecar_testhooks

// Without sidecar_testhooks evs's gate never switches (QD-338): a gate-off revocation check reads open.

package sidecartest

func setEvsGate(net *Net, on bool) error {
	if on {
		return nil
	}
	return ErrEvsGateFixed
}
