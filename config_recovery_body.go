//go:build !ios_extension

// A network device opens the verified binding under its held config generations and seals its own local root.
package sidecar

func (self *Sidecar) gkmRecoveryKeyAt(view GkmAuthView, memberId Id) (*GkmRecoveryKey, error) {
	state, ok := view.(*ConfigState)
	if !ok {
		return nil, ErrGkmKeyMissing
	}
	repoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, err
	}
	return state.recoveryKey(memberId, func(generation uint64) *EvsRepoKey { return self.GkmHeldKey(repoId, generation) })
}

// A cold follower can start on a folded head instead of observing the original RecoveryBind entry.
func (self *Sidecar) sealOwnRecoveryBinding(key *GkmRecoveryKey) error {
	authority := self.authority()
	if authority == nil {
		return ErrSidecarActNoAuthority
	}
	if err := self.keepRecoveryPublicKey(key.BindingKeySha256, key.XwingPublicKey); err != nil {
		return err
	}
	return self.syncRecoverySeal(authority, authority.Pin())
}
