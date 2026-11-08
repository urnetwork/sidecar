//go:build !windows

// The key store files' checks on Unix: 0600 files and a 0700 directory, the user's own.

package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// Refuses a file looser than 0600 or another user's.
func checkOsKeyStoreFileMode(info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errOsKeyStoreLooseMode
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return errors.New("a key store file belongs to another user")
	}
	return nil
}

// Refuses a directory open to others or another user's.
func checkOsKeyStoreDirectoryMode(info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errOsKeyStoreLooseMode
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return errors.New("the key store's directory belongs to another user")
	}
	return nil
}

// Syncs the directory, so a rename in it is durable.
func syncOsKeyStoreDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
