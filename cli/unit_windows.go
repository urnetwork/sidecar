// The Windows host's unit environment: a Task Scheduler logon task needs nothing but the OS (§5.8).

package main

// This user's environment for a logon task.
func hostUnitEnv() (*unitEnv, error) {
	return &unitEnv{goos: "windows"}, nil
}
