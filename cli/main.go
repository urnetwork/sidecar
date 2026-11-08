// The ur binary, which also runs as git-remote-ur (§4.10). No command exists yet: --version works,
// and every other invocation fails, git-remote-ur's included.
package main

import (
	"fmt"
	"os"

	"github.com/urnetwork/sidecar"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("ur %s\n", sidecar.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "ur: no command is implemented yet")
	os.Exit(2)
}
