// meshctl is the operator CLI for Local Compute Mesh.
//
// Subcommands (init, pair, join, status, models, drain, revoke) land in
// weekend-1 step 2 onward; this is the entry point so `make build` produces
// both binaries from the start.
package main

import (
	"fmt"
	"os"
)

// version is set by the linker (see Makefile LDFLAGS).
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("meshctl", version)
	default:
		fmt.Fprintf(os.Stderr, "meshctl: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: meshctl <command>

commands:
  version   print version`)
}
