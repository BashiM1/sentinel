/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// sentinelctl is a small CLI for offline interaction with Sentinel
// state held outside the cluster. The one shipped subcommand is
// `verify`, which reads a local audit chain and reports integrity.
//
// Intentionally uses only the standard library `flag` package; no
// cobra/viper/pflag dependency. The CLI is for operators and CI,
// not a general-purpose tool, so flag parsing complexity is not
// worth a new dependency.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/BashiM1/sentinel/pkg/audit"
)

const usageText = `Usage: sentinelctl <command> [flags]

Commands:
  verify   Verify the integrity of a local audit chain.

Run "sentinelctl <command> --help" for command-specific flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. Returns the process exit code so
// tests can assert on it without trapping os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "sentinelctl: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

// runVerify parses verify-specific flags, opens the local audit
// backend, and runs Verify. Exit codes:
//
//	0  — chain intact
//	1  — chain broken
//	2  — usage error or I/O failure
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "audit base path (e.g. /tmp/sentinel-audit)")
	scan := fs.String("scan", "", "GovernanceScan name")
	namespace := fs.String("namespace", "", "GovernanceScan namespace")
	key := fs.String("key", "", "HMAC key used by the controller (see SENTINEL_AUDIT_KEY)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sentinelctl verify --path <dir> --scan <name> --namespace <ns> --key <key>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || *scan == "" || *namespace == "" || *key == "" {
		fs.Usage()
		return 2
	}

	backend, err := audit.NewLocalBackend(*path, []byte(*key))
	if err != nil {
		fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
		return 2
	}

	result, err := backend.Verify(context.Background(), *scan, *namespace)
	if err != nil {
		fmt.Fprintf(stderr, "sentinelctl: verify: %v\n", err)
		return 2
	}
	if result.Intact {
		fmt.Fprintf(stdout, "Chain integrity: OK (%d entries, 0 breaks)\n", result.EntryCount)
		return 0
	}
	fmt.Fprintf(stdout, "Chain integrity: BROKEN at entry %d (%s)\n", result.FirstBreak, result.BreakReason)
	return 1
}
