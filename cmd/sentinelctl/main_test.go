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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BashiM1/sentinel/pkg/audit"
)

const testKey = "test-key"

// seedChain writes n entries into a temp audit dir and returns the dir.
func seedChain(t *testing.T, scan, ns string, n int) string {
	t.Helper()
	dir := t.TempDir()
	b, err := audit.NewLocalBackend(dir, []byte(testKey))
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	ctx := context.Background()
	start := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		if _, err := b.Append(ctx, audit.AuditEntry{
			Timestamp: start.Add(time.Duration(i) * time.Second),
			ScanName:  scan,
			Namespace: ns,
			Event:     "Test",
			Principal: "tester",
			Detail:    "seed",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	return dir
}

func TestSentinelctl_VerifyIntactChain(t *testing.T) {
	dir := seedChain(t, "scan-a", "ns", 7)

	var out, errOut bytes.Buffer
	code := run([]string{
		"verify",
		"--path", dir,
		"--scan", "scan-a",
		"--namespace", "ns",
		"--key", testKey,
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("expected exit 0 for intact chain, got %d; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Chain integrity: OK") {
		t.Errorf("expected 'Chain integrity: OK' in stdout; got %q", out.String())
	}
	if !strings.Contains(out.String(), "7 entries") {
		t.Errorf("expected entry count in stdout; got %q", out.String())
	}
}

func TestSentinelctl_VerifyBrokenChain(t *testing.T) {
	dir := seedChain(t, "scan-b", "ns", 5)

	// Tamper with the middle file: change Detail without rehashing.
	scanDir := filepath.Join(dir, "ns", "scan-b")
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	// File order is filename order; the middle file is index 2.
	target := filepath.Join(scanDir, entries[2].Name())
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entry audit.AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	entry.Detail = "TAMPERED"
	tampered, _ := json.MarshalIndent(entry, "", "  ")
	if err := os.WriteFile(target, tampered, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var out, errOut bytes.Buffer
	code := run([]string{
		"verify",
		"--path", dir,
		"--scan", "scan-b",
		"--namespace", "ns",
		"--key", testKey,
	}, &out, &errOut)

	if code != 1 {
		t.Fatalf("expected exit 1 for broken chain, got %d; stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "BROKEN at entry 2") {
		t.Errorf("expected 'BROKEN at entry 2' in stdout; got %q", out.String())
	}
}

func TestSentinelctl_VerifyEmptyChainIsIntact(t *testing.T) {
	dir := t.TempDir()

	var out, errOut bytes.Buffer
	code := run([]string{
		"verify",
		"--path", dir,
		"--scan", "no-such-scan",
		"--namespace", "ns",
		"--key", testKey,
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("expected exit 0 for empty chain, got %d; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "0 entries") {
		t.Errorf("expected '0 entries' in stdout; got %q", out.String())
	}
}

func TestSentinelctl_MissingFlagsExitsUsage(t *testing.T) {
	cases := [][]string{
		{"verify", "--scan", "x", "--namespace", "y", "--key", "k"},   // missing --path
		{"verify", "--path", "/x", "--namespace", "y", "--key", "k"},  // missing --scan
		{"verify", "--path", "/x", "--scan", "y", "--key", "k"},       // missing --namespace
		{"verify", "--path", "/x", "--scan", "y", "--namespace", "n"}, // missing --key
	}
	for i, args := range cases {
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if code != 2 {
			t.Errorf("case %d: expected exit 2 (usage), got %d; stderr=%s", i, code, errOut.String())
		}
	}
}

func TestSentinelctl_UnknownCommandExitsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"nonsense"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("expected 'unknown command' in stderr; got %q", errOut.String())
	}
}

func TestSentinelctl_NoArgsExitsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

func TestSentinelctl_HelpExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 for help, got %d", code)
	}
	if !strings.Contains(out.String(), "verify") {
		t.Errorf("help output should mention the verify command; got %q", out.String())
	}
}
