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

package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// newBackend constructs a LocalBackend rooted at t.TempDir().
func newBackend(t *testing.T) *LocalBackend {
	t.Helper()
	b, err := NewLocalBackend(t.TempDir(), []byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	return b
}

// appendSeries writes n entries with sequential 1-second-apart timestamps so
// filenames sort unambiguously and the tests are deterministic.
func appendSeries(t *testing.T, b *LocalBackend, scan, ns string, n int) {
	t.Helper()
	ctx := context.Background()
	start := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		_, err := b.Append(ctx, AuditEntry{
			Timestamp: start.Add(time.Duration(i) * time.Second),
			ScanName:  scan,
			Namespace: ns,
			Event:     "Test",
			Principal: "tester",
			Detail:    "entry " + itoa(i),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func TestLocalBackend_AppendOneListReturnsIt(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)

	persisted, err := b.Append(ctx, AuditEntry{
		Timestamp: time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC),
		ScanName:  "scan-a",
		Namespace: "default",
		Event:     "ScanStarted",
		Principal: "alice",
		Detail:    "hello",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if persisted.Hash == "" {
		t.Error("Append must return the persisted entry with Hash populated")
	}
	if persisted.ID == "" {
		t.Error("Append must return the persisted entry with ID populated")
	}

	got, err := b.List(ctx, "scan-a", "default")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Event != "ScanStarted" {
		t.Errorf("Event: want ScanStarted, got %q", got[0].Event)
	}
	if got[0].PreviousHash != "" {
		t.Errorf("first entry should have empty PreviousHash; got %q", got[0].PreviousHash)
	}
	if got[0].Hash == "" {
		t.Error("Hash should be populated after Append")
	}
	if got[0].ID == "" {
		t.Error("ID should be auto-assigned when caller leaves it empty")
	}
}

func TestLocalBackend_TenEntriesVerifyIntact(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	appendSeries(t, b, "scan", "ns", 10)

	res, err := b.Verify(ctx, "scan", "ns")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Intact {
		t.Fatalf("expected intact chain; got %+v", res)
	}
	if res.EntryCount != 10 {
		t.Errorf("EntryCount: want 10, got %d", res.EntryCount)
	}
	if res.FirstBreak != -1 {
		t.Errorf("FirstBreak: want -1, got %d", res.FirstBreak)
	}
}

func TestLocalBackend_TamperedEntryDetected(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	appendSeries(t, b, "scan", "ns", 5)

	// Pick the third file (index 2) by sorted filename and overwrite
	// its Detail without recomputing the Hash.
	scanDir := filepath.Join(b.basePath, "ns", "scan")
	files := jsonFilesSorted(t, scanDir)
	if len(files) != 5 {
		t.Fatalf("expected 5 files, got %d", len(files))
	}
	target := filepath.Join(scanDir, files[2])

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read tampered file: %v", err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry.Detail = "TAMPERED" // Hash field left untouched
	tampered, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(target, tampered, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	res, err := b.Verify(ctx, "scan", "ns")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Intact {
		t.Fatalf("expected break, got intact: %+v", res)
	}
	if res.FirstBreak != 2 {
		t.Errorf("FirstBreak: want 2, got %d (reason: %s)", res.FirstBreak, res.BreakReason)
	}
	if !strings.Contains(res.BreakReason, "hash mismatch") {
		t.Errorf("BreakReason should mention 'hash mismatch'; got %q", res.BreakReason)
	}
}

func TestLocalBackend_DeletedFileDetected(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	appendSeries(t, b, "scan", "ns", 5)

	// Delete the third file. After removal, entry 3 collapses to index 2
	// and its PreviousHash points at the deleted entry's Hash, breaking
	// the link.
	scanDir := filepath.Join(b.basePath, "ns", "scan")
	files := jsonFilesSorted(t, scanDir)
	if err := os.Remove(filepath.Join(scanDir, files[2])); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	res, err := b.Verify(ctx, "scan", "ns")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Intact {
		t.Fatalf("expected break after deletion; got intact: %+v", res)
	}
	if res.EntryCount != 4 {
		t.Errorf("EntryCount after deletion: want 4, got %d", res.EntryCount)
	}
	if res.FirstBreak != 2 {
		t.Errorf("FirstBreak: want 2 (slot where deleted entry used to sit), got %d", res.FirstBreak)
	}
	if !strings.Contains(res.BreakReason, "previousHash") {
		t.Errorf("BreakReason should mention 'previousHash'; got %q", res.BreakReason)
	}
}

func TestLocalBackend_SeparateScansIndependent(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)

	appendSeries(t, b, "scan-A", "ns", 3)
	appendSeries(t, b, "scan-B", "ns", 5)

	a, err := b.Verify(ctx, "scan-A", "ns")
	if err != nil {
		t.Fatalf("Verify A: %v", err)
	}
	if !a.Intact || a.EntryCount != 3 {
		t.Errorf("scan-A: want intact with 3 entries; got %+v", a)
	}
	bRes, err := b.Verify(ctx, "scan-B", "ns")
	if err != nil {
		t.Fatalf("Verify B: %v", err)
	}
	if !bRes.Intact || bRes.EntryCount != 5 {
		t.Errorf("scan-B: want intact with 5 entries; got %+v", bRes)
	}

	// Tampering with scan-A must not affect scan-B's verification result.
	aDir := filepath.Join(b.basePath, "ns", "scan-A")
	aFiles := jsonFilesSorted(t, aDir)
	if err := os.Remove(filepath.Join(aDir, aFiles[1])); err != nil {
		t.Fatalf("remove: %v", err)
	}

	a2, _ := b.Verify(ctx, "scan-A", "ns")
	if a2.Intact {
		t.Error("scan-A should be broken after deletion")
	}
	bRes2, _ := b.Verify(ctx, "scan-B", "ns")
	if !bRes2.Intact {
		t.Errorf("scan-B should remain intact; got %+v", bRes2)
	}
}

func TestLocalBackend_EmptyChainVerifiesIntact(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)

	// No Appends — the directory does not exist yet. Verify must
	// return Intact=true with zero entries, not an error.
	res, err := b.Verify(ctx, "never-appended", "ns")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Intact || res.EntryCount != 0 || res.FirstBreak != -1 {
		t.Errorf("empty chain should be intact with 0 entries; got %+v", res)
	}
}

func TestLocalBackend_SingleEntryVerifiesIntact(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	appendSeries(t, b, "scan", "ns", 1)

	res, err := b.Verify(ctx, "scan", "ns")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Intact || res.EntryCount != 1 {
		t.Errorf("single-entry chain should be intact; got %+v", res)
	}
}

func TestLocalBackend_AppendAutoFillsIDAndTimestamp(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	before := time.Now()

	if _, err := b.Append(ctx, AuditEntry{
		ScanName:  "scan",
		Namespace: "ns",
		Event:     "X",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, _ := b.List(ctx, "scan", "ns")
	if len(got) != 1 {
		t.Fatalf("expected 1 entry")
	}
	if got[0].ID == "" {
		t.Error("ID was empty; Append must auto-assign")
	}
	if got[0].Timestamp.Before(before) {
		t.Error("Timestamp should be auto-set to >= the moment Append was called")
	}
}

func TestLocalBackend_AppendRejectsMissingFields(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)

	if _, err := b.Append(ctx, AuditEntry{Namespace: "ns"}); err == nil {
		t.Error("expected error for missing ScanName")
	}
	if _, err := b.Append(ctx, AuditEntry{ScanName: "scan"}); err == nil {
		t.Error("expected error for missing Namespace")
	}
}

func TestNewLocalBackend_RejectsInvalidConfig(t *testing.T) {
	if _, err := NewLocalBackend("", []byte("k")); err == nil {
		t.Error("expected error for empty basePath")
	}
	if _, err := NewLocalBackend(t.TempDir(), nil); err == nil {
		t.Error("expected error for nil hmacKey")
	}
	if _, err := NewLocalBackend(t.TempDir(), []byte{}); err == nil {
		t.Error("expected error for empty hmacKey")
	}
}

// --- helpers ---

func jsonFilesSorted(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %q: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}
