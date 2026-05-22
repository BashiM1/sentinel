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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// fixedEntry is the canonical input used by the determinism and
// known-value tests. Keep it stable — a change here means the entire
// chain format has bumped and existing on-disk chains will fail to
// verify against the new code.
func fixedEntry() AuditEntry {
	return AuditEntry{
		ID:           "id-1",
		Timestamp:    time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC),
		ScanName:     "scan-1",
		Namespace:    "default",
		Event:        "ScanStarted",
		Principal:    "alice",
		Detail:       "test",
		PreviousHash: "",
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	key := []byte("k")
	h1 := ComputeHash(fixedEntry(), key)
	h2 := ComputeHash(fixedEntry(), key)
	if h1 != h2 {
		t.Fatalf("ComputeHash not deterministic: %s vs %s", h1, h2)
	}
}

// TestComputeHash_KnownValue locks in the exact algorithm (HMAC-SHA256
// over plain field concatenation, timestamp normalised to UTC
// RFC3339Nano, fields in the order documented in ComputeHash). If this
// test breaks, the chain format has changed — bump a version and
// migrate existing chains or accept that older chains will fail to
// verify against the new code.
func TestComputeHash_KnownValue(t *testing.T) {
	key := []byte("secret-key")

	// Compute the expected hash manually using the exact same primitive
	// (HMAC-SHA256) over the exact same concatenated input the
	// production function should be feeding the HMAC.
	h := hmac.New(sha256.New, key)
	h.Write([]byte("id-1"))
	h.Write([]byte("2026-05-22T10:00:00Z")) // RFC3339Nano with no sub-second → no trailing ".999..."
	h.Write([]byte("scan-1"))
	h.Write([]byte("default"))
	h.Write([]byte("ScanStarted"))
	h.Write([]byte("alice"))
	h.Write([]byte("test"))
	h.Write([]byte("")) // PreviousHash
	want := hex.EncodeToString(h.Sum(nil))

	got := ComputeHash(fixedEntry(), key)
	if got != want {
		t.Fatalf("ComputeHash known-value mismatch\n  want: %s\n  got:  %s", want, got)
	}
}

func TestComputeHash_DifferentInputsProduceDifferentHashes(t *testing.T) {
	key := []byte("k")
	base := fixedEntry()
	baseHash := ComputeHash(base, key)

	mutators := map[string]func(*AuditEntry){
		"ID":           func(e *AuditEntry) { e.ID = "id-2" },
		"Timestamp":    func(e *AuditEntry) { e.Timestamp = e.Timestamp.Add(time.Second) },
		"ScanName":     func(e *AuditEntry) { e.ScanName = "scan-2" },
		"Namespace":    func(e *AuditEntry) { e.Namespace = "other" },
		"Event":        func(e *AuditEntry) { e.Event = "ScanCompleted" },
		"Principal":    func(e *AuditEntry) { e.Principal = "bob" },
		"Detail":       func(e *AuditEntry) { e.Detail = "different" },
		"PreviousHash": func(e *AuditEntry) { e.PreviousHash = "deadbeef" },
	}
	for field, mutate := range mutators {
		t.Run(field, func(t *testing.T) {
			modified := base
			mutate(&modified)
			h := ComputeHash(modified, key)
			if h == baseHash {
				t.Fatalf("changing %s did not change the hash; concatenation-without-delimiter weakness or a missing field write", field)
			}
		})
	}
}

func TestComputeHash_DifferentKeysProduceDifferentHashes(t *testing.T) {
	entry := fixedEntry()
	h1 := ComputeHash(entry, []byte("key-A"))
	h2 := ComputeHash(entry, []byte("key-B"))
	if h1 == h2 {
		t.Fatal("two different keys produced the same hash — HMAC is not actually keyed")
	}
}

func TestComputeHash_EmptyPreviousHash(t *testing.T) {
	// The first entry in a chain has PreviousHash == "". Make sure this
	// hashes without crashing and is distinct from a hash with a
	// non-empty PreviousHash.
	key := []byte("k")
	first := fixedEntry()
	first.PreviousHash = ""

	withPrev := first
	withPrev.PreviousHash = "deadbeef"

	if ComputeHash(first, key) == ComputeHash(withPrev, key) {
		t.Fatal("empty and non-empty PreviousHash produced equal hashes")
	}
}

func TestComputeHash_TimestampNormalisedToUTC(t *testing.T) {
	// A timestamp expressed in a different timezone should produce the
	// same hash as its UTC equivalent. Without UTC normalisation, a
	// controller in BST and a CLI in UTC would compute different hashes
	// for what is logically the same instant.
	key := []byte("k")
	utc := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	bst := utc.In(time.FixedZone("BST", 3600))

	a := fixedEntry()
	a.Timestamp = utc
	b := fixedEntry()
	b.Timestamp = bst

	if ComputeHash(a, key) != ComputeHash(b, key) {
		t.Fatalf("same instant in different timezones produced different hashes")
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	r := VerifyChain(nil, []byte("k"))
	if !r.Intact || r.EntryCount != 0 || r.FirstBreak != -1 {
		t.Fatalf("empty chain should verify intact with 0 entries; got %+v", r)
	}
}

func TestVerifyChain_HappyPath(t *testing.T) {
	key := []byte("k")
	// Build a 3-entry chain by hand so the test does not depend on the
	// LocalBackend's Append.
	entries := make([]AuditEntry, 3)
	for i := range entries {
		e := AuditEntry{
			ID:        fmtID(i),
			Timestamp: time.Date(2026, 5, 22, 10, 0, i, 0, time.UTC),
			ScanName:  "scan",
			Namespace: "ns",
			Event:     "X",
			Principal: "alice",
			Detail:    fmtDetail(i),
		}
		if i > 0 {
			e.PreviousHash = entries[i-1].Hash
		}
		e.Hash = ComputeHash(e, key)
		entries[i] = e
	}

	r := VerifyChain(entries, key)
	if !r.Intact || r.FirstBreak != -1 {
		t.Fatalf("expected intact chain; got %+v", r)
	}
	if r.EntryCount != 3 {
		t.Fatalf("EntryCount: want 3, got %d", r.EntryCount)
	}
}

func TestVerifyChain_TamperedEntryCaughtAtIndex(t *testing.T) {
	key := []byte("k")
	entries := buildChain(key, 5)

	// Tamper entry 2's Detail without recomputing its Hash. The stored
	// Hash will no longer match the recomputed Hash; FirstBreak should
	// point at index 2.
	entries[2].Detail = "TAMPERED"

	r := VerifyChain(entries, key)
	if r.Intact {
		t.Fatal("expected break")
	}
	if r.FirstBreak != 2 {
		t.Fatalf("FirstBreak: want 2, got %d", r.FirstBreak)
	}
	if r.BreakReason == "" {
		t.Fatal("BreakReason should be populated on a break")
	}
}

func TestVerifyChain_DeletedEntryCaughtAtNextIndex(t *testing.T) {
	key := []byte("k")
	entries := buildChain(key, 5)

	// Delete entry 2. After removal, entry 3 lands at index 2 with a
	// PreviousHash pointing at the deleted entry's Hash, which no longer
	// matches the entry at i-1 (which is the old entry 1). VerifyChain
	// should report a break at index 2 with a previousHash mismatch.
	deleted := append([]AuditEntry{}, entries[:2]...)
	deleted = append(deleted, entries[3:]...)

	r := VerifyChain(deleted, key)
	if r.Intact {
		t.Fatal("expected break after deletion")
	}
	if r.FirstBreak != 2 {
		t.Fatalf("FirstBreak: want 2, got %d (reason: %s)", r.FirstBreak, r.BreakReason)
	}
}

func TestVerifyChain_BrokenLinkAtFirstEntry(t *testing.T) {
	key := []byte("k")
	entries := buildChain(key, 3)

	// First entry should have PreviousHash="". Overwrite it without
	// recomputing the Hash; both the link check and the hash check
	// would catch this. Verify the break is at index 0.
	entries[0].PreviousHash = "bogus"

	r := VerifyChain(entries, key)
	if r.Intact {
		t.Fatal("expected break")
	}
	if r.FirstBreak != 0 {
		t.Fatalf("FirstBreak: want 0, got %d", r.FirstBreak)
	}
}

// --- helpers ---

func buildChain(key []byte, n int) []AuditEntry {
	out := make([]AuditEntry, n)
	for i := 0; i < n; i++ {
		e := AuditEntry{
			ID:        fmtID(i),
			Timestamp: time.Date(2026, 5, 22, 10, 0, i, 0, time.UTC),
			ScanName:  "scan",
			Namespace: "ns",
			Event:     "X",
			Principal: "alice",
			Detail:    fmtDetail(i),
		}
		if i > 0 {
			e.PreviousHash = out[i-1].Hash
		}
		e.Hash = ComputeHash(e, key)
		out[i] = e
	}
	return out
}

func fmtID(i int) string {
	return "id-" + itoa(i)
}
func fmtDetail(i int) string {
	return "entry-" + itoa(i)
}

// itoa: stdlib-only; avoid pulling strconv just for a test helper.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
