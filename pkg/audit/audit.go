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

// Package audit provides an HMAC-chained, tamper-evident audit trail.
//
// The package has zero Kubernetes dependencies on purpose so that any Go
// program — operators, CLIs, log-shipper sidecars — can import it and
// emit chain-linked entries without pulling in client-go. Standard
// library plus github.com/google/uuid only.
//
// The chain is a linked list of AuditEntry objects: each entry's
// PreviousHash is the Hash of the previous entry, and Hash is computed
// over the entry's content (HMAC-SHA256 with a key held only by the
// Backend). Tampering with any entry, or removing a non-terminal entry,
// breaks VerifyChain at the affected index.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// AuditEntry is one record in the chain.
//
// JSON struct tags use lowerCamelCase to match the project's existing
// Kubernetes-style field naming on disk; this lets a human read an
// audit file with `jq` and get fields that look similar to a `kubectl
// get -o json` of the source resource.
type AuditEntry struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ScanName     string    `json:"scanName"`
	Namespace    string    `json:"namespace"`
	Event        string    `json:"event"`
	Principal    string    `json:"principal"`
	Detail       string    `json:"detail"`
	PreviousHash string    `json:"previousHash"`
	Hash         string    `json:"hash"`
}

// Backend is the persistence interface. The interface is part of the
// design — three backends (local filesystem, GCS, S3 Object Lock) are
// already on the roadmap (CLAUDE.md "Shelved"), so the abstraction is
// upfront-justified rather than premature.
type Backend interface {
	// Append persists a new entry. The implementation assigns ID and
	// Timestamp if the caller left them zero-valued, looks up the
	// current chain tail to set PreviousHash, computes Hash with its
	// configured key, and writes atomically. The returned AuditEntry is
	// the finalised, persisted record; callers use its Hash to populate
	// downstream pointers (e.g. GovernanceScan.Status.AuditRef).
	//
	// Concurrent Appends against the same (scanName, namespace) are not
	// safe for the local backend; M0 assumes a single controller.
	Append(ctx context.Context, entry AuditEntry) (AuditEntry, error)

	// List returns every entry for (scanName, namespace) sorted in
	// chronological order. An absent chain returns (nil, nil) — not an
	// error — so callers can distinguish "no entries yet" from "I/O
	// failure".
	List(ctx context.Context, scanName, namespace string) ([]AuditEntry, error)

	// Verify lists the chain and runs VerifyChain over it.
	Verify(ctx context.Context, scanName, namespace string) (*VerifyResult, error)
}

// VerifyResult is the report from a chain verification.
type VerifyResult struct {
	// Intact is true iff every entry's stored hash matches its
	// recomputed hash AND every entry's PreviousHash matches the
	// preceding entry's Hash (or "" for the first entry).
	Intact bool

	// EntryCount is the number of entries observed.
	EntryCount int

	// FirstBreak is the zero-based index of the first broken entry, or
	// -1 if the chain is intact.
	FirstBreak int

	// BreakReason is a human-readable description of the first break,
	// or "" if the chain is intact.
	BreakReason string
}

// ComputeHash returns the HMAC-SHA256 hash for an entry, hex-encoded.
//
// SECURITY: this hashes the plain concatenation of fields without any
// delimiter. That is a known HMAC anti-pattern — two distinct field
// combinations whose concatenations happen to be equal (e.g.,
// ScanName="ab"+Namespace="c" vs ScanName="a"+Namespace="bc") will
// collide. The risk is bounded by the HMAC key (an attacker without the
// key still cannot forge entries), but a future hardening pass should
// add explicit length prefixes or a JSON canonical form. The MVP keeps
// the simple concat to match the design doc; if you change the input
// encoding you MUST also bump a chain-format version and re-hash
// existing chains, otherwise old chains fail to verify.
func ComputeHash(entry AuditEntry, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(entry.ID))
	// Normalise to UTC + RFC3339Nano so a chain written by a controller
	// in one timezone verifies against a CLI in another.
	h.Write([]byte(entry.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(entry.ScanName))
	h.Write([]byte(entry.Namespace))
	h.Write([]byte(entry.Event))
	h.Write([]byte(entry.Principal))
	h.Write([]byte(entry.Detail))
	h.Write([]byte(entry.PreviousHash))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain walks an ordered slice of entries and reports the first
// integrity violation. Two failure modes are checked per entry:
//
//  1. The entry's stored Hash matches ComputeHash(entry, key).
//  2. The entry's PreviousHash matches the preceding entry's Hash, or
//     "" for the first entry.
//
// Hash mismatch is checked first because for a tampered entry the
// reported FirstBreak is the tampered entry itself; for a deleted entry
// the hash check passes but the link check catches the gap at the
// entry after the deletion.
func VerifyChain(entries []AuditEntry, key []byte) *VerifyResult {
	result := &VerifyResult{
		EntryCount: len(entries),
		FirstBreak: -1,
	}
	if len(entries) == 0 {
		result.Intact = true
		return result
	}

	for i := range entries {
		entry := entries[i]
		recomputed := ComputeHash(entry, key)
		if recomputed != entry.Hash {
			result.FirstBreak = i
			result.BreakReason = fmt.Sprintf(
				"entry %d hash mismatch (id=%s): recomputed %s, stored %s",
				i, entry.ID, recomputed, entry.Hash)
			return result
		}

		expectedPrev := ""
		if i > 0 {
			expectedPrev = entries[i-1].Hash
		}
		if entry.PreviousHash != expectedPrev {
			result.FirstBreak = i
			result.BreakReason = fmt.Sprintf(
				"entry %d previousHash mismatch (id=%s): expected %s, got %s",
				i, entry.ID, expectedPrev, entry.PreviousHash)
			return result
		}
	}

	result.Intact = true
	return result
}
