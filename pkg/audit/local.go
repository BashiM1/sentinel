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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LocalBackend writes audit entries to a directory tree on the local
// filesystem.
//
// Layout: {basePath}/{namespace}/{scanName}/{ts}-{id}.json
//
// The timestamp prefix in the filename means lexicographic sort equals
// chronological sort (timestamps are normalised to UTC RFC3339Nano
// inside the filename for that reason). The UUID suffix breaks ties on
// the rare same-nanosecond collision.
type LocalBackend struct {
	basePath string
	key      []byte
}

// Compile-time check that LocalBackend implements Backend.
var _ Backend = (*LocalBackend)(nil)

// NewLocalBackend constructs a LocalBackend and ensures basePath exists.
// An empty basePath or empty hmacKey is a programming error and is
// rejected at construction time so the operator does not silently get
// an unverifiable audit chain.
func NewLocalBackend(basePath string, hmacKey []byte) (*LocalBackend, error) {
	if basePath == "" {
		return nil, errors.New("audit: NewLocalBackend: basePath is empty")
	}
	if len(hmacKey) == 0 {
		return nil, errors.New("audit: NewLocalBackend: hmacKey is empty")
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return nil, fmt.Errorf("audit: create base path %q: %w", basePath, err)
	}
	return &LocalBackend{basePath: basePath, key: hmacKey}, nil
}

// Append persists a new entry. The caller supplies a partial AuditEntry
// (ID/Timestamp may be zero, PreviousHash/Hash are ignored); this
// method fills the blanks, looks up the chain tail, writes the
// finalised entry atomically via a temp-file rename, and returns the
// finalised entry so callers can use the assigned Hash downstream.
func (b *LocalBackend) Append(ctx context.Context, entry AuditEntry) (AuditEntry, error) {
	if entry.ScanName == "" {
		return AuditEntry{}, errors.New("audit: Append: ScanName is empty")
	}
	if entry.Namespace == "" {
		return AuditEntry{}, errors.New("audit: Append: Namespace is empty")
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	existing, err := b.List(ctx, entry.ScanName, entry.Namespace)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("audit: list existing entries: %w", err)
	}
	entry.PreviousHash = ""
	if n := len(existing); n > 0 {
		entry.PreviousHash = existing[n-1].Hash
	}
	entry.Hash = ComputeHash(entry, b.key)

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return AuditEntry{}, fmt.Errorf("audit: marshal entry: %w", err)
	}

	dir := filepath.Join(b.basePath, entry.Namespace, entry.ScanName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return AuditEntry{}, fmt.Errorf("audit: mkdir %q: %w", dir, err)
	}

	filename := fmt.Sprintf("%s-%s.json", entry.Timestamp.UTC().Format(time.RFC3339Nano), entry.ID)
	if err := writeAtomic(filepath.Join(dir, filename), data); err != nil {
		return AuditEntry{}, err
	}
	return entry, nil
}

// List returns the chain for (scanName, namespace) sorted chronologically.
// A missing directory is "no entries", not an error.
func (b *LocalBackend) List(ctx context.Context, scanName, namespace string) ([]AuditEntry, error) {
	if scanName == "" || namespace == "" {
		return nil, errors.New("audit: List requires non-empty scanName and namespace")
	}
	dir := filepath.Join(b.basePath, namespace, scanName)
	files, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read dir %q: %w", dir, err)
	}

	// Pre-sort by filename so the read order is deterministic before any
	// timestamp comparison. Filenames embed the timestamp, so lex sort
	// equals chronological sort except for ties (broken by UUID).
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })

	entries := make([]AuditEntry, 0, len(files))
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("audit: read %q: %w", path, err)
		}
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("audit: unmarshal %q: %w", path, err)
		}
		entries = append(entries, entry)
	}

	// Defence in depth: sort by Timestamp regardless of filename order, so
	// even if a future writer chose a different filename scheme the chain
	// still walks in the intended order. Stable sort preserves the
	// filename-order tiebreak when timestamps collide.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Timestamp.Before(entries[j].Timestamp) })
	return entries, nil
}

// Verify lists the chain and runs VerifyChain over it. Returning a
// non-nil error means we could not even read the chain; an intact=false
// result with nil error means the chain was readable but broken.
func (b *LocalBackend) Verify(ctx context.Context, scanName, namespace string) (*VerifyResult, error) {
	entries, err := b.List(ctx, scanName, namespace)
	if err != nil {
		return nil, err
	}
	return VerifyChain(entries, b.key), nil
}

// writeAtomic writes data to a temp file in the same directory as path
// and renames it into place. Same-directory rename is atomic on POSIX
// filesystems; the temp file is cleaned up on any failure so a crashed
// Append does not litter the audit tree.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-audit-*")
	if err != nil {
		return fmt.Errorf("audit: create temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("audit: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("audit: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("audit: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("audit: rename %q to %q: %w", tmpName, path, err)
	}
	success = true
	return nil
}
