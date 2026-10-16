package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// racyWindow: a file modified within this time before the cache was written may have been changed again within
// the same timestamp tick, so its cached hash is not trusted (the same rule git applies to its index).
const racyWindow = 2 * time.Second

// CacheEntry remembers what a file looked like when it was hashed.
type CacheEntry struct {
	Size  int64  `json:"size"`
	ModNs int64  `json:"mod_ns"`
	Hash  string `json:"hash"`
}

// Cache lets a later scan skip hashing files whose size and modification time did not change.
//
// This is a speed-up, not a security measure: size and modification time can be set by whoever can change the
// file. Use it to make checks of big folders fast on a machine you trust; run without it when tampering is the
// question.
type Cache struct {
	Algorithm string                `json:"algorithm"`
	Created   time.Time             `json:"created"`
	Entries   map[string]CacheEntry `json:"entries"`
}

// LoadCache reads a cache file. A missing, damaged or other-algorithm cache gives an empty one: a cache can
// only ever make a scan faster, never make it fail.
func LoadCache(path, algorithm string) *Cache {
	empty := &Cache{Algorithm: algorithm, Entries: map[string]CacheEntry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var c Cache
	if json.Unmarshal(data, &c) != nil || c.Algorithm != algorithm || c.Entries == nil {
		return empty
	}
	return &c
}

// lookup returns the cached hash when the file still has the size and modification time it had before.
func (c *Cache) lookup(rel string, size, modNs int64) (string, bool) {
	if c == nil {
		return "", false
	}
	e, ok := c.Entries[rel]
	if !ok || e.Size != size || e.ModNs != modNs {
		return "", false
	}
	if modNs >= c.Created.Add(-racyWindow).UnixNano() {
		return "", false
	}
	return e.Hash, true
}

// Save writes a cache with the given entries, atomically.
func Save(path, algorithm string, entries map[string]CacheEntry, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(Cache{Algorithm: algorithm, Created: now, Entries: entries})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".assay-cache-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
