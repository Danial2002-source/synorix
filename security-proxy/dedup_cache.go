package main

import (
	"container/list"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type CacheEntry struct {
	Key         string
	Value       []byte
	Headers     http.Header
	StatusCode  int
	ContentType string
	Size        int64
	ExpiresAt   time.Time
	Hash        string
	ETag        string      // For cache coherency validation
	CreatedAt   time.Time   // Track entry age
	AccessCount int64       // Track access patterns
	RequestSig  string      // Request signature for validation
}

type CacheStats struct {
	Hits              int64 `json:"hits"`
	Misses            int64 `json:"misses"`
	Evictions         int64 `json:"evictions"`
	Entries           int64 `json:"entries"`
	Bytes             int64 `json:"bytes"`
	SavedBytes        int64 `json:"saved_bytes"`
	CachePoisonings   int64 `json:"cache_poisonings"`
	StaleHits         int64 `json:"stale_hits"`
	InvalidHits       int64 `json:"invalid_hits"`
	LargeEvictions    int64 `json:"large_evictions"`
}

type cacheItem struct {
	key   string
	entry *CacheEntry
}

type DedupCache struct {
	mu               sync.Mutex
	entries          map[string]*list.Element
	lru              *list.List
	maxEntries       int
	maxBytes         int64
	ttl              time.Duration
	stats            CacheStats
	maxEntrySize     int64    // Max single entry size (10MB default)
	poisonThreshold  float64  // Cache poisoning detection threshold
	lastPoisonCheck  time.Time
}

func NewDedupCache(maxEntries int, maxBytes int64, ttl time.Duration) *DedupCache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	return &DedupCache{
		entries:          make(map[string]*list.Element),
		lru:              list.New(),
		maxEntries:       maxEntries,
		maxBytes:         maxBytes,
		ttl:              ttl,
		stats:            CacheStats{},
		maxEntrySize:     10 * 1024 * 1024, // 10MB max entry
		poisonThreshold:  0.8,              // Alert if >80% hits are invalid
		lastPoisonCheck:  time.Now(),
	}
}

func (dc *DedupCache) Get(key string) (*CacheEntry, bool) {
	if key == "" {
		return nil, false
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if ele, ok := dc.entries[key]; ok {
		item := ele.Value.(*cacheItem)
		entry := item.entry

		// Check TTL expiration
		if time.Now().After(entry.ExpiresAt) {
			dc.removeElement(ele, false)
			dc.stats.Misses++
			return nil, false
		}

		// Update access count and timestamp
		entry.AccessCount++
		dc.lru.MoveToFront(ele)
		dc.stats.Hits++

		// Check for cache poisoning periodically
		if time.Now().Sub(dc.lastPoisonCheck) > 1*time.Minute {
			dc.detectCachePoisoning()
			dc.lastPoisonCheck = time.Now()
		}

		return entry, true
	}

	dc.stats.Misses++
	return nil, false
}

// ValidateCacheEntry checks if cached entry is still valid using ETag
func (dc *DedupCache) ValidateCacheEntry(entry *CacheEntry, currentETag string) bool {
	if entry == nil {
		return false
	}

	// If current request has ETag and it differs, cache is invalid
	if currentETag != "" && entry.ETag != "" && entry.ETag != currentETag {
		return false
	}

	// Check if entry is too old (age > 90% of TTL)
	agePercent := float64(time.Now().Sub(entry.CreatedAt)) / float64(dc.ttl)
	if agePercent > 0.9 {
		return false
	}

	return true
}

func (dc *DedupCache) Set(key string, entry *CacheEntry) bool {
	if key == "" || entry == nil {
		return false
	}

	// Reject entries larger than max allowed size
	if entry.Size > dc.maxEntrySize {
		dc.mu.Lock()
		dc.stats.LargeEvictions++
		dc.mu.Unlock()
		return false
	}

	// Reject entries larger than total cache
	if entry.Size > dc.maxBytes {
		return false
	}

	// Set creation timestamp and extract ETag from headers
	entry.CreatedAt = time.Now()
	entry.ExpiresAt = entry.CreatedAt.Add(dc.ttl)
	if entry.Headers != nil {
		entry.ETag = entry.Headers.Get("ETag")
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if ele, ok := dc.entries[key]; ok {
		item := ele.Value.(*cacheItem)
		dc.stats.Bytes -= item.entry.Size
		item.entry = entry
		dc.stats.Bytes += entry.Size
		dc.lru.MoveToFront(ele)
		return true
	}

	ele := dc.lru.PushFront(&cacheItem{key: key, entry: entry})
	dc.entries[key] = ele
	dc.stats.Entries++
	dc.stats.Bytes += entry.Size

	dc.evictIfNeeded()
	return true
}

func (dc *DedupCache) RecordSavedBytes(bytes int64) {
	if bytes <= 0 {
		return
	}
	dc.mu.Lock()
	dc.stats.SavedBytes += bytes
	dc.mu.Unlock()
}

// detectCachePoisoning checks for anomalous cache hit patterns
func (dc *DedupCache) detectCachePoisoning() {
	if dc.stats.Hits == 0 {
		return
	}

	invalidRatio := float64(dc.stats.InvalidHits) / float64(dc.stats.Hits)
	if invalidRatio > dc.poisonThreshold {
		logrus.Warnf("⚠️  Potential cache poisoning detected: %.1f%% invalid hits", invalidRatio*100)
		dc.stats.CachePoisonings++
		// Could trigger additional actions like clearing cache or alerting
	}
}

// ClearLargeEntries removes entries exceeding size threshold
func (dc *DedupCache) ClearLargeEntries(sizeThreshold int64) int64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	freed := int64(0)
	toDelete := []*list.Element{}

	for _, ele := range dc.entries {
		item := ele.Value.(*cacheItem)
		if item.entry.Size > sizeThreshold {
			toDelete = append(toDelete, ele)
		}
	}

	for _, ele := range toDelete {
		item := ele.Value.(*cacheItem)
		freed += item.entry.Size
		dc.removeElement(ele, true)
	}

	return freed
}

func (dc *DedupCache) Stats() CacheStats {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.stats
}

func (dc *DedupCache) MaxEntries() int {
	return dc.maxEntries
}

func (dc *DedupCache) MaxBytes() int64 {
	return dc.maxBytes
}

func (dc *DedupCache) TTL() time.Duration {
	return dc.ttl
}

func (dc *DedupCache) evictIfNeeded() {
	for dc.stats.Entries > int64(dc.maxEntries) || dc.stats.Bytes > dc.maxBytes {
		ele := dc.lru.Back()
		if ele == nil {
			return
		}

		// Prioritize eviction of large entries when memory pressure is high
		if dc.stats.Bytes > dc.maxBytes*9/10 { // >90% capacity
			item := ele.Value.(*cacheItem)
			if item.entry.Size > dc.maxEntrySize/2 {
				dc.removeElement(ele, true)
				continue
			}
		}

		dc.removeElement(ele, true)
	}
}

func (dc *DedupCache) removeElement(ele *list.Element, countEviction bool) {
	if ele == nil {
		return
	}
	item := ele.Value.(*cacheItem)
	delete(dc.entries, item.key)
	dc.lru.Remove(ele)
	dc.stats.Entries--
	dc.stats.Bytes -= item.entry.Size
	if countEviction {
		dc.stats.Evictions++
	}
}
