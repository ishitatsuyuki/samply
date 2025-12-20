use schnellru::{ByLength, LruMap};

use super::types::StackMode;

/// Information about a frame's address, used for cache key construction.
/// This is the "input" side of the cache - what goes into frame resolution.
#[derive(Clone, Copy, Debug)]
pub struct FrameAddressInfo {
    /// The lookup address (already adjusted for return addresses via saturating_sub(1))
    pub lookup_address: u64,
    /// User or Kernel mode
    pub stack_mode: StackMode,
    /// True if this is an instruction pointer, false if return address
    pub from_ip: bool,
}

/// Cache key for stack lookups.
/// Combines the frame's lookup address, mode, type, and parent stack index.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackCacheKey {
    /// The lookup address (already adjusted for return addresses via saturating_sub(1))
    pub lookup_address: u64,
    /// User or Kernel mode
    pub stack_mode: StackMode,
    /// True if this is an instruction pointer, false if return address
    pub from_ip: bool,
    /// The parent stack index (None for root frames)
    pub parent_stack_index: Option<usize>,
}

impl StackCacheKey {
    /// Create a cache key from frame address info and parent stack index.
    pub fn new(info: FrameAddressInfo, parent_stack_index: Option<usize>) -> Self {
        Self {
            lookup_address: info.lookup_address,
            stack_mode: info.stack_mode,
            from_ip: info.from_ip,
            parent_stack_index,
        }
    }
}

/// LRU cache for (address, parent_stack) -> stack_index mappings.
/// Uses schnellru for proper LRU eviction when the cache is full.
pub struct StackCache {
    cache: LruMap<StackCacheKey, usize>,
}

impl StackCache {
    /// Create a new cache with the specified maximum size.
    pub fn new(max_size: u32) -> Self {
        Self {
            cache: LruMap::new(ByLength::new(max_size)),
        }
    }

    /// Look up a cached stack index. Updates LRU order on hit.
    #[inline]
    pub fn get(&mut self, key: &StackCacheKey) -> Option<usize> {
        self.cache.get(key).copied()
    }

    /// Insert a new cache entry. Evicts the least recently used entry if full.
    #[inline]
    pub fn insert(&mut self, key: StackCacheKey, stack_index: usize) {
        self.cache.insert(key, stack_index);
    }
}

impl Default for StackCache {
    fn default() -> Self {
        Self::new(8192)
    }
}
