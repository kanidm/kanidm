#[derive(Debug)]
struct CacheEntry {
    token: RadiusAuthToken,
    fetched_at: Instant,
}

impl CacheEntry {
    /// Duration since this entry was pulled from Kanidm
    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.fetched_at)
    }

    /// If it's less than the TTL
    fn fresh(&self, now: Instant, ttl: Duration) -> bool {
        self.age(now) <= ttl
    }

    /// If it's past the TTL but within the stale window
    fn stale_allowed(&self, now: Instant, ttl: Duration, stale_window: Duration) -> bool {
        let age = self.age(now);
        age > ttl && age <= ttl.saturating_add(stale_window)
    }
}

struct LookupCache {
    cache_ttl: Duration,
    cache_stale_if_error: Duration,
    cache_max_entries: usize,
    cache: Mutex<BTreeMap<String, CacheEntry>>,
}

impl LookupCache {
    fn new() -> Self {
        Self {
            cache_ttl: Duration::from_secs(30),
            cache_stale_if_error: Duration::from_secs(120),
            cache_max_entries: 10_000,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn lookup_cache(&self, user_id: &str, now: Instant) -> Option<RadiusAuthToken> {
        let Ok(mut cache_guard) = self.cache.lock() else {
            error!("Couldn't acquire cache lock for lookup_cache");
            return None;
        };
        let entry = cache_guard.get(user_id)?;
        if entry.fresh(now, self.cache_ttl) {
            return Some(entry.token.clone());
        } else {
            cache_guard.remove(user_id);
        }
        None
    }

    fn lookup_stale_cache(&self, user_id: &str, now: Instant) -> Option<RadiusAuthToken> {
        let Ok(mut cache_guard) = self.cache.lock() else {
            error!("Couldn't acquire cache lock for lookup_stale_cache");
            return None;
        };
        let entry = cache_guard.get(user_id)?;
        if entry.stale_allowed(now, self.cache_ttl, self.cache_stale_if_error) {
            return Some(entry.token.clone());
        } else {
            cache_guard.remove(user_id);
        }
        None
    }

    fn insert_cache(&self, user_id: String, token: RadiusAuthToken, now: Instant) {
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= self.cache_max_entries && !guard.contains_key(&user_id) {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.fetched_at)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest_key);
                }
            }
            guard.insert(
                user_id,
                CacheEntry {
                    token,
                    fetched_at: now,
                },
            );
        } else {
            error!("Couldn't acquire cache lock for insert_cache");
        }
    }
}


