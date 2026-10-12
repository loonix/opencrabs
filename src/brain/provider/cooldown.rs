//! Per-provider cooldown registry.
//!
//! A 429 that declares a wait parks the provider until that moment. The
//! fallback chain routes around a parked provider, and it re-enters on its
//! own once the window lapses. A registry instance per chain, not a global,
//! so parallel tests never share state.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
pub struct CooldownRegistry {
    until: Mutex<HashMap<String, Instant>>,
}

impl CooldownRegistry {
    /// Park `provider` until `until`. A later, longer 429 extends the window;
    /// an earlier one never shortens it.
    pub fn park(&self, provider: &str, until: Instant) {
        let mut map = self.until.lock().unwrap_or_else(|p| p.into_inner());
        let slot = map.entry(provider.to_string()).or_insert(until);
        if until > *slot {
            *slot = until;
        }
    }

    /// True while the provider's declared window is still open.
    pub fn is_cooling(&self, provider: &str) -> bool {
        let map = self.until.lock().unwrap_or_else(|p| p.into_inner());
        map.get(provider)
            .is_some_and(|until| *until > Instant::now())
    }

    /// True when a window was ever recorded and not yet forgotten, cooling or
    /// lapsed. A lapsed record is what lets the chain try the provider again.
    pub fn has_record(&self, provider: &str) -> bool {
        let map = self.until.lock().unwrap_or_else(|p| p.into_inner());
        map.contains_key(provider)
    }

    /// Drop the record for `provider`.
    pub fn forget(&self, provider: &str) {
        let mut map = self.until.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(provider);
    }
}
