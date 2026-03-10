//! In-memory lookup table store for IOC matching and enrichment at eval time.
//!
//! A lookup table is a named set of string values (case-insensitive).  Rules use
//! the `|lookup` Sigma modifier to check whether a field value is a member of a
//! named table — replacing long `|contains` lists with maintainable, hot-swappable
//! data sets (IP reputation lists, known-bad hashes, CMDB user lists, etc.).
//!
//! ## Example Sigma usage
//! ```yaml
//! detection:
//!   selection:
//!     src_ip|lookup: ioc_ips      # field value must be in the 'ioc_ips' table
//!   condition: selection
//! ```
//!
//! Multiple tables can be listed (OR semantics — value found in ANY table):
//! ```yaml
//! src_ip|lookup:
//!   - ioc_ips
//!   - threat_feed
//! ```
//!
//! ## Thread safety
//! `LookupStore` uses a [`DashMap`] of [`Arc<HashSet>`] so that:
//! - Reads are concurrent and lock-free (shared Arc clone).
//! - Writes atomically replace the entire table (swap the Arc pointer).

use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Metadata returned when listing available lookup tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupTableInfo {
    pub name: String,
    pub entry_count: usize,
}

/// Thread-safe, in-memory store for named lookup tables.
///
/// Each table is an immutable, reference-counted [`HashSet<String>`].  Readers
/// grab a cheap `Arc` clone; writers atomically swap the entire set so readers
/// never block writers and vice-versa.
#[derive(Default)]
pub struct LookupStore {
    /// table_name → Arc<HashSet<lowercase_value>>
    tables: DashMap<String, Arc<HashSet<String>>>,
}

impl LookupStore {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Write operations ───────────────────────────────────────────────────────

    /// Create or completely replace a table with the given entries.
    /// Entries are stored lowercase for case-insensitive matching.
    pub fn set_entries(&self, name: &str, entries: impl IntoIterator<Item = String>) {
        let set: HashSet<String> = entries.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        self.tables.insert(name.to_string(), Arc::new(set));
    }

    /// Add entries to an existing table (creates the table if it does not exist).
    pub fn add_entries(&self, name: &str, entries: impl IntoIterator<Item = String>) {
        let new_values: Vec<String> =
            entries.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        let mut entry = self.tables.entry(name.to_string()).or_insert_with(|| Arc::new(HashSet::new()));
        let mut set: HashSet<String> = (**entry).clone();
        set.extend(new_values);
        *entry = Arc::new(set);
    }

    /// Remove specific entries from a table.  No-op if the table does not exist.
    pub fn remove_entries(&self, name: &str, entries: &[String]) {
        if let Some(mut entry) = self.tables.get_mut(name) {
            let lower: HashSet<String> =
                entries.iter().map(|s| s.to_ascii_lowercase()).collect();
            let set: HashSet<String> =
                (**entry).iter().filter(|v| !lower.contains(*v)).cloned().collect();
            *entry = Arc::new(set);
        }
    }

    /// Delete a table entirely.  Returns `true` if the table existed.
    pub fn delete_table(&self, name: &str) -> bool {
        self.tables.remove(name).is_some()
    }

    // ── Read operations ────────────────────────────────────────────────────────

    /// Check if `value` is a member of the named table (case-insensitive).
    /// Returns `false` if the table does not exist.
    pub fn contains(&self, table: &str, value: &str) -> bool {
        self.tables
            .get(table)
            .map(|set| set.contains(&value.to_ascii_lowercase()))
            .unwrap_or(false)
    }

    /// Return metadata for all known tables, sorted by name.
    pub fn list_tables(&self) -> Vec<LookupTableInfo> {
        let mut infos: Vec<LookupTableInfo> = self
            .tables
            .iter()
            .map(|entry| LookupTableInfo {
                name: entry.key().clone(),
                entry_count: entry.value().len(),
            })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        infos
    }

    /// Return all entries for a table in sorted order, or `None` if it does not exist.
    pub fn get_entries(&self, name: &str) -> Option<Vec<String>> {
        self.tables.get(name).map(|set| {
            let mut v: Vec<String> = set.iter().cloned().collect();
            v.sort();
            v
        })
    }

    /// Return `true` if the named table exists (even if empty).
    pub fn table_exists(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_case_insensitive() {
        let store = LookupStore::new();
        store.set_entries("ioc_ips", vec!["1.2.3.4".to_string(), "10.0.0.1".to_string()]);
        assert!(store.contains("ioc_ips", "1.2.3.4"));
        assert!(store.contains("ioc_ips", "1.2.3.4"));
        assert!(!store.contains("ioc_ips", "5.5.5.5"));
    }

    #[test]
    fn add_and_remove_entries() {
        let store = LookupStore::new();
        store.set_entries("hashes", vec!["aabbcc".to_string()]);
        store.add_entries("hashes", vec!["ddeeff".to_string()]);
        assert!(store.contains("hashes", "aabbcc"));
        assert!(store.contains("hashes", "ddeeff"));
        store.remove_entries("hashes", &["aabbcc".to_string()]);
        assert!(!store.contains("hashes", "aabbcc"));
        assert!(store.contains("hashes", "ddeeff"));
    }

    #[test]
    fn delete_table() {
        let store = LookupStore::new();
        store.set_entries("t", vec!["x".to_string()]);
        assert!(store.table_exists("t"));
        assert!(store.delete_table("t"));
        assert!(!store.table_exists("t"));
        assert!(!store.delete_table("t")); // already gone
    }

    #[test]
    fn missing_table_returns_false() {
        let store = LookupStore::new();
        assert!(!store.contains("nonexistent", "anything"));
    }

    #[test]
    fn list_tables_sorted() {
        let store = LookupStore::new();
        store.set_entries("z_table", vec!["a".to_string()]);
        store.set_entries("a_table", vec!["b".to_string(), "c".to_string()]);
        let infos = store.list_tables();
        assert_eq!(infos[0].name, "a_table");
        assert_eq!(infos[0].entry_count, 2);
        assert_eq!(infos[1].name, "z_table");
    }
}
