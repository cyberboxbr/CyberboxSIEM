// ─────────────────────────────────────────────────────────────────────────────
//  CyberboxSIEM — Detection Engine  (cyberbox-sigma-v2)
//
//  Implements a production-grade Sigma rule compiler and executor.
//
//  Sigma spec coverage:
//    ✓ logsource  (category / product / service) + event-source routing
//    ✓ Named selections + condition expression (ref, and, or, not, 1 of, all of, them)
//    ✓ Field modifiers: contains, startswith, endswith, re, cidr, windash,
//                       base64 (UTF-8 + UTF-16LE/wide), base64offset (3 variants),
//                       lt/lte/gt/gte, fieldref (cross-field equality),
//                       lookup (membership check against named lookup tables)
//    ✓ |all modifier (every value must match)
//    ✓ Keywords selections (full-text)
//    ✓ Null field checks
//    ✓ Nested JSON field paths (dot notation, case-insensitive keys)
//    ✓ Sigma→OCSF field name taxonomy mapping (60+ common fields)
//    ✓ Severity-based routing destinations
//    ✓ Aggregation conditions: count/sum/min/max/avg with sliding time window
//    ✓ timeframe: field wires rule-level agg window
//    ✓ Temporal correlation: near operator with per-entity sliding buffers
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use chrono::{Duration, Utc};
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use cyberbox_core::{CyberboxError, LookupStore};
use cyberbox_models::{
    AlertRecord, AlertStatus, DetectionRule, EventEnvelope, EventSource, MitreAttack, RoutingState,
    RuleTestResult, Severity,
};

// ─── Process-global regex cache ───────────────────────────────────────────────
// Compiling a `Regex` is ~77 µs; caching by pattern string amortises this cost
// to a one-time hit per unique pattern across all rules and evaluations.

static REGEX_CACHE: OnceLock<DashMap<String, Arc<Regex>>> = OnceLock::new();

#[inline]
fn compiled_regex(pattern: &str) -> Option<Arc<Regex>> {
    let cache = REGEX_CACHE.get_or_init(DashMap::new);
    if let Some(r) = cache.get(pattern) {
        return Some(Arc::clone(&r));
    }
    match Regex::new(pattern) {
        Ok(re) => {
            let arc = Arc::new(re);
            cache.insert(pattern.to_string(), Arc::clone(&arc));
            Some(arc)
        }
        Err(_) => None,
    }
}

// ─── Sharded concurrent map for aggregate/distinct buffers ────────────────────
//
// Replaces `DashMap<String, Mutex<V>>` for `agg_buffers` and
// `distinct_buffers`.  DashMap uses 16 shards (RwLock each); under rayon
// parallel rule evaluation several threads may land in the same shard.
//
// `ShardedMap` uses 64 shards of plain `Mutex<HashMap>`.  Advantages:
//   • 4× more shards → lower contention
//   • `Mutex` is cheaper than `RwLock` for write-heavy aggregate workloads
//   • No epoch-GC overhead (cf. `flurry`)
//   • `with_entry` holds the shard lock only while the closure runs (~1 µs),
//     which is shorter than DashMap's two-phase dance

const SHARDED_MAP_SHARDS: usize = 64;

struct ShardedMap<V> {
    shards: Vec<std::sync::Mutex<HashMap<String, V>>>,
}

impl<V: Default> ShardedMap<V> {
    fn new() -> Self {
        let shards = (0..SHARDED_MAP_SHARDS)
            .map(|_| std::sync::Mutex::new(HashMap::new()))
            .collect();
        Self { shards }
    }

    /// Shard index for `key` via FNV-1a (branch-free, no alloc).
    #[inline]
    fn shard_idx(key: &str) -> usize {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in key.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        (h as usize) % SHARDED_MAP_SHARDS
    }

    /// Run `f` with a mutable reference to the entry for `key`, inserting a
    /// default value if the key is absent.  Holds the shard lock for the
    /// duration of `f`.
    fn with_entry<F, R>(&self, key: &str, f: F) -> R
    where
        F: FnOnce(&mut V) -> R,
    {
        let idx = Self::shard_idx(key);
        let mut shard = self.shards[idx].lock().unwrap();
        let entry = shard.entry(key.to_string()).or_default();
        f(entry)
    }

    /// Remove all keys matching `pred`.
    #[allow(dead_code)]
    fn retain<F>(&self, mut pred: F)
    where
        F: FnMut(&str) -> bool,
    {
        for shard in &self.shards {
            shard.lock().unwrap().retain(|k, _| pred(k));
        }
    }

    /// Remove all entries.
    fn clear(&self) {
        for shard in &self.shards {
            shard.lock().unwrap().clear();
        }
    }
}

// ─── Compiled Plan Types ──────────────────────────────────────────────────────

/// The fully compiled representation of a Sigma rule, stored as JSON
/// in `DetectionRule.compiled_plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledSigmaPlan {
    pub engine_version: String,
    pub title: String,
    pub description: String,
    pub logsource: LogSource,
    /// The root condition AST node.
    pub condition: ConditionNode,
    /// Named selections parsed from the `detection` block.
    pub selections: HashMap<String, SelectionGroup>,
    pub tags: Vec<String>,
    /// Sliding-window duration in seconds parsed from the `timeframe:` field.
    /// When present, overrides the `RuleExecutor`'s global `agg_window`.
    #[serde(default)]
    pub timeframe_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// AST node for Sigma condition expressions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ConditionNode {
    /// Reference to a named selection: `selection`
    Ref { name: String },
    /// Logical AND: `a and b`
    And {
        left: Box<ConditionNode>,
        right: Box<ConditionNode>,
    },
    /// Logical OR: `a or b`
    Or {
        left: Box<ConditionNode>,
        right: Box<ConditionNode>,
    },
    /// Logical NOT: `not a`
    Not { inner: Box<ConditionNode> },
    /// At least one selection matching glob: `1 of sel*` / `1 of them`
    OneOf { pattern: String },
    /// All selections matching glob must match: `all of sel*` / `all of them`
    AllOf { pattern: String },
    /// Full-text keyword search across the raw payload
    Keywords { terms: Vec<String> },
    /// Aggregate condition: `selection | count() by src_ip > 10`
    Aggregate {
        selection: String,
        agg: Box<AggregateCondition>,
    },
    /// Temporal correlation: both selections must fire from the same entity within a window.
    /// Condition syntax: `sel_a near sel_b within 30s [by entity_field]`
    Near {
        base: String,
        nearby: String,
        entity_field: Option<String>,
        within_seconds: u64,
    },
}

/// A selection group — all matchers combined with AND semantics.
/// Within each matcher, the list of values is OR'd (unless `match_all` is set).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionGroup {
    pub matchers: Vec<FieldMatcher>,
}

/// One field comparison within a selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMatcher {
    /// `None` means this is a keywords/full-text matcher.
    pub field: Option<String>,
    pub modifiers: Vec<FieldModifier>,
    pub values: Vec<String>,
    /// When true, every value must match (`|all` modifier).
    pub match_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldModifier {
    Contains,
    StartsWith,
    /// Check whether the field exists (`true`) or is absent/null (`false`).
    /// Value in the YAML is a boolean: `Field|exists: true`.
    Exists,
    EndsWith,
    Re,
    Cidr,
    Base64,
    Base64Offset,
    Wide,
    Windash,
    Lt,
    Lte,
    Gt,
    Gte,
    /// Compare the source field's value against the runtime value of another named field.
    /// The reference field name is stored as a string in `FieldMatcher::values`.
    /// Syntax: `SourceImage|fieldref: TargetImage`
    FieldRef,
    /// Check whether the field value is a member of a named lookup table.
    /// The lookup table name(s) are stored in `FieldMatcher::values`.
    /// Syntax: `src_ip|lookup: ioc_ips`
    Lookup,
}

// ─── Aggregation Types ────────────────────────────────────────────────────────

/// Aggregate function used in a pipe condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Min,
    Max,
    Avg,
    /// Count of distinct values of `field` within the time window.
    /// Syntax: `count_distinct(TargetUserName)`.
    CountDistinct,
}

/// Comparison operator for an aggregate threshold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AggCompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

/// Fully parsed aggregate condition: `count() by src_ip > 10`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateCondition {
    /// The aggregate function to apply.
    pub function: AggregateFunction,
    /// Field to aggregate over (None for `count()`).
    pub field: Option<String>,
    /// Field to group events by before aggregating (None = global count).
    pub group_by: Option<String>,
    /// Comparison operator.
    pub operator: AggCompareOp,
    /// Numeric threshold.
    pub threshold: f64,
}

// ─── Per-event evaluation context (P4 field-extraction cache) ─────────────────

/// Pre-computed data for evaluating many rules against a single event.
///
/// Build once with [`build_event_context`] before the parallel rule loop, then
/// pass a shared reference into each [`RuleExecutor::evaluate_with_context`] call.
/// This amortises the cost of JSON field extraction and payload serialisation
/// across all rules that inspect the same event.
pub struct EventContext<'a> {
    /// The underlying event (needed for aggregate/near buffers that store it).
    pub event: &'a EventEnvelope,
    /// `raw_payload` serialised to ASCII-lowercase **once** — reused by all
    /// keywords matchers so they don't each pay the `to_string().to_ascii_lowercase()` cost.
    pub(crate) raw_payload_lower: String,
    /// Field values pre-extracted from the event for every field name referenced
    /// by the active rule set.  Fields absent from the cache are looked up live
    /// (best-effort, never a correctness constraint).
    pub(crate) field_cache: HashMap<String, Vec<String>>,
    /// Optional lookup table store for `|lookup` modifier evaluation.
    /// `None` in contexts where no store has been wired up (e.g. dry-run without data).
    pub(crate) lookup_store: Option<Arc<LookupStore>>,
}

impl<'a> EventContext<'a> {
    /// Attach a [`LookupStore`] so that `|lookup` modifiers can be evaluated.
    /// Call this after [`build_event_context`] before passing the context to the rule executor.
    pub fn with_lookup_store(mut self, store: Arc<LookupStore>) -> Self {
        self.lookup_store = Some(store);
        self
    }
}

/// Walk a `ConditionNode` tree and collect every field name that is directly
/// referenced (aggregate group-by / field, near entity_field).
/// Selection matcher fields are collected by the caller separately.
fn collect_condition_field_names(node: &ConditionNode, out: &mut HashSet<String>) {
    match node {
        ConditionNode::And { left, right } | ConditionNode::Or { left, right } => {
            collect_condition_field_names(left, out);
            collect_condition_field_names(right, out);
        }
        ConditionNode::Not { inner } => collect_condition_field_names(inner, out),
        ConditionNode::Aggregate { agg, .. } => {
            if let Some(f) = &agg.group_by {
                out.insert(f.clone());
            }
            if let Some(f) = &agg.field {
                out.insert(f.clone());
            }
        }
        ConditionNode::Near { entity_field, .. } => {
            if let Some(f) = entity_field {
                out.insert(f.clone());
            }
        }
        _ => {}
    }
}

/// Collect all field names referenced by a compiled rule plan.
///
/// Includes selection matcher fields, fieldref target fields, and any field
/// names inside aggregate / near conditions.
pub fn collect_plan_field_names(plan: &CompiledSigmaPlan) -> HashSet<String> {
    let mut fields = HashSet::new();
    for group in plan.selections.values() {
        for matcher in &group.matchers {
            if let Some(f) = &matcher.field {
                fields.insert(f.clone());
                // fieldref values are themselves field names to look up at runtime.
                if matcher.modifiers.contains(&FieldModifier::FieldRef) {
                    for v in &matcher.values {
                        fields.insert(v.clone());
                    }
                }
            }
        }
    }
    collect_condition_field_names(&plan.condition, &mut fields);
    fields
}

/// Build an [`EventContext`] by pre-extracting every field in `field_names`.
///
/// Call this once per event before the `par_iter` over rules so all rules share
/// the same pre-computed field values and lowercased payload string.
pub fn build_event_context<'a>(
    event: &'a EventEnvelope,
    field_names: &HashSet<String>,
) -> EventContext<'a> {
    let raw_payload_lower = event.raw_payload.to_string().to_ascii_lowercase();
    let mut field_cache = HashMap::with_capacity(field_names.len());
    for field in field_names {
        let vals = extract_field_values_raw(event, field);
        if !vals.is_empty() {
            field_cache.insert(field.clone(), vals);
        }
    }
    EventContext {
        event,
        raw_payload_lower,
        field_cache,
        lookup_store: None,
    }
}

// ─── SigmaCompiler ────────────────────────────────────────────────────────────

/// Parses Sigma YAML source into a `CompiledSigmaPlan` stored as `serde_json::Value`.
#[derive(Clone, Default)]
pub struct SigmaCompiler;

impl SigmaCompiler {
    /// Compile a Sigma rule YAML string into a compiled plan JSON value.
    /// Returns `CyberboxError::BadRequest` on malformed input.
    pub fn compile(&self, sigma_source: &str) -> Result<Value, CyberboxError> {
        if sigma_source.trim().is_empty() {
            return Err(CyberboxError::BadRequest(
                "sigma_source cannot be empty".to_string(),
            ));
        }

        let yaml: serde_yaml::Value = serde_yaml::from_str(sigma_source)
            .map_err(|e| CyberboxError::BadRequest(format!("invalid Sigma YAML: {e}")))?;

        let root = yaml.as_mapping().ok_or_else(|| {
            CyberboxError::BadRequest("sigma rule must be a YAML mapping".to_string())
        })?;

        let title = yaml_str(root, "title")
            .unwrap_or("untitled_rule")
            .to_string();
        let description = yaml_str(root, "description").unwrap_or("").to_string();
        let tags = parse_sigma_tags(root);
        let logsource = parse_sigma_logsource(root);
        let detection = root
            .get("detection")
            .and_then(|v| v.as_mapping())
            .ok_or_else(|| {
                CyberboxError::BadRequest("sigma rule must have a 'detection' block".to_string())
            })?;

        let condition_str = detection
            .get("condition")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CyberboxError::BadRequest(
                    "detection block must have a 'condition' field".to_string(),
                )
            })?;

        // `timeframe:` lives inside the detection block per the Sigma spec.
        // Fall back to the root level for legacy / non-standard rules.
        let timeframe_seconds = detection
            .get("timeframe")
            .and_then(|v| v.as_str())
            .or_else(|| yaml_str(root, "timeframe"))
            .and_then(parse_sigma_timeframe);

        let mut selections: HashMap<String, SelectionGroup> = HashMap::new();
        for (key, value) in detection.iter() {
            let key_str = match key.as_str() {
                Some(s) => s,
                None => continue,
            };
            // Reserved detection keys — not selections.
            if matches!(key_str, "condition" | "timeframe") {
                continue;
            }
            let group = parse_selection_group(value)
                .map_err(|e| CyberboxError::BadRequest(format!("selection '{key_str}': {e}")))?;
            selections.insert(key_str.to_string(), group);
        }

        let condition = parse_condition_expr(condition_str)
            .map_err(|e| CyberboxError::BadRequest(format!("condition '{condition_str}': {e}")))?;

        let plan = CompiledSigmaPlan {
            engine_version: "cyberbox-sigma-v2".to_string(),
            title,
            description,
            logsource,
            condition,
            selections,
            tags,
            timeframe_seconds,
        };

        serde_json::to_value(&plan)
            .map_err(|e| CyberboxError::Internal(format!("serialize compiled plan: {e}")))
    }
}

// ─── YAML Helpers ─────────────────────────────────────────────────────────────

fn yaml_str<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    map.get(key).and_then(|v| v.as_str())
}

fn parse_sigma_logsource(root: &serde_yaml::Mapping) -> LogSource {
    let ls = root.get("logsource").and_then(|v| v.as_mapping());
    let get = |key: &str| -> Option<String> { ls?.get(key)?.as_str().map(|s| s.to_string()) };
    LogSource {
        category: get("category"),
        product: get("product"),
        service: get("service"),
    }
}

fn parse_sigma_tags(root: &serde_yaml::Mapping) -> Vec<String> {
    root.get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ─── MITRE ATT&CK Enrichment ──────────────────────────────────────────────────

/// Static table: (technique_id, tactic, technique_name).
///
/// Covers the techniques that appear most often in public Sigma rule repositories.
/// Tactic slugs follow MITRE's own naming (underscores, lowercase).
/// Sub-techniques are listed explicitly; the base technique entry serves as a fallback.
static MITRE_TECHNIQUES: &[(&str, &str, &str)] = &[
    // ── Execution ────────────────────────────────────────────────────────────
    ("T1059", "execution", "Command and Scripting Interpreter"),
    ("T1059.001", "execution", "PowerShell"),
    ("T1059.002", "execution", "AppleScript"),
    ("T1059.003", "execution", "Windows Command Shell"),
    ("T1059.004", "execution", "Unix Shell"),
    ("T1059.005", "execution", "Visual Basic"),
    ("T1059.006", "execution", "Python"),
    ("T1059.007", "execution", "JavaScript"),
    ("T1106", "execution", "Native API"),
    ("T1569", "execution", "System Services"),
    ("T1569.002", "execution", "Service Execution"),
    ("T1204", "execution", "User Execution"),
    ("T1204.001", "execution", "Malicious Link"),
    ("T1204.002", "execution", "Malicious File"),
    // ── Persistence ──────────────────────────────────────────────────────────
    ("T1547", "persistence", "Boot or Logon Autostart Execution"),
    (
        "T1547.001",
        "persistence",
        "Registry Run Keys / Startup Folder",
    ),
    ("T1547.004", "persistence", "Winlogon Helper DLL"),
    ("T1547.009", "persistence", "Shortcut Modification"),
    ("T1543", "persistence", "Create or Modify System Process"),
    ("T1543.003", "persistence", "Windows Service"),
    ("T1574", "persistence", "Hijack Execution Flow"),
    ("T1574.002", "persistence", "DLL Side-Loading"),
    ("T1098", "persistence", "Account Manipulation"),
    ("T1078", "persistence", "Valid Accounts"),
    // ── Privilege Escalation ─────────────────────────────────────────────────
    ("T1055", "privilege_escalation", "Process Injection"),
    (
        "T1055.001",
        "privilege_escalation",
        "Dynamic-link Library Injection",
    ),
    (
        "T1055.002",
        "privilege_escalation",
        "Portable Executable Injection",
    ),
    ("T1055.012", "privilege_escalation", "Process Hollowing"),
    (
        "T1548",
        "privilege_escalation",
        "Abuse Elevation Control Mechanism",
    ),
    (
        "T1548.002",
        "privilege_escalation",
        "Bypass User Account Control",
    ),
    ("T1134", "privilege_escalation", "Access Token Manipulation"),
    (
        "T1134.001",
        "privilege_escalation",
        "Token Impersonation/Theft",
    ),
    // ── Defense Evasion ──────────────────────────────────────────────────────
    (
        "T1027",
        "defense_evasion",
        "Obfuscated Files or Information",
    ),
    ("T1027.010", "defense_evasion", "Command Obfuscation"),
    ("T1036", "defense_evasion", "Masquerading"),
    ("T1036.003", "defense_evasion", "Rename System Utilities"),
    ("T1070", "defense_evasion", "Indicator Removal"),
    ("T1070.001", "defense_evasion", "Clear Windows Event Logs"),
    ("T1070.004", "defense_evasion", "File Deletion"),
    ("T1112", "defense_evasion", "Modify Registry"),
    ("T1218", "defense_evasion", "System Binary Proxy Execution"),
    ("T1218.007", "defense_evasion", "Msiexec"),
    ("T1218.010", "defense_evasion", "Regsvr32"),
    ("T1218.011", "defense_evasion", "Rundll32"),
    ("T1562", "defense_evasion", "Impair Defenses"),
    ("T1562.001", "defense_evasion", "Disable or Modify Tools"),
    ("T1564", "defense_evasion", "Hide Artifacts"),
    (
        "T1564.001",
        "defense_evasion",
        "Hidden Files and Directories",
    ),
    // ── Credential Access ────────────────────────────────────────────────────
    ("T1003", "credential_access", "OS Credential Dumping"),
    ("T1003.001", "credential_access", "LSASS Memory"),
    ("T1003.002", "credential_access", "Security Account Manager"),
    ("T1003.003", "credential_access", "NTDS"),
    ("T1110", "credential_access", "Brute Force"),
    ("T1110.001", "credential_access", "Password Guessing"),
    ("T1110.003", "credential_access", "Password Spraying"),
    ("T1552", "credential_access", "Unsecured Credentials"),
    (
        "T1558",
        "credential_access",
        "Steal or Forge Kerberos Tickets",
    ),
    ("T1558.003", "credential_access", "Kerberoasting"),
    // ── Discovery ────────────────────────────────────────────────────────────
    ("T1012", "discovery", "Query Registry"),
    (
        "T1016",
        "discovery",
        "System Network Configuration Discovery",
    ),
    ("T1033", "discovery", "System Owner/User Discovery"),
    ("T1049", "discovery", "System Network Connections Discovery"),
    ("T1057", "discovery", "Process Discovery"),
    ("T1069", "discovery", "Permission Groups Discovery"),
    ("T1082", "discovery", "System Information Discovery"),
    ("T1083", "discovery", "File and Directory Discovery"),
    ("T1087", "discovery", "Account Discovery"),
    // ── Lateral Movement ─────────────────────────────────────────────────────
    ("T1021", "lateral_movement", "Remote Services"),
    ("T1021.001", "lateral_movement", "Remote Desktop Protocol"),
    ("T1021.002", "lateral_movement", "SMB/Windows Admin Shares"),
    ("T1021.006", "lateral_movement", "Windows Remote Management"),
    ("T1570", "lateral_movement", "Lateral Tool Transfer"),
    // ── Collection ───────────────────────────────────────────────────────────
    ("T1005", "collection", "Data from Local System"),
    ("T1119", "collection", "Automated Collection"),
    // ── Command and Control ──────────────────────────────────────────────────
    ("T1071", "command_and_control", "Application Layer Protocol"),
    ("T1071.001", "command_and_control", "Web Protocols"),
    ("T1105", "command_and_control", "Ingress Tool Transfer"),
    ("T1571", "command_and_control", "Non-Standard Port"),
    ("T1572", "command_and_control", "Protocol Tunneling"),
    // ── Exfiltration ─────────────────────────────────────────────────────────
    ("T1041", "exfiltration", "Exfiltration Over C2 Channel"),
    (
        "T1048",
        "exfiltration",
        "Exfiltration Over Alternative Protocol",
    ),
    // ── Initial Access ───────────────────────────────────────────────────────
    (
        "T1190",
        "initial_access",
        "Exploit Public-Facing Application",
    ),
    ("T1566", "initial_access", "Phishing"),
    ("T1566.001", "initial_access", "Spearphishing Attachment"),
    ("T1566.002", "initial_access", "Spearphishing Link"),
    ("T1133", "initial_access", "External Remote Services"),
    // ── Impact ───────────────────────────────────────────────────────────────
    ("T1486", "impact", "Data Encrypted for Impact"),
    ("T1496", "impact", "Resource Hijacking"),
    ("T1489", "impact", "Service Stop"),
    ("T1490", "impact", "Inhibit System Recovery"),
];

/// Look up the (tactic, technique_name) for a canonical technique ID like `"T1059.001"`.
///
/// If the sub-technique is not in the table, falls back to the base technique entry.
/// Returns `(None, None)` for completely unknown IDs.
fn mitre_lookup(technique_id: &str) -> (Option<String>, Option<String>) {
    // Try exact match first, then base technique (strip sub-technique suffix).
    let found = MITRE_TECHNIQUES
        .iter()
        .find(|(id, _, _)| id.eq_ignore_ascii_case(technique_id));

    if let Some((_, tactic, name)) = found {
        return (Some(tactic.to_string()), Some(name.to_string()));
    }

    // Fall back to base technique (e.g. "T1059" for "T1059.001").
    if let Some(dot) = technique_id.find('.') {
        let base = &technique_id[..dot];
        if let Some((_, tactic, name)) = MITRE_TECHNIQUES
            .iter()
            .find(|(id, _, _)| id.eq_ignore_ascii_case(base))
        {
            return (Some(tactic.to_string()), Some(name.to_string()));
        }
    }

    (None, None)
}

/// Returns the total number of techniques in CyberboxSIEM's static MITRE ATT&CK table.
/// Used by the coverage report endpoint to compute the coverage percentage.
pub fn mitre_technique_count() -> usize {
    MITRE_TECHNIQUES.len()
}

/// Parse `tags: [attack.t1059.001, attack.execution, ...]` into structured `MitreAttack` entries.
///
/// Only tags that start with `attack.t` (technique IDs) are converted.
/// Tactic-only tags (`attack.execution`, `attack.defense_evasion`, …) are skipped —
/// the tactic is derived from the technique lookup table instead.
pub fn parse_mitre_from_tags(tags: &[String]) -> Vec<MitreAttack> {
    tags.iter()
        .filter_map(|tag| {
            let lower = tag.to_ascii_lowercase();
            let rest = lower.strip_prefix("attack.")?;
            // Must start with 't' followed by digits to be a technique ID.
            let after_t = rest.strip_prefix('t')?;
            if !after_t.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            // Canonicalise: "t1059.001" → "T1059.001"
            let technique_id = format!("T{}", after_t);
            let (tactic, technique_name) = mitre_lookup(&technique_id);
            Some(MitreAttack {
                technique_id,
                tactic,
                technique_name,
            })
        })
        .collect()
}

/// Parse a Sigma `timeframe:` value (e.g. `"5m"`, `"1h"`, `"30s"`, `"1d"`, `"1w"`)
/// into a duration in seconds. Returns `None` for unrecognised formats.
fn parse_sigma_timeframe(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s.len() < 2 {
        return None;
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str.parse().ok()?;
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    Some(num * mult)
}

// ─── Logsource Routing ────────────────────────────────────────────────────────

/// Returns `true` if the event's source is compatible with the rule's logsource.
///
/// Rules with no logsource constraints match all events.  Rules that declare a
/// `product` or `category` are only evaluated against matching event sources,
/// preventing Windows rules from running on Linux or firewall events and vice-versa.
pub fn logsource_matches_event(logsource: &LogSource, source: &EventSource) -> bool {
    if logsource.product.is_none() && logsource.category.is_none() && logsource.service.is_none() {
        return true;
    }

    if let Some(product) = &logsource.product {
        match product.to_ascii_lowercase().as_str() {
            "windows" | "sysmon" | "microsoft-windows" => {
                if !matches!(
                    source,
                    EventSource::WindowsSysmon | EventSource::AgentForwarded
                ) {
                    return false;
                }
            }
            "linux" => {
                if !matches!(
                    source,
                    EventSource::LinuxAudit
                        | EventSource::LinuxAuth
                        | EventSource::Syslog
                        | EventSource::AgentForwarded
                ) {
                    return false;
                }
            }
            "aws" | "gcp" | "azure" | "okta" | "cloud" | "google" => {
                if !matches!(source, EventSource::CloudAudit | EventSource::Otlp) {
                    return false;
                }
            }
            "palo_alto" | "cisco" | "fortinet" | "checkpoint" | "firewall" => {
                if !matches!(source, EventSource::Firewall) {
                    return false;
                }
            }
            // Unknown product — be permissive; don't skip
            _ => {}
        }
    }

    if let Some(category) = &logsource.category {
        match category.to_ascii_lowercase().as_str() {
            "process_creation"
            | "process_access"
            | "process_tampering"
            | "image_load"
            | "driver_load"
            | "file_event"
            | "registry_add"
            | "registry_delete"
            | "registry_event"
            | "registry_rename"
            | "registry_set"
            | "create_remote_thread"
            | "create_stream_hash"
            | "pipe_created"
            | "wmi_event"
            | "raw_access_read" => {
                if !matches!(
                    source,
                    EventSource::WindowsSysmon | EventSource::AgentForwarded
                ) {
                    return false;
                }
            }
            "network_connection" | "network_protocol" | "dns_query" | "firewall" => {
                if !matches!(
                    source,
                    EventSource::Firewall
                        | EventSource::Otlp
                        | EventSource::WindowsSysmon
                        | EventSource::AgentForwarded
                        | EventSource::Syslog
                ) {
                    return false;
                }
            }
            "authentication" | "auth" | "login" | "account_management" => {
                // Auth events can arrive from many sources
                if !matches!(
                    source,
                    EventSource::WindowsSysmon
                        | EventSource::LinuxAuth
                        | EventSource::LinuxAudit
                        | EventSource::CloudAudit
                        | EventSource::AgentForwarded
                        | EventSource::Syslog
                ) {
                    return false;
                }
            }
            // Unknown category — be permissive
            _ => {}
        }
    }

    true
}

// ─── Selection Parsing ────────────────────────────────────────────────────────

/// Parse one detection selection value into a `SelectionGroup`.
fn parse_selection_group(value: &serde_yaml::Value) -> Result<SelectionGroup, String> {
    match value {
        // Sequence top-level → keywords (full-text search, OR semantics)
        serde_yaml::Value::Sequence(seq) => {
            let terms: Vec<String> = seq.iter().filter_map(yaml_value_to_string).collect();
            Ok(SelectionGroup {
                matchers: vec![FieldMatcher {
                    field: None,
                    modifiers: vec![FieldModifier::Contains],
                    values: terms,
                    match_all: false,
                }],
            })
        }
        // Mapping → field-based matchers (AND between fields)
        serde_yaml::Value::Mapping(map) => {
            let mut matchers = Vec::new();
            for (key, val) in map.iter() {
                let key_str = key
                    .as_str()
                    .ok_or_else(|| "field key must be a string".to_string())?;
                matchers.push(parse_field_matcher(key_str, val)?);
            }
            Ok(SelectionGroup { matchers })
        }
        other => Err(format!("unsupported selection type: {other:?}")),
    }
}

/// Parse a key like `"CommandLine|contains|all"` and its value into a `FieldMatcher`.
fn parse_field_matcher(key: &str, value: &serde_yaml::Value) -> Result<FieldMatcher, String> {
    let parts: Vec<&str> = key.split('|').collect();
    let field = parts[0].to_string();

    let mut modifiers: Vec<FieldModifier> = Vec::new();
    let mut match_all = false;

    for &part in &parts[1..] {
        match part.to_lowercase().as_str() {
            "contains" => modifiers.push(FieldModifier::Contains),
            "startswith" => modifiers.push(FieldModifier::StartsWith),
            "endswith" => modifiers.push(FieldModifier::EndsWith),
            "re" | "regex" => modifiers.push(FieldModifier::Re),
            "cidr" => modifiers.push(FieldModifier::Cidr),
            "base64" => modifiers.push(FieldModifier::Base64),
            "base64offset" => modifiers.push(FieldModifier::Base64Offset),
            "wide" => modifiers.push(FieldModifier::Wide),
            "windash" => modifiers.push(FieldModifier::Windash),
            "lt" => modifiers.push(FieldModifier::Lt),
            "lte" => modifiers.push(FieldModifier::Lte),
            "gt" => modifiers.push(FieldModifier::Gt),
            "gte" => modifiers.push(FieldModifier::Gte),
            "all" => match_all = true,
            "i" | "ignorecase" => {} // always case-insensitive — no-op
            "exists" => modifiers.push(FieldModifier::Exists),
            "fieldref" => modifiers.push(FieldModifier::FieldRef),
            "lookup" => modifiers.push(FieldModifier::Lookup),
            other => return Err(format!("unknown modifier '{other}'")),
        }
    }

    let values = match value {
        serde_yaml::Value::Sequence(seq) => seq.iter().filter_map(yaml_value_to_string).collect(),
        serde_yaml::Value::Null => vec!["__null__".to_string()],
        other => match yaml_value_to_string(other) {
            Some(s) => vec![s],
            None => vec![],
        },
    };

    Ok(FieldMatcher {
        field: Some(field),
        modifiers,
        values,
        match_all,
    })
}

fn yaml_value_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Null => Some("__null__".to_string()),
        _ => None,
    }
}

// ─── Condition Expression Parser ──────────────────────────────────────────────
//
//  Grammar (LL(1) recursive-descent):
//    condition := or_expr
//    or_expr   := and_expr  ('or'  and_expr)*
//    and_expr  := unary     ('and' unary)*
//    unary     := 'not' unary | atom
//    atom      := '(' condition ')'
//               | ('1' 'of' | 'all' 'of') PATTERN
//               | IDENT
//
//  PATTERN may be a selection name optionally ending with '*', or "them".

fn parse_condition_expr(input: &str) -> Result<ConditionNode, String> {
    let mut parser = ConditionParser::new(input);
    let node = parser.parse_or()?;
    if !parser.is_done() {
        return Err(format!(
            "unexpected token '{}' after valid condition",
            parser.peek().unwrap_or("")
        ));
    }
    Ok(node)
}

struct ConditionParser {
    tokens: Vec<String>,
    pos: usize,
}

impl ConditionParser {
    fn new(input: &str) -> Self {
        Self {
            tokens: tokenize_condition(input),
            pos: 0,
        }
    }

    fn is_done(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(|s| s.as_str())
    }

    fn advance(&mut self) -> Option<&str> {
        let tok = self.tokens.get(self.pos).map(|s| s.as_str());
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, expected: &str) -> Result<(), String> {
        match self.advance() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(()),
            Some(t) => Err(format!("expected '{expected}', got '{t}'")),
            None => Err(format!("expected '{expected}', got end of input")),
        }
    }

    fn parse_or(&mut self) -> Result<ConditionNode, String> {
        let mut left = self.parse_and()?;
        while self
            .peek()
            .map(|t| t.eq_ignore_ascii_case("or"))
            .unwrap_or(false)
        {
            self.pos += 1;
            let right = self.parse_and()?;
            left = ConditionNode::Or {
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ConditionNode, String> {
        let mut left = self.parse_unary()?;
        while self
            .peek()
            .map(|t| t.eq_ignore_ascii_case("and"))
            .unwrap_or(false)
        {
            self.pos += 1;
            let right = self.parse_unary()?;
            left = ConditionNode::And {
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<ConditionNode, String> {
        if self
            .peek()
            .map(|t| t.eq_ignore_ascii_case("not"))
            .unwrap_or(false)
        {
            self.pos += 1;
            let inner = self.parse_unary()?;
            return Ok(ConditionNode::Not {
                inner: Box::new(inner),
            });
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<ConditionNode, String> {
        match self.peek() {
            Some("(") => {
                self.pos += 1;
                let node = self.parse_or()?;
                self.expect(")")?;
                Ok(node)
            }
            // "1 of <pattern>"
            Some("1") => {
                self.pos += 1;
                self.expect("of")?;
                let pat = self
                    .advance()
                    .ok_or_else(|| "expected pattern after '1 of'".to_string())?
                    .to_string();
                Ok(ConditionNode::OneOf { pattern: pat })
            }
            // "all of <pattern>"
            Some(t) if t.eq_ignore_ascii_case("all") => {
                self.pos += 1;
                self.expect("of")?;
                let pat = self
                    .advance()
                    .ok_or_else(|| "expected pattern after 'all of'".to_string())?
                    .to_string();
                Ok(ConditionNode::AllOf { pattern: pat })
            }
            Some(name) if !name.is_empty() => {
                let name = name.to_string();
                self.pos += 1;
                // Aggregate pipe: `selection_name | func(field) [by group_field] op threshold`
                if self.peek() == Some("|") {
                    self.pos += 1; // consume `|`
                    let agg = self.parse_aggregate()?;
                    return Ok(ConditionNode::Aggregate {
                        selection: name,
                        agg: Box::new(agg),
                    });
                }
                // Temporal correlation: `sel_a near sel_b within 30s [by entity_field]`
                if self
                    .peek()
                    .map(|t| t.eq_ignore_ascii_case("near"))
                    .unwrap_or(false)
                {
                    self.pos += 1; // consume "near"
                    let nearby = self
                        .advance()
                        .ok_or_else(|| "expected selection name after 'near'".to_string())?
                        .to_string();
                    self.expect("within")?;
                    let tf_tok = self
                        .advance()
                        .ok_or_else(|| "expected timeframe after 'within'".to_string())?
                        .to_string();
                    let within_seconds = parse_sigma_timeframe(&tf_tok)
                        .ok_or_else(|| format!("invalid timeframe '{tf_tok}'"))?;
                    let entity_field = if self
                        .peek()
                        .map(|t| t.eq_ignore_ascii_case("by"))
                        .unwrap_or(false)
                    {
                        self.pos += 1;
                        Some(
                            self.advance()
                                .ok_or_else(|| "expected field name after 'by'".to_string())?
                                .to_string(),
                        )
                    } else {
                        None
                    };
                    return Ok(ConditionNode::Near {
                        base: name,
                        nearby,
                        entity_field,
                        within_seconds,
                    });
                }
                Ok(ConditionNode::Ref { name })
            }
            _ => Err("unexpected end of condition expression".to_string()),
        }
    }

    /// Parse the right-hand side of a pipe: `count() [by field] op threshold`
    fn parse_aggregate(&mut self) -> Result<AggregateCondition, String> {
        // Function name
        let func_tok = self
            .advance()
            .ok_or_else(|| "expected aggregate function name after '|'".to_string())?
            .to_lowercase();
        let function = match func_tok.as_str() {
            "count" => AggregateFunction::Count,
            "count_distinct" => AggregateFunction::CountDistinct,
            "sum" => AggregateFunction::Sum,
            "min" => AggregateFunction::Min,
            "max" => AggregateFunction::Max,
            "avg" => AggregateFunction::Avg,
            other => return Err(format!("unknown aggregate function '{other}'")),
        };

        // Argument list: `(field?)` or `()`
        self.expect("(")?;
        let field = if self.peek() != Some(")") {
            Some(
                self.advance()
                    .ok_or_else(|| "expected field name or ')'".to_string())?
                    .to_string(),
            )
        } else {
            None
        };
        self.expect(")")?;

        // Optional `by <group_field>`
        let group_by = if self
            .peek()
            .map(|t| t.eq_ignore_ascii_case("by"))
            .unwrap_or(false)
        {
            self.pos += 1;
            Some(
                self.advance()
                    .ok_or_else(|| "expected field name after 'by'".to_string())?
                    .to_string(),
            )
        } else {
            None
        };

        // Comparison operator
        let op_tok = self
            .advance()
            .ok_or_else(|| "expected comparison operator (>, >=, <, <=, ==)".to_string())?
            .to_string();
        let operator = match op_tok.as_str() {
            ">" => AggCompareOp::Gt,
            ">=" => AggCompareOp::Gte,
            "<" => AggCompareOp::Lt,
            "<=" => AggCompareOp::Lte,
            "==" => AggCompareOp::Eq,
            other => return Err(format!("unknown comparison operator '{other}'")),
        };

        // Numeric threshold
        let thresh_tok = self
            .advance()
            .ok_or_else(|| "expected numeric threshold".to_string())?
            .to_string();
        let threshold = thresh_tok
            .parse::<f64>()
            .map_err(|_| format!("invalid threshold value '{thresh_tok}'"))?;

        // count() ignores the field arg; count_distinct requires one
        if matches!(function, AggregateFunction::CountDistinct) && field.is_none() {
            return Err(
                "count_distinct requires a field argument, e.g. count_distinct(TargetUserName)"
                    .to_string(),
            );
        }
        let field = match function {
            AggregateFunction::Count => None,
            _ => field,
        };

        Ok(AggregateCondition {
            function,
            field,
            group_by,
            operator,
            threshold,
        })
    }
}

/// Split a condition string into tokens.
/// Handles: words, parentheses, `|`, and comparison operators (`>`, `>=`, `<`, `<=`, `==`).
fn tokenize_condition(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        // Single-char structural tokens
        if c == '(' || c == ')' || c == '|' {
            tokens.push(c.to_string());
            chars.next();
            continue;
        }
        // One- or two-char comparison operators: > >= < <= ==
        if c == '>' || c == '<' || c == '=' {
            chars.next();
            let mut op = c.to_string();
            if chars.peek() == Some(&'=') {
                op.push('=');
                chars.next();
            }
            tokens.push(op);
            continue;
        }
        // Word token (identifiers, numbers, wildcards)
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace()
                || c == '('
                || c == ')'
                || c == '|'
                || c == '>'
                || c == '<'
                || c == '='
            {
                break;
            }
            word.push(c);
            chars.next();
        }
        if !word.is_empty() {
            tokens.push(word);
        }
    }
    tokens
}

// ─── Incremental aggregate buffer types ───────────────────────────────────────

/// Sliding-window numeric buffer with a maintained `running_sum`.
/// Count/Sum/Avg are O(1); Min/Max scan the deque (uncommon aggregates).
#[derive(Default)]
struct AggEntry {
    deque: VecDeque<(std::time::Instant, f64)>,
    running_sum: f64,
}

impl AggEntry {
    fn evict_stale(&mut self, now: std::time::Instant, window: std::time::Duration) {
        while let Some((ts, _)) = self.deque.front() {
            if now.duration_since(*ts) < window {
                break;
            }
            let (_, val) = self.deque.pop_front().unwrap();
            self.running_sum -= val;
        }
    }

    fn push(&mut self, ts: std::time::Instant, val: f64) {
        self.running_sum += val;
        self.deque.push_back((ts, val));
    }

    fn count(&self) -> usize {
        self.deque.len()
    }
    fn sum(&self) -> f64 {
        self.running_sum
    }
    fn avg(&self) -> f64 {
        let n = self.deque.len();
        if n == 0 {
            0.0
        } else {
            self.running_sum / n as f64
        }
    }
    fn min(&self) -> f64 {
        self.deque
            .iter()
            .map(|(_, v)| *v)
            .fold(f64::INFINITY, f64::min)
    }
    fn max(&self) -> f64 {
        self.deque
            .iter()
            .map(|(_, v)| *v)
            .fold(f64::NEG_INFINITY, f64::max)
    }
}

/// Sliding-window string buffer with a maintained occurrence-count map.
/// `distinct_count()` is O(1); eviction is O(1) amortised.
#[derive(Default)]
struct DistinctEntry {
    deque: VecDeque<(std::time::Instant, String)>,
    counts: HashMap<String, usize>,
}

impl DistinctEntry {
    fn evict_stale(&mut self, now: std::time::Instant, window: std::time::Duration) {
        while let Some((ts, _)) = self.deque.front() {
            if now.duration_since(*ts) < window {
                break;
            }
            let (_, val) = self.deque.pop_front().unwrap();
            if let Some(c) = self.counts.get_mut(&val) {
                if *c <= 1 {
                    self.counts.remove(&val);
                } else {
                    *c -= 1;
                }
            }
        }
    }

    fn push(&mut self, ts: std::time::Instant, val: String) {
        *self.counts.entry(val.clone()).or_insert(0) += 1;
        self.deque.push_back((ts, val));
    }

    fn distinct_count(&self) -> usize {
        self.counts.len()
    }
}

// ─── RuleExecutor ─────────────────────────────────────────────────────────────

/// Evaluates compiled Sigma rules against events and constructs `AlertRecord`s on match.
/// Deduplication/suppression is handled at the storage layer via `suppress_or_create_alert`.
#[derive(Clone)]
pub struct RuleExecutor {
    suppression_window: Duration,
    /// Per-(rule, group_by_value) sliding-window buffer for aggregate conditions.
    /// Key: `"{rule_id}:{selection}:{group_by_val}"` → `AggEntry`
    ///
    /// Uses 64-shard `ShardedMap` (plain `Mutex<HashMap>` per shard) instead of
    /// DashMap.  4× more shards + cheaper Mutex (vs RwLock) reduces contention
    /// under rayon-parallel rule evaluation.
    agg_buffers: Arc<ShardedMap<AggEntry>>,
    /// Per-(rule, group_by_value) buffer for count_distinct.
    /// Key: `"{rule_id}:{selection}:{group_by_val}:distinct"` → `DistinctEntry`
    distinct_buffers: Arc<ShardedMap<DistinctEntry>>,
    /// Time window for aggregate conditions (default: 60 s).
    agg_window: std::time::Duration,
    /// Compiled plan cache keyed by rule_id.
    ///
    /// Avoids re-deserializing `rule.compiled_plan` (a `serde_json::Value`) on every
    /// call to `evaluate()`.  Entries are inserted on first miss and invalidated via
    /// `invalidate_rule()` / `invalidate_all()` when rules are mutated.
    plan_cache: Arc<DashMap<Uuid, Arc<CompiledSigmaPlan>>>,
    /// Per-(rule, selection) sliding-window buffers for `near` temporal correlation.
    /// Key: `"{rule_id}:{selection_name}"` → VecDeque<(Instant, entity_value)>
    temporal_buffers: Arc<DashMap<String, VecDeque<(std::time::Instant, String)>>>,
}

impl Default for RuleExecutor {
    fn default() -> Self {
        Self {
            suppression_window: Duration::minutes(5),
            agg_buffers: Arc::new(ShardedMap::new()),
            distinct_buffers: Arc::new(ShardedMap::new()),
            agg_window: std::time::Duration::from_secs(60),
            plan_cache: Arc::new(DashMap::new()),
            temporal_buffers: Arc::new(DashMap::new()),
        }
    }
}

impl RuleExecutor {
    pub fn with_suppression_window(window: Duration) -> Self {
        Self {
            suppression_window: window,
            agg_buffers: Arc::new(ShardedMap::new()),
            distinct_buffers: Arc::new(ShardedMap::new()),
            agg_window: std::time::Duration::from_secs(60),
            plan_cache: Arc::new(DashMap::new()),
            temporal_buffers: Arc::new(DashMap::new()),
        }
    }

    /// Remove a specific rule's compiled plan from the cache.
    ///
    /// Call this after any rule upsert or delete so the next evaluation picks up
    /// the updated plan.
    pub fn invalidate_rule(&self, rule_id: Uuid) {
        self.plan_cache.remove(&rule_id);
        let prefix = format!("{rule_id}:");
        self.temporal_buffers.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Flush the entire plan cache, temporal buffers, and aggregate state.
    pub fn invalidate_all(&self) {
        self.plan_cache.clear();
        self.temporal_buffers.clear();
        self.agg_buffers.clear();
        self.distinct_buffers.clear();
    }

    /// Override the aggregate sliding-window duration (default: 60 s).
    pub fn with_agg_window(mut self, window: std::time::Duration) -> Self {
        self.agg_window = window;
        self
    }

    /// Collect all field names referenced by a set of rules.
    ///
    /// Used on the ingest hot-path to build the [`EventContext`] field cache
    /// once per request (not per event) before the `par_iter` rule evaluation.
    /// Plans are deserialized and cached in `plan_cache` as a side effect.
    pub fn collect_fields_for_rules(&self, rules: &[DetectionRule]) -> HashSet<String> {
        let mut all_fields = HashSet::new();
        for rule in rules {
            let plan_opt = if let Some(cached) = self.plan_cache.get(&rule.rule_id) {
                Some(Arc::clone(cached.value()))
            } else {
                serde_json::from_value::<CompiledSigmaPlan>(rule.compiled_plan.clone())
                    .ok()
                    .map(|p| {
                        let p = Arc::new(p);
                        self.plan_cache.insert(rule.rule_id, Arc::clone(&p));
                        p
                    })
            };
            if let Some(plan) = plan_opt {
                all_fields.extend(collect_plan_field_names(&plan));
            }
        }
        all_fields
    }

    /// Evaluate a compiled rule against an event.
    /// Returns a `RuleTestResult` with match status and which selections fired.
    ///
    /// Prefer [`evaluate_with_context`] on the ingest hot-path — it reuses
    /// pre-computed field values and the lowercased payload string across all
    /// rules for the same event.
    pub fn evaluate(&self, rule: &DetectionRule, event: &EventEnvelope) -> RuleTestResult {
        // Build a minimal context with an empty field cache and no lookup store.
        // All field lookups fall through to live extraction — correct but not
        // cached.  Use evaluate_with_context on the ingest hot-path instead.
        let ctx = EventContext {
            event,
            raw_payload_lower: event.raw_payload.to_string().to_ascii_lowercase(),
            field_cache: HashMap::new(),
            lookup_store: None,
        };
        self.evaluate_with_context(rule, &ctx)
    }

    /// Evaluate a compiled rule using a pre-built [`EventContext`].
    ///
    /// On the ingest hot-path, build the context once per event via
    /// [`build_event_context`] and pass a shared reference into each rule in
    /// the `par_iter`.  Field values and the lowercased payload string are
    /// computed only once and reused across all rules.
    pub fn evaluate_with_context(
        &self,
        rule: &DetectionRule,
        ctx: &EventContext,
    ) -> RuleTestResult {
        // Fast path: return cached plan (avoids JSON clone + deserialization on every event).
        let plan: Arc<CompiledSigmaPlan> = if let Some(cached) = self.plan_cache.get(&rule.rule_id)
        {
            Arc::clone(cached.value())
        } else {
            match serde_json::from_value::<CompiledSigmaPlan>(rule.compiled_plan.clone()) {
                Ok(p) => {
                    let p = Arc::new(p);
                    self.plan_cache.insert(rule.rule_id, Arc::clone(&p));
                    p
                }
                Err(e) => {
                    return RuleTestResult {
                        matched: false,
                        reasoning: format!("compiled plan deserialization error: {e}"),
                    };
                }
            }
        };

        // Skip evaluation entirely if the event source doesn't match the rule's logsource
        if !logsource_matches_event(&plan.logsource, &ctx.event.source) {
            return RuleTestResult {
                matched: false,
                reasoning: "logsource mismatch — rule skipped for this event source".to_string(),
            };
        }

        let effective_agg_window = plan
            .timeframe_seconds
            .map(std::time::Duration::from_secs)
            .unwrap_or(self.agg_window);

        let mut matched_info: Vec<String> = Vec::new();
        let matched = eval_condition(
            &plan.condition,
            &plan.selections,
            ctx,
            rule.rule_id,
            self,
            effective_agg_window,
            &mut matched_info,
        );

        RuleTestResult {
            matched,
            reasoning: if matched {
                if matched_info.is_empty() {
                    "condition matched".to_string()
                } else {
                    format!("matched — {}", matched_info.join("; "))
                }
            } else {
                "no match".to_string()
            },
        }
    }

    /// Attempt to build an alert for a matched event.
    /// Returns `None` if the (rule, event) pair is within its suppression window.
    pub fn maybe_build_alert(
        &self,
        rule: &DetectionRule,
        event: &EventEnvelope,
        evidence_ref: String,
    ) -> Option<AlertRecord> {
        let source_str = serde_json::to_value(&event.source)
            .ok()
            .and_then(|v| v.as_str().map(ToString::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        let dedupe_key = format!("{}:{}", rule.rule_id, source_str);
        let now = Utc::now();

        // Extract MITRE ATT&CK context from the compiled plan's tags.
        let mitre_attack = rule
            .compiled_plan
            .get("tags")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .map(|tags| parse_mitre_from_tags(&tags))
            .unwrap_or_default();

        Some(AlertRecord {
            alert_id: Uuid::new_v4(),
            tenant_id: rule.tenant_id.clone(),
            rule_id: rule.rule_id,
            first_seen: now,
            last_seen: now,
            status: AlertStatus::Open,
            evidence_refs: vec![evidence_ref],
            routing_state: RoutingState {
                destinations: severity_destinations(&rule.severity),
                last_routed_at: None,
                dedupe_key,
                suppression_until: Some(now + self.suppression_window),
            },
            assignee: None,
            hit_count: 1,
            mitre_attack,
            resolution: None,
            close_note: None,
            agent_meta: None,
        })
    }
}

// ─── Condition Evaluation ─────────────────────────────────────────────────────

fn eval_condition(
    node: &ConditionNode,
    selections: &HashMap<String, SelectionGroup>,
    ctx: &EventContext,
    rule_id: Uuid,
    executor: &RuleExecutor,
    agg_window: std::time::Duration,
    matched_info: &mut Vec<String>,
) -> bool {
    match node {
        ConditionNode::Ref { name } => {
            if let Some(group) = selections.get(name) {
                let hit = eval_selection_group(group, ctx);
                if hit {
                    matched_info.push(format!("selection '{name}'"));
                }
                hit
            } else {
                false
            }
        }
        ConditionNode::And { left, right } => {
            eval_condition(
                left,
                selections,
                ctx,
                rule_id,
                executor,
                agg_window,
                matched_info,
            ) && eval_condition(
                right,
                selections,
                ctx,
                rule_id,
                executor,
                agg_window,
                matched_info,
            )
        }
        ConditionNode::Or { left, right } => {
            eval_condition(
                left,
                selections,
                ctx,
                rule_id,
                executor,
                agg_window,
                matched_info,
            ) || eval_condition(
                right,
                selections,
                ctx,
                rule_id,
                executor,
                agg_window,
                matched_info,
            )
        }
        ConditionNode::Not { inner } => !eval_condition(
            inner,
            selections,
            ctx,
            rule_id,
            executor,
            agg_window,
            &mut Vec::new(),
        ),
        ConditionNode::OneOf { pattern } => {
            let candidates = glob_selections(selections, pattern);
            candidates.iter().any(|name| {
                let hit = selections
                    .get(*name)
                    .map(|g| eval_selection_group(g, ctx))
                    .unwrap_or(false);
                if hit {
                    matched_info.push(format!("selection '{name}'"));
                }
                hit
            })
        }
        ConditionNode::AllOf { pattern } => {
            let candidates = glob_selections(selections, pattern);
            !candidates.is_empty()
                && candidates.iter().all(|name| {
                    selections
                        .get(*name)
                        .map(|g| eval_selection_group(g, ctx))
                        .unwrap_or(false)
                })
        }
        ConditionNode::Keywords { terms } => {
            // Use the pre-lowercased payload string from context — no re-serialisation.
            let hit = terms
                .iter()
                .any(|t| ctx.raw_payload_lower.contains(&t.to_ascii_lowercase()));
            if hit {
                matched_info.push("keyword match".to_string());
            }
            hit
        }
        ConditionNode::Aggregate { selection, agg } => eval_aggregate(
            selection,
            agg,
            selections,
            ctx,
            rule_id,
            executor,
            agg_window,
            matched_info,
        ),
        ConditionNode::Near {
            base,
            nearby,
            entity_field,
            within_seconds,
        } => eval_near(
            base,
            nearby,
            entity_field.as_deref(),
            *within_seconds,
            selections,
            ctx,
            rule_id,
            executor,
            matched_info,
        ),
    }
}

/// Temporal correlation: both `base` and `nearby` selections must have fired
/// from the same entity value within `within_seconds` (non-ordered / symmetric).
///
/// On every call the function:
///   1. Evicts stale entries from both per-selection buffers.
///   2. Records the current event if it matches a selection.
///   3. Returns `true` if both buffers contain at least one record for the
///      same entity value.
fn eval_near(
    base: &str,
    nearby: &str,
    entity_field: Option<&str>,
    within_seconds: u64,
    selections: &HashMap<String, SelectionGroup>,
    ctx: &EventContext,
    rule_id: Uuid,
    executor: &RuleExecutor,
    matched_info: &mut Vec<String>,
) -> bool {
    let window = std::time::Duration::from_secs(within_seconds);
    let now = std::time::Instant::now();

    let entity_val = entity_field
        .and_then(|f| {
            get_field_values(ctx, f)
                .into_iter()
                .next()
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "__global__".to_string());

    // Record match + evict stale entries for each selection.
    for sel_name in [base, nearby] {
        if let Some(group) = selections.get(sel_name) {
            let buf_key = format!("{rule_id}:{sel_name}");
            let mut entry = executor
                .temporal_buffers
                .entry(buf_key)
                .or_insert_with(VecDeque::new);
            // Evict stale entries from the front (entries are always appended in time order).
            while let Some((ts, _)) = entry.front() {
                if now.duration_since(*ts) >= window {
                    entry.pop_front();
                } else {
                    break;
                }
            }
            if eval_selection_group(group, ctx) {
                entry.push_back((now, entity_val.clone()));
            }
        }
    }

    // Fire only when BOTH selections have a non-stale record for this entity.
    let hit = [base, nearby].iter().all(|sel_name| {
        let buf_key = format!("{rule_id}:{sel_name}");
        executor
            .temporal_buffers
            .get(&buf_key)
            .map(|buf| buf.iter().any(|(_, e)| e == &entity_val))
            .unwrap_or(false)
    });

    if hit {
        let by_label = entity_field
            .map(|f| format!(" by {f}={entity_val}"))
            .unwrap_or_default();
        matched_info.push(format!(
            "near({base}, {nearby}){by_label} within {within_seconds}s"
        ));
    }
    hit
}

/// Evaluate a `selection | func(field) [by group] op threshold` aggregate condition.
///
/// Events are buffered per `(rule_id, selection, group_by_value)` in a sliding
/// time window.  Only events where the selection matches are counted.
fn eval_aggregate(
    selection: &str,
    agg: &AggregateCondition,
    selections: &HashMap<String, SelectionGroup>,
    ctx: &EventContext,
    rule_id: Uuid,
    executor: &RuleExecutor,
    agg_window: std::time::Duration,
    matched_info: &mut Vec<String>,
) -> bool {
    // Gate: only buffer events that match the selection filter
    let sel_hit = selections
        .get(selection)
        .map(|g| eval_selection_group(g, ctx))
        .unwrap_or(false);
    if !sel_hit {
        return false;
    }

    // Determine the group-by dimension value
    let group_val = agg
        .group_by
        .as_ref()
        .and_then(|field| {
            get_field_values(ctx, field)
                .into_iter()
                .next()
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "__all__".to_string());

    let buf_key = format!("{rule_id}:{selection}:{group_val}");
    let now = std::time::Instant::now();
    let window = agg_window;

    // count_distinct uses its own string buffer (field values, not numerics).
    if agg.function == AggregateFunction::CountDistinct {
        let field_val = agg
            .field
            .as_ref()
            .and_then(|f| {
                get_field_values(ctx, f)
                    .into_iter()
                    .next()
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();

        let distinct_key = format!("{buf_key}:distinct");
        // ShardedMap::with_entry locks exactly one of 64 shards for the duration
        // of the closure, then releases it — no two-phase DashMap dance needed.
        let distinct_count: usize = executor
            .distinct_buffers
            .with_entry(&distinct_key, |entry| {
                entry.evict_stale(now, window);
                entry.push(now, field_val);
                entry.distinct_count()
            });

        let result = distinct_count as f64;
        let hit = match agg.operator {
            AggCompareOp::Gt => result > agg.threshold,
            AggCompareOp::Gte => result >= agg.threshold,
            AggCompareOp::Lt => result < agg.threshold,
            AggCompareOp::Lte => result <= agg.threshold,
            AggCompareOp::Eq => (result - agg.threshold).abs() < 0.5,
        };
        if hit {
            let field_name = agg.field.as_deref().unwrap_or("");
            let group_label = agg
                .group_by
                .as_ref()
                .map(|f| format!(" by {f}={group_val}"))
                .unwrap_or_default();
            matched_info.push(format!(
                "count_distinct({field_name}){group_label} = {result:.0} (threshold {} {:.0})",
                match agg.operator {
                    AggCompareOp::Gt => ">",
                    AggCompareOp::Gte => ">=",
                    AggCompareOp::Lt => "<",
                    AggCompareOp::Lte => "<=",
                    AggCompareOp::Eq => "==",
                },
                agg.threshold
            ));
        }
        return hit;
    }

    // Numeric value contributed by this event (for Count, Sum, Min, Max, Avg)
    let contrib: f64 = match agg.function {
        AggregateFunction::Count | AggregateFunction::CountDistinct => 1.0,
        _ => agg
            .field
            .as_ref()
            .and_then(|f| {
                get_field_values(ctx, f)
                    .into_iter()
                    .next()
                    .map(|s| s.to_string())
            })
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0),
    };

    // ShardedMap::with_entry locks exactly one of 64 shards for the closure duration.
    let result = executor.agg_buffers.with_entry(&buf_key, |entry| {
        entry.evict_stale(now, window);
        entry.push(now, contrib);
        match agg.function {
            AggregateFunction::Count | AggregateFunction::CountDistinct => entry.count() as f64,
            AggregateFunction::Sum => entry.sum(),
            AggregateFunction::Min => entry.min(),
            AggregateFunction::Max => entry.max(),
            AggregateFunction::Avg => entry.avg(),
        }
    });

    // Compare against threshold
    let hit = match agg.operator {
        AggCompareOp::Gt => result > agg.threshold,
        AggCompareOp::Gte => result >= agg.threshold,
        AggCompareOp::Lt => result < agg.threshold,
        AggCompareOp::Lte => result <= agg.threshold,
        AggCompareOp::Eq => (result - agg.threshold).abs() < 0.5,
    };

    if hit {
        let func_label = match &agg.function {
            AggregateFunction::Count => "count()".to_string(),
            AggregateFunction::CountDistinct => {
                format!("count_distinct({})", agg.field.as_deref().unwrap_or(""))
            }
            AggregateFunction::Sum => format!("sum({})", agg.field.as_deref().unwrap_or("")),
            AggregateFunction::Min => format!("min({})", agg.field.as_deref().unwrap_or("")),
            AggregateFunction::Max => format!("max({})", agg.field.as_deref().unwrap_or("")),
            AggregateFunction::Avg => format!("avg({})", agg.field.as_deref().unwrap_or("")),
        };
        let op_label = match agg.operator {
            AggCompareOp::Gt => ">",
            AggCompareOp::Gte => ">=",
            AggCompareOp::Lt => "<",
            AggCompareOp::Lte => "<=",
            AggCompareOp::Eq => "==",
        };
        let group_label = agg
            .group_by
            .as_ref()
            .map(|f| format!(" by {f}={group_val}"))
            .unwrap_or_default();
        matched_info.push(format!(
            "{func_label}{group_label} = {result:.0} (threshold {op_label} {:.0})",
            agg.threshold
        ));
    }

    hit
}

/// All matchers in a group must pass (AND semantics between matchers).
fn eval_selection_group(group: &SelectionGroup, ctx: &EventContext) -> bool {
    group.matchers.iter().all(|m| eval_field_matcher(m, ctx))
}

/// Get field values from cache first, falling back to live extraction.
///
/// Returns a `Vec<String>` — either borrowed-as-clone from the cache or freshly
/// extracted.  The cache hit path avoids re-parsing JSON that was already
/// processed once before the `par_iter`.
fn get_field_values(ctx: &EventContext, field: &str) -> Vec<String> {
    if let Some(cached) = ctx.field_cache.get(field) {
        cached.clone()
    } else {
        extract_field_values_raw(ctx.event, field)
    }
}

fn eval_field_matcher(matcher: &FieldMatcher, ctx: &EventContext) -> bool {
    match &matcher.field {
        // Keywords matcher — reuse the pre-lowercased payload string from context.
        None => {
            let check = |v: &str| ctx.raw_payload_lower.contains(&v.to_ascii_lowercase());
            if matcher.match_all {
                matcher.values.iter().all(|v| check(v))
            } else {
                matcher.values.iter().any(|v| check(v))
            }
        }
        Some(field) => {
            // |exists modifier: check field presence, ignore values entirely.
            if matcher.modifiers.contains(&FieldModifier::Exists) {
                let field_exists = !get_field_values(ctx, field).is_empty();
                // The YAML value is `true` or `false`; "true" → field must exist.
                let want_exists = matcher
                    .values
                    .iter()
                    .any(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "no" | "0"));
                return field_exists == want_exists;
            }

            // |fieldref modifier: compare this field's value against another field's
            // runtime value.  matcher.values contains the reference field name(s).
            // Semantics: any source value equals any reference value (case-insensitive).
            if matcher.modifiers.contains(&FieldModifier::FieldRef) {
                let src_values = get_field_values(ctx, field);
                if src_values.is_empty() {
                    return false;
                }
                return matcher.values.iter().any(|ref_field| {
                    let ref_values = get_field_values(ctx, ref_field);
                    src_values
                        .iter()
                        .any(|sv| ref_values.iter().any(|rv| sv.eq_ignore_ascii_case(rv)))
                });
            }

            // |lookup modifier: check if any field value is a member of a named lookup table.
            // matcher.values contains lookup table name(s) (OR semantics — any table matches).
            // With |all: every table name must contain at least one of the field values.
            if matcher.modifiers.contains(&FieldModifier::Lookup) {
                let field_vals = get_field_values(ctx, field);
                if field_vals.is_empty() {
                    return false;
                }
                if let Some(store) = &ctx.lookup_store {
                    return if matcher.match_all {
                        // Every listed table must contain at least one field value
                        matcher
                            .values
                            .iter()
                            .all(|table| field_vals.iter().any(|fv| store.contains(table, fv)))
                    } else {
                        // Any field value found in any listed table
                        field_vals
                            .iter()
                            .any(|fv| matcher.values.iter().any(|table| store.contains(table, fv)))
                    };
                }
                // No lookup store wired — treat as no-match
                return false;
            }

            let field_values = get_field_values(ctx, field);
            if field_values.is_empty() {
                // Field absent → only matches an explicit null check
                return matcher.values.iter().any(|v| v == "__null__");
            }
            if matcher.match_all {
                // Every pattern must match at least one field value
                matcher.values.iter().all(|pattern| {
                    field_values
                        .iter()
                        .any(|fv| apply_modifiers(fv, pattern, &matcher.modifiers))
                })
            } else {
                // Any pattern matching any field value
                field_values.iter().any(|fv| {
                    matcher
                        .values
                        .iter()
                        .any(|pattern| apply_modifiers(fv, pattern, &matcher.modifiers))
                })
            }
        }
    }
}

/// Case-insensitive glob match supporting `*` (any sequence) and `?` (any single char).
///
/// Uses an iterative DP approach — O(m × n) time — so adversarial `***` patterns
/// don't cause exponential blowup.
///
/// Per the Sigma spec, plain field patterns (no `|contains`/`|startswith`/`|endswith`
/// modifier) treat `*` and `?` as glob wildcards, not literals.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<u8> = pattern.to_ascii_lowercase().into_bytes();
    let t: Vec<u8> = text.to_ascii_lowercase().into_bytes();
    let (pm, tn) = (p.len(), t.len());

    // dp[i][j] = pattern[..i] matches text[..j]
    let mut dp = vec![vec![false; tn + 1]; pm + 1];
    dp[0][0] = true;

    // Leading `*`s match the empty prefix of text.
    for i in 1..=pm {
        if p[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        } else {
            break;
        }
    }

    for i in 1..=pm {
        for j in 1..=tn {
            if p[i - 1] == b'*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1]; // match 0 or 1 more char
            } else if p[i - 1] == b'?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[pm][tn]
}

#[inline]
fn is_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

/// Apply the modifier chain to one (field_value, pattern) pair.
fn apply_modifiers(field_val: &str, pattern: &str, modifiers: &[FieldModifier]) -> bool {
    if modifiers.is_empty() {
        // Sigma spec: `*` / `?` in a bare (no-modifier) pattern are glob wildcards.
        return if is_glob(pattern) {
            glob_match(pattern, field_val)
        } else {
            field_val.eq_ignore_ascii_case(pattern)
        };
    }

    let has_windash = modifiers.contains(&FieldModifier::Windash);
    let has_wide = modifiers.contains(&FieldModifier::Wide);
    let has_base64 = modifiers.contains(&FieldModifier::Base64);
    let has_b64offset = modifiers.contains(&FieldModifier::Base64Offset);

    // Normalise field value
    let fv = if has_windash {
        normalize_windash(&field_val.to_ascii_lowercase())
    } else {
        field_val.to_ascii_lowercase()
    };

    // Normalise pattern base
    let pat_base = if has_windash {
        normalize_windash(&pattern.to_ascii_lowercase())
    } else {
        pattern.to_ascii_lowercase()
    };

    // Build the candidate pattern(s) to match against.
    //
    //  |base64            → one candidate: base64(UTF-8 bytes of pattern)
    //  |wide|base64       → one candidate: base64(UTF-16LE bytes of pattern)
    //  |base64offset      → three candidates: base64 at byte-offsets 0, 1, 2
    //                       (UTF-8 bytes unless |wide is also set)
    //  |wide              → for field-value comparison, interleave nulls so the
    //                       pattern represents UTF-16LE text inline
    //  (none of the above) → single candidate = pat_base
    let candidates: Vec<String> = if has_b64offset {
        let raw_bytes: Vec<u8> = if has_wide {
            pat_base
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect()
        } else {
            pat_base.as_bytes().to_vec()
        };
        base64_offset_variants(&raw_bytes).to_vec()
    } else if has_base64 {
        let encoded = if has_wide {
            base64_encode_utf16le(&pat_base)
        } else {
            base64_encode(pat_base.as_bytes())
        };
        vec![encoded]
    } else if has_wide {
        // UTF-16LE interleaved: "ab" → "a\x00b\x00"
        let wide: String = pat_base.chars().flat_map(|c| [c, '\x00']).collect();
        vec![wide]
    } else {
        vec![pat_base]
    };

    // base64 output is mixed-case; since `fv` is already lowercased we must
    // lowercase the candidates too so contains/startswith/endswith work.
    let candidates: Vec<String> = if has_base64 || has_b64offset {
        candidates
            .into_iter()
            .map(|c| c.to_ascii_lowercase())
            .collect()
    } else {
        candidates
    };

    // Primary matching modifier
    for modifier in modifiers {
        match modifier {
            FieldModifier::Contains => return candidates.iter().any(|p| fv.contains(p.as_str())),
            FieldModifier::StartsWith => {
                return candidates.iter().any(|p| fv.starts_with(p.as_str()))
            }
            FieldModifier::EndsWith => return candidates.iter().any(|p| fv.ends_with(p.as_str())),
            FieldModifier::Re => {
                return compiled_regex(pattern)
                    .map(|re| re.is_match(field_val))
                    .unwrap_or(false)
            }
            FieldModifier::Cidr => return cidr_contains(field_val, pattern),
            FieldModifier::Lt => {
                let (a, b) = parse_pair(field_val, pattern);
                return a < b;
            }
            FieldModifier::Lte => {
                let (a, b) = parse_pair(field_val, pattern);
                return a <= b;
            }
            FieldModifier::Gt => {
                let (a, b) = parse_pair(field_val, pattern);
                return a > b;
            }
            FieldModifier::Gte => {
                let (a, b) = parse_pair(field_val, pattern);
                return a >= b;
            }
            // Pre-processing / structural modifiers — handled elsewhere
            FieldModifier::Base64
            | FieldModifier::Base64Offset
            | FieldModifier::Wide
            | FieldModifier::Windash
            | FieldModifier::Exists
            | FieldModifier::FieldRef
            | FieldModifier::Lookup => continue,
        }
    }

    // Fallback: contains (handles |base64 / |wide / |windash with no explicit match op)
    candidates.iter().any(|p| fv.contains(p.as_str()))
}

// ─── Field Extraction ─────────────────────────────────────────────────────────

/// Sigma field name → OCSF dot-path mapping.
///
/// Covers Windows Sysmon, Windows Security/Event Log, network, file, registry,
/// DNS, and generic host fields that appear in the majority of public Sigma rules.
/// Lookup is case-insensitive; the OCSF paths use dot notation resolved by
/// `json_lookup`.
static SIGMA_TO_OCSF: &[(&str, &str)] = &[
    // ── Windows process (Sysmon EventID 1, 10, …) ──────────────────────────
    ("CommandLine", "process.cmd_line"),
    ("Image", "process.file.path"),
    ("OriginalFileName", "process.file.name"),
    ("CurrentDirectory", "process.file.parent_folder"),
    ("ParentCommandLine", "process.parent_process.cmd_line"),
    ("ParentImage", "process.parent_process.file.path"),
    ("ProcessId", "process.pid"),
    ("ParentProcessId", "process.parent_process.pid"),
    ("ProcessGuid", "process.uid"),
    ("ParentProcessGuid", "process.parent_process.uid"),
    // ── Windows hashes ───────────────────────────────────────────────────────
    ("Hashes", "process.file.hashes"),
    ("MD5", "process.file.hashes.md5"),
    ("SHA1", "process.file.hashes.sha1"),
    ("SHA256", "process.file.hashes.sha256"),
    ("Imphash", "process.file.hashes.imphash"),
    // ── Windows user / session ───────────────────────────────────────────────
    ("User", "actor.user.name"),
    ("SubjectUserName", "actor.user.name"),
    ("SubjectDomainName", "actor.user.domain"),
    ("SubjectLogonId", "actor.session.uid"),
    ("TargetUserName", "dst_endpoint.user.name"),
    ("TargetDomainName", "dst_endpoint.domain"),
    ("TargetLogonId", "dst_endpoint.session.uid"),
    ("LogonType", "auth.logon_type"),
    ("LogonGuid", "actor.session.uid"),
    // ── Windows event metadata ────────────────────────────────────────────────
    ("EventID", "metadata.uid"),
    ("Channel", "metadata.log_name"),
    ("Provider_Name", "metadata.product.name"),
    ("ComputerName", "device.hostname"),
    ("MachineName", "device.hostname"),
    ("WorkstationName", "src_endpoint.hostname"),
    ("IpAddress", "src_endpoint.ip"),
    ("IpPort", "src_endpoint.port"),
    // ── Network connection (Sysmon EventID 3 / firewall) ─────────────────────
    ("src_ip", "src_endpoint.ip"),
    ("dst_ip", "dst_endpoint.ip"),
    ("src_port", "src_endpoint.port"),
    ("dst_port", "dst_endpoint.port"),
    ("SourceIp", "src_endpoint.ip"),
    ("DestinationIp", "dst_endpoint.ip"),
    ("SourcePort", "src_endpoint.port"),
    ("DestinationPort", "dst_endpoint.port"),
    ("SourceHostname", "src_endpoint.hostname"),
    ("DestinationHostname", "dst_endpoint.hostname"),
    ("Protocol", "connection_info.protocol_name"),
    ("Initiated", "connection_info.direction"),
    // ── File (Sysmon EventID 11 / EDR) ───────────────────────────────────────
    ("TargetFilename", "file.path"),
    ("FileName", "file.name"),
    ("FileSize", "file.size"),
    // ── Registry (Sysmon EventID 12-14) ──────────────────────────────────────
    ("TargetObject", "registry.key"),
    ("Details", "registry.value"),
    ("NewName", "registry.new_key"),
    ("EventType", "metadata.event_type"),
    // ── DNS (Sysmon EventID 22) ───────────────────────────────────────────────
    ("QueryName", "dns_query.hostname"),
    ("QueryResults", "dns_answer.rdata"),
    ("query", "dns_query.hostname"),
    // ── Pipe / named pipe (Sysmon EventID 17-18) ─────────────────────────────
    ("PipeName", "process.file.path"),
    // ── WMI (Sysmon EventID 19-21) ────────────────────────────────────────────
    ("EventNamespace", "metadata.log_name"),
    ("Name", "metadata.event_type"),
    // ── Generic host ─────────────────────────────────────────────────────────
    ("Hostname", "device.hostname"),
    ("ProcessName", "process.file.path"),
    ("IntegrityLevel", "process.integrity_info"),
    // ── winlog.* dotted prefix aliases ───────────────────────────────────────
    ("winlog.event_id", "metadata.uid"),
    ("winlog.computer_name", "device.hostname"),
    ("winlog.task", "metadata.log_name"),
];

/// Extract all string representations of `field` from the event.
///
/// Lookup order:
///   1. OCSF path from the Sigma→OCSF taxonomy map (if the field has a mapping)
///   2. Raw field name in `raw_payload` (case-insensitive, dot-path)
///   3. Raw field name in `ocsf_record`
fn extract_field_values_raw(event: &EventEnvelope, field: &str) -> Vec<String> {
    let mut out = Vec::new();

    // 1. Try the taxonomy-mapped OCSF path first
    if let Some(&ocsf_path) = SIGMA_TO_OCSF
        .iter()
        .find(|(sigma, _)| sigma.eq_ignore_ascii_case(field))
        .map(|(_, ocsf)| ocsf)
    {
        collect_json_field(&event.ocsf_record, ocsf_path, &mut out);
    }

    // 2 & 3. Fall back to raw field name in both payloads
    if out.is_empty() {
        collect_json_field(&event.raw_payload, field, &mut out);
        if out.is_empty() {
            collect_json_field(&event.ocsf_record, field, &mut out);
        }
    }

    out
}

fn collect_json_field(root: &Value, field: &str, out: &mut Vec<String>) {
    if let Some(v) = json_lookup(root, field) {
        flatten_json_strings(v, out);
    }
}

/// Lookup a field in a JSON value.
/// Supports: exact key, case-insensitive key, dot-notation paths.
fn json_lookup<'a>(value: &'a Value, field: &str) -> Option<&'a Value> {
    if let Some(v) = value.get(field) {
        return Some(v);
    }
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if k.eq_ignore_ascii_case(field) {
                return Some(v);
            }
        }
    }
    if let Some(dot) = field.find('.') {
        let head = &field[..dot];
        let tail = &field[dot + 1..];
        if let Some(sub) = json_lookup(value, head) {
            return json_lookup(sub, tail);
        }
    }
    None
}

fn flatten_json_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Null => out.push("__null__".to_string()),
        Value::Array(arr) => arr.iter().for_each(|v| flatten_json_strings(v, out)),
        Value::Object(_) => out.push(value.to_string()),
    }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/// Match selection names against a Sigma glob pattern.
/// Supports trailing `*` wildcard and the special keyword `"them"` (= all).
fn glob_selections<'a>(
    selections: &'a HashMap<String, SelectionGroup>,
    pattern: &str,
) -> Vec<&'a str> {
    selections
        .keys()
        .filter(|name| {
            if pattern.eq_ignore_ascii_case("them") {
                true
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                name.starts_with(prefix)
            } else {
                name.as_str() == pattern
            }
        })
        .map(|s| s.as_str())
        .collect()
}

/// Normalize Windows CLI argument dash variants to ASCII `-`.
/// Handles: `/`, `–` (U+2013), `—` (U+2014), `−` (U+2212).
fn normalize_windash(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\u{2013}' | '\u{2014}' | '\u{2212}' => '-',
            other => other,
        })
        .collect()
}

/// Base64-encode a string as UTF-16LE for `|wide|base64`.
fn base64_encode_utf16le(s: &str) -> String {
    let bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    base64_encode(&bytes)
}

/// Generate the three base64 offset variants for `|base64offset`.
///
/// When a known string `s` appears inside a larger base64-encoded blob the
/// observable base64 fragment depends on where `s` starts (byte offset mod 3).
/// Three prefixes ([], [0x00], [0x00,0x00]) shift the input so all three
/// alignments are covered; we skip the characters that encode only the null
/// prefix and strip trailing padding.
fn base64_offset_variants(bytes: &[u8]) -> [String; 3] {
    let variant = |prefix_len: usize| {
        let mut buf = vec![0u8; prefix_len];
        buf.extend_from_slice(bytes);
        let skip = (prefix_len * 4 + 2) / 3; // ceil(prefix_len * 4 / 3)
        let encoded = base64_encode(&buf);
        encoded[skip..].trim_end_matches('=').to_string()
    };
    [variant(0), variant(1), variant(2)]
}

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(BASE64_ALPHABET[b0 >> 2] as char);
        out.push(BASE64_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// IPv4 CIDR containment check — no external dependencies required.
fn cidr_contains(ip_str: &str, cidr: &str) -> bool {
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };
    let prefix_len: u32 = match prefix_str.trim().parse() {
        Ok(n) if n <= 32 => n,
        _ => return false,
    };
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    match (parse_ipv4(ip_str.trim()), parse_ipv4(net_str.trim())) {
        (Some(target), Some(network)) => (target & mask) == (network & mask),
        _ => false,
    }
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let octets: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    Some(
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32),
    )
}

fn parse_pair(a: &str, b: &str) -> (f64, f64) {
    (
        a.parse::<f64>().unwrap_or(f64::NAN),
        b.parse::<f64>().unwrap_or(f64::NAN),
    )
}

/// Route alerts to destinations based on rule severity.
fn severity_destinations(severity: &Severity) -> Vec<String> {
    match severity {
        Severity::Critical => vec!["teams".to_string(), "pagerduty".to_string()],
        Severity::High => vec!["teams".to_string()],
        Severity::Medium => vec!["teams".to_string()],
        Severity::Low => vec![],
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cyberbox_models::{DetectionMode, EnrichmentMetadata, EventSource};
    use serde_json::json;

    fn make_rule(sigma_source: &str) -> DetectionRule {
        let plan = SigmaCompiler.compile(sigma_source).expect("compile failed");
        DetectionRule {
            rule_id: Uuid::new_v4(),
            tenant_id: "tenant-a".to_string(),
            sigma_source: sigma_source.to_string(),
            compiled_plan: plan,
            schedule_or_stream: DetectionMode::Stream,
            schedule: None,
            severity: Severity::High,
            enabled: true,
            scheduler_health: None,
            threshold_count: None,
            threshold_group_by: None,
            suppression_window_secs: None,
        }
    }

    fn make_event(payload: Value) -> EventEnvelope {
        EventEnvelope {
            event_id: Uuid::new_v4(),
            tenant_id: "tenant-a".to_string(),
            source: EventSource::WindowsSysmon,
            event_time: Utc::now(),
            ingest_time: Utc::now(),
            raw_payload: payload,
            ocsf_record: json!({}),
            enrichment: EnrichmentMetadata::default(),
            integrity_hash: Uuid::new_v4().to_string(),
        }
    }

    // ── Compiler ──────────────────────────────────────────────────────────────

    #[test]
    fn compiler_extracts_metadata() {
        let plan: CompiledSigmaPlan = serde_json::from_value(
            SigmaCompiler
                .compile(
                    "title: Test Rule\n\
                     description: detects stuff\n\
                     logsource:\n  product: windows\n  category: process_creation\n\
                     tags:\n  - attack.t1059.001\n\
                     detection:\n  selection:\n    CommandLine|contains:\n      - powershell\n  \
                     condition: selection",
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(plan.title, "Test Rule");
        assert_eq!(plan.logsource.product.as_deref(), Some("windows"));
        assert_eq!(plan.tags, vec!["attack.t1059.001"]);
    }

    #[test]
    fn compiler_rejects_empty() {
        assert!(SigmaCompiler.compile("   ").is_err());
    }

    #[test]
    fn compiler_rejects_missing_detection() {
        assert!(SigmaCompiler.compile("title: foo\n").is_err());
    }

    #[test]
    fn compiler_rejects_missing_condition() {
        assert!(SigmaCompiler
            .compile("title: foo\ndetection:\n  sel:\n    - term\n")
            .is_err());
    }

    // ── Condition parser ──────────────────────────────────────────────────────

    #[test]
    fn condition_simple_ref() {
        let node = parse_condition_expr("selection").unwrap();
        assert!(matches!(node, ConditionNode::Ref { name } if name == "selection"));
    }

    #[test]
    fn condition_and_not() {
        assert!(matches!(
            parse_condition_expr("selection and not filter").unwrap(),
            ConditionNode::And { .. }
        ));
    }

    #[test]
    fn condition_one_of_glob() {
        let node = parse_condition_expr("1 of sel*").unwrap();
        assert!(matches!(node, ConditionNode::OneOf { pattern } if pattern == "sel*"));
    }

    #[test]
    fn condition_all_of_them() {
        let node = parse_condition_expr("all of them").unwrap();
        assert!(matches!(node, ConditionNode::AllOf { pattern } if pattern == "them"));
    }

    #[test]
    fn condition_nested_parens() {
        assert!(matches!(
            parse_condition_expr("(sel1 or sel2) and not filter").unwrap(),
            ConditionNode::And { .. }
        ));
    }

    // ── Executor / evaluation ─────────────────────────────────────────────────

    #[test]
    fn eval_contains_matches() {
        let rule = make_rule(
            "title: PS\nlogsource:\n  product: windows\n\
             detection:\n  selection:\n    CommandLine|contains:\n      - powershell\n  \
             condition: selection",
        );
        let ev = make_event(json!({ "CommandLine": "C:\\Windows\\powershell.exe -enc AAAA" }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev).matched);
    }

    #[test]
    fn eval_contains_no_match() {
        let rule = make_rule(
            "title: PS\nlogsource:\n  product: windows\n\
             detection:\n  selection:\n    CommandLine|contains:\n      - powershell\n  \
             condition: selection",
        );
        let ev = make_event(json!({ "CommandLine": "notepad.exe readme.txt" }));
        assert!(!RuleExecutor::default().evaluate(&rule, &ev).matched);
    }

    #[test]
    fn eval_and_not_filter() {
        let rule = make_rule(
            "title: PS enc\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - powershell\n  filter:\n    CommandLine|contains:\n      - legitimate.ps1\n  condition: selection and not filter",
        );
        let ev_match = make_event(json!({ "CommandLine": "powershell -enc AAAA" }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev_match).matched);

        let ev_filtered = make_event(json!({ "CommandLine": "powershell -File legitimate.ps1" }));
        assert!(
            !RuleExecutor::default()
                .evaluate(&rule, &ev_filtered)
                .matched
        );
    }

    #[test]
    fn eval_all_modifier() {
        let rule = make_rule(
            "title: Multi\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - bypass\n      - hidden\n  condition: selection",
        );
        let ev_both = make_event(json!({ "CommandLine": "powershell -bypass -hidden" }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev_both).matched);

        let ev_one = make_event(json!({ "CommandLine": "powershell -bypass" }));
        assert!(!RuleExecutor::default().evaluate(&rule, &ev_one).matched);
    }

    #[test]
    fn eval_case_insensitive_field_lookup() {
        let rule = make_rule(
            "title: CI\nlogsource:\n  product: windows\n\
             detection:\n  selection:\n    commandline|contains:\n      - powershell\n  \
             condition: selection",
        );
        // Field key "CommandLine" in event, rule uses lowercase "commandline"
        let ev = make_event(json!({ "CommandLine": "powershell -enc X" }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev).matched);
    }

    #[test]
    fn eval_cidr_modifier() {
        let rule = make_rule(
            "title: Private\nlogsource:\n  category: network\n\
             detection:\n  selection:\n    dst_ip|cidr:\n      - 10.0.0.0/8\n  \
             condition: selection",
        );
        assert!(
            RuleExecutor::default()
                .evaluate(&rule, &make_event(json!({ "dst_ip": "10.20.30.40" })))
                .matched
        );
        assert!(
            !RuleExecutor::default()
                .evaluate(&rule, &make_event(json!({ "dst_ip": "192.168.1.1" })))
                .matched
        );
    }

    #[test]
    fn eval_windash_normalizes_slash() {
        let rule = make_rule(
            "title: WD\nlogsource:\n  product: windows\n\
             detection:\n  selection:\n    CommandLine|windash|contains:\n      - -enc\n  \
             condition: selection",
        );
        // /enc should match after windash normalization
        let ev = make_event(json!({ "CommandLine": "powershell /enc AAAA" }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev).matched);
    }

    #[test]
    fn eval_one_of_condition() {
        let rule = make_rule(
            "title: 1of\nlogsource:\n  product: windows\ndetection:\n  sel_a:\n    ProcessName|contains:\n      - malware.exe\n  sel_b:\n    CommandLine|contains:\n      - -shellcode\n  condition: 1 of sel*",
        );
        assert!(
            RuleExecutor::default()
                .evaluate(
                    &rule,
                    &make_event(json!({ "ProcessName": "C:\\malware.exe" }))
                )
                .matched
        );
        assert!(
            RuleExecutor::default()
                .evaluate(
                    &rule,
                    &make_event(json!({ "CommandLine": "inject -shellcode 0xDEAD" }))
                )
                .matched
        );
        assert!(
            !RuleExecutor::default()
                .evaluate(&rule, &make_event(json!({ "ProcessName": "notepad.exe" })))
                .matched
        );
    }

    #[test]
    fn eval_keywords_selection() {
        let rule = make_rule(
            "title: KW\nlogsource:\n  product: windows\n\
             detection:\n  keywords:\n    - mimikatz\n    - sekurlsa\n  condition: keywords",
        );
        assert!(
            RuleExecutor::default()
                .evaluate(
                    &rule,
                    &make_event(json!({ "Message": "process mimikatz.exe started" }))
                )
                .matched
        );
        assert!(
            !RuleExecutor::default()
                .evaluate(&rule, &make_event(json!({ "Message": "notepad started" })))
                .matched
        );
    }

    #[test]
    fn dedup_same_source_produces_consistent_dedupe_key() {
        // Suppression is now storage-level; maybe_build_alert always returns Some.
        // Two calls from the same source should produce the same dedupe_key so
        // suppress_or_create_alert can merge them into a single alert.
        let executor = RuleExecutor::default();
        let rule = make_rule(
            "title: Dedup\nlogsource:\n  product: windows\n\
             detection:\n  sel:\n    cmd|contains:\n      - hack\n  condition: sel",
        );
        let ev = make_event(json!({ "cmd": "hack the planet" }));
        let a1 = executor
            .maybe_build_alert(&rule, &ev, "evt:1".to_string())
            .expect("first call should return Some");
        let a2 = executor
            .maybe_build_alert(&rule, &ev, "evt:2".to_string())
            .expect("second call should also return Some — storage handles dedup");
        assert_eq!(
            a1.routing_state.dedupe_key, a2.routing_state.dedupe_key,
            "both alerts must share the same dedupe_key for storage-level suppression to work"
        );
    }

    #[test]
    fn cidr_edge_cases() {
        assert!(cidr_contains("192.168.1.1", "192.168.0.0/16"));
        assert!(cidr_contains("10.0.0.1", "10.0.0.0/8"));
        assert!(!cidr_contains("172.16.0.1", "10.0.0.0/8"));
        assert!(cidr_contains("0.0.0.0", "0.0.0.0/0"));
        assert!(cidr_contains("255.255.255.255", "255.255.255.255/32"));
    }

    #[test]
    fn dot_path_field_lookup() {
        let rule = make_rule(
            "title: Path\nlogsource:\n  category: process_creation\n\
             detection:\n  selection:\n    process.name|contains:\n      - malware\n  \
             condition: selection",
        );
        let ev = make_event(json!({ "process": { "name": "malware.exe" } }));
        assert!(RuleExecutor::default().evaluate(&rule, &ev).matched);
    }

    #[test]
    fn severity_routing_critical_includes_pagerduty() {
        let dests = severity_destinations(&Severity::Critical);
        assert!(dests.contains(&"pagerduty".to_string()));
    }

    #[test]
    fn severity_routing_low_is_empty() {
        assert!(severity_destinations(&Severity::Low).is_empty());
    }

    // ── Aggregation ───────────────────────────────────────────────────────────

    fn make_agg_rule(sigma_source: &str) -> DetectionRule {
        make_rule(sigma_source)
    }

    #[test]
    fn agg_count_no_group_by_triggers_after_threshold() {
        // Brute-force login: > 5 failed logins within the window
        let rule = make_agg_rule(
            "title: BruteForce\nlogsource:\n  category: authentication\n\
             detection:\n  selection:\n    event_type: failed_login\n  \
             condition: selection | count() > 5",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        // First 5 events must NOT trigger (count not yet > 5)
        let ev = make_event(json!({ "event_type": "failed_login" }));
        for _ in 0..5 {
            assert!(
                !executor.evaluate(&rule, &ev).matched,
                "should not match before threshold"
            );
        }
        // 6th event crosses count > 5
        assert!(
            executor.evaluate(&rule, &ev).matched,
            "should match at count == 6"
        );
    }

    #[test]
    fn agg_count_by_src_ip_isolates_groups() {
        // Port-scan: > 3 events per src_ip within the window
        let rule = make_agg_rule(
            "title: PortScan\nlogsource:\n  category: network\n\
             detection:\n  selection:\n    event_type: connection\n  \
             condition: selection | count() by src_ip > 3",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        let ev_a = make_event(json!({ "event_type": "connection", "src_ip": "1.2.3.4" }));
        let ev_b = make_event(json!({ "event_type": "connection", "src_ip": "9.9.9.9" }));

        // Drain 3 events for src_ip A — should not trigger yet
        for _ in 0..3 {
            assert!(!executor.evaluate(&rule, &ev_a).matched);
        }
        // 3 events for src_ip B also don't trigger
        for _ in 0..3 {
            assert!(!executor.evaluate(&rule, &ev_b).matched);
        }
        // 4th for A triggers
        assert!(executor.evaluate(&rule, &ev_a).matched);
        // 3rd for B still not triggered (count is 3, not > 3)
        // (note: we already sent 3 above, so 4th also triggers)
        assert!(executor.evaluate(&rule, &ev_b).matched);
    }

    #[test]
    fn agg_non_matching_selection_never_counts() {
        let rule = make_agg_rule(
            "title: LoginCount\nlogsource:\n  category: auth\n\
             detection:\n  selection:\n    event_type: failed_login\n  \
             condition: selection | count() > 2",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        // Events that don't match the selection should never count
        let ev_ok = make_event(json!({ "event_type": "success_login" }));
        for _ in 0..100 {
            assert!(
                !executor.evaluate(&rule, &ev_ok).matched,
                "non-matching event must not count"
            );
        }
    }

    #[test]
    fn agg_sum_detects_data_exfiltration() {
        // Data exfil: sum(bytes_sent) > 10_000 within window
        let rule = make_agg_rule(
            "title: Exfil\nlogsource:\n  category: network\n\
             detection:\n  selection:\n    direction: outbound\n  \
             condition: selection | sum(bytes_sent) > 10000",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        // Send 5 events of 2000 bytes each = 10000, NOT > 10000
        for _ in 0..5 {
            let ev = make_event(json!({ "direction": "outbound", "bytes_sent": 2000 }));
            assert!(!executor.evaluate(&rule, &ev).matched);
        }
        // 6th event: sum = 12000 > 10000 → alert
        let ev = make_event(json!({ "direction": "outbound", "bytes_sent": 2000 }));
        assert!(executor.evaluate(&rule, &ev).matched);
    }

    #[test]
    fn agg_condition_parser_roundtrip() {
        let node = parse_condition_expr("brute | count() by src_ip > 10").unwrap();
        match node {
            ConditionNode::Aggregate { selection, agg } => {
                assert_eq!(selection, "brute");
                assert_eq!(agg.function, AggregateFunction::Count);
                assert_eq!(agg.group_by.as_deref(), Some("src_ip"));
                assert!(matches!(agg.operator, AggCompareOp::Gt));
                assert!((agg.threshold - 10.0).abs() < 0.01);
            }
            other => panic!("expected Aggregate, got {other:?}"),
        }
    }

    #[test]
    fn agg_condition_parser_sum_no_group() {
        let node = parse_condition_expr("sel | sum(bytes) > 500").unwrap();
        match node {
            ConditionNode::Aggregate { selection, agg } => {
                assert_eq!(selection, "sel");
                assert_eq!(agg.function, AggregateFunction::Sum);
                assert_eq!(agg.field.as_deref(), Some("bytes"));
                assert!(agg.group_by.is_none());
                assert!(matches!(agg.operator, AggCompareOp::Gt));
            }
            other => panic!("expected Aggregate, got {other:?}"),
        }
    }

    #[test]
    fn agg_condition_and_with_filter() {
        // Combining aggregate with a NOT filter: `(sel | count() > 5) and not whitelist`
        let node = parse_condition_expr("(sel | count() > 5) and not whitelist").unwrap();
        assert!(matches!(node, ConditionNode::And { .. }));
    }

    #[test]
    fn agg_gte_operator() {
        let node = parse_condition_expr("sel | count() >= 3").unwrap();
        match node {
            ConditionNode::Aggregate { agg, .. } => {
                assert!(matches!(agg.operator, AggCompareOp::Gte));
                assert!((agg.threshold - 3.0).abs() < 0.01);
            }
            _ => panic!("expected Aggregate"),
        }
    }

    // ── count_distinct ────────────────────────────────────────────────────────

    #[test]
    fn count_distinct_parser_roundtrip() {
        let node =
            parse_condition_expr("sel | count_distinct(TargetUserName) by IpAddress > 5").unwrap();
        match node {
            ConditionNode::Aggregate { selection, agg } => {
                assert_eq!(selection, "sel");
                assert_eq!(agg.function, AggregateFunction::CountDistinct);
                assert_eq!(agg.field.as_deref(), Some("TargetUserName"));
                assert_eq!(agg.group_by.as_deref(), Some("IpAddress"));
                assert!(matches!(agg.operator, AggCompareOp::Gt));
                assert!((agg.threshold - 5.0).abs() < 0.01);
            }
            other => panic!("expected Aggregate, got {other:?}"),
        }
    }

    #[test]
    fn count_distinct_detects_lateral_movement() {
        // Lateral movement: one src_ip touches > 3 distinct TargetHosts within window.
        let rule = make_agg_rule(
            "title: LatMove\nlogsource:\n  category: network\n\
             detection:\n  selection:\n    event_type: smb_connect\n  \
             condition: selection | count_distinct(TargetHost) by src_ip > 3",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        let make_ev = |src: &str, target: &str| {
            make_event(json!({ "event_type": "smb_connect", "src_ip": src, "TargetHost": target }))
        };

        // 3 distinct targets from attacker — should NOT trigger (need > 3)
        for host in ["host-a", "host-b", "host-c"] {
            assert!(
                !executor.evaluate(&rule, &make_ev("10.0.0.1", host)).matched,
                "3 distinct targets must not trigger"
            );
        }
        // Same target again — still 3 distinct, no trigger
        assert!(
            !executor
                .evaluate(&rule, &make_ev("10.0.0.1", "host-a"))
                .matched,
            "repeated target must not increase distinct count"
        );
        // 4th distinct target → triggers
        assert!(
            executor
                .evaluate(&rule, &make_ev("10.0.0.1", "host-d"))
                .matched,
            "4th distinct target must trigger"
        );

        // Different src_ip with same 4 targets should ALSO trigger independently
        for host in ["host-a", "host-b", "host-c"] {
            executor.evaluate(&rule, &make_ev("192.168.1.5", host));
        }
        assert!(
            executor
                .evaluate(&rule, &make_ev("192.168.1.5", "host-z"))
                .matched,
            "independent src_ip group must trigger on its own 4th distinct target"
        );

        // Completely different attacker stays isolated
        let innocent = make_ev("172.16.0.1", "host-x");
        assert!(
            !executor.evaluate(&rule, &innocent).matched,
            "new src_ip with 1 connection must not trigger"
        );
    }

    #[test]
    fn count_distinct_no_group_by_counts_globally() {
        // Without group_by, distinct values are counted across all events.
        let rule = make_agg_rule(
            "title: UniqueSrcs\nlogsource:\n  category: network\n\
             detection:\n  selection:\n    proto: tcp\n  \
             condition: selection | count_distinct(src_ip) > 2",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_secs(60));

        let ev = |ip: &str| make_event(json!({ "proto": "tcp", "src_ip": ip }));
        assert!(!executor.evaluate(&rule, &ev("1.1.1.1")).matched);
        assert!(!executor.evaluate(&rule, &ev("2.2.2.2")).matched);
        // Repeat — distinct still 2
        assert!(!executor.evaluate(&rule, &ev("1.1.1.1")).matched);
        // 3rd distinct → triggers (> 2)
        assert!(executor.evaluate(&rule, &ev("3.3.3.3")).matched);
    }

    #[test]
    fn plan_cache_is_used_on_subsequent_evaluate_calls() {
        let executor = RuleExecutor::default();
        let rule = make_rule(
            "title: CacheTest\ndetection:\n  sel:\n    cmd|contains: attack\n  condition: sel",
        );
        let event = make_event(json!({ "cmd": "do attack now" }));

        // First call populates cache
        assert!(executor.evaluate(&rule, &event).matched);
        // Second call should use cache (same result expected)
        assert!(executor.evaluate(&rule, &event).matched);
        // Cache should contain one entry for this rule
        assert!(
            executor.plan_cache.contains_key(&rule.rule_id),
            "plan_cache must hold an entry for the rule after evaluate()"
        );
    }

    #[test]
    fn invalidate_rule_removes_entry_from_plan_cache() {
        let executor = RuleExecutor::default();
        let rule = make_rule(
            "title: InvalidateMe\ndetection:\n  sel:\n    x|contains: y\n  condition: sel",
        );
        let event = make_event(json!({ "x": "y" }));
        executor.evaluate(&rule, &event);
        assert!(executor.plan_cache.contains_key(&rule.rule_id));
        executor.invalidate_rule(rule.rule_id);
        assert!(
            !executor.plan_cache.contains_key(&rule.rule_id),
            "plan_cache entry must be removed after invalidate_rule()"
        );
    }

    // ── Timeframe ─────────────────────────────────────────────────────────────

    #[test]
    fn timeframe_parser_converts_sigma_format_to_seconds() {
        assert_eq!(parse_sigma_timeframe("30s"), Some(30));
        assert_eq!(parse_sigma_timeframe("5m"), Some(300));
        assert_eq!(parse_sigma_timeframe("1h"), Some(3_600));
        assert_eq!(parse_sigma_timeframe("1d"), Some(86_400));
        assert_eq!(parse_sigma_timeframe("1w"), Some(604_800));
        assert_eq!(parse_sigma_timeframe("100m"), Some(6_000));
        assert_eq!(parse_sigma_timeframe(""), None);
        assert_eq!(parse_sigma_timeframe("5x"), None);
        assert_eq!(parse_sigma_timeframe("notanumber_m"), None);
    }

    #[test]
    fn compiler_extracts_timeframe_from_detection_block() {
        // Per the Sigma spec, timeframe lives INSIDE the detection block.
        let plan: CompiledSigmaPlan = serde_json::from_value(
            SigmaCompiler
                .compile(
                    "title: Brute\n\
                     detection:\n\
                     \x20 selection:\n    event_type: fail\n\
                     \x20 condition: selection | count() > 5\n\
                     \x20 timeframe: 5m",
                )
                .expect("compile should succeed"),
        )
        .expect("plan should deserialize");

        assert_eq!(
            plan.timeframe_seconds,
            Some(300),
            "timeframe: 5m inside detection block should compile to 300 seconds"
        );
    }

    #[test]
    fn compiler_timeframe_in_detection_does_not_become_a_selection() {
        // The `timeframe` key must be skipped during selection parsing — not
        // inserted as a SelectionGroup (which would fail with "unsupported selection type").
        let result = SigmaCompiler.compile(
            "title: Brute\n\
             detection:\n\
             \x20 selection:\n    EventID: 4625\n\
             \x20 condition: selection | count() > 10\n\
             \x20 timeframe: 15m",
        );
        assert!(
            result.is_ok(),
            "rule with timeframe inside detection must compile: {:?}",
            result
        );
        let plan: CompiledSigmaPlan = serde_json::from_value(result.unwrap()).unwrap();
        assert!(
            !plan.selections.contains_key("timeframe"),
            "timeframe must not appear as a selection name"
        );
        assert_eq!(plan.timeframe_seconds, Some(900));
    }

    #[test]
    fn agg_timeframe_from_rule_overrides_executor_default() {
        // Rule declares timeframe: 5m (300 s). Executor is configured with a 1 ms
        // global window — so tiny that events would expire instantly if the executor
        // window were used, causing count() to never exceed 1.
        // With the rule's timeframe respected, the 300 s window is used and count
        // accumulates correctly.
        let rule = make_agg_rule(
            "title: BruteForce\nlogsource:\n  category: auth\n\
             detection:\n  selection:\n    event_type: failed_login\n  \
             condition: selection | count() > 3\n\
             timeframe: 5m",
        );
        // Executor has a near-zero global window — would break agg if used
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_millis(1));

        let ev = make_event(json!({ "event_type": "failed_login" }));

        // First 3 should not match (count not > 3)
        for _ in 0..3 {
            assert!(
                !executor.evaluate(&rule, &ev).matched,
                "should not trigger before threshold"
            );
        }
        // 4th crosses threshold — only possible if the rule's 5m window is used
        assert!(
            executor.evaluate(&rule, &ev).matched,
            "rule timeframe (5m) must override the executor's 1ms global window"
        );
    }

    // ── Sprint A: field mapping ────────────────────────────────────────────────

    #[test]
    fn field_mapping_commandline_resolves_via_ocsf() {
        // A rule using Sigma's `CommandLine` field should match data stored in
        // the OCSF `process.cmd_line` path.
        let rule = make_rule(
            "title: CommandLine\n\
             detection:\n  sel:\n    CommandLine|contains: mimikatz\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let mut event = make_event(json!({}));
        event.ocsf_record = json!({ "process": { "cmd_line": "C:\\tools\\mimikatz.exe" } });
        assert!(
            executor.evaluate(&rule, &event).matched,
            "CommandLine should map to process.cmd_line in ocsf_record"
        );
    }

    #[test]
    fn field_mapping_network_fields_resolve() {
        let rule = make_rule(
            "title: SuspiciousConn\n\
             detection:\n  sel:\n    dst_port: '4444'\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let mut event = make_event(json!({}));
        event.ocsf_record = json!({ "dst_endpoint": { "port": "4444" } });
        assert!(
            executor.evaluate(&rule, &event).matched,
            "dst_port should map to dst_endpoint.port in ocsf_record"
        );
    }

    #[test]
    fn field_mapping_falls_back_to_raw_payload() {
        // Fields not in the map should still be found in raw_payload
        let rule = make_rule(
            "title: Custom\n\
             detection:\n  sel:\n    custom_vendor_field|contains: malware\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let event = make_event(json!({ "custom_vendor_field": "malware.exe" }));
        assert!(
            executor.evaluate(&rule, &event).matched,
            "unmapped field should fall back to raw_payload lookup"
        );
    }

    // ── |exists modifier ─────────────────────────────────────────────────────

    #[test]
    fn exists_true_matches_when_field_present() {
        let rule = make_rule(
            "title: ExistsTrue\n\
             detection:\n  sel:\n    CommandLine|exists: true\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let ev_has = make_event(json!({ "CommandLine": "powershell -enc abc" }));
        let ev_none = make_event(json!({ "ProcessName": "cmd.exe" }));
        assert!(
            executor.evaluate(&rule, &ev_has).matched,
            "|exists: true must match when field is present"
        );
        assert!(
            !executor.evaluate(&rule, &ev_none).matched,
            "|exists: true must not match when field is absent"
        );
    }

    #[test]
    fn exists_false_matches_when_field_absent() {
        let rule = make_rule(
            "title: ExistsFalse\n\
             detection:\n  sel:\n    ParentCommandLine|exists: false\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let ev_no_parent = make_event(json!({ "CommandLine": "cmd.exe /c whoami" }));
        let ev_has_parent =
            make_event(json!({ "CommandLine": "cmd.exe", "ParentCommandLine": "explorer.exe" }));
        assert!(
            executor.evaluate(&rule, &ev_no_parent).matched,
            "|exists: false must match when field is absent"
        );
        assert!(
            !executor.evaluate(&rule, &ev_has_parent).matched,
            "|exists: false must not match when field is present"
        );
    }

    #[test]
    fn exists_modifier_in_compound_rule() {
        // Common real-world pattern: require presence of field A AND absence of field B.
        let rule = make_rule(
            "title: Compound\n\
             detection:\n\
             \x20 sel_has_cmd:\n    CommandLine|exists: true\n\
             \x20 sel_no_parent:\n    ParentCommandLine|exists: false\n\
             \x20 condition: sel_has_cmd and sel_no_parent",
        );
        let executor = RuleExecutor::default();
        let ev_match = make_event(json!({ "CommandLine": "evil.exe" }));
        let ev_no =
            make_event(json!({ "CommandLine": "evil.exe", "ParentCommandLine": "explorer.exe" }));
        let ev_no2 = make_event(json!({ "ProcessName": "svchost.exe" }));
        assert!(executor.evaluate(&rule, &ev_match).matched);
        assert!(!executor.evaluate(&rule, &ev_no).matched);
        assert!(!executor.evaluate(&rule, &ev_no2).matched);
    }

    #[test]
    fn exists_modifier_compiles_without_error() {
        // Ensure the compiler doesn't reject |exists as an unknown modifier.
        let result = SigmaCompiler.compile(
            "title: ExistsCompile\n\
             detection:\n  sel:\n    Image|exists: true\n  condition: sel",
        );
        assert!(
            result.is_ok(),
            "rule with |exists must compile: {:?}",
            result
        );
    }

    // ── `timeframe` inside detection block ───────────────────────────────────

    #[test]
    fn timeframe_inside_detection_enables_agg_window() {
        // Rule uses timeframe inside the detection block (correct Sigma format).
        // The effective window should be 100ms (very small), NOT the executor default (60s).
        let rule = make_agg_rule(
            "title: TimedBrute\n\
             detection:\n\
             \x20 selection:\n    EventID: '4625'\n\
             \x20 condition: selection | count() > 2\n\
             \x20 timeframe: 1m",
        );
        let executor = RuleExecutor::default().with_agg_window(std::time::Duration::from_millis(1)); // tiny global window

        // With a 1-minute rule timeframe, all 3 events fall in window → triggers.
        for _ in 0..2 {
            assert!(
                !executor
                    .evaluate(&rule, &make_event(json!({ "EventID": "4625" })))
                    .matched
            );
        }
        assert!(
            executor
                .evaluate(&rule, &make_event(json!({ "EventID": "4625" })))
                .matched,
            "3rd event must trigger when rule timeframe is 1m (overrides tiny executor window)"
        );
    }

    // ── Glob wildcard patterns ────────────────────────────────────────────────

    #[test]
    fn glob_match_trailing_wildcard() {
        // '*\powershell.exe' — the most common Sigma glob pattern
        assert!(glob_match(
            r"*\powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        assert!(!glob_match(r"*\powershell.exe", r"C:\tools\nc.exe"));
    }

    #[test]
    fn glob_match_leading_wildcard() {
        assert!(glob_match("*.exe", "calc.exe"));
        assert!(glob_match("*.exe", "C:\\Windows\\calc.exe"));
        assert!(!glob_match("*.exe", "calc.bat"));
    }

    #[test]
    fn glob_match_both_ends() {
        assert!(glob_match("* -enc *", "powershell -enc YWJj"));
        assert!(glob_match(
            "* -enc *",
            "cmd /c powershell -enc YWJj trailing"
        ));
        assert!(!glob_match("* -enc *", "powershell -noprofile"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("cmd.?xe", "cmd.exe"));
        assert!(glob_match("cmd.?xe", "cmd.Exe"));
        assert!(!glob_match("cmd.?xe", "cmd.exee"));
    }

    #[test]
    fn glob_match_exact_when_no_wildcard() {
        // Without * or ?, glob_match should behave like eq_ignore_ascii_case.
        assert!(glob_match("powershell.exe", "POWERSHELL.EXE"));
        assert!(!glob_match("powershell.exe", "cmd.exe"));
    }

    #[test]
    fn glob_match_star_only() {
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_star_is_case_insensitive() {
        assert!(glob_match("*POWERSHELL*", "c:\\windows\\powershell.exe"));
    }

    #[test]
    fn glob_in_field_pattern_without_modifier() {
        // End-to-end: rule uses bare glob pattern, no |endswith modifier.
        // YAML single-quoted '*\powershell.exe' → literal pattern *\powershell.exe
        // (single backslash, matching the event value).
        let rule = make_rule(
            "title: GlobRule\ndetection:\n  sel:\n    Image: '*\\powershell.exe'\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let ev_match = make_event(json!({ "Image": "C:\\Windows\\System32\\powershell.exe" }));
        let ev_no = make_event(json!({ "Image": "C:\\tools\\nc.exe" }));
        assert!(
            executor.evaluate(&rule, &ev_match).matched,
            "bare glob '*\\powershell.exe' must match path ending with powershell.exe"
        );
        assert!(!executor.evaluate(&rule, &ev_no).matched);
    }

    #[test]
    fn glob_in_field_pattern_leading_and_trailing() {
        // Detects ' -enc ' anywhere in CommandLine using bare glob.
        let rule = make_rule(
            "title: EncodedCmd\ndetection:\n  sel:\n    CommandLine: '* -enc *'\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let ev_match = make_event(json!({ "CommandLine": "powershell.exe -enc YWJj" }));
        let ev_no = make_event(json!({ "CommandLine": "powershell.exe -noprofile" }));
        assert!(executor.evaluate(&rule, &ev_match).matched);
        assert!(!executor.evaluate(&rule, &ev_no).matched);
    }

    #[test]
    fn glob_multivalue_any_hits() {
        // Multiple glob patterns in a list — any must match (OR semantics).
        // Single backslash in YAML = single backslash in pattern value.
        let rule = make_rule(
            "title: MultiGlob\ndetection:\n  sel:\n    Image:\n      - '*\\powershell.exe'\n      - '*\\cmd.exe'\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        assert!(
            executor
                .evaluate(
                    &rule,
                    &make_event(json!({ "Image": "C:\\Windows\\cmd.exe" }))
                )
                .matched
        );
        assert!(
            executor
                .evaluate(
                    &rule,
                    &make_event(json!({ "Image": "C:\\Windows\\powershell.exe" }))
                )
                .matched
        );
        assert!(
            !executor
                .evaluate(&rule, &make_event(json!({ "Image": "C:\\tools\\nc.exe" })))
                .matched
        );
    }

    #[test]
    fn contains_modifier_does_not_treat_star_as_glob() {
        // |contains: the * is a literal substring, NOT a glob wildcard.
        let rule = make_rule(
            "title: ContainsLiteral\ndetection:\n  sel:\n    CommandLine|contains: '* -enc'\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        // Only matches if the literal string "* -enc" appears in the value.
        let ev_literal = make_event(json!({ "CommandLine": "invoke-expression * -enc" }));
        let ev_glob = make_event(json!({ "CommandLine": "powershell -enc abc" }));
        assert!(
            executor.evaluate(&rule, &ev_literal).matched,
            "|contains must find the literal '* -enc' substring"
        );
        assert!(
            !executor.evaluate(&rule, &ev_glob).matched,
            "|contains must NOT treat * as wildcard"
        );
    }

    // ── Sprint B: modifier correctness ────────────────────────────────────────

    #[test]
    fn modifier_base64_encodes_utf8_bytes() {
        // |base64 without |wide should encode pattern as plain UTF-8 bytes.
        // "powershell" in base64 (UTF-8): cG93ZXJzaGVsbA==
        // A field value that contains that substring should match.
        let rule = make_rule(
            "title: PSEnc\n\
             detection:\n  sel:\n    CommandLine|base64|contains: powershell\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        // base64("powershell") = "cG93ZXJzaGVsbA=="
        let event = make_event(json!({ "CommandLine": "cG93ZXJzaGVsbA==" }));
        assert!(
            executor.evaluate(&rule, &event).matched,
            "|base64|contains should find UTF-8 base64 of 'powershell'"
        );
    }

    #[test]
    fn modifier_base64offset_matches_all_three_offsets() {
        // "IEX" base64 offset variants that appear in PowerShell encoded commands.
        // At offset 0: "SUVY" (but this test uses a simple known value)
        // We verify that the function produces 3 distinct non-empty variants.
        let variants = base64_offset_variants(b"IEX");
        assert_eq!(variants.len(), 3);
        assert!(
            variants.iter().all(|v| !v.is_empty()),
            "all variants must be non-empty"
        );
        // All three variants must be distinct strings
        assert_ne!(variants[0], variants[1]);
        assert_ne!(variants[1], variants[2]);
    }

    #[test]
    fn modifier_wide_base64_encodes_utf16le() {
        // |wide|base64 should encode as UTF-16LE then base64.
        // "ps" in UTF-16LE = [0x70,0x00,0x73,0x00], base64 = "cABzAA=="
        let rule = make_rule(
            "title: WideBase64\n\
             detection:\n  sel:\n    CommandLine|wide|base64|contains: ps\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let event = make_event(json!({ "CommandLine": "cABzAA==" }));
        assert!(
            executor.evaluate(&rule, &event).matched,
            "|wide|base64|contains should find UTF-16LE base64 of 'ps'"
        );
    }

    #[test]
    fn modifier_startswith_and_endswith_work() {
        let executor = RuleExecutor::default();

        let rule_sw = make_rule(
            "title: SW\ndetection:\n  sel:\n    CommandLine|startswith: powershell\n  condition: sel",
        );
        let ev_match = make_event(json!({ "CommandLine": "powershell -enc abc" }));
        let ev_no = make_event(json!({ "CommandLine": "cmd /c whoami" }));
        assert!(executor.evaluate(&rule_sw, &ev_match).matched);
        assert!(!executor.evaluate(&rule_sw, &ev_no).matched);

        let rule_ew = make_rule(
            "title: EW\ndetection:\n  sel:\n    CommandLine|endswith: .exe\n  condition: sel",
        );
        let ev_exe = make_event(json!({ "CommandLine": "C:\\system32\\calc.exe" }));
        let ev_noexe = make_event(json!({ "CommandLine": "python script.py" }));
        assert!(executor.evaluate(&rule_ew, &ev_exe).matched);
        assert!(!executor.evaluate(&rule_ew, &ev_noexe).matched);
    }

    // ── Sprint C: logsource routing ───────────────────────────────────────────

    #[test]
    fn logsource_routing_windows_rule_skips_linux_event() {
        let rule = make_rule(
            "title: WinOnly\nlogsource:\n  product: windows\n\
             detection:\n  sel:\n    - malware\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        // Linux event — rule should be skipped even though "malware" matches raw_payload
        let mut event = make_event(json!({ "message": "malware detected" }));
        event.source = EventSource::LinuxAudit;
        assert!(
            !executor.evaluate(&rule, &event).matched,
            "windows logsource rule must not run on LinuxAudit events"
        );
    }

    #[test]
    fn logsource_routing_windows_rule_matches_sysmon_event() {
        let rule = make_rule(
            "title: WinOnly\nlogsource:\n  product: windows\n\
             detection:\n  sel:\n    - malware\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let mut event = make_event(json!({ "message": "malware.exe" }));
        event.source = EventSource::WindowsSysmon;
        assert!(
            executor.evaluate(&rule, &event).matched,
            "windows logsource rule must run on WindowsSysmon events"
        );
    }

    #[test]
    fn logsource_routing_no_logsource_matches_all_sources() {
        let rule = make_rule("title: Any\ndetection:\n  sel:\n    - malware\n  condition: sel");
        let executor = RuleExecutor::default();
        for source in [
            EventSource::WindowsSysmon,
            EventSource::LinuxAudit,
            EventSource::Firewall,
            EventSource::CloudAudit,
            EventSource::Syslog,
        ] {
            let mut event = make_event(json!({ "message": "malware" }));
            event.source = source;
            assert!(
                executor.evaluate(&rule, &event).matched,
                "rule with no logsource must match all event sources"
            );
        }
    }

    #[test]
    fn logsource_routing_category_process_creation_skips_firewall() {
        let rule = make_rule(
            "title: ProcCreate\nlogsource:\n  category: process_creation\n\
             detection:\n  sel:\n    - malware\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let mut event = make_event(json!({ "message": "malware" }));
        event.source = EventSource::Firewall;
        assert!(
            !executor.evaluate(&rule, &event).matched,
            "process_creation category rule must not run on Firewall events"
        );
    }

    // ── Sprint D: MITRE ATT&CK enrichment ────────────────────────────────────

    #[test]
    fn mitre_enrichment_populated_on_alert_build() {
        let executor = RuleExecutor::default();
        let rule = make_rule(
            "title: PSEnc\n\
             logsource:\n  product: windows\n  category: process_creation\n\
             tags:\n  - attack.t1059.001\n  - attack.execution\n\
             detection:\n  sel:\n    CommandLine|contains: powershell\n  condition: sel",
        );
        let event = make_event(json!({ "CommandLine": "powershell -enc abc" }));
        let alert = executor
            .maybe_build_alert(&rule, &event, "evt:1".to_string())
            .expect("should build alert");

        assert_eq!(
            alert.mitre_attack.len(),
            1,
            "one technique tag should produce one entry"
        );
        let m = &alert.mitre_attack[0];
        assert_eq!(m.technique_id, "T1059.001");
        assert_eq!(m.tactic.as_deref(), Some("execution"));
        assert_eq!(m.technique_name.as_deref(), Some("PowerShell"));
    }

    #[test]
    fn mitre_enrichment_empty_when_no_tags() {
        let executor = RuleExecutor::default();
        let rule = make_rule(
            "title: NoTags\n\
             detection:\n  sel:\n    msg|contains: test\n  condition: sel",
        );
        let event = make_event(json!({ "msg": "test" }));
        let alert = executor
            .maybe_build_alert(&rule, &event, "evt:1".to_string())
            .expect("should build alert");
        assert!(
            alert.mitre_attack.is_empty(),
            "no tags → empty mitre_attack"
        );
    }

    #[test]
    fn mitre_enrichment_tactic_only_tags_are_skipped() {
        let executor = RuleExecutor::default();
        // Only tactic tags, no technique IDs → mitre_attack must be empty.
        let rule = make_rule(
            "title: TacticOnly\n\
             tags:\n  - attack.execution\n  - attack.defense_evasion\n\
             detection:\n  sel:\n    msg|contains: x\n  condition: sel",
        );
        let event = make_event(json!({ "msg": "x" }));
        let alert = executor
            .maybe_build_alert(&rule, &event, "evt:1".to_string())
            .expect("should build alert");
        assert!(
            alert.mitre_attack.is_empty(),
            "tactic-only tags must not produce MitreAttack entries"
        );
    }

    #[test]
    fn mitre_enrichment_base_technique_fallback() {
        // T1059 base (no sub-technique number) should still resolve tactic + name.
        let rule = make_rule(
            "title: BaseTech\n\
             tags:\n  - attack.t1059\n\
             detection:\n  sel:\n    cmd|contains: sh\n  condition: sel",
        );
        let executor = RuleExecutor::default();
        let event = make_event(json!({ "cmd": "sh -c id" }));
        let alert = executor
            .maybe_build_alert(&rule, &event, "evt:1".to_string())
            .expect("should build alert");
        assert_eq!(alert.mitre_attack.len(), 1);
        assert_eq!(alert.mitre_attack[0].technique_id, "T1059");
        assert_eq!(alert.mitre_attack[0].tactic.as_deref(), Some("execution"));
    }

    #[test]
    fn parse_mitre_from_tags_unknown_technique_has_none_fields() {
        let tags = vec!["attack.t9999.999".to_string()];
        let result = parse_mitre_from_tags(&tags);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].technique_id, "T9999.999");
        assert!(
            result[0].tactic.is_none(),
            "unknown technique → tactic should be None"
        );
        assert!(result[0].technique_name.is_none());
    }

    // ── |fieldref modifier ────────────────────────────────────────────────────

    const FIELDREF_RULE: &str =
        "title: Self-Injection\ndetection:\n  selection:\n    SourceImage|fieldref: TargetImage\n  condition: selection";

    #[test]
    fn fieldref_compiler_compiles_without_error() {
        SigmaCompiler
            .compile(FIELDREF_RULE)
            .expect("fieldref should compile without error");
    }

    #[test]
    fn fieldref_matches_when_fields_are_equal() {
        let rule = make_rule(FIELDREF_RULE);
        let executor = RuleExecutor::default();
        let event = make_event(json!({
            "SourceImage": "C:\\Windows\\System32\\lsass.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe"
        }));
        assert!(executor.evaluate(&rule, &event).matched);
    }

    #[test]
    fn fieldref_no_match_when_fields_differ() {
        let rule = make_rule(FIELDREF_RULE);
        let executor = RuleExecutor::default();
        let event = make_event(json!({
            "SourceImage": "C:\\malware.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe"
        }));
        assert!(!executor.evaluate(&rule, &event).matched);
    }

    #[test]
    fn fieldref_no_match_when_source_field_absent() {
        let rule = make_rule(FIELDREF_RULE);
        let executor = RuleExecutor::default();
        let event = make_event(json!({ "TargetImage": "C:\\Windows\\lsass.exe" }));
        assert!(!executor.evaluate(&rule, &event).matched);
    }

    #[test]
    fn fieldref_is_case_insensitive() {
        let rule = make_rule(
            "title: Case Test\ndetection:\n  selection:\n    User|fieldref: TargetUserName\n  condition: selection",
        );
        let executor = RuleExecutor::default();
        let event = make_event(json!({
            "User": "DOMAIN\\Administrator",
            "TargetUserName": "domain\\administrator"
        }));
        assert!(executor.evaluate(&rule, &event).matched);
    }

    #[test]
    fn fieldref_compound_rule_with_and() {
        // fieldref selection AND a contains selection — both must match.
        let rule = make_rule(
            "title: Hollow Process\n\
             detection:\n  self_inject:\n    SourceImage|fieldref: TargetImage\n  \
             known_tool:\n    CommandLine|contains: '--hollow'\n  \
             condition: self_inject and known_tool",
        );
        let executor = RuleExecutor::default();

        // Both conditions met → match
        let hit = make_event(json!({
            "SourceImage": "C:\\evil.exe",
            "TargetImage": "C:\\evil.exe",
            "CommandLine": "evil.exe --hollow"
        }));
        assert!(executor.evaluate(&rule, &hit).matched);

        // Different images → no match even though CommandLine matches
        let miss = make_event(json!({
            "SourceImage": "C:\\evil.exe",
            "TargetImage": "C:\\victim.exe",
            "CommandLine": "evil.exe --hollow"
        }));
        assert!(!executor.evaluate(&rule, &miss).matched);
    }

    // ── `near` temporal correlation ───────────────────────────────────────────

    /// Rule that matches a process event near a network event on the same host.
    const NEAR_RULE: &str = "title: PS Near Net\n\
         detection:\n  sel_proc:\n    Image|contains: powershell\n  \
         sel_net:\n    DestinationPort: '443'\n  \
         condition: sel_proc near sel_net within 30s by ComputerName";

    #[test]
    fn near_compiler_compiles_without_error() {
        SigmaCompiler
            .compile(NEAR_RULE)
            .expect("near rule should compile without error");
    }

    #[test]
    fn near_fires_when_both_selections_seen() {
        let rule = make_rule(NEAR_RULE);
        let executor = RuleExecutor::default();
        let host = json!({ "ComputerName": "ws01" });

        // Event A: process
        let proc_event = make_event(json!({
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ComputerName": "ws01"
        }));
        // Event B: network
        let net_event = make_event(json!({
            "DestinationPort": "443",
            "ComputerName": "ws01"
        }));
        let _ = host; // suppress unused warning

        // First event should not fire alone
        assert!(!executor.evaluate(&rule, &proc_event).matched);
        // Second event, same entity, within window → fires
        assert!(executor.evaluate(&rule, &net_event).matched);
    }

    #[test]
    fn near_no_fire_with_only_one_selection() {
        let rule = make_rule(NEAR_RULE);
        let executor = RuleExecutor::default();

        // Only the process event — network never arrives
        let proc_event = make_event(json!({
            "Image": "powershell.exe",
            "ComputerName": "ws01"
        }));
        assert!(!executor.evaluate(&rule, &proc_event).matched);
        // Second call with the same process event again — still no network event
        assert!(!executor.evaluate(&rule, &proc_event).matched);
    }

    #[test]
    fn near_isolates_by_entity_field() {
        let rule = make_rule(NEAR_RULE);
        let executor = RuleExecutor::default();

        // ws01 fires process event
        let proc_ws01 = make_event(json!({
            "Image": "powershell.exe",
            "ComputerName": "ws01"
        }));
        // ws02 fires only network event
        let net_ws02 = make_event(json!({
            "DestinationPort": "443",
            "ComputerName": "ws02"
        }));
        // ws01 fires network event too
        let net_ws01 = make_event(json!({
            "DestinationPort": "443",
            "ComputerName": "ws01"
        }));

        executor.evaluate(&rule, &proc_ws01); // record ws01 process
                                              // ws02 network alone → no alert (ws02 never had a process event)
        assert!(!executor.evaluate(&rule, &net_ws02).matched);
        // ws01 network → alert (ws01 had both)
        assert!(executor.evaluate(&rule, &net_ws01).matched);
    }

    #[test]
    fn near_respects_window_expiry() {
        // 0-second window: every recorded entry is immediately stale on the next call.
        let rule = make_rule(
            "title: Zero Window\n\
             detection:\n  sel_a:\n    cmd|contains: payload_a\n  \
             sel_b:\n    cmd|contains: payload_b\n  \
             condition: sel_a near sel_b within 0s",
        );
        let executor = RuleExecutor::default();

        let event_a = make_event(json!({ "cmd": "payload_a" }));
        let event_b = make_event(json!({ "cmd": "payload_b" }));

        executor.evaluate(&rule, &event_a);
        // With a 0s window the entry for sel_a is already stale → no fire
        assert!(!executor.evaluate(&rule, &event_b).matched);
    }

    #[test]
    fn near_fires_without_by_clause() {
        // No `by` field — all events share the __global__ bucket.
        let rule = make_rule(
            "title: Global Near\n\
             detection:\n  sel_a:\n    cmd|contains: alpha\n  \
             sel_b:\n    cmd|contains: beta\n  \
             condition: sel_a near sel_b within 60s",
        );
        let executor = RuleExecutor::default();

        let event_a = make_event(json!({ "cmd": "alpha" }));
        let event_b = make_event(json!({ "cmd": "beta" }));

        assert!(!executor.evaluate(&rule, &event_a).matched);
        assert!(executor.evaluate(&rule, &event_b).matched);
    }

    // ── |lookup modifier tests ──────────────────────────────────────────────

    const LOOKUP_RULE: &str = "title: IOC IP Hit\n\
         detection:\n  selection:\n    src_ip|lookup: ioc_ips\n  \
         condition: selection";

    /// Build an EventContext with an optional lookup store for lookup tests.
    fn make_ctx_with_store<'a>(
        event: &'a EventEnvelope,
        store: Arc<LookupStore>,
    ) -> EventContext<'a> {
        build_event_context(event, &HashSet::new()).with_lookup_store(store)
    }

    #[test]
    fn lookup_matches_value_in_table() {
        let rule = make_rule(LOOKUP_RULE);
        let store = Arc::new(LookupStore::new());
        store.set_entries(
            "ioc_ips",
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
        );

        let event = make_event(json!({ "src_ip": "1.2.3.4" }));
        let executor = RuleExecutor::default();
        let ctx = make_ctx_with_store(&event, Arc::clone(&store));
        assert!(executor.evaluate_with_context(&rule, &ctx).matched);
    }

    #[test]
    fn lookup_no_match_when_value_absent() {
        let rule = make_rule(LOOKUP_RULE);
        let store = Arc::new(LookupStore::new());
        store.set_entries("ioc_ips", vec!["1.2.3.4".to_string()]);

        let event = make_event(json!({ "src_ip": "9.9.9.9" }));
        let executor = RuleExecutor::default();
        let ctx = make_ctx_with_store(&event, Arc::clone(&store));
        assert!(!executor.evaluate_with_context(&rule, &ctx).matched);
    }

    #[test]
    fn lookup_case_insensitive() {
        let rule = make_rule(
            "title: Hash Check\n\
             detection:\n  selection:\n    FileHash|lookup: bad_hashes\n  \
             condition: selection",
        );
        let store = Arc::new(LookupStore::new());
        // Store normalises to lowercase; value arriving uppercase must still match.
        store.set_entries("bad_hashes", vec!["AABBCCDD".to_string()]);

        let event = make_event(json!({ "FileHash": "aabbccdd" }));
        let executor = RuleExecutor::default();
        let ctx = make_ctx_with_store(&event, Arc::clone(&store));
        assert!(executor.evaluate_with_context(&rule, &ctx).matched);
    }

    #[test]
    fn lookup_no_store_returns_false() {
        // Without a lookup store, |lookup always returns false (safe default).
        let rule = make_rule(LOOKUP_RULE);
        let event = make_event(json!({ "src_ip": "1.2.3.4" }));
        let executor = RuleExecutor::default();
        // evaluate() builds EventContext with lookup_store = None
        assert!(!executor.evaluate(&rule, &event).matched);
    }

    #[test]
    fn lookup_multiple_tables_or_semantics() {
        let rule = make_rule(
            "title: Multi-table\n\
             detection:\n  selection:\n    src_ip|lookup:\n      - list_a\n      - list_b\n  \
             condition: selection",
        );
        let store = Arc::new(LookupStore::new());
        store.set_entries("list_a", vec!["10.0.0.1".to_string()]);
        store.set_entries("list_b", vec!["10.0.0.2".to_string()]);

        let executor = RuleExecutor::default();

        // In list_b only — still matches (OR semantics over tables)
        let event = make_event(json!({ "src_ip": "10.0.0.2" }));
        let ctx = make_ctx_with_store(&event, Arc::clone(&store));
        assert!(executor.evaluate_with_context(&rule, &ctx).matched);

        // Not in either table — no match
        let event2 = make_event(json!({ "src_ip": "1.1.1.1" }));
        let ctx2 = make_ctx_with_store(&event2, Arc::clone(&store));
        assert!(!executor.evaluate_with_context(&rule, &ctx2).matched);
    }
}
