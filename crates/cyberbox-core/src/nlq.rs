//! Natural Language Query (NLQ) — translates a plain-English security question
//! into a `SearchQueryRequest` using an LLM (Claude or OpenAI).
//!
//! ## Flow
//! ```text
//!  "show failed SSH logins from root in the last hour"
//!          │
//!          ▼  POST to Claude or OpenAI API
//!  LLM   →  { "sql_where": "...", "time_range_hours": 1, "limit": 200 }
//!          │
//!          ▼  sanitise: strip dangerous tokens
//!  SearchQueryRequest { extra_where: Some("..."), time_range, pagination }
//! ```
//!
//! ## Safety
//! The WHERE clause returned by the LLM is checked for dangerous SQL tokens
//! (DROP, UNION, INSERT, …) before use. The mandatory `tenant_id` predicate
//! is always injected server-side by the event store — the LLM cannot bypass it.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use cyberbox_models::{Pagination, QueryFilter, SearchQueryRequest, TimeRange};

// ─── Provider selection ──────────────────────────────────────────────────────

/// Which LLM provider to use for NLQ features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NlqProvider {
    Anthropic,
    OpenAI,
}

impl NlqProvider {
    /// Auto-detect provider from available API keys.
    /// Prefers Anthropic when both keys are set.
    pub fn auto_detect(anthropic_key: &str, openai_key: &str) -> Option<Self> {
        if !anthropic_key.is_empty() {
            Some(Self::Anthropic)
        } else if !openai_key.is_empty() {
            Some(Self::OpenAI)
        } else {
            None
        }
    }

    /// Parse from a config string. Falls back to auto-detection if unrecognised.
    pub fn from_config(s: &str, anthropic_key: &str, openai_key: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => {
                if !anthropic_key.is_empty() {
                    Some(Self::Anthropic)
                } else {
                    None
                }
            }
            "openai" | "gpt" => {
                if !openai_key.is_empty() {
                    Some(Self::OpenAI)
                } else {
                    None
                }
            }
            "" | "auto" => Self::auto_detect(anthropic_key, openai_key),
            _ => Self::auto_detect(anthropic_key, openai_key),
        }
    }
}

impl std::fmt::Display for NlqProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anthropic => write!(f, "anthropic"),
            Self::OpenAI => write!(f, "openai"),
        }
    }
}

// ─── API constants ───────────────────────────────────────────────────────────

const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
const OPENAI_CHAT_URL: &str = "https://api.openai.com/v1/chat/completions";

/// Anthropic: use Haiku for low-latency, low-cost NLQ translation.
const ANTHROPIC_MODEL: &str = "claude-haiku-4-5-20251001";
/// OpenAI: use GPT-4.1-mini for comparable speed/cost.
const OPENAI_MODEL: &str = "gpt-4.1-mini";

const MAX_TOKENS: u32 = 512;

const SYSTEM_PROMPT: &str = "\
You are a SIEM query translator. Convert a natural-language security question \
into a structured JSON response for querying the event store.\n\
\n\
Event table schema (ClickHouse):\n\
  event_time   DateTime  (UTC)\n\
  tenant_id    String    (never include in sql_where — injected server-side)\n\
  source       String    values: 'api' | 'syslog' | 'kafka' | 'stream'\n\
  raw_payload  String    JSON blob. Common fields:\n\
    src_ip, dst_ip, user, hostname, msg, EventID (int),\n\
    severity (int 0-7 per syslog), facility (int), app_name,\n\
    action, proto, dpt (int), spt (int), tag\n\
  ocsf_record  String    JSON blob (OCSF-normalised)\n\
\n\
ClickHouse JSON extraction functions:\n\
  JSONExtractString(raw_payload, 'field')   → String\n\
  JSONExtractInt(raw_payload, 'field')      → Int\n\
  JSONExtractFloat(raw_payload, 'field')    → Float\n\
  raw_payload LIKE '%keyword%'              → full-text substring search\n\
  source = 'syslog'                        → filter by event source\n\
\n\
Rules:\n\
1. Return ONLY valid JSON — no prose, no markdown, no code fences.\n\
2. Format exactly: {\"sql_where\":\"<WHERE clause>\",\"time_range_hours\":<int>,\"limit\":<int>}\n\
3. sql_where must be a boolean expression (no SELECT/FROM/WHERE keywords).\n\
4. Never include tenant_id in sql_where.\n\
5. Default time_range_hours: 24. Default limit: 100. Max limit: 1000.\n\
6. For ambiguous queries use sql_where: '1=1'.";

// ─── Public types ──────────────────────────────────────────────────────────────

/// NLQ HTTP request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NlqRequest {
    /// Plain-English question, e.g. "show me failed SSH logins in the last hour".
    pub query: String,
}

/// Intermediate translation returned by [`translate`].
#[derive(Debug, Clone)]
pub struct NlqTranslation {
    /// Ready-to-execute search request (tenant_id and pagination pre-filled).
    pub search: SearchQueryRequest,
    /// The sanitised SQL WHERE clause (for UI transparency).
    pub generated_where: String,
    /// The original natural-language query echoed back.
    pub interpreted_as: String,
}

// ─── Anthropic (Claude) wire types ───────────────────────────────────────────

#[derive(Serialize)]
struct ClaudeRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<ClaudeMsg<'a>>,
}

#[derive(Serialize)]
struct ClaudeMsg<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Deserialize)]
struct ClaudeContent {
    text: String,
}

// ─── OpenAI wire types ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct OpenAIRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<OpenAIMsg<'a>>,
}

#[derive(Serialize)]
struct OpenAIMsg<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessageContent,
}

#[derive(Deserialize)]
struct OpenAIMessageContent {
    content: String,
}

// ─── Shared parsed NLQ response ──────────────────────────────────────────────

#[derive(Deserialize)]
struct ParsedNlq {
    sql_where: String,
    #[serde(default)]
    time_range_hours: Option<u64>,
    #[serde(default)]
    limit: Option<u32>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Translate a natural-language query into a [`SearchQueryRequest`].
///
/// The returned `search.extra_where` carries the sanitised WHERE clause.
/// `search.tenant_id` is set from the caller's auth context — the LLM
/// cannot override it.
pub async fn translate(
    req: &NlqRequest,
    tenant_id: &str,
    api_key: &str,
    provider: NlqProvider,
    client: &reqwest::Client,
) -> anyhow::Result<NlqTranslation> {
    let text = call_llm(
        SYSTEM_PROMPT,
        &req.query,
        MAX_TOKENS,
        api_key,
        provider,
        client,
    )
    .await?;

    let json_str = strip_code_fences(&text);
    let parsed: ParsedNlq = serde_json::from_str(json_str.trim())
        .map_err(|e| anyhow::anyhow!("LLM returned non-JSON: {e}\nraw: {json_str}"))?;

    let where_clause = sanitise_where(&parsed.sql_where);
    let hours = parsed.time_range_hours.unwrap_or(24).clamp(1, 720);
    let page_size = parsed.limit.unwrap_or(100).clamp(1, 1000);

    let now = Utc::now();
    let start = now - chrono::Duration::hours(hours as i64);

    let search = SearchQueryRequest {
        tenant_id: tenant_id.to_string(),
        sql: String::new(), // use store default SELECT
        time_range: TimeRange { start, end: now },
        filters: Vec::<QueryFilter>::new(),
        pagination: Pagination { page: 1, page_size },
        extra_where: Some(where_clause.clone()),
    };

    Ok(NlqTranslation {
        search,
        generated_where: where_clause,
        interpreted_as: req.query.clone(),
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Strip ` ```json ... ``` ` or ` ``` ... ``` ` fences from LLM output.
fn strip_code_fences(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with("```") {
        if let Some(newline) = s.find('\n') {
            let inner = &s[newline + 1..];
            if let Some(end) = inner.rfind("```") {
                return inner[..end].trim();
            }
            return inner.trim();
        }
    }
    s
}

/// Reject SQL tokens that could be dangerous if the LLM's response were
/// compromised.  This is defence-in-depth; the store also enforces SELECT-only
/// on the `sql` field and always injects the `tenant_id` predicate server-side.
pub fn sanitise_where(raw: &str) -> String {
    const DANGEROUS: &[&str] = &[
        "drop",
        "insert",
        "update",
        "delete",
        "create",
        "alter",
        "truncate",
        "exec",
        "execute",
        "--",
        "/*",
        "*/",
        ";",
        "xp_",
        "sp_",
        "union",
        "information_schema",
        "sleep(",
    ];
    let lower = raw.to_ascii_lowercase();
    for token in DANGEROUS {
        if lower.contains(token) {
            tracing::warn!(rejected = raw, "NLQ: rejected unsafe WHERE clause");
            return "1=1".to_string();
        }
    }
    if raw.trim().is_empty() {
        "1=1".to_string()
    } else {
        raw.to_string()
    }
}

// ─── Sigma rule generator ────────────────────────────────────────────────────

const SIGMA_SYSTEM_PROMPT: &str = "\
You are a Sigma detection rule author for a SIEM platform. Generate a valid Sigma \
YAML rule based on the user's description.\n\
\n\
Sigma rule structure:\n\
  title: <short title>\n\
  status: experimental\n\
  description: <one sentence>\n\
  logsource:\n\
    category: <process_creation|network_connection|file_event|authentication|...>\n\
    product: <windows|linux|...>   # omit if generic\n\
  detection:\n\
    selection:\n\
      FieldName|contains: value\n\
    condition: selection\n\
  level: <informational|low|medium|high|critical>\n\
  tags:\n\
    - attack.<tactic>.<TXXXx>\n\
\n\
Rules:\n\
1. Return ONLY valid YAML — no prose, no markdown fences.\n\
2. Use realistic field names from common log sources.\n\
3. Set level accurately based on the threat severity.\n\
4. Include at least one MITRE ATT&CK tag when applicable.\n\
5. Keep detection focused — prefer specific over broad conditions.";

/// Request body for the Sigma rule generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSigmaRequest {
    /// Plain-English description of what to detect.
    /// Example: "detect PowerShell downloading files from the internet"
    pub description: String,
}

/// Response from the Sigma rule generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSigmaResponse {
    /// Generated Sigma YAML, ready to POST to /api/v1/rules.
    pub sigma_yaml: String,
    /// The description echoed back.
    pub description: String,
}

/// Generate a Sigma rule from a plain-English description.
pub async fn generate_sigma(
    req: &GenerateSigmaRequest,
    api_key: &str,
    provider: NlqProvider,
    client: &reqwest::Client,
) -> anyhow::Result<GenerateSigmaResponse> {
    let text = call_llm(
        SIGMA_SYSTEM_PROMPT,
        &req.description,
        1024,
        api_key,
        provider,
        client,
    )
    .await?;
    // Strip fences if the LLM wrapped the YAML
    let yaml = strip_code_fences(&text).to_string();
    Ok(GenerateSigmaResponse {
        sigma_yaml: yaml,
        description: req.description.clone(),
    })
}

// ─── Alert explanation ────────────────────────────────────────────────────────

const EXPLAIN_SYSTEM_PROMPT: &str = "\
You are a senior SOC analyst. Explain the following SIEM alert in plain English \
for a security analyst who may not be familiar with the specific technique.\n\
\n\
Return ONLY valid JSON with this structure:\n\
{\n\
  \"summary\": \"<1-2 sentence plain-English description of what happened>\",\n\
  \"why_suspicious\": \"<why this pattern is a security concern>\",\n\
  \"likely_cause\": \"<most probable explanation: attack, misconfiguration, or false positive>\",\n\
  \"recommended_actions\": [\"<action 1>\", \"<action 2>\", ...],\n\
  \"false_positive_likelihood\": \"low|medium|high\"\n\
}";

/// Response from the alert explanation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertExplanation {
    pub summary: String,
    pub why_suspicious: String,
    pub likely_cause: String,
    pub recommended_actions: Vec<String>,
    pub false_positive_likelihood: String,
}

/// Ask the LLM to explain an alert in plain English.
///
/// `alert_context` should be a compact JSON string of the alert fields that
/// the LLM needs: rule title, severity, matched fields, raw payload excerpt.
pub async fn explain_alert(
    alert_context: &str,
    api_key: &str,
    provider: NlqProvider,
    client: &reqwest::Client,
) -> anyhow::Result<AlertExplanation> {
    let text = call_llm(
        EXPLAIN_SYSTEM_PROMPT,
        alert_context,
        512,
        api_key,
        provider,
        client,
    )
    .await?;
    let json_str = strip_code_fences(&text);
    let explanation: AlertExplanation = serde_json::from_str(json_str.trim())
        .map_err(|e| anyhow::anyhow!("LLM returned non-JSON explanation: {e}\nraw: {json_str}"))?;
    Ok(explanation)
}

// ─── Rule tuning suggestions ─────────────────────────────────────────────────

const TUNE_SYSTEM_PROMPT: &str = "\
You are a senior detection engineer for a SIEM. Analyze the provided Sigma rule and \
its recent alert history (JSON). Suggest concrete improvements to reduce false positives \
while preserving detection coverage.\n\
\n\
Return ONLY valid JSON:\n\
{\n\
  \"issues\": [\"<specific false-positive pattern observed>\", ...],\n\
  \"suggestions\": [\n\
    {\n\
      \"issue\": \"<what causes the false positive>\",\n\
      \"recommendation\": \"<what to change>\",\n\
      \"revised_condition\": \"<Sigma condition or selection snippet>\"\n\
    }\n\
  ],\n\
  \"revised_sigma_yaml\": \"<full improved Sigma YAML or empty string if minor changes only>\",\n\
  \"estimated_fp_reduction_pct\": <0-100>\n\
}";

/// Suggestions returned by the rule tuning endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningSuggestion {
    pub issue: String,
    pub recommendation: String,
    pub revised_condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuneRuleResponse {
    pub issues: Vec<String>,
    pub suggestions: Vec<TuningSuggestion>,
    pub revised_sigma_yaml: String,
    pub estimated_fp_reduction_pct: u32,
}

/// Ask the LLM to analyze a rule + its recent alert history and suggest improvements.
///
/// `sigma_source` is the raw YAML; `alert_history_json` is a compact JSON string
/// summarising recent alerts (status, resolution, hit counts, etc.).
pub async fn tune_rule(
    sigma_source: &str,
    alert_history_json: &str,
    api_key: &str,
    provider: NlqProvider,
    client: &reqwest::Client,
) -> anyhow::Result<TuneRuleResponse> {
    let user_msg = format!(
        "Sigma rule:\n```yaml\n{sigma_source}\n```\n\nRecent alert history:\n{alert_history_json}"
    );
    let text = call_llm(
        TUNE_SYSTEM_PROMPT,
        &user_msg,
        1024,
        api_key,
        provider,
        client,
    )
    .await?;
    let json_str = strip_code_fences(&text);
    let response: TuneRuleResponse = serde_json::from_str(json_str.trim()).map_err(|e| {
        anyhow::anyhow!("LLM returned non-JSON tune response: {e}\nraw: {json_str}")
    })?;
    Ok(response)
}

// ─── Shared LLM caller ──────────────────────────────────────────────────────

async fn call_llm(
    system: &str,
    user_msg: &str,
    max_tokens: u32,
    api_key: &str,
    provider: NlqProvider,
    client: &reqwest::Client,
) -> anyhow::Result<String> {
    match provider {
        NlqProvider::Anthropic => {
            call_anthropic(system, user_msg, max_tokens, api_key, client).await
        }
        NlqProvider::OpenAI => call_openai(system, user_msg, max_tokens, api_key, client).await,
    }
}

async fn call_anthropic(
    system: &str,
    user_msg: &str,
    max_tokens: u32,
    api_key: &str,
    client: &reqwest::Client,
) -> anyhow::Result<String> {
    let req = ClaudeRequest {
        model: ANTHROPIC_MODEL,
        max_tokens,
        system,
        messages: vec![ClaudeMsg {
            role: "user",
            content: user_msg,
        }],
    };
    let resp = client
        .post(ANTHROPIC_MESSAGES_URL)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .json::<ClaudeResponse>()
        .await?;
    Ok(resp
        .content
        .into_iter()
        .next()
        .map(|c| c.text)
        .unwrap_or_default())
}

async fn call_openai(
    system: &str,
    user_msg: &str,
    max_tokens: u32,
    api_key: &str,
    client: &reqwest::Client,
) -> anyhow::Result<String> {
    let req = OpenAIRequest {
        model: OPENAI_MODEL,
        max_tokens,
        messages: vec![
            OpenAIMsg {
                role: "system",
                content: system,
            },
            OpenAIMsg {
                role: "user",
                content: user_msg,
            },
        ],
    };
    let resp = client
        .post(OPENAI_CHAT_URL)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .json::<OpenAIResponse>()
        .await?;
    Ok(resp
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_allows_safe_json_extract() {
        let w = "JSONExtractString(raw_payload, 'user') = 'root'";
        assert_eq!(sanitise_where(w), w);
    }

    #[test]
    fn sanitise_allows_like_search() {
        let w = "raw_payload LIKE '%failed password%'";
        assert_eq!(sanitise_where(w), w);
    }

    #[test]
    fn sanitise_blocks_drop() {
        assert_eq!(sanitise_where("1=1; DROP TABLE events_hot"), "1=1");
    }

    #[test]
    fn sanitise_blocks_union() {
        assert_eq!(
            sanitise_where("1=1 UNION SELECT password FROM users"),
            "1=1"
        );
    }

    #[test]
    fn sanitise_blocks_comment_injection() {
        assert_eq!(sanitise_where("1=1 -- ignore the rest"), "1=1");
    }

    #[test]
    fn sanitise_empty_returns_tautology() {
        assert_eq!(sanitise_where("   "), "1=1");
    }

    #[test]
    fn strip_fences_removes_json_markdown() {
        let s = "```json\n{\"sql_where\":\"1=1\"}\n```";
        assert_eq!(strip_code_fences(s), "{\"sql_where\":\"1=1\"}");
    }

    #[test]
    fn strip_fences_passthrough_plain_json() {
        let s = "{\"sql_where\":\"1=1\"}";
        assert_eq!(strip_code_fences(s), s);
    }

    #[test]
    fn provider_auto_detect_anthropic_preferred() {
        assert_eq!(
            NlqProvider::auto_detect("sk-ant-key", "sk-openai-key"),
            Some(NlqProvider::Anthropic)
        );
    }

    #[test]
    fn provider_auto_detect_openai_fallback() {
        assert_eq!(
            NlqProvider::auto_detect("", "sk-openai-key"),
            Some(NlqProvider::OpenAI)
        );
    }

    #[test]
    fn provider_auto_detect_none() {
        assert_eq!(NlqProvider::auto_detect("", ""), None);
    }

    #[test]
    fn provider_from_config_explicit() {
        assert_eq!(
            NlqProvider::from_config("openai", "", "sk-key"),
            Some(NlqProvider::OpenAI)
        );
        assert_eq!(
            NlqProvider::from_config("anthropic", "sk-ant", ""),
            Some(NlqProvider::Anthropic)
        );
    }

    #[test]
    fn provider_from_config_missing_key() {
        assert_eq!(NlqProvider::from_config("openai", "sk-ant", ""), None);
    }
}
