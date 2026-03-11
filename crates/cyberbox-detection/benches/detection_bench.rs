use chrono::Utc;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use cyberbox_detection::{RuleExecutor, SigmaCompiler};
use cyberbox_models::{
    DetectionMode, DetectionRule, EnrichmentMetadata, EventEnvelope, EventSource, Severity,
};
use serde_json::json;
use uuid::Uuid;

// ── Sigma rule fixtures ───────────────────────────────────────────────────────

const STREAM_RULE: &str = "
title: PowerShell Encoded Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: powershell
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
";

const MULTI_MODIFIER_RULE: &str = "
title: Suspicious Process Creation
logsource:
  product: windows
  category: process_creation
detection:
  selection_proc:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
  selection_net:
    CommandLine|contains|windash: '-exec'
  filter:
    Image|startswith: 'C:\\Windows\\System32\\'
  condition: (selection_proc and selection_net) and not filter
";

const AGGREGATE_RULE: &str = "
title: Brute Force Login
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count() by TargetUserName > 5
  timeframe: 60s
";

const NEAR_RULE: &str = "
title: PowerShell then Network
logsource:
  product: windows
detection:
  selection_proc:
    Image|contains: powershell
  selection_net:
    DestinationPort: '443'
  condition: selection_proc near selection_net within 30s by ComputerName
";

const FIELDREF_RULE: &str = "
title: Parent Process Mismatch
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    SourceImage|fieldref: TargetImage
  condition: selection
";

const REGEX_RULE: &str = "
title: Obfuscated PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|re: '(?i)(invoke-expression|iex)\\s*\\('
  condition: selection
";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_rule(compiler: &SigmaCompiler, sigma: &str) -> DetectionRule {
    DetectionRule {
        rule_id: Uuid::new_v4(),
        tenant_id: "bench-tenant".to_string(),
        sigma_source: sigma.to_string(),
        compiled_plan: compiler.compile(sigma).expect("bench rule must compile"),
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

fn make_event(raw_payload: serde_json::Value) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::new_v4(),
        tenant_id: "bench-tenant".to_string(),
        source: EventSource::WindowsSysmon,
        event_time: Utc::now(),
        ingest_time: Utc::now(),
        raw_payload,
        ocsf_record: json!({}),
        enrichment: EnrichmentMetadata::default(),
        integrity_hash: "bench".to_string(),
    }
}

// ── Benchmark groups ──────────────────────────────────────────────────────────

/// How long does compilation (YAML parse + AST build + JSON serialize) take?
fn bench_compile(c: &mut Criterion) {
    let compiler = SigmaCompiler;
    let mut group = c.benchmark_group("compile");

    group.bench_function("stream_rule", |b| {
        b.iter(|| compiler.compile(STREAM_RULE).unwrap())
    });
    group.bench_function("multi_modifier_rule", |b| {
        b.iter(|| compiler.compile(MULTI_MODIFIER_RULE).unwrap())
    });
    group.bench_function("aggregate_rule", |b| {
        b.iter(|| compiler.compile(AGGREGATE_RULE).unwrap())
    });
    group.bench_function("near_rule", |b| {
        b.iter(|| compiler.compile(NEAR_RULE).unwrap())
    });
    group.bench_function("fieldref_rule", |b| {
        b.iter(|| compiler.compile(FIELDREF_RULE).unwrap())
    });
    group.bench_function("regex_rule", |b| {
        b.iter(|| compiler.compile(REGEX_RULE).unwrap())
    });

    group.finish();
}

/// Per-event evaluation latency with a warm plan cache.
fn bench_evaluate(c: &mut Criterion) {
    let compiler = SigmaCompiler;
    let executor = RuleExecutor::default();

    let stream_rule = make_rule(&compiler, STREAM_RULE);
    let multi_rule = make_rule(&compiler, MULTI_MODIFIER_RULE);
    let agg_rule = make_rule(&compiler, AGGREGATE_RULE);
    let near_rule = make_rule(&compiler, NEAR_RULE);
    let fieldref_rule = make_rule(&compiler, FIELDREF_RULE);
    let regex_rule = make_rule(&compiler, REGEX_RULE);

    let matching_ps = make_event(json!({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell -enc SQBuAHYAbwBrAGUA",
        "TargetUserName": "Administrator",
        "EventID": 4625,
        "ComputerName": "WORKSTATION-1",
        "DestinationPort": "443",
        "SourceImage": "same.exe",
        "TargetImage": "same.exe",
    }));

    let non_matching = make_event(json!({
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe README.txt",
        "EventID": 4624,
        "TargetUserName": "nobody",
        "ComputerName": "SERVER-2",
        "SourceImage": "foo.exe",
        "TargetImage": "bar.exe",
    }));

    // Warm the plan cache with one evaluation before timing starts.
    executor.evaluate(&stream_rule, &matching_ps);
    executor.evaluate(&multi_rule, &matching_ps);
    executor.evaluate(&agg_rule, &matching_ps);
    executor.evaluate(&near_rule, &matching_ps);
    executor.evaluate(&fieldref_rule, &matching_ps);
    executor.evaluate(&regex_rule, &matching_ps);

    let mut group = c.benchmark_group("evaluate");

    group.bench_function("stream/match", |b| {
        b.iter(|| executor.evaluate(&stream_rule, &matching_ps))
    });
    group.bench_function("stream/no_match", |b| {
        b.iter(|| executor.evaluate(&stream_rule, &non_matching))
    });
    group.bench_function("multi_modifier/match", |b| {
        b.iter(|| executor.evaluate(&multi_rule, &matching_ps))
    });
    group.bench_function("aggregate_count/match", |b| {
        b.iter(|| executor.evaluate(&agg_rule, &matching_ps))
    });
    group.bench_function("near_temporal/match", |b| {
        b.iter(|| executor.evaluate(&near_rule, &matching_ps))
    });
    group.bench_function("fieldref/match", |b| {
        b.iter(|| executor.evaluate(&fieldref_rule, &matching_ps))
    });
    group.bench_function("regex/match", |b| {
        b.iter(|| executor.evaluate(&regex_rule, &matching_ps))
    });

    group.finish();
}

/// Simulated throughput: N events evaluated against one rule (cache warm).
/// Reveals amortized cost and any lock contention in aggregation buffers.
fn bench_throughput(c: &mut Criterion) {
    let compiler = SigmaCompiler;
    let executor = RuleExecutor::default();

    let stream_rule = make_rule(&compiler, STREAM_RULE);
    let agg_rule = make_rule(&compiler, AGGREGATE_RULE);

    let event = make_event(json!({
        "Image": "powershell.exe",
        "CommandLine": "powershell -enc AAAA",
        "EventID": 4625,
        "TargetUserName": "admin",
    }));

    // Warm cache.
    executor.evaluate(&stream_rule, &event);
    executor.evaluate(&agg_rule, &event);

    let mut group = c.benchmark_group("throughput");
    group.sample_size(20);

    for n in [10u64, 100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("stream_rule/events", n), &n, |b, &n| {
            b.iter(|| {
                for _ in 0..n {
                    executor.evaluate(&stream_rule, &event);
                }
            })
        });
    }

    for n in [10u64, 100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("aggregate_rule/events", n), &n, |b, &n| {
            b.iter(|| {
                for _ in 0..n {
                    executor.evaluate(&agg_rule, &event);
                }
            })
        });
    }

    group.finish();
}

/// How much does a cold-cache (first-call plan deserialisation) cost vs warm?
fn bench_cache_miss(c: &mut Criterion) {
    let compiler = SigmaCompiler;
    let event = make_event(json!({
        "Image": "powershell.exe",
        "CommandLine": "powershell -enc AAAA",
    }));

    c.bench_function("evaluate/cold_cache_miss", |b| {
        b.iter(|| {
            // Fresh executor = empty cache every iteration.
            let executor = RuleExecutor::default();
            let rule = make_rule(&compiler, STREAM_RULE);
            executor.evaluate(&rule, &event)
        })
    });

    let compiler2 = SigmaCompiler;
    let executor_warm = RuleExecutor::default();
    let warm_rule = make_rule(&compiler2, STREAM_RULE);
    executor_warm.evaluate(&warm_rule, &event); // seed cache

    c.bench_function("evaluate/warm_cache_hit", |b| {
        b.iter(|| executor_warm.evaluate(&warm_rule, &event))
    });
}

criterion_group!(
    benches,
    bench_compile,
    bench_evaluate,
    bench_throughput,
    bench_cache_miss,
);
criterion_main!(benches);
