use std::time::Duration;

use axum::{routing::get, Router};
use cyberbox_core::{telemetry, AppConfig};
#[cfg(feature = "kafka-native")]
use cyberbox_detection::RuleExecutor;
use cyberbox_detection::SigmaCompiler;
#[cfg(feature = "kafka-native")]
use cyberbox_models::RuleSchedulerHealth;
#[cfg(feature = "kafka-native")]
use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

#[cfg(feature = "kafka-native")]
const NORMALIZED_EVENT_PRODUCER_LABEL: &str = "worker_normalized";
#[cfg(feature = "kafka-native")]
type DeliveryTrackerFuture = BoxFuture<'static, DeliveryOutcome>;

#[cfg(feature = "kafka-native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerRole {
    All,
    Normalizer,
    StreamDetect,
    Scheduler,
    Sink,
}

#[cfg(feature = "kafka-native")]
impl WorkerRole {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Ok(Self::All),
            "normalizer" => Ok(Self::Normalizer),
            "stream-detect" | "stream_detect" | "streamdetect" | "stream-detection" => {
                Ok(Self::StreamDetect)
            }
            "scheduler" => Ok(Self::Scheduler),
            "sink" | "clickhouse-sink" | "clickhouse_sink" => Ok(Self::Sink),
            other => anyhow::bail!(
                "unsupported worker_role '{}'; expected one of: all, normalizer, stream-detect, scheduler, sink",
                other
            ),
        }
    }

    fn runs_normalizer(self) -> bool {
        matches!(self, Self::All | Self::Normalizer)
    }

    fn runs_stream_detect(self) -> bool {
        matches!(self, Self::All | Self::StreamDetect)
    }

    fn runs_scheduler(self) -> bool {
        matches!(self, Self::All | Self::Scheduler)
    }

    fn runs_sink(self) -> bool {
        matches!(self, Self::All | Self::Sink)
    }

    fn requires_clickhouse(self, config: &AppConfig) -> bool {
        (self.runs_stream_detect() || self.runs_scheduler() || self.runs_sink())
            && (config.clickhouse_search_enabled || config.clickhouse_sink_enabled)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let otlp = (!config.otlp_endpoint.is_empty()).then_some(config.otlp_endpoint.as_str());
    telemetry::init("cyberbox_worker", otlp);
    let metrics_handle = install_metrics_exporter()?;
    let metrics_bind_addr = config.worker_metrics_bind_addr.clone();
    tokio::spawn(async move {
        if let Err(err) = serve_metrics_endpoint(metrics_handle, metrics_bind_addr).await {
            tracing::error!(error = %err, "worker metrics endpoint exited");
        }
    });

    let compiler = SigmaCompiler;
    let _ = compiler.compile("title: baseline\ndetection:\n  selection:\n    - suspicious")?;

    #[cfg(feature = "kafka-native")]
    {
        let role = WorkerRole::parse(&config.worker_role)?;
        tracing::info!(role = ?role, "starting worker role");
        run_with_kafka(&config, role).await?;
    }

    #[cfg(not(feature = "kafka-native"))]
    {
        run_mock_mode(&config).await;
    }

    Ok(())
}

fn install_metrics_exporter() -> anyhow::Result<PrometheusHandle> {
    let builder = PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Full("scheduler_rule_last_run_duration_seconds".to_string()),
        &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
    )?;
    Ok(builder.install_recorder()?)
}

async fn serve_metrics_endpoint(
    metrics_handle: PrometheusHandle,
    bind_addr: String,
) -> anyhow::Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let handle = metrics_handle.clone();
            async move { handle.render() }
        }),
    );

    let socket: std::net::SocketAddr = bind_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(socket).await?;
    tracing::info!(%socket, "worker metrics endpoint listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
struct DeliveryReporter {
    tx: tokio::sync::mpsc::Sender<TrackedDeliveryFuture>,
    publisher_label: &'static str,
    queue_size: usize,
}

#[cfg(feature = "kafka-native")]
struct TrackedDeliveryFuture {
    queued_at: std::time::Instant,
    delivery_future: rdkafka::producer::future_producer::DeliveryFuture,
}

#[cfg(feature = "kafka-native")]
struct DeliveryOutcome {
    duration_seconds: f64,
    state: DeliveryState,
}

#[cfg(feature = "kafka-native")]
enum DeliveryState {
    Acked,
    Failed(rdkafka::error::KafkaError),
    Canceled,
}

#[cfg(feature = "kafka-native")]
impl DeliveryReporter {
    fn spawn(publisher_label: &'static str, queue_size: usize) -> Self {
        let queue_size = queue_size.max(1);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<TrackedDeliveryFuture>(queue_size);
        tokio::spawn(async move {
            let mut in_flight: FuturesUnordered<DeliveryTrackerFuture> = FuturesUnordered::new();
            loop {
                tokio::select! {
                    maybe_tracked = rx.recv() => {
                        match maybe_tracked {
                            Some(tracked) => {
                                in_flight.push(Box::pin(async move {
                                    let duration_seconds = tracked.queued_at.elapsed().as_secs_f64();
                                    let state = match tracked.delivery_future.await {
                                        Ok(Ok((_partition, _offset))) => DeliveryState::Acked,
                                        Ok(Err((err, _message))) => DeliveryState::Failed(err),
                                        Err(_canceled) => DeliveryState::Canceled,
                                    };
                                    DeliveryOutcome {
                                        duration_seconds,
                                        state,
                                    }
                                }));
                            }
                            None => break,
                        }
                    }
                    maybe_outcome = in_flight.next(), if !in_flight.is_empty() => {
                        if let Some(outcome) = maybe_outcome {
                            record_delivery_outcome(publisher_label, outcome);
                        }
                    }
                }
            }

            while let Some(outcome) = in_flight.next().await {
                record_delivery_outcome(publisher_label, outcome);
            }
        });

        Self {
            tx,
            publisher_label,
            queue_size,
        }
    }

    fn track(&self, delivery_future: rdkafka::producer::future_producer::DeliveryFuture) {
        let queue_depth = self.queue_size.saturating_sub(self.tx.capacity());
        metrics::gauge!(
            "kafka_producer_delivery_tracker_queue_depth",
            "publisher" => self.publisher_label
        )
        .set(queue_depth as f64);
        match self.tx.try_send(TrackedDeliveryFuture {
            queued_at: std::time::Instant::now(),
            delivery_future,
        }) {
            Ok(()) => {
                metrics::counter!(
                    "kafka_producer_delivery_future_enqueued_total",
                    "publisher" => self.publisher_label
                )
                .increment(1);
            }
            Err(err) => {
                let reason = match err {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => "full",
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => "closed",
                };
                metrics::counter!(
                    "kafka_producer_delivery_future_drop_total",
                    "publisher" => self.publisher_label,
                    "reason" => reason
                )
                .increment(1);
            }
        }
        let queue_depth = self.queue_size.saturating_sub(self.tx.capacity());
        metrics::gauge!(
            "kafka_producer_delivery_tracker_queue_depth",
            "publisher" => self.publisher_label
        )
        .set(queue_depth as f64);
    }
}

#[cfg(feature = "kafka-native")]
fn record_delivery_outcome(publisher_label: &'static str, outcome: DeliveryOutcome) {
    metrics::histogram!(
        "kafka_producer_delivery_duration_seconds",
        "publisher" => publisher_label
    )
    .record(outcome.duration_seconds);

    match outcome.state {
        DeliveryState::Acked => {
            metrics::counter!(
                "kafka_producer_delivery_success_total",
                "publisher" => publisher_label
            )
            .increment(1);
        }
        DeliveryState::Failed(err) => {
            metrics::counter!(
                "kafka_producer_delivery_error_total",
                "publisher" => publisher_label,
                "kind" => delivery_error_kind(&err)
            )
            .increment(1);
        }
        DeliveryState::Canceled => {
            metrics::counter!(
                "kafka_producer_delivery_canceled_total",
                "publisher" => publisher_label
            )
            .increment(1);
        }
    }
}

#[cfg(feature = "kafka-native")]
fn delivery_error_kind(err: &rdkafka::error::KafkaError) -> &'static str {
    use rdkafka::error::RDKafkaErrorCode;

    match err.rdkafka_error_code() {
        Some(RDKafkaErrorCode::MessageTimedOut) => "message_timed_out",
        Some(RDKafkaErrorCode::UnknownTopicOrPartition) => "unknown_topic_or_partition",
        Some(RDKafkaErrorCode::NotEnoughReplicas) => "not_enough_replicas",
        Some(RDKafkaErrorCode::NotEnoughReplicasAfterAppend) => "not_enough_replicas_after_append",
        Some(_) => "other",
        None => "unknown",
    }
}

#[cfg(feature = "kafka-native")]
async fn enqueue_with_backpressure(
    producer: &rdkafka::producer::FutureProducer,
    topic: &str,
    payload: &[u8],
    queue_full_max_retries: u32,
    queue_full_backoff_ms: u64,
    delivery_reporter: &DeliveryReporter,
    publisher_label: &'static str,
) -> Result<(), rdkafka::error::KafkaError> {
    use rdkafka::{
        error::RDKafkaErrorCode,
        producer::{FutureRecord, Producer},
    };

    let started = std::time::Instant::now();
    let queue_full_backoff_ms = queue_full_backoff_ms.max(1);

    metrics::counter!(
        "kafka_producer_enqueue_attempt_total",
        "publisher" => publisher_label
    )
    .increment(1);

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // Keep key unset so librdkafka can spread batches across partitions.
        match producer.send_result(FutureRecord::<(), _>::to(topic).payload(payload)) {
            Ok(delivery_future) => {
                delivery_reporter.track(delivery_future);
                metrics::counter!(
                    "kafka_producer_enqueue_success_total",
                    "publisher" => publisher_label
                )
                .increment(1);
                if attempt > 1 {
                    metrics::counter!(
                        "kafka_producer_enqueue_success_after_retry_total",
                        "publisher" => publisher_label
                    )
                    .increment(1);
                }
                metrics::histogram!(
                    "kafka_producer_enqueue_duration_seconds",
                    "publisher" => publisher_label
                )
                .record(started.elapsed().as_secs_f64());
                metrics::gauge!(
                    "kafka_producer_in_flight_count",
                    "publisher" => publisher_label
                )
                .set(producer.in_flight_count() as f64);
                return Ok(());
            }
            Err((err, _msg)) => {
                let queue_full =
                    matches!(err.rdkafka_error_code(), Some(RDKafkaErrorCode::QueueFull));

                if queue_full {
                    metrics::counter!(
                        "kafka_producer_queue_full_total",
                        "publisher" => publisher_label
                    )
                    .increment(1);

                    if attempt <= queue_full_max_retries {
                        metrics::counter!(
                            "kafka_producer_retry_total",
                            "publisher" => publisher_label
                        )
                        .increment(1);
                        let backoff_ms = queue_full_backoff_ms.saturating_mul(u64::from(attempt));
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        continue;
                    }

                    metrics::counter!(
                        "kafka_producer_queue_full_exhausted_total",
                        "publisher" => publisher_label
                    )
                    .increment(1);
                }

                metrics::counter!(
                    "kafka_producer_enqueue_error_total",
                    "publisher" => publisher_label,
                    "kind" => if queue_full { "queue_full" } else { "other" }
                )
                .increment(1);
                metrics::histogram!(
                    "kafka_producer_enqueue_duration_seconds",
                    "publisher" => publisher_label
                )
                .record(started.elapsed().as_secs_f64());
                metrics::gauge!(
                    "kafka_producer_in_flight_count",
                    "publisher" => publisher_label
                )
                .set(producer.in_flight_count() as f64);
                return Err(err);
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn run_with_kafka(config: &AppConfig, role: WorkerRole) -> anyhow::Result<()> {
    use anyhow::Context;
    use cyberbox_storage::ClickHouseEventStore;

    if role.runs_stream_detect() && !config.clickhouse_search_enabled {
        anyhow::bail!(
            "worker role {:?} requires clickhouse_search_enabled=true for rule state and alerts",
            role
        );
    }
    if role.runs_scheduler() && !config.clickhouse_search_enabled {
        anyhow::bail!(
            "worker role {:?} requires clickhouse_search_enabled=true for scheduled detections",
            role
        );
    }
    if role.runs_sink() && !config.clickhouse_sink_enabled {
        anyhow::bail!(
            "worker role {:?} requires clickhouse_sink_enabled=true for ClickHouse persistence",
            role
        );
    }

    let clickhouse_store = if role.requires_clickhouse(config) {
        let store = ClickHouseEventStore::new(
            &config.clickhouse_url,
            &config.clickhouse_user,
            &config.clickhouse_password,
            &config.clickhouse_database,
            &config.clickhouse_table,
        )
        .with_insert_settings(
            config.clickhouse_insert_async_enabled,
            config.clickhouse_insert_wait_for_async,
        )
        .with_insert_deduplication_settings(
            config.clickhouse_insert_async_deduplicate_enabled,
            config.clickhouse_insert_deduplication_token_enabled,
        )
        .with_replicated_tables_enabled(config.clickhouse_replicated_tables_enabled);
        store
            .ensure_schema()
            .await
            .context("failed to ensure clickhouse schema")?;
        Some(store)
    } else {
        None
    };

    let mut tasks = tokio::task::JoinSet::new();

    if role.runs_normalizer() {
        let normalizer_config = config.clone();
        tasks.spawn(async move { run_normalizer_loop(normalizer_config).await });
    }

    if role.runs_stream_detect() {
        let detector_config = config.clone();
        let detector_store = clickhouse_store
            .clone()
            .context("stream detection role requires clickhouse store")?;
        tasks
            .spawn(async move { run_stream_detection_loop(detector_config, detector_store).await });
    }

    if role.runs_scheduler() {
        let scheduler_config = config.clone();
        let scheduler_store = clickhouse_store
            .clone()
            .context("scheduler role requires clickhouse store")?;
        tasks.spawn(async move { run_scheduler_loop(scheduler_config, scheduler_store).await });
    }

    if role.runs_sink() {
        let sink_config = config.clone();
        let sink_store = clickhouse_store
            .clone()
            .context("sink role requires clickhouse store")?;
        let sink_worker_count = config.clickhouse_sink_worker_count.max(1);
        tracing::info!(sink_worker_count, "starting clickhouse sink workers");
        for worker_index in 0..sink_worker_count {
            let sink_config = sink_config.clone();
            let sink_store = sink_store.clone();
            tasks.spawn(
                async move { run_clickhouse_sink(sink_config, sink_store, worker_index).await },
            );
        }
    }

    if tasks.is_empty() {
        anyhow::bail!("no worker tasks scheduled for role {:?}", role);
    }

    while let Some(task_result) = tasks.join_next().await {
        match task_result {
            Ok(Ok(())) => {
                tracing::warn!("worker task exited unexpectedly without error");
            }
            Ok(Err(err)) => {
                return Err(err.context("worker task failed"));
            }
            Err(err) => {
                return Err(anyhow::anyhow!("worker task join failure: {}", err));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "kafka-native")]
fn normalizer_group_id(config: &AppConfig) -> String {
    format!("{}-normalizer", config.kafka_worker_group_id)
}

#[cfg(feature = "kafka-native")]
fn stream_detect_group_id(config: &AppConfig) -> String {
    format!("{}-stream-detect", config.kafka_worker_group_id)
}

#[cfg(feature = "kafka-native")]
fn sink_group_id(config: &AppConfig) -> String {
    format!("{}-clickhouse-sink", config.kafka_worker_group_id)
}

#[cfg(feature = "kafka-native")]
async fn run_normalizer_loop(config: AppConfig) -> anyhow::Result<()> {
    use anyhow::Context;
    use cyberbox_core::normalize;
    use cyberbox_models::IncomingEvent;
    use futures::StreamExt;
    use rdkafka::{
        config::ClientConfig,
        consumer::{Consumer, StreamConsumer},
        message::Message,
        producer::FutureProducer,
    };

    let group_id = normalizer_group_id(&config);
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &group_id)
        .set("bootstrap.servers", &config.redpanda_brokers)
        .set("enable.auto.commit", "true")
        .set("session.timeout.ms", "6000")
        .create()
        .context("failed to create raw normalizer consumer")?;

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &config.redpanda_brokers)
        .set(
            "message.timeout.ms",
            config
                .kafka_producer_message_timeout_ms
                .max(1000)
                .to_string(),
        )
        .set("acks", &config.kafka_producer_acks)
        .set(
            "enable.idempotence",
            if config.kafka_producer_enable_idempotence {
                "true"
            } else {
                "false"
            },
        )
        .set(
            "max.in.flight.requests.per.connection",
            config
                .kafka_producer_max_in_flight_requests_per_connection
                .max(1)
                .to_string(),
        )
        .set("retries", i32::MAX.to_string())
        .set("linger.ms", "10")
        .set("batch.num.messages", "10000")
        .set(
            "queue.buffering.max.messages",
            config
                .kafka_producer_queue_buffering_max_messages
                .max(1)
                .to_string(),
        )
        .set(
            "queue.buffering.max.kbytes",
            config
                .kafka_producer_queue_buffering_max_kbytes
                .max(1)
                .to_string(),
        )
        .set("compression.type", "lz4")
        .create()
        .context("failed to create normalized event producer")?;
    let producer_queue_full_max_retries = config.kafka_producer_queue_full_max_retries;
    let producer_queue_full_backoff_ms = config.kafka_producer_queue_full_backoff_ms.max(1);
    let delivery_reporter = DeliveryReporter::spawn(
        NORMALIZED_EVENT_PRODUCER_LABEL,
        config.kafka_producer_delivery_tracker_queue_size,
    );

    let geoip_enricher: Option<cyberbox_core::geoip::GeoIpEnricher> =
        if config.geoip_enabled && !config.geoip_db_path.is_empty() {
            match cyberbox_core::GeoIpEnricher::open(&config.geoip_db_path) {
                Ok(e) => {
                    tracing::info!(
                        db_path = %config.geoip_db_path,
                        "GeoIP enricher initialised"
                    );
                    Some(e)
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "GeoIP enricher failed to load; enrichment disabled"
                    );
                    None
                }
            }
        } else {
            None
        };

    consumer.subscribe(&[&config.kafka_raw_topic])?;
    tracing::info!(
        group_id = %group_id,
        raw_topic = %config.kafka_raw_topic,
        normalized_topic = %config.kafka_normalized_topic,
        brokers = %config.redpanda_brokers,
        geoip_enabled = config.geoip_enabled,
        "normalizer subscribed to raw event topic"
    );

    let mut stream = consumer.stream();
    loop {
        match stream.next().await {
            Some(Ok(msg)) => {
                if let Some(payload) = msg.payload() {
                    match serde_json::from_slice::<IncomingEvent>(payload) {
                        Ok(incoming) => {
                            metrics::counter!("worker_normalizer_events_total").increment(1);
                            let mut normalized = normalize::normalize_to_ocsf(&incoming);
                            let geoip_result = geoip_enricher
                                .as_ref()
                                .and_then(|e| e.enrich_event(&incoming.raw_payload));
                            normalized = normalize::attach_enrichment(
                                normalized,
                                vec!["stream:normalizer-v1".to_string()],
                                geoip_result,
                            );

                            match serde_json::to_vec(&normalized) {
                                Ok(normalized_payload) => {
                                    if let Err(err) = enqueue_with_backpressure(
                                        &producer,
                                        &config.kafka_normalized_topic,
                                        &normalized_payload,
                                        producer_queue_full_max_retries,
                                        producer_queue_full_backoff_ms,
                                        &delivery_reporter,
                                        NORMALIZED_EVENT_PRODUCER_LABEL,
                                    )
                                    .await
                                    {
                                        tracing::error!(
                                            error = %err,
                                            "failed to publish normalized event"
                                        );
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(
                                        error = %err,
                                        "failed to serialize normalized event"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            metrics::counter!("worker_normalizer_decode_error_total").increment(1);
                            tracing::warn!(error = %err, "failed to decode raw event payload");
                        }
                    }
                }
            }
            Some(Err(err)) => tracing::error!(error = %err, "normalizer stream error"),
            None => {
                tracing::warn!("normalizer stream ended unexpectedly; sleeping before retry");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn run_stream_detection_loop(
    config: AppConfig,
    clickhouse_store: cyberbox_storage::ClickHouseEventStore,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use cyberbox_core::TeamsNotifier;
    use cyberbox_models::EventEnvelope;
    use futures::StreamExt;
    use rdkafka::{
        config::ClientConfig,
        consumer::{Consumer, StreamConsumer},
        message::Message,
    };
    use std::collections::HashMap;

    let group_id = stream_detect_group_id(&config);
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &group_id)
        .set("bootstrap.servers", &config.redpanda_brokers)
        .set("enable.auto.commit", "true")
        .set("session.timeout.ms", "6000")
        .create()
        .context("failed to create stream detection consumer")?;

    consumer.subscribe(&[&config.kafka_normalized_topic])?;
    tracing::info!(
        group_id = %group_id,
        normalized_topic = %config.kafka_normalized_topic,
        brokers = %config.redpanda_brokers,
        "stream-detect subscribed to normalized event topic"
    );

    let teams_notifier = TeamsNotifier::from_config(&config);
    // Per-partition RuleExecutor map: aggregate/temporal state is fully isolated per
    // Kafka partition, so events for the same group_by field always land on the same
    // RuleExecutor (Kafka key-based partitioning guarantees this).  Zero cross-partition
    // contention on agg_buffers under concurrent consumption.
    let mut executors_by_partition: std::collections::HashMap<i32, RuleExecutor> =
        std::collections::HashMap::new();
    let refresh_interval_seconds = config.stream_rule_cache_refresh_interval_seconds.max(1);
    let mut stream_rule_refresh_interval =
        tokio::time::interval(Duration::from_secs(refresh_interval_seconds));
    stream_rule_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut stream_rules_by_tenant: HashMap<String, Vec<cyberbox_models::DetectionRule>> =
        HashMap::new();
    match load_stream_rules_by_tenant(&clickhouse_store).await {
        Ok(rules) => {
            metrics::gauge!("stream_rule_cache_tenant_count").set(rules.len() as f64);
            metrics::gauge!("stream_rule_cache_rule_count")
                .set(rules.values().map(std::vec::Vec::len).sum::<usize>() as f64);
            stream_rules_by_tenant = rules;
        }
        Err(err) => {
            metrics::counter!("stream_rule_cache_refresh_error_total").increment(1);
            tracing::warn!(
                error = %err,
                "failed to initialize stream rule cache; continuing with empty cache"
            );
        }
    }

    let mut stream = consumer.stream();
    loop {
        tokio::select! {
            maybe_message = stream.next() => {
                match maybe_message {
                    Some(Ok(msg)) => {
                        if let Some(payload) = msg.payload() {
                            match serde_json::from_slice::<EventEnvelope>(payload) {
                                Ok(normalized) => {
                                    if let Some(rules) = stream_rules_by_tenant.get(&normalized.tenant_id) {
                                        // Route to the partition-local executor so that aggregate
                                        // and temporal buffers are never shared across partitions.
                                        let partition = msg.partition();
                                        let executor = executors_by_partition
                                            .entry(partition)
                                            .or_insert_with(RuleExecutor::default);
                                        for rule in rules {
                                            let result = executor.evaluate(rule, &normalized);
                                            if !result.matched {
                                                continue;
                                            }

                                            metrics::counter!(
                                                "stream_rule_match_count",
                                                "tenant_id" => normalized.tenant_id.clone(),
                                                "rule_id" => rule.rule_id.to_string()
                                            )
                                            .increment(1);

                                            if let Some(alert) = executor.maybe_build_alert(
                                                rule,
                                                &normalized,
                                                format!("event:{}", normalized.event_id),
                                            ) {
                                                let mut alert = alert;
                                                match teams_notifier.send_alert(&alert).await {
                                                    Ok(()) => {
                                                        alert.routing_state.last_routed_at =
                                                            Some(chrono::Utc::now());
                                                    }
                                                    Err(err) => {
                                                        tracing::warn!(
                                                            tenant_id = %normalized.tenant_id,
                                                            rule_id = %rule.rule_id,
                                                            event_id = %normalized.event_id,
                                                            error = %err,
                                                            "teams alert routing failed"
                                                        );
                                                    }
                                                }
                                                if let Err(err) = cyberbox_storage::AlertStore::suppress_or_create_alert(
                                                    &clickhouse_store,
                                                    alert,
                                                )
                                                .await
                                                {
                                                    tracing::error!(
                                                        tenant_id = %normalized.tenant_id,
                                                        rule_id = %rule.rule_id,
                                                        event_id = %normalized.event_id,
                                                        error = %err,
                                                        "failed to persist stream detection alert"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    metrics::counter!("stream_detect_decode_error_total").increment(1);
                                    tracing::warn!(error = %err, "failed to decode normalized event payload");
                                }
                            }
                        }
                    }
                    Some(Err(err)) => tracing::error!(error = %err, "stream-detect consumer error"),
                    None => {
                        tracing::warn!("stream-detect consumer ended unexpectedly; sleeping before retry");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            _ = stream_rule_refresh_interval.tick() => {
                match load_stream_rules_by_tenant(&clickhouse_store).await {
                    Ok(rules) => {
                        metrics::counter!("stream_rule_cache_refresh_total").increment(1);
                        metrics::gauge!("stream_rule_cache_tenant_count").set(rules.len() as f64);
                        metrics::gauge!("stream_rule_cache_rule_count")
                            .set(rules.values().map(std::vec::Vec::len).sum::<usize>() as f64);
                        stream_rules_by_tenant = rules;
                        // Invalidate plan caches on all partition executors so the next
                        // evaluate() call picks up the refreshed compiled plans.
                        for exec in executors_by_partition.values() {
                            exec.invalidate_all();
                        }
                    }
                    Err(err) => {
                        metrics::counter!("stream_rule_cache_refresh_error_total").increment(1);
                        tracing::warn!(error = %err, "stream rule cache refresh failed");
                    }
                }
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn run_scheduler_loop(
    config: AppConfig,
    clickhouse_store: cyberbox_storage::ClickHouseEventStore,
) -> anyhow::Result<()> {
    use cyberbox_core::TeamsNotifier;
    use std::collections::HashMap;

    let rule_executor = RuleExecutor::default();
    let teams_notifier = TeamsNotifier::from_config(&config);

    // Restore watermarks persisted by previous runs so we resume from exactly
    // where we left off instead of re-scanning the fixed lookback window.
    let mut last_run_by_rule: HashMap<uuid::Uuid, chrono::DateTime<chrono::Utc>> =
        match clickhouse_store.load_rule_watermarks().await {
            Ok(wm) => {
                tracing::info!(
                    count = wm.len(),
                    "loaded scheduler watermarks from ClickHouse"
                );
                wm
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load scheduler watermarks — starting with empty state"
                );
                HashMap::new()
            }
        };
    let mut health_by_rule: HashMap<(String, uuid::Uuid), RuleSchedulerHealth> = HashMap::new();
    let tick_seconds = config.scheduler_tick_interval_seconds.max(1);
    let mut interval = tokio::time::interval(Duration::from_secs(tick_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tracing::info!(tick_seconds, "scheduler loop started");

    loop {
        interval.tick().await;
        if let Err(err) = run_scheduled_detection_tick(
            &config,
            &clickhouse_store,
            &rule_executor,
            &teams_notifier,
            &mut last_run_by_rule,
            &mut health_by_rule,
        )
        .await
        {
            tracing::error!(error = %err, "scheduled detection tick failed");
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn load_stream_rules_by_tenant(
    clickhouse_store: &cyberbox_storage::ClickHouseEventStore,
) -> anyhow::Result<std::collections::HashMap<String, Vec<cyberbox_models::DetectionRule>>> {
    use std::collections::HashMap;

    let rules = clickhouse_store.list_stream_rules().await?;
    let mut grouped = HashMap::<String, Vec<cyberbox_models::DetectionRule>>::new();
    for rule in rules {
        grouped
            .entry(rule.tenant_id.clone())
            .or_default()
            .push(rule);
    }
    Ok(grouped)
}

#[cfg(feature = "kafka-native")]
async fn run_scheduled_detection_tick(
    config: &AppConfig,
    clickhouse_store: &cyberbox_storage::ClickHouseEventStore,
    rule_executor: &RuleExecutor,
    teams_notifier: &cyberbox_core::TeamsNotifier,
    last_run_by_rule: &mut std::collections::HashMap<uuid::Uuid, chrono::DateTime<chrono::Utc>>,
    health_by_rule: &mut std::collections::HashMap<(String, uuid::Uuid), RuleSchedulerHealth>,
) -> anyhow::Result<()> {
    use chrono::Utc;
    use cyberbox_models::RuleScheduleConfig;
    use cyberbox_storage::AlertStore;
    use std::collections::HashSet;

    if !config.clickhouse_search_enabled {
        tracing::debug!("scheduled detection skipped: clickhouse_search_enabled=false");
        return Ok(());
    }

    const EVENTS_PER_RULE_LIMIT: u64 = 500;
    const DEFAULT_RULE_INTERVAL_SECONDS: u32 = 30;
    const DEFAULT_RULE_LOOKBACK_SECONDS: u32 = 300;

    let rules = clickhouse_store.list_scheduled_rules().await?;
    if rules.is_empty() {
        tracing::debug!("scheduled detection tick: no enabled scheduled rules");
        last_run_by_rule.clear();
        health_by_rule.clear();
        return Ok(());
    }

    let active_rule_ids: HashSet<uuid::Uuid> = rules.iter().map(|rule| rule.rule_id).collect();
    let active_rule_keys: HashSet<(String, uuid::Uuid)> = rules
        .iter()
        .map(|rule| (rule.tenant_id.clone(), rule.rule_id))
        .collect();
    last_run_by_rule.retain(|rule_id, _| active_rule_ids.contains(rule_id));
    health_by_rule.retain(|key, _| active_rule_keys.contains(key));

    let mut alerts_emitted = 0usize;
    for rule in rules {
        let tenant_label = rule.tenant_id.clone();
        let rule_id_label = rule.rule_id.to_string();
        let health_key = (rule.tenant_id.clone(), rule.rule_id);
        let health = health_by_rule.entry(health_key.clone()).or_default();
        let schedule = rule.schedule.clone().unwrap_or(RuleScheduleConfig {
            interval_seconds: DEFAULT_RULE_INTERVAL_SECONDS,
            lookback_seconds: DEFAULT_RULE_LOOKBACK_SECONDS,
        });
        let now = Utc::now();
        if let Some(last_run) = last_run_by_rule.get(&rule.rule_id) {
            let elapsed_seconds = now.signed_duration_since(*last_run).num_seconds();
            if elapsed_seconds < schedule.interval_seconds as i64 {
                metrics::counter!(
                    "scheduler_rule_skipped_by_interval_count",
                    "tenant_id" => tenant_label.clone(),
                    "rule_id" => rule_id_label.clone()
                )
                .increment(1);
                health.skipped_by_interval_count =
                    health.skipped_by_interval_count.saturating_add(1);
                if let Err(err) = clickhouse_store
                    .upsert_rule_scheduler_health(&rule.tenant_id, rule.rule_id, health)
                    .await
                {
                    tracing::warn!(
                        tenant_id = %rule.tenant_id,
                        rule_id = %rule.rule_id,
                        error = %err,
                        "failed to persist rule scheduler health"
                    );
                }
                continue;
            }
        }

        metrics::counter!(
            "scheduler_rule_run_count",
            "tenant_id" => tenant_label.clone(),
            "rule_id" => rule_id_label.clone()
        )
        .increment(1);
        health.run_count = health.run_count.saturating_add(1);

        let started = std::time::Instant::now();
        let mut matches_for_rule = 0u64;

        // Determine the event scan window.
        // When a persisted watermark exists we scan exactly [watermark, now) —
        // this prevents duplicates on restart and catches up after long outages.
        // On the very first run (no watermark) we fall back to the rule's
        // configured lookback_seconds so we don't cold-start with zero history.
        let watermark_start = last_run_by_rule.get(&rule.rule_id).copied();
        let execution_result = async {
            let events = if let Some(from) = watermark_start {
                clickhouse_store
                    .list_events_in_range(&rule.tenant_id, from, now, EVENTS_PER_RULE_LIMIT)
                    .await?
            } else {
                clickhouse_store
                    .list_recent_events(
                        &rule.tenant_id,
                        schedule.lookback_seconds as u64,
                        EVENTS_PER_RULE_LIMIT,
                    )
                    .await?
            };
            for event in events {
                let result = rule_executor.evaluate(&rule, &event);
                if !result.matched {
                    continue;
                }
                matches_for_rule += 1;

                if let Some(alert) = rule_executor.maybe_build_alert(
                    &rule,
                    &event,
                    format!("event:{}", event.event_id),
                ) {
                    let mut alert = alert;
                    match teams_notifier.send_alert(&alert).await {
                        Ok(()) => {
                            alert.routing_state.last_routed_at = Some(Utc::now());
                        }
                        Err(err) => {
                            tracing::warn!(
                                tenant_id = %rule.tenant_id,
                                rule_id = %rule.rule_id,
                                event_id = %event.event_id,
                                error = %err,
                                "teams alert routing failed"
                            );
                        }
                    }
                    clickhouse_store.suppress_or_create_alert(alert).await?;
                    alerts_emitted += 1;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        let run_duration_seconds = started.elapsed().as_secs_f64();
        metrics::gauge!(
            "scheduler_rule_last_run_duration_seconds",
            "tenant_id" => tenant_label.clone(),
            "rule_id" => rule_id_label.clone()
        )
        .set(run_duration_seconds);
        health.last_run_duration_seconds = run_duration_seconds;

        if matches_for_rule > 0 {
            metrics::counter!(
                "scheduler_rule_match_count",
                "tenant_id" => tenant_label.clone(),
                "rule_id" => rule_id_label.clone()
            )
            .increment(matches_for_rule);
            health.match_count = health.match_count.saturating_add(matches_for_rule);
        }

        if let Err(err) = execution_result {
            metrics::counter!(
                "scheduler_rule_error_count",
                "tenant_id" => tenant_label,
                "rule_id" => rule_id_label
            )
            .increment(1);
            health.error_count = health.error_count.saturating_add(1);
            tracing::error!(
                tenant_id = %rule.tenant_id,
                rule_id = %rule.rule_id,
                error = %err,
                "scheduled rule execution failed"
            );
            if let Err(persist_err) = clickhouse_store
                .upsert_rule_scheduler_health(&rule.tenant_id, rule.rule_id, health)
                .await
            {
                tracing::warn!(
                    tenant_id = %rule.tenant_id,
                    rule_id = %rule.rule_id,
                    error = %persist_err,
                    "failed to persist rule scheduler health"
                );
            }
            continue;
        }

        if let Err(err) = clickhouse_store
            .upsert_rule_scheduler_health(&rule.tenant_id, rule.rule_id, health)
            .await
        {
            tracing::warn!(
                tenant_id = %rule.tenant_id,
                rule_id = %rule.rule_id,
                error = %err,
                "failed to persist rule scheduler health"
            );
        }

        // Persist the watermark so the next restart resumes from `now`.
        // Non-fatal: if this fails we'll re-scan the window on next startup
        // (worst case: some events evaluated twice, dedupe suppresses re-alerts).
        if let Err(err) = clickhouse_store
            .upsert_rule_watermark(&rule.tenant_id, rule.rule_id, now)
            .await
        {
            tracing::warn!(
                tenant_id = %rule.tenant_id,
                rule_id = %rule.rule_id,
                error = %err,
                "failed to persist scheduler watermark"
            );
        }
        last_run_by_rule.insert(rule.rule_id, now);
    }

    tracing::info!(alerts_emitted, "scheduled detection tick completed");
    Ok(())
}

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
struct SinkOffsetRecord {
    topic: String,
    partition: i32,
    offset: i64,
}

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
struct SinkBufferedEvent {
    event: cyberbox_models::EventEnvelope,
    offset: SinkOffsetRecord,
}

#[cfg(feature = "kafka-native")]
async fn run_clickhouse_sink(
    config: AppConfig,
    clickhouse_store: cyberbox_storage::ClickHouseEventStore,
    worker_index: usize,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use cyberbox_models::EventEnvelope;
    use futures::StreamExt;
    use rdkafka::{
        config::ClientConfig,
        consumer::{CommitMode, Consumer, StreamConsumer},
        message::Message,
    };

    let sink_group_id = sink_group_id(&config);
    let sink_client_id = format!("{}-worker-{}", sink_group_id, worker_index);
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &sink_group_id)
        .set("client.id", &sink_client_id)
        .set("bootstrap.servers", &config.redpanda_brokers)
        .set("enable.auto.commit", "false")
        .set("enable.auto.offset.store", "false")
        .set("session.timeout.ms", "6000")
        .set("fetch.min.bytes", "1048576")
        .set("queued.max.messages.kbytes", "65536")
        .create()
        .context("failed to create clickhouse sink consumer")?;

    consumer.subscribe(&[&config.kafka_normalized_topic])?;
    let sink_batch_size = config.clickhouse_sink_batch_size.max(1);
    let sink_batch_max_bytes = config.clickhouse_sink_batch_max_bytes.max(1024);
    let sink_flush_interval =
        Duration::from_millis(config.clickhouse_sink_flush_interval_ms.max(10));
    let sink_max_retries = config.clickhouse_sink_max_retries.max(1);
    let sink_retry_backoff_base_ms = config.clickhouse_sink_retry_backoff_base_ms.max(1);
    let sink_retry_backoff_jitter_ms = config.clickhouse_sink_retry_backoff_jitter_ms;
    let sink_buffer_high_watermark_events = sink_batch_size.saturating_mul(4);
    let sink_buffer_low_watermark_events =
        std::cmp::max(sink_batch_size, sink_buffer_high_watermark_events / 2);
    let sink_buffer_high_watermark_bytes = sink_batch_max_bytes.saturating_mul(4);
    let sink_buffer_low_watermark_bytes =
        std::cmp::max(sink_batch_max_bytes, sink_buffer_high_watermark_bytes / 2);
    tracing::info!(
        normalized_topic = %config.kafka_normalized_topic,
        table = %config.clickhouse_table,
        sink_batch_size,
        sink_batch_max_bytes,
        sink_buffer_high_watermark_events,
        sink_buffer_low_watermark_events,
        sink_buffer_high_watermark_bytes,
        sink_buffer_low_watermark_bytes,
        sink_flush_interval_ms = config.clickhouse_sink_flush_interval_ms,
        sink_max_retries,
        sink_retry_backoff_base_ms,
        sink_retry_backoff_jitter_ms,
        worker_index,
        "clickhouse sink subscribed to normalized topic"
    );

    metrics::gauge!("clickhouse_sink_consumer_paused").set(0.0);
    metrics::gauge!("clickhouse_sink_buffer_bytes").set(0.0);
    metrics::gauge!("clickhouse_sink_pending_commit_offsets").set(0.0);
    let mut sink_consumer_paused = false;
    let mut buffer: Vec<SinkBufferedEvent> = Vec::with_capacity(sink_batch_size * 2);
    let mut buffer_bytes = 0usize;
    let mut pending_commit_offsets: Option<Vec<SinkOffsetRecord>> = None;
    let mut stream = consumer.stream();
    let mut flush_timer = tokio::time::interval(sink_flush_interval);
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if let Some(offsets) = pending_commit_offsets.take() {
            set_sink_pause_state(&consumer, &mut sink_consumer_paused, true, worker_index);
            metrics::gauge!("clickhouse_sink_pending_commit_offsets").set(offsets.len() as f64);
            match commit_sink_offsets_with_retry(
                &consumer,
                offsets.as_slice(),
                sink_max_retries,
                sink_retry_backoff_base_ms,
                sink_retry_backoff_jitter_ms,
            )
            .await
            {
                Ok(()) => {
                    metrics::gauge!("clickhouse_sink_pending_commit_offsets").set(0.0);
                }
                Err(err) => {
                    metrics::counter!("clickhouse_sink_commit_retry_loop_error_total").increment(1);
                    tracing::error!(
                        worker_index,
                        error = %err,
                        pending_offsets = offsets.len(),
                        "failed to commit pending sink offsets; keeping consumer paused"
                    );
                    pending_commit_offsets = Some(offsets);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            }
        }

        tokio::select! {
            maybe_message = stream.next() => {
                match maybe_message {
                    Some(Ok(msg)) => {
                        let topic = msg.topic().to_string();
                        let partition = msg.partition();
                        let offset = msg.offset();
                        if let Some(payload) = msg.payload() {
                            let payload_len = payload.len();
                            match serde_json::from_slice::<EventEnvelope>(payload) {
                                Ok(event) => {
                                    while sink_buffer_needs_pause(
                                        buffer.len(),
                                        buffer_bytes,
                                        sink_buffer_high_watermark_events,
                                        sink_buffer_high_watermark_bytes,
                                    ) {
                                        set_sink_pause_state(
                                            &consumer,
                                            &mut sink_consumer_paused,
                                            true,
                                            worker_index,
                                        );
                                        metrics::counter!("clickhouse_sink_backpressure_wait_total")
                                            .increment(1);
                                        if let Err(err) = flush_and_commit_clickhouse_buffer(
                                            &clickhouse_store,
                                            &consumer,
                                            &mut buffer,
                                            &mut buffer_bytes,
                                            sink_max_retries,
                                            sink_retry_backoff_base_ms,
                                            sink_retry_backoff_jitter_ms,
                                            &mut pending_commit_offsets,
                                            worker_index,
                                        )
                                        .await
                                        {
                                            tracing::error!(
                                                worker_index,
                                                error = %err,
                                                "clickhouse sink backpressure flush failed; retrying"
                                            );
                                            tokio::time::sleep(Duration::from_millis(250)).await;
                                        } else if pending_commit_offsets.is_some() {
                                            break;
                                        } else if sink_buffer_can_resume(
                                            buffer.len(),
                                            buffer_bytes,
                                            sink_buffer_low_watermark_events,
                                            sink_buffer_low_watermark_bytes,
                                        ) {
                                            set_sink_pause_state(
                                                &consumer,
                                                &mut sink_consumer_paused,
                                                false,
                                                worker_index,
                                            );
                                        }
                                    }

                                    if pending_commit_offsets.is_some() {
                                        continue;
                                    }

                                    buffer.push(SinkBufferedEvent {
                                        event,
                                        offset: SinkOffsetRecord {
                                            topic,
                                            partition,
                                            offset,
                                        },
                                    });
                                    buffer_bytes = buffer_bytes.saturating_add(payload_len);
                                    metrics::gauge!("clickhouse_sink_buffer_size").set(buffer.len() as f64);
                                    metrics::gauge!("clickhouse_sink_buffer_bytes").set(buffer_bytes as f64);

                                    if buffer.len() >= sink_batch_size || buffer_bytes >= sink_batch_max_bytes {
                                        if let Err(err) = flush_and_commit_clickhouse_buffer(
                                            &clickhouse_store,
                                            &consumer,
                                            &mut buffer,
                                            &mut buffer_bytes,
                                            sink_max_retries,
                                            sink_retry_backoff_base_ms,
                                            sink_retry_backoff_jitter_ms,
                                            &mut pending_commit_offsets,
                                            worker_index,
                                        )
                                        .await
                                        {
                                            tracing::error!(worker_index, error = %err, "failed to flush clickhouse sink batch");
                                        }
                                    }

                                    if pending_commit_offsets.is_some()
                                        || sink_buffer_needs_pause(
                                            buffer.len(),
                                            buffer_bytes,
                                            sink_buffer_high_watermark_events,
                                            sink_buffer_high_watermark_bytes,
                                        )
                                    {
                                        set_sink_pause_state(
                                            &consumer,
                                            &mut sink_consumer_paused,
                                            true,
                                            worker_index,
                                        );
                                    } else if sink_buffer_can_resume(
                                        buffer.len(),
                                        buffer_bytes,
                                        sink_buffer_low_watermark_events,
                                        sink_buffer_low_watermark_bytes,
                                    ) {
                                        set_sink_pause_state(
                                            &consumer,
                                            &mut sink_consumer_paused,
                                            false,
                                            worker_index,
                                        );
                                    }
                                }
                                Err(err) => {
                                    metrics::counter!("clickhouse_sink_decode_error_total").increment(1);
                                    tracing::warn!(
                                        worker_index,
                                        error = %err,
                                        "failed to decode normalized event payload for clickhouse sink"
                                    );
                                    match consumer.commit_message(&msg, CommitMode::Sync) {
                                        Ok(()) => {
                                            metrics::counter!("clickhouse_sink_decode_skip_commit_total")
                                                .increment(1);
                                        }
                                        Err(commit_err) => {
                                            metrics::counter!("clickhouse_sink_commit_error_total")
                                                .increment(1);
                                            tracing::warn!(
                                                worker_index,
                                                error = %commit_err,
                                                "failed to commit offset for undecodable sink event"
                                            );
                                        }
                                    }
                                }
                            }
                        } else {
                            metrics::counter!("clickhouse_sink_empty_payload_total").increment(1);
                            match consumer.commit_message(&msg, CommitMode::Sync) {
                                Ok(()) => {
                                    metrics::counter!("clickhouse_sink_empty_payload_commit_total")
                                        .increment(1);
                                }
                                Err(commit_err) => {
                                    metrics::counter!("clickhouse_sink_commit_error_total")
                                        .increment(1);
                                    tracing::warn!(
                                        worker_index,
                                        topic,
                                        partition,
                                        offset,
                                        error = %commit_err,
                                        "failed to commit offset for empty sink payload"
                                    );
                                }
                            }
                        }
                    }
                    Some(Err(err)) => {
                        metrics::counter!("clickhouse_sink_consumer_error_total").increment(1);
                        tracing::error!(worker_index, error = %err, "clickhouse sink consumer error");
                    }
                    None => {
                        tracing::warn!(worker_index, "clickhouse sink consumer stream ended; flushing buffer and waiting");
                        if let Err(err) = flush_and_commit_clickhouse_buffer(
                            &clickhouse_store,
                            &consumer,
                            &mut buffer,
                            &mut buffer_bytes,
                            sink_max_retries,
                            sink_retry_backoff_base_ms,
                            sink_retry_backoff_jitter_ms,
                            &mut pending_commit_offsets,
                            worker_index,
                        )
                        .await
                        {
                            tracing::error!(worker_index, error = %err, "failed to flush clickhouse sink batch on stream end");
                        }
                        if pending_commit_offsets.is_none() && sink_buffer_can_resume(
                            buffer.len(),
                            buffer_bytes,
                            sink_buffer_low_watermark_events,
                            sink_buffer_low_watermark_bytes,
                        ) {
                            set_sink_pause_state(
                                &consumer,
                                &mut sink_consumer_paused,
                                false,
                                worker_index,
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            _ = flush_timer.tick() => {
                if let Err(err) = flush_and_commit_clickhouse_buffer(
                    &clickhouse_store,
                    &consumer,
                    &mut buffer,
                    &mut buffer_bytes,
                    sink_max_retries,
                    sink_retry_backoff_base_ms,
                    sink_retry_backoff_jitter_ms,
                    &mut pending_commit_offsets,
                    worker_index,
                )
                .await
                {
                    tracing::error!(worker_index, error = %err, "failed to flush clickhouse sink batch on timer");
                }
                if pending_commit_offsets.is_none() && sink_buffer_can_resume(
                    buffer.len(),
                    buffer_bytes,
                    sink_buffer_low_watermark_events,
                    sink_buffer_low_watermark_bytes,
                ) {
                    set_sink_pause_state(
                        &consumer,
                        &mut sink_consumer_paused,
                        false,
                        worker_index,
                    );
                }
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn flush_and_commit_clickhouse_buffer(
    clickhouse_store: &cyberbox_storage::ClickHouseEventStore,
    consumer: &rdkafka::consumer::StreamConsumer,
    buffer: &mut Vec<SinkBufferedEvent>,
    buffer_bytes: &mut usize,
    max_retries: u32,
    retry_backoff_base_ms: u64,
    retry_backoff_jitter_ms: u64,
    pending_commit_offsets: &mut Option<Vec<SinkOffsetRecord>>,
    worker_index: usize,
) -> anyhow::Result<()> {
    if pending_commit_offsets.is_some() {
        return Ok(());
    }

    let Some(offsets) = flush_clickhouse_buffer(
        clickhouse_store,
        buffer,
        buffer_bytes,
        max_retries,
        retry_backoff_base_ms,
        retry_backoff_jitter_ms,
    )
    .await?
    else {
        return Ok(());
    };

    if let Err(err) = commit_sink_offsets_with_retry(
        consumer,
        offsets.as_slice(),
        max_retries,
        retry_backoff_base_ms,
        retry_backoff_jitter_ms,
    )
    .await
    {
        metrics::counter!("clickhouse_sink_commit_pending_total").increment(1);
        metrics::gauge!("clickhouse_sink_pending_commit_offsets").set(offsets.len() as f64);
        tracing::error!(
            worker_index,
            error = %err,
            pending_offsets = offsets.len(),
            "sink offsets not committed after flush; pausing consumer and retrying commit"
        );
        *pending_commit_offsets = Some(offsets);
    }

    Ok(())
}

#[cfg(feature = "kafka-native")]
async fn flush_clickhouse_buffer(
    clickhouse_store: &cyberbox_storage::ClickHouseEventStore,
    buffer: &mut Vec<SinkBufferedEvent>,
    buffer_bytes: &mut usize,
    max_retries: u32,
    retry_backoff_base_ms: u64,
    retry_backoff_jitter_ms: u64,
) -> anyhow::Result<Option<Vec<SinkOffsetRecord>>> {
    use anyhow::anyhow;

    if buffer.is_empty() {
        return Ok(None);
    }

    let pending_batch = std::mem::take(buffer);
    let pending_batch_bytes = *buffer_bytes;
    *buffer_bytes = 0;
    metrics::gauge!("clickhouse_sink_buffer_size").set(0.0);
    metrics::gauge!("clickhouse_sink_buffer_bytes").set(0.0);

    let batch_len = pending_batch.len();
    let mut events_to_insert = Vec::with_capacity(batch_len);
    let mut offsets_to_commit = Vec::with_capacity(batch_len);
    for record in pending_batch {
        events_to_insert.push(record.event);
        offsets_to_commit.push(record.offset);
    }
    let deduplication_token = build_sink_deduplication_token(offsets_to_commit.as_slice());

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let started = std::time::Instant::now();
        match clickhouse_store
            .insert_events_with_deduplication_token(
                events_to_insert.as_slice(),
                Some(deduplication_token.as_str()),
            )
            .await
        {
            Ok(()) => {
                metrics::counter!("clickhouse_sink_events_inserted_total")
                    .increment(batch_len as u64);
                metrics::counter!("clickhouse_sink_flush_total").increment(1);
                metrics::histogram!("clickhouse_sink_flush_duration_seconds")
                    .record(started.elapsed().as_secs_f64());
                metrics::gauge!("clickhouse_sink_last_batch_size").set(batch_len as f64);
                metrics::gauge!("clickhouse_sink_last_batch_bytes").set(pending_batch_bytes as f64);
                return Ok(Some(offsets_to_commit));
            }
            Err(err) => {
                metrics::counter!("clickhouse_sink_flush_error_total").increment(1);
                if attempt >= max_retries {
                    let mut restored = Vec::with_capacity(events_to_insert.len());
                    for (event, offset_record) in events_to_insert
                        .into_iter()
                        .zip(offsets_to_commit.into_iter())
                    {
                        restored.push(SinkBufferedEvent {
                            event,
                            offset: offset_record,
                        });
                    }
                    *buffer = restored;
                    *buffer_bytes = pending_batch_bytes;
                    metrics::gauge!("clickhouse_sink_buffer_size").set(buffer.len() as f64);
                    metrics::gauge!("clickhouse_sink_buffer_bytes").set(*buffer_bytes as f64);
                    return Err(anyhow!(
                        "clickhouse sink flush failed after {} attempts: {}",
                        attempt,
                        err
                    ));
                }
                tracing::warn!(
                    error = %err,
                    attempt,
                    max_retries,
                    batch_len,
                    "clickhouse sink flush failed, retrying"
                );
                let backoff_ms =
                    sink_retry_backoff_ms(retry_backoff_base_ms, retry_backoff_jitter_ms, attempt);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
async fn commit_sink_offsets_with_retry(
    consumer: &rdkafka::consumer::StreamConsumer,
    offsets: &[SinkOffsetRecord],
    max_retries: u32,
    retry_backoff_base_ms: u64,
    retry_backoff_jitter_ms: u64,
) -> anyhow::Result<()> {
    use anyhow::anyhow;

    if offsets.is_empty() {
        return Ok(());
    }

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match commit_sink_offsets(consumer, offsets) {
            Ok(()) => return Ok(()),
            Err(err) => {
                metrics::counter!("clickhouse_sink_commit_error_total").increment(1);
                if attempt >= max_retries {
                    return Err(anyhow!(
                        "sink offset commit failed after {} attempts: {}",
                        attempt,
                        err
                    ));
                }
                metrics::counter!("clickhouse_sink_commit_retry_total").increment(1);
                let backoff_ms =
                    sink_retry_backoff_ms(retry_backoff_base_ms, retry_backoff_jitter_ms, attempt);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
fn commit_sink_offsets(
    consumer: &rdkafka::consumer::StreamConsumer,
    records: &[SinkOffsetRecord],
) -> anyhow::Result<()> {
    use anyhow::Context;
    use rdkafka::{
        consumer::{CommitMode, Consumer},
        Offset, TopicPartitionList,
    };
    use std::collections::HashMap;

    if records.is_empty() {
        return Ok(());
    }

    let mut next_offsets = HashMap::<(String, i32), i64>::new();
    for record in records {
        let next_offset = record.offset.saturating_add(1);
        let key = (record.topic.clone(), record.partition);
        next_offsets
            .entry(key)
            .and_modify(|current| *current = (*current).max(next_offset))
            .or_insert(next_offset);
    }

    let mut offsets = TopicPartitionList::new();
    for ((topic, partition), next_offset) in next_offsets {
        offsets
            .add_partition_offset(&topic, partition, Offset::Offset(next_offset))
            .with_context(|| {
                format!(
                    "failed to build commit offset for topic={} partition={} offset={}",
                    topic, partition, next_offset
                )
            })?;
    }

    consumer
        .commit(&offsets, CommitMode::Sync)
        .context("failed to commit sink offsets")?;
    metrics::counter!("clickhouse_sink_commit_total").increment(1);
    metrics::counter!("clickhouse_sink_committed_events_total").increment(records.len() as u64);
    Ok(())
}

#[cfg(feature = "kafka-native")]
fn sink_retry_backoff_ms(base_ms: u64, jitter_ms: u64, attempt: u32) -> u64 {
    let jitter = if jitter_ms == 0 {
        0
    } else {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        now_ms % (jitter_ms + 1)
    };
    base_ms
        .saturating_mul(u64::from(attempt))
        .saturating_add(jitter)
}

#[cfg(feature = "kafka-native")]
fn build_sink_deduplication_token(offsets: &[SinkOffsetRecord]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut stable_offsets: Vec<(&str, i32, i64)> = offsets
        .iter()
        .map(|offset| (offset.topic.as_str(), offset.partition, offset.offset))
        .collect();
    stable_offsets.sort_unstable();

    let mut hasher = DefaultHasher::new();
    for (topic, partition, offset) in stable_offsets {
        topic.hash(&mut hasher);
        partition.hash(&mut hasher);
        offset.hash(&mut hasher);
    }

    format!("sink-v1-{:016x}-{}", hasher.finish(), offsets.len())
}

#[cfg(feature = "kafka-native")]
fn sink_buffer_needs_pause(
    buffer_len: usize,
    buffer_bytes: usize,
    high_watermark_events: usize,
    high_watermark_bytes: usize,
) -> bool {
    buffer_len >= high_watermark_events || buffer_bytes >= high_watermark_bytes
}

#[cfg(feature = "kafka-native")]
fn sink_buffer_can_resume(
    buffer_len: usize,
    buffer_bytes: usize,
    low_watermark_events: usize,
    low_watermark_bytes: usize,
) -> bool {
    buffer_len <= low_watermark_events && buffer_bytes <= low_watermark_bytes
}

#[cfg(feature = "kafka-native")]
fn set_sink_pause_state(
    consumer: &rdkafka::consumer::StreamConsumer,
    sink_consumer_paused: &mut bool,
    should_pause: bool,
    worker_index: usize,
) {
    use rdkafka::consumer::Consumer;

    if should_pause == *sink_consumer_paused {
        return;
    }

    let assignment = match consumer.assignment() {
        Ok(assignment) => assignment,
        Err(err) => {
            tracing::warn!(
                worker_index,
                error = %err,
                "failed to fetch sink assignment for pause/resume"
            );
            return;
        }
    };

    if assignment.elements().is_empty() {
        return;
    }

    if should_pause {
        match consumer.pause(&assignment) {
            Ok(()) => {
                *sink_consumer_paused = true;
                metrics::counter!("clickhouse_sink_consumer_pause_total").increment(1);
                metrics::gauge!("clickhouse_sink_consumer_paused").set(1.0);
            }
            Err(err) => {
                tracing::warn!(worker_index, error = %err, "failed to pause sink consumer");
            }
        }
    } else {
        match consumer.resume(&assignment) {
            Ok(()) => {
                *sink_consumer_paused = false;
                metrics::counter!("clickhouse_sink_consumer_resume_total").increment(1);
                metrics::gauge!("clickhouse_sink_consumer_paused").set(0.0);
            }
            Err(err) => {
                tracing::warn!(worker_index, error = %err, "failed to resume sink consumer");
            }
        }
    }
}

#[cfg(not(feature = "kafka-native"))]
async fn run_mock_mode(config: &AppConfig) {
    tracing::warn!(
        brokers = %config.redpanda_brokers,
        "worker started in mock-stream mode; build with --features kafka-native for real Redpanda consumption"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        tracing::info!("scheduled detection tick executed (mock mode)");
    }
}
