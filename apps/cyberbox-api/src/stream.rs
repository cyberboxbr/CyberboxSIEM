use cyberbox_core::{AppConfig, CyberboxError};
use cyberbox_models::{IncomingEvent, ReplayRequest};
#[cfg(feature = "kafka-native")]
use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
#[cfg(feature = "kafka-native")]
use std::time::{Duration, Instant};

#[cfg(feature = "kafka-native")]
use rdkafka::{
    config::ClientConfig,
    error::{KafkaError, RDKafkaErrorCode},
    producer::future_producer::DeliveryFuture,
    producer::{FutureProducer, FutureRecord, Producer},
};

#[cfg(feature = "kafka-native")]
type DeliveryTrackerFuture = BoxFuture<'static, DeliveryOutcome>;

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
struct DeliveryReporter {
    tx: tokio::sync::mpsc::Sender<TrackedDeliveryFuture>,
    publisher_label: &'static str,
    queue_size: usize,
}

#[cfg(feature = "kafka-native")]
struct TrackedDeliveryFuture {
    queued_at: Instant,
    delivery_future: DeliveryFuture,
}

#[cfg(feature = "kafka-native")]
struct DeliveryOutcome {
    duration_seconds: f64,
    state: DeliveryState,
}

#[cfg(feature = "kafka-native")]
enum DeliveryState {
    Acked,
    Failed(KafkaError),
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

    fn track(&self, delivery_future: DeliveryFuture) {
        let queue_depth = self.queue_size.saturating_sub(self.tx.capacity());
        metrics::gauge!(
            "kafka_producer_delivery_tracker_queue_depth",
            "publisher" => self.publisher_label
        )
        .set(queue_depth as f64);
        match self.tx.try_send(TrackedDeliveryFuture {
            queued_at: Instant::now(),
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
fn delivery_error_kind(err: &KafkaError) -> &'static str {
    match err.rdkafka_error_code() {
        Some(RDKafkaErrorCode::MessageTimedOut) => "message_timed_out",
        Some(RDKafkaErrorCode::UnknownTopicOrPartition) => "unknown_topic_or_partition",
        Some(RDKafkaErrorCode::NotEnoughReplicas) => "not_enough_replicas",
        Some(RDKafkaErrorCode::NotEnoughReplicasAfterAppend) => "not_enough_replicas_after_append",
        Some(_) => "other",
        None => "unknown",
    }
}

#[derive(Clone, Default)]
pub enum RawEventPublisher {
    #[default]
    Noop,
    #[cfg(feature = "kafka-native")]
    Kafka(KafkaRawEventPublisher),
}

#[derive(Clone, Default)]
pub enum ReplayRequestPublisher {
    #[default]
    Noop,
    #[cfg(feature = "kafka-native")]
    Kafka(KafkaReplayRequestPublisher),
}

impl ReplayRequestPublisher {
    pub fn from_config(config: &AppConfig) -> Result<Self, CyberboxError> {
        #[cfg(feature = "kafka-native")]
        {
            return Ok(Self::Kafka(KafkaReplayRequestPublisher::new(config)?));
        }

        #[cfg(not(feature = "kafka-native"))]
        {
            let _ = config;
            Ok(Self::Noop)
        }
    }

    pub async fn publish(&self, request: &ReplayRequest) -> Result<(), CyberboxError> {
        #[cfg(not(feature = "kafka-native"))]
        let _ = request;
        match self {
            Self::Noop => Err(CyberboxError::Internal(
                "replay publisher is unavailable; rebuild cyberbox-api with kafka-native"
                    .to_string(),
            )),
            #[cfg(feature = "kafka-native")]
            Self::Kafka(publisher) => publisher.publish(request).await,
        }
    }
}

impl RawEventPublisher {
    pub fn from_config(config: &AppConfig) -> Result<Self, CyberboxError> {
        if !config.kafka_publish_raw_enabled {
            return Ok(Self::Noop);
        }

        #[cfg(feature = "kafka-native")]
        {
            return Ok(Self::Kafka(KafkaRawEventPublisher::new(config)?));
        }

        #[cfg(not(feature = "kafka-native"))]
        {
            Err(CyberboxError::Internal(
                "kafka fast path requires api build with kafka-native feature".to_string(),
            ))
        }
    }

    pub async fn publish_raw_event(
        &self,
        _incoming_event: &IncomingEvent,
    ) -> Result<(), CyberboxError> {
        match self {
            Self::Noop => Err(CyberboxError::Internal(
                "raw kafka publisher is disabled; ingest fast path requires kafka".to_string(),
            )),
            #[cfg(feature = "kafka-native")]
            Self::Kafka(publisher) => publisher.publish(_incoming_event).await,
        }
    }
}

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
pub struct KafkaRawEventPublisher {
    producer: FutureProducer,
    topic: String,
    queue_full_max_retries: u32,
    queue_full_backoff_ms: u64,
    overload_retry_after_seconds: u64,
    delivery_reporter: DeliveryReporter,
}

#[cfg(feature = "kafka-native")]
#[derive(Clone)]
pub struct KafkaReplayRequestPublisher {
    producer: FutureProducer,
    topic: String,
    queue_full_max_retries: u32,
    queue_full_backoff_ms: u64,
    overload_retry_after_seconds: u64,
    delivery_reporter: DeliveryReporter,
}

#[cfg(feature = "kafka-native")]
impl KafkaRawEventPublisher {
    const METRIC_PUBLISHER_LABEL: &'static str = "api_raw";

    fn new(config: &AppConfig) -> Result<Self, CyberboxError> {
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
            .map_err(|err| {
                CyberboxError::Internal(format!("failed to create kafka producer: {err}"))
            })?;

        Ok(Self {
            producer,
            topic: config.kafka_raw_topic.clone(),
            queue_full_max_retries: config.kafka_producer_queue_full_max_retries,
            queue_full_backoff_ms: config.kafka_producer_queue_full_backoff_ms.max(1),
            overload_retry_after_seconds: config.kafka_producer_overload_retry_after_seconds.max(1),
            delivery_reporter: DeliveryReporter::spawn(
                Self::METRIC_PUBLISHER_LABEL,
                config.kafka_producer_delivery_tracker_queue_size,
            ),
        })
    }

    async fn publish(&self, event: &IncomingEvent) -> Result<(), CyberboxError> {
        let payload = serde_json::to_vec(event)
            .map_err(|err| CyberboxError::Internal(format!("event serialization failed: {err}")))?;
        let started = Instant::now();
        metrics::counter!(
            "kafka_producer_enqueue_attempt_total",
            "publisher" => Self::METRIC_PUBLISHER_LABEL
        )
        .increment(1);

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self
                .producer
                // Keep key unset so librdkafka can spread batches across partitions.
                .send_result(FutureRecord::<(), _>::to(&self.topic).payload(&payload))
            {
                Ok(delivery_future) => {
                    self.delivery_reporter.track(delivery_future);
                    metrics::counter!(
                        "kafka_producer_enqueue_success_total",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .increment(1);
                    if attempt > 1 {
                        metrics::counter!(
                            "kafka_producer_enqueue_success_after_retry_total",
                            "publisher" => Self::METRIC_PUBLISHER_LABEL
                        )
                        .increment(1);
                    }
                    metrics::histogram!(
                        "kafka_producer_enqueue_duration_seconds",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .record(started.elapsed().as_secs_f64());
                    metrics::gauge!(
                        "kafka_producer_in_flight_count",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .set(self.producer.in_flight_count() as f64);
                    return Ok(());
                }
                Err((err, _msg)) => {
                    let queue_full = is_queue_full_error(&err);
                    if queue_full {
                        metrics::counter!(
                            "kafka_producer_queue_full_total",
                            "publisher" => Self::METRIC_PUBLISHER_LABEL
                        )
                        .increment(1);

                        if attempt <= self.queue_full_max_retries {
                            metrics::counter!(
                                "kafka_producer_retry_total",
                                "publisher" => Self::METRIC_PUBLISHER_LABEL
                            )
                            .increment(1);
                            let backoff_ms = self
                                .queue_full_backoff_ms
                                .saturating_mul(u64::from(attempt));
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            continue;
                        }

                        metrics::counter!(
                            "kafka_producer_queue_full_exhausted_total",
                            "publisher" => Self::METRIC_PUBLISHER_LABEL
                        )
                        .increment(1);
                    }

                    metrics::counter!(
                        "kafka_producer_enqueue_error_total",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL,
                        "kind" => if queue_full { "queue_full" } else { "other" }
                    )
                    .increment(1);
                    metrics::histogram!(
                        "kafka_producer_enqueue_duration_seconds",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .record(started.elapsed().as_secs_f64());
                    metrics::gauge!(
                        "kafka_producer_in_flight_count",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .set(self.producer.in_flight_count() as f64);

                    if queue_full {
                        return Err(CyberboxError::TooManyRequests {
                            message: "ingest overloaded: kafka producer queue is saturated"
                                .to_string(),
                            retry_after_seconds: self.overload_retry_after_seconds,
                        });
                    }

                    return Err(CyberboxError::Internal(format!(
                        "kafka raw event publish failed after {attempt} attempt(s): {err}"
                    )));
                }
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
impl KafkaReplayRequestPublisher {
    const METRIC_PUBLISHER_LABEL: &'static str = "api_replay";

    fn new(config: &AppConfig) -> Result<Self, CyberboxError> {
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
            .map_err(|err| {
                CyberboxError::Internal(format!("failed to create kafka replay producer: {err}"))
            })?;

        Ok(Self {
            producer,
            topic: config.kafka_replay_topic.clone(),
            queue_full_max_retries: config.kafka_producer_queue_full_max_retries,
            queue_full_backoff_ms: config.kafka_producer_queue_full_backoff_ms.max(1),
            overload_retry_after_seconds: config.kafka_producer_overload_retry_after_seconds.max(1),
            delivery_reporter: DeliveryReporter::spawn(
                Self::METRIC_PUBLISHER_LABEL,
                config.kafka_producer_delivery_tracker_queue_size,
            ),
        })
    }

    async fn publish(&self, request: &ReplayRequest) -> Result<(), CyberboxError> {
        let payload = serde_json::to_vec(request).map_err(|err| {
            CyberboxError::Internal(format!("replay request serialization failed: {err}"))
        })?;
        let started = Instant::now();
        metrics::counter!(
            "kafka_producer_enqueue_attempt_total",
            "publisher" => Self::METRIC_PUBLISHER_LABEL
        )
        .increment(1);

        let mut attempt = 0u32;
        let message_key = request.key.as_deref().or(request.tenant_id.as_deref());
        loop {
            attempt += 1;
            let enqueue_result: Result<DeliveryFuture, KafkaError> = match message_key {
                Some(key) => self
                    .producer
                    .send_result(FutureRecord::to(&self.topic).payload(&payload).key(key))
                    .map_err(|(err, _)| err),
                None => self
                    .producer
                    .send_result(FutureRecord::<(), _>::to(&self.topic).payload(&payload))
                    .map_err(|(err, _)| err),
            };
            match enqueue_result {
                Ok(delivery_future) => {
                    self.delivery_reporter.track(delivery_future);
                    metrics::counter!(
                        "kafka_producer_enqueue_success_total",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .increment(1);
                    metrics::histogram!(
                        "kafka_producer_enqueue_duration_seconds",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .record(started.elapsed().as_secs_f64());
                    return Ok(());
                }
                Err(err) if is_queue_full_error(&err) && attempt <= self.queue_full_max_retries =>
                {
                    metrics::counter!(
                        "kafka_producer_queue_full_retry_total",
                        "publisher" => Self::METRIC_PUBLISHER_LABEL
                    )
                    .increment(1);
                    tokio::time::sleep(Duration::from_millis(self.queue_full_backoff_ms)).await;
                }
                Err(err) if is_queue_full_error(&err) => {
                    return Err(CyberboxError::TooManyRequests {
                        message: "kafka replay producer queue is full".to_string(),
                        retry_after_seconds: self.overload_retry_after_seconds,
                    });
                }
                Err(err) => {
                    return Err(CyberboxError::Internal(format!(
                        "failed to enqueue replay request: {err}"
                    )));
                }
            }
        }
    }
}

#[cfg(feature = "kafka-native")]
fn is_queue_full_error(err: &KafkaError) -> bool {
    matches!(err.rdkafka_error_code(), Some(RDKafkaErrorCode::QueueFull))
}
