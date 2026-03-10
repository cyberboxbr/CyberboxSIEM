set shell := ["powershell.exe", "-NoLogo", "-Command"]

infra:
  docker compose -f infra/docker/docker-compose.yml up -d

topics:
  ./scripts/create-topics.ps1

topics-role-tuned:
  ./scripts/create-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64

topics-reset-role-tuned:
  ./scripts/reset-load-topics.ps1 -Broker localhost:19092 -ApiReplicas 1 -NormalizerReplicas 3 -StreamDetectReplicas 3 -SinkReplicas 4 -SinkWorkersPerReplica 6 -RawMinPartitions 24 -NormalizedMinPartitions 64

api:
  $env:Path='C:\Program Files\CMake\bin;' + $env:Path; cargo run --release -p cyberbox-api --features kafka-native

worker:
  $env:Path='C:\Program Files\CMake\bin;' + $env:Path; cargo run --release -p cyberbox-worker --features kafka-native

api-dev:
  $env:Path='C:\Program Files\CMake\bin;' + $env:Path; cargo run -p cyberbox-api --features kafka-native

worker-dev:
  $env:Path='C:\Program Files\CMake\bin;' + $env:Path; cargo run -p cyberbox-worker --features kafka-native

api-dev-container:
  ./scripts/start-api-dev-container.ps1

worker-dev-replicas replicas='4' group_id='cyberbox-worker-v2':
  ./scripts/start-worker-dev-replicas.ps1 -Replicas {{replicas}} -WorkerGroupId {{group_id}}

worker-role-stack group_id='cyberbox-worker-v3':
  ./scripts/start-worker-role-stack.ps1 -WorkerGroupId {{group_id}} -ExposeRoleMetrics

pipeline-health group_id='cyberbox-worker-v3':
  ./scripts/check-worker-groups.ps1 -GroupBase {{group_id}}

wait-pipeline group_id='cyberbox-worker-v3':
  ./scripts/wait-worker-groups.ps1 -GroupBase {{group_id}} -TimeoutSeconds 1800

pipeline-health-tuned group_id='cyberbox-worker-v3':
  ./scripts/check-worker-groups.ps1 -GroupBase {{group_id}} -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24

wait-pipeline-tuned group_id='cyberbox-worker-v3':
  ./scripts/wait-worker-groups.ps1 -GroupBase {{group_id}} -MinNormalizerMembers 3 -MinStreamDetectMembers 3 -MinSinkMembers 24 -TimeoutSeconds 1800

api-mock:
  cargo run -p cyberbox-api

worker-mock:
  cargo run -p cyberbox-worker

ui:
  cd web/cyberbox-ui; npm run dev

test-api:
  cargo test -p cyberbox-api

build-ui:
  cd web/cyberbox-ui; npm run build

smoke:
  cargo test -p cyberbox-api
  cd web/cyberbox-ui; npm ci; npm run build

load-eps-async:
  cargo run --release -p cyberbox-loadgen -- --duration-seconds 30 --concurrency 12 --batch-size 100

load-eps-fixed:
  cargo run --release -p cyberbox-loadgen -- --duration-seconds 60 --concurrency 24 --batch-size 100 --target-eps 15000

load-eps-max:
  cargo run --release -p cyberbox-loadgen -- --duration-seconds 120 --concurrency 48 --batch-size 100 --skip-persist-check

load-eps-max-sweep:
  ./scripts/load-max-eps.ps1 -DurationSeconds 120 -ConcurrencyLevels 24,32,48,64 -BatchSize 100 -SkipPersistenceCheck

load-soak:
  ./scripts/load-soak.ps1 -DurationSeconds 300 -TargetEps 15000 -Concurrency 24 -BatchSize 100

load-soak-6h:
  ./scripts/load-soak.ps1 -DurationSeconds 21600 -TargetEps 15000 -Concurrency 24 -BatchSize 100 -WorkerMetricsUrl http://127.0.0.1:19191/metrics

load-matrix:
  ./scripts/load-matrix.ps1 -MatrixPath config/load-matrix.json

operator-flow-smoke:
  ./scripts/operator-flow-smoke.ps1 -RuleWarmupSeconds 20 -AlertWaitSeconds 180

overload-429:
  ./scripts/load-overload-429.ps1 -RestartApiWithStrictProfile -DurationSeconds 45 -Concurrency 96 -BatchSize 200
