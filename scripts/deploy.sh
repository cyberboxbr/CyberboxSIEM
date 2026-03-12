#!/bin/bash
# CyberboxSIEM — EC2 deploy script
# Called by GitHub Actions via SSM or manually on the instance.
# Usage: IMAGE_TAG=abc123 bash deploy.sh
set -euo pipefail

cd /opt/cyberbox

ECR_REGISTRY="619425982006.dkr.ecr.us-east-1.amazonaws.com"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "=== ECR login ==="
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "=== Pulling images (tag: $IMAGE_TAG) ==="
for svc in cyberbox-api cyberbox-worker cyberbox-collector cyberbox-ui; do
  docker pull "$ECR_REGISTRY/$svc:$IMAGE_TAG"
done

echo "=== Deploying ==="
export ECR_REGISTRY IMAGE_TAG
docker compose --env-file .env -f docker-compose.prod.yml up -d --remove-orphans

# Restart nginx so it resolves new container IPs (Docker DNS caching)
echo "=== Restarting nginx ==="
docker compose -f docker-compose.prod.yml restart nginx

echo "=== Waiting for health ==="
sleep 10

# Check API health
for attempt in $(seq 1 12); do
  if docker compose -f docker-compose.prod.yml exec -T cyberbox-api \
    wget -qO- http://localhost:8080/healthz 2>/dev/null; then
    echo ""
    echo "API healthy"
    break
  fi
  echo "Waiting for API... attempt $attempt/12"
  sleep 5
done

echo ""
echo "=== Container status ==="
docker compose -f docker-compose.prod.yml ps

echo "=== Deploy complete: $IMAGE_TAG ==="
