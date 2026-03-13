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

echo "=== Persisting IMAGE_TAG ==="
# Save the tag to .env so manual restarts / EC2 reboots use the same image
if grep -q '^IMAGE_TAG=' .env 2>/dev/null; then
  sed -i "s|^IMAGE_TAG=.*|IMAGE_TAG=$IMAGE_TAG|" .env
else
  echo "IMAGE_TAG=$IMAGE_TAG" >> .env
fi
if grep -q '^ECR_REGISTRY=' .env 2>/dev/null; then
  sed -i "s|^ECR_REGISTRY=.*|ECR_REGISTRY=$ECR_REGISTRY|" .env
else
  echo "ECR_REGISTRY=$ECR_REGISTRY" >> .env
fi

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
echo "=== Auth smoke test ==="
# Catch 401 regressions: /api/v1/agents must work without headers in bypass mode
AUTH_HTTP=$(docker compose -f docker-compose.prod.yml exec -T cyberbox-api \
  wget --spider -S http://localhost:8080/api/v1/agents 2>&1 | grep "HTTP/" | tail -1 | awk '{print $2}')
if [ "$AUTH_HTTP" = "200" ]; then
  echo "Auth bypass OK (200)"
else
  echo "WARNING: /api/v1/agents returned HTTP $AUTH_HTTP — auth bypass may be broken!"
fi

echo ""
echo "=== Container status ==="
docker compose -f docker-compose.prod.yml ps

echo "=== Deploy complete: $IMAGE_TAG ==="
