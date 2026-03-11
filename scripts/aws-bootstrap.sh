#!/usr/bin/env bash
# ── CyberboxSIEM — AWS Infrastructure Bootstrap ─────────────────────────────
#
# Run this ONCE to set up:
#   1. ECR repositories for all Docker images
#   2. EKS cluster with managed node group
#   3. IAM OIDC provider for GitHub Actions (keyless auth)
#   4. IAM role for GitHub Actions to push to ECR + deploy to EKS
#
# Prerequisites:
#   - AWS CLI v2 configured (aws sts get-caller-identity)
#   - eksctl installed (https://eksctl.io)
#   - kubectl installed
#   - helm installed
#
# Usage:
#   export AWS_REGION=us-east-1
#   export GITHUB_ORG=your-github-org     # e.g. "cyberboxsecurity"
#   export GITHUB_REPO=CyberboxSIEM
#   bash scripts/aws-bootstrap.sh
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

REGION="${AWS_REGION:-us-east-1}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-cyberbox-production}"
NODE_INSTANCE_TYPE="${NODE_INSTANCE_TYPE:-t3.xlarge}"
NODE_COUNT="${NODE_COUNT:-3}"
NODE_MIN="${NODE_MIN:-2}"
NODE_MAX="${NODE_MAX:-6}"
GITHUB_ORG="${GITHUB_ORG:?Set GITHUB_ORG}"
GITHUB_REPO="${GITHUB_REPO:-CyberboxSIEM}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  CyberboxSIEM — AWS Bootstrap                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Region:       $REGION"
echo "║  Account:      $ACCOUNT_ID"
echo "║  Cluster:      $CLUSTER_NAME"
echo "║  Nodes:        $NODE_COUNT × $NODE_INSTANCE_TYPE ($NODE_MIN–$NODE_MAX)"
echo "║  GitHub:       $GITHUB_ORG/$GITHUB_REPO"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
read -p "Proceed? (y/N) " -n 1 -r
echo
[[ $REPLY =~ ^[Yy]$ ]] || exit 1

# ── 1. ECR Repositories ─────────────────────────────────────────────────────

echo ""
echo "▸ Creating ECR repositories..."
for repo in cyberbox-api cyberbox-worker cyberbox-collector cyberbox-agent cyberbox-ui; do
  if aws ecr describe-repositories --repository-names "$repo" --region "$REGION" &>/dev/null; then
    echo "  ✓ $repo (exists)"
  else
    aws ecr create-repository \
      --repository-name "$repo" \
      --region "$REGION" \
      --image-scanning-configuration scanOnPush=true \
      --encryption-configuration encryptionType=AES256 \
      --output text --query 'repository.repositoryUri'
    echo "  ✓ $repo (created)"
  fi
done

# Set lifecycle policy (keep last 20 images, expire untagged after 7 days)
LIFECYCLE_POLICY='{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Expire untagged after 7 days",
      "selection": { "tagStatus": "untagged", "countType": "sinceImagePushed", "countUnit": "days", "countNumber": 7 },
      "action": { "type": "expire" }
    },
    {
      "rulePriority": 2,
      "description": "Keep last 20 tagged images",
      "selection": { "tagStatus": "tagged", "tagPrefixList": ["latest"], "countType": "imageCountMoreThan", "countNumber": 20 },
      "action": { "type": "expire" }
    }
  ]
}'

for repo in cyberbox-api cyberbox-worker cyberbox-collector cyberbox-agent cyberbox-ui; do
  aws ecr put-lifecycle-policy \
    --repository-name "$repo" \
    --lifecycle-policy-text "$LIFECYCLE_POLICY" \
    --region "$REGION" >/dev/null 2>&1 || true
done
echo "  ✓ Lifecycle policies set"

# ── 2. EKS Cluster ──────────────────────────────────────────────────────────

echo ""
echo "▸ Creating EKS cluster (this takes ~15 minutes)..."
if aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" &>/dev/null; then
  echo "  ✓ Cluster $CLUSTER_NAME already exists"
else
  eksctl create cluster \
    --name "$CLUSTER_NAME" \
    --region "$REGION" \
    --version 1.31 \
    --nodegroup-name cyberbox-nodes \
    --node-type "$NODE_INSTANCE_TYPE" \
    --nodes "$NODE_COUNT" \
    --nodes-min "$NODE_MIN" \
    --nodes-max "$NODE_MAX" \
    --managed \
    --asg-access \
    --with-oidc
  echo "  ✓ Cluster created"
fi

# Update kubeconfig
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$REGION"
echo "  ✓ kubeconfig updated"

# ── 3. GitHub Actions OIDC Provider ─────────────────────────────────────────

echo ""
echo "▸ Setting up GitHub Actions OIDC..."

OIDC_PROVIDER="token.actions.githubusercontent.com"
OIDC_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"

if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" &>/dev/null; then
  echo "  ✓ OIDC provider exists"
else
  THUMBPRINT=$(openssl s_client -servername "$OIDC_PROVIDER" -connect "$OIDC_PROVIDER:443" < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout | sed 's/://g' | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
  aws iam create-open-id-connect-provider \
    --url "https://${OIDC_PROVIDER}" \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list "$THUMBPRINT"
  echo "  ✓ OIDC provider created"
fi

# ── 4. IAM Role for GitHub Actions ──────────────────────────────────────────

echo ""
echo "▸ Creating IAM role for GitHub Actions..."

ROLE_NAME="CyberboxSIEM-GitHubActions"

TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_ORG}/${GITHUB_REPO}:*"
        }
      }
    }
  ]
}
EOF
)

PERMISSIONS_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRAuth",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "ECRPush",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeRepositories",
        "ecr:CreateRepository"
      ],
      "Resource": "arn:aws:ecr:${REGION}:${ACCOUNT_ID}:repository/cyberbox-*"
    },
    {
      "Sid": "EKSAccess",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "arn:aws:eks:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"
    }
  ]
}
EOF
)

if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
  echo "  ✓ Role $ROLE_NAME exists — updating trust policy"
  aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document "$TRUST_POLICY"
else
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "GitHub Actions for CyberboxSIEM CI/CD"
  echo "  ✓ Role created"
fi

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "CyberboxSIEM-CICD" \
  --policy-document "$PERMISSIONS_POLICY"
echo "  ✓ Permissions attached"

ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)

# ── 5. Grant the role access to EKS ─────────────────────────────────────────

echo ""
echo "▸ Granting GitHub Actions role access to EKS..."

# Create Kubernetes RBAC for the GitHub Actions role
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cyberbox-deployer
rules:
  - apiGroups: ["", "apps", "batch", "networking.k8s.io", "autoscaling", "policy"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cyberbox-deployer-binding
subjects:
  - kind: Group
    name: cyberbox-deployers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cyberbox-deployer
  apiGroup: rbac.authorization.k8s.io
EOF

# Map the IAM role to the Kubernetes group
eksctl create iamidentitymapping \
  --cluster "$CLUSTER_NAME" \
  --region "$REGION" \
  --arn "$ROLE_ARN" \
  --group cyberbox-deployers \
  --username github-actions \
  2>/dev/null || echo "  (mapping may already exist)"
echo "  ✓ EKS access granted"

# ── 6. Install cluster add-ons ───────────────────────────────────────────────

echo ""
echo "▸ Installing cluster add-ons..."

# AWS Load Balancer Controller (for ALB Ingress)
helm repo add eks https://aws.github.io/eks-charts 2>/dev/null || true
helm repo update eks
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --set clusterName="$CLUSTER_NAME" \
  --set serviceAccount.create=true \
  --set serviceAccount.name=aws-load-balancer-controller \
  2>/dev/null || echo "  (LB controller may need IAM service account — see docs)"
echo "  ✓ AWS LB Controller"

# Metrics Server (for HPA)
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml 2>/dev/null || true
echo "  ✓ Metrics Server"

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Bootstrap complete!                                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Add these GitHub repo secrets:                              ║"
echo "║                                                              ║"
echo "║    AWS_ACCOUNT_ID     = $ACCOUNT_ID"
echo "║    AWS_REGION         = $REGION"
echo "║    AWS_ROLE_ARN       = $ROLE_ARN"
echo "║    EKS_CLUSTER_NAME   = $CLUSTER_NAME"
echo "║                                                              ║"
echo "║  Then push to master — the pipeline will auto-deploy.       ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
