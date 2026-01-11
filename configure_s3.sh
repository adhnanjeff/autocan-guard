#!/bin/bash
# S3 Storage Configuration - CRITICAL EVENTS ONLY
# COST-SAFE: Only stores security incidents, not routine data

# Required: S3 bucket name
export S3_BUCKET_NAME="sdv-data-pro"

# Required: AWS credentials
export AWS_ACCESS_KEY_ID="AKIAWYHDRAXEK2YGGRNU"
export AWS_SECRET_ACCESS_KEY="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"

# Optional: AWS region (default: us-east-1)
export AWS_REGION="ap-southeast-2"

# Enable S3 backend (FILTERED - only critical events)
export STORAGE_BACKEND="s3"

echo "✅ S3 storage configured (CRITICAL EVENTS ONLY)"
echo "Bucket: $S3_BUCKET_NAME"
echo "Region: $AWS_REGION"
echo "Backend: $STORAGE_BACKEND"
echo "⚠️  COST PROTECTION: Only trust<0.8 and HIGH/CRITICAL alerts stored"