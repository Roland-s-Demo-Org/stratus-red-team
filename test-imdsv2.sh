#!/bin/bash
# Test script for validating IMDSv2 configuration in EC2 instances
# This script runs the unit tests for the ec2-user-data attack technique

set -e

echo "=========================================="
echo "Running IMDSv2 Configuration Tests"
echo "=========================================="
echo ""

# Change to the test directory
cd "$(dirname "$0")/v2/internal/attacktechniques/aws/execution/ec2-user-data"

echo "Running unit tests..."
go test -v -run TestIMDSv2

echo ""
echo "=========================================="
echo "All IMDSv2 tests passed!"
echo "=========================================="
echo ""
echo "The EC2 instance configuration includes:"
echo "  ✓ IMDSv2 enforcement (http_tokens = required)"
echo "  ✓ Metadata endpoint enabled"
echo "  ✓ Hop limit set to 1"
echo ""
echo "This configuration mitigates SSRF attacks against"
echo "the EC2 Instance Metadata Service."
