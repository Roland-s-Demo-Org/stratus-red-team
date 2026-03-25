# IMDSv2 Unit Tests - Summary

## Overview
This document summarizes the unit tests added to validate the IMDSv2 configuration for the EC2 User Data attack technique.

## Files Added

### 1. `v2/internal/attacktechniques/aws/execution/ec2-user-data/main_test.go`
Comprehensive unit tests that validate the IMDSv2 security configuration in the Terraform code.

**Test Functions:**
- `TestIMDSv2Configuration` - Verifies all three IMDSv2 settings are present
- `TestMetadataOptionsBlockStructure` - Validates proper block structure
- `TestNoIMDSv1Fallback` - Ensures IMDSv1 is not allowed
- `TestInstanceHasIAMRole` - Confirms IAM role usage (which necessitates IMDSv2)
- `TestTerraformCodeIsValid` - Basic Terraform syntax validation
- `TestSSRFMitigationDocumentation` - Documents and validates each security setting
- `TestMetadataOptionsPlacement` - Verifies correct placement in resource block
- `TestComplianceWithAWSBestPractices` - Validates AWS security standards compliance

### 2. `v2/internal/attacktechniques/aws/execution/ec2-user-data/TEST_README.md`
Comprehensive documentation explaining:
- What the tests validate
- How to run the tests
- Security context and rationale
- Troubleshooting guide
- AWS best practices references

### 3. `test-imdsv2.sh`
Convenience script for running the IMDSv2 tests with clear output.

## Test Coverage

The tests validate the following security configuration:

```hcl
metadata_options {
  http_endpoint               = "enabled"   # Keep metadata service available
  http_tokens                 = "required"  # Enforce IMDSv2 (no IMDSv1 fallback)
  http_put_response_hop_limit = 1          # Prevent proxy/NAT forwarding
}
```

## Security Benefits

These tests ensure that:
1. **SSRF attacks are mitigated** - IMDSv2 requires session tokens that can't be obtained via simple GET requests
2. **Credential theft is prevented** - Even if SSRF exists, attackers can't steal IAM credentials
3. **Defense in depth** - Multiple layers of protection (tokens + hop limit)
4. **Compliance** - Configuration meets AWS security best practices

## Running the Tests

```bash
# Run all tests
make test

# Run just the IMDSv2 tests
cd v2/internal/attacktechniques/aws/execution/ec2-user-data
go test -v

# Use convenience script
./test-imdsv2.sh
```

## Integration with CI/CD

The tests are automatically run as part of the existing test suite via `make test`, which is typically executed in CI/CD pipelines.

## Future Enhancements

Consider extending these tests to:
1. Other EC2 instances in the repository that use IAM roles
2. Validate IMDSv2 configuration in actual running instances (integration tests)
3. Add tests for other SSRF mitigation techniques
4. Create a linter to automatically check for IMDSv2 in new Terraform code

## References

- [AWS IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS Security Blog on IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [Stratus Red Team Testing Framework](https://github.com/stretchr/testify)
