# Unit Tests for IMDSv2 Configuration

## Overview

This directory contains unit tests that verify the EC2 instance is properly configured with IMDSv2 (Instance Metadata Service Version 2) to mitigate SSRF (Server-Side Request Forgery) attacks.

## Test File

- `main_test.go` - Contains comprehensive tests for the IMDSv2 security configuration

## Running the Tests

From the repository root:
```bash
make test
```

Or to run just these tests:
```bash
cd v2/internal/attacktechniques/aws/execution/ec2-user-data
go test -v
```

Or use the convenience script:
```bash
./test-imdsv2.sh
```

To run a specific test:
```bash
cd v2/internal/attacktechniques/aws/execution/ec2-user-data
go test -v -run TestIMDSv2Configuration
```

## Test Coverage

### 1. TestIMDSv2Configuration
Verifies that the EC2 instance has the required IMDSv2 settings:
- `http_tokens = "required"` - Forces the use of IMDSv2 session tokens
- `http_endpoint = "enabled"` - Keeps the metadata endpoint available
- `http_put_response_hop_limit = 1` - Restricts metadata access to the instance itself

### 2. TestMetadataOptionsBlockStructure
Validates that the `metadata_options` block is properly structured within the `aws_instance` resource and contains all required configuration parameters.

### 3. TestNoIMDSv1Fallback
Ensures that IMDSv1 is not allowed as a fallback option, which would defeat the SSRF protection.

### 4. TestInstanceHasIAMRole
Confirms that the instance uses an IAM instance profile, which is why IMDSv2 protection is critical (to prevent credential theft via SSRF).

### 5. TestTerraformCodeIsValid
Performs basic validation that the Terraform code is well-formed and contains the expected resources.

### 6. TestSSRFMitigationDocumentation
Documents and validates the defense-in-depth approach to SSRF mitigation through multiple configuration settings.

## Security Context

### Why IMDSv2 is Important

EC2 instances with IAM roles are vulnerable to SSRF attacks where an attacker can:
1. Exploit a web application running on the instance
2. Make requests to the metadata service at `http://169.254.169.254`
3. Steal temporary IAM credentials
4. Use those credentials to access AWS resources

### How IMDSv2 Mitigates SSRF

IMDSv2 requires a two-step process:
1. First, obtain a session token via a PUT request with a specific TTL header
2. Then, use that token in subsequent GET requests to retrieve metadata

This prevents simple SSRF attacks because:
- Most SSRF vulnerabilities only allow GET requests
- The PUT request requires a custom header that's difficult to inject
- The hop limit prevents forwarding through proxies

### Configuration Details

```hcl
metadata_options {
  http_endpoint               = "enabled"   # Keep metadata service available
  http_tokens                 = "required"  # Enforce IMDSv2 (no IMDSv1 fallback)
  http_put_response_hop_limit = 1          # Prevent proxy/NAT forwarding
}
```

## References

- [AWS IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS Security Best Practices for IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## Maintenance

When modifying the Terraform configuration in `main.tf`, ensure:
1. The `metadata_options` block remains intact
2. All three settings are present and correctly configured
3. Run the tests to verify the changes don't break the security configuration
4. Update tests if new security requirements are added

## Troubleshooting

### Test Failures

If tests fail, check the following:

1. **TestIMDSv2Configuration fails**: The `metadata_options` block may be missing or incorrectly configured
   - Verify the block exists in `main.tf`
   - Check that all three settings are present with correct values

2. **TestNoIMDSv1Fallback fails**: IMDSv1 may be enabled as a fallback
   - Ensure `http_tokens` is set to `"required"` not `"optional"`
   - This is critical for SSRF protection

3. **TestMetadataOptionsPlacement fails**: The block may be in the wrong location
   - Ensure `metadata_options` is inside the `aws_instance` resource
   - It should come after basic instance configuration

4. **TestComplianceWithAWSBestPractices fails**: Configuration doesn't meet AWS security standards
   - Review AWS documentation on IMDSv2
   - Ensure hop limit is set to 1

### Fixing Configuration Issues

If the IMDSv2 configuration is missing or incorrect, add/update the following in the `aws_instance` resource:

```hcl
resource "aws_instance" "instance" {
  # ... other configuration ...
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```
