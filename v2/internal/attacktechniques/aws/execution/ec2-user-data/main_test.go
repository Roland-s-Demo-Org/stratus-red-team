package aws

// Unit tests for the EC2 User Data attack technique
// These tests verify that the EC2 instance is properly configured with IMDSv2
// to mitigate SSRF (Server-Side Request Forgery) attacks against the Instance
// Metadata Service.
//
// The tests validate that:
// - IMDSv2 is enforced (http_tokens = "required")
// - Metadata endpoint is enabled but secured
// - Hop limit is set to 1 to prevent proxy forwarding
// - Configuration follows AWS security best practices
//
// Run these tests with: go test -v

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMDSv2Configuration verifies that the EC2 instance is configured with IMDSv2
// to mitigate SSRF attacks against the instance metadata service
func TestIMDSv2Configuration(t *testing.T) {
	terraformCode := string(tf)

	// Verify that metadata_options block exists
	assert.Contains(t, terraformCode, "metadata_options", 
		"EC2 instance should have metadata_options block configured")

	// Verify that http_tokens is set to "required" (IMDSv2)
	assert.Contains(t, terraformCode, `http_tokens                 = "required"`,
		"EC2 instance should require IMDSv2 tokens (http_tokens = required)")

	// Verify that http_endpoint is enabled
	assert.Contains(t, terraformCode, `http_endpoint               = "enabled"`,
		"EC2 instance metadata endpoint should be enabled")

	// Verify that http_put_response_hop_limit is set to 1
	assert.Contains(t, terraformCode, `http_put_response_hop_limit = 1`,
		"EC2 instance should have http_put_response_hop_limit set to 1")
}

// TestMetadataOptionsBlockStructure verifies the metadata_options block is properly
// structured within the aws_instance resource
func TestMetadataOptionsBlockStructure(t *testing.T) {
	terraformCode := string(tf)

	// Find the aws_instance resource
	instanceRegex := regexp.MustCompile(`resource\s+"aws_instance"\s+"instance"\s+\{[^}]*metadata_options\s+\{[^}]*\}[^}]*\}`)
	matches := instanceRegex.FindString(terraformCode)
	
	require.NotEmpty(t, matches, "aws_instance resource should contain metadata_options block")

	// Verify all three required settings are present in the metadata_options block
	metadataOptionsRegex := regexp.MustCompile(`metadata_options\s+\{([^}]*)\}`)
	metadataMatches := metadataOptionsRegex.FindStringSubmatch(terraformCode)
	
	require.Len(t, metadataMatches, 2, "Should find metadata_options block")
	
	metadataContent := metadataMatches[1]
	assert.Contains(t, metadataContent, `http_endpoint`, "metadata_options should configure http_endpoint")
	assert.Contains(t, metadataContent, `http_tokens`, "metadata_options should configure http_tokens")
	assert.Contains(t, metadataContent, `http_put_response_hop_limit`, "metadata_options should configure http_put_response_hop_limit")
}

// TestNoIMDSv1Fallback ensures that IMDSv1 is not allowed as a fallback
func TestNoIMDSv1Fallback(t *testing.T) {
	terraformCode := string(tf)

	// Ensure http_tokens is not set to "optional" which would allow IMDSv1
	assert.NotContains(t, terraformCode, `http_tokens                 = "optional"`,
		"EC2 instance should not allow IMDSv1 (http_tokens should not be optional)")
	
	// Ensure http_tokens is not set to empty/default which would allow IMDSv1
	metadataOptionsRegex := regexp.MustCompile(`metadata_options\s+\{([^}]*)\}`)
	metadataMatches := metadataOptionsRegex.FindStringSubmatch(terraformCode)
	
	if len(metadataMatches) >= 2 {
		metadataContent := metadataMatches[1]
		// Check that http_tokens is explicitly set
		httpTokensRegex := regexp.MustCompile(`http_tokens\s+=\s+"([^"]+)"`)
		tokenMatches := httpTokensRegex.FindStringSubmatch(metadataContent)
		
		require.Len(t, tokenMatches, 2, "http_tokens should be explicitly set")
		assert.Equal(t, "required", tokenMatches[1], "http_tokens must be set to 'required'")
	}
}

// TestInstanceHasIAMRole verifies that the instance uses an IAM instance profile
// which makes it vulnerable to SSRF attacks if IMDSv2 is not enforced
func TestInstanceHasIAMRole(t *testing.T) {
	terraformCode := string(tf)

	// Verify that the instance has an IAM instance profile
	assert.Contains(t, terraformCode, "iam_instance_profile",
		"EC2 instance should have an IAM instance profile configured")
	
	// Verify that aws_iam_instance_profile resource exists
	assert.Contains(t, terraformCode, `resource "aws_iam_instance_profile"`,
		"Terraform should define an IAM instance profile resource")
	
	// Verify that aws_iam_role resource exists
	assert.Contains(t, terraformCode, `resource "aws_iam_role"`,
		"Terraform should define an IAM role resource")
}

// TestTerraformCodeIsValid performs basic validation that the Terraform code is well-formed
func TestTerraformCodeIsValid(t *testing.T) {
	terraformCode := string(tf)

	// Basic sanity checks
	assert.NotEmpty(t, terraformCode, "Terraform code should not be empty")
	
	// Check for required Terraform blocks
	assert.Contains(t, terraformCode, "terraform {", "Should contain terraform configuration block")
	assert.Contains(t, terraformCode, "provider \"aws\"", "Should contain AWS provider configuration")
	
	// Check for the main EC2 instance resource
	assert.Contains(t, terraformCode, `resource "aws_instance" "instance"`,
		"Should contain aws_instance resource named 'instance'")
	
	// Verify balanced braces (basic syntax check)
	openBraces := strings.Count(terraformCode, "{")
	closeBraces := strings.Count(terraformCode, "}")
	assert.Equal(t, openBraces, closeBraces, "Terraform code should have balanced braces")
}

// TestSSRFMitigationDocumentation verifies that the configuration follows AWS best practices
func TestSSRFMitigationDocumentation(t *testing.T) {
	terraformCode := string(tf)

	// The combination of these settings provides defense-in-depth against SSRF:
	// 1. http_tokens = "required" - Forces IMDSv2 which requires a session token
	// 2. http_put_response_hop_limit = 1 - Prevents forwarding through proxies/NAT
	// 3. http_endpoint = "enabled" - Keeps metadata service available for legitimate use

	tests := []struct {
		name     string
		setting  string
		value    string
		rationale string
	}{
		{
			name:     "IMDSv2 Required",
			setting:  "http_tokens",
			value:    "required",
			rationale: "Requiring session tokens prevents simple SSRF attacks",
		},
		{
			name:     "Hop Limit Restricted",
			setting:  "http_put_response_hop_limit",
			value:    "1",
			rationale: "Limiting hops prevents metadata access through proxies",
		},
		{
			name:     "Endpoint Enabled",
			setting:  "http_endpoint",
			value:    "enabled",
			rationale: "Endpoint must be enabled for legitimate metadata access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := regexp.MustCompile(regexp.QuoteMeta(tt.setting) + `\s+=\s+"?` + regexp.QuoteMeta(tt.value) + `"?`)
			assert.Regexp(t, pattern, terraformCode, 
				"Setting %s should be %s: %s", tt.setting, tt.value, tt.rationale)
		})
	}
}

// TestMetadataOptionsPlacement verifies that metadata_options is placed correctly
// within the aws_instance resource block
func TestMetadataOptionsPlacement(t *testing.T) {
	terraformCode := string(tf)

	// Verify that metadata_options comes after the instance configuration
	// and is part of the aws_instance resource
	instanceBlockRegex := regexp.MustCompile(`resource\s+"aws_instance"\s+"instance"\s+\{([\s\S]*?)\n\}`)
	matches := instanceBlockRegex.FindStringSubmatch(terraformCode)
	
	require.Len(t, matches, 2, "Should find aws_instance resource block")
	
	instanceContent := matches[1]
	assert.Contains(t, instanceContent, "metadata_options", 
		"metadata_options should be within the aws_instance resource block")
	
	// Verify metadata_options comes after basic instance configuration
	amiIndex := strings.Index(instanceContent, "ami")
	metadataIndex := strings.Index(instanceContent, "metadata_options")
	
	assert.Greater(t, metadataIndex, amiIndex, 
		"metadata_options should come after basic instance configuration")
}

// TestComplianceWithAWSBestPractices validates the configuration meets AWS security standards
func TestComplianceWithAWSBestPractices(t *testing.T) {
	terraformCode := string(tf)

	// AWS recommends IMDSv2 for all EC2 instances with IAM roles
	// Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
	
	t.Run("IMDSv2 enforced for instance with IAM role", func(t *testing.T) {
		hasIAMRole := strings.Contains(terraformCode, "iam_instance_profile")
		hasIMDSv2 := strings.Contains(terraformCode, `http_tokens                 = "required"`)
		
		if hasIAMRole {
			assert.True(t, hasIMDSv2, 
				"EC2 instances with IAM roles must enforce IMDSv2 to prevent credential theft")
		}
	})
	
	t.Run("Hop limit prevents SSRF through proxies", func(t *testing.T) {
		hopLimitRegex := regexp.MustCompile(`http_put_response_hop_limit\s+=\s+(\d+)`)
		matches := hopLimitRegex.FindStringSubmatch(terraformCode)
		
		require.Len(t, matches, 2, "http_put_response_hop_limit should be set")
		
		hopLimit := matches[1]
		assert.Equal(t, "1", hopLimit, 
			"Hop limit should be 1 to prevent metadata access through proxies/NAT")
	})
}
