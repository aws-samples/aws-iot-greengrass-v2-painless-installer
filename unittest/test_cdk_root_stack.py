import os
import aws_cdk as core
import aws_cdk.assertions as assertions

from cdk.greengrass_installer_stack import GreengrassInstallerStack
from cdk.environment_variables import RuntimeEnvVars


def test_stack_creates_successfully():
    """Test that the stack synthesizes without errors with the modernized config."""
    os.environ.setdefault("SES_VERIFIED_EMAIL", "test@example.com")
    os.environ.setdefault("COGNITO_DOMAIN_PREFIX", "test-prefix-123")
    app = core.App()
    env = RuntimeEnvVars()
    stack = GreengrassInstallerStack(app, "TestStack", env=env)
    template = assertions.Template.from_stack(stack)

    # Verify Lambda runtime is Python 3.12
    template.has_resource_properties("AWS::Lambda::Function", {
        "Runtime": "python3.12",
    })

    # Verify Lambda architecture is ARM64
    template.has_resource_properties("AWS::Lambda::Function", {
        "Architectures": ["arm64"],
    })

    # Verify DynamoDB table has PITR enabled
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "PointInTimeRecoverySpecification": {
            "PointInTimeRecoveryEnabled": True,
        },
    })

    # Verify Cognito UserPool has advanced security enforced
    template.has_resource_properties("AWS::Cognito::UserPool", {
        "UserPoolAddOns": {
            "AdvancedSecurityMode": "ENFORCED",
        },
    })

    # Verify S3 buckets use KMS encryption (at least one)
    template.has_resource_properties("AWS::S3::Bucket", {
        "BucketEncryption": {
            "ServerSideEncryptionConfiguration": [
                {
                    "ServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    }
                }
            ]
        },
    })
