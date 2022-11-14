import json

from constructs import Construct
from aws_cdk import (
    ScopedAws,
    aws_iot as iot,
    aws_iam as iam,
    aws_s3 as s3,
)
from cdk.environment_variables import RuntimeEnvVars


class IotCoreSetup(Construct):
    """
    CDK does not support creating Thing Group and Thing Type.
    Until supported the application cannot use those elements.
    """

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars,
                 gg_artifacts_bucket: s3.Bucket, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        aws_scope = ScopedAws(scope)

        device_policy_name = "ggi_GreengrassV2CoreDeviceDefaultPolicy"
        device_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:Connect",
                        "iot:Publish",
                        "iot:Subscribe",
                        "iot:Receive",
                        "greengrass:*"
                    ],
                    "Resource": [
                        "arn:aws:iot:{}:{}:*".format(aws_scope.region, aws_scope.account_id)
                    ]
                }
            ]
        }
        device_policy = iot.CfnPolicy(self, "DevicePolicy",
                                      policy_document=device_policy_doc,
                                      policy_name=device_policy_name
                                      )
        env.device_policy_name.value = device_policy.policy_name

        token_exchange_role_name = "ggi_GreengrassV2TokenExchangeRole"
        token_exchange_role = iam.Role(self, "TokenExchangeRole",
                                       assumed_by=iam.ServicePrincipal("credentials.iot.amazonaws.com"),
                                       description="Token Exchange Role required by Greengrass",
                                       role_name=token_exchange_role_name
                                       )
        env.token_exchange_role_name.value = token_exchange_role.role_name

        token_exchange_role_access_policy_doc = iam.PolicyDocument(
            statements=[iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogStreams"],
                resources=["arn:aws:logs:{}:{}:log-group:*".format(aws_scope.region, aws_scope.account_id)]
            ), iam.PolicyStatement(
                actions=["logs:PutLogEvents"],
                resources=["arn:aws:logs:{}:{}:log-group:*:log-stream:*".format(aws_scope.region, aws_scope.account_id)]
            ),iam.PolicyStatement(
                actions=["s3:GetBucketLocation"],
                resources=["*"]
            ), iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=["{}/*".format(gg_artifacts_bucket.bucket_arn)]
            )
            ]
        )
        token_exchange_role_access_policy_name = "ggi_GreengrassV2TokenExchangeRoleAccessPolicy"
        token_exchange_role_access_policy = iam.Policy(
            self, "TokenExhangeRoleAccessPolicy",
            document=token_exchange_role_access_policy_doc,
            policy_name=token_exchange_role_access_policy_name,
            roles=[token_exchange_role]
        )


        role_alias_name = "ggi_GreengrassCoreTokenExchangeRoleAlias"
        token_exchange_role_alias = iot.CfnRoleAlias(self, "TokenExchangeRoleAlias",
                                                     role_arn=token_exchange_role.role_arn,
                                                     role_alias=role_alias_name
                                                     )
        env.token_exchange_role_alias.value = token_exchange_role_alias.role_alias
        token_exchange_role_alias_policy_name = "ggi_GreengrassV2CoreTokenExchangeRoleAliasPolicy"
        token_exchange_role_alias_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iot:AssumeRoleWithCertificate",
                    "Resource": token_exchange_role_alias.role_arn
                }
            ]
        }
        token_exchange_role_alias_policy = iot.CfnPolicy(
            self, "TokenExchangeRoleAliasPolicy",
            policy_document=token_exchange_role_alias_policy_doc,
            policy_name=token_exchange_role_alias_policy_name
        )
        env.token_exchange_role_alias_policy_name.value = token_exchange_role_alias_policy.policy_name
