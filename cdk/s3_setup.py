# Copyright 2010-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

# This file is licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


from constructs import Construct
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    RemovalPolicy
)
from cdk.environment_variables import RuntimeEnvVars
from cdk_nag import NagSuppressions, NagPackSuppression

class S3Setup(Construct):

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create a server access logs bucket
        access_logs_bucket = s3.Bucket(self, "ServerLogs",
                                       encryption=s3.BucketEncryption.S3_MANAGED,
                                       block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                       enforce_ssl=True,
                                       )

        NagSuppressions.add_resource_suppressions(access_logs_bucket, [
            {'id': "AwsSolutions-S1",
             'reason': "Can't find how to enable logs on the logs bucket"
             },
            {'id': "AwsSolutions-S2",
             'reason': "Can't find how to enable logs on the logs bucket"
             },
        ])

        # Bucket used for storing the customised installation scripts the User will run on the device
        self._downloads_bucket = s3.Bucket(self, "DownloadsBucket",
                                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                           encryption=s3.BucketEncryption.S3_MANAGED,
                                           enforce_ssl=True,
                                           versioned=False,
                                           removal_policy=RemovalPolicy.RETAIN,
                                           server_access_logs_bucket=access_logs_bucket,
                                           server_access_logs_prefix="DownloadsBucket",
                                           )
        env.s3_downloads_bucket.value = self._downloads_bucket.bucket_name

        # Bucket hosting the installation script template(s)
        self._scripts_bucket = s3.Bucket(self, "ScriptsBucket",
                                         block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                         encryption=s3.BucketEncryption.S3_MANAGED,
                                         enforce_ssl=True,
                                         versioned=True,
                                         removal_policy=RemovalPolicy.RETAIN,
                                         server_access_logs_bucket=access_logs_bucket,
                                         server_access_logs_prefix="ScriptsBucket"
                                         )
        env.s3_bucket_scripts.value = self._scripts_bucket.bucket_name
        s3deploy.BucketDeployment(self, "DeployScripts",
                                  sources=[s3deploy.Source.asset(
                                      "edge",
                                      exclude=["__pycache__",
                                               ".DS_Store",
                                               "install_greengrass_dependencies_amzlinux2.sh"])],
                                  destination_bucket=self._scripts_bucket
                                  )

        # Bucket used to host the greengrass configuration templates
        self._gg_config_bucket = s3.Bucket(self, "GreengrassConfigBucket",
                                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                           encryption=s3.BucketEncryption.S3_MANAGED,
                                           enforce_ssl=True,
                                           versioned=True,
                                           removal_policy=RemovalPolicy.RETAIN,
                                           server_access_logs_bucket=access_logs_bucket,
                                           server_access_logs_prefix="GreengrassConfigBucket"
                                           )
        env.s3_bucket_greengrass_config.value = self._gg_config_bucket.bucket_name
        s3deploy.BucketDeployment(self, "DeployGreengrassConfig",
                                  sources=[s3deploy.Source.asset(
                                      "cloud/iot/gg_configs",
                                      exclude=["__pycache__", ".DS_Store"])],
                                  destination_bucket=self._gg_config_bucket
                                  )

        # Bucket used to host the IoT Provisioning Templates
        self._prov_templates_bucket = s3.Bucket(self, "provTemplatesBucket",
                                                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                                encryption=s3.BucketEncryption.S3_MANAGED,
                                                enforce_ssl=True,
                                                versioned=True,
                                                removal_policy=RemovalPolicy.RETAIN,
                                                server_access_logs_bucket=access_logs_bucket,
                                                server_access_logs_prefix="provTemplatesBucket"
                                                )
        env.s3_bucket_provisioning_templates.value = self._prov_templates_bucket.bucket_name
        s3deploy.BucketDeployment(self, "DeployProvisioningTemplates",
                                  sources=[s3deploy.Source.asset(
                                      "cloud/iot/iot_templates",
                                      exclude=["__pycache__", ".DS_Store"])],
                                  destination_bucket=self._prov_templates_bucket
                                  )

        # The Greengrass artifacts bucket is added to allow Greengrass Role to get objects in the Policy.
        self._greengrass_artifacts_bucket = s3.Bucket(self, "greengrassArtifactsBucket",
                                                      block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                                      encryption=s3.BucketEncryption.S3_MANAGED,
                                                      enforce_ssl=True,
                                                      versioned=False,
                                                      removal_policy=RemovalPolicy.RETAIN,
                                                      server_access_logs_bucket=access_logs_bucket,
                                                      server_access_logs_prefix="greengrassArtifactsBucket"
                                                      )
        env.s3_greengrass_artifacts_bucket.value = self._greengrass_artifacts_bucket.bucket_name

    @property
    def downloads_bucket(self) -> s3.Bucket:
        return self._downloads_bucket

    @property
    def scripts_bucket(self) -> s3.Bucket:
        return self._scripts_bucket

    @property
    def gg_config_bucket(self) -> s3.Bucket:
        return self._gg_config_bucket

    @property
    def prov_templates_bucket(self) -> s3.Bucket:
        return self._prov_templates_bucket

    @property
    def gg_artifacts_bucket(self) -> s3.Bucket:
        return self._greengrass_artifacts_bucket
