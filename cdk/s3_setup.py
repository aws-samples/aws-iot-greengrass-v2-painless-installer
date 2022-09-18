from constructs import Construct
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    RemovalPolicy
)
from cdk.environment_variables import RuntimeEnvVars


class S3Setup(Construct):

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Bucket used for storing the customised installation scripts the User will run on the device
        self._downloads_bucket = s3.Bucket(self, "DownloadsBucket",
                                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                           encryption=s3.BucketEncryption.S3_MANAGED,
                                           enforce_ssl=True,
                                           versioned=False,
                                           removal_policy=RemovalPolicy.RETAIN
                                           )
        env.s3_downloads_bucket.value = self._downloads_bucket.bucket_name

        # Bucket hosting the installation script template(s)
        self._scripts_bucket = s3.Bucket(self, "ScriptsBucket",
                                         block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                         encryption=s3.BucketEncryption.S3_MANAGED,
                                         enforce_ssl=True,
                                         versioned=True,
                                         removal_policy=RemovalPolicy.RETAIN
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
        self._gg_config_bucket = s3.Bucket(self, "ggConfigBucket",
                                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                           encryption=s3.BucketEncryption.S3_MANAGED,
                                           enforce_ssl=True,
                                           versioned=True,
                                           removal_policy=RemovalPolicy.RETAIN
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
                                                removal_policy=RemovalPolicy.RETAIN
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
                                                      removal_policy=RemovalPolicy.RETAIN
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
