# Define here all the environment variables that cannot be automatically
# determined by CDK
import os


class _EnvVar(object):

    def __init__(self, name, value):
        self._name = name
        self._value = value

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class RuntimeEnvVars(object):
    """
    Host here the environment variables that should be set at runtime
    for instance for Lambda functions
    """
    def __init__(self):
        # General
        self.log_level = _EnvVar('LOG_LEVEL', 'DEBUG')
        # SES
        self.ses_email_from = _EnvVar('SES_SENDER_EMAIL', os.environ['SES_VERIFIED_EMAIL'])
        # Cognito
        self.cognito_pool_url = _EnvVar('COGNITO_URL', '')
        self.cognito_pool_id = _EnvVar('COGNITO_USER_POOL_ID', '')
        self.cognito_pool_operator_client_name = _EnvVar('COGNITO_CLIENT_NAME', '')
        self.cognito_pool_gginstaller_client_id = _EnvVar('COGNITO_CLIENT_ID', '')
        self.cognito_group_provisioning = _EnvVar('COGNITO_PROV_GROUP', '')
        # API Gateway

        # S3
        self.s3_bucket_provisioning_templates = _EnvVar('S3_BUCKET_NAME', '')
        self.provisioning_template_name = _EnvVar('PROVISIONING_TEMPLATE', 'ggi_default-iot-provisioning-template.json')
        self.s3_bucket_greengrass_config = _EnvVar('S3_BUCKET_NAME', '')
        self.greengrass_config_template_name = _EnvVar('GG_CONFIG_TEMPLATE',
                                                       'ggi_default_greengrass-config-template.yaml')
        self.s3_bucket_scripts = _EnvVar('S3_RESOURCES_BUCKET', '')
        self.installer_script_name = _EnvVar('INSTALLER_SCRIPT_NAME', 'install_gg.py')
        self.s3_downloads_bucket = _EnvVar('S3_DOWNLOAD_BUCKET', '')
        self.s3_greengrass_artifacts_bucket = _EnvVar('S3_GREENGRASS_ARTIFACTS_BUCKET', '')
        # DynamoDB
        self.dynamodb_table_name = _EnvVar('DYNAMO_TABLE_NAME', '')
        self.dynamodb_idx_dev_trans = _EnvVar('DYNAMO_IDX_DEV_TRANS', '')
        self.dynamodb_idx_thing_trans = _EnvVar('DYNAMO_IDX_THING_TRANS', '')
        self.dynamodb_idx_trans_dev = _EnvVar('DYNAMO_IDX_TRANS_DEV', '')
        # IoT Core Setup
        self.device_policy_name = _EnvVar('DEVICE_POLICY_NAME', '')
        self.token_exchange_role_name = _EnvVar('TOKEN_EXCHANGE_ROLE_NAME', '')
        self.token_exchange_role_alias = _EnvVar('TOKEN_EXCHANGE_ROLE_ALIAS', '')
        self.token_exchange_role_alias_policy_name = _EnvVar('TOKEN_EXCHANGE_ROLE_ALIAS_POLICY_NAME', '')

    def __str__(self):
        vl = []
        for k, v in vars(self).items():
            if isinstance(v, _EnvVar):
                vl.append("{} = {}: {}".format(k, v.name, v.value))
        return str(vl)


# Below is a list of Environment Variables that must be set prior to deploying the CDK.
_deploy_env_vars = ('SES_VERIFIED_EMAIL',)


def check_deploy_env_vars(env_vars: tuple = _deploy_env_vars) -> None:
    print("Checking presence of required Environment Variables")
    missing = []
    for env_var in env_vars:
        try:
            os.environ[env_var]
        except KeyError:
            missing.append(env_var)
    if missing:
        raise RuntimeError("Deployment aborted. You need to declare the following Environment Variables: \n"
                           "{}".format(missing))
