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
    # General
    log_level = _EnvVar('LOG_LEVEL', 'DEBUG')
    # SES
    ses_email_from = _EnvVar('SES_EMAIL_FROM', '')
    # Cognito
    cognito_pool_url = _EnvVar('COGNITO_URL', '')
    cognito_pool_id = _EnvVar('COGNITO_USER_POOL_ID', '')
    cognito_pool_operator_client_id = _EnvVar('COGNITO_CLIENT_ID', '')
    cognito_pool_gginstaller_client_id = _EnvVar('COGNITO_CLIENT_ID', '')
    # S3
    s3_bucket_provisioning_templates = _EnvVar('S3_BUCKET_NAME', '')
    provisioning_template_name = _EnvVar('PROVISIONING_TEMPLATE', 'ggi_default-iot-provisioning-template.json')
    s3_bucket_greengrass_config = _EnvVar('S3_BUCKET_NAME', '')
    greengrass_config_template_name = _EnvVar('GG_CONFIG_TEMPLATE', 'ggi_default_greengrass-config-template.yaml')
    s3_bucket_scripts = _EnvVar('S3_RESOURCES_BUCKET', '')
    installer_script_name = _EnvVar('INSTALLER_SCRIPT_NAME', 'install_gg.py')
    s3_downloads_bucket = _EnvVar('S3_DOWNLOAD_BUCKET', '')
    # DynamoDB
    dynamodb_table_name = _EnvVar('DYNAMO_TABLE_NAME', '')
    dynamodb_idx_dev_trans = _EnvVar('DYNAMO_IDX_DEV_TRANS', '')
    dynamodb_idx_thing_trans = _EnvVar('DYNAMO_IDX_THING_TRANS', '')
    dynamodb_idx_trans_dev = _EnvVar('DYNAMO_IDX_TRANS_DEV', '')



# Below is a list of Environment Variables that must be set prior to deploying the CDK.
_deploy_env_vars = ()


def check_deploy_env_vars(env_vars: tuple = _deploy_env_vars) -> None:
    missing = []
    for env_var in env_vars:
        try:
            os.environ[env_var]
        except KeyError:
            missing.append(env_var)
    if missing:
        raise RuntimeError("Deployment aborted. You need to declare the following Environment Variables: \n"
                           "{}".format(missing))
