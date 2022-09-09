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
    ses_email_from = _EnvVar('SES_EMAIL_FROM', '')
    log_level = _EnvVar('LOG_LEVEL', 'DEBUG')
    cognito_pool_url = _EnvVar('COGNITO_URL', '')
    cognito_pool_id = _EnvVar('COGNITO_USER_POOL_ID', '')
    cognito_pool_operator_client_id = _EnvVar('COGNITO_CLIENT_ID', '')
    cognito_pool_gginstaller_client_id = _EnvVar('COGNITO_CLIENT_ID', '')

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
