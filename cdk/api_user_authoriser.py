from constructs import Construct
from aws_cdk import (
    Duration,
    aws_lambda as _lambda,
    aws_apigateway as apigw,
)
from cdk.environment_variables import RuntimeEnvVars


class ApiUserAuthorizer(Construct):

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self._handler = _lambda.Function(
            self, "UserAuthorizerLambda",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler='ggi_apigw_user_authoriser_lambda.handler',
            code=_lambda.Code.from_asset('cloud/lambdas'),
            environment={
                env.log_level.name: env.log_level.value,
                env.cognito_pool_id.name: env.cognito_pool_id.value,
                env.cognito_pool_operator_client_id.name: env.cognito_pool_operator_client_id.value,
                env.cognito_pool_url.name: env.cognito_pool_url.value,
            },
        )

        self._auth = apigw.RequestAuthorizer(self, "UserCustomAuth",
                                             handler=self._handler,
                                             identity_sources=[apigw.IdentitySource.query_string("code")],
                                             results_cache_ttl=Duration.seconds(0)
                                             )

    @property
    def authorizer(self):
        return self._auth
