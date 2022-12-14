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

import typing

from constructs import Construct
from aws_cdk import (
    Duration,
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_logs
)
from cdk.environment_variables import RuntimeEnvVars


class ApiUserAuthorizer(Construct):

    def __init__(self, scope: Construct, id: str, env: RuntimeEnvVars,
                 runtime: _lambda.Runtime, architecture: _lambda.Architecture,
                 layers: typing.Optional[typing.Sequence[_lambda.ILayerVersion]],
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self._handler = _lambda.Function(
            self, "UserAuthorizerLambda",
            runtime=runtime,
            architecture=architecture,
            layers=layers,
            handler='ggi_apigw_user_authoriser_lambda.lambda_handler',
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_apigw_user_authoriser_lambda.py"]),
            environment={
                env.log_level.name: env.log_level.value,
                env.cognito_pool_id.name: env.cognito_pool_id.value,
                env.cognito_pool_operator_client_name.name: env.cognito_pool_operator_client_name.value,
                env.cognito_pool_url.name: env.cognito_pool_url.value,
            },
            log_retention=aws_logs.RetentionDays.THREE_MONTHS
        )

        self._auth = apigw.RequestAuthorizer(self, "UserCustomAuth",
                                             handler=self._handler,
                                             identity_sources=[apigw.IdentitySource.query_string("code")],
                                             results_cache_ttl=Duration.seconds(0)
                                             )

    @property
    def authorizer(self):
        return self._auth

    @property
    def function(self):
        return self._handler
