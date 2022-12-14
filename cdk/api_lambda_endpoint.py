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
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_logs

)
from cdk.environment_variables import _EnvVar


class ApiEndpointConfig(Construct):

    def __init__(self, scope: Construct, id: str,
                 function_name: str, runtime: _lambda.Runtime, architecture: _lambda.Architecture,
                 api_resource: apigw.Resource, api_method: str,
                 code_module: str, layers: typing.Optional[typing.Sequence[_lambda.ILayerVersion]] = None,
                 code_path: str = 'cloud/lambdas',
                 environment: typing.Optional[typing.Sequence[_EnvVar]] = None,
                 request_parameters: dict = None,
                 request_models: typing.Optional[typing.Mapping[str, apigw.IModel]] = None,
                 request_validator: apigw.RequestValidator = None,
                 authorization_type: apigw.AuthorizationType = None, authorizer: apigw.Authorizer = None,
                 authorization_scopes: typing.Optional[typing.Sequence[str]] = None,
                 **kwargs) -> None:

        super().__init__(scope, id, **kwargs)

        self._lambda_f = _lambda.Function(
            self, function_name,
            runtime=runtime,
            architecture=architecture,
            layers=layers,
            handler=code_module + ".lambda_handler",
            code=_lambda.Code.from_asset(code_path,
                                         exclude=["**", "!{}.py".format(code_module)]),
            environment=None if environment is None else {x.name: x.value for x in environment},
            log_retention=aws_logs.RetentionDays.THREE_MONTHS
        )
        self._integration = apigw.LambdaIntegration(self._lambda_f, proxy=True)
        self._method = api_resource.add_method(
            http_method=api_method,
            integration=self._integration,
            request_parameters=request_parameters,
            request_models=request_models,
            request_validator=request_validator,
            authorization_type=authorization_type,
            authorizer=authorizer,
            authorization_scopes=authorization_scopes,
        )

    @property
    def function(self) -> _lambda.Function:
        return self._lambda_f

    @property
    def method(self) -> apigw.Method:
        return self._method

