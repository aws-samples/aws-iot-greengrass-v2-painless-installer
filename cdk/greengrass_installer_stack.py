from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_cognito as cognito,
    aws_apigateway as apigw,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_iam as iam
)
from constructs import Construct

from cdk.environment_variables import RuntimeEnvVars
from cdk.api_user_authoriser import ApiUserAuthorizer
from cdk.s3_setup import S3Setup
from cdk.dynamodb_setup import DynamodbSetup
from cdk.iot_core_setup import IotCoreSetup


class GreengrassInstallerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Set a few constants to simplify code updates
        LAMBDA_ARCH = _lambda.Architecture.X86_64
        LAMBDA_RUNTIME = _lambda.Runtime.PYTHON_3_9

        # Define the common Layer for all the Lambda
        lambda_common_layer = _lambda.LayerVersion(
            self, "LambdaUtils",
            removal_policy=RemovalPolicy.DESTROY,
            compatible_architectures=[LAMBDA_ARCH],
            compatible_runtimes=[LAMBDA_RUNTIME],
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_lambda_utils.py"]),
            description="A set of helper functions for the Greengrass installer"
        )

        # Deploy S3 resources
        s3_res = S3Setup(self, 'S3Setup', env=env)

        # Create DynamoDB Table and indexes
        ddb = DynamodbSetup(self, "ProvisioningDB", env=env)

        # Setup IoT Core roles and policies
        iot_core = IotCoreSetup(self, "IoTCoreSetup", env=env, gg_artifacts_bucket=s3_res.gg_artifacts_bucket)

        # Because of https://github.com/aws/aws-cdk/issues/10878 a cloudWatch Role mus tbe created maunally
        # for the API to be able to log to CloudWatch
        cw_role = iam.Role(
            self, "CWRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            description="Role required by CSK to enable API Gateway to log toCloudWatch",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonAPIGatewayPushToCloudWatchLogs")])
        cfn_account = apigw.CfnAccount(self, "account",
                                       cloud_watch_role_arn=cw_role.role_arn)
        # define API gateway and its Production Stage
        api_prod_logs_grp = logs.LogGroup(self, "ApiGatewayAccessLogs")
        api = apigw.RestApi(
            self, "GGIApi",
            rest_api_name="ggprovisioning",
            default_cors_preflight_options=apigw.CorsOptions(
                allow_origins=apigw.Cors.ALL_ORIGINS,
                allow_methods=apigw.Cors.ALL_METHODS
            ),
            deploy_options=apigw.StageOptions(
                access_log_destination=apigw.LogGroupLogDestination(api_prod_logs_grp),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True)
            ),
            cloud_watch_role=False
        )

        '''
        deployment = apigw.Deployment(self, "Deployment", api=api)
        apigw.Stage(self, "test",
                    deployment=deployment,
                    stage_name='test',
                    access_log_destination=apigw.LogGroupLogDestination(api_prod_logs_grp),
                    access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                        caller=True,
                        http_method=True,
                        ip=True,
                        protocol=True,
                        request_time=True,
                        resource_path=True,
                        response_length=True,
                        status=True,
                        user=True)
                    )
        '''

        # Create all the resources offered by the API Gateway
        # /manage resources are used by a human
        api_res_manage = api.root.add_resource("manage")
        api_res_manage_init = api_res_manage.add_resource("init")
        api_res_manage_init_form = api_res_manage_init.add_resource("form")
        api_res_manage_request = api_res_manage.add_resource("request")
        # /provision resources are used by the installation script
        api_res_provision = api.root.add_resource("provision")
        api_res_provision_gg = api_res_provision.add_resource("greengrass-config")
        api_res_provision_thing = api_res_provision.add_resource("register-thing")
        # /request resources are used by the installation script
        api_res_req = api.root.add_resource("request")
        api_res_req_create = api_res_req.add_resource("create")
        api_res_req_status = api_res_req.add_resource("status")
        api_res_req_update = api_res_req.add_resource("update")

        # This dependency is required when launching API Gateway with CloudWatch Logs enabled
        # as the first API ever in the account
        cfn_account.node.add_dependency(api_res_manage)

        # API Request Validator
        req_params_validator = apigw.RequestValidator(self, "qs_validator",
                                                      rest_api=api,
                                                      request_validator_name="queryStringAndHeadersValidator",
                                                      validate_request_parameters=True, )

        # Create a Provisioning model for the API
        model_prov_schema = apigw.JsonSchema(
            schema=apigw.JsonSchemaVersion.DRAFT4,
            title="Thing provisioning schema",
            type=apigw.JsonSchemaType.OBJECT,
            properties={
                "CSR": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                "deviceId": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                "transactionId": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
            }
        )

        api_model_prov = api.add_model("ThingProvisioning",
                                       schema=model_prov_schema,
                                       )

        # Configure Cognito
        cognito_pool = cognito.UserPool(self, "GGIPool",
                                        user_pool_name="ggipool",
                                        sign_in_aliases={'username': True, 'email': True},
                                        self_sign_up_enabled=False,
                                        removal_policy=RemovalPolicy.DESTROY
                                        )

        cognito_domain = cognito_pool.add_domain(
            "CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix="gginstaller")
        )

        request_scope = cognito.ResourceServerScope(scope_name="request",
                                                    scope_description="Request a new provisioning of GG"
                                                    )
        provision_scope = cognito.ResourceServerScope(scope_name="provision",
                                                      scope_description="Perform provisioning actions"
                                                      )
        manage_scope = cognito.ResourceServerScope(scope_name="manage",
                                                   scope_description="Manage provisioning"
                                                   )
        installer_server = cognito_pool.add_resource_server("ggInstallerRS",
                                                            identifier="ggInstallerRS",
                                                            scopes=[request_scope, provision_scope, manage_scope]
                                                            )

        users_group = cognito.CfnUserPoolGroup(self, "Operators", user_pool_id=cognito_pool.user_pool_id,
                                               description="Users allowed to Provision Ggrrengras devices",
                                               group_name="GreengrassProvisioningOperators"
                                               )

        # FIXME: Set callback URL correctly
        cognito_pool_client_operator = cognito_pool.add_client(
            "operator",
            access_token_validity=Duration.hours(1),
            auth_flows=cognito.AuthFlow(
                user_password=True
            ),
            generate_secret=False,
            id_token_validity=Duration.hours(1),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                callback_urls=["https://somwhere.com",
                               "https://somehereelse.com",
                               ],
                scopes=[cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID],
            ),
            refresh_token_validity=Duration.hours(1),
            user_pool_client_name="operator"
        )
        cognito_pool_client_operator.apply_removal_policy(RemovalPolicy.DESTROY)

        '''
        [api.url + api_res_manage_init_form.path,
                               api.url + api_res_manage_request.path,
                               ]
        '''

        cognito_pool_client_gginstaller = cognito_pool.add_client(
            "gginstaller",
            access_token_validity=Duration.hours(1),
            auth_flows=cognito.AuthFlow(
                user_srp=True,
                custom=True
            ),
            generate_secret=True,
            id_token_validity=Duration.hours(1),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    client_credentials=True
                ),
                scopes=[cognito.OAuthScope.resource_server(installer_server, request_scope)],
            ),
            refresh_token_validity=Duration.hours(1),
            user_pool_client_name="gginstaller"
        )
        cognito_pool_client_gginstaller.apply_removal_policy(RemovalPolicy.DESTROY)

        # Define the authorizers for this API
        api_auth_cognito = apigw.CognitoUserPoolsAuthorizer(self, "CognitoAuthorizer",
                                                            cognito_user_pools=[cognito_pool],
                                                            )

        api_auth_custom = ApiUserAuthorizer(self, "UserLambdaAuthorizer",
                                            env=env,
                                            runtime=LAMBDA_RUNTIME,
                                            architecture=LAMBDA_ARCH,
                                            layers=[lambda_common_layer])

        # Set environment variables that can now be set
        env.cognito_pool_id.value = cognito_pool.user_pool_id
        env.cognito_pool_url.value = cognito_domain.base_url()
        env.cognito_pool_operator_client_id.value = cognito_pool_client_operator.user_pool_client_id
        env.cognito_pool_gginstaller_client_id.value = cognito_pool_client_gginstaller.user_pool_client_id

        # Add GET method to manage/init which will redirect to the login page - Must not require Auth
        redirect_auth_lambda = _lambda.Function(
            self, "RedirectAuthLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            layers=[lambda_common_layer],
            handler="ggi_apigw_redirect_auth_for_init_form_lambda.handler",
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_apigw_redirect_auth_for_init_form_lambda.py"]),
            environment={
                env.log_level.name: env.log_level.value,
                env.cognito_pool_operator_client_id.name: env.cognito_pool_operator_client_id.value,
                env.cognito_pool_url.name: env.cognito_pool_url.value,
            },
        )
        redirect_auth_integration = apigw.LambdaIntegration(redirect_auth_lambda, proxy=True)
        api_res_manage_init.add_method("GET", redirect_auth_integration)

        # Add GET method to init/form to fetch the form - Must not require Auth
        get_form_lambda = _lambda.Function(
            self, "GetFormLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            layers=[lambda_common_layer],
            handler="ggi_apigw_init_get_form_lambda.handler",
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_apigw_init_get_form_lambda.py"])
        )
        get_form_integration = apigw.LambdaIntegration(get_form_lambda, proxy=True)
        api_res_manage_init_form.add_method(
            "GET", get_form_integration,
            request_parameters={"method.request.querystring.code": True},
            request_validator=req_params_validator
        )

        # Add POST method to init/form for process the form data
        process_form_lambda = _lambda.Function(
            self, "ProcessFormLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            layers=[lambda_common_layer],
            handler="ggi_apigw_init_process_form_lambda.handler",
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_apigw_init_process_form_lambda.py"])
        )
        process_form_integration = apigw.LambdaIntegration(process_form_lambda, proxy=True)
        api_res_manage_init_form.add_method(
            "POST", process_form_integration,
            request_parameters={"method.request.querystring.code": True},
            request_validator=req_params_validator,
            authorization_type=apigw.AuthorizationType.CUSTOM,
            authorizer=api_auth_custom.authorizer
        )

        # Add GET method to provision/greengrass-config
        get_ggconfig_lambda = _lambda.Function(
            self, "GetGgConfigLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            layers=[lambda_common_layer],
            handler="ggi_apigw_provision_greengrass_config_lambda.handler",
            code=_lambda.Code.from_asset('cloud/lambdas',
                                         exclude=["**", "!ggi_apigw_provision_greengrass_config_lambda.py"]),
        )
        get_ggconfig_integration = apigw.LambdaIntegration(get_ggconfig_lambda, proxy=True)
        api_res_provision_gg.add_method(
            "GET", get_ggconfig_integration,
            request_parameters={"method.request.querystring.deviceId": True,
                                "method.request.querystring.transactionId": True,
                                "method.request.header.Authorization": True},
            request_validator=req_params_validator,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito

        )

        # TODO: IoT Core config - roles & Policies
        # TODO: Environment variables on all Lambdas
