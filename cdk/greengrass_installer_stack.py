from aws_cdk import (
    ScopedAws,
    Duration,
    Stack,
    RemovalPolicy,
    aws_cognito as cognito,
    aws_apigateway as apigw,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_iam as iam,
    aws_ses as ses
)
from constructs import Construct

from cdk.environment_variables import RuntimeEnvVars
from cdk.api_user_authoriser import ApiUserAuthorizer
from cdk.s3_setup import S3Setup
from cdk.dynamodb_setup import DynamodbSetup
from cdk.iot_core_setup import IotCoreSetup
from cdk.api_lambda_endpoint import ApiEndpointConfig


class GreengrassInstallerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 env: RuntimeEnvVars, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define the AWs scope
        aws_scope = ScopedAws(self)

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
        dynamodb = DynamodbSetup(self, "ProvisioningDB", env=env)

        # Create SES Identity
        ses_id = ses.EmailIdentity(self, "SESIdentity",
                                   identity=ses.Identity.email(env.ses_email_from.value))
        ses_id.apply_removal_policy(RemovalPolicy.DESTROY)

        # Setup IoT Core roles and policies
        iot_core = IotCoreSetup(self, "IoTCoreSetup", env=env, gg_artifacts_bucket=s3_res.gg_artifacts_bucket)

        # Because of https://github.com/aws/aws-cdk/issues/10878 a cloudWatch Role mus tbe created manually
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

        # This dependency is required when launching API Gateway with CloudWatch Logs enabled
        # as the first API ever in the account
        cfn_account.node.add_dependency(api_res_manage)

        # API Request Validator
        req_validator_params = apigw.RequestValidator(self, "qs_validator",
                                                      rest_api=api,
                                                      request_validator_name="queryStringAndHeadersValidator",
                                                      validate_request_parameters=True, )
        req_validator_all = apigw.RequestValidator(self, "all_validator",
                                                   rest_api=api,
                                                   request_validator_name="queryStringAndHeadersAndbodyValidator",
                                                   validate_request_parameters=True,
                                                   validate_request_body=True
                                                   )

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

        api_model_thing_provisioning = api.add_model("ThingProvisioning",
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

        # OAuth scopes for API Gateway endpoints
        apigw_scope_request = "{}/{}".format(installer_server.user_pool_resource_server_id, request_scope.scope_name)

        users_group = cognito.CfnUserPoolGroup(self, "Operators", user_pool_id=cognito_pool.user_pool_id,
                                               description="Users allowed to Provision Greengrass devices",
                                               group_name="GreengrassProvisioningOperators"
                                               )
        env.cognito_group_provisionning.value = users_group.group_name

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
                                                            results_cache_ttl=Duration.seconds(0)
                                                            )

        api_auth_custom = ApiUserAuthorizer(self, "UserLambdaAuthorizer",
                                            env=env,
                                            runtime=LAMBDA_RUNTIME,
                                            architecture=LAMBDA_ARCH,
                                            layers=[lambda_common_layer])

        # Set environment variables that can now be set
        env.cognito_pool_id.value = cognito_pool.user_pool_id
        env.cognito_pool_url.value = cognito_domain.base_url()
        env.cognito_pool_gginstaller_client_id.value = cognito_pool_client_gginstaller.user_pool_client_id

        # ### API Endpoints configuration ### #

        # Set all the API Resources
        api_res_manage_init = api_res_manage.add_resource("init")
        api_res_manage_init_form = api_res_manage_init.add_resource("form")
        api_res_manage_request = api_res_manage.add_resource("request")
        # /provision resources are used by the installation script
        api_res_provision = api.root.add_resource("provision")
        api_res_provision_gg = api_res_provision.add_resource("greengrass-config")
        api_res_register_thing = api_res_provision.add_resource("register-thing")
        # /request resources are used by the installation script
        api_res_req = api.root.add_resource("request")
        api_res_req_create = api_res_req.add_resource("create")
        api_res_req_status = api_res_req.add_resource("status")
        api_res_req_update = api_res_req.add_resource("update")

        # This User Poll Client is created from a CFN Resource to avoid circular dependency between
        # Cognito Pool and API Gateway. By setting this Pool Client separately we can inform CF to wait until
        # API Gateway is deployed, which itself requires the Cognito Pool to be deployed.
        cognito_pool_client_operator = cognito.CfnUserPoolClient(
            self, "operator",
            user_pool_id=cognito_pool.user_pool_id,
            access_token_validity=1,
            allowed_o_auth_flows=["code"],
            allowed_o_auth_flows_user_pool_client=True,
            allowed_o_auth_scopes=["email", "openid"],
            callback_ur_ls=[api.url + api_res_manage_init_form.path.lstrip("/") + "/",
                            api.url + api_res_manage_request.path.lstrip("/") + "/"],
            client_name="operator",
            explicit_auth_flows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            generate_secret=False,
            id_token_validity=1,
            prevent_user_existence_errors="ENABLED",
            token_validity_units=cognito.CfnUserPoolClient.TokenValidityUnitsProperty(refresh_token="hours"),
            refresh_token_validity=1
        )
        cognito_pool_client_operator.add_depends_on(api.node.default_child)
        env.cognito_pool_operator_client_id.value = cognito_pool_client_operator.client_name

        # manage/init GET - Must not require Auth
        api_ep_manage_init_get = ApiEndpointConfig(
            self, "manage_init_get",
            function_name="RedirectAuthLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_manage_init,
            api_method="GET",
            code_module="ggi_apigw_redirect_auth_for_init_form_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.cognito_pool_operator_client_id, env.cognito_pool_url],
            request_parameters=None,
            request_models=None,
            request_validator=None,
            authorization_type=None,
            authorizer=None,
            authorization_scopes=None
        )

        # manage/init/form GET - Must not require Auth
        api_ep_manage_init_form_get = ApiEndpointConfig(
            self, "manage_init_form_get",
            function_name="GetFormLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_manage_init_form,
            api_method="GET",
            code_module="ggi_apigw_init_get_form_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level],
            request_parameters={"method.request.querystring.code": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=None,
            authorizer=None,
            authorization_scopes=None
        )

        # init/form POST
        api_ep_manage_init_form_post = ApiEndpointConfig(
            self, "manage_init_form_post",
            function_name="PostFormLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_manage_init_form,
            api_method="POST",
            code_module="ggi_apigw_init_process_form_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.cognito_pool_id, env.cognito_pool_url,
                         env.cognito_pool_gginstaller_client_id, env.s3_downloads_bucket, env.s3_bucket_scripts,
                         env.installer_script_name],
            request_parameters={"method.request.querystring.code": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.CUSTOM,
            authorizer=api_auth_custom.authorizer,
            authorization_scopes=None
        )
        s3_res.scripts_bucket.grant_read(api_ep_manage_init_form_post.function)
        s3_res.downloads_bucket.grant_read_write(api_ep_manage_init_form_post.function)
        cognito_pool.grant(
            api_ep_manage_init_form_post.function,
            "cognito-idp:Describe*",
            "cognito-idp:List*"
        )
        api_ep_manage_init_form_post.function.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSIoTConfigReadOnlyAccess")
        )

        # manage/request GET
        api_ep_manage_request_get = ApiEndpointConfig(
            self, "manage_request_get",
            function_name="GetManageRequestLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_manage_request,
            api_method="GET",
            code_module="ggi_apigw_provisioning_request_allow_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.dynamodb_table_name],
            request_parameters={"method.request.querystring.code": True, "method.request.querystring.state": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.CUSTOM,
            authorizer=api_auth_custom.authorizer,
            authorization_scopes=None
        )
        dynamodb.table.grant_read_write_data(api_ep_manage_request_get.function)

        # provision/greengrass-config GET
        api_ep_provision_greengrass_config_get = ApiEndpointConfig(
            self, "provision_greengrass-config_get",
            function_name="GetGreengrassConfigLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_provision_gg,
            api_method="GET",
            code_module="ggi_apigw_provision_greengrass_config_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.dynamodb_table_name, env.s3_bucket_greengrass_config,
                         env.greengrass_config_template_name, env.token_exchange_role_alias],
            request_parameters={"method.request.querystring.greengrassConfigTemplate": False,
                                "method.request.querystring.transactionId": True,
                                "method.request.querystring.deviceId": True,
                                "method.request.header.Authorization": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito,
            authorization_scopes=[apigw_scope_request]
        )
        dynamodb.table.grant_read_data(api_ep_provision_greengrass_config_get.function)
        s3_res.gg_config_bucket.grant_read(api_ep_provision_greengrass_config_get.function)
        api_ep_manage_init_form_post.function.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSIoTConfigReadOnlyAccess")
        )

        # provision/register-thing POST
        api_ep_provision_register_thing_post = ApiEndpointConfig(
            self, "provisiong_register-thing_post",
            function_name="PostRegisterthingLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_register_thing,
            api_method="POST",
            code_module="ggi_apigw_provision_thing_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.dynamodb_table_name, env.s3_bucket_provisioning_templates,
                         env.provisioning_template_name],
            request_parameters={"method.request.header.Authorization": True},
            request_models={'application/json': api_model_thing_provisioning},
            request_validator=req_validator_all,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito,
            authorization_scopes=[apigw_scope_request]
        )
        dynamodb.table.grant_read_write_data(api_ep_provision_register_thing_post.function)
        s3_res.prov_templates_bucket.grant_read(api_ep_provision_register_thing_post.function)
        api_ep_provision_register_thing_post.function.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSIoTConfigReadOnlyAccess")
        )
        api_ep_provision_register_thing_post.function.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSIoTThingsRegistration")
        )

        # request/create GET
        api_ep_request_create_get = ApiEndpointConfig(
            self, "request_create_get",
            function_name="GetRequestCreateLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_req_create,
            api_method="GET",
            code_module="ggi_apigw_provisioning_request_create_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.cognito_group_provisionning, env.cognito_pool_id,
                         env.cognito_pool_url, env.cognito_pool_operator_client_id, env.dynamodb_table_name,
                         env.apigw_base_url, env.ses_email_from],
            request_parameters={"method.request.querystring.deviceId": True,
                                "method.request.querystring.thingName": True,
                                "method.request.querystring.userName": True,
                                "method.request.header.Authorization": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito,
            authorization_scopes=[apigw_scope_request]
        )
        cognito_pool.grant(
            api_ep_request_create_get.function,
            "cognito-idp:Describe*",
            "cognito-idp:List*"
        )
        api_ep_request_create_get.function.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSIoTConfigReadOnlyAccess")
        )
        dynamodb.table.grant_read_write_data(api_ep_request_create_get.function)
        api_ep_request_create_get.function.add_to_role_policy(iam.PolicyStatement(
            actions=["ses:SendEmail", "ses:SendRawEmail"],
            effect=iam.Effect.ALLOW,
            resources=["arn:aws:ses:{}:{}:identity/{}".format(aws_scope.region, aws_scope.account_id,
                                                              ses_id.email_identity_name)]
            )
        )

        # request/status GET
        api_ep_request_status_get = ApiEndpointConfig(
            self, "request_status_get",
            function_name="GetRequestStatusLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_req_status,
            api_method="GET",
            code_module="ggi_apigw_provisioning_request_status_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.dynamodb_table_name],
            request_parameters={"method.request.querystring.deviceId": True,
                                "method.request.querystring.transactionId": True,
                                "method.request.header.Authorization": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito,
            authorization_scopes=[apigw_scope_request]
        )
        dynamodb.table.grant_read_data(api_ep_request_status_get.function)

        # request/update GET
        api_ep_request_update_get = ApiEndpointConfig(
            self, "request_update_get",
            function_name="GetRequestUpdateLambda",
            runtime=LAMBDA_RUNTIME,
            architecture=LAMBDA_ARCH,
            api_resource=api_res_req_update,
            api_method="GET",
            code_module="ggi_apigw_provisioning_request_update_lambda",
            layers=[lambda_common_layer],
            environment=[env.log_level, env.dynamodb_table_name],
            request_parameters={"method.request.querystring.deviceId": True,
                                "method.request.querystring.transactionId": True,
                                "method.request.querystring.newStatus": True,
                                "method.request.header.Authorization": True},
            request_models=None,
            request_validator=req_validator_params,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=api_auth_cognito,
            authorization_scopes=[apigw_scope_request]
        )
        dynamodb.table.grant_read_write_data(api_ep_request_update_get.function)
