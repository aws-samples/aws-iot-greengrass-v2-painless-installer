#!/usr/bin/env python3

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

"""
Lambda Authorizer taking an Authorization Code to validae a request
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import os
import boto3
from uuid import uuid4

# Cognito Configuration
# TODO: simplify by detecting automatically when possible
COG_POOL = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_POOL:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_CID = os.environ.get("COG_CLIENT_ID")
if not COG_CID:
    raise Exception("Environment variable COG_CLIENT_ID missing")

# Set some boto3 clients
cog_client = boto3.client('cognito-idp')

# Constants
AUTHORIZED_RESOURCES = ["/manage/request", "/manage/init/form"]


def unauthorised():
    raise Exception('Unauthorized')


def get_redirect_uri(event) -> str:
    """
    Builds and returns a URL to redirect to after authorisation
    :param event: the event as received by the handler
    :return: the URL
    """
    context = event['requestContext']
    red = "https://{0}{1}".format(context['domainName'], context['path'])
    logger.debug("Redirect URL: {}".format(red))
    return red


def get_authorizer_allow_policy(user_info: dict, event: dict) -> dict:
    """
    Builds an Authoriser Policy for Cognito
    :param user_info: User dictionary
    :param event: event dictionary as received by the handler
    :return: a Policy dictionary
    """
    policy = {
        "principalId": "{}-{}".format(user_info['sub'], str(uuid4())),
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event['methodArn']
                }
            ]
        },
        "context": {
            "username": user_info['username'],
            "email": user_info['email']
        }
    }
    logger.debug("Authorizer Policy Document:\n{}".format(policy))
    return policy


def lambda_handler(event, context):
    logger.debug(event)
    resource = event.get('resource')
    # Limit the access to specific API Gateway resources
    if resource not in AUTHORIZED_RESOURCES:
        logger.debug("Denying access for resource '{}' not allowed".format(resource))
        unauthorised()
    # We need an Authorization Code in the query string parameters
    code = event['queryStringParameters'].get('code')
    if not code:
        logger.debug("Denying for missing authorisation code")
        unauthorised()

    # Exchange the Code for Tokens to validate the Code
    tokens = get_tokens_from_code(authorization_code=code,
                                  redirect_uri=get_redirect_uri(event),
                                  client_secret=get_user_pool_secret(cog_client=cog_client,
                                                                     user_pool_id=COG_POOL,
                                                                     client_id=COG_CID),
                                  client_id=COG_CID,
                                  cognito_url=COG_URL
                                  )
    if not tokens:
        logger.debug("Denying for missing tokens")
        unauthorised()

    # Check the token is still valid for this User
    user_info = get_userinfo(tokens=tokens, cognito_url=COG_URL)
    if not user_info:
        logger.debug("Denying for missing User Info")
        unauthorised()

    return get_authorizer_allow_policy(user_info=user_info, event=event)
