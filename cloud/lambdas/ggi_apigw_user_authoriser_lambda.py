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
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import os
import boto3
from base64 import b64encode
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


def get_redirect_uri(event):
    context = event['requestContext']
    red = "https://{0}{1}".format(context['domainName'], context['path'])
    logger.debug("Redirect URL: {}".format(red))
    return red


def get_tokens_from_code(authorization_code, redirect_uri, client_secret, client_id=COG_CID, cognito_url=COG_URL):
    url = "{}/oauth2/token".format(cognito_url)
    method = "POST"
    headers = {'Content-Type': "application/x-www-form-urlencoded"}
    if client_secret:
        b64_auth = 'Basic {}'.format(
            b64encode(bytes("{}:{}".format(client_id, client_secret), "ascii")).decode("ascii"))
        headers['Authorization'] = b64_auth
    params = None
    data_as_json = False
    data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': redirect_uri,
    }
    if not client_secret:
        data['client_id'] = client_id

    response = request(
        url=url,
        data=data,
        params=params,
        headers=headers,
        method=method,
        data_as_json=data_as_json
    )

    if response.status == 200:
        return response.json()
    else:
        logger.debug("Error response to auth code exchange:\n{}".format(response))
        return {}


def get_userinfo(tokens, cognito_url=COG_URL):
    url = "{}/oauth2/userInfo".format(cognito_url)
    method = "GET"
    headers = {'Authorization': "Bearer {}".format(tokens.get('access_token', ""))}
    response = request(
        url=url,
        headers=headers,
        method=method
    )
    if response.status == 200:
        return response.json()
    else:
        logger.debug("Error response to auth code exchange:\n{}".format(response))
        return {}


def get_authorizer_allow_policy(user_info, event, code):
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
    if resource not in AUTHORIZED_RESOURCES:
        logger.debug("Denying access for resource '{}' not allowed".format(resource))
        unauthorised()
    code = event['queryStringParameters'].get('code')
    if not code:
        logger.debug("Denying for missing authorisation code")
        unauthorised()

    tokens = get_tokens_from_code(authorization_code=code,
                                  redirect_uri=get_redirect_uri(event),
                                  client_secret=get_user_pool_secret(cog_client=cog_client,
                                                                     user_pool_id=COG_POOL,
                                                                     client_id=COG_CID)
                                  )
    if not tokens:
        logger.debug("Denying for missing tokens")
        unauthorised()

    user_info = get_userinfo(tokens)
    if not user_info:
        logger.debug("Denying for missing User Info")
        unauthorised()

    return get_authorizer_allow_policy(user_info=user_info, event=event, code=code)
