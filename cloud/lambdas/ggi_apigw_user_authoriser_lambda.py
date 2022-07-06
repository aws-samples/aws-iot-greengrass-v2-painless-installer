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

import logging
import os
import sys
import boto3
import json
import typing
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from base64 import b64encode
from uuid import uuid4

# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)

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
AUTHORIZED_RESOURCES = ["/manage/request"]


class Response(typing.NamedTuple):
    """Container for HTTP response."""

    body: str
    headers: Message
    status: int
    error_count: int = 0

    def json(self) -> typing.Any:
        """
        Decode body's JSON.
        Returns:
            Pythonic representation of the JSON object
        """
        try:
            output = json.loads(self.body)
        except json.JSONDecodeError:
            output = str(self.body)
        return output

    def __str__(self):

        return str({
            'body': self.json(),
            'status': self.status,
            'error_count': self.error_count,
            'headers': str(self.headers),
        })


def request(
        url: str,
        data: dict = None,
        params: dict = None,
        headers: dict = None,
        method: str = "GET",
        data_as_json: bool = True,
        error_count: int = 0,
) -> Response:
    """
    Perform HTTP request.
    Args:
        url: url to fetch
        data: dict of keys/values to be encoded and submitted
        params: dict of keys/values to be encoded in URL query string
        headers: optional dict of request headers
        method: HTTP method , such as GET or POST
        data_as_json: if True, data will be JSON-encoded
        error_count: optional current count of HTTP errors, to manage recursion
    Raises:
        URLError: if url starts with anything other than "http"
    Returns:
        A dict with headers, body, status code, and, if applicable, object
        rendered from JSON
    """
    if not url.startswith("http"):
        raise urllib.error.URLError("Incorrect and possibly insecure protocol in url")
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json", **headers}

    if method == "GET":
        params = {**params, **data}
        data = None

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()

    httprequest = urllib.request.Request(
        url, data=request_data, headers=headers, method=method
    )

    # print("url: {}".format(url))
    # print("data: {}".format(data))
    # print("headers: {}".format(headers))
    # print("method: {}".format(method))

    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            response = Response(
                headers=httpresponse.headers,
                status=httpresponse.status,
                body=httpresponse.read().decode(
                    httpresponse.headers.get_content_charset('UTF-8')
                ),
            )
    except urllib.error.HTTPError as e:
        body = e.read().decode(e.headers.get_content_charset('UTF-8'))
        response = Response(
            headers=e.headers,
            status=e.code,
            error_count=error_count + 1,
            body="{}: {}".format(str(e.reason), body),
        )
    return response


def unauthorised():
    raise Exception('Unauthorized')


def get_user_pool_secret(user_ool_id=COG_POOL, client_id=COG_CID):
    resp = cog_client.describe_user_pool_client(
        UserPoolId=user_ool_id,
        ClientId=client_id
    )
    logger.debug("Response to Pool Description: {}".format(resp))
    secret = resp['UserPoolClient'].get('ClientSecret', "")
    if secret:
        logger.debug("Secret for Client ID '{}' starts with '{}'...".format(client_id, secret[:5]))
    else:
        logger.debug("Client ID '{}' doesn't have any secret".format(client_id))
    return secret


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


def get_authorizer_allow_policy(user_info, event):
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
    state = event['queryStringParameters'].get('state')
    if not state:
        logger.debug("Denying for missing state")
        unauthorised()
    red = get_redirect_uri(event=event)
    secret = get_user_pool_secret()
    tokens = get_tokens_from_code(authorization_code=code,
                                  redirect_uri=get_redirect_uri(event),
                                  client_secret=get_user_pool_secret())
    if not tokens:
        logger.debug("Denying for missing tokens")
        unauthorised()

    user_info = get_userinfo(tokens)
    if not user_info:
        logger.debug("Denying for missing User Info")
        unauthorised()

    return get_authorizer_allow_policy(user_info=user_info, event=event)


