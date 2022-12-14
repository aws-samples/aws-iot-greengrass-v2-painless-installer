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
This is a Lambda Layer collecting a set of functions used by many of the Lambda Functions of this application
User in Lambda Functions with:
   from ggi_lambda_utils import *
"""
import logging
import os
import sys
from enum import Enum
import typing
import json
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message

from boto3 import client as botoclient
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
import re
from datetime import datetime
from base64 import b64encode

# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)

# DynamoDB (de)serializer
ddbTs = TypeSerializer()
ddbTd = TypeDeserializer()


class Status(Enum):
    """
    Defines the possible satus of a Status Request.
    Make sure this stays in sync with the same class in the edge script
    """
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    ALLOWED = 5
    PROGRESS = 6
    REGISTERED = 7
    SUCCESS = 8
    NONE = 9


# What statuses are final failures to the provisioning process transaction
FAILED_XACTIONS = [Status.FAILED, Status.CANCELLED, Status.DENIED]


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

    # logger.debug("url: {}".format(url))
    # logger.debug("data: {}".format(data))
    # logger.debug("headers: {}".format(headers))
    # logger.debug("method: {}".format(method))

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


def unmarshall(dynamo_obj: typing.Union[dict, list]) -> typing.Union[dict, list, None]:
    """Convert a DynamoDB dict or list into a standard dict or list of dicts."""
    if dynamo_obj is None:
        return dynamo_obj
    elif isinstance(dynamo_obj, dict):
        return {k: ddbTd.deserialize(v) for k, v in dynamo_obj.items()}
    elif isinstance(dynamo_obj, list):
        ll = []
        for obj in dynamo_obj:
            ll.append(unmarshall(obj))
        return ll
    else:
        raise RuntimeError("Failed to unmarshall DynamoDB object: {}".format(dynamo_obj))


def marshall(python_obj: typing.Union[dict, list]) -> dict:
    """
    Converts a standard list or dict into a DynamoDB compatible dict.
    :param python_obj: A python Dict or List to marshall
    :return: A dict compatible with DynamoDB API
    """
    if isinstance(python_obj, dict):
        return {k: ddbTs.serialize(v) for k, v in python_obj.items()}
    elif isinstance(python_obj, list):
        lst = []
        for obj in python_obj:
            lst.append(marshall(obj))
        return {'L': lst}
    else:
        raise RuntimeError("Failed to marshall DynamoDB object: {}".format(python_obj))


def is_valid_thing_name(thing_name: str) -> bool:
    """
    Checks that Thing Name matches IoT Core requirements
    :param thing_name: The name to check
    :return: True of match or False
    """
    pattern = "^[0-9a-zA-Z:\-_]*$"
    return re.fullmatch(pattern=pattern, string=thing_name) is not None


def is_valid_thing_attribute(attribute: str) -> bool:
    """
    Checks that Thing Attribute matches IoT Core requirements
    :param attribute: The attribute to check
    :return: True of match or False
    """
    pattern = "^[a-zA-Z0-9_.,@/:#-]*$"
    return re.fullmatch(pattern=pattern, string=attribute) is not None and len(attribute) < 801


def is_new_iot_thing(thing_name: str, iot_client: botoclient):
    """
    Checks if the thing_name already exists in IoT Core
    :param thing_name: proposed name
    :param iot_client: the boto3 client for Iot Core
    :return: Ture if the name is new or False if it exists
    """
    try:
        _ = iot_client.describe_thing(thingName=thing_name)
        return False
    except iot_client.exceptions.ResourceNotFoundException:
        return True


def update_request_status(current_request: dict, action: str, new_status: str, table: str,
                          ddb_client: botoclient) -> None:
    """
    Updates the DynamodB Item with the new information
    :param current_request: the unmarshalled Item as returned by DynamoDB API
    :param action: brief description of what the change was about
    :param new_status: The string associated with the new Status
    :param table: DynamoDB able name
    :param ddb_client: Boto3 client for DynamoDB
    :return: Nothing but might raise an exception if problem
    """
    history = current_request['history']
    history[datetime.utcnow().isoformat()] = {'action': action,
                                              'previous_status': str(current_request['currentStatus'])}
    attribute_value = {':cs': new_status,
                       ':h': history}
    key = {'deviceId': current_request['deviceId'],
           'transactionId': current_request['transactionId']}
    response = ddb_client.update_item(
        ExpressionAttributeNames={
            '#CS': 'currentStatus',
            '#H': 'history',
        },
        ExpressionAttributeValues=marshall(attribute_value),
        Key=marshall(key),
        ReturnValues='ALL_NEW',
        TableName=table,
        UpdateExpression='SET #CS = :cs, #H = :h'
    )
    logger.debug("New DB values after update: \n{}".format(response))


def get_ddb_item(pkey: str, pvalue: str, skey: str, svalue: str, table: str,
                 ddb_client: botoclient) -> typing.Union[dict, list, None]:
    """
    Retrieve an item from DynamoDB using Partition Key and Sort Key
    :param pkey: Partition Key name
    :param pvalue:Partition Key value
    :param skey: Sort Key name
    :param svalue:Sort Key value
    :param table: DynamodB Table name
    :param ddb_client: boto3 client for DynamoDB
    :return: The unmarshalled dynamodB Item or None
    """

    try:
        response = ddb_client.get_item(
            Key=marshall({pkey: pvalue, skey: svalue}),
            TableName=table,
            ReturnConsumedCapacity='NONE',
        )
        return unmarshall(response.get('Item'))
    except ddb_client.exceptions.ResourceNotFoundException:
        logger.warning("An edge device tried to access non-existing Provisioning Request:"
                       "pkey: {}, skey: {}".format(pvalue, svalue))
        return None


def get_tokens_from_code(authorization_code: str, redirect_uri: str, client_secret: str, client_id: str,
                         cognito_url: str) -> dict:
    """
    Exchanges the Authorization Code for Tokens
    :param authorization_code: the Code returns by Cognito after Auth
    :param redirect_uri: The URL to redirect to after code exchange
    :param client_secret: Cognito client password or secret
    :param client_id: Cognito client ID
    :param cognito_url: Cognito domain
    :return: a dict containing the Cognito Tokens or empty dict
    """
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


def get_userinfo(tokens: dict, cognito_url: str) -> dict:
    """
    Retrieves the User Info with a Token from the public Cognito userInfo endpoint
    :param tokens: Dictionary of Tokens
    :param cognito_url: Cognito Domain
    :return: User dictionary as returned by userInfo or empty dict
    """
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


def get_user_pool_secret(cog_client: botoclient, user_pool_id: str, client_id: str) -> str:
    """
    Retrieve the password for the Cognito User
    :param cog_client:
    :param user_pool_id:
    :param client_id:
    :return:
    """
    resp = cog_client.describe_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id
    )
    logger.debug("Response to Pool Description: {}".format(resp))
    secret = resp['UserPoolClient'].get('ClientSecret', "")
    if secret:
        logger.debug("Secret for Client ID '{}' starts with '{}'...".format(client_id, secret[:5]))
    else:
        logger.debug("Client ID '{}' doesn't have any secret".format(client_id))
    return secret


def get_cognito_client_id_from_name(cog_client: botoclient, pool_id: str, name: str) -> str:
    """
    Retrieve the Cognito Client ID from the Cognito User Pool Name
    :param cog_client: The Boto3 client for Cognito
    :param name:
    :param pool_id:
    :return: str, empty of failed
    """
    clients = cog_client.list_user_pool_clients(UserPoolId=pool_id)
    cid = ''
    for client in clients['UserPoolClients']:
        if client.get('ClientName') == name:
            cid = client['ClientId']
            break
    return cid


def list_bucket(s3_client: botoclient, bucket_name: str, suffix: str = "") -> list[str]:
    """
    Returns a list of object keys found in this bucket
    :param s3_client: a boto3 client for S3
    :param bucket_name: the name fo the bucket to list
    :param suffix: only keys ending with this suffix will be returned. Default empty = all keys are returned.
    :return: a list of object keys
    """

    response = s3_client.list_objects_v2(Bucket=bucket_name)
    keys = []
    for obj in response['Contents']:
        if obj['Key'].endswith(suffix):
            keys.append(obj['Key'])
    return keys
