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
from enum import Enum
import typing
import json
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
import re
from datetime import datetime


# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)

# DynamoDB (de)serialiser
ddbTs = TypeSerializer()
ddbTd = TypeDeserializer()


class Status(Enum):
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    ALLOWED = 5
    PROGRESS = 6
    SUCCESS = 7
    NONE = 8


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


def unmarshall(dynamo_obj):
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


def marshall(python_obj):
    """Convert a standard list or dict into a DynamoDB ."""
    if isinstance(python_obj, dict):
        return {k: ddbTs.serialize(v) for k, v in python_obj.items()}
    elif isinstance(python_obj, list):
        lst = []
        for obj in python_obj:
            lst.append(marshall(obj))
        return {'L': lst}
    else:
        raise RuntimeError("Failed to marshall DynamoDB object: {}".format(python_obj))


def is_valid_thing_name(thing_name):
    # Check that Thing Name matches IoT Core requirements
    pattern = "^[0-9a-zA-Z:\-_]*$"
    return re.fullmatch(pattern=pattern, string=thing_name) is not None


def update_request_status(current_request, action, new_status, table, ddb_client):
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


def get_ddb_item(pkey, pvalue, skey, svalue, table, ddb_client):
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
