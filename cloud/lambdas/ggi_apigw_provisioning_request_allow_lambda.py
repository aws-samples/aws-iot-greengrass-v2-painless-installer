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
import boto3
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from uuid import UUID
import re
from datetime import datetime
import traceback

# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")
ddbTs = TypeSerializer()
ddbTd = TypeDeserializer()

# Set some boto3 clients
ddb_client = boto3.client('dynamodb')


class Status(Enum):
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    ALLOWED = 5
    PROGRESS = 6
    SUCCESS = 7
    NONE = 8


def ok_200(msg):
    page = '<!doctype html><html lang="en-us"> <body><h1>Success</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def accepted_202(msg):
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 202,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def bad_request_400(msg):
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 400,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def error_500(msg="Something went wrong on the Backend. Check the logs."):
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 500,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def decode_state(event):
    state = event['queryStringParameters'].get('state')
    d = {}
    if state:
        params = state.split()
        for p in params:
            k, v = p.split("=")
            d[k] = v
    # logger.debug("State Params: {}".format(d))
    return d


def get_authorizer_params(event):
    to_retrieve = ['email', 'username']
    params = event['requestContext'].get('authorizer')
    d = {}
    if params:
        for p in to_retrieve:
            d[p] = params[p]
    # logger.debug("Authorizer Params: {}".format(d))
    return d


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


def get_ddb_item(pkey, pvalue, skey, svalue, table=DDB_TABLE):
    response = ddb_client.get_item(
        Key=marshall({pkey: pvalue, skey: svalue}),
        TableName=table,
        ReturnConsumedCapacity='NONE',
    )
    return unmarshall(response.get('Item'))


def is_valid_state_params(params):
    """
    State parameters are passed as Query String Parameters and could have been altered
    :param params:
    :return:
    """
    good = True
    # Check transactionId is a UUID version 4
    try:
        _ = UUID(params['transactionId'], version=4)
    except ValueError:
        logger.critical("The transactionId is not a valid uuid4. It could mean an attempt of code injection")
        good = False

    # Check that Thing Name matches IoT Core requirements
    pattern = "^[0-9a-zA-Z:\-_]*$"
    if re.fullmatch(pattern=pattern, string=params['deviceId']) is None:
        logger.critical("The thing Name is not a valid name according to IoT Core rule.")
        good = False

    # Check if action is part of allowed list
    actions_allowed = ['allow', 'deny']
    if params['action'] not in actions_allowed:
        logger.critical("The action does not a valid value: '{}'".format(params['action']))
        good = False

    return good


def is_same_requester(request, username, email):
    return request['requester']['email'] == email and request['requester']['username'] == username


def update_request_status(current_request, action, new_status, table=DDB_TABLE):
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


def lambda_handler(event, context):
    try:
        # logger.debug("Event: {}".format(event))

        # Retrieve operational parameters
        parameters = decode_state(event=event)
        if is_valid_state_params(parameters) is False:
            return bad_request_400("Process aborted due to invalid parameters. Check the logs for details.")
        parameters = parameters | get_authorizer_params(event=event)
        logger.debug("Used parameters: {}".format(parameters))

        # Retrieve the request from the DB
        prov_req = get_ddb_item(pkey='transactionId', pvalue=parameters['transactionId'],
                                skey='deviceId', svalue=parameters['deviceId'])
        logger.debug("Record found in the DB: {}".format(prov_req))
        if not prov_req:
            msg = "A provisioning request with TransactionId '{}' " \
                  "and deviceId '{}' could not be found.".format(parameters['transactionId'],
                                                                 parameters['deviceId'])
            logger.warning(msg)
            return accepted_202(msg)
        # Validate the request ownership: the same user and email as when the request was recreated
        if not is_same_requester(request=prov_req, username=parameters['username'], email=parameters['email']):
            logger.critical("The user trying to allow/deny the request is not the original requester")
            return bad_request_400("You are not allowed to take this action.")
        # The request must be in status PENDING, ALLOWED or DENIED to be allowed or denied
        if not prov_req['currentStatus'] in [Status.PENDING.name, Status.ALLOWED.name, Status.DENIED.name]:
            logger.warning("Attempt to {} the quest {} while in status {}".format(parameters['action'],
                                                                                  parameters['transactionId'],
                                                                                  prov_req['currentStatus']))
            return bad_request_400("Operation not allowed. See logs for details.")
        # Update the record in the DB
        new_status = Status.ALLOWED if parameters['action'] == "allow" else Status.DENIED
        update_request_status(current_request=prov_req, new_status=new_status.name, action=parameters['action'])
        # Finally, send response to the User
        return ok_200("The provisioning request with TransactionId '{}' "
                      "and deviceId '{}' has been <b>{}</b>.".format(parameters['transactionId'],
                                                                     parameters['deviceId'], new_status.name))

    except Exception as e:
        logger.error("Error during runtime: {}".format(e))
        traceback.print_exc(file=sys.stdout)
        return error_500()
