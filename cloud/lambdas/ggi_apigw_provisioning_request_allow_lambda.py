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
Marks an existing Provisioning Request as allowed or denied by the user.
this is done after a thorough check of the various parameters because the entry point to this function is a link in
an email and could have been altered.
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import os
import sys
import boto3
from uuid import UUID
import re
import traceback
from urllib.parse import parse_qs

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")

# Set some boto3 clients
ddb_client = boto3.client('dynamodb')


def ok_200(msg: str) -> dict:
    """
    Returns a 200 response with HTML page in body
    :param msg: A message to the user
    :return: An HTML document in the response dict
    """
    page = '<!doctype html><html lang="en-us"> <body><h1>Success</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def accepted_202(msg: str) -> dict:
    """
    Returns a 202 response with HTML page in body. To be used when the request was properly formatted but the
    information provided does not allow to perform the expect operations
    :param msg: A message to the user
    :return: An HTML document in the response dict
    """
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 202,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def bad_request_400(msg: str) -> dict:
    """
    The request was improperly formatted or parameters are missing.
    :param msg: A message to the user
    :return: An HTML document in the response dict
    """
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 400,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def error_500(msg: str = "Something went wrong on the Backend. Check the logs.") -> dict:
    """
    Something went wrong.
    :param msg: A message to the user
    :return: An HTML document in the response dict
    """
    page = '<!doctype html><html lang="en-us"> <body><h1>Error !!!</h1><br>{}</body></html>'.format(msg)
    return {
        'statusCode': 500,
        'headers': {'Content-Type': "text/html; charset=UTF-8"},
        'body': page
    }


def decode_state(event: dict) -> dict:
    """
    Decode the query string parameters string embedded into the Cognito state query string parameter
    :param event: the event object as passed to the handler
    :return: a dictionary with the query string parameters included in the state parameter.
    """
    qs = parse_qs(event['queryStringParameters'].get('state'))
    logger.debug("Decoded State Params: {}".format(qs))
    return {k: qs[k][0] for k in qs.keys()}


def get_authorizer_params(event: dict) -> dict:
    """
    Retrieves teh parameters passed by the Lambda authorizer
    :param event: the event object as passed to the handler
    :return: a dictionary with the parameters
    """
    to_retrieve = ['email', 'username']
    params = event['requestContext'].get('authorizer')
    d = {}
    if params:
        for p in to_retrieve:
            d[p] = params[p]
    # logger.debug("Authorizer Params: {}".format(d))
    return d


def is_valid_state_params(params: dict) -> bool:
    """
    State parameters are passed as Query String Parameters and could have been altered. This is a minimalistic
    validation of those parameters
    :param params: dictionary with the parameters
    :return: True if valid or False
    """
    good = True
    # Check transactionId is a UUID version 4
    try:
        _ = UUID(params['transactionId'], version=4)
    except ValueError:
        logger.critical("The transactionId is not a valid uuid4. It could mean an attempt of code injection")
        good = False

    # Check if action is part of allowed list
    actions_allowed = ['allow', 'deny']
    if params['action'] not in actions_allowed:
        logger.critical("The action does not a valid value: '{}'".format(params['action']))
        good = False

    return good


def is_same_requester(request: dict, username: str, email: str) -> bool:
    """
    Compares the info included in the request to the expected username and email address
    :param request: dictionary with username and email keys
    :param username: the user name
    :param email: the email address of this user
    :return: True if it's a match or False
    """
    return request['requester']['email'] == email and request['requester']['username'] == username


def lambda_handler(event, context):
    """
    Updates the provisioning request transaction in the DB with new status, after validation of the various parameters
    and transaction current status
    :param event:
    :param context:
    :return:
    """
    try:
        # logger.debug("Event: {}".format(event))
        logger.debug("Query String Params: {}".format(event['queryStringParameters']))
        # Retrieve operational parameters
        parameters = decode_state(event=event)
        if is_valid_state_params(parameters) is False:
            return bad_request_400("Process aborted due to invalid parameters. Check the logs for details.")
        parameters = parameters | get_authorizer_params(event=event)
        logger.debug("Used parameters: {}".format(parameters))

        # Retrieve the request from the DB
        prov_req = get_ddb_item(pkey='transactionId', pvalue=parameters['transactionId'],
                                skey='deviceId', svalue=parameters['deviceId'],
                                table=DDB_TABLE, ddb_client=ddb_client)
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
        update_request_status(current_request=prov_req,
                              new_status=new_status.name,
                              action=parameters['action'],
                              table=DDB_TABLE,
                              ddb_client=ddb_client)
        # Finally, send response to the User
        return ok_200("The provisioning request with TransactionId '{}' "
                      "and deviceId '{}' has been <b>{}</b>.".format(parameters['transactionId'],
                                                                     parameters['deviceId'], new_status.name))

    except Exception as e:
        logger.error("Error during runtime: {}".format(e))
        traceback.print_exc(file=sys.stdout)
        return error_500()
