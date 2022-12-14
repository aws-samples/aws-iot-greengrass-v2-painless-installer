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
Updates a provisioning request with a new status. This Lambda cannot be called to allow or deny a request.
It is only used when the provisioning request has previously been allowed or is in progress.
On success, returns the new status name in the response body.
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import os
import sys
import boto3
import traceback

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")

# Set some boto3 clients
ddb_client = boto3.client('dynamodb')


def ok_200(status: str) -> dict:
    """
    Returns an OK response contianing the current status of the provisioning request
    :param status: status name
    :return: response
    """
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'status': status})
    }


def bad_request(msg, status_code: int = 400) -> dict:
    """
    Returns a 4xx response with Bad Request as default
    :param msg: Message to the user
    :param status_code: status code to use - default = 400
    :return: response
    """
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def internal_error(status_code: int = 500) -> dict:
    """
    Something went wrong
    :param status_code: status code to use - default = 500
    :return: response
    """
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def lambda_handler(event, context):
    try:
        # Retrieve the Item from DynamoDB
        parameters = event['queryStringParameters']
        item = get_ddb_item(pkey='transactionId', pvalue=parameters['transactionId'],
                            skey='deviceId', svalue=parameters['deviceId'],
                            table=DDB_TABLE, ddb_client=ddb_client)
        if not item:
            return bad_request(msg="The provisioning request was not found.")

        # Conditionally update the Status.
        cu_status = Status[item['currentStatus']]
        try:
            new_status = Status[parameters.get('newStatus')]
        except KeyError:
            return bad_request(msg="The requested new status is invalid: {} ".format(parameters.get('newStatus')))

        if cu_status not in [Status.ALLOWED, Status.PROGRESS, Status.REGISTERED]:
            return bad_request(msg="The current status of the Provisioning Request is {} and cannot"
                                   " be updated to {}".format(cu_status.name, new_status.name))

        if new_status not in [Status.FAILED, Status.PROGRESS, Status.REGISTERED, Status.SUCCESS]:
            return bad_request(msg="The requested new status {} is not allowed".format(new_status.name))

        update_request_status(current_request=item,
                              new_status=new_status.name,
                              action="Change Status to {}".format(new_status.name),
                              table=DDB_TABLE,
                              ddb_client=ddb_client)

        # Respond with the new status name
        return ok_200(status=new_status.name)

    except Exception as e:
        logger.error("Error during runtime: {}".format(e))
        traceback.print_exc(file=sys.stdout)
        return internal_error()
