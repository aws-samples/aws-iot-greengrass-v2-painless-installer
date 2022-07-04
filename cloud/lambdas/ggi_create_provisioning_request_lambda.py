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
This Lambda initiates a new provisioning. Conditions to allow a provisioning are:
* The 'userName' maps to a user allowed to perform provisioning and with a validated email address.
* There are no existing provisioning for this 'deviceId except' in states 'failed' or 'denied' or 'timeout'.
* A thing with this thingName doesn't exist.

Actions executed:
* Create an entry in the Database:
    * deviceId
    * thingName
    * currentState 'pending'
    * userName
    * email
    * Acknowledgement Expiration: 1 hour ahead
* Email the User with 'approve' and 'deny' links
* Return to the caller:
    * 200: {'transactionId': 'string'}
    * 400: {'details': 'string'}

Configuration:
* Environment Variables:

* Roles & Policies:



"""
import logging
import sys
import traceback
import boto3
import os
import json
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from uuid import uuid4
from enum import Enum
from datetime import datetime

# Set the logger and log level
#  Define a LOG_LEVEL environment variable and give it he desired value
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARNING")).upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "WARNING"
logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
logger.setLevel(LOG_LEVEL)

# Cognito Configuration
COG_GRP = os.environ.get("COGNITO_PROV_GROUP", "GreengrassProvisioningOperators")
COG_POOL = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_POOL:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")
ddbTs = TypeSerializer()
ddbTd = TypeDeserializer()

# Set some boto3 clients
cog_client = boto3.client('cognito-idp')
iot_client = boto3.client('iot')
ddb_client = boto3.client('dynamodb')


def find_confirmed_user_in_group(user_name, users):
    # logger.debug("Users received: {}".format(users))
    for user in users:
        if user['Username'] == user_name:
            if user['UserStatus'] == "CONFIRMED":
                return user
            else:
                return None
    return None


def get_user_from_group(user_name, pool_id=COG_POOL, group=COG_GRP):
    user = None
    if not user_name:
        logger.warning("user_name is None - can't proceed!")
        return user

    resp = cog_client.list_users_in_group(
        UserPoolId=pool_id,
        GroupName=group
    )
    user = find_confirmed_user_in_group(user_name, resp.get('Users'))
    if not user:
        nextToken = resp.get('nextToken')
        while nextToken:
            resp = cog_client.list_users_in_group(
                UserPoolId=pool_id,
                GroupName=group,
                nextToken=nextToken
            )
            user = find_confirmed_user_in_group(user_name, resp.get('Users'))
            if not user:
                nextToken = resp.get('nextToken')
            else:
                break
    logger.debug("Found User: '{}'".format(user))
    return user


def get_user_email(user):
    email = None
    for attr in user.get('Attributes'):
        if attr.get('Name') == "email":
            email = attr.get('Value')
            break
    logger.debug("User email: '{}'".format(email))
    return email


def bad_request(msg, status_code=403):
    return {
        'statusCode': status_code,
        'body': {'reason': json.dumps(msg)}
    }


def internal_error(status_code=500):
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'body': {'reason': json.dumps(msg)}
    }


def is_new_iot_thing(thing_name):
    try:
        _ = iot_client.describe_thing(thingName=thing_name)
        return False
    except iot_client.exceptions.ResourceNotFoundException:
        return True


def unmarshall(dynamo_obj):
    """Convert a DynamoDB dict or list into a standard dict or list of dicts."""
    if isinstance(dynamo_obj, dict):
        return {k: ddbTd.deserialize(v) for k, v in dynamo_obj.items()}
    elif isinstance(dynamo_obj, list):
        l = []
        for obj in dynamo_obj:
            l.append(unmarshall(obj))
        return l
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


def get_items_by_device_id(device_id, ddb_table_name=DDB_TABLE, index="deviceId-transactionId-index"):
    resp = ddb_client.query(
        TableName=ddb_table_name,
        IndexName=index,
        Select='ALL_ATTRIBUTES',
        ReturnConsumedCapacity='NONE',
        ExpressionAttributeValues={
            ':v1': {
                'S': device_id,
            },
        },
        KeyConditionExpression="deviceId = :v1",
    )
    return unmarshall(resp['Items'])


def get_items_by_thing_name(thing_name, ddb_table_name=DDB_TABLE, index="thingName-transactionId-index"):
    resp = ddb_client.query(
        TableName=ddb_table_name,
        IndexName=index,
        Select='ALL_ATTRIBUTES',
        ReturnConsumedCapacity='NONE',
        ExpressionAttributeValues={
            ':v1': {
                'S': thing_name,
            },
        },
        KeyConditionExpression="thingName = :v1",
    )
    return unmarshall(resp['Items'])


class Status(Enum):
    PENDING = 1
    FAILED = 2
    CANCELLED = 3
    DENIED = 4
    PROGRESS = 5
    SUCCESS = 6
    NONE = 7


FAILED_XACTIONS = [Status.FAILED, Status.CANCELLED, Status.DENIED]


def get_history_from_template(prev_status, action):
    return {
        datetime.utcnow().isoformat(): {
            "action": action,
            "previous_status": prev_status
        }
    }


def new_xaction_record(thing_name, device_id, username, email, action, history=None, prev_status=None):
    if history is None:
        history = {}
    if prev_status is None:
        prev_status = "NONE"
    return {
        'transactionId': str(uuid4()),
        'deviceId': device_id,
        'thingName': thing_name,
        'currentStatus': Status.PENDING.name,
        'requester': {'username': username, 'email': email},
        'history': history | get_history_from_template(prev_status, action)
    }


def lambda_handler(event, context):
    try:
        logger.info("Starting Lambda {}.{}".format(context.function_name, context.function_version))

        # Retrieve Query String Parameters
        user_name = event["queryStringParameters"].get('userName')
        thing_name = event["queryStringParameters"].get('thingName')
        device_id = event["queryStringParameters"].get('deviceId')
        logger.debug("Received query string parameters: userName = '{}', thingName = '{}', "
                     "deviceId = '{}'".format(user_name, thing_name, device_id))

        # Check User group membership and retrieve validated email address
        user = get_user_from_group(user_name=user_name)
        if not user:
            logger.warning("A confirmed User '{}' was not found in "
                           "group '{}' of pool '{}'".format(user_name, COG_GRP, COG_POOL))
            return bad_request("Request rejected")
        email = get_user_email(user)
        if not email:
            logger.warning("A email address could not be found for User '{}'".format(user_name))
            return bad_request("Request rejected")

        # Check if the Thing Name or the Device ID already exist.
        if is_new_iot_thing(thing_name) is False:
            return bad_request("A thing with name '{}' already exists".format(thing_name))
        xactions = get_items_by_device_id(device_id=device_id)
        for xaction in xactions:
            if Status[xaction['currentStatus'].upper()] not in FAILED_XACTIONS:
                logger.warning(
                    "Received new provisioning request for a Device already in progress: {}".format(device_id))
                return bad_request("There is already a Transaction in progress")
        xactions = get_items_by_thing_name(thing_name=thing_name)
        for xaction in xactions:
            if xaction['currentStatus'] not in FAILED_XACTIONS:
                logger.warning(
                    "Received new provisioning request for a Thing already in progress: {}".format(thing_name))
                return bad_request("There is already a Transaction in progress")

        xaction = new_xaction_record(thing_name=thing_name,
                                     device_id=device_id,
                                     username=user_name,
                                     email=email,
                                     action="create")

        print(xaction)
        m_xaction = marshall(xaction)
        print(m_xaction)
        print(unmarshall(m_xaction))


        resp = ddb_client.put_item(
            TableName=DDB_TABLE,
            Item=m_xaction,
            ReturnConsumedCapacity='NONE',
        )

        print(resp)


    except Exception as e:
        logger.error(e)
        traceback.print_exc(file=sys.stdout)
        return internal_error()
