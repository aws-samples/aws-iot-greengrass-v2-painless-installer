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
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import sys
import traceback
import boto3
import os
import json
from uuid import uuid4
from datetime import datetime


# Cognito Configuration
# TODO: simplify by detecting automatically when possible
COG_GRP = os.environ.get("COGNITO_PROV_GROUP", "GreengrassProvisioningOperators")
COG_POOL = os.environ.get("COGNITO_USER_POOL_ID")
if not COG_POOL:
    raise Exception("Environment variable COGNITO_USER_POOL_ID missing")
COG_URL = os.environ.get("COGNITO_URL")
if not COG_URL:
    raise Exception("Environment variable COGNITO_URL missing")
COG_CID = os.environ.get("COG_CLIENT_ID")
if not COG_CID:
    raise Exception("Environment variable COG_CLIENT_ID missing")

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")

# API Gateway configuration
API_URL = os.environ.get("API_BASE_URL")
if not API_URL:
    raise Exception("Environment variable API_ENDPOINT missing")
OPS_ENDPOINT = "manage/request/"

# SES Configuration
SES_SENDER = os.environ.get("SES_SENDER_EMAIL")
if not SES_SENDER:
    raise Exception("Environment variable SES_SENDER_EMAIL missing")

# Set some boto3 clients
cog_client = boto3.client('cognito-idp')
iot_client = boto3.client('iot')
ddb_client = boto3.client('dynamodb')
ses_client = boto3.client("ses")


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


def ok_200(transactionId):
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'transactionId': transactionId})
    }


def bad_request(msg, status_code=403):
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def internal_error(status_code=500):
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def is_new_iot_thing(thing_name):
    try:
        _ = iot_client.describe_thing(thingName=thing_name)
        return False
    except iot_client.exceptions.ResourceNotFoundException:
        return True


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


def new_xaction_record(thing_name, device_id, username, email):
    now = datetime.utcnow().isoformat()
    return {
        'transactionId': str(uuid4()),
        'deviceId': device_id,
        'thingName': thing_name,
        'currentStatus': Status.PENDING.name,
        'dateCreated': now,
        'requester': {'username': username, 'email': email},
        'history': {now: {
            "action": "create",
            "previous_status": "NONE"
        }
        }
    }


def send_email(transaction_id, device_id, thing_name, recipient, api_url=API_URL, source=SES_SENDER):
    auth_url = '{0}/login?client_id={1}&response_type=code'.format(COG_URL, COG_CID)
    state_allow = '&state=action=allow+transactionId={0}+deviceId={1}'.format(transaction_id, device_id)
    state_deny = '&state=action=deny+transactionId={0}+deviceId={1}'.format(transaction_id, device_id)
    redirect = '&redirect_uri={0}/{1}'.format(api_url, OPS_ENDPOINT)

    data = 'The device {0} is requesting to be provisioned on AWS IoT as a Thing named {1}.<br>' \
           'Please allow or deny this request by clicking on one of the links below (log-in required):<br><br>' \
           '<a class="ulink" href="{2}{3}{5}" target="_blank">Allow this provisioning request</a>.<br><br>' \
           '<a class="ulink" href="{2}{4}{5}" target="_blank">Deny this provisioning request</a>.<br>'.format(
            device_id, thing_name, auth_url, state_allow, state_deny, redirect)
    body = {
        'Html': {
            'Charset': "UTF-8",
            'Data': data
        }
    }
    subject = {
        'Charset': "UTF-8",
        'Data': "Device Provisioning Request for {}".format(device_id)
    }

    return ses_client.send_email(
        Destination={'ToAddresses': [recipient]},
        Message={'Body': body, 'Subject': subject},
        Source=source
    )


def lambda_handler(event, context):
    try:
        logger.info("Starting Lambda {}.{}".format(context.function_name, context.function_version))

        # Retrieve Query String Parameters
        user_name = event["queryStringParameters"].get('userName')
        thing_name = event["queryStringParameters"].get('thingName')
        device_id = event["queryStringParameters"].get('deviceId')
        logger.debug("Received query string parameters: userName = '{}', thingName = '{}', "
                     "deviceId = '{}'".format(user_name, thing_name, device_id))

        if is_valid_thing_name(thing_name) is not True:
            logger.warning("Invalid Thing Name requested: '{}'".format(thing_name))
            return bad_request("Invalid Thing Name: {}".format(thing_name))

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
            return bad_request("A thing with name {} already exists".format(thing_name))
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

        # Write a new transaction in the DB
        xaction = new_xaction_record(thing_name=thing_name,
                                     device_id=device_id,
                                     username=user_name,
                                     email=email)
        logger.debug("Writing to DynamoDB: {}".format(xaction))
        resp = ddb_client.put_item(
            TableName=DDB_TABLE,
            Item=marshall(xaction),
            ReturnConsumedCapacity='NONE',
        )
        logger.debug("DynamoDB response: {}".format(resp))

        # Email the Operator with Allow and Deny links.
        resp = send_email(transaction_id=xaction['transactionId'],
                          device_id=device_id,
                          thing_name=thing_name,
                          recipient=email)

        logger.debug("Email sending response: {}".format(resp))

        return ok_200(xaction['transactionId'])

    except Exception as e:
        logger.error("Error during runtime: {}".format(e))
        traceback.print_exc(file=sys.stdout)
        return internal_error()
