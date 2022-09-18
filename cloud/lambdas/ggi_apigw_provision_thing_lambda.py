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
Provisions a new IoT Thing in AWS IoT Core using a provisioning template.
The CSR is signed and the certificate is returned to the caller together with other necessary information.
"""
# Import the helper functions from the layer
from ggi_lambda_utils import *

# Other imports
import traceback
import boto3

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")

# S3 bucket containing the template documents
S3_BUCKET = os.environ.get("S3_BUCKET_NAME")
if not S3_BUCKET:
    raise Exception("Environment variable S3_BUCKET_NAME missing")

# Provisioning Template to use
PROV_TEMPLATE = os.environ.get("DEFAULT_THING_PROVISIONING_TEMPLATE")
if not PROV_TEMPLATE:
    raise Exception("Environment variable DEFAULT_THING_PROVISIONING_TEMPLATE missing.")

# Policy names (to attach via the provisioning template)
TOKEN_POLICY = os.environ.get("TOKEN_EXCHANGE_ROLE_ALIAS_POLICY_NAME")
if not TOKEN_POLICY:
    raise Exception("Environment variable TOKEN_EXCHANGE_ROLE_ALIAS_POLICY_NAME missing.")

DEVICE_POLICY = os.environ.get("DEVICE_POLICY_NAME")
if not DEVICE_POLICY:
    raise Exception("Environment variable DEVICE_POLICY_NAME missing.")


# Set some boto3 clients
ddb_client = boto3.client('dynamodb')
s3_client = boto3.client('s3')
iot_client = boto3.client('iot')


def ok_200(body: dict) -> dict:
    """
    Returns a 200 response with JSON body
    :param body: dictionary of returned properties
    :return: response
    """
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps(body)
    }


def bad_request(msg: str, status_code: int = 403) -> dict:
    """
    :param msg: error message to display
    :param status_code: error code
    :return: response
    """
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def internal_error(status_code: int = 500) -> dict:
    """
    No custom message supported to avoid leaking of info
    :param status_code: error code
    :return: response
    """
    msg = "Something unexpected happened. Try again and contact support if the problem persists."
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': "application.json"},
        'body': json.dumps({'reason': msg})
    }


def lambda_handler(event, context) -> dict:
    """
    Provision a Thing in IoT Core. Expects the body of event to contain a string-encoded JSON object with
    the following elements:
    * CSR: Certificate signature request
    * deviceId: Device identifier like a serial number
    * transactionId: the UUID generated when creating the provisioning request
    * provisioningTemplate: S3 key of an alternative provisioning template to use.
      If omitted the template set by the corresponding environment variable is used.
    """
    # Retrieve properties and the provisioning request information
    try:
        body = json.loads(event['body'])
        csr = body['CSR']
        device_id = body['deviceId']
        transaction_id = body['transactionId']
        # Optional body properties
        template_name = body.get('provisioningTemplate', PROV_TEMPLATE)
        item = get_ddb_item(pkey='transactionId', pvalue=transaction_id,
                            skey='deviceId', svalue=device_id,
                            table=DDB_TABLE, ddb_client=ddb_client)
        if not item:
            return bad_request(msg="The provisioning request was not found.")
        if item['currentStatus'] != Status.PROGRESS.name:
            return bad_request("The current status of this request does not allow registering an IoT Thing.")
        thing_name = item['thingName']
        logger.info("ready to register the new thing: {}".format(thing_name))
    except KeyError as e:
        msg = "Malformed body. Check the logs."
        logger.error("Malformed body: {}".format(e))
        return bad_request(msg)
    except Exception as e:
        logger.critical("Error when retrieving initial data:\n{}".format(e))
        traceback.print_exc(file=sys.stdout)
        return internal_error()

    # Get the template
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=template_name)
        text_template = response['Body'].read().decode('utf-8')
        logger.debug("Provisioning template before update:\n{}".format(text_template))
        # Update the template
        rpl = {
            "$DEVICE_POLICY_NAME$": DEVICE_POLICY,
            "$TOKEN_EXCHANGE_ROLE_ALIAS_POLICY_NAME$": TOKEN_POLICY,
        }
        for k, v in rpl.items():
            text_template = text_template.replace(k, v)
        template = json.loads(text_template)
        logger.debug("Provisioning template after update:\n{}".format(template))
    except Exception as e:
        logger.critical("Exception when reading Provisioning Template {} from S3:\n{}".format(template_name, e))
        return bad_request(msg="The provisioning template could not be read")

    try:
        # Register the Thing in IoT Core
        response = iot_client.register_thing(
            templateBody=json.dumps(template),
            parameters={
                'ThingName': thing_name,
                'deviceId': device_id,
                'CSR': csr
            }
        )
        logger.info("New IoT Thing {} successfully registered".format(thing_name))
        logger.debug(response)
        # Extract the certificate signed from the CSR
        certificate_pem = response['certificatePem']

        # Fetch the IoT Data Endpoint
        response = iot_client.describe_endpoint(endpointType="iot:Data-ATS")
        data_endpoint = response['endpointAddress']
        logger.debug("The IoT Endpoint is: {}".format(data_endpoint))

        # Update the Status in DynamoDB
        new_status = Status.REGISTERED
        update_request_status(current_request=item,
                              new_status=new_status.name,
                              action="Change Status to {}".format(new_status.name),
                              table=DDB_TABLE,
                              ddb_client=ddb_client)

        # Return the data
        return ok_200({'certificatePem': certificate_pem,
                       'iotDataEndpoint': data_endpoint,
                       'thingName': thing_name,
                       'deviceId': device_id})

    except Exception as e:
        logger.critical("Unexpected error: \n{}".format(e))
        return internal_error()
