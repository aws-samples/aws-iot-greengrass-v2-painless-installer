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
import traceback
import boto3
from base64 import b64encode

# DynamoDB configuration
DDB_TABLE = os.environ.get("DYNAMO_TABLE_NAME")
if not DDB_TABLE:
    raise Exception("Environment variable DYNAMO_TABLE_NAME missing")

# S3 bucket containing the template documents
S3_BUCKET = os.environ.get("S3_BUCKET_NAME")
if not S3_BUCKET:
    raise Exception("Environment variable S3_BUCKET_NAME missing")

# Provisioning Template to use
GG_CONFIG_TEMPLATE = os.environ.get("GG_CONFIG_TEMPLATE", "ggi_default_greengrass-config-template.yaml")

# Constants
IOT_ROLE_ALIAS = "ggi_GreengrassCoreTokenExchangeRoleAlias"

# Set some boto3 clients
ddb_client = boto3.client('dynamodb')
s3_client = boto3.client('s3')
iot_client = boto3.client('iot')


def ok_200(body):
    return {
        'statusCode': 200,
        'headers': {'Content-Type': "text/plain", "Content-Transfer-Encoding": "base64"},
        'body': b64encode(bytes(body, "utf-8"))
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


def get_iot_endpoint(endpoint_type):
    response = iot_client.describe_endpoint(endpointType=endpoint_type)
    return response['endpointAddress']


def lambda_handler(event, context):
    try:
        try:
            parameters = event['queryStringParameters']
            item = get_ddb_item(pkey='transactionId', pvalue=parameters['transactionId'],
                                skey='deviceId', svalue=parameters['deviceId'],
                                table=DDB_TABLE, ddb_client=ddb_client)
            template_name = parameters.get('greengrassConfigTemplate', GG_CONFIG_TEMPLATE)
            if not item:
                return bad_request(msg="The provisioning request was not found.")
            if item['currentStatus'] != Status.REGISTERED.name:
                return bad_request("The current status of this request does not allow installing Greengrass.")
            thing_name = item['thingName']
            logger.info("Ready to prepare Greengrass Configuration")
        except KeyError as e:
            msg = "Malformed query string parameters. Check the logs."
            logger.error("Malformed query string parameters: {}".format(e))
            return bad_request(msg)
        except Exception as e:
            logger.critical("Error when retrieving initial data:\n{}".format(e))
            traceback.print_exc(file=sys.stdout)
            return internal_error()

        try:
            response = s3_client.get_object(Bucket=S3_BUCKET, Key=template_name)
            template = response['Body'].read().decode('utf-8')
            logger.debug("Configuration template:\n{}".format(template))
        except Exception as e:
            logger.critical("Exception when reading Configuration Template {} from S3:\n{}".format(template_name, e))
            return bad_request(msg="The configuration template could not be read")

        # Prepare a dict of configuration elements to replace in the template
        rpl = {
            "$system.thingName$": thing_name,
            "$services.aws.greengrass.Nucleus.configuration.awsRegion$": os.environ.get('AWS_REGION'),
            "$services.aws.greengrass.Nucleus.configuration.iotRoleAlias$": IOT_ROLE_ALIAS,
            "$services.aws.greengrass.Nucleus.configuration.iotCredEndpoint$": get_iot_endpoint("iot:CredentialProvider"),
            "$services.aws.greengrass.Nucleus.configuration.iotDataEndpoint": get_iot_endpoint("iot:Data-ATS"),
        }

        for k, v in rpl.items():
            template = template.replace(k, v)

        logger.debug("Updated GG Config:\n{}".format(template))

        # Send the config
        return ok_200(template)

    except Exception as e:
        logger.critical("Unexpected error: \n{}".format(e))
        return internal_error()